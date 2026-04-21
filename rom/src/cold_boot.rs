/*++

Licensed under the Apache-2.0 license.

File Name:

    cold_boot.rs

Abstract:

    Cold Boot Flow - Handles initial boot when MCU powers on

--*/

#![allow(clippy::empty_loop)]

use crate::mailbox;
use crate::{
    configure_mcu_mbox_axi_users, device_ownership_transfer, fatal_error,
    verify_mcu_mbox_axi_users, verify_prod_debug_unlock_pk_hash, AxiUsers, BootFlow, DotBlob,
    I3cMailboxHandler, I3cServicesModes, RomEnv, RomParameters, MCU_MEMORY_MAP,
};
use caliptra_api::mailbox::{
    CmStableKeyType, CommandId, FeProgReq, MailboxReqHeader, StashMeasurementReq,
    StashMeasurementResp,
};
use caliptra_api::CaliptraApiError;
use caliptra_api::SocManager;
use caliptra_api_types::{DeviceLifecycle, SecurityState};
use caliptra_mcu_error::McuError;
use caliptra_mcu_registers_generated::fuses;
use caliptra_mcu_registers_generated::i3c::bits::RecIntfCfg;
use caliptra_mcu_registers_generated::mci::bits::{MboxExecute, MboxLock};
use caliptra_mcu_romtime::{CaliptraSoC, HexBytes, HexWord, McuBootMilestones, McuRomBootStatus};
use core::fmt::Write;
use core::ops::Deref;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use zerocopy::{transmute, IntoBytes};

pub struct ColdBoot {}

impl ColdBoot {
    fn program_field_entropy(
        program_field_entropy: &[bool; 4],
        soc_manager: &mut CaliptraSoC,
        mci: &caliptra_mcu_romtime::Mci,
    ) {
        for (partition, _) in program_field_entropy
            .iter()
            .enumerate()
            .filter(|(_, partition)| **partition)
        {
            caliptra_mcu_romtime::println!(
                "[mcu-rom] Executing FE_PROG command for partition {}",
                partition
            );

            let req = FeProgReq {
                partition: partition as u32,
                ..Default::default()
            };
            let req = req.as_bytes();
            let chksum = caliptra_api::calc_checksum(CommandId::FE_PROG.into(), req);
            // set the checksum
            let req = FeProgReq {
                hdr: MailboxReqHeader { chksum },
                partition: partition as u32,
            };
            let req: [u32; 2] = transmute!(req);
            if let Err(err) = soc_manager.start_mailbox_req(
                CommandId::FE_PROG.into(),
                req.len() * 4,
                req.iter().copied(),
            ) {
                match err {
                    CaliptraApiError::MailboxCmdFailed(code) => {
                        caliptra_mcu_romtime::println!(
                            "[mcu-rom] Error sending mailbox command: {}",
                            HexWord(code)
                        );
                    }
                    _ => {
                        caliptra_mcu_romtime::println!("[mcu-rom] Error sending mailbox command");
                    }
                }
                fatal_error(McuError::ROM_COLD_BOOT_FIELD_ENTROPY_PROG_START);
            }
            if let Err(err) = soc_manager.finish_mailbox_resp(8, 8) {
                match err {
                    CaliptraApiError::MailboxCmdFailed(code) => {
                        caliptra_mcu_romtime::println!(
                            "[mcu-rom] Error finishing mailbox command: {}",
                            HexWord(code)
                        );
                    }
                    _ => {
                        caliptra_mcu_romtime::println!("[mcu-rom] Error finishing mailbox command");
                    }
                }
                fatal_error(McuError::ROM_COLD_BOOT_FIELD_ENTROPY_PROG_FINISH);
            };

            // Set status for each partition completion
            let partition_status = match partition {
                0 => McuRomBootStatus::FieldEntropyPartition0Complete.into(),
                1 => McuRomBootStatus::FieldEntropyPartition1Complete.into(),
                2 => McuRomBootStatus::FieldEntropyPartition2Complete.into(),
                3 => McuRomBootStatus::FieldEntropyPartition3Complete.into(),
                _ => mci.flow_checkpoint(),
            };
            mci.set_flow_checkpoint(partition_status);
        }
    }

    /// Calculate SHA384 hash of ROM and compare it against the stored value. Optionally stash it.
    fn rom_digest_integrity(soc_manager: &mut CaliptraSoC, stash: bool) {
        const DIGEST_SIZE: usize = 48;
        // Safety: MCU_MEMORY_MAP fields are linker-provided constants.
        let rom_size = unsafe { MCU_MEMORY_MAP.rom_size } as usize;
        let hashable_len = rom_size - DIGEST_SIZE;
        let rom = unsafe {
            core::slice::from_raw_parts(MCU_MEMORY_MAP.rom_offset as *const u32, hashable_len / 4)
        };

        let digest = mailbox::cm_sha384(soc_manager, rom);
        caliptra_mcu_romtime::println!("[mcu-rom] MCU ROM digest: {}", HexBytes(&digest));

        let expected_digest: &[u8; DIGEST_SIZE] = unsafe {
            &*((MCU_MEMORY_MAP.rom_offset as usize + hashable_len) as *const [u8; DIGEST_SIZE])
        };
        caliptra_mcu_romtime::println!(
            "[mcu-rom] MCU ROM expected digest: {}",
            HexBytes(expected_digest)
        );

        if digest != *expected_digest {
            caliptra_mcu_romtime::println!("[mcu-rom] MCU ROM digest mismatch");
            fatal_error(McuError::ROM_COLD_BOOT_ROM_DIGEST_MISMATCH);
        }

        if stash {
            Self::stash_measurement(soc_manager, &digest);
        }
    }

    fn stash_measurement(soc_manager: &mut CaliptraSoC, measurement: &[u8; 48]) {
        let req = StashMeasurementReq {
            hdr: MailboxReqHeader { chksum: 0 },
            metadata: [0u8; 4],
            measurement: *measurement,
            context: [0u8; 48],
            svn: 0,
        };
        let mut req_u32: [u32; core::mem::size_of::<StashMeasurementReq>() / 4] =
            zerocopy::transmute!(req);
        let mut resp_u32 = [0u32; core::mem::size_of::<StashMeasurementResp>() / 4];

        if let Err(err) = soc_manager.exec_mailbox_req_u32(
            CommandId::STASH_MEASUREMENT.into(),
            &mut req_u32,
            &mut resp_u32,
        ) {
            caliptra_mcu_romtime::println!(
                "[mcu-rom] STASH_MEASUREMENT error: {}",
                HexWord(crate::err_code(&err))
            );
            fatal_error(McuError::GENERIC_EXCEPTION);
        }

        // StashMeasurementResp: hdr(2 u32) + dpe_result(1 u32)
        let dpe_result = resp_u32[2];
        if dpe_result != 0 {
            caliptra_mcu_romtime::println!(
                "[mcu-rom] Stash Measurement failed: dpe_result={}",
                dpe_result
            );
            fatal_error(McuError::GENERIC_EXCEPTION);
        }
    }
}

/// Run integrator-configured DOT locked-state recovery handlers in sequence.
///
/// Each handler that succeeds triggers a warm reset and never returns.
/// The integrator controls the order and retry policy via
/// `RomParameters::dot_locked_recovery_handlers`.
fn attempt_dot_locked_recovery(
    env: &mut RomEnv,
    dot_fuses: &crate::DotFuses,
    params: &RomParameters,
    dot_flash: &dyn crate::hil::FlashStorage,
    key_type: CmStableKeyType,
) -> McuError {
    use crate::device_ownership_transfer::{DotLockedRecoveryContext, DotLockedRecoveryManager};

    if params.dot_locked_recovery_handlers.is_empty() {
        return McuError::ROM_COLD_BOOT_DOT_ERROR;
    }

    let ctx = DotLockedRecoveryContext {
        dot_fuses,
        dot_flash,
        key_type,
    };
    let mut manager = DotLockedRecoveryManager::new(params.dot_locked_recovery_handlers);
    match manager.run(env, &ctx) {
        Ok(()) => {
            caliptra_mcu_romtime::println!(
                "[mcu-rom] DOT locked-state recovery succeeded, resetting"
            );
            env.mci.trigger_warm_reset();
            fatal_error(McuError::ROM_COLD_BOOT_RESET_ERROR);
        }
        Err(err) => err,
    }
}

/// [`DotLockedRecoveryHandler`] that enters the I3C services mailbox loop.
///
/// The handler runs the interactive I3C command loop (DOT_RECOVERY,
/// DOT_OVERRIDE, etc.) and returns success if the loop completes
/// without error.
pub struct I3cDotLockedRecoveryHandler {
    pub i3c_base: caliptra_mcu_romtime::StaticRef<caliptra_mcu_registers_generated::i3c::regs::I3c>,
    pub services: crate::I3cServicesModes,
    pub i3c_target_addr: u8,
}

impl crate::device_ownership_transfer::DotLockedRecoveryHandler for I3cDotLockedRecoveryHandler {
    fn attempt(
        &self,
        env: &mut RomEnv,
        ctx: &crate::device_ownership_transfer::DotLockedRecoveryContext<'_>,
    ) -> caliptra_mcu_error::McuResult<()> {
        let dot_ctx = crate::DotContext {
            soc_manager: &mut env.soc_manager,
            mci: &env.mci,
            otp: &env.otp,
            dot_fuses: ctx.dot_fuses,
            dot_flash: ctx.dot_flash,
            key_type: ctx.key_type,
        };
        enter_i3c_services(
            &env.mci,
            self.i3c_base,
            self.services,
            self.i3c_target_addr,
            Some(dot_ctx),
        );
        Ok(())
    }
}

/// Enter I3C services mode if enabled in `RomParameters`.
///
/// Runs the I3C mailbox handler loop, processing commands until completion
/// or timeout. Sets boot status checkpoints on entry and exit.
fn enter_i3c_services(
    mci: &caliptra_mcu_romtime::Mci,
    i3c_base: caliptra_mcu_romtime::StaticRef<caliptra_mcu_registers_generated::i3c::regs::I3c>,
    services: I3cServicesModes,
    target_addr: u8,
    dot_ctx: Option<crate::DotContext<'_>>,
) {
    // Extend the watchdog timeout for I3C services since the loop may run
    // for an extended period waiting for commands from the BMC.
    mci.configure_wdt(u32::MAX as u64, 1);

    // Disable the recovery interface status registers.
    i3c_base
        .sec_fw_recovery_if_recovery_status
        .write(caliptra_mcu_registers_generated::i3c::bits::RecoveryStatus::DevRecStatus.val(3));
    i3c_base
        .sec_fw_recovery_if_device_status_0
        .write(caliptra_mcu_registers_generated::i3c::bits::DeviceStatus0::DevStatus.val(0));

    // Clear the virtual device address to fully deactivate the recovery
    // device on the I3C bus.
    i3c_base.stdby_ctrl_mode_stby_cr_virt_device_addr.set(0);

    caliptra_mcu_romtime::println!("[mcu-rom-i3c-svc] Recovery disabled");

    mci.set_flow_checkpoint(McuRomBootStatus::I3cServicesStarted.into());

    // Acquire the MCI mailbox lock so we can use its SRAM as a word-aligned
    // reassembly buffer for multi-packet I3C commands.
    //
    // On HW the lock is forced to 1 on reset, so reading it will return
    // 1 (locked). We release any stale lock by writing execute=0, then retry.
    // See issue #1220.

    // Reading the lock register atomically acquires it when it returns 0.
    // Loop until acquired or give up after a bounded number of attempts.
    // On the first failure we release a potentially stale lock.
    let mut lock_acquired = false;
    let mut released_stale = false;
    for _ in 0..100 {
        if mci.registers.mcu_mbox0_csr_mbox_lock.read(MboxLock::Lock) == 0 {
            lock_acquired = true;
            break;
        }
        // First failed attempt: release a possibly stale lock from a prior run
        if !released_stale {
            released_stale = true;
            mci.registers
                .mcu_mbox0_csr_mbox_execute
                .write(MboxExecute::Execute::CLEAR);
        }
    }
    if !lock_acquired {
        caliptra_mcu_romtime::println!("[mcu-rom-i3c-svc] Warning: could not acquire mailbox lock");
    }

    let reassembly_buf = unsafe {
        core::slice::from_raw_parts_mut(
            mci.registers.mcu_mbox0_csr_mbox_sram.as_ptr() as *mut u32,
            crate::i3c_mailbox::MAX_REASSEMBLY_WORDS,
        )
    };

    let mut handler =
        I3cMailboxHandler::new(i3c_base, services, target_addr, dot_ctx, reassembly_buf);
    match handler.run(|| {
        mci.set_flow_checkpoint(McuRomBootStatus::I3cServicesReady.into());
    }) {
        Ok(()) => {
            mci.set_flow_checkpoint(McuRomBootStatus::I3cServicesComplete.into());
        }
        Err(err) => {
            caliptra_mcu_romtime::println!("[mcu-rom] I3C services error: {}", HexWord(err.into()));
        }
    }

    // Release mailbox lock if we acquired it
    if lock_acquired {
        mci.registers
            .mcu_mbox0_csr_mbox_execute
            .write(MboxExecute::Execute::CLEAR);
    }
}

impl BootFlow for ColdBoot {
    fn run(env: &mut RomEnv, params: RomParameters) -> ! {
        crate::call_hook(params.hooks, |h| h.pre_cold_boot());
        caliptra_mcu_romtime::println!(
            "[mcu-rom] Starting cold boot flow at time {}",
            caliptra_mcu_romtime::mcycle()
        );

        env.mci
            .set_flow_checkpoint(McuRomBootStatus::ColdBootFlowStarted.into());

        // Create local references to minimize code changes
        let mci = &env.mci;
        let soc = &env.soc;
        let lc = &env.lc;
        let otp = &mut env.otp;
        let i3c = &mut env.i3c;
        let i3c1 = &mut env.i3c1;
        let straps = env.straps.deref();
        if straps.active_i3c > 1 {
            caliptra_mcu_romtime::println!(
                "[mcu-rom] WARNING: invalid active_i3c value {}, falling back to 0",
                straps.active_i3c
            );
        }
        // Select which I3C core to use for recovery based on platform strap.
        let i3c_base = if straps.active_i3c == 1 {
            env.i3c1_base
        } else {
            env.i3c_base
        };
        let i3c_target_addr = if straps.active_i3c == 1 {
            straps.i3c1_static_addr
        } else {
            straps.i3c_static_addr
        };
        caliptra_mcu_romtime::println!(
            "[mcu-rom] Active I3C core for recovery: {}",
            straps.active_i3c
        );

        caliptra_mcu_romtime::println!("[mcu-rom] Setting Caliptra boot go");

        crate::call_hook(params.hooks, |h| h.pre_caliptra_boot());
        mci.caliptra_boot_go();
        mci.set_flow_checkpoint(McuRomBootStatus::CaliptraBootGoAsserted.into());
        mci.set_flow_milestone(McuBootMilestones::CPTRA_BOOT_GO_ASSERTED.into());

        // If testing Caliptra Core, hang here until the test signals it to continue.
        if cfg!(feature = "core_test") {
            while mci.registers.mci_reg_generic_input_wires[1].get() & (1 << 30) == 0 {}
        }

        lc.init().unwrap();
        mci.set_flow_checkpoint(McuRomBootStatus::LifecycleControllerInitialized.into());

        if let Some((state, token)) = params.lifecycle_transition {
            mci.set_flow_checkpoint(McuRomBootStatus::LifecycleTransitionStarted.into());
            if let Err(err) = lc.transition(state, &token) {
                caliptra_mcu_romtime::println!(
                    "[mcu-rom] Error transitioning lifecycle: {:?}",
                    err
                );
                fatal_error(err);
            }
            caliptra_mcu_romtime::println!("Lifecycle transition successful; halting");
            mci.set_flow_checkpoint(McuRomBootStatus::LifecycleTransitionComplete.into());
            loop {}
        }

        // Initialize OTP.
        if let Err(err) = otp.init(
            params.otp_enable_consistency_check,
            params.otp_enable_integrity_check,
            params.otp_check_timeout_override,
        ) {
            caliptra_mcu_romtime::println!(
                "[mcu-rom] Error initializing OTP: {}",
                HexWord(err.into())
            );
            fatal_error(err);
        }
        mci.set_flow_checkpoint(McuRomBootStatus::OtpControllerInitialized.into());

        if let Some(tokens) = params.burn_lifecycle_tokens.as_ref() {
            caliptra_mcu_romtime::println!("[mcu-rom] Burning lifecycle tokens");
            mci.set_flow_checkpoint(McuRomBootStatus::LifecycleTokenBurningStarted.into());

            if otp.check_error().is_some() {
                caliptra_mcu_romtime::println!("[mcu-rom] OTP error: {}", HexWord(otp.status()));
                otp.print_errors();
                caliptra_mcu_romtime::println!("[mcu-rom] Halting");
                caliptra_mcu_romtime::test_exit(1);
            }

            if let Err(err) = otp.burn_lifecycle_tokens(tokens) {
                caliptra_mcu_romtime::println!(
                    "[mcu-rom] Error burning lifecycle tokens {:?}; OTP status: {}",
                    err,
                    HexWord(otp.status())
                );
                otp.print_errors();
                caliptra_mcu_romtime::println!("[mcu-rom] Halting");
                caliptra_mcu_romtime::test_exit(1);
            }
            caliptra_mcu_romtime::println!("[mcu-rom] Lifecycle token burning successful; halting");
            mci.set_flow_checkpoint(McuRomBootStatus::LifecycleTokenBurningComplete.into());
            loop {}
        }

        caliptra_mcu_romtime::println!("[mcu-rom] OTP initialized");

        let flash_boot = ((mci.registers.mci_reg_generic_input_wires[1].get() & (1 << 29)) != 0)
            || params.request_flash_boot;

        if flash_boot && (params.flash_partition_driver.is_none() || !cfg!(feature = "hw-2-1")) {
            caliptra_mcu_romtime::println!(
                "Flash boot requested but missing flash driver or AXI bypass not enabled in ROM"
            );
            fatal_error(McuError::ROM_COLD_BOOT_FLASH_NOT_CONFIGURED_ERROR);
        }

        if flash_boot {
            caliptra_mcu_romtime::println!(
                "[mcu-rom] Configurating Caliptra watchdog timers for flash boot: {} {}",
                straps.cptra_wdt_cfg0,
                straps.cptra_wdt_cfg1
            );
            soc.set_cptra_wdt_cfg(0, straps.cptra_wdt_cfg0);
            soc.set_cptra_wdt_cfg(1, straps.cptra_wdt_cfg1);

            let state = SecurityState::from(mci.security_state());
            let lifecycle = state.device_lifecycle();
            match (state.debug_locked(), lifecycle) {
                (false, _) => {
                    mci.configure_wdt(
                        straps.mcu_wdt_cfg0_debug.into(),
                        straps.mcu_wdt_cfg1_debug.into(),
                    );
                }
                (true, DeviceLifecycle::Manufacturing) => {
                    mci.configure_wdt(
                        straps.mcu_wdt_cfg0_manufacturing.into(),
                        straps.mcu_wdt_cfg1_manufacturing.into(),
                    );
                }
                (true, _) => {
                    mci.configure_wdt(straps.mcu_wdt_cfg0.into(), straps.mcu_wdt_cfg1.into());
                }
            }
        } else {
            caliptra_mcu_romtime::println!(
                "[mcu-rom] Configurating Caliptra watchdog timers for streaming boot: {} {}",
                800_000_000,
                800_000_000,
            );
            soc.set_cptra_wdt_cfg(0, 800_000_000);
            soc.set_cptra_wdt_cfg(1, 800_000_000);
            mci.configure_wdt(800_000_000, 1);
        }
        mci.set_nmi_vector(unsafe { MCU_MEMORY_MAP.rom_offset });
        mci.set_flow_checkpoint(McuRomBootStatus::WatchdogConfigured.into());

        caliptra_mcu_romtime::println!("[mcu-rom] Initializing I3C");
        if straps.active_i3c == 1 {
            caliptra_mcu_romtime::println!("[mcu-rom] Initializing I3C1 (active)");
            i3c1.configure(straps.i3c1_static_addr, true);
        } else {
            i3c.configure(straps.i3c_static_addr, true);
        }
        mci.set_flow_checkpoint(McuRomBootStatus::I3cInitialized.into());

        caliptra_mcu_romtime::println!(
            "[mcu-rom] Waiting for Caliptra to be ready for fuses: {}",
            soc.ready_for_fuses()
        );
        while !soc.ready_for_fuses() {}
        mci.set_flow_checkpoint(McuRomBootStatus::CaliptraReadyForFuses.into());

        caliptra_mcu_romtime::println!("[mcu-rom] Writing fuses to Caliptra");

        soc.set_axi_users(AxiUsers {
            mbox_users: params
                .cptra_mbox_axi_users
                .map(|u| if u != 0 { Some(u) } else { None }),
            fuse_user: params.cptra_fuse_axi_user,
            trng_user: params.cptra_trng_axi_user,
            dma_user: params.cptra_dma_axi_user,
        });
        mci.set_flow_checkpoint(McuRomBootStatus::AxiUsersConfigured.into());

        // Configure iTRNG
        let Ok(window_size) = otp.read_entry(fuses::CPTRA_ITRNG_HEALTH_TEST_WINDOW_SIZE) else {
            caliptra_mcu_romtime::println!("[mcu-rom] Error reading CPTRA_ITRNG_WINDOW_SIZE");
            fatal_error(McuError::ROM_OTP_READ_CPTRA_ITRNG_WINDOW_SIZE_ERROR);
        };
        let Ok(config0) = otp.read_entry(fuses::CPTRA_ITRNG_ENTROPY_CONFIG_0) else {
            caliptra_mcu_romtime::println!("[mcu-rom] Error reading CPTRA_ITRNG_ENTROPY_CONFIG_0");
            fatal_error(McuError::ROM_OTP_READ_CPTRA_ITRNG_CONFIG0_ERROR);
        };
        let Ok(config1) = otp.read_entry(fuses::CPTRA_ITRNG_ENTROPY_CONFIG_1) else {
            caliptra_mcu_romtime::println!("[mcu-rom] Error reading CPTRA_ITRNG_ENTROPY_CONFIG_1");
            fatal_error(McuError::ROM_OTP_READ_CPTRA_ITRNG_CONFIG1_ERROR);
        };
        soc.configure_itrng(crate::CptraItrngArgs {
            bypass_mode: params.itrng_entropy_bypass_mode,
            window_size: window_size as u16,
            config0,
            config1,
        });

        caliptra_mcu_romtime::println!("[mcu-rom] Populating fuses");
        crate::call_hook(params.hooks, |h| h.pre_populate_fuses_to_caliptra());
        let pk_hash_idx = soc.populate_fuses(otp, mci, &params);
        mci.set_flow_checkpoint(McuRomBootStatus::FusesPopulatedToCaliptra.into());

        // Configure MCU mailbox AXI users before locking
        caliptra_mcu_romtime::println!("[mcu-rom] Configuring MCU mailbox AXI users");
        let mcu_mbox_config = configure_mcu_mbox_axi_users(
            mci,
            &params.mci_mbox0_axi_users,
            &params.mci_mbox1_axi_users,
        );
        mci.set_flow_checkpoint(McuRomBootStatus::McuMboxAxiUsersConfigured.into());

        let size_value = params.mcu_fw_sram_exec_region_size.unwrap_or(
            unsafe { MCU_MEMORY_MAP.sram_size }
                - crate::MCU_SRAM_DEFAULT_PROTECTED_REGION_BLOCKS * 4096
                - 1,
        );
        mci.set_fw_sram_exec_region_size(size_value);

        // Set SS_CONFIG_DONE_STICKY to lock MCI configuration registers
        caliptra_mcu_romtime::println!(
            "[mcu-rom] Setting SS_CONFIG_DONE_STICKY to lock configuration"
        );
        mci.set_ss_config_done_sticky();
        mci.set_flow_checkpoint(McuRomBootStatus::SsConfigDoneStickySet.into());

        // Set SS_CONFIG_DONE to lock MCI configuration registers until warm reset
        caliptra_mcu_romtime::println!("[mcu-rom] Setting SS_CONFIG_DONE");
        mci.set_ss_config_done();
        mci.set_flow_checkpoint(McuRomBootStatus::SsConfigDoneSet.into());

        // Verify that SS_CONFIG_DONE_STICKY and SS_CONFIG_DONE are actually set
        if !mci.is_ss_config_done_sticky() || !mci.is_ss_config_done() {
            caliptra_mcu_romtime::println!("[mcu-rom] SS_CONFIG_DONE verification failed");
            fatal_error(McuError::ROM_SOC_SS_CONFIG_DONE_VERIFY_FAILED);
        }

        // Verify PK hashes haven't been tampered with after locking
        caliptra_mcu_romtime::println!("[mcu-rom] Verifying production debug unlock PK hashes");
        if let Err(err) = verify_prod_debug_unlock_pk_hash(mci, otp) {
            caliptra_mcu_romtime::println!("[mcu-rom] PK hash verification failed");
            fatal_error(err);
        }
        mci.set_flow_checkpoint(McuRomBootStatus::PkHashVerified.into());

        // Verify MCU mailbox AXI users haven't been tampered with after locking
        caliptra_mcu_romtime::println!("[mcu-rom] Verifying MCU mailbox AXI users");
        if let Err(err) = verify_mcu_mbox_axi_users(mci, &mcu_mbox_config) {
            caliptra_mcu_romtime::println!("[mcu-rom] MCU mailbox AXI user verification failed");
            fatal_error(err);
        }
        mci.set_flow_checkpoint(McuRomBootStatus::McuMboxAxiUsersVerified.into());

        caliptra_mcu_romtime::println!("[mcu-rom] Setting Caliptra fuse write done");
        soc.fuse_write_done();
        while soc.ready_for_fuses() {}
        mci.set_flow_checkpoint(McuRomBootStatus::FuseWriteComplete.into());
        mci.set_flow_milestone(McuBootMilestones::CPTRA_FUSES_WRITTEN.into());
        crate::call_hook(params.hooks, |h| h.post_populate_fuses_to_caliptra());

        // If testing Caliptra Core, hang here until the test signals it to continue.
        if cfg!(feature = "core_test") {
            while mci.registers.mci_reg_generic_input_wires[1].get() & (1 << 31) == 0 {}
        }

        caliptra_mcu_romtime::println!("[mcu-rom] Waiting for Caliptra Core boot FSM to be DONE");
        soc.wait_for_bootfsm_done(10_000_000);
        crate::call_hook(params.hooks, |h| h.post_caliptra_boot());

        caliptra_mcu_romtime::println!("[mcu-rom] Waiting for Caliptra to be ready for mbox",);
        while !soc.ready_for_mbox() {
            if soc.cptra_fw_fatal_error() {
                caliptra_mcu_romtime::println!("[mcu-rom] Caliptra reported a fatal error");
                fatal_error(McuError::ROM_COLD_BOOT_CALIPTRA_FATAL_ERROR_BEFORE_MB_READY);
            }
            soc.check_hw_errors();
        }

        caliptra_mcu_romtime::println!("[mcu-rom] Caliptra is ready for mailbox commands",);
        mci.set_flow_checkpoint(McuRomBootStatus::CaliptraReadyForMailbox.into());

        // Load DOT fuses from vendor non-secret partition
        // TODO: read these from a place specified by ROM configuration
        let dot_fuses = match device_ownership_transfer::DotFuses::load_from_otp(&env.otp) {
            Ok(dot_fuses) => dot_fuses,
            Err(_) => {
                caliptra_mcu_romtime::println!("[mcu-rom] Error reading DOT fuses");
                fatal_error(McuError::ROM_OTP_READ_ERROR);
            }
        };

        // Determine owner PK hash: from DOT flow if available, otherwise from fuses
        let owner_pk_hash = if let Some(dot_flash) = params.dot_flash {
            caliptra_mcu_romtime::println!("[mcu-rom] Reading DOT blob");
            let mut dot_blob = [0u8; device_ownership_transfer::DOT_BLOB_SIZE];
            if let Err(err) = dot_flash.read(&mut dot_blob, 0) {
                caliptra_mcu_romtime::println!(
                    "[mcu-rom] Fatal error reading DOT blob from flash: {}",
                    HexWord(usize::from(err) as u32)
                );
                fatal_error(McuError::ROM_COLD_BOOT_DOT_ERROR);
            }
            mci.set_flow_checkpoint(McuRomBootStatus::DeviceOwnershipTransferFlashRead.into());

            if dot_blob.iter().all(|&b| b == 0) || dot_blob.iter().all(|&b| b == 0xFF) {
                if dot_fuses.enabled && dot_fuses.is_locked() {
                    let key_type = params
                        .dot_stable_key_type
                        .unwrap_or(CmStableKeyType::IDevId);
                    caliptra_mcu_romtime::println!(
                        "[mcu-rom] DOT fuses are initialized but DOT blob is empty/corrupt"
                    );
                    let err =
                        attempt_dot_locked_recovery(env, &dot_fuses, &params, dot_flash, key_type);
                    fatal_error(err);
                }
                caliptra_mcu_romtime::println!("[mcu-rom] DOT blob is empty; skipping DOT flow");
                device_ownership_transfer::load_owner_pkhash(&env.otp)
            } else {
                let dot_blob: DotBlob = transmute!(dot_blob);
                match device_ownership_transfer::dot_flow(
                    env,
                    &dot_fuses,
                    &dot_blob,
                    params
                        .dot_stable_key_type
                        .unwrap_or(CmStableKeyType::IDevId),
                ) {
                    Ok(owner) => owner,
                    Err(err) => {
                        if dot_fuses.is_locked() {
                            let key_type = params
                                .dot_stable_key_type
                                .unwrap_or(CmStableKeyType::IDevId);
                            // Try locked-state recovery; if it succeeds it
                            // resets and never returns.
                            let _recovery_err = attempt_dot_locked_recovery(
                                env, &dot_fuses, &params, dot_flash, key_type,
                            );
                        }
                        caliptra_mcu_romtime::println!(
                            "[mcu-rom] Fatal error performing Device Ownership Transfer: {}",
                            HexWord(err.into())
                        );
                        fatal_error(err);
                    }
                }
            }
        } else {
            // No DOT flash configured, use owner PK hash from fuses
            device_ownership_transfer::load_owner_pkhash(&env.otp)
        };

        // Write owner PK hash to Caliptra if available
        if let Some(ref owner) = owner_pk_hash {
            env.soc.set_owner_pk_hash(owner);
            env.soc.lock_owner_pk_hash();
        }

        // Enter I3C services unconditionally if force_i3c_services is set
        if params.force_i3c_services {
            if let Some(services) = params.i3c_services {
                let dot_ctx = params.dot_flash.map(|dot_flash| {
                    let key_type = params
                        .dot_stable_key_type
                        .unwrap_or(CmStableKeyType::IDevId);
                    crate::DotContext {
                        soc_manager: &mut env.soc_manager,
                        mci: &env.mci,
                        otp: &env.otp,
                        dot_fuses: &dot_fuses,
                        dot_flash,
                        key_type,
                    }
                });
                enter_i3c_services(&env.mci, i3c_base, services, i3c_target_addr, dot_ctx);
            }
        }

        // Re-borrow after DOT flow (which took &mut env).
        let mci = &env.mci;
        let soc = &env.soc;
        let soc_manager = &mut env.soc_manager;

        // tell Caliptra to download firmware from the recovery interface
        caliptra_mcu_romtime::println!("[mcu-rom] Sending RI_DOWNLOAD_FIRMWARE command",);
        crate::call_hook(params.hooks, |h| h.pre_load_firmware());
        if let Err(err) =
            soc_manager.start_mailbox_req(CommandId::RI_DOWNLOAD_FIRMWARE.into(), 0, [].into_iter())
        {
            match err {
                CaliptraApiError::MailboxCmdFailed(code) => {
                    caliptra_mcu_romtime::println!(
                        "[mcu-rom] Error sending mailbox command: {}",
                        HexWord(code)
                    );
                }
                _ => {
                    caliptra_mcu_romtime::println!("[mcu-rom] Error sending mailbox command");
                }
            }
            fatal_error(McuError::ROM_COLD_BOOT_START_RI_DOWNLOAD_ERROR);
        }
        mci.set_flow_checkpoint(McuRomBootStatus::RiDownloadFirmwareCommandSent.into());

        caliptra_mcu_romtime::println!(
            "[mcu-rom] Done sending RI_DOWNLOAD_FIRMWARE command: status {}",
            HexWord(u32::from(
                soc_manager.soc_mbox().status().read().mbox_fsm_ps()
            ))
        );
        if let Err(err) = soc_manager.finish_mailbox_resp(8, 8) {
            match err {
                CaliptraApiError::MailboxCmdFailed(code) => {
                    caliptra_mcu_romtime::println!(
                        "[mcu-rom] Error finishing mailbox command: {}",
                        HexWord(code)
                    );
                }
                _ => {
                    caliptra_mcu_romtime::println!("[mcu-rom] Error finishing mailbox command");
                }
            }
            fatal_error(McuError::ROM_COLD_BOOT_FINISH_RI_DOWNLOAD_ERROR);
        }
        mci.set_flow_checkpoint(McuRomBootStatus::RiDownloadFirmwareComplete.into());
        mci.set_flow_milestone(McuBootMilestones::RI_DOWNLOAD_COMPLETED.into());

        // Loading flash into the recovery flow is only possible in 2.1+.
        if flash_boot {
            if let Some(flash_driver) = params.flash_partition_driver {
                caliptra_mcu_romtime::println!("[mcu-rom] Starting Flash recovery flow");
                mci.set_flow_checkpoint(McuRomBootStatus::FlashRecoveryFlowStarted.into());

                // Set AXI bypass mode once before the recovery flow
                i3c_base
                    .soc_mgmt_if_rec_intf_cfg
                    .modify(RecIntfCfg::RecIntfBypass::SET);

                crate::recovery::load_flash_image_to_recovery(i3c_base, flash_driver)
                    .unwrap_or_else(|_| fatal_error(McuError::ROM_COLD_BOOT_LOAD_IMAGE_ERROR));

                caliptra_mcu_romtime::println!("[mcu-rom] Flash Recovery flow complete");
                mci.set_flow_checkpoint(McuRomBootStatus::FlashRecoveryFlowComplete.into());
                mci.set_flow_milestone(McuBootMilestones::FLASH_RECOVERY_FLOW_COMPLETED.into());
            }
        }

        caliptra_mcu_romtime::println!("[mcu-rom] Waiting for MCU firmware to be ready");
        soc.wait_for_firmware_ready(mci);
        caliptra_mcu_romtime::println!("[mcu-rom] Firmware is ready");
        mci.set_flow_checkpoint(McuRomBootStatus::FirmwareReadyDetected.into());

        soc.pk_hash_volatile_lock(&env.otp, pk_hash_idx);
        if env.otp.check_error().is_some() {
            caliptra_mcu_romtime::println!("[mcu-rom] OTP error: {}", HexWord(env.otp.status()));
            env.otp.print_errors();
        }

        if let Some(image_verifier) = params.mcu_image_verifier {
            let header = unsafe {
                core::slice::from_raw_parts(
                    MCU_MEMORY_MAP.sram_offset as *const u8,
                    params.mcu_image_header_size,
                )
            };

            caliptra_mcu_romtime::println!("[mcu-rom] Verifying firmware header");
            if !image_verifier.verify_header(header, &env.otp) {
                caliptra_mcu_romtime::println!("Firmware header verification failed; halting");
                fatal_error(McuError::ROM_COLD_BOOT_HEADER_VERIFY_ERROR);
            }
        }

        // Check that the firmware was actually loaded before jumping to it
        let firmware_ptr = unsafe {
            (MCU_MEMORY_MAP.sram_offset + params.mcu_image_header_size as u32) as *const u32
        };
        // Safety: this address is valid
        if unsafe { core::ptr::read_volatile(firmware_ptr) } == 0 {
            caliptra_mcu_romtime::println!("Invalid firmware detected; halting");
            fatal_error(McuError::ROM_COLD_BOOT_INVALID_FIRMWARE);
        }
        caliptra_mcu_romtime::println!("[mcu-rom] Firmware load detected");
        mci.set_flow_checkpoint(McuRomBootStatus::FirmwareValidationComplete.into());
        crate::call_hook(params.hooks, |h| h.post_load_firmware());

        // wait for the Caliptra RT to be ready
        // this is a busy loop, but it should be very short
        caliptra_mcu_romtime::println!(
            "[mcu-rom] Waiting for Caliptra RT to be ready for runtime mailbox commands"
        );
        while !soc.ready_for_runtime() {
            soc.check_hw_errors();
        }
        mci.set_flow_checkpoint(McuRomBootStatus::CaliptraRuntimeReady.into());

        let stash_rom_digest = params.stash_rom_digest.unwrap_or(false);
        Self::rom_digest_integrity(soc_manager, stash_rom_digest);

        // NOTE: Firmware manifest DOT command processing is intentionally
        // handled in FwBoot (fw_boot.rs), not here.  FwBoot runs after the
        // warm-reset chain, so firmware in MCU SRAM is always decrypted by
        // that point – even during encrypted boot.  Processing is gated by
        // `params.fw_manifest_dot_enabled` so integrators can opt in.

        caliptra_mcu_romtime::println!("[mcu-rom] Finished common initialization");

        // program field entropy if requested
        if params.program_field_entropy.iter().any(|x| *x) {
            caliptra_mcu_romtime::println!("[mcu-rom] Programming field entropy");
            mci.set_flow_checkpoint(McuRomBootStatus::FieldEntropyProgrammingStarted.into());
            Self::program_field_entropy(&params.program_field_entropy, &mut env.soc_manager, mci);
            mci.set_flow_checkpoint(McuRomBootStatus::FieldEntropyProgrammingComplete.into());
        }

        if params.recovery_status_open {
            caliptra_mcu_romtime::println!("[mcu-rom] Leaving recovery interface open");
            if env.straps.active_i3c == 1 {
                env.i3c1.set_recovery_status_open();
            } else {
                env.i3c.set_recovery_status_open();
            }
        } else {
            caliptra_mcu_romtime::println!("[mcu-rom] Disabling recovery interface");
            if env.straps.active_i3c == 1 {
                env.i3c1.disable_recovery();
            } else {
                env.i3c.disable_recovery();
            }
        }

        // Reset so FirmwareBootReset can jump to firmware
        caliptra_mcu_romtime::println!("[mcu-rom] Resetting to boot firmware");
        mci.set_flow_checkpoint(McuRomBootStatus::ColdBootFlowComplete.into());
        mci.set_flow_milestone(McuBootMilestones::COLD_BOOT_FLOW_COMPLETE.into());
        crate::call_hook(params.hooks, |h| h.post_cold_boot());
        mci.trigger_warm_reset();
        caliptra_mcu_romtime::println!("[mcu-rom] ERROR: Still running after reset request!");
        fatal_error(McuError::ROM_COLD_BOOT_RESET_ERROR);
    }
}

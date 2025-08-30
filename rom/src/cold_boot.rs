/*++

Licensed under the Apache-2.0 license.

File Name:

    cold_boot.rs

Abstract:

    Cold Boot Flow - Handles initial boot when MCU powers on

--*/

#![allow(clippy::empty_loop)]

use crate::boot_status::McuRomBootStatus;
use crate::{fatal_error, BootFlow, RomEnv, RomParameters, MCU_MEMORY_MAP};
use caliptra_api::mailbox::{CommandId, FeProgReq, MailboxReqHeader};
use caliptra_api::CaliptraApiError;
use caliptra_api::SocManager;
use core::fmt::Write;
use romtime::{CaliptraSoC, HexWord};
use zerocopy::{transmute, IntoBytes};

pub struct ColdBoot {}

impl ColdBoot {
    fn program_field_entropy(
        program_field_entropy: &[bool; 4],
        soc_manager: &mut CaliptraSoC,
        mci: &romtime::Mci,
    ) {
        for (partition, _) in program_field_entropy
            .iter()
            .enumerate()
            .filter(|(_, partition)| **partition)
        {
            romtime::println!(
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
                        romtime::println!(
                            "[mcu-rom] Error sending mailbox command: {}",
                            HexWord(code)
                        );
                    }
                    _ => {
                        romtime::println!("[mcu-rom] Error sending mailbox command");
                    }
                }
                fatal_error(6);
            }
            if let Err(err) = soc_manager.finish_mailbox_resp(8, 8) {
                match err {
                    CaliptraApiError::MailboxCmdFailed(code) => {
                        romtime::println!(
                            "[mcu-rom] Error finishing mailbox command: {}",
                            HexWord(code)
                        );
                    }
                    _ => {
                        romtime::println!("[mcu-rom] Error finishing mailbox command");
                    }
                }
                fatal_error(7);
            };

            // Set status for each partition completion
            let partition_status = match partition {
                0 => McuRomBootStatus::FieldEntropyPartition0Complete.into(),
                1 => McuRomBootStatus::FieldEntropyPartition1Complete.into(),
                2 => McuRomBootStatus::FieldEntropyPartition2Complete.into(),
                3 => McuRomBootStatus::FieldEntropyPartition3Complete.into(),
                _ => mci.flow_status(),
            };
            mci.set_flow_status(partition_status);
        }
    }
}

impl BootFlow for ColdBoot {
    fn run(env: &mut RomEnv, params: RomParameters) -> ! {
        romtime::println!("[mcu-rom] Starting cold boot flow");
        env.mci
            .set_flow_status(McuRomBootStatus::ColdBootFlowStarted.into());

        // Create local references to minimize code changes
        let mci = &env.mci;
        let soc = &env.soc;
        let lc = &env.lc;
        let otp = &mut env.otp;
        let i3c = &mut env.i3c;
        let i3c_base = env.i3c_base;
        let soc_manager = &mut env.soc_manager;
        let straps = &env.straps;

        romtime::println!("[mcu-rom] Setting Caliptra boot go");
        mci.caliptra_boot_go();
        mci.set_flow_status(McuRomBootStatus::CaliptraBootGoAsserted.into());

        lc.init().unwrap();
        mci.set_flow_status(McuRomBootStatus::LifecycleControllerInitialized.into());

        if let Some((state, token)) = params.lifecycle_transition {
            mci.set_flow_status(McuRomBootStatus::LifecycleTransitionStarted.into());
            if let Err(err) = lc.transition(state, &token) {
                romtime::println!("[mcu-rom] Error transitioning lifecycle: {:?}", err);
                fatal_error(err.into());
            }
            romtime::println!("Lifecycle transition successful; halting");
            mci.set_flow_status(McuRomBootStatus::LifecycleTransitionComplete.into());
            loop {}
        }

        // FPGA has problems with the integrity check, so we disable it
        if let Err(err) = otp.init() {
            romtime::println!("[mcu-rom] Error initializing OTP: {}", HexWord(err as u32));
            fatal_error(err as u32);
        }
        mci.set_flow_status(McuRomBootStatus::OtpControllerInitialized.into());

        if let Some(tokens) = params.burn_lifecycle_tokens.as_ref() {
            romtime::println!("[mcu-rom] Burning lifecycle tokens");
            mci.set_flow_status(McuRomBootStatus::LifecycleTokenBurningStarted.into());

            if otp.check_error().is_some() {
                romtime::println!("[mcu-rom] OTP error: {}", HexWord(otp.status()));
                otp.print_errors();
                romtime::println!("[mcu-rom] Halting");
                romtime::test_exit(1);
            }

            if let Err(err) = otp.burn_lifecycle_tokens(tokens) {
                romtime::println!(
                    "[mcu-rom] Error burning lifecycle tokens {:?}; OTP status: {}",
                    err,
                    HexWord(otp.status())
                );
                otp.print_errors();
                romtime::println!("[mcu-rom] Halting");
                romtime::test_exit(1);
            }
            romtime::println!("[mcu-rom] Lifecycle token burning successful; halting");
            mci.set_flow_status(McuRomBootStatus::LifecycleTokenBurningComplete.into());
            loop {}
        }

        let fuses = match otp.read_fuses() {
            Ok(fuses) => {
                mci.set_flow_status(McuRomBootStatus::FusesReadFromOtp.into());
                fuses
            }
            Err(e) => {
                romtime::println!("Error reading fuses: {}", HexWord(e as u32));
                fatal_error(1);
            }
        };

        // TODO: Handle flash image loading with the watchdog enabled
        if params.flash_partition_driver.is_none() {
            soc.set_cptra_wdt_cfg(0, straps.cptra_wdt_cfg0);
            soc.set_cptra_wdt_cfg(1, straps.cptra_wdt_cfg1);

            mci.set_nmi_vector(unsafe { MCU_MEMORY_MAP.rom_offset });
            mci.configure_wdt(straps.mcu_wdt_cfg0, straps.mcu_wdt_cfg1);
            mci.set_flow_status(McuRomBootStatus::WatchdogConfigured.into());
        }

        romtime::println!("[mcu-rom] Initializing I3C");
        i3c.configure(straps.i3c_static_addr, true);
        mci.set_flow_status(McuRomBootStatus::I3cInitialized.into());

        romtime::println!(
            "[mcu-rom] Waiting for Caliptra to be ready for fuses: {}",
            soc.ready_for_fuses()
        );
        while !soc.ready_for_fuses() {}
        mci.set_flow_status(McuRomBootStatus::CaliptraReadyForFuses.into());

        romtime::println!("[mcu-rom] Writing fuses to Caliptra");
        romtime::println!(
            "[mcu-rom] Setting Caliptra mailbox user 0 to {}",
            HexWord(straps.axi_user)
        );

        soc.set_cptra_mbox_valid_axi_user(0, straps.axi_user);
        romtime::println!("[mcu-rom] Locking Caliptra mailbox user 0");
        soc.set_cptra_mbox_axi_user_lock(0, 1);

        romtime::println!("[mcu-rom] Setting fuse user");
        soc.set_cptra_fuse_valid_axi_user(straps.axi_user);
        romtime::println!("[mcu-rom] Locking fuse user");
        soc.set_cptra_fuse_axi_user_lock(1);
        romtime::println!("[mcu-rom] Setting TRNG user");
        soc.set_cptra_trng_valid_axi_user(straps.axi_user);
        romtime::println!("[mcu-rom] Locking TRNG user");
        soc.set_cptra_trng_axi_user_lock(1);
        romtime::println!("[mcu-rom] Setting DMA user");
        soc.set_ss_caliptra_dma_axi_user(straps.axi_user);
        mci.set_flow_status(McuRomBootStatus::AxiUsersConfigured.into());

        soc.populate_fuses(&fuses, params.program_field_entropy.iter().any(|x| *x));
        mci.set_flow_status(McuRomBootStatus::FusesPopulatedToCaliptra.into());

        romtime::println!("[mcu-rom] Setting Caliptra fuse write done");
        soc.fuse_write_done();
        while soc.ready_for_fuses() {}
        mci.set_flow_status(McuRomBootStatus::FuseWriteComplete.into());

        // Hang here when testing Caliptra Core when subsystem features aren't used
        if cfg!(feature = "core_test") {
            loop {}
        }

        romtime::println!("[mcu-rom] Waiting for Caliptra to be ready for mbox",);
        while !soc.ready_for_mbox() {
            if soc.cptra_fw_fatal_error() {
                romtime::println!("[mcu-rom] Caliptra reported a fatal error");
                fatal_error(3);
            }
        }

        romtime::println!("[mcu-rom] Caliptra is ready for mailbox commands",);
        mci.set_flow_status(McuRomBootStatus::CaliptraReadyForMailbox.into());

        // tell Caliptra to download firmware from the recovery interface
        romtime::println!("[mcu-rom] Sending RI_DOWNLOAD_FIRMWARE command",);
        if let Err(err) =
            soc_manager.start_mailbox_req(CommandId::RI_DOWNLOAD_FIRMWARE.into(), 0, [].into_iter())
        {
            match err {
                CaliptraApiError::MailboxCmdFailed(code) => {
                    romtime::println!("[mcu-rom] Error sending mailbox command: {}", HexWord(code));
                }
                _ => {
                    romtime::println!("[mcu-rom] Error sending mailbox command");
                }
            }
            fatal_error(4);
        }
        mci.set_flow_status(McuRomBootStatus::RiDownloadFirmwareCommandSent.into());

        romtime::println!(
            "[mcu-rom] Done sending RI_DOWNLOAD_FIRMWARE command: status {}",
            HexWord(u32::from(
                soc_manager.soc_mbox().status().read().mbox_fsm_ps()
            ))
        );
        if let Err(err) = soc_manager.finish_mailbox_resp(8, 8) {
            match err {
                CaliptraApiError::MailboxCmdFailed(code) => {
                    romtime::println!(
                        "[mcu-rom] Error finishing mailbox command: {}",
                        HexWord(code)
                    );
                }
                _ => {
                    romtime::println!("[mcu-rom] Error finishing mailbox command");
                }
            }
            fatal_error(5);
        };
        mci.set_flow_status(McuRomBootStatus::RiDownloadFirmwareComplete.into());

        // Loading flash into the recovery flow is only possible in 2.1+.
        if cfg!(feature = "hw-2-1") {
            if let Some(flash_driver) = params.flash_partition_driver {
                romtime::println!("[mcu-rom] Starting Flash recovery flow");
                mci.set_flow_status(McuRomBootStatus::FlashRecoveryFlowStarted.into());

                crate::recovery::load_flash_image_to_recovery(i3c_base, flash_driver)
                    .map_err(|_| fatal_error(1))
                    .unwrap();

                romtime::println!("[mcu-rom] Flash Recovery flow complete");
                mci.set_flow_status(McuRomBootStatus::FlashRecoveryFlowComplete.into());
            }
        }

        romtime::println!("[mcu-rom] Waiting for firmware to be ready");
        while !soc.fw_ready() {
            if soc.cptra_fw_fatal_error() {
                romtime::println!("[mcu-rom] Caliptra reported a fatal error");
                fatal_error(6);
            }
        }
        romtime::println!("[mcu-rom] Firmware is ready");
        mci.set_flow_status(McuRomBootStatus::FirmwareReadyDetected.into());

        // Check that the firmware was actually loaded before jumping to it
        let firmware_ptr = unsafe { MCU_MEMORY_MAP.sram_offset as *const u32 };
        // Safety: this address is valid
        if unsafe { core::ptr::read_volatile(firmware_ptr) } == 0 {
            romtime::println!("Invalid firmware detected; halting");
            fatal_error(1);
        }
        romtime::println!("[mcu-rom] Firmware load detected");
        mci.set_flow_status(McuRomBootStatus::FirmwareValidationComplete.into());

        // wait for the Caliptra RT to be ready
        // this is a busy loop, but it should be very short
        romtime::println!(
            "[mcu-rom] Waiting for Caliptra RT to be ready for runtime mailbox commands"
        );
        while !soc.ready_for_runtime() {}
        mci.set_flow_status(McuRomBootStatus::CaliptraRuntimeReady.into());

        romtime::println!("[mcu-rom] Finished common initialization");

        // program field entropy if requested
        if params.program_field_entropy.iter().any(|x| *x) {
            romtime::println!("[mcu-rom] Programming field entropy");
            mci.set_flow_status(McuRomBootStatus::FieldEntropyProgrammingStarted.into());
            Self::program_field_entropy(&params.program_field_entropy, soc_manager, mci);
            mci.set_flow_status(McuRomBootStatus::FieldEntropyProgrammingComplete.into());
        }

        // Jump to firmware
        romtime::println!("[mcu-rom] Jumping to firmware");
        mci.set_flow_status(McuRomBootStatus::ColdBootFlowComplete.into());

        #[cfg(target_arch = "riscv32")]
        unsafe {
            let firmware_entry = MCU_MEMORY_MAP.sram_offset;
            core::arch::asm!(
                "jr {0}",
                in(reg) firmware_entry,
                options(noreturn)
            );
        }

        #[cfg(not(target_arch = "riscv32"))]
        panic!("Attempting to jump to firmware on non-RISC-V platform");
    }
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    cold_boot.rs

Abstract:

    Cold Boot Flow - Handles initial boot when MCU powers on

--*/

#![allow(clippy::empty_loop)]

use crate::boot_status::McuRomBootStatus;
use crate::{fatal_error, BootFlow, McuBootMilestones, RomEnv, RomParameters, MCU_MEMORY_MAP};
use caliptra_api::mailbox::{CommandId, FeProgReq, MailboxReqHeader};
use caliptra_api::CaliptraApiError;
use caliptra_api::SocManager;
use caliptra_drivers::okref;
use core::fmt::Write;
use core::ops::Deref;
use mcu_error::McuError;
use romtime::{CaliptraSoC, HexWord};
use tock_registers::interfaces::Readable;
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
                fatal_error(McuError::ROM_COLD_BOOT_FIELD_ENTROPY_PROG_START);
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
}

impl BootFlow for ColdBoot {
    fn run(env: &mut RomEnv, params: RomParameters) -> ! {
        #[cfg(target_arch = "riscv32")]
        {
            use tock_registers::register_bitfields;
            register_bitfields![usize,
                value [
                    value OFFSET(0) NUMBITS(32) [],
                ],
            ];
            let mcycle: riscv_csr::csr::ReadWriteRiscvCsr<
                usize,
                value::Register,
                { riscv_csr::csr::MCYCLE },
            > = riscv_csr::csr::ReadWriteRiscvCsr::new();
            let mcycleh: riscv_csr::csr::ReadWriteRiscvCsr<
                usize,
                value::Register,
                { riscv_csr::csr::MCYCLEH },
            > = riscv_csr::csr::ReadWriteRiscvCsr::new();
            let cycle = (mcycleh.get() as u64) << 32 | (mcycle.get() as u64);
            romtime::println!("[mcu-rom] Starting cold boot flow at time {}", cycle);
        }
        env.mci
            .set_flow_checkpoint(McuRomBootStatus::ColdBootFlowStarted.into());

        // Create local references to minimize code changes
        let mci = &env.mci;
        let soc = &env.soc;
        let lc = &env.lc;
        let otp = &mut env.otp;
        let i3c = &mut env.i3c;
        let i3c_base = env.i3c_base;
        let soc_manager = &mut env.soc_manager;
        let straps = env.straps.deref();

        romtime::println!("[mcu-rom] Setting Caliptra boot go");
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
                romtime::println!("[mcu-rom] Error transitioning lifecycle: {:?}", err);
                fatal_error(err);
            }
            romtime::println!("Lifecycle transition successful; halting");
            mci.set_flow_checkpoint(McuRomBootStatus::LifecycleTransitionComplete.into());
            loop {}
        }

        // FPGA has problems with the integrity check, so we disable it
        if let Err(err) = otp.init() {
            romtime::println!("[mcu-rom] Error initializing OTP: {}", HexWord(err.into()));
            fatal_error(err);
        }
        mci.set_flow_checkpoint(McuRomBootStatus::OtpControllerInitialized.into());

        if let Some(tokens) = params.burn_lifecycle_tokens.as_ref() {
            romtime::println!("[mcu-rom] Burning lifecycle tokens");
            mci.set_flow_checkpoint(McuRomBootStatus::LifecycleTokenBurningStarted.into());

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
            mci.set_flow_checkpoint(McuRomBootStatus::LifecycleTokenBurningComplete.into());
            loop {}
        }

        romtime::println!("[mcu-rom] Reading fuses");
        let fuses_result = otp.read_fuses();
        let fuses_result = okref(&fuses_result);
        let fuses = match fuses_result {
            Ok(fuses) => {
                mci.set_flow_checkpoint(McuRomBootStatus::FusesReadFromOtp.into());
                fuses
            }
            Err(e) => {
                romtime::println!("Error reading fuses: {}", HexWord(e.into()));
                fatal_error(e);
            }
        };

        // TODO: Handle flash image loading with the watchdog enabled
        if params.flash_partition_driver.is_none() {
            soc.set_cptra_wdt_cfg(0, straps.cptra_wdt_cfg0);
            soc.set_cptra_wdt_cfg(1, straps.cptra_wdt_cfg1);

            mci.set_nmi_vector(unsafe { MCU_MEMORY_MAP.rom_offset });
            mci.configure_wdt(straps.mcu_wdt_cfg0, straps.mcu_wdt_cfg1);
            mci.set_flow_checkpoint(McuRomBootStatus::WatchdogConfigured.into());
        }

        romtime::println!("[mcu-rom] Initializing I3C");
        i3c.configure(straps.i3c_static_addr, true);
        mci.set_flow_checkpoint(McuRomBootStatus::I3cInitialized.into());

        romtime::println!(
            "[mcu-rom] Waiting for Caliptra to be ready for fuses: {}",
            soc.ready_for_fuses()
        );
        while !soc.ready_for_fuses() {}
        mci.set_flow_checkpoint(McuRomBootStatus::CaliptraReadyForFuses.into());

        romtime::println!("[mcu-rom] Writing fuses to Caliptra");

        soc.set_axi_users(straps.into());
        mci.set_flow_checkpoint(McuRomBootStatus::AxiUsersConfigured.into());

        romtime::println!("[mcu-rom] Populating fuses");
        soc.populate_fuses(fuses, mci);
        mci.set_flow_checkpoint(McuRomBootStatus::FusesPopulatedToCaliptra.into());

        romtime::println!("[mcu-rom] Setting Caliptra fuse write done");
        soc.fuse_write_done();
        while soc.ready_for_fuses() {}
        mci.set_flow_checkpoint(McuRomBootStatus::FuseWriteComplete.into());
        mci.set_flow_milestone(McuBootMilestones::CPTRA_FUSES_WRITTEN.into());

        romtime::println!("[mcu-rom] Waiting for Caliptra to be ready for mbox",);
        while !soc.ready_for_mbox() {
            if soc.cptra_fw_fatal_error() {
                romtime::println!("[mcu-rom] Caliptra reported a fatal error");
                fatal_error(McuError::ROM_COLD_BOOT_CALIPTRA_FATAL_ERROR_BEFORE_MB_READY);
            }
        }

        romtime::println!("[mcu-rom] Caliptra is ready for mailbox commands",);
        mci.set_flow_checkpoint(McuRomBootStatus::CaliptraReadyForMailbox.into());

        // If testing Caliptra Core, hang here until the test signals it to continue.
        if cfg!(feature = "core_test") {
            while mci.registers.mci_reg_generic_input_wires[1].get() & (1 << 31) == 0 {}
        }

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
                    romtime::println!("[mcu-rom] Error sending mailbox command: {:?}", err);
                }
            }
            fatal_error(McuError::ROM_COLD_BOOT_START_RI_DOWNLOAD_ERROR);
        }
        mci.set_flow_checkpoint(McuRomBootStatus::RiDownloadFirmwareCommandSent.into());

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
            fatal_error(McuError::ROM_COLD_BOOT_FINISH_RI_DOWNLOAD_ERROR);
        };
        mci.set_flow_checkpoint(McuRomBootStatus::RiDownloadFirmwareComplete.into());
        mci.set_flow_milestone(McuBootMilestones::RI_DOWNLOAD_COMPLETED.into());

        // Loading flash into the recovery flow is only possible in 2.1+.
        if cfg!(feature = "hw-2-1") {
            if let Some(flash_driver) = params.flash_partition_driver {
                romtime::println!("[mcu-rom] Starting Flash recovery flow");
                mci.set_flow_checkpoint(McuRomBootStatus::FlashRecoveryFlowStarted.into());

                crate::recovery::load_flash_image_to_recovery(i3c_base, flash_driver)
                    .map_err(|_| fatal_error(McuError::ROM_COLD_BOOT_LOAD_IMAGE_ERROR))
                    .unwrap();

                romtime::println!("[mcu-rom] Flash Recovery flow complete");
                mci.set_flow_checkpoint(McuRomBootStatus::FlashRecoveryFlowComplete.into());
                mci.set_flow_milestone(McuBootMilestones::FLASH_RECOVERY_FLOW_COMPLETED.into());
            }
        }

        romtime::println!("[mcu-rom] Waiting for MCU firmware to be ready");
        soc.wait_for_firmware_ready(mci);
        romtime::println!("[mcu-rom] Firmware is ready");
        mci.set_flow_checkpoint(McuRomBootStatus::FirmwareReadyDetected.into());

        if let Some(image_verifier) = params.mcu_image_verifier {
            let header = unsafe {
                core::slice::from_raw_parts(
                    MCU_MEMORY_MAP.sram_offset as *const u8,
                    params.mcu_image_header_size,
                )
            };

            romtime::println!("[mcu-rom] Verifying firmware header");
            if !image_verifier.verify_header(header, fuses) {
                romtime::println!("Firmware header verification failed; halting");
                fatal_error(McuError::ROM_COLD_BOOT_HEADER_VERIFY_ERROR);
            }
        }

        // Check that the firmware was actually loaded before jumping to it
        let firmware_ptr = unsafe {
            (MCU_MEMORY_MAP.sram_offset + params.mcu_image_header_size as u32) as *const u32
        };
        // Safety: this address is valid
        if unsafe { core::ptr::read_volatile(firmware_ptr) } == 0 {
            romtime::println!("Invalid firmware detected; halting");
            fatal_error(McuError::ROM_COLD_BOOT_INVALID_FIRMWARE);
        }
        romtime::println!("[mcu-rom] Firmware load detected");
        mci.set_flow_checkpoint(McuRomBootStatus::FirmwareValidationComplete.into());

        // wait for the Caliptra RT to be ready
        // this is a busy loop, but it should be very short
        romtime::println!(
            "[mcu-rom] Waiting for Caliptra RT to be ready for runtime mailbox commands"
        );
        while !soc.ready_for_runtime() {}
        mci.set_flow_checkpoint(McuRomBootStatus::CaliptraRuntimeReady.into());

        romtime::println!("[mcu-rom] Finished common initialization");

        // program field entropy if requested
        if params.program_field_entropy.iter().any(|x| *x) {
            romtime::println!("[mcu-rom] Programming field entropy");
            mci.set_flow_checkpoint(McuRomBootStatus::FieldEntropyProgrammingStarted.into());
            Self::program_field_entropy(&params.program_field_entropy, soc_manager, mci);
            mci.set_flow_checkpoint(McuRomBootStatus::FieldEntropyProgrammingComplete.into());
        }

        i3c.disable_recovery();

        // Reset so FirmwareBootReset can jump to firmware
        romtime::println!("[mcu-rom] Resetting to boot firmware");
        mci.set_flow_checkpoint(McuRomBootStatus::ColdBootFlowComplete.into());
        mci.set_flow_milestone(McuBootMilestones::COLD_BOOT_FLOW_COMPLETE.into());
        mci.trigger_warm_reset();
        romtime::println!("[mcu-rom] ERROR: Still running after reset request!");
        fatal_error(McuError::ROM_COLD_BOOT_RESET_ERROR);
    }
}

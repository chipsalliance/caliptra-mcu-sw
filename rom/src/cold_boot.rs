/*++

Licensed under the Apache-2.0 license.

File Name:

    cold_boot.rs

Abstract:

    Cold Boot Flow - Handles initial boot when MCU powers on

--*/

#![allow(clippy::empty_loop)]

use crate::boot_status::McuRomBootStatus;
use crate::err_code;
use crate::mailbox;
use crate::{
    configure_mcu_mbox_axi_users, device_ownership_transfer, fatal_error,
    verify_mcu_mbox_axi_users, verify_prod_debug_unlock_pk_hash, BootFlow, DotBlob,
    McuBootMilestones, RomEnv, RomParameters, MCU_MEMORY_MAP,
};
use caliptra_api::mailbox::{
    CmStableKeyType, CommandId, FeProgReq, MailboxReqHeader, MailboxRespHeader,
};
use caliptra_api::CaliptraApiError;
use caliptra_api_types::{DeviceLifecycle, SecurityState};
use core::fmt::Write;
use core::ops::Deref;
use mcu_error::McuError;
use romtime::{CaliptraSoC, HexBytes, HexWord, LifecycleControllerState, LifecycleToken};
use tock_registers::interfaces::Readable;
use zerocopy::{transmute, IntoBytes};

/// Bit in `mci_reg_generic_input_wires[1]` that signals encrypted firmware boot.
/// When set, MCU ROM sends `RI_DOWNLOAD_ENCRYPTED_FIRMWARE` instead of `RI_DOWNLOAD_FIRMWARE`,
/// then decrypts the firmware in MCU SRAM after Caliptra RT finishes loading.
const ENCRYPTED_BOOT_WIRE_BIT: u32 = 1 << 28;

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

            let mut req = FeProgReq {
                partition: partition as u32,
                ..Default::default()
            };
            let chksum = caliptra_api::calc_checksum(
                CommandId::FE_PROG.into(),
                &req.as_bytes()[core::mem::size_of::<MailboxReqHeader>()..],
            );
            req.hdr.chksum = chksum;
            if let Err(err) =
                soc_manager.start_mailbox_req_bytes(CommandId::FE_PROG.into(), req.as_bytes())
            {
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
            {
                let mut resp_buf = [0u8; core::mem::size_of::<MailboxRespHeader>()];
                if let Err(err) = soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
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
                }
            }

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

    /// Decrypt the encrypted MCU firmware in SRAM using DMA-based decryption:
    ///   1. Import the AES key via CM_IMPORT
    ///   2. Issue CM_AES_GCM_DECRYPT_DMA to decrypt in-place via DMA
    ///
    /// The firmware image in SRAM is formatted as `ciphertext || 16-byte GCM tag`.
    /// `ciphertext_size` is the ciphertext length only (GCM tag excluded), as
    /// returned by GET_MCU_FW_SIZE. Caliptra RT already strips the tag from the
    /// size in recovery_flow.rs.
    /// `sha384` is the SHA-384 digest of the ciphertext, obtained from the
    /// GET_MCU_FW_SIZE response (computed by Caliptra RT during the recovery flow).
    /// After decryption the plaintext replaces the ciphertext in SRAM.
    fn decrypt_firmware(soc_manager: &mut CaliptraSoC, ciphertext_size: u32, sha384: &[u8; 48]) {
        if ciphertext_size == 0 {
            romtime::println!("[mcu-rom] Encrypted firmware ciphertext size is zero");
            fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_START_ERROR);
        }
        let sram_base = unsafe { MCU_MEMORY_MAP.sram_offset } as usize;

        // Use the MCU SRAM address for in-place DMA decryption.
        // Caliptra RT downloaded the ciphertext here via the recovery interface,
        // so the DMA decrypt must target the same AXI address.
        // On both emulator and FPGA, sram_offset is the AXI bus address
        // (FPGA: mci_base + 0xc0_0000; emulator: identity-mapped).
        let sram_axi_addr = sram_base as u64;

        // Extract GCM tag (16 bytes immediately after ciphertext in SRAM)
        let tag: [u8; mailbox::GCM_TAG_SIZE] = unsafe {
            let tag_ptr =
                (sram_base + ciphertext_size as usize) as *const [u8; mailbox::GCM_TAG_SIZE];
            core::ptr::read_volatile(tag_ptr)
        };

        // Step 1: Import the test AES key
        let cmk = mailbox::cm_import_aes_key(soc_manager);

        // Step 2: Issue CM_AES_GCM_DECRYPT_DMA to decrypt in-place in MCU SRAM
        // The length must match what Caliptra RT used for sha384_mcu_sram(),
        // which is the ciphertext size (excluding the 16-byte GCM tag).
        mailbox::cm_aes_gcm_decrypt_dma(
            soc_manager,
            &cmk,
            &tag,
            sha384,
            sram_axi_addr,
            ciphertext_size,
        );
    }

    /// Calculate SHA384 hash of ROM and compare it against the stored value. Optionally stash it.
    fn rom_digest_integrity(soc_manager: &mut CaliptraSoC, stash: bool) {
        const DIGEST_SIZE: usize = 48;
        let rom_base = unsafe { MCU_MEMORY_MAP.rom_offset } as *const u8;
        let rom_size = unsafe { MCU_MEMORY_MAP.rom_size } as usize - DIGEST_SIZE;
        let digest = mailbox::cm_sha384(soc_manager, rom_base, rom_size);
        romtime::println!("[mcu-rom] MCU ROM digest: {}", HexBytes(&digest));

        let digest_offset = rom_base.wrapping_add(rom_size);
        let mut expected_digest = [0u8; DIGEST_SIZE];
        // Safety: rom_size + digest_size = rom_size so we're in-bounds.
        unsafe {
            core::ptr::copy_nonoverlapping(
                digest_offset,
                expected_digest.as_mut_ptr(),
                DIGEST_SIZE,
            );
        }

        romtime::println!(
            "[mcu-rom] MCU ROM expected digest: {}",
            HexBytes(&expected_digest)
        );

        if digest != expected_digest {
            romtime::println!("[mcu-rom] MCU ROM digest mismatch");
            fatal_error(McuError::ROM_COLD_BOOT_ROM_DIGEST_MISMATCH);
        }

        if stash {
            mailbox::stash_measurement(soc_manager, &digest);
        }
    }

    /// Execute the FIPS zeroization flow.
    ///
    /// Per the Caliptra SS Hardware Specification, when the PPD signal is
    /// asserted the MCU ROM must:
    ///   1. Command Caliptra to zeroize UDS and field entropy via
    ///      ZEROIZE_UDS_FE (secret fuses can only be zeroized by Caliptra).
    ///   2. Write 0xFFFF_FFFF to FC_FIPS_ZEROZATION mask to authorize the
    ///      fuse controller to zeroize non-secret fuses.
    ///   3. Request an LC transition to SCRAP (no token required).
    ///   4. Halt, waiting for the SoC to issue a cold reset.
    ///
    /// This function never returns.
    fn handle_fips_zeroization(
        mci: &romtime::Mci,
        lc: &romtime::Lifecycle,
        soc_manager: &mut CaliptraSoC,
    ) -> ! {
        romtime::println!("[mcu-rom] Executing FIPS zeroization flow");

        // Step 1: Command Caliptra to zeroize UDS and all field entropy partitions.
        romtime::println!("[mcu-rom] Sending ZEROIZE_UDS_FE to Caliptra");
        mci.set_flow_checkpoint(McuRomBootStatus::FipsZeroizationUdsFeStarted.into());

        let flags = caliptra_api::mailbox::ZEROIZE_UDS_FLAG
            | caliptra_api::mailbox::ZEROIZE_FE0_FLAG
            | caliptra_api::mailbox::ZEROIZE_FE1_FLAG
            | caliptra_api::mailbox::ZEROIZE_FE2_FLAG
            | caliptra_api::mailbox::ZEROIZE_FE3_FLAG;

        let mut req = caliptra_api::mailbox::ZeroizeUdsFeReq {
            flags,
            ..Default::default()
        };
        let chksum = caliptra_api::calc_checksum(
            CommandId::ZEROIZE_UDS_FE.into(),
            &req.as_bytes()[core::mem::size_of::<MailboxReqHeader>()..],
        );
        req.hdr.chksum = chksum;

        if let Err(err) =
            soc_manager.start_mailbox_req_bytes(CommandId::ZEROIZE_UDS_FE.into(), req.as_bytes())
        {
            romtime::println!(
                "[mcu-rom] FIPS zeroization: ZEROIZE_UDS_FE send failed: {}",
                HexWord(err_code(&err))
            );
            fatal_error(McuError::ROM_FIPS_ZEROIZATION_UDS_FE_START_ERROR);
        }
        {
            let mut resp_buf = [0u8; core::mem::size_of::<MailboxRespHeader>()];
            if let Err(err) = soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
                romtime::println!(
                    "[mcu-rom] FIPS zeroization: ZEROIZE_UDS_FE finish failed: {}",
                    HexWord(err_code(&err))
                );
                fatal_error(McuError::ROM_FIPS_ZEROIZATION_UDS_FE_FINISH_ERROR);
            }
        }
        romtime::println!("[mcu-rom] ZEROIZE_UDS_FE completed successfully");
        mci.set_flow_checkpoint(McuRomBootStatus::FipsZeroizationUdsFeComplete.into());

        // Step 2: Authorize fuse controller zeroization of non-secret fuses.
        mci.set_fips_zeroization_mask();
        mci.set_flow_checkpoint(McuRomBootStatus::FipsZeroizationMaskSet.into());

        // Step 3: Request LC transition to SCRAP. The transition is recorded
        // in OTP and takes effect permanently after the next cold reset.
        romtime::println!("[mcu-rom] Requesting LC transition to SCRAP for FIPS zeroization");
        mci.set_flow_checkpoint(McuRomBootStatus::FipsZeroizationScrapTransitionStarted.into());
        if let Err(err) = lc.transition(LifecycleControllerState::Scrap, &LifecycleToken([0u8; 16]))
        {
            romtime::println!(
                "[mcu-rom] FIPS zeroization: LC SCRAP transition failed: {:?}",
                err
            );
            fatal_error(McuError::ROM_FIPS_ZEROIZATION_LC_TRANSITION_ERROR);
        }

        // Step 4: Halt. The SoC must issue a cold reset for the SCRAP
        // transition and fuse zeroization to take effect.
        romtime::println!("[mcu-rom] FIPS zeroization complete; halting for cold reset");
        mci.set_flow_checkpoint(McuRomBootStatus::FipsZeroizationComplete.into());
        loop {}
    }
}

impl BootFlow for ColdBoot {
    fn run(env: &mut RomEnv, params: RomParameters) -> ! {
        romtime::println!(
            "[mcu-rom] Starting cold boot flow at time {}",
            romtime::mcycle()
        );
        env.mci
            .set_flow_checkpoint(McuRomBootStatus::ColdBootFlowStarted.into());

        // Create local references to minimize code changes
        let mci = &env.mci;
        let soc = &env.soc;
        let lc = &env.lc;
        let otp = &mut env.otp;
        let i3c = &mut env.i3c;
        let i3c_base = env.i3c_base;
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

        // Check for FIPS zeroization PPD signal early. The full zeroization
        // flow (including the Caliptra ZEROIZE_UDS_FE command) runs later,
        // after Caliptra is ready for mailbox commands.
        let fips_zeroization = mci.fips_zeroization_requested();
        if fips_zeroization {
            romtime::println!(
                "[mcu-rom] FIPS zeroization PPD signal detected; \
                 will execute zeroization after Caliptra boot"
            );
            mci.set_flow_checkpoint(McuRomBootStatus::FipsZeroizationDetected.into());
        }

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

        // Initialize OTP.
        if let Err(err) = otp.init(
            params.otp_enable_consistency_check,
            params.otp_enable_integrity_check,
            params.otp_check_timeout_override,
        ) {
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

        romtime::println!("[mcu-rom] OTP initialized");

        let flash_boot = ((mci.registers.mci_reg_generic_input_wires[1].get() & (1 << 29)) != 0)
            || params.request_flash_boot;

        if flash_boot && (params.flash_partition_driver.is_none() || !cfg!(feature = "hw-2-1")) {
            romtime::println!(
                "Flash boot requested but missing flash driver or AXI bypass not enabled in ROM"
            );
            fatal_error(McuError::ROM_COLD_BOOT_FLASH_NOT_CONFIGURED_ERROR);
        }

        if flash_boot {
            romtime::println!(
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
                    mci.configure_wdt(straps.mcu_wdt_cfg0_debug, straps.mcu_wdt_cfg1_debug);
                }
                (true, DeviceLifecycle::Manufacturing) => {
                    mci.configure_wdt(
                        straps.mcu_wdt_cfg0_manufacturing,
                        straps.mcu_wdt_cfg1_manufacturing,
                    );
                }
                (true, _) => {
                    mci.configure_wdt(straps.mcu_wdt_cfg0, straps.mcu_wdt_cfg1);
                }
            }
        } else {
            romtime::println!(
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
        soc.populate_fuses(otp, mci);
        mci.set_flow_checkpoint(McuRomBootStatus::FusesPopulatedToCaliptra.into());

        // Configure MCU mailbox AXI users before locking
        romtime::println!("[mcu-rom] Configuring MCU mailbox AXI users");
        let mcu_mbox_config = configure_mcu_mbox_axi_users(mci, straps);
        mci.set_flow_checkpoint(McuRomBootStatus::McuMboxAxiUsersConfigured.into());

        // Set SS_CONFIG_DONE_STICKY to lock MCI configuration registers
        romtime::println!("[mcu-rom] Setting SS_CONFIG_DONE_STICKY to lock configuration");
        mci.set_ss_config_done_sticky();
        mci.set_flow_checkpoint(McuRomBootStatus::SsConfigDoneStickySet.into());

        // Set SS_CONFIG_DONE to lock MCI configuration registers until warm reset
        romtime::println!("[mcu-rom] Setting SS_CONFIG_DONE");
        mci.set_ss_config_done();
        mci.set_flow_checkpoint(McuRomBootStatus::SsConfigDoneSet.into());

        // Verify that SS_CONFIG_DONE_STICKY and SS_CONFIG_DONE are actually set
        if !mci.is_ss_config_done_sticky() || !mci.is_ss_config_done() {
            romtime::println!("[mcu-rom] SS_CONFIG_DONE verification failed");
            fatal_error(McuError::ROM_SOC_SS_CONFIG_DONE_VERIFY_FAILED);
        }

        // Verify PK hashes haven't been tampered with after locking
        romtime::println!("[mcu-rom] Verifying production debug unlock PK hashes");
        if let Err(err) = verify_prod_debug_unlock_pk_hash(mci, otp) {
            romtime::println!("[mcu-rom] PK hash verification failed");
            fatal_error(err);
        }
        mci.set_flow_checkpoint(McuRomBootStatus::PkHashVerified.into());

        // Verify MCU mailbox AXI users haven't been tampered with after locking
        romtime::println!("[mcu-rom] Verifying MCU mailbox AXI users");
        if let Err(err) = verify_mcu_mbox_axi_users(mci, &mcu_mbox_config) {
            romtime::println!("[mcu-rom] MCU mailbox AXI user verification failed");
            fatal_error(err);
        }
        mci.set_flow_checkpoint(McuRomBootStatus::McuMboxAxiUsersVerified.into());

        romtime::println!("[mcu-rom] Setting Caliptra fuse write done");
        soc.fuse_write_done();
        while soc.ready_for_fuses() {}
        mci.set_flow_checkpoint(McuRomBootStatus::FuseWriteComplete.into());
        mci.set_flow_milestone(McuBootMilestones::CPTRA_FUSES_WRITTEN.into());

        // If testing Caliptra Core, hang here until the test signals it to continue.
        if cfg!(feature = "core_test") {
            while mci.registers.mci_reg_generic_input_wires[1].get() & (1 << 31) == 0 {}
        }

        romtime::println!("[mcu-rom] Waiting for Caliptra to be ready for mbox",);
        while !soc.ready_for_mbox() {
            if soc.cptra_fw_fatal_error() {
                romtime::println!("[mcu-rom] Caliptra reported a fatal error");
                fatal_error(McuError::ROM_COLD_BOOT_CALIPTRA_FATAL_ERROR_BEFORE_MB_READY);
            }
        }

        romtime::println!("[mcu-rom] Caliptra is ready for mailbox commands",);
        mci.set_flow_checkpoint(McuRomBootStatus::CaliptraReadyForMailbox.into());

        // Execute full FIPS zeroization flow now that Caliptra is ready for
        // mailbox commands. This never returns (halts for cold reset).
        if fips_zeroization {
            ColdBoot::handle_fips_zeroization(mci, lc, &mut env.soc_manager);
        }

        // Load DOT fuses from vendor non-secret partition
        // TODO: read these from a place specified by ROM configuration
        let dot_fuses = match device_ownership_transfer::DotFuses::load_from_otp(&env.otp) {
            Ok(dot_fuses) => dot_fuses,
            Err(_) => {
                romtime::println!("[mcu-rom] Error reading DOT fuses");
                fatal_error(McuError::ROM_OTP_READ_ERROR);
            }
        };

        // Determine owner PK hash: from DOT flow if available, otherwise from fuses
        let owner_pk_hash = if let Some(dot_flash) = params.dot_flash {
            romtime::println!("[mcu-rom] Reading DOT blob");
            let mut dot_blob = [0u8; core::mem::size_of::<DotBlob>()];
            if let Err(err) = dot_flash.read(&mut dot_blob, 0) {
                romtime::println!(
                    "[mcu-rom] Fatal error reading DOT blob from flash: {}",
                    HexWord(usize::from(err) as u32)
                );
                fatal_error(McuError::ROM_COLD_BOOT_DOT_ERROR);
            }
            mci.set_flow_checkpoint(McuRomBootStatus::DeviceOwnershipTransferFlashRead.into());

            if dot_blob.iter().all(|&b| b == 0) || dot_blob.iter().all(|&b| b == 0xFF) {
                if dot_fuses.enabled {
                    // DOT is initialized but blob is empty/corrupt - this is a fatal error
                    // TODO: Add recovery mechanism for this case
                    romtime::println!(
                        "[mcu-rom] DOT fuses are initialized but DOT blob is empty/corrupt"
                    );
                    fatal_error(McuError::ROM_COLD_BOOT_DOT_ERROR);
                }
                romtime::println!("[mcu-rom] DOT blob is empty; skipping DOT flow");
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
                        romtime::println!(
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

        // re-borrow to avoid ownership issues
        let mci = &env.mci;
        let soc = &env.soc;
        let soc_manager = &mut env.soc_manager;

        // Check GPIO wire for encrypted firmware boot mode (core_test only).
        // When the encrypted boot wire is set, MCU ROM sends RI_DOWNLOAD_ENCRYPTED_FIRMWARE
        // which tells Caliptra RT to load firmware without activating MCU.
        let encrypted_boot = cfg!(feature = "core_test")
            && mci.registers.mci_reg_generic_input_wires[1].get() & ENCRYPTED_BOOT_WIRE_BIT != 0;

        // Tell Caliptra to download firmware from the recovery interface.
        // Use RI_DOWNLOAD_ENCRYPTED_FIRMWARE when encrypted boot is requested.
        romtime::println!("[mcu-rom] Sending RI_DOWNLOAD_FIRMWARE command");
        let ri_cmd = if encrypted_boot {
            //romtime::println!("[mcu-rom] Sending RI_DOWNLOAD_ENCRYPTED_FIRMWARE command");
            CommandId::RI_DOWNLOAD_ENCRYPTED_FIRMWARE.into()
        } else {
            //romtime::println!("[mcu-rom] Sending RI_DOWNLOAD_FIRMWARE command");
            CommandId::RI_DOWNLOAD_FIRMWARE.into()
        };

        if let Err(err) = soc_manager.start_mailbox_req_bytes(ri_cmd, &[]) {
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

        {
            let mut resp_buf = [0u8; core::mem::size_of::<MailboxRespHeader>()];
            if let Err(err) = soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
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
            }
        }
        mci.set_flow_checkpoint(McuRomBootStatus::RiDownloadFirmwareComplete.into());
        mci.set_flow_milestone(McuBootMilestones::RI_DOWNLOAD_COMPLETED.into());

        // Loading flash into the recovery flow is only possible in 2.1+.
        if flash_boot {
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

        if encrypted_boot {
            // --- Encrypted firmware boot flow ---
            // In encrypted mode, Caliptra RT loads firmware to MCU SRAM but does NOT
            // set FW_EXEC_CTRL[2] and does NOT reset MCU. We skip wait_for_firmware_ready()
            // and instead wait for Caliptra RT to be ready for runtime commands, then
            // decrypt the firmware ourselves.
            romtime::println!("[mcu-rom] Encrypted boot: waiting for Caliptra RT to be ready");
            while !soc.ready_for_runtime() {}
            mci.set_flow_checkpoint(McuRomBootStatus::CaliptraRuntimeReady.into());

            // Query ciphertext size and SHA-384 digest via GET_MCU_FW_SIZE.
            // Caliptra RT strips the 16-byte GCM tag from the size and
            // computes SHA-384 over the ciphertext only during the recovery
            // flow, so MCU ROM can forward both directly to CM_AES_GCM_DECRYPT_DMA.
            let (ciphertext_size, sha384) = mailbox::get_mcu_fw_size(soc_manager);
            romtime::println!(
                "[mcu-rom] Encrypted boot: ciphertext size = {} bytes",
                ciphertext_size
            );

            // Decrypt firmware in MCU SRAM via CM_IMPORT + CM_AES_GCM_DECRYPT_DMA
            Self::decrypt_firmware(soc_manager, ciphertext_size, &sha384);
        } else {
            // --- Normal (unencrypted) firmware boot flow ---
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
                if !image_verifier.verify_header(header, &env.otp) {
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
            romtime::println!(
                "[mcu-rom] Waiting for Caliptra RT to be ready for runtime mailbox commands"
            );
            while !soc.ready_for_runtime() {}
            mci.set_flow_checkpoint(McuRomBootStatus::CaliptraRuntimeReady.into());
        }

        Self::rom_digest_integrity(soc_manager, true);

        // --- Common tail: field entropy, disable recovery, reset ---
        romtime::println!("[mcu-rom] Finished boot-mode-specific initialization");

        // program field entropy if requested
        if params.program_field_entropy.iter().any(|x| *x) {
            romtime::println!("[mcu-rom] Programming field entropy");
            mci.set_flow_checkpoint(McuRomBootStatus::FieldEntropyProgrammingStarted.into());
            Self::program_field_entropy(&params.program_field_entropy, soc_manager, mci);
            mci.set_flow_checkpoint(McuRomBootStatus::FieldEntropyProgrammingComplete.into());
        }

        env.i3c.disable_recovery();

        // Reset so FirmwareBootReset can jump to firmware
        romtime::println!("[mcu-rom] Resetting to boot firmware");
        mci.set_flow_checkpoint(McuRomBootStatus::ColdBootFlowComplete.into());
        mci.set_flow_milestone(McuBootMilestones::COLD_BOOT_FLOW_COMPLETE.into());
        mci.trigger_warm_reset();
        romtime::println!("[mcu-rom] ERROR: Still running after reset request!");
        fatal_error(McuError::ROM_COLD_BOOT_RESET_ERROR);
    }
}

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
    FuseParams, I3cMailboxHandler, I3cServicesModes, RomEnv, RomParameters, MCU_MEMORY_MAP,
};
use caliptra_api::mailbox::{
    CmImportReq, CmImportResp, CmKeyUsage, CmStableKeyType, Cmk, CommandId, FeProgReq,
    MailboxReqHeader, MailboxRespHeader, StashMeasurementReq, StashMeasurementResp, CMK_SIZE_BYTES,
    MAX_CMB_DATA_SIZE,
};
#[cfg(feature = "ocp-lock")]
use caliptra_api::mailbox::{
    OcpLockReportHekMetadataReq, OcpLockReportHekMetadataResp, OcpLockReportHekMetadataRespFlags,
};
use caliptra_api::{calc_checksum, CaliptraApiError};
use caliptra_api_types::{DeviceLifecycle, SecurityState};
use core::fmt::Write;
use core::ops::Deref;
use mcu_error::McuError;
use registers_generated::fuses;
use registers_generated::i3c::bits::RecIntfCfg;
#[cfg(feature = "ocp-lock")]
use romtime::ocp_lock::HekState;
use romtime::{
    CaliptraSoC, HexBytes, HexWord, LifecycleControllerState, LifecycleToken, McuBootMilestones,
    McuRomBootStatus,
};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use zerocopy::{transmute, FromBytes, Immutable, IntoBytes, KnownLayout};

// TODO: Remove these local CM_AES_GCM_DECRYPT_DMA definitions once caliptra-sw
// includes the DMA decrypt command and the caliptra-sw git pointer is updated.

/// Command ID for CM_AES_GCM_DECRYPT_DMA ("CMDD").
const CMD_CM_AES_GCM_DECRYPT_DMA: u32 = 0x434D_4444;

/// Maximum AAD size for CM_AES_GCM_DECRYPT_DMA command.
const CM_AES_GCM_DECRYPT_DMA_MAX_AAD_SIZE: usize = MAX_CMB_DATA_SIZE;

/// Request struct for the CM_AES_GCM_DECRYPT_DMA mailbox command.
///
/// This command performs in-place AES-GCM decryption of data at an AXI address
/// using DMA. It first verifies the SHA-384 of the encrypted data, then
/// performs decryption.
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
struct CmAesGcmDecryptDmaReq {
    pub hdr: MailboxReqHeader,
    /// CMK (Cryptographic Mailbox Key) - 128 bytes
    pub cmk: Cmk,
    /// AES-GCM IV (12 bytes, as 3 x u32)
    pub iv: [u32; 3],
    /// AES-GCM tag (16 bytes, as 4 x u32)
    pub tag: [u32; 4],
    /// SHA-384 hash of the encrypted data (48 bytes)
    pub encrypted_data_sha384: [u8; 48],
    /// AXI address low 32 bits
    pub axi_addr_lo: u32,
    /// AXI address high 32 bits
    pub axi_addr_hi: u32,
    /// Length of data to decrypt in bytes
    pub length: u32,
    /// Length of AAD in bytes
    pub aad_length: u32,
    /// AAD data (0..=4095 bytes)
    pub aad: [u8; CM_AES_GCM_DECRYPT_DMA_MAX_AAD_SIZE],
}

impl Default for CmAesGcmDecryptDmaReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cmk: Cmk::default(),
            iv: [0u32; 3],
            tag: [0u32; 4],
            encrypted_data_sha384: [0u8; 48],
            axi_addr_lo: 0,
            axi_addr_hi: 0,
            length: 0,
            aad_length: 0,
            aad: [0u8; CM_AES_GCM_DECRYPT_DMA_MAX_AAD_SIZE],
        }
    }
}

/// Response struct for the CM_AES_GCM_DECRYPT_DMA mailbox command.
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
struct CmAesGcmDecryptDmaResp {
    pub hdr: MailboxRespHeader,
    /// Indicates whether the GCM tag was verified (1 = success, 0 = failure)
    pub tag_verified: u32,
}

/// Command ID for GET_MCU_FW_SIZE ("GMFS").
///
/// MCU ROM issues this command after Caliptra RT is ready for runtime mailbox
/// commands. Caliptra RT responds with the size of the MCU firmware image
/// (ciphertext + GCM tag) that was downloaded during the recovery flow.
// TODO: Remove once the caliptra-sw git pointer includes GET_MCU_FW_SIZE.
const CMD_GET_MCU_FW_SIZE: u32 = 0x474D_4653;

/// Response struct for GET_MCU_FW_SIZE mailbox command.
// TODO: Remove once the caliptra-sw git pointer includes GetMcuFwSizeResp.
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
struct GetMcuFwSizeResp {
    pub hdr: MailboxRespHeader,
    /// Ciphertext size in bytes (GCM tag excluded).
    pub size: u32,
    /// SHA-384 digest of the ciphertext (computed by Caliptra RT).
    pub sha384: [u8; 48],
}

impl Default for GetMcuFwSizeResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            size: 0,
            sha384: [0u8; 48],
        }
    }
}

/// Bit in `mci_reg_generic_input_wires[1]` that signals encrypted firmware boot.
/// When set, MCU ROM sends `RI_DOWNLOAD_ENCRYPTED_FIRMWARE` instead of `RI_DOWNLOAD_FIRMWARE`,
/// then decrypts the firmware in MCU SRAM after Caliptra RT finishes loading.
const ENCRYPTED_BOOT_WIRE_BIT: u32 = 1 << 28;

/// Test AES-256 key used for encrypted MCU firmware in sw-emulated models.
/// Must match `MCU_TEST_AES_KEY` in caliptra-sw hw-model.
const MCU_TEST_AES_KEY: [u8; 32] = [0xaa; 32];

/// Test AES-GCM IV used for encrypted MCU firmware in sw-emulated models.
/// Must match `MCU_TEST_IV` in caliptra-sw hw-model.
const MCU_TEST_IV: [u8; 12] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
];

/// GCM authentication tag size in bytes.
const GCM_TAG_SIZE: usize = 16;

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
        let tag: [u8; GCM_TAG_SIZE] = unsafe {
            let tag_ptr = (sram_base + ciphertext_size as usize) as *const [u8; GCM_TAG_SIZE];
            core::ptr::read_volatile(tag_ptr)
        };

        // Step 1: Import the test AES key
        let cmk = Self::cm_import_aes_key(soc_manager);

        // Step 2: Issue CM_AES_GCM_DECRYPT_DMA to decrypt in-place in MCU SRAM
        // The length must match what Caliptra RT used for sha384_mcu_sram(),
        // which is the ciphertext size (excluding the 16-byte GCM tag).
        Self::cm_aes_gcm_decrypt_dma(
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
        // Safety: MCU_MEMORY_MAP fields are linker-provided constants.
        let rom_size = unsafe { MCU_MEMORY_MAP.rom_size } as usize;
        let hashable_len = rom_size - DIGEST_SIZE;
        let rom = unsafe {
            core::slice::from_raw_parts(MCU_MEMORY_MAP.rom_offset as *const u32, hashable_len / 4)
        };

        let digest = mailbox::cm_sha384(soc_manager, rom);
        romtime::println!("[mcu-rom] MCU ROM digest: {}", HexBytes(&digest));

        let expected_digest: &[u8; DIGEST_SIZE] = unsafe {
            &*((MCU_MEMORY_MAP.rom_offset as usize + hashable_len) as *const [u8; DIGEST_SIZE])
        };
        romtime::println!(
            "[mcu-rom] MCU ROM expected digest: {}",
            HexBytes(expected_digest)
        );

        if digest != *expected_digest {
            romtime::println!("[mcu-rom] MCU ROM digest mismatch");
            fatal_error(McuError::ROM_COLD_BOOT_ROM_DIGEST_MISMATCH);
        }

        if stash {
            Self::stash_measurement(soc_manager, &digest);
        }
    }

    fn stash_measurement(soc_manager: &mut CaliptraSoC, measurement: &[u8; 48]) {
        let mut req = StashMeasurementReq {
            hdr: MailboxReqHeader { chksum: 0 },
            metadata: [0u8; 4],
            measurement: *measurement,
            context: [0u8; 48],
            svn: 0,
        };
        let cmd: u32 = CommandId::STASH_MEASUREMENT.into();
        let chksum = calc_checksum(cmd, &req.as_bytes()[4..]);
        req.hdr.chksum = chksum;

        if let Err(err) = soc_manager.start_mailbox_req_bytes(cmd, req.as_bytes()) {
            romtime::println!(
                "[mcu-rom] STASH_MEASUREMENT start error: {}",
                HexWord(Self::err_code(&err))
            );
            fatal_error(McuError::GENERIC_EXCEPTION);
        }

        let mut resp_buf = [0u8; core::mem::size_of::<StashMeasurementResp>()];
        if let Err(err) = soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
            romtime::println!(
                "[mcu-rom] STASH_MEASUREMENT finish error: {}",
                HexWord(Self::err_code(&err))
            );
            fatal_error(McuError::GENERIC_EXCEPTION);
        }

        let dpe_result = match resp_buf.get(8..12) {
            Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            None => {
                romtime::println!("[mcu-rom] STASH_MEASUREMENT response too short");
                fatal_error(McuError::GENERIC_EXCEPTION);
            }
        };

        if dpe_result != 0 {
            romtime::println!(
                "[mcu-rom] Stash Measurement failed: dpe_result={}",
                dpe_result
            );
            fatal_error(McuError::GENERIC_EXCEPTION);
        }
    }

    /// Import the test AES key via CM_IMPORT and return the CMK handle.
    fn cm_import_aes_key(soc_manager: &mut CaliptraSoC) -> Cmk {
        let mut input = [0u8; 64]; // MAX_KEY_SIZE = 64
        match input.get_mut(..32) {
            Some(dst) => dst.copy_from_slice(&MCU_TEST_AES_KEY),
            None => fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_START_ERROR),
        }

        let mut req = CmImportReq {
            hdr: MailboxReqHeader { chksum: 0 },
            key_usage: CmKeyUsage::Aes.into(),
            input_size: 32,
            input,
        };
        let cmd: u32 = CommandId::CM_IMPORT.into();
        let chksum = calc_checksum(cmd, &req.as_bytes()[4..]);
        req.hdr.chksum = chksum;

        if let Err(err) = soc_manager.start_mailbox_req_bytes(cmd, req.as_bytes()) {
            romtime::println!(
                "[mcu-rom] CM_IMPORT start error: {}",
                HexWord(Self::err_code(&err))
            );
            fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_START_ERROR);
        }

        let mut resp_buf = [0u8; core::mem::size_of::<CmImportResp>()];
        if let Err(err) = soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
            romtime::println!(
                "[mcu-rom] CM_IMPORT finish error: {}",
                HexWord(Self::err_code(&err))
            );
            fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_START_ERROR);
        }

        // Extract CMK from response: hdr(8) + cmk(128)
        let mut cmk_bytes = [0u8; CMK_SIZE_BYTES];
        match resp_buf.get(8..8 + CMK_SIZE_BYTES) {
            Some(src) => cmk_bytes.copy_from_slice(src),
            None => fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_START_ERROR),
        }
        Cmk(cmk_bytes)
    }

    /// Issue CM_AES_GCM_DECRYPT_DMA to decrypt firmware in-place via DMA.
    fn cm_aes_gcm_decrypt_dma(
        soc_manager: &mut CaliptraSoC,
        cmk: &Cmk,
        tag: &[u8; GCM_TAG_SIZE],
        encrypted_data_sha384: &[u8; 48],
        axi_addr: u64,
        ciphertext_len: u32,
    ) {
        let tag_u32: [u32; 4] = transmute!(*tag);
        let iv_u32: [u32; 3] = transmute!(MCU_TEST_IV);

        let mut req = CmAesGcmDecryptDmaReq {
            hdr: MailboxReqHeader { chksum: 0 },
            cmk: cmk.clone(),
            iv: iv_u32,
            tag: tag_u32,
            encrypted_data_sha384: *encrypted_data_sha384,
            axi_addr_lo: axi_addr as u32,
            axi_addr_hi: (axi_addr >> 32) as u32,
            length: ciphertext_len,
            aad_length: 0,
            aad: [0u8; CM_AES_GCM_DECRYPT_DMA_MAX_AAD_SIZE],
        };
        let cmd: u32 = CMD_CM_AES_GCM_DECRYPT_DMA;
        let chksum = calc_checksum(cmd, &req.as_bytes()[4..]);
        req.hdr.chksum = chksum;

        if let Err(err) = soc_manager.start_mailbox_req_bytes(cmd, req.as_bytes()) {
            romtime::println!(
                "[mcu-rom] CM_AES_GCM_DECRYPT_DMA start error: {}",
                HexWord(Self::err_code(&err))
            );
            fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_START_ERROR);
        }

        let mut resp_buf = [0u8; core::mem::size_of::<CmAesGcmDecryptDmaResp>()];
        if let Err(err) = soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
            romtime::println!(
                "[mcu-rom] CM_AES_GCM_DECRYPT_DMA finish error: {}",
                HexWord(Self::err_code(&err))
            );
            fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_FINISH_ERROR);
        }

        // CmAesGcmDecryptDmaResp: hdr(8) + tag_verified(4)
        let tag_verified = match resp_buf.get(8..12) {
            Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            None => {
                romtime::println!("[mcu-rom] CM_AES_GCM_DECRYPT_DMA response too short");
                fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_FINISH_ERROR);
            }
        };
        if tag_verified != 1 {
            romtime::println!(
                "[mcu-rom] GCM tag verification failed: tag_verified={}",
                tag_verified
            );
            fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_TAG_MISMATCH);
        }
    }

    /// Query the MCU firmware ciphertext size and SHA-384 digest from Caliptra RT
    /// via the GET_MCU_FW_SIZE mailbox command.
    ///
    /// Returns `(ciphertext_size, sha384)` where `ciphertext_size` is the
    /// ciphertext length in bytes (GCM tag excluded — Caliptra RT strips it)
    /// and `sha384` is the SHA-384 digest of the ciphertext only, computed
    /// by Caliptra RT during the recovery flow.
    fn get_mcu_fw_size(soc_manager: &mut CaliptraSoC) -> (u32, [u8; 48]) {
        let mut req = MailboxReqHeader { chksum: 0 };
        let chksum = calc_checksum(CMD_GET_MCU_FW_SIZE, &[]);
        req.chksum = chksum;

        if let Err(err) = soc_manager.start_mailbox_req_bytes(CMD_GET_MCU_FW_SIZE, req.as_bytes()) {
            romtime::println!(
                "[mcu-rom] GET_MCU_FW_SIZE start error: {}",
                HexWord(Self::err_code(&err))
            );
            fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_ACTIVATE_START_ERROR);
        }

        let mut resp_buf = [0u8; core::mem::size_of::<GetMcuFwSizeResp>()];
        if let Err(err) = soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
            romtime::println!(
                "[mcu-rom] GET_MCU_FW_SIZE finish error: {}",
                HexWord(Self::err_code(&err))
            );
            fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_ACTIVATE_FINISH_ERROR);
        }

        // GetMcuFwSizeResp: hdr(8) + size(4) + sha384(48)
        let size = match resp_buf.get(8..12) {
            Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            None => {
                romtime::println!("[mcu-rom] GET_MCU_FW_SIZE response too short");
                fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_ACTIVATE_FINISH_ERROR);
            }
        };
        let mut sha384 = [0u8; 48];
        match resp_buf.get(12..60) {
            Some(src) => sha384.copy_from_slice(src),
            None => {
                romtime::println!("[mcu-rom] GET_MCU_FW_SIZE response missing sha384");
                fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_ACTIVATE_FINISH_ERROR);
            }
        }
        (size, sha384)
    }

    /// Extract a u32 error code from a CaliptraApiError for logging.
    fn err_code(err: &CaliptraApiError) -> u32 {
        match err {
            CaliptraApiError::MailboxCmdFailed(c) => *c,
            _ => 0xdead_ffff,
        }
    }

    /// Execute the FIPS zeroization flow (continued).
    ///
    /// Per the Caliptra SS Hardware Specification, when the PPD signal is
    /// asserted the MCU ROM must:
    ///   1. Write 0xFFFF_FFFF to FC_FIPS_ZEROZATION mask to authorize the
    ///      fuse controller to zeroize non-secret fuses.  (**Done earlier in
    ///      `ColdBoot::run`, before `SS_CONFIG_DONE_STICKY` locks the
    ///      register.**)
    ///   2. Command Caliptra to zeroize UDS and field entropy via
    ///      ZEROIZE_UDS_FE (secret fuses can only be zeroized by Caliptra).
    ///   3. Request an LC transition to SCRAP (no token required).
    ///   4. Halt, waiting for the SoC to issue a cold reset.
    ///
    /// This function handles steps 2-4 and never returns.
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
        let chksum = calc_checksum(
            CommandId::ZEROIZE_UDS_FE.into(),
            &req.as_bytes()[core::mem::size_of::<MailboxReqHeader>()..],
        );
        req.hdr.chksum = chksum;

        if let Err(err) =
            soc_manager.start_mailbox_req_bytes(CommandId::ZEROIZE_UDS_FE.into(), req.as_bytes())
        {
            romtime::println!(
                "[mcu-rom] FIPS zeroization: ZEROIZE_UDS_FE send failed: {}",
                HexWord(Self::err_code(&err))
            );
            fatal_error(McuError::ROM_FIPS_ZEROIZATION_UDS_FE_START_ERROR);
        }
        {
            let mut resp_buf = [0u8; core::mem::size_of::<MailboxRespHeader>()];
            if let Err(err) = soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
                romtime::println!(
                    "[mcu-rom] FIPS zeroization: ZEROIZE_UDS_FE finish failed: {}",
                    HexWord(Self::err_code(&err))
                );
                fatal_error(McuError::ROM_FIPS_ZEROIZATION_UDS_FE_FINISH_ERROR);
            }
        }
        romtime::println!("[mcu-rom] ZEROIZE_UDS_FE completed successfully");
        mci.set_flow_checkpoint(McuRomBootStatus::FipsZeroizationUdsFeComplete.into());

        // Note: FC_FIPS_ZEROZATION mask was already set before
        // SS_CONFIG_DONE_STICKY (in ColdBoot::run) because the register is
        // locked once SS_CONFIG_DONE is asserted.

        // Step 2: Request LC transition to SCRAP. The transition is recorded
        // in OTP and takes effect permanently after the next cold reset.
        romtime::println!("[mcu-rom] Requesting LC transition to SCRAP for FIPS zeroization");
        mci.set_flow_checkpoint(McuRomBootStatus::FipsZeroizationScrapTransitionStarted.into());
        if let Err(err) = lc.transition(LifecycleControllerState::Scrap, &LifecycleToken([0u8; 16]))
        {
            romtime::println!(
                "[mcu-rom] FIPS zeroization: LC SCRAP transition failed: {}",
                HexWord(err.into())
            );
            fatal_error(McuError::ROM_FIPS_ZEROIZATION_LC_TRANSITION_ERROR);
        }

        // Step 3: Halt. The SoC must issue a cold reset for the SCRAP
        // transition and fuse zeroization to take effect.
        romtime::println!("[mcu-rom] FIPS zeroization complete; halting for cold reset");
        mci.set_flow_checkpoint(McuRomBootStatus::FipsZeroizationComplete.into());
        loop {}
    }

    /// Report HEK metadata to Caliptra ROM via the REPORT_HEK_METADATA mailbox command.
    #[cfg(feature = "ocp-lock")]
    fn report_hek_metadata(hek_state: Option<HekState>, soc_manager: &mut romtime::CaliptraSoC) {
        if cfg!(feature = "core_test") {
            return;
        }

        let Some(hek_state) = hek_state else {
            romtime::println!(
                "[mcu-rom] No valid active HEK state. Skipping reporting HEK metadata."
            );
            return;
        };

        romtime::println!("[mcu-rom] Reporting HEK metadata");

        let mut req = OcpLockReportHekMetadataReq {
            total_slots: hek_state.total_slots as u16,
            active_slots: hek_state.active_slot as u16,
            seed_state: hek_state.active_state.into(),
            ..Default::default()
        };
        let cmd: u32 = CommandId::OCP_LOCK_REPORT_HEK_METADATA.into();
        let chksum = calc_checksum(
            cmd,
            &req.as_bytes()[core::mem::size_of::<MailboxReqHeader>()..],
        );
        req.hdr.chksum = chksum;

        if let Err(err) = soc_manager.start_mailbox_req_bytes(cmd, req.as_bytes()) {
            romtime::println!(
                "[mcu-rom] REPORT_HEK_METADATA start error: {}",
                HexWord(Self::err_code(&err))
            );
            fatal_error(McuError::ROM_COLD_BOOT_HEK_REPORT_ERROR);
        }

        let mut resp_buf = [0u8; core::mem::size_of::<OcpLockReportHekMetadataResp>()];
        if let Err(err) = soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
            romtime::println!(
                "[mcu-rom] REPORT_HEK_METADATA finish error: {}",
                HexWord(Self::err_code(&err))
            );
            fatal_error(McuError::ROM_COLD_BOOT_HEK_REPORT_ERROR);
        }

        let resp: OcpLockReportHekMetadataResp = transmute!(resp_buf);
        let caliptra_hek_available = resp
            .flags
            .contains(OcpLockReportHekMetadataRespFlags::HEK_AVAILABLE);
        romtime::println!(
            "[mcu-rom] Caliptra HEK available: {}",
            caliptra_hek_available
        );
    }
}

/// Attempts DOT recovery using available recovery mechanisms.
/// The order is determined by `params.dot_recovery_policy`.
/// If recovery succeeds, triggers a warm reset (never returns).
/// If recovery fails or no handler is available, returns the last error (if any).
fn attempt_dot_recovery(
    env: &mut RomEnv,
    dot_fuses: &crate::DotFuses,
    params: &RomParameters,
    dot_flash: &dyn crate::hil::FlashStorage,
    key_type: CmStableKeyType,
) -> Option<McuError> {
    use crate::DotRecoveryPolicy;

    if params.dot_recovery_policy == DotRecoveryPolicy::None {
        return None;
    }

    let recovery_handler = params.dot_recovery_handler?;
    romtime::println!("[mcu-rom] Attempting DOT recovery via backup blob");
    match device_ownership_transfer::dot_recovery_flow(
        env,
        dot_fuses,
        recovery_handler,
        dot_flash,
        key_type,
    ) {
        Ok(()) => {
            romtime::println!("[mcu-rom] DOT backup recovery succeeded, resetting");
            env.mci.trigger_warm_reset();
            fatal_error(McuError::ROM_COLD_BOOT_RESET_ERROR);
        }
        Err(err) => {
            romtime::println!(
                "[mcu-rom] DOT backup recovery failed: {}",
                HexWord(err.into())
            );
            Some(err)
        }
    }
}

/// Attempts DOT override using the recovery transport if available.
/// DOT_OVERRIDE happens in recovery mode when the blob is corrupted/invalid.
/// If override succeeds, triggers a warm reset (never returns).
/// If override fails or no transport is available, returns to caller.
fn attempt_dot_override(
    env: &mut RomEnv,
    dot_fuses: &crate::DotFuses,
    params: &RomParameters,
    dot_flash: &dyn crate::hil::FlashStorage,
    key_type: CmStableKeyType,
) {
    if let Some(transport) = params.dot_recovery_transport {
        if params.dot_recovery_wdt_timeout > 0 {
            env.mci.configure_wdt(params.dot_recovery_wdt_timeout, 1);
        }
        romtime::println!("[mcu-rom] Attempting DOT override via challenge/response");
        match device_ownership_transfer::dot_override_challenge_flow(
            env, dot_fuses, transport, dot_flash, key_type,
        ) {
            Ok(()) => {
                romtime::println!("[mcu-rom] DOT override succeeded, resetting");
                env.mci.trigger_warm_reset();
                fatal_error(McuError::ROM_COLD_BOOT_RESET_ERROR);
            }
            Err(err) => {
                romtime::println!(
                    "[mcu-rom] DOT override failed: {}, continuing boot",
                    HexWord(err.into())
                );
            }
        }
    }
}

/// Enter I3C services mode if enabled in `RomParameters`.
///
/// Runs the I3C mailbox handler loop, processing commands until completion
/// or timeout. Sets boot status checkpoints on entry and exit.
fn enter_i3c_services(
    mci: &romtime::Mci,
    i3c_base: romtime::StaticRef<registers_generated::i3c::regs::I3c>,
    services: I3cServicesModes,
) {
    // Extend the watchdog timeout for I3C services since the loop may run
    // for an extended period waiting for commands from the BMC.
    mci.configure_wdt(u32::MAX as u64, 1);

    // Disable the recovery interface status registers.
    i3c_base
        .sec_fw_recovery_if_recovery_status
        .write(registers_generated::i3c::bits::RecoveryStatus::DevRecStatus.val(3));
    i3c_base
        .sec_fw_recovery_if_device_status_0
        .write(registers_generated::i3c::bits::DeviceStatus0::DevStatus.val(0));

    // Clear the virtual device address to fully deactivate the recovery
    // device on the I3C bus.
    i3c_base.stdby_ctrl_mode_stby_cr_virt_device_addr.set(0);

    romtime::println!("[mcu-rom-i3c-svc] Recovery disabled");

    mci.set_flow_checkpoint(McuRomBootStatus::I3cServicesStarted.into());
    let mut handler = I3cMailboxHandler::new(i3c_base, services);
    match handler.run() {
        Ok(()) => {
            mci.set_flow_checkpoint(McuRomBootStatus::I3cServicesComplete.into());
        }
        Err(err) => {
            romtime::println!("[mcu-rom] I3C services error: {}", HexWord(err.into()));
        }
    }
}

impl BootFlow for ColdBoot {
    fn run(env: &mut RomEnv, mut params: RomParameters) -> ! {
        #[cfg(feature = "ocp-lock")]
        let mut params = params;

        crate::call_hook(params.hooks, |h| h.pre_cold_boot());
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
        let i3c1 = &mut env.i3c1;
        let straps = env.straps.deref();
        if straps.active_i3c > 1 {
            romtime::println!(
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
        romtime::println!(
            "[mcu-rom] Active I3C core for recovery: {}",
            straps.active_i3c
        );

        romtime::println!("[mcu-rom] Setting Caliptra boot go");

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

        // Check for FIPS zeroization PPD signal early. The full zeroization
        // flow (including the Caliptra ZEROIZE_UDS_FE command) runs later,
        // after Caliptra is ready for mailbox commands.
        //
        // The FC_FIPS_ZEROZATION mask register must be written here, before
        // SS_CONFIG_DONE_STICKY is set, because that lock makes the register
        // read-only.
        let fips_zeroization = mci.fips_zeroization_requested();
        if fips_zeroization {
            romtime::println!(
                "[mcu-rom] FIPS zeroization PPD signal detected; \
                 will execute zeroization after Caliptra boot"
            );
            mci.set_flow_checkpoint(McuRomBootStatus::FipsZeroizationDetected.into());
            mci.set_fips_zeroization_mask();
            mci.set_flow_checkpoint(McuRomBootStatus::FipsZeroizationMaskSet.into());
        }

        if let Some((state, token)) = params.lifecycle_transition {
            mci.set_flow_checkpoint(McuRomBootStatus::LifecycleTransitionStarted.into());
            if let Err(err) = lc.transition(state, &token) {
                romtime::println!(
                    "[mcu-rom] Error transitioning lifecycle: {}",
                    HexWord(err.into())
                );
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
                    "[mcu-rom] Error burning lifecycle tokens {}; OTP status: {}",
                    HexWord(err.into()),
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

        let recovery_boot = ((mci.registers.mci_reg_generic_input_wires[1].get() & (1 << 29)) != 0)
            || params.request_recovery_boot;

        if recovery_boot && (params.image_provider_manager.is_none() || !cfg!(feature = "hw-2-1")) {
            romtime::println!(
                "Recovery boot requested but missing image provider or AXI bypass not enabled"
            );
            fatal_error(McuError::ROM_COLD_BOOT_RECOVERY_NOT_CONFIGURED_ERROR);
        }

        if recovery_boot {
            romtime::println!(
                "[mcu-rom] Configuring Caliptra watchdog timers for recovery boot: {} {}",
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
        if straps.active_i3c == 1 {
            romtime::println!("[mcu-rom] Initializing I3C1 (active)");
            i3c1.configure(straps.i3c1_static_addr, true);
        } else {
            i3c.configure(straps.i3c_static_addr, true);
        }
        mci.set_flow_checkpoint(McuRomBootStatus::I3cInitialized.into());

        romtime::println!(
            "[mcu-rom] Waiting for Caliptra to be ready for fuses: {}",
            soc.ready_for_fuses()
        );
        while !soc.ready_for_fuses() {}
        mci.set_flow_checkpoint(McuRomBootStatus::CaliptraReadyForFuses.into());

        romtime::println!("[mcu-rom] Writing fuses to Caliptra");

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
            romtime::println!("[mcu-rom] Error reading CPTRA_ITRNG_WINDOW_SIZE");
            fatal_error(McuError::ROM_OTP_READ_CPTRA_ITRNG_WINDOW_SIZE_ERROR);
        };
        let Ok(config0) = otp.read_entry(fuses::CPTRA_ITRNG_ENTROPY_CONFIG_0) else {
            romtime::println!("[mcu-rom] Error reading CPTRA_ITRNG_ENTROPY_CONFIG_0");
            fatal_error(McuError::ROM_OTP_READ_CPTRA_ITRNG_CONFIG0_ERROR);
        };
        let Ok(config1) = otp.read_entry(fuses::CPTRA_ITRNG_ENTROPY_CONFIG_1) else {
            romtime::println!("[mcu-rom] Error reading CPTRA_ITRNG_ENTROPY_CONFIG_1");
            fatal_error(McuError::ROM_OTP_READ_CPTRA_ITRNG_CONFIG1_ERROR);
        };
        soc.configure_itrng(crate::CptraItrngArgs {
            bypass_mode: params.itrng_entropy_bypass_mode,
            window_size: window_size as u16,
            config0,
            config1,
        });

        romtime::println!("[mcu-rom] Populating fuses");
        crate::call_hook(params.hooks, |h| h.pre_populate_fuses_to_caliptra());
        let _fuse_state = soc.populate_fuses(
            otp,
            mci,
            &mut FuseParams {
                #[cfg(feature = "ocp-lock")]
                ocp_lock_config: Some(&mut params.ocp_lock_config),
                vendor_key_policy: params.vendor_key_policy,
                ..Default::default()
            },
        );

        // Create handoff data
        romtime::handoff::HandoffData::write(romtime::handoff::HandoffArgs {
            #[cfg(feature = "ocp-lock")]
            hek_state: _fuse_state.hek_state.unwrap_or_default(),
        });

        mci.set_flow_checkpoint(McuRomBootStatus::FusesPopulatedToCaliptra.into());

        // Configure MCU mailbox AXI users before locking
        romtime::println!("[mcu-rom] Configuring MCU mailbox AXI users");
        let mcu_mbox_config = configure_mcu_mbox_axi_users(
            mci,
            &params.mci_mbox0_axi_users,
            &params.mci_mbox1_axi_users,
        );
        mci.set_flow_checkpoint(McuRomBootStatus::McuMboxAxiUsersConfigured.into());

        let size_value = params.mcu_fw_sram_exec_region_size.unwrap_or(
            (unsafe { MCU_MEMORY_MAP.sram_size } / 4096)
                - crate::MCU_SRAM_DEFAULT_PROTECTED_REGION_BLOCKS
                - 1,
        );
        mci.set_fw_sram_exec_region_size(size_value);

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
        crate::call_hook(params.hooks, |h| h.post_populate_fuses_to_caliptra());

        // If testing Caliptra Core, hang here until the test signals it to continue.
        if cfg!(feature = "core_test") {
            while mci.registers.mci_reg_generic_input_wires[1].get() & (1 << 31) == 0 {}
        }

        romtime::println!("[mcu-rom] Waiting for Caliptra Core boot FSM to be DONE");
        soc.wait_for_bootfsm_done(10_000_000);

        romtime::println!("[mcu-rom] Waiting for Caliptra to be ready for mbox",);
        while !soc.ready_for_mbox() {
            if soc.cptra_fw_fatal_error() {
                romtime::println!("[mcu-rom] Caliptra reported a fatal error");
                fatal_error(McuError::ROM_COLD_BOOT_CALIPTRA_FATAL_ERROR_BEFORE_MB_READY);
            }
            soc.check_hw_errors();
        }

        crate::call_hook(params.hooks, |h| h.post_caliptra_boot());
        romtime::println!("[mcu-rom] Caliptra is ready for mailbox commands",);
        mci.set_flow_checkpoint(McuRomBootStatus::CaliptraReadyForMailbox.into());

        // Execute full FIPS zeroization flow now that Caliptra is ready for
        // mailbox commands. This never returns (halts for cold reset).
        if fips_zeroization {
            ColdBoot::handle_fips_zeroization(mci, lc, &mut env.soc_manager);
        }

        // Report HEK metadata to Caliptra ROM
        #[cfg(feature = "ocp-lock")]
        Self::report_hek_metadata(_fuse_state.hek_state, &mut env.soc_manager);

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
            let mut dot_blob = [0u8; device_ownership_transfer::DOT_BLOB_SIZE];
            if let Err(err) = dot_flash.read(&mut dot_blob, 0) {
                romtime::println!(
                    "[mcu-rom] Fatal error reading DOT blob from flash: {}",
                    HexWord(usize::from(err) as u32)
                );
                fatal_error(McuError::ROM_COLD_BOOT_DOT_ERROR);
            }
            mci.set_flow_checkpoint(McuRomBootStatus::DeviceOwnershipTransferFlashRead.into());

            if dot_blob.iter().all(|&b| b == 0) || dot_blob.iter().all(|&b| b == 0xFF) {
                if dot_fuses.enabled && dot_fuses.is_locked() {
                    // DOT is in ODD state but blob is empty/corrupt.
                    // Try backup-blob recovery first, then override.
                    let key_type = params
                        .dot_stable_key_type
                        .unwrap_or(CmStableKeyType::IDevId);
                    let recovery_err =
                        attempt_dot_recovery(env, &dot_fuses, &params, dot_flash, key_type);
                    // Recovery success triggers a warm reset and never returns.
                    // If recovery failed or was not configured, try override.
                    attempt_dot_override(env, &dot_fuses, &params, dot_flash, key_type);
                    // Try I3C services if DOT_RECOVERY enabled
                    if let Some(services) = params.i3c_services {
                        if services.contains(I3cServicesModes::DOT_RECOVERY) {
                            enter_i3c_services(&env.mci, i3c_base, services);
                        }
                    }
                    romtime::println!(
                        "[mcu-rom] DOT fuses are initialized but DOT blob is empty/corrupt"
                    );
                    fatal_error(recovery_err.unwrap_or(McuError::ROM_COLD_BOOT_DOT_ERROR));
                }
                romtime::println!("[mcu-rom] DOT blob is empty; skipping DOT flow");
                device_ownership_transfer::load_owner_pkhash(&env.otp)
            } else {
                let dot_blob = DotBlob::read_from_bytes(&dot_blob).unwrap();
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
                        // DOT flow failed (e.g., HMAC verification) - attempt recovery/override if in ODD state
                        if dot_fuses.is_locked() {
                            let key_type = params
                                .dot_stable_key_type
                                .unwrap_or(CmStableKeyType::IDevId);
                            let recovery_err =
                                attempt_dot_recovery(env, &dot_fuses, &params, dot_flash, key_type);
                            // Recovery success triggers a warm reset and never returns.
                            // If recovery failed or was not configured, try override.
                            attempt_dot_override(env, &dot_fuses, &params, dot_flash, key_type);
                            if let Some(e) = recovery_err {
                                romtime::println!(
                                    "[mcu-rom] DOT recovery failed: {}",
                                    HexWord(e.into())
                                );
                            }
                            // Try I3C services if DOT_RECOVERY enabled
                            if let Some(services) = params.i3c_services {
                                if services.contains(I3cServicesModes::DOT_RECOVERY) {
                                    enter_i3c_services(&env.mci, i3c_base, services);
                                }
                            }
                        }
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

        // OCP LOCK and stable owner key are mutually exclusive HEK consumers.
        #[cfg(feature = "stable-owner-key")]
        {
            // Derive stable owner key using the OTP personalization seed.
            if let Err(err) = crate::stable_owner_key::derive_stable_owner_key(env) {
                romtime::println!(
                    "[mcu-rom] Stable owner key derivation failed: {}",
                    HexWord(err.into())
                );
                fatal_error(err);
            }
        }

        // Enter I3C services unconditionally if force_i3c_services is set
        if params.force_i3c_services {
            if let Some(services) = params.i3c_services {
                enter_i3c_services(&env.mci, i3c_base, services);
            }
        }

        // Re-borrow after DOT flow (which took &mut env).
        let mci = &env.mci;
        let soc = &env.soc;

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

        crate::call_hook(params.hooks, |h| h.pre_load_firmware());
        if let Err(err) = env.soc_manager.start_mailbox_req_bytes(ri_cmd, &[]) {
            match err {
                CaliptraApiError::MailboxCmdFailed(code) => {
                    romtime::println!("[mcu-rom] Error sending mailbox command: {}", HexWord(code));
                }
                _ => {
                    romtime::println!(
                        "[mcu-rom] Error sending mailbox command: {}",
                        HexWord(Self::err_code(&err))
                    );
                }
            }
            fatal_error(McuError::ROM_COLD_BOOT_START_RI_DOWNLOAD_ERROR);
        }
        mci.set_flow_checkpoint(McuRomBootStatus::RiDownloadFirmwareCommandSent.into());

        {
            let mut resp_buf = [0u8; core::mem::size_of::<MailboxRespHeader>()];
            if let Err(err) = env.soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
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

        // Loading images into the recovery flow is only possible in 2.1+.
        if recovery_boot {
            if let Some(ref mut manager) = params.image_provider_manager {
                romtime::println!("[mcu-rom] Starting recovery flow");
                mci.set_flow_checkpoint(McuRomBootStatus::FlashRecoveryFlowStarted.into());

                // Set AXI bypass mode once before the recovery flow
                i3c_base
                    .soc_mgmt_if_rec_intf_cfg
                    .modify(RecIntfCfg::RecIntfBypass::SET);

                crate::recovery::load_image_with_retry(i3c_base, manager)
                    .unwrap_or_else(|_| fatal_error(McuError::ROM_COLD_BOOT_LOAD_IMAGE_ERROR));

                romtime::println!("[mcu-rom] Recovery flow complete");
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
            while !soc.ready_for_runtime() {
                soc.check_hw_errors();
            }
            mci.set_flow_checkpoint(McuRomBootStatus::CaliptraRuntimeReady.into());

            // Query ciphertext size and SHA-384 digest via GET_MCU_FW_SIZE.
            // Caliptra RT strips the 16-byte GCM tag from the size and
            // computes SHA-384 over the ciphertext only during the recovery
            // flow, so MCU ROM can forward both directly to CM_AES_GCM_DECRYPT_DMA.
            let (ciphertext_size, sha384) = Self::get_mcu_fw_size(&mut env.soc_manager);
            romtime::println!(
                "[mcu-rom] Encrypted boot: ciphertext size = {} bytes",
                ciphertext_size
            );

            // Decrypt firmware in MCU SRAM via CM_IMPORT + CM_AES_GCM_DECRYPT_DMA
            Self::decrypt_firmware(&mut env.soc_manager, ciphertext_size, &sha384);
            crate::call_hook(params.hooks, |h| h.post_load_firmware());
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
            crate::call_hook(params.hooks, |h| h.post_load_firmware());

            // wait for the Caliptra RT to be ready
            romtime::println!(
                "[mcu-rom] Waiting for Caliptra RT to be ready for runtime mailbox commands"
            );
            while !soc.ready_for_runtime() {
                soc.check_hw_errors();
            }
            mci.set_flow_checkpoint(McuRomBootStatus::CaliptraRuntimeReady.into());
        }

        soc.pk_hash_volatile_lock(&env.otp, _fuse_state.pk_hash_idx);
        if env.otp.check_error().is_some() {
            romtime::println!("[mcu-rom] OTP error: {}", HexWord(env.otp.status()));
            env.otp.print_errors();
        }

        let stash_rom_digest = params.stash_rom_digest.unwrap_or(false);
        Self::rom_digest_integrity(&mut env.soc_manager, stash_rom_digest);

        // NOTE: Firmware manifest DOT command processing is intentionally
        // handled in FwBoot (fw_boot.rs), not here.  FwBoot runs after the
        // warm-reset chain, so firmware in MCU SRAM is always decrypted by
        // that point – even during encrypted boot.  Processing is gated by
        // `params.fw_manifest_dot_enabled` so integrators can opt in.

        // Re-borrow for the common tail section.
        let mci = &env.mci;

        // --- Common tail: field entropy, disable recovery, reset ---
        romtime::println!("[mcu-rom] Finished boot-mode-specific initialization");

        // program field entropy if requested
        if params.program_field_entropy.iter().any(|x| *x) {
            romtime::println!("[mcu-rom] Programming field entropy");
            mci.set_flow_checkpoint(McuRomBootStatus::FieldEntropyProgrammingStarted.into());
            Self::program_field_entropy(&params.program_field_entropy, &mut env.soc_manager, mci);
            mci.set_flow_checkpoint(McuRomBootStatus::FieldEntropyProgrammingComplete.into());
        }

        if params.recovery_status_open {
            romtime::println!("[mcu-rom] Leaving recovery interface open");
            if env.straps.active_i3c == 1 {
                env.i3c1.set_recovery_status_open();
            } else {
                env.i3c.set_recovery_status_open();
            }
        } else {
            romtime::println!("[mcu-rom] Disabling recovery interface");
            if env.straps.active_i3c == 1 {
                env.i3c1.disable_recovery();
            } else {
                env.i3c.disable_recovery();
            }
        }

        // Reset so FirmwareBootReset can jump to firmware
        romtime::println!("[mcu-rom] Resetting to boot firmware");
        mci.set_flow_checkpoint(McuRomBootStatus::ColdBootFlowComplete.into());
        mci.set_flow_milestone(McuBootMilestones::COLD_BOOT_FLOW_COMPLETE.into());

        #[cfg(feature = "test-force-hitless-update")]
        {
            use registers_generated::mci::bits::ResetReason;
            use tock_registers::interfaces::ReadWriteable;
            // Replace FwBootUpdReset with FwHitlessUpdReset so the emulator
            // preserves the hitless bit across this MCU reset and the ROM
            // re-enters as `FirmwareHitlessUpdate`. Only used by the
            // fw-manifest-dot hitless integration test.
            romtime::println!("[mcu-rom] test-force-hitless-update: forcing hitless reset reason");
            mci.registers
                .mci_reg_reset_reason
                .modify(ResetReason::FwBootUpdReset::CLEAR + ResetReason::FwHitlessUpdReset::SET);
        }

        crate::call_hook(params.hooks, |h| h.post_cold_boot());
        mci.trigger_warm_reset();
        romtime::println!("[mcu-rom] ERROR: Still running after reset request!");
        fatal_error(McuError::ROM_COLD_BOOT_RESET_ERROR);
    }
}

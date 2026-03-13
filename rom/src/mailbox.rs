/*++

Licensed under the Apache-2.0 license.

File Name:

    mailbox.rs

Abstract:

    Helper functions for various mailbox commands.

--*/

use crate::{err_code, fatal_error};
use caliptra_api::calc_checksum;
use caliptra_api::mailbox::{
    CmImportReq, CmImportResp, CmKeyUsage, CmShaFinalReq, CmShaFinalResp, CmShaInitReq,
    CmShaInitResp, CmShaUpdateReq, Cmk, CommandId, MailboxReqHeader, MailboxRespHeader,
    StashMeasurementReq, StashMeasurementResp, CMB_SHA_CONTEXT_SIZE, CMK_SIZE_BYTES,
    MAX_CMB_DATA_SIZE,
};
use mcu_error::McuError;
use romtime::{CaliptraSoC, HexWord};
use zerocopy::{transmute, FromBytes, Immutable, IntoBytes, KnownLayout};

/// GCM authentication tag size in bytes.
pub const GCM_TAG_SIZE: usize = 16;

/// CmHashAlgorithm::Sha384 value (matches caliptra-api enum).
const CM_HASH_ALGORITHM_SHA384: u32 = 1;

// TODO: Remove these local CM_AES_GCM_DECRYPT_DMA definitions once caliptra-sw
// includes the DMA decrypt command and the caliptra-sw git pointer is updated.

/// Command ID for CM_AES_GCM_DECRYPT_DMA ("CMDD").
const CMD_CM_AES_GCM_DECRYPT_DMA: u32 = 0x434D_4444;

/// Maximum AAD size for CM_AES_GCM_DECRYPT_DMA command.
const CM_AES_GCM_DECRYPT_DMA_MAX_AAD_SIZE: usize = MAX_CMB_DATA_SIZE;

/// Test AES-256 key used for encrypted MCU firmware in sw-emulated models.
/// Must match `MCU_TEST_AES_KEY` in caliptra-sw hw-model.
const MCU_TEST_AES_KEY: [u8; 32] = [0xaa; 32];

/// Test AES-GCM IV used for encrypted MCU firmware in sw-emulated models.
/// Must match `MCU_TEST_IV` in caliptra-sw hw-model.
const MCU_TEST_IV: [u8; 12] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
];

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

/// Import the test AES key via CM_IMPORT and return the CMK handle.
pub fn cm_import_aes_key(soc_manager: &mut CaliptraSoC) -> Cmk {
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
            HexWord(err_code(&err))
        );
        fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_START_ERROR);
    }

    let mut resp_buf = [0u8; core::mem::size_of::<CmImportResp>()];
    if let Err(err) = soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
        romtime::println!(
            "[mcu-rom] CM_IMPORT finish error: {}",
            HexWord(err_code(&err))
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
pub fn cm_aes_gcm_decrypt_dma(
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
            HexWord(err_code(&err))
        );
        fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_START_ERROR);
    }

    let mut resp_buf = [0u8; core::mem::size_of::<CmAesGcmDecryptDmaResp>()];
    if let Err(err) = soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
        romtime::println!(
            "[mcu-rom] CM_AES_GCM_DECRYPT_DMA finish error: {}",
            HexWord(err_code(&err))
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
pub fn get_mcu_fw_size(soc_manager: &mut CaliptraSoC) -> (u32, [u8; 48]) {
    let mut req = MailboxReqHeader { chksum: 0 };
    let chksum = calc_checksum(CMD_GET_MCU_FW_SIZE, &[]);
    req.chksum = chksum;

    if let Err(err) = soc_manager.start_mailbox_req_bytes(CMD_GET_MCU_FW_SIZE, req.as_bytes()) {
        romtime::println!(
            "[mcu-rom] GET_MCU_FW_SIZE start error: {}",
            HexWord(err_code(&err))
        );
        fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_ACTIVATE_START_ERROR);
    }

    let mut resp_buf = [0u8; core::mem::size_of::<GetMcuFwSizeResp>()];
    if let Err(err) = soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
        romtime::println!(
            "[mcu-rom] GET_MCU_FW_SIZE finish error: {}",
            HexWord(err_code(&err))
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

/// Compute SHA-384 of data in SRAM using CM_SHA_INIT / UPDATE / FINAL
/// streaming commands. Returns the 48-byte digest.
///
/// Each phase (INIT, UPDATE, FINAL) is in a separate function so its large
/// request struct (~4 KiB each) lives in its own stack frame and is freed
/// before the next phase begins.  Without this split the MCU ROM stack
/// (<= 12 KiB) can overflow when all three structs coexist on one frame.
pub fn cm_sha384(soc_manager: &mut CaliptraSoC, rom_base: *const u8, rom_len: usize) -> [u8; 48] {
    // We need to stream the ROM in MAX_CMB_DATA_SIZE (4096) chunks.
    // If the data fits in one chunk, INIT carries it all and FINAL has input_size=0.

    let mut offset = 0;
    let first_chunk = rom_len.min(MAX_CMB_DATA_SIZE);

    // ---- CM_SHA_INIT ----
    let mut sha_context = cm_sha_init(soc_manager, rom_base, first_chunk);
    offset += first_chunk;

    // ---- CM_SHA_UPDATE (middle chunks) ----
    while rom_len - offset > MAX_CMB_DATA_SIZE {
        let chunk = MAX_CMB_DATA_SIZE;
        cm_sha_update(
            soc_manager,
            rom_base.wrapping_add(offset),
            chunk,
            &mut sha_context,
        );
        offset += chunk;
    }

    // ---- CM_SHA_FINAL ----
    let remaining = rom_len - offset;
    cm_sha_final(
        soc_manager,
        rom_base.wrapping_add(offset),
        remaining,
        sha_context,
    )
}

/// Send CM_SHA_INIT with the first chunk and return the SHA context.
#[inline(never)]
fn cm_sha_init(
    soc_manager: &mut CaliptraSoC,
    sram_addr: *const u8,
    chunk_len: usize,
) -> [u8; CMB_SHA_CONTEXT_SIZE] {
    let mut sha_req = CmShaInitReq {
        hdr: MailboxReqHeader { chksum: 0 },
        hash_algorithm: CM_HASH_ALGORITHM_SHA384,
        input_size: chunk_len as u32,
        input: [0u8; MAX_CMB_DATA_SIZE],
    };
    // Copy first chunk from SRAM
    // Safety: chunk_len is less than rom_size so we're always in-bounds.
    unsafe {
        core::ptr::copy_nonoverlapping(sram_addr, sha_req.input.as_mut_ptr(), chunk_len);
    }
    let cmd: u32 = CommandId::CM_SHA_INIT.into();
    let chksum = calc_checksum(cmd, &sha_req.as_bytes()[4..]);
    sha_req.hdr.chksum = chksum;

    if let Err(err) = soc_manager.start_mailbox_req_bytes(cmd, sha_req.as_bytes()) {
        romtime::println!(
            "[mcu-rom] CM_SHA_INIT start error: {}",
            HexWord(err_code(&err))
        );
        fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_START_ERROR);
    }
    let mut resp_buf = [0u8; core::mem::size_of::<CmShaInitResp>()];
    if let Err(err) = soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
        romtime::println!(
            "[mcu-rom] CM_SHA_INIT finish error: {:?} {}",
            err,
            HexWord(err_code(&err))
        );
        fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_START_ERROR);
    }
    // Extract SHA context from response: hdr(8) + context(CMB_SHA_CONTEXT_SIZE)
    let mut sha_context = [0u8; CMB_SHA_CONTEXT_SIZE];
    match resp_buf.get(8..8 + CMB_SHA_CONTEXT_SIZE) {
        Some(src) => sha_context.copy_from_slice(src),
        None => fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_START_ERROR),
    }
    sha_context
}

/// Send CM_SHA_UPDATE for one middle chunk and update the SHA context.
#[inline(never)]
fn cm_sha_update(
    soc_manager: &mut CaliptraSoC,
    sram_addr: *const u8,
    chunk_len: usize,
    sha_context: &mut [u8; CMB_SHA_CONTEXT_SIZE],
) {
    let mut update_req = CmShaUpdateReq {
        hdr: MailboxReqHeader { chksum: 0 },
        context: *sha_context,
        input_size: chunk_len as u32,
        input: [0u8; MAX_CMB_DATA_SIZE],
    };
    // Safety: chunk_len is less than rom_size so we're always in-bounds.
    unsafe {
        core::ptr::copy_nonoverlapping(sram_addr, update_req.input.as_mut_ptr(), chunk_len);
    }
    let cmd: u32 = CommandId::CM_SHA_UPDATE.into();
    let chksum = calc_checksum(cmd, &update_req.as_bytes()[4..]);
    update_req.hdr.chksum = chksum;

    if let Err(err) = soc_manager.start_mailbox_req_bytes(cmd, update_req.as_bytes()) {
        romtime::println!(
            "[mcu-rom] CM_SHA_UPDATE start error: {}",
            HexWord(err_code(&err))
        );
        fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_START_ERROR);
    }
    // Response is same layout as CmShaInitResp
    let mut resp_buf = [0u8; core::mem::size_of::<CmShaInitResp>()];
    if let Err(err) = soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
        romtime::println!(
            "[mcu-rom] CM_SHA_UPDATE finish error: {}",
            HexWord(err_code(&err))
        );
        fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_START_ERROR);
    }
    match resp_buf.get(8..8 + CMB_SHA_CONTEXT_SIZE) {
        Some(src) => sha_context.copy_from_slice(src),
        None => fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_START_ERROR),
    }
}

/// Send CM_SHA_FINAL with any remaining data and return the 48-byte digest.
#[inline(never)]
fn cm_sha_final(
    soc_manager: &mut CaliptraSoC,
    sram_addr: *const u8,
    remaining: usize,
    sha_context: [u8; CMB_SHA_CONTEXT_SIZE],
) -> [u8; 48] {
    let mut final_req = CmShaFinalReq {
        hdr: MailboxReqHeader { chksum: 0 },
        context: sha_context,
        input_size: remaining as u32,
        input: [0u8; MAX_CMB_DATA_SIZE],
    };
    if remaining > 0 {
        // Safety: rom_len in cm_sha384 must be <= the actual rom_size.
        unsafe {
            core::ptr::copy_nonoverlapping(sram_addr, final_req.input.as_mut_ptr(), remaining);
        }
    }
    let cmd: u32 = CommandId::CM_SHA_FINAL.into();
    let chksum = calc_checksum(cmd, &final_req.as_bytes()[4..]);
    final_req.hdr.chksum = chksum;

    if let Err(err) = soc_manager.start_mailbox_req_bytes(cmd, final_req.as_bytes()) {
        romtime::println!(
            "[mcu-rom] CM_SHA_FINAL start error: {}",
            HexWord(err_code(&err))
        );
        fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_START_ERROR);
    }
    let mut final_resp_buf = [0u8; core::mem::size_of::<CmShaFinalResp>()];
    if let Err(err) = soc_manager.finish_mailbox_resp_bytes(&mut final_resp_buf) {
        romtime::println!(
            "[mcu-rom] CM_SHA_FINAL finish error: {}",
            HexWord(err_code(&err))
        );
        fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_START_ERROR);
    }
    // CmShaFinalResp: hdr(8) + data_len(4) + hash(64)
    // For SHA-384, only the first 48 bytes of hash are valid.
    let mut digest = [0u8; 48];
    match final_resp_buf.get(12..12 + 48) {
        Some(src) => digest.copy_from_slice(src),
        None => fatal_error(McuError::ROM_COLD_BOOT_ENCRYPTED_FW_DECRYPT_START_ERROR),
    }
    digest
}

pub fn stash_measurement(soc_manager: &mut CaliptraSoC, measurement: &[u8; 48]) {
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
            HexWord(err_code(&err))
        );
        fatal_error(McuError::GENERIC_EXCEPTION);
    }

    let mut resp_buf = [0u8; core::mem::size_of::<StashMeasurementResp>()];
    if let Err(err) = soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
        romtime::println!(
            "[mcu-rom] STASH_MEASUREMENT finish error: {}",
            HexWord(err_code(&err))
        );
        fatal_error(McuError::GENERIC_EXCEPTION);
    }

    // StashMeasurementResp: hdr(8) + dpe_result(4)
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

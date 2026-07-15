// Licensed under the Apache-2.0 license

//! Raw Caliptra mailbox command execution for caller-owned wire buffers.
//!
//! This is for transport pass-through paths that already own a complete
//! command request/response buffer. It keeps checksum and mailbox error
//! handling in `caliptra-api-lite` without importing the full `caliptra-api`
//! crate.

use mcu_error::McuResult;

pub const CMD_SELF_TEST_START: u32 = 0x4650_4C54; // "FPLT"
pub const CMD_SELF_TEST_GET_RESULTS: u32 = 0x4650_4C67; // "FPLg"
pub const CMD_FW_INFO: u32 = 0x494E_464F; // "INFO"

pub const CMD_CM_SHA_INIT: u32 = 0x434D_5349; // "CMSI"
pub const CMD_CM_SHA_UPDATE: u32 = 0x434D_5355; // "CMSU"
pub const CMD_CM_SHA_FINAL: u32 = 0x434D_5346; // "CMSF"
pub const CMD_CM_HMAC: u32 = 0x434D_484D; // "CMHM"
pub const CMD_CM_HMAC_KDF_COUNTER: u32 = 0x434D_4B43; // "CMKC"
pub const CMD_CM_HKDF_EXTRACT: u32 = 0x434D_4B54; // "CMKT"
pub const CMD_CM_HKDF_EXPAND: u32 = 0x434D_4B50; // "CMKP"
pub const CMD_CM_IMPORT: u32 = 0x434D_494D; // "CMIM"
pub const CMD_CM_DELETE: u32 = 0x434D_444C; // "CMDL"
pub const CMD_CM_STATUS: u32 = 0x434D_5354; // "CMST"
pub const CMD_CM_RANDOM_GENERATE: u32 = 0x434D_5247; // "CMRG"
pub const CMD_CM_RANDOM_STIR: u32 = 0x434D_5253; // "CMRS"

pub const CMD_CM_AES_ENCRYPT_INIT: u32 = 0x434D_4149; // "CMAI"
pub const CMD_CM_AES_ENCRYPT_UPDATE: u32 = 0x434D_4155; // "CMAU"
pub const CMD_CM_AES_DECRYPT_INIT: u32 = 0x434D_414A; // "CMAJ"
pub const CMD_CM_AES_DECRYPT_UPDATE: u32 = 0x434D_4156; // "CMAV"

pub const CMD_CM_AES_GCM_ENCRYPT_INIT: u32 = 0x434D_4749; // "CMGI"
pub const CMD_CM_AES_GCM_ENCRYPT_UPDATE: u32 = 0x434D_4755; // "CMGU"
pub const CMD_CM_AES_GCM_ENCRYPT_FINAL: u32 = 0x434D_4746; // "CMGF"
pub const CMD_CM_AES_GCM_DECRYPT_INIT: u32 = 0x434D_4449; // "CMDI"
pub const CMD_CM_AES_GCM_DECRYPT_UPDATE: u32 = 0x434D_4455; // "CMDU"
pub const CMD_CM_AES_GCM_DECRYPT_FINAL: u32 = 0x434D_4446; // "CMDF"

pub const CMD_CM_ECDH_GENERATE: u32 = 0x434D_4547; // "CMEG"
pub const CMD_CM_ECDH_FINISH: u32 = 0x434D_4546; // "CMEF"
pub const CMD_CM_ECDSA_PUBLIC_KEY: u32 = 0x434D_4550; // "CMEP"
pub const CMD_CM_ECDSA_SIGN: u32 = 0x434D_4553; // "CMES"
pub const CMD_CM_ECDSA_VERIFY: u32 = 0x434D_4556; // "CMEV"
pub const CMD_CM_MLDSA_PUBLIC_KEY: u32 = 0x434D_4D50; // "CMMP"
pub const CMD_CM_MLDSA_SIGN: u32 = 0x434D_4D53; // "CMMS"
pub const CMD_CM_MLDSA_VERIFY: u32 = 0x434D_4D56; // "CMMV"

pub const CMD_PRODUCTION_AUTH_DEBUG_UNLOCK_REQ: u32 = 0x5044_5552; // "PDUR"
pub const CMD_PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN: u32 = 0x5044_5554; // "PDUT"
pub const MAILBOX_RESP_HEADER_SIZE: usize = 8;

pub fn mailbox_checksum(cmd: u32, data: &[u8]) -> u32 {
    crate::wire::calc_checksum(cmd, data)
}

pub async fn raw_mailbox_execute(cmd: u32, req: &mut [u8], rsp: &mut [u8]) -> McuResult<usize> {
    crate::wire::populate_checksum(cmd, req)?;
    crate::wire::mbox_execute(cmd, req, rsp).await
}

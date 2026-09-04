// Licensed under the Apache-2.0 license

//! Caliptra mailbox protocol constants needed by the SHA primitives.
//!
//! Mirrored from `caliptra-api` rev `bfccd8a` (`api/src/mailbox.rs`,
//! `api/src/checksum.rs`). The values are part of the Caliptra
//! mailbox **wire protocol**, not an implementation detail — drift
//! would also break Caliptra's own clients, so they are effectively
//! stable.
//!
//! What this crate avoids is not the `caliptra-api` *dependency* — that is a
//! hard dependency of the `mailbox-io` feature, used by
//! [`crate::firmware_update`] and [`crate::image_loader`] — but `caliptra-api`'s
//! large fixed-size request/response **values**, which would put multi-kilobyte
//! `[u8; N]` arrays on the stack of every consumer of [`crate::ApiAlloc`].
//! Mirroring the constants and building slim wire prefixes here keeps those
//! types out of the code paths, while `const _: () = assert!(...)` cross-checks
//! against `caliptra-api`'s `size_of` / `offset_of` (see [`crate::cert`]) keep
//! the mirror honest at compile time for free.

use crate::slice::copy_bytes;

// ---- Caliptra mailbox constants -------------------------------------------

/// Maximum payload bytes in any single `Cm*` mailbox request — the
/// fixed-size `input: [u8; MAX_CMB_DATA_SIZE]` tail field on
/// `caliptra-api`'s `CmSha*Req` structs.
#[allow(dead_code)] // only referenced from a `const _: () = assert!(...)` in sha.rs
pub(crate) const MAX_CMB_DATA_SIZE: usize = 4096;

/// SHA running-context size returned per `CmShaInit` /
/// `CmShaUpdate` — Caliptra's opaque "full running state".
/// SHA running-context size mirrored from `caliptra-api`. Used in
/// const asserts to keep our slim wire prefixes in sync with the
/// public hash-state size.
#[allow(dead_code)] // only referenced from `const _: ()` asserts
pub(crate) const CMB_SHA_CONTEXT_SIZE: usize = 200;

// ---- Command IDs (FourCC) -------------------------------------------------

pub(crate) const CMD_CM_SHA_INIT: u32 = 0x434D_5349; // "CMSI"
pub(crate) const CMD_CM_SHA_UPDATE: u32 = 0x434D_5355; // "CMSU"
pub(crate) const CMD_CM_SHA_FINAL: u32 = 0x434D_5346; // "CMSF"
pub(crate) const CMD_CM_RANDOM_GENERATE: u32 = 0x434D_5247; // "CMRG"
pub(crate) const CMD_ECDSA384_SIGNATURE_VERIFY: u32 = 0x4543_5632; // "ECV2"
pub(crate) const CMD_CM_DERIVE_STABLE_KEY: u32 = 0x494D_4453; // "CMDS"

/// Caliptra mailbox command ID for `AUTHORIZE_AND_STASH`.
/// Mirrored from `caliptra-api::CommandId::AUTHORIZE_AND_STASH`.
pub(crate) const CMD_AUTHORIZE_AND_STASH: u32 = 0x4154_5348; // "ATSH"

/// Caliptra mailbox command ID for `POPULATE_IDEV_MLDSA87_CERT`.
/// Mirrored from `caliptra-api::CommandId::POPULATE_IDEV_MLDSA87_CERT`.
pub(crate) const CMD_POPULATE_IDEV_MLDSA87_CERT: u32 = 0x4944_4D50; // "IDMP"

// ---- DPE (Caliptra `InvokeDpeCommand`) ------------------------------------

/// Caliptra mailbox command ID for `INVOKE_DPE_ECC384`.
/// Mirrored from `caliptra-api::CommandId::INVOKE_DPE_ECC384`.
pub(crate) const CMD_INVOKE_DPE: u32 = 0x4450_4543; // "DPEC"

/// Caliptra mailbox command ID for `INVOKE_DPE_MLDSA87`.
/// Mirrored from `caliptra-api::CommandId::INVOKE_DPE_MLDSA87`.
pub(crate) const CMD_INVOKE_DPE_MLDSA87: u32 = 0x4450_454D; // "DPEM"

/// Caliptra mailbox command ID for `CERTIFY_KEY_CHUNKS`.
/// Mirrored from `caliptra-api::CommandId::CERTIFY_KEY_CHUNKS`.
pub(crate) const CMD_CERTIFY_KEY_CHUNKS: u32 = 0x434B_4348; // "CKCH"

/// Caliptra mailbox command ID for the top-level `DPE_TAG_TCI` command.
/// Mirrored from `caliptra-api::CommandId::DPE_TAG_TCI`.
pub(crate) const CMD_DPE_TAG_TCI: u32 = 0x5451_4754; // "TGQT"

/// Caliptra mailbox command ID for the top-level `DPE_GET_TAGGED_TCI` command.
/// Mirrored from `caliptra-api::CommandId::DPE_GET_TAGGED_TCI`.
pub(crate) const CMD_DPE_GET_TAGGED_TCI: u32 = 0x4754_4744; // "GTGD"

/// DPE per-command-header magic (`CommandHdr::DPE_COMMAND_MAGIC`).
pub(crate) const DPE_COMMAND_MAGIC: u32 = 0x4450_4543; // "DPEC"

/// DPE per-response-header magic (`ResponseHdr::DPE_RESPONSE_MAGIC`).
pub(crate) const DPE_RESPONSE_MAGIC: u32 = 0x4450_4552; // "DPER"

/// DPE profile used by Caliptra's runtime DPE — P-384 / SHA-384.
/// Mirrored from `caliptra-api::DPE_PROFILE` (`DpeProfile::P384Sha384 = 4`).
pub const DPE_PROFILE_P384_SHA384: u32 = 4;

/// DPE profile used by Caliptra's runtime DPE — ML-DSA-87.
/// Mirrored from `caliptra-api::DpeProfile::Mldsa87 = 5`.
pub const DPE_PROFILE_MLDSA87: u32 = 5;

/// DPE `DeriveContext` command ID (`dpe::commands::Command::DERIVE_CONTEXT`).
pub(crate) const DPE_CMD_DERIVE_CONTEXT: u32 = 0x08;

/// DPE vendor `UpdateContextMeasurement` command ID.
pub(crate) const DPE_CMD_UPDATE_CONTEXT_MEASUREMENT: u32 = 0x8000_0000;

/// DPE `GetCertificateChain` command ID
/// (`dpe::commands::Command::GET_CERTIFICATE_CHAIN`).
pub(crate) const DPE_CMD_GET_CERTIFICATE_CHAIN: u32 = 0x10;

/// DPE `Sign` command ID (`dpe::commands::Command::SIGN`).
pub(crate) const DPE_CMD_SIGN: u32 = 0x0A;

/// DPE `RotateContextHandle` command ID
/// (`dpe::commands::Command::ROTATE_CONTEXT_HANDLE`).
pub(crate) const DPE_CMD_ROTATE_CONTEXT_HANDLE: u32 = 0x0e;

/// `QUOTE_PCRS_ECC384` command ID.
pub(crate) const CMD_QUOTE_PCRS_ECC384: u32 = 0x5043_5251; // "PCRQ"

/// `QUOTE_PCRS_MLDSA87` command ID.
pub(crate) const CMD_QUOTE_PCRS_MLDSA87: u32 = 0x5043_524d; // "PCRM"

/// `EXTEND_PCR` command ID.
pub(crate) const CMD_EXTEND_PCR: u32 = 0x5043_5245; // "PCRE"

/// `GET_IDEV_ECC384_CSR` command ID.
pub(crate) const CMD_GET_IDEV_ECC384_CSR: u32 = 0x4944_4352; // "IDCR"

/// `GET_IDEV_MLDSA87_CSR` command ID.
pub(crate) const CMD_GET_IDEV_MLDSA87_CSR: u32 = 0x4944_4d52; // "IDMR"

/// `GET_ATTESTED_ECC384_CSR` command ID.
pub(crate) const CMD_GET_ATTESTED_ECC384_CSR: u32 = 0x4145_4352; // "AECR"

/// `GET_ATTESTED_MLDSA87_CSR` command ID.
pub(crate) const CMD_GET_ATTESTED_MLDSA87_CSR: u32 = 0x414D_4352; // "AMCR"

/// `FE_PROG` (field-entropy program) command ID.
pub(crate) const CMD_FE_PROG: u32 = 0x4645_5052; // "FEPR"

/// `PRODUCTION_AUTH_DEBUG_UNLOCK_REQ` command ID.
pub(crate) const CMD_PRODUCTION_AUTH_DEBUG_UNLOCK_REQ: u32 = 0x5044_5552; // "PDUR"

/// `PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN` command ID.
pub(crate) const CMD_PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN: u32 = 0x5044_5554; // "PDUT"

/// Mailbox response header size: `chksum(4) + fips_status(4)`.
pub(crate) const MBOX_RESP_HEADER_SIZE: usize = 8;

// ---- Crypto Manager command IDs -------------------------------------------

pub(crate) const CMD_CM_ECDH_GENERATE: u32 = 0x434D_4547; // "CMEG"
pub(crate) const CMD_CM_ECDH_FINISH: u32 = 0x434D_4546; // "CMEF"
pub(crate) const CMD_CM_HMAC: u32 = 0x434D_484D; // "CMHM"
pub(crate) const CMD_CM_HKDF_EXTRACT: u32 = 0x434D_4B54; // "CMKT"
pub(crate) const CMD_CM_HKDF_EXPAND: u32 = 0x434D_4B50; // "CMKP"
pub(crate) const CMD_CM_IMPORT: u32 = 0x434D_494D; // "CMIM"
pub(crate) const CMD_CM_DELETE: u32 = 0x434D_444C; // "CMDL"
pub(crate) const CMD_CM_AES_GCM_SPDM_ENCRYPT_INIT: u32 = 0x434D_5345; // "CMSE"
pub(crate) const CMD_CM_AES_GCM_ENCRYPT_UPDATE: u32 = 0x434D_4755; // "CMGU"
pub(crate) const CMD_CM_AES_GCM_ENCRYPT_FINAL: u32 = 0x434D_4746; // "CMGF"
pub(crate) const CMD_CM_AES_GCM_SPDM_DECRYPT_INIT: u32 = 0x434D_5344; // "CMSD"
pub(crate) const CMD_CM_AES_GCM_DECRYPT_UPDATE: u32 = 0x434D_4455; // "CMDU"
pub(crate) const CMD_CM_AES_GCM_DECRYPT_FINAL: u32 = 0x434D_4446; // "CMDF"

// ---- Hash algorithm discriminator -----------------------------------------

pub(crate) const CM_HASH_ALGO_SHA384: u32 = 1;
pub(crate) const CM_HASH_ALGO_SHA512: u32 = 2;

// ---- Mailbox error mapping -------------------------------------------------

/// Map a mailbox error to an McuErrorCode, preserving Busy distinction.
#[inline]
pub(crate) fn map_mbox_err(
    e: caliptra_mcu_libsyscall_caliptra::mailbox::MailboxError,
) -> mcu_error::McuErrorCode {
    use caliptra_mcu_libsyscall_caliptra::mailbox::MailboxError;
    use caliptra_mcu_libtock_platform::ErrorCode;
    match e {
        MailboxError::ErrorCode(ErrorCode::Busy) => mcu_error::codes::MAILBOX_BUSY,
        _ => mcu_error::codes::INTERNAL_BUG,
    }
}

// ---- Checksum -------------------------------------------------------------

/// Calculate the Caliptra mailbox checksum:
/// `0 - (sum(cmd_le_bytes) + sum(data_bytes))`, wrapping.
///
/// Mirrors `caliptra-api::calc_checksum`.
pub(crate) fn calc_checksum(cmd: u32, data: &[u8]) -> u32 {
    let mut checksum = 0u32;
    for c in cmd.to_le_bytes().iter() {
        checksum = checksum.wrapping_add(*c as u32);
    }
    for d in data {
        checksum = checksum.wrapping_add(*d as u32);
    }
    0u32.wrapping_sub(checksum)
}

// ---- Mailbox execute -------------------------------------------------------

/// Execute a Caliptra mailbox command. Returns `MAILBOX_BUSY` on busy
/// — caller decides whether to retry.
pub(crate) async fn mbox_execute(
    cmd: u32,
    req: &[u8],
    rsp: &mut [u8],
) -> mcu_error::McuResult<usize> {
    let mbox = caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox::<
        caliptra_mcu_libsyscall_caliptra::DefaultSyscalls,
    >::new();
    mbox.execute(cmd, req, rsp).await.map_err(map_mbox_err)
}

/// Execute a mailbox command whose request is a header followed by a separate
/// contiguous payload, without concatenating the two into one buffer.
///
/// `header` is sent verbatim ahead of `payload`. Unlike a streamed send, the
/// payload is already in memory, so the mailbox is held only for the transfer.
pub(crate) async fn mbox_execute_slice(
    cmd: u32,
    header: Option<&[u8]>,
    payload: &[u8],
    rsp: &mut [u8],
) -> mcu_error::McuResult<usize> {
    let mbox = caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox::<
        caliptra_mcu_libsyscall_caliptra::DefaultSyscalls,
    >::new();
    mbox.execute_with_payload_slice(cmd, header, payload, rsp)
        .await
        .map_err(map_mbox_err)
}

// ---- Shared utilities -----------------------------------------------------

/// Round `n` up to the nearest multiple of 4 for mailbox alignment.
pub(crate) fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

/// Write the Caliptra mailbox checksum into the first 4 bytes of
/// `data`, which must have been zeroed in that position beforehand.
pub(crate) fn populate_checksum(cmd: u32, data: &mut [u8]) -> mcu_error::McuResult<()> {
    if data.len() < 4 {
        return Err(mcu_error::codes::INVARIANT);
    }
    let checksum = calc_checksum(cmd, data);
    let Some(dst) = data.get_mut(..4) else {
        return Err(mcu_error::codes::INVARIANT);
    };
    copy_bytes(dst, &checksum.to_le_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checksum_matches_caliptra_api() {
        // Vector lifted from caliptra-api::checksum tests.
        assert_eq!(calc_checksum(0xe8dc3994, &[0x83, 0xe7, 0x25]), 0xfffffbe0);
    }
}

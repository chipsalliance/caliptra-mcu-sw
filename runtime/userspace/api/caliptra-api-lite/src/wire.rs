// Licensed under the Apache-2.0 license

//! Caliptra mailbox protocol constants needed by the SHA primitives.
//!
//! Mirrored from `caliptra-api` rev `bfccd8a` (`api/src/mailbox.rs`,
//! `api/src/checksum.rs`). The values are part of the Caliptra
//! mailbox **wire protocol**, not an implementation detail — drift
//! would also break Caliptra's own clients, so they are effectively
//! stable.
//!
//! Keeping them here lets this crate stay free of the
//! `caliptra-api` dependency, which would otherwise be pulled into
//! every consumer of [`crate::Alloc`].

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

// ---- DPE (Caliptra `InvokeDpeCommand`) ------------------------------------

/// Caliptra mailbox command ID for `INVOKE_DPE`.
/// Mirrored from `caliptra-api::CommandId::INVOKE_DPE`.
pub(crate) const CMD_INVOKE_DPE: u32 = 0x4450_4543; // "DPEC"

/// DPE per-command-header magic (`CommandHdr::DPE_COMMAND_MAGIC`).
pub(crate) const DPE_COMMAND_MAGIC: u32 = 0x4450_4543; // "DPEC"

/// DPE per-response-header magic (`ResponseHdr::DPE_RESPONSE_MAGIC`).
pub(crate) const DPE_RESPONSE_MAGIC: u32 = 0x4450_4552; // "DPER"

/// DPE profile used by Caliptra's runtime DPE — P-384 / SHA-384.
/// Mirrored from `caliptra-api::DPE_PROFILE` (`DpeProfile::P384Sha384 = 4`).
pub(crate) const DPE_PROFILE_P384_SHA384: u32 = 4;

/// DPE `GetCertificateChain` command ID
/// (`dpe::commands::Command::GET_CERTIFICATE_CHAIN`).
pub(crate) const DPE_CMD_GET_CERTIFICATE_CHAIN: u32 = 0x10;

/// DPE `CertifyKey` command ID (`dpe::commands::Command::CERTIFY_KEY`).
pub(crate) const DPE_CMD_CERTIFY_KEY: u32 = 0x09;

/// DPE `Sign` command ID (`dpe::commands::Command::SIGN`).
pub(crate) const DPE_CMD_SIGN: u32 = 0x0A;

/// `QUOTE_PCRS_ECC384` command ID.
pub(crate) const CMD_QUOTE_PCRS_ECC384: u32 = 0x5043_5251; // "PCRQ"

/// `GET_ATTESTED_ECC384_CSR` command ID.
pub(crate) const CMD_GET_ATTESTED_ECC384_CSR: u32 = 0x4145_4352; // "AECR"

/// `GET_ATTESTED_MLDSA87_CSR` command ID.
pub(crate) const CMD_GET_ATTESTED_MLDSA87_CSR: u32 = 0x414D_4352; // "AMCR"

/// `FE_PROG` (field-entropy program) command ID.
pub(crate) const CMD_FE_PROG: u32 = 0x4645_5052; // "FEPR"

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
#[allow(dead_code)]
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
    data[..4].copy_from_slice(&checksum.to_le_bytes());
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

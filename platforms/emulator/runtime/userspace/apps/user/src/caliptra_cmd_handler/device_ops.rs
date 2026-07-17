// Licensed under the Apache-2.0 license

use caliptra_mcu_common_commands::{
    CaliptraCmdResult, CaliptraCompletionCode, DEBUG_UNLOCK_CHALLENGE_SIZE,
    DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE,
};
use caliptra_mcu_libsyscall_caliptra::mailbox::{Mailbox, MailboxError};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_platform::ErrorCode;
use constant_time_eq::constant_time_eq;
use mcu_caliptra_api_lite::{
    cm_hmac, cm_import, fe_prog, get_attested_csr_ecc384, get_attested_csr_mldsa87,
    request_debug_unlock_challenge, rng_generate, ApiAlloc, CmKeyUsage, McuErrorCode,
    PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD, PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN,
};

const ALGO_ECC_P384: u32 = 0x0001;
const ALGO_MLDSA87: u32 = 0x0002;

/// Symmetric test HMAC key used by emulator command-auth validator paths.
///
/// This is not a production secret source; production should provision or
/// derive authorization material outside firmware.
pub(crate) const TEST_AUTH_CMD_HMAC_KEY: [u8; 48] = [
    0x72, 0xec, 0x12, 0x02, 0x77, 0x69, 0xb9, 0xdc, 0x04, 0xbd, 0xd0, 0xc0, 0x86, 0xca, 0x1b, 0x20,
    0x2f, 0x47, 0x1e, 0xee, 0xf2, 0x8c, 0x2d, 0xa8, 0xc5, 0x4c, 0x75, 0xc2, 0x48, 0xa6, 0x80, 0x0a,
    0x11, 0xbf, 0xd5, 0xcd, 0x09, 0xed, 0x57, 0x0c, 0xb4, 0xc2, 0xa1, 0x37, 0x6b, 0xa2, 0xcb, 0xcd,
];

pub async fn request_debug_unlock<A: ApiAlloc>(
    alloc: &A,
    unlock_level: u8,
    out: &mut [u8],
) -> CaliptraCmdResult<usize> {
    let needed = DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE + DEBUG_UNLOCK_CHALLENGE_SIZE;
    if out.len() < needed {
        return Err(CaliptraCompletionCode::InsufficientResources);
    }

    request_debug_unlock_challenge(alloc, unlock_level, out)
        .await
        .map_err(map_mcu_err)
}

/// Relay a debug-unlock token to Caliptra.
///
/// The debug-unlock token is (potentially) delivered in streamed chunks, so
/// firmware cannot recompute a `MailboxReqHeader` checksum over data it never
/// fully buffers. The requester therefore supplies the checksum as part of a
/// complete Caliptra RT mailbox request, and both transports (MCU mailbox and
/// SPDM VDM) relay it as a pure pass-through — firmware never synthesizes a
/// header. This differs from other Caliptra commands, whose checksum the lite
/// API builds from in-firmware parameters.
pub async fn authorize_debug_unlock_token<A: ApiAlloc>(
    _alloc: &A,
    token_request: &[u8],
) -> CaliptraCmdResult<()> {
    // 8-byte response header is a write-only throwaway, so use a stack buffer.
    // `_alloc` is kept for a uniform device-op signature but ignored at this size.
    let mut resp_buf = [0u8; PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN];

    Mailbox::<DefaultSyscalls>::new()
        .execute_with_payload_slice(
            PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD,
            None,
            token_request,
            &mut resp_buf,
        )
        .await
        .map_err(map_mailbox_error)?;
    Ok(())
}

pub async fn export_attested_csr(
    device_key_id: u32,
    algorithm: u32,
    nonce: &[u8; 32],
    out: &mut [u8],
) -> CaliptraCmdResult<usize> {
    let result = match algorithm {
        ALGO_ECC_P384 => get_attested_csr_ecc384(device_key_id, nonce, out).await,
        ALGO_MLDSA87 => get_attested_csr_mldsa87(device_key_id, nonce, out).await,
        _ => return Err(CaliptraCompletionCode::InvalidParameter),
    };
    result.map_err(map_mcu_err)
}

pub async fn generate_auth_challenge<A: ApiAlloc>(alloc: &A) -> CaliptraCmdResult<[u8; 32]> {
    let mut challenge = [0u8; 32];
    rng_generate(alloc, &mut challenge)
        .await
        .map_err(map_mcu_err)?;
    Ok(challenge)
}

pub async fn verify_authorized_mac<A: ApiAlloc>(
    alloc: &A,
    key: &[u8],
    cmd_id: u32,
    payload: &[u8],
    challenge: &[u8; 32],
    mac: &[u8; 48],
) -> CaliptraCmdResult<()> {
    let cmk = cm_import(alloc, CmKeyUsage::Hmac, key)
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

    let input_len = core::mem::size_of::<u32>()
        .checked_add(payload.len())
        .and_then(|len| len.checked_add(challenge.len()))
        .filter(|len| *len <= 256)
        .ok_or(CaliptraCompletionCode::InsufficientResources)?;
    // Keep the larger staging buffer in scratch so it does not inflate task state.
    let mut hmac_input = alloc
        .alloc(input_len)
        .map_err(|_| CaliptraCompletionCode::InsufficientResources)?;
    let (cmd_out, remainder) = hmac_input
        .split_at_mut_checked(core::mem::size_of::<u32>())
        .ok_or(CaliptraCompletionCode::InsufficientResources)?;
    cmd_out.copy_from_slice(&cmd_id.to_be_bytes());
    let (payload_out, challenge_out) = remainder
        .split_at_mut_checked(payload.len())
        .ok_or(CaliptraCompletionCode::InsufficientResources)?;
    payload_out.copy_from_slice(payload);
    challenge_out.copy_from_slice(challenge);

    let mut computed_mac = [0u8; 48];
    let mac_len = cm_hmac(alloc, &cmk, &hmac_input, &mut computed_mac)
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    if mac_len != 48 {
        return Err(CaliptraCompletionCode::OperationFailed);
    }

    if constant_time_eq(&computed_mac, mac) {
        Ok(())
    } else {
        Err(CaliptraCompletionCode::AccessDenied)
    }
}

pub async fn program_field_entropy<A: ApiAlloc>(
    alloc: &A,
    partition: u32,
) -> CaliptraCmdResult<()> {
    fe_prog(alloc, partition).await.map_err(map_mcu_err)
}

pub(crate) fn map_mcu_err(e: McuErrorCode) -> CaliptraCompletionCode {
    use mcu_error::codes;
    if e == codes::MAILBOX_BUSY {
        CaliptraCompletionCode::CaliptraMailboxBusy
    } else if e == codes::INVARIANT || e == codes::INTERNAL_BUG {
        CaliptraCompletionCode::OperationFailed
    } else if e.domain() == mcu_error::domain::MEMORY {
        CaliptraCompletionCode::InsufficientResources
    } else {
        CaliptraCompletionCode::GeneralError
    }
}

pub(crate) fn map_mailbox_error(e: MailboxError) -> CaliptraCompletionCode {
    match e {
        MailboxError::ErrorCode(ErrorCode::Busy) => CaliptraCompletionCode::CaliptraMailboxBusy,
        MailboxError::ErrorCode(_) | MailboxError::MailboxError(_) => {
            CaliptraCompletionCode::OperationFailed
        }
    }
}

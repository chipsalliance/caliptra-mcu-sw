// Licensed under the Apache-2.0 license

use crate::protocol::*;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext, SHA384_HASH_SIZE};
use libapi_caliptra::error::CaliptraApiError;

pub const REQUESTER_CONTEXT_LEN: usize = 8;

// This is the `combined_spdm_prefix` length for signing context
pub const SPDM_SIGNING_CONTEXT_LEN: usize = SPDM_PREFIX_LEN + SPDM_CONTEXT_LEN;

pub const SPDM_PREFIX_LEN: usize = 64;
pub const SPDM_CONTEXT_LEN: usize = 36;

#[derive(Debug, PartialEq)]
pub enum SignCtxError {
    UnsupportedVersion,
    BufferTooSmall,
    InvalidSignCtxString,
    CaliptraApi(CaliptraApiError),
}

pub type SignatureCtxResult<T> = Result<T, SignCtxError>;

pub(crate) fn create_responder_signing_context(
    spdm_version: SpdmVersion,
    opcode: ReqRespCode,
) -> SignatureCtxResult<[u8; SPDM_SIGNING_CONTEXT_LEN]> {
    if spdm_version < SpdmVersion::V12 {
        Err(SignCtxError::UnsupportedVersion)?;
    }

    let mut combined_spdm_prefix = [0u8; SPDM_SIGNING_CONTEXT_LEN];

    let base_str = b"dmtf-spdm-v";
    let version_str = spdm_version.to_str().as_bytes();
    let mut spdm_prefix = [0u8; SPDM_PREFIX_LEN];

    let mut pos = 0;
    for _ in 0..4 {
        spdm_prefix[pos..pos + base_str.len()].copy_from_slice(base_str);
        pos += base_str.len();
        spdm_prefix[pos..pos + version_str.len()].copy_from_slice(version_str);
        pos += version_str.len();
        if pos % 16 != 0 {
            Err(SignCtxError::BufferTooSmall)?;
        }
    }

    let spdm_context = opcode
        .spdm_context_string()
        .map_err(|_| SignCtxError::InvalidSignCtxString)?;
    combined_spdm_prefix[..SPDM_PREFIX_LEN].copy_from_slice(&spdm_prefix);
    combined_spdm_prefix[SPDM_PREFIX_LEN..].copy_from_slice(&spdm_context);

    Ok(combined_spdm_prefix)
}

pub(crate) async fn get_tbs_via_response_code(
    spdm_version: SpdmVersion,
    resp_code: ReqRespCode,
    transcript_hash: [u8; SHA384_HASH_SIZE],
) -> SignatureCtxResult<[u8; SHA384_HASH_SIZE]> {
    if spdm_version < SpdmVersion::V12 {
        return Ok(transcript_hash);
    }
    let signing_context = create_responder_signing_context(spdm_version, resp_code)?;

    // Create the TBS (To-Be-Signed) message
    let mut tbs = [0u8; SHA384_HASH_SIZE];

    let mut message = [0u8; SPDM_SIGNING_CONTEXT_LEN + SHA384_HASH_SIZE];
    message[..SPDM_SIGNING_CONTEXT_LEN].copy_from_slice(&signing_context);
    message[SPDM_SIGNING_CONTEXT_LEN..].copy_from_slice(&transcript_hash);

    let mut hash_ctx = HashContext::new();

    hash_ctx
        .init(HashAlgoType::SHA384, Some(&message))
        .await
        .map_err(SignCtxError::CaliptraApi)?;

    hash_ctx
        .finalize(&mut tbs)
        .await
        .map_err(SignCtxError::CaliptraApi)?;
    Ok(tbs)
}

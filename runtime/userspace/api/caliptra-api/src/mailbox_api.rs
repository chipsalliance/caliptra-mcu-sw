// Licensed under the Apache-2.0 license

//! This module provides custom redefinitions for certain Caliptra mailbox API requests
//! and responses.
//!
//! These redefinitions are optimized to reduce the size of the structures
//! while maintaining compatibility with the original API. Careful attention is required
//! when modifying these definitions to ensure they remain consistent with the original API.
//!
//! # Constants
//! - `MAX_CRYPTO_MBOX_DATA_SIZE`: Maximum size of cryptographic mailbox data.
//! - `MAX_DPE_RESP_DATA_SIZE`: Maximum size of DPE response data.
//! - `MAX_ECC_CERT_SIZE`: Maximum size of an ECC certificate.
//! - `MAX_MLDSA_CERT_SIZE`: Maximum size of a MLDSA certificate.
//! - `MAX_CERT_CHUNK_SIZE`: Maximum size of a certificate chunk.
//! - `MAX_RANDOM_NUM_SIZE`: Maximum size of a random number and the rand_stir input.
//!
//! # Assertions
//! - Ensures that the redefined structures do not exceed the size of their original counterparts.
//!
//! # Structures
//! - `ShaInitReq`: Represents a request to initialize a SHA operation. Equivalent to `CmShaInitReq`.
//! - `ShaUpdateReq`: Represents a request to update a SHA operation with additional data. Equivalent to `CmShaUpdateReq`.
//! - `ShaFinalReq`: Represents a request to finalize a SHA operation. Equivalent to `CmShaFinalReq`.
//! - `DpeEcResp`: Represents a response for DPE commands with variable-length data. Equivalent to `InvokeDpeResp`.
//! - `CertifyEcKeyResp`: Represents a response for the "Certify Key" DPE command. Equivalent to `CertifyKeyResp`.
//! - `CertificateChainResp`: Represents a response containing a chunk of a certificate chain. Equivalent to `GetCertificateChainResp`.
//! - `RandomStirReq`: Represents a request to stir the random number generator. Equivalent to `CmRandomStirReq`.
//! - `RandomGenerateResp`: Represents a response for generating random numbers. Equivalent to `CmRandomGenerateResp`.
//!
//! # Enums
//! - `DpeResponse`: Enum representing various DPE command responses:
//!
//! # Usage
//! These structures and constants are intended for use in the Caliptra subsystem's mailbox
//! API, particularly for cryptographic and DPE-related operations.

use crate::error::CaliptraApiError;
use crate::error::CaliptraApiResult;
use caliptra_api::mailbox::CmRandomGenerateResp;
use caliptra_api::mailbox::{
    CmRandomStirReq, InvokeDpeResp, MailboxReqHeader, MailboxRespHeader, MailboxRespHeaderVarSize,
    CMB_SHA_CONTEXT_SIZE, MAX_CMB_DATA_SIZE,
};
use core::mem::size_of;
use dpe::context::ContextHandle;
use dpe::response::{CertifyKeyResp, GetCertificateChainResp, ResponseHdr, SignResp};
use dpe::DPE_PROFILE;
use libsyscall_caliptra::mailbox::{Mailbox, MailboxError};
use libtock_platform::ErrorCode;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const MAX_CRYPTO_MBOX_DATA_SIZE: usize = 1024;
pub const MAX_DPE_RESP_DATA_SIZE: usize = 2048;
pub const MAX_ECC_CERT_SIZE: usize = 1536;
pub const MAX_MLDSA_CERT_SIZE: usize = 17 * 1024;
pub const MAX_CERT_CHUNK_SIZE: usize = 1024;
pub const MAX_RANDOM_STIR_SIZE: usize = 48;
pub const MAX_RANDOM_NUM_SIZE: usize = 48;

const _: () = assert!(MAX_CRYPTO_MBOX_DATA_SIZE <= MAX_CMB_DATA_SIZE);
const _: () = assert!(size_of::<DpeEcResp>() <= size_of::<InvokeDpeResp>());
const _: () = assert!(size_of::<CertificateChainResp>() <= size_of::<GetCertificateChainResp>());
const _: () = assert!(size_of::<CertifyEcKeyResp>() <= MAX_DPE_RESP_DATA_SIZE);
const _: () = assert!(size_of::<CertifyEcKeyResp>() <= size_of::<CertifyKeyResp>());
const _: () = assert!(size_of::<RandomStirReq>() <= size_of::<CmRandomStirReq>());
const _: () = assert!(size_of::<RandomGenerateResp>() <= size_of::<CmRandomGenerateResp>());

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub(crate) struct ShaInitReq {
    pub hdr: MailboxReqHeader,
    pub hash_algorithm: u32,
    pub input_size: u32,
    pub input: [u8; MAX_CRYPTO_MBOX_DATA_SIZE],
}

// CM_SHA_UPDATE
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub(crate) struct ShaUpdateReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_SHA_CONTEXT_SIZE],
    pub input_size: u32,
    pub input: [u8; MAX_CRYPTO_MBOX_DATA_SIZE],
}

// CM_SHA_FINAL
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub(crate) struct ShaFinalReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_SHA_CONTEXT_SIZE],
    pub input_size: u32,
    pub input: [u8; 0],
}

// CM_RANDOM_STIR
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub(crate) struct RandomStirReq {
    pub hdr: MailboxReqHeader,
    pub input_size: u32,
    pub input: [u8; MAX_RANDOM_STIR_SIZE],
}

// CM_RANDOM_GENERATE
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub(crate) struct RandomGenerateResp {
    pub hdr: MailboxRespHeaderVarSize,
    pub data: [u8; MAX_RANDOM_NUM_SIZE],
}

impl Default for RandomGenerateResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeaderVarSize::default(),
            data: [0u8; MAX_RANDOM_NUM_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub(crate) struct DpeEcResp {
    pub hdr: MailboxRespHeader,
    pub data_size: u32,
    pub data: [u8; MAX_DPE_RESP_DATA_SIZE], // variable length
}
impl Default for DpeEcResp {
    fn default() -> Self {
        DpeEcResp {
            hdr: MailboxRespHeader::default(),
            data_size: 0,
            data: [0; MAX_DPE_RESP_DATA_SIZE],
        }
    }
}

// DPE Commands

#[allow(clippy::large_enum_variant)]
pub(crate) enum DpeResponse {
    CertifyKey(CertifyEcKeyResp),
    Sign(SignResp),
    GetCertificateChain(CertificateChainResp),
}

#[repr(C)]
#[derive(
    Debug,
    PartialEq,
    Eq,
    zerocopy::IntoBytes,
    zerocopy::TryFromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub(crate) struct CertifyEcKeyResp {
    pub resp_hdr: ResponseHdr,
    pub new_context_handle: ContextHandle,
    pub derived_pubkey_x: [u8; DPE_PROFILE.ecc_int_size()],
    pub derived_pubkey_y: [u8; DPE_PROFILE.ecc_int_size()],
    pub cert_size: u32,
    pub cert: [u8; MAX_ECC_CERT_SIZE],
}

#[repr(C)]
#[derive(
    Debug,
    PartialEq,
    Eq,
    zerocopy::TryFromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub(crate) struct CertificateChainResp {
    pub resp_hdr: ResponseHdr,
    pub certificate_size: u32,
    pub certificate_chain: [u8; MAX_CERT_CHUNK_SIZE],
}

pub async fn execute_mailbox_cmd(
    mailbox: &Mailbox,
    cmd: u32,
    req_bytes: &mut [u8],
    resp_bytes: &mut [u8],
) -> CaliptraApiResult<usize> {
    mailbox
        .populate_checksum(cmd, req_bytes)
        .map_err(CaliptraApiError::Syscall)?;
    match mailbox.execute(cmd, req_bytes, resp_bytes).await {
        Ok(size) => Ok(size),
        Err(MailboxError::ErrorCode(ErrorCode::Busy)) => Err(CaliptraApiError::MailboxBusy)?,
        Err(e) => Err(CaliptraApiError::Mailbox(e))?,
    }
}

// Licensed under the Apache-2.0 license

//! DPE primitives over Caliptra's `INVOKE_DPE` mailbox command, plus
//! the dedicated top-level `DPE_TAG_TCI` tagging command.
//!
//! The DPE command and response layouts are the `caliptra-dpe` definitions
//! (`caliptra_dpe::commands`, `caliptra_dpe::response`). Those types are
//! 4-byte aligned, while mailbox buffers carry no alignment guarantee, so
//! they are never borrowed in place: commands are built by value and written
//! with [`IntoBytes::write_to`], small responses are copied out with
//! [`TryFromBytes::try_read_from_bytes`], and the large ML-DSA layouts are
//! addressed by `offset_of!` so they stay in the caller's [`ScratchAlloc`]
//! buffer rather than on the stack.

use caliptra_api::mailbox::{
    AxiResponseInfo, GetTaggedTciReq, GetTaggedTciResp, InvokeDpeMldsa87Flags, InvokeDpeMldsa87Req,
    InvokeDpeReq, InvokeDpeResp, MailboxReqHeader, MldsaSignType, RevokeExportedCdiHandleReq,
    SignWithExportedEcdsaReq, SignWithExportedEcdsaResp, SignWithExportedMldsaReq,
    SignWithExportedMldsaResp, TagTciReq,
};
use caliptra_dpe::commands::{
    CertifyKeyCommand, CertifyKeyMldsa87Cmd, CertifyKeyP384Cmd, Command, CommandHdr,
    DeriveContextCmd, GetCertificateChainCmd, RotateCtxCmd, RotateCtxFlags, SignFlags,
    SignMldsa87Cmd, SignP384Cmd, UpdateContextMeasurementCmd,
};
use caliptra_dpe::context::ContextHandle;
use caliptra_dpe::response::{
    CertifyKeyMldsa87RespHdr, CertifyKeyP384RespHdr, DeriveContextExportedCdiRespHdr,
    DeriveContextResp, GetCertificateChainResp, NewHandleResp, ResponseHdr, SignMlDsaResp,
    SignP384Resp, UpdateContextMeasurementResp,
};
use caliptra_dpe::tci::TciMeasurement;
use core::{
    mem::{offset_of, size_of},
    ops::Deref,
};
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};
use mcu_error::McuResult;
use zerocopy::{Immutable, IntoBytes, TryFromBytes};

use crate::dma::AxiDmaTarget;
use crate::mldsa::{mldsa87_compute_mu, MLDSA87_CONTEXT_MAX_SIZE, MLDSA87_TR_SIZE};
use crate::shake::shake256_hash;
use crate::slice::{checked_slice_mut, copy_bytes, internal_slice};
use crate::wire::{
    calc_checksum, mbox_execute, mbox_execute_in_place, populate_checksum, CMD_CERTIFY_KEY_CHUNKS,
    CMD_DPE_GET_TAGGED_TCI, CMD_DPE_TAG_TCI, CMD_INVOKE_DPE, CMD_INVOKE_DPE_MLDSA87,
    CMD_REVOKE_EXPORTED_CDI_HANDLE, CMD_SIGN_WITH_EXPORTED_ECDSA, CMD_SIGN_WITH_EXPORTED_MLDSA,
    DPE_PROFILE_MLDSA87, DPE_PROFILE_P384_SHA384, DPE_RESPONSE_MAGIC, MBOX_RESP_HEADER_SIZE,
};
use crate::ScratchAlloc;

/// DPE `DeriveContext` request flags (`caliptra_dpe::commands::DeriveContextFlags`).
pub use caliptra_dpe::commands::DeriveContextFlags as DpeDeriveContextFlags;

/// DPE profile identifier used for DPE command dispatch.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DpeProfile {
    P384Sha384 = DPE_PROFILE_P384_SHA384,
    Mldsa87 = DPE_PROFILE_MLDSA87,
}

impl DpeProfile {
    pub const fn invoke_cmd_id(self) -> u32 {
        match self {
            Self::P384Sha384 => CMD_INVOKE_DPE,
            Self::Mldsa87 => CMD_INVOKE_DPE_MLDSA87,
        }
    }

    /// Length of the `INVOKE_DPE` mailbox framing this profile puts ahead of the DPE payload.
    const fn invoke_req_prefix_len(self) -> usize {
        match self {
            Self::P384Sha384 => INVOKE_DPE_REQ_PREFIX_LEN,
            Self::Mldsa87 => INVOKE_DPE_MLDSA87_REQ_PREFIX_LEN,
        }
    }
}

/// The `caliptra-dpe` profile carried in DPE command and response headers.
impl From<DpeProfile> for caliptra_dpe::DpeProfile {
    fn from(profile: DpeProfile) -> Self {
        match profile {
            DpeProfile::P384Sha384 => Self::P384Sha384,
            DpeProfile::Mldsa87 => Self::Mldsa87,
        }
    }
}

/// Length in bytes of the DPE key/UEID label used by every
/// `CertifyKey` / `Sign` call in this crate.
pub const DPE_LABEL_LEN: usize = 48;

/// Output format selector for `CertifyKey` — we only support the
/// X.509 leaf certificate form.
const DPE_CERTIFY_KEY_FORMAT_X509: u32 = CertifyKeyCommand::FORMAT_X509;

/// DPE context handle width.
pub const DPE_CONTEXT_HANDLE_SIZE: usize = ContextHandle::SIZE;

pub type DpeContextHandle = [u8; DPE_CONTEXT_HANDLE_SIZE];

/// Exported CDI handle width.
pub const EXPORTED_CDI_SIZE: usize = caliptra_dpe::MAX_EXPORTED_CDI_SIZE;

/// SHA-384 TCI measurement width used by DPE P-384 / SHA-384 `DeriveContext`.
pub const DPE_TCI_MEASUREMENT_SIZE: usize = caliptra_dpe::TCI_SIZE;

const DEFAULT_DPE_CONTEXT_HANDLE: DpeContextHandle = [0u8; DPE_CONTEXT_HANDLE_SIZE];

/// Upper bound on the X.509 leaf certificate Caliptra's DPE can
/// emit — fits both ECC-384 and ML-DSA-87 leaf certificates.
pub const DPE_MAX_LEAF_CERT_SIZE: usize = 10 * 1024;

/// Maximum bytes that may be fetched in a single
/// [`dpe_get_cert_chain_chunk`] call. Bounded well below the
/// `InvokeDpeResp::DATA_MAX_SIZE` of 8 KB so a single call fits in a
/// few bitmap-allocator slots.
pub const DPE_MAX_CHUNK_SIZE: usize = 1024;

/// External `mu` width consumed by DPE ML-DSA-87 `Sign`.
pub const DPE_MLDSA87_MU_SIZE: usize = 64;

/// ML-DSA-87 signature width returned by DPE `Sign`.
pub const DPE_MLDSA87_SIGNATURE_SIZE: usize = 4627;

/// SHA-384 digest width consumed by DPE P-384 `Sign`.
pub const DPE_P384_DIGEST_SIZE: usize = 48;

/// Maximum TBS payload length accepted by `SIGN_WITH_EXPORTED_MLDSA`.
pub const EXPORTED_CDI_MAX_MLDSA87_TBS_SIZE: usize =
    caliptra_api::mailbox::SignWithExportedMldsaReq::MAX_TBS_SIZE;

/// Typed input to DPE-backed attestation signing.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SigningInput<'a> {
    /// SHA-384 digest for ECDSA P-384.
    EccP384Digest(&'a [u8; DPE_P384_DIGEST_SIZE]),
    /// Pure ML-DSA-87 message with an explicit FIPS 204 signing context.
    Mldsa87Message {
        /// FIPS 204 `ctx`, at most [`MLDSA87_CONTEXT_MAX_SIZE`] bytes.
        context: &'a [u8],
        /// SPDM prefix bound by the signature.
        prefix: &'a [u8],
        /// Transcript hash bound by the signature.
        hash: &'a [u8],
    },
    /// Precomputed external `mu` for ML-DSA-87.
    Mldsa87Mu(&'a [u8; DPE_MLDSA87_MU_SIZE]),
}

impl SigningInput<'_> {
    /// DPE profile required by this signing input.
    pub const fn profile(&self) -> DpeProfile {
        match self {
            Self::EccP384Digest(_) => DpeProfile::P384Sha384,
            Self::Mldsa87Message { .. } | Self::Mldsa87Mu(_) => DpeProfile::Mldsa87,
        }
    }
}

/// Typed input to Exported-CDI signing (`SIGN_WITH_EXPORTED_ECDSA` / `SIGN_WITH_EXPORTED_MLDSA`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ExportedCdiSigningInput<'a> {
    /// SHA-384 digest (48 bytes) for ECDSA P-384 (`SIGN_WITH_EXPORTED_ECDSA`).
    EccP384Digest(&'a [u8; DPE_P384_DIGEST_SIZE]),
    /// Raw TBS bytes (up to [`EXPORTED_CDI_MAX_MLDSA87_TBS_SIZE`] bytes) for ML-DSA-87
    /// (`SIGN_WITH_EXPORTED_MLDSA`).
    Mldsa87Raw(&'a [u8]),
}

impl ExportedCdiSigningInput<'_> {
    /// DPE profile required by this exported-CDI signing input.
    pub const fn profile(&self) -> DpeProfile {
        match self {
            Self::EccP384Digest(_) => DpeProfile::P384Sha384,
            Self::Mldsa87Raw(_) => DpeProfile::Mldsa87,
        }
    }
}

// ---------------------------------------------------------------------------
// Mailbox framing layout
// ---------------------------------------------------------------------------

// `InvokeDpeReq`, `InvokeDpeMldsa87Req`, `InvokeDpeResp` and `SignWithExportedMldsaReq` end in a large variable-length array, so only the fixed framing ahead of it is addressed, by offset.

/// Length of the `InvokeDpeReq` framing (`hdr` + `data_size`) ahead of the DPE payload (`CommandHdr` + command body).
const INVOKE_DPE_REQ_PREFIX_LEN: usize = offset_of!(InvokeDpeReq, data);
const INVOKE_DPE_REQ_DATA_SIZE_OFF: usize = offset_of!(InvokeDpeReq, data_size);

/// Length of the `InvokeDpeMldsa87Req` framing (`hdr` + `flags` + `axi_response` + `data_size`) ahead of the DPE payload.
const INVOKE_DPE_MLDSA87_REQ_PREFIX_LEN: usize = offset_of!(InvokeDpeMldsa87Req, data);
const INVOKE_DPE_MLDSA87_REQ_FLAGS_OFF: usize = offset_of!(InvokeDpeMldsa87Req, flags);
const INVOKE_DPE_MLDSA87_REQ_AXI_RESPONSE_OFF: usize =
    offset_of!(InvokeDpeMldsa87Req, axi_response);
const INVOKE_DPE_MLDSA87_REQ_DATA_SIZE_OFF: usize = offset_of!(InvokeDpeMldsa87Req, data_size);

/// Length of the `InvokeDpeResp` framing (`hdr` + `data_size`) ahead of the DPE response payload.
const INVOKE_DPE_RESP_PREFIX_LEN: usize = offset_of!(InvokeDpeResp, data);
const INVOKE_DPE_RESP_DATA_SIZE_OFF: usize = offset_of!(InvokeDpeResp, data_size);

/// ECC P-384 signature size (r + s, 48 bytes each).
pub const DPE_P384_SIGNATURE_SIZE: usize = 96;

const TAG_TCI_REQ_LEN: usize = size_of::<TagTciReq>();
const GET_TAGGED_TCI_REQ_LEN: usize = size_of::<GetTaggedTciReq>();
/// Bytes of `GetTaggedTciResp` this module consumes. Caliptra's response also carries a trailing `svn` that is not read; the response buffer stops short of it.
const GET_TAGGED_TCI_RESP_LEN: usize = offset_of!(GetTaggedTciResp, svn);
const GET_TAGGED_TCI_RESP_CUMULATIVE_OFF: usize = offset_of!(GetTaggedTciResp, tci_cumulative);
const GET_TAGGED_TCI_RESP_CURRENT_OFF: usize = offset_of!(GetTaggedTciResp, tci_current);
const REVOKE_EXPORTED_CDI_HANDLE_REQ_LEN: usize = size_of::<RevokeExportedCdiHandleReq>();
pub const SIGN_WITH_EXPORTED_ECDSA_REQ_LEN: usize = size_of::<SignWithExportedEcdsaReq>();
pub const SIGN_WITH_EXPORTED_ECDSA_RESP_LEN: usize = size_of::<SignWithExportedEcdsaResp>();
const SIGN_WITH_EXPORTED_ECDSA_RESP_SIG_R_OFF: usize =
    offset_of!(SignWithExportedEcdsaResp, signature_r);
const SIGN_WITH_EXPORTED_ECDSA_RESP_SIG_S_OFF: usize =
    offset_of!(SignWithExportedEcdsaResp, signature_s);
pub const SIGN_WITH_EXPORTED_MLDSA_REQ_LEN: usize = size_of::<SignWithExportedMldsaReq>();
const SIGN_WITH_EXPORTED_MLDSA_REQ_CDI_OFF: usize =
    offset_of!(SignWithExportedMldsaReq, exported_cdi_handle);
const SIGN_WITH_EXPORTED_MLDSA_REQ_SIGN_TYPE_OFF: usize =
    offset_of!(SignWithExportedMldsaReq, sign_type);
const SIGN_WITH_EXPORTED_MLDSA_REQ_TBS_SIZE_OFF: usize =
    offset_of!(SignWithExportedMldsaReq, tbs_size);
const SIGN_WITH_EXPORTED_MLDSA_REQ_TBS_OFF: usize = offset_of!(SignWithExportedMldsaReq, tbs);
pub const SIGN_WITH_EXPORTED_MLDSA_RESP_LEN: usize = size_of::<SignWithExportedMldsaResp>();
const SIGN_WITH_EXPORTED_MLDSA_RESP_SIG_OFF: usize =
    offset_of!(SignWithExportedMldsaResp, signature);

// The `caliptra-api` layouts are pinned here so that a change in a future `caliptra-sw` revision fails the build instead of silently changing the bytes this module puts on, or expects from, the mailbox.
const _: () = assert!(INVOKE_DPE_REQ_DATA_SIZE_OFF == 4);
const _: () = assert!(INVOKE_DPE_MLDSA87_REQ_FLAGS_OFF == 4);
const _: () = assert!(INVOKE_DPE_MLDSA87_REQ_AXI_RESPONSE_OFF == 8);
const _: () = assert!(size_of::<AxiResponseInfo>() == 12);
const _: () = assert!(
    offset_of!(AxiResponseInfo, addr_lo) == 0
        && offset_of!(AxiResponseInfo, addr_hi) == 4
        && offset_of!(AxiResponseInfo, max_size) == 8
);
const _: () = assert!(InvokeDpeMldsa87Flags::EXTERNAL_AXI_RESPONSE.bits() == 1 << 31);
const _: () = assert!(INVOKE_DPE_MLDSA87_REQ_DATA_SIZE_OFF == 20);
const _: () = assert!(INVOKE_DPE_RESP_DATA_SIZE_OFF == MBOX_RESP_HEADER_SIZE);
const _: () = assert!(TAG_TCI_REQ_LEN == 4 + DPE_CONTEXT_HANDLE_SIZE + 4);
const _: () = assert!(offset_of!(TagTciReq, handle) == 4);
const _: () = assert!(offset_of!(TagTciReq, tag) == 4 + DPE_CONTEXT_HANDLE_SIZE);
const _: () = assert!(GET_TAGGED_TCI_REQ_LEN == 4 + 4);
const _: () = assert!(offset_of!(GetTaggedTciReq, tag) == 4);
const _: () = assert!(GET_TAGGED_TCI_RESP_LEN == MBOX_RESP_HEADER_SIZE + 48 + 48);
const _: () = assert!(GET_TAGGED_TCI_RESP_CUMULATIVE_OFF == MBOX_RESP_HEADER_SIZE);
const _: () =
    assert!(GET_TAGGED_TCI_RESP_CURRENT_OFF == MBOX_RESP_HEADER_SIZE + DPE_TCI_MEASUREMENT_SIZE);
const _: () = assert!(REVOKE_EXPORTED_CDI_HANDLE_REQ_LEN == 4 + EXPORTED_CDI_SIZE);
const _: () = assert!(offset_of!(RevokeExportedCdiHandleReq, exported_cdi_handle) == 4);
const _: () =
    assert!(SIGN_WITH_EXPORTED_ECDSA_REQ_LEN == 4 + EXPORTED_CDI_SIZE + DPE_P384_DIGEST_SIZE);
const _: () = assert!(offset_of!(SignWithExportedEcdsaReq, exported_cdi_handle) == 4);
const _: () = assert!(offset_of!(SignWithExportedEcdsaReq, tbs) == 4 + EXPORTED_CDI_SIZE);
const _: () = assert!(SIGN_WITH_EXPORTED_ECDSA_RESP_LEN == MBOX_RESP_HEADER_SIZE + 4 * 48);
const _: () = assert!(SIGN_WITH_EXPORTED_ECDSA_RESP_SIG_R_OFF == MBOX_RESP_HEADER_SIZE + 2 * 48);
const _: () = assert!(SIGN_WITH_EXPORTED_ECDSA_RESP_SIG_S_OFF == MBOX_RESP_HEADER_SIZE + 3 * 48);
const _: () = assert!(DPE_P384_SIGNATURE_SIZE == 2 * 48);
const _: () = assert!(SIGN_WITH_EXPORTED_MLDSA_REQ_CDI_OFF == 4);
const _: () = assert!(SIGN_WITH_EXPORTED_MLDSA_REQ_SIGN_TYPE_OFF == 4 + EXPORTED_CDI_SIZE);
const _: () = assert!(SIGN_WITH_EXPORTED_MLDSA_REQ_TBS_SIZE_OFF == 4 + EXPORTED_CDI_SIZE + 4);
const _: () = assert!(SIGN_WITH_EXPORTED_MLDSA_REQ_TBS_OFF == 4 + EXPORTED_CDI_SIZE + 4 + 4);
const _: () = assert!(
    SIGN_WITH_EXPORTED_MLDSA_REQ_TBS_OFF + EXPORTED_CDI_MAX_MLDSA87_TBS_SIZE
        == SIGN_WITH_EXPORTED_MLDSA_REQ_LEN
);
const _: () = assert!(
    SIGN_WITH_EXPORTED_MLDSA_RESP_SIG_OFF + DPE_MLDSA87_SIGNATURE_SIZE + 1
        == SIGN_WITH_EXPORTED_MLDSA_RESP_LEN
);

const GET_CERT_CHAIN_RESP_CERT_SIZE_OFF: usize =
    offset_of!(GetCertificateChainResp, certificate_size);
const GET_CERT_CHAIN_RESP_CHAIN_OFF: usize = offset_of!(GetCertificateChainResp, certificate_chain);

const SIGN_MLDSA87_REQ_LEN: usize = invoke_dpe_req_len::<SignMldsa87Cmd>(DpeProfile::Mldsa87);
const SIGN_MLDSA87_RESP_LEN: usize = INVOKE_DPE_RESP_PREFIX_LEN + size_of::<SignMlDsaResp>();
const SIGN_MLDSA87_RESP_HANDLE_OFF: usize = offset_of!(SignMlDsaResp, new_context_handle);
const SIGN_MLDSA87_RESP_SIG_OFF: usize = offset_of!(SignMlDsaResp, sig);
const SIGN_MLDSA87_RESP_PADDING_OFF: usize = offset_of!(SignMlDsaResp, _padding);
const CERTIFY_KEY_P384_RESP_PREFIX_LEN: usize = size_of::<CertifyKeyP384RespHdr>();
pub const CERTIFY_KEY_MLDSA87_PUBKEY_SIZE: usize = caliptra_image_types::MLDSA87_PUB_KEY_BYTE_SIZE;
pub const CERTIFY_KEY_MLDSA87_RESP_PREFIX_LEN: usize = size_of::<CertifyKeyMldsa87RespHdr>();
pub const CERTIFY_KEY_FLAG_USE_MLDSA: u32 =
    caliptra_api::mailbox::CertifyKeyChunksFlags::USE_MLDSA.bits();
const CERTIFY_KEY_CHUNKS_REQ_LEN: usize = size_of::<caliptra_api::mailbox::CertifyKeyChunksReq>();
const CERTIFY_KEY_CHUNKS_RESP_INFO_LEN: usize =
    size_of::<caliptra_api::mailbox::CertifyKeyChunksRespInfo>();
/// Peak scratch allocation during ML-DSA-87 signing: max of CertifyKey phase and Sign phase.
pub const DPE_MLDSA87_SIGN_SCRATCH_PEAK: usize = {
    let certify_key_phase = CERTIFY_KEY_CHUNKS_REQ_LEN
        + CERTIFY_KEY_CHUNKS_RESP_INFO_LEN
        + CERTIFY_KEY_MLDSA87_RESP_PREFIX_LEN
        + crate::shake::SHAKE256_CONTEXT_SIZE;
    let sign_phase = SIGN_MLDSA87_RESP_LEN;
    if certify_key_phase > sign_phase {
        certify_key_phase
    } else {
        sign_phase
    }
};
/// Peak scratch allocation during `dpe_derive_context_exported_cdi`
pub const DPE_DERIVE_CONTEXT_EXPORTED_CDI_SCRATCH_PEAK: usize = {
    let ecc = invoke_dpe_req_len::<DeriveContextCmd>(DpeProfile::P384Sha384);
    let mldsa = invoke_dpe_req_len::<DeriveContextCmd>(DpeProfile::Mldsa87);
    if mldsa > ecc {
        mldsa
    } else {
        ecc
    }
};

const CERTIFY_KEY_CHUNKS_MAX_REQ_SIZE: usize =
    if CERTIFY_KEY_MLDSA87_RESP_PREFIX_LEN > DPE_MAX_CHUNK_SIZE {
        CERTIFY_KEY_MLDSA87_RESP_PREFIX_LEN
    } else {
        DPE_MAX_CHUNK_SIZE
    };
const CERTIFY_KEY_P384_RESP_PUBKEY_X_OFF: usize =
    offset_of!(CertifyKeyP384RespHdr, derived_pubkey_x);
const CERTIFY_KEY_P384_RESP_PUBKEY_Y_OFF: usize =
    offset_of!(CertifyKeyP384RespHdr, derived_pubkey_y);
const CERTIFY_KEY_P384_RESP_CERT_SIZE_OFF: usize = offset_of!(CertifyKeyP384RespHdr, cert_size);
const CERTIFY_KEY_MLDSA87_RESP_PUBKEY_OFF: usize = offset_of!(CertifyKeyMldsa87RespHdr, pubkey);
const CERTIFY_KEY_MLDSA87_RESP_CERT_SIZE_OFF: usize =
    offset_of!(CertifyKeyMldsa87RespHdr, cert_size);

#[inline]
fn certify_key_prefix_len(profile: DpeProfile) -> usize {
    match profile {
        DpeProfile::P384Sha384 => CERTIFY_KEY_P384_RESP_PREFIX_LEN,
        DpeProfile::Mldsa87 => CERTIFY_KEY_MLDSA87_RESP_PREFIX_LEN,
    }
}

#[inline]
fn certify_key_cert_size_offset(profile: DpeProfile) -> usize {
    match profile {
        DpeProfile::P384Sha384 => CERTIFY_KEY_P384_RESP_CERT_SIZE_OFF,
        DpeProfile::Mldsa87 => CERTIFY_KEY_MLDSA87_RESP_CERT_SIZE_OFF,
    }
}
const CERTIFY_KEY_CHUNKS_REQ_MAX_SIZE_OFF: usize =
    offset_of!(caliptra_api::mailbox::CertifyKeyChunksReq, max_size);
const CERTIFY_KEY_CHUNKS_REQ_OFFSET_OFF: usize =
    offset_of!(caliptra_api::mailbox::CertifyKeyChunksReq, offset);
const CERTIFY_KEY_CHUNKS_REQ_DPE_CMD_OFF: usize =
    offset_of!(caliptra_api::mailbox::CertifyKeyChunksReq, certify_key_req);
// The embedded DPE `CertifyKey` command. The P-384 and ML-DSA-87 variants
// share one layout (asserted below), so a single set of offsets serves both.
const CERTIFY_KEY_CHUNKS_REQ_HANDLE_OFF: usize =
    CERTIFY_KEY_CHUNKS_REQ_DPE_CMD_OFF + offset_of!(CertifyKeyP384Cmd, handle);
const CERTIFY_KEY_CHUNKS_REQ_FORMAT_OFF: usize =
    CERTIFY_KEY_CHUNKS_REQ_DPE_CMD_OFF + offset_of!(CertifyKeyP384Cmd, format);
const CERTIFY_KEY_CHUNKS_REQ_LABEL_OFF: usize =
    CERTIFY_KEY_CHUNKS_REQ_DPE_CMD_OFF + offset_of!(CertifyKeyP384Cmd, label);
const CERTIFY_KEY_CHUNKS_RESP_HANDLE_OFF: usize = offset_of!(
    caliptra_api::mailbox::CertifyKeyChunksRespInfo,
    context_handle
);
const CERTIFY_KEY_CHUNKS_RESP_CHUNK_LEN_OFF: usize =
    offset_of!(caliptra_api::mailbox::CertifyKeyChunksRespInfo, chunk_len);

// The `caliptra-dpe` layouts are pinned here so that a change in a future
// `caliptra-dpe` revision fails the build instead of silently changing the
// bytes this module puts on, or expects from, the mailbox.
const _: () = assert!(INVOKE_DPE_REQ_PREFIX_LEN == 8);
const _: () = assert!(INVOKE_DPE_MLDSA87_REQ_PREFIX_LEN == 24);
const _: () = assert!(size_of::<CommandHdr>() == 12);
const _: () = assert!(size_of::<GetCertificateChainCmd>() == 8);
const _: () = assert!(size_of::<SignP384Cmd>() == DPE_CONTEXT_HANDLE_SIZE + 48 + 4 + 48);
const _: () = assert!(size_of::<SignP384Resp>() == 12 + DPE_CONTEXT_HANDLE_SIZE + 48 + 48);
const _: () = assert!(size_of::<SignMldsa87Cmd>() == DPE_CONTEXT_HANDLE_SIZE + 48 + 4 + 64);
const _: () = assert!(
    size_of::<SignMlDsaResp>() == 12 + DPE_CONTEXT_HANDLE_SIZE + DPE_MLDSA87_SIGNATURE_SIZE + 1
);
const _: () = assert!(SIGN_MLDSA87_RESP_HANDLE_OFF == 12);
const _: () = assert!(SIGN_MLDSA87_RESP_SIG_OFF == 12 + DPE_CONTEXT_HANDLE_SIZE);
const _: () = assert!(
    SIGN_MLDSA87_RESP_PADDING_OFF == 12 + DPE_CONTEXT_HANDLE_SIZE + DPE_MLDSA87_SIGNATURE_SIZE
);
const _: () =
    assert!(size_of::<DeriveContextCmd>() == DPE_CONTEXT_HANDLE_SIZE + 48 + 4 + 4 + 4 + 4);
const _: () =
    assert!(size_of::<UpdateContextMeasurementCmd>() == DPE_CONTEXT_HANDLE_SIZE + 48 + 4 + 4 + 4);
const _: () = assert!(
    size_of::<DeriveContextResp>() == 12 + DPE_CONTEXT_HANDLE_SIZE + DPE_CONTEXT_HANDLE_SIZE
);
const _: () = assert!(
    size_of::<DeriveContextExportedCdiRespHdr>()
        == 12 + DPE_CONTEXT_HANDLE_SIZE + DPE_CONTEXT_HANDLE_SIZE + EXPORTED_CDI_SIZE + 4
);
const _: () = assert!(
    size_of::<UpdateContextMeasurementResp>()
        == 12 + DPE_CONTEXT_HANDLE_SIZE + DPE_CONTEXT_HANDLE_SIZE
);
const _: () = assert!(INVOKE_DPE_RESP_PREFIX_LEN == 12);
const _: () = assert!(size_of::<ResponseHdr>() == 12);
const _: () = assert!(DPE_CONTEXT_HANDLE_SIZE == 16);
const _: () = assert!(DPE_TCI_MEASUREMENT_SIZE == 48);
const _: () = assert!(EXPORTED_CDI_SIZE == 32);
const _: () = assert!(DPE_PROFILE_P384_SHA384 == 4);
const _: () = assert!(DPE_PROFILE_MLDSA87 == 5);
const _: () =
    assert!(invoke_dpe_req_len::<GetCertificateChainCmd>(DpeProfile::P384Sha384) == 8 + 12 + 8);
const _: () =
    assert!(invoke_dpe_req_len::<GetCertificateChainCmd>(DpeProfile::Mldsa87) == 24 + 12 + 8);
const _: () = assert!(GET_CERT_CHAIN_RESP_CERT_SIZE_OFF == 12);
const _: () = assert!(GET_CERT_CHAIN_RESP_CHAIN_OFF == 12 + 4);
const _: () = assert!(invoke_dpe_req_len::<SignP384Cmd>(DpeProfile::P384Sha384) == 8 + 12 + 116);
const _: () = assert!(SIGN_MLDSA87_REQ_LEN == 24 + 12 + 132);
const _: () = assert!(SIGN_MLDSA87_RESP_LEN == 12 + 12 + 16 + 4627 + 1);
const _: () = assert!(SIGN_MLDSA87_RESP_LEN <= caliptra_api::mailbox::MAILBOX_SIZE);
const _: () =
    assert!(invoke_dpe_req_len::<DeriveContextCmd>(DpeProfile::P384Sha384) == 8 + 12 + 80);
const _: () = assert!(invoke_dpe_req_len::<DeriveContextCmd>(DpeProfile::Mldsa87) == 24 + 12 + 80);
const _: () = assert!(
    invoke_dpe_req_len::<UpdateContextMeasurementCmd>(DpeProfile::P384Sha384) == 8 + 12 + 76
);
const _: () = assert!(
    caliptra_api::mailbox::CertifyKeyChunksReq::CERTIFY_KEY_REQ_SIZE
        == DPE_CONTEXT_HANDLE_SIZE + 4 + 4 + 48
);
const _: () = assert!(
    caliptra_api::mailbox::CertifyKeyChunksReq::CERTIFY_KEY_REQ_SIZE
        == size_of::<CertifyKeyP384Cmd>()
);
const _: () = assert!(size_of::<CertifyKeyMldsa87Cmd>() == size_of::<CertifyKeyP384Cmd>());
const _: () = assert!(
    offset_of!(CertifyKeyMldsa87Cmd, handle) == offset_of!(CertifyKeyP384Cmd, handle)
        && offset_of!(CertifyKeyMldsa87Cmd, format) == offset_of!(CertifyKeyP384Cmd, format)
        && offset_of!(CertifyKeyMldsa87Cmd, label) == offset_of!(CertifyKeyP384Cmd, label)
);
const _: () = assert!(offset_of!(CertifyKeyP384Cmd, handle) == 0);
const _: () = assert!(offset_of!(CertifyKeyP384Cmd, format) == DPE_CONTEXT_HANDLE_SIZE + 4);
const _: () = assert!(offset_of!(CertifyKeyP384Cmd, label) == DPE_CONTEXT_HANDLE_SIZE + 4 + 4);
const _: () = assert!(size_of::<[u8; DPE_LABEL_LEN]>() == 48);
const _: () = assert!(CERTIFY_KEY_P384_RESP_PREFIX_LEN == 128);
const _: () = assert!(CERTIFY_KEY_P384_RESP_PUBKEY_X_OFF == 12 + DPE_CONTEXT_HANDLE_SIZE);
const _: () = assert!(CERTIFY_KEY_P384_RESP_PUBKEY_Y_OFF == 12 + DPE_CONTEXT_HANDLE_SIZE + 48);
const _: () = assert!(CERTIFY_KEY_P384_RESP_CERT_SIZE_OFF == 12 + DPE_CONTEXT_HANDLE_SIZE + 96);
const _: () = assert!(CERTIFY_KEY_MLDSA87_PUBKEY_SIZE == 2592);
const _: () = assert!(CERTIFY_KEY_MLDSA87_RESP_PREFIX_LEN == 2624);
const _: () = assert!(CERTIFY_KEY_MLDSA87_RESP_PUBKEY_OFF == 12 + DPE_CONTEXT_HANDLE_SIZE);
const _: () = assert!(
    CERTIFY_KEY_MLDSA87_RESP_CERT_SIZE_OFF
        == 12 + DPE_CONTEXT_HANDLE_SIZE + CERTIFY_KEY_MLDSA87_PUBKEY_SIZE
);
const _: () = assert!(CERTIFY_KEY_CHUNKS_REQ_LEN == 92);
const _: () = assert!(CERTIFY_KEY_CHUNKS_RESP_INFO_LEN == 32);
const _: () = assert!(DPE_MLDSA87_SIGN_SCRATCH_PEAK == SIGN_MLDSA87_RESP_LEN);
const _: () = assert!(size_of::<RotateCtxCmd>() == DPE_CONTEXT_HANDLE_SIZE + 4);
const _: () = assert!(size_of::<NewHandleResp>() == 12 + DPE_CONTEXT_HANDLE_SIZE);
const _: () = assert!(invoke_dpe_req_len::<RotateCtxCmd>(DpeProfile::P384Sha384) == 8 + 12 + 20);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parameters for one DPE `DeriveContext` command.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DpeDeriveContextParams {
    pub parent_handle: DpeContextHandle,
    pub measurement: [u8; DPE_TCI_MEASUREMENT_SIZE],
    pub flags: DpeDeriveContextFlags,
    pub tci_type: u32,
    pub target_locality: u32,
    pub svn: u32,
}

impl From<&DpeDeriveContextParams> for DeriveContextCmd {
    fn from(params: &DpeDeriveContextParams) -> Self {
        Self {
            handle: ContextHandle(params.parent_handle),
            data: TciMeasurement(params.measurement),
            flags: params.flags,
            tci_type: params.tci_type,
            target_locality: params.target_locality,
            svn: params.svn,
        }
    }
}

/// Handles returned by one DPE `DeriveContext` command.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DpeDeriveContextResult {
    /// New child context handle.
    pub child_handle: DpeContextHandle,
    /// Rotated parent context handle.
    pub parent_handle: DpeContextHandle,
}

/// Handles and certificate returned by one DPE `DeriveContext` command with `EXPORT_CDI`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DpeDeriveContextExportedCdiResult {
    /// New child context handle.
    pub child_handle: DpeContextHandle,
    /// Rotated parent context handle.
    pub parent_handle: DpeContextHandle,
    /// Derived 32-byte exported CDI handle.
    pub exported_cdi: [u8; EXPORTED_CDI_SIZE],
    /// Certificate size in bytes written into the destination buffer.
    pub cert_size: usize,
}

/// Parameters for one DPE `UpdateContextMeasurement` command.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DpeUpdateContextMeasurementParams {
    pub parent_handle: DpeContextHandle,
    pub measurement: [u8; DPE_TCI_MEASUREMENT_SIZE],
    pub tci_type: u32,
}

impl From<&DpeUpdateContextMeasurementParams> for UpdateContextMeasurementCmd {
    fn from(params: &DpeUpdateContextMeasurementParams) -> Self {
        Self {
            parent_handle: ContextHandle(params.parent_handle),
            data: TciMeasurement(params.measurement),
            reserved: 0,
            tci_type: params.tci_type,
            reserved_svn: 0,
        }
    }
}

/// Handles returned by one DPE `UpdateContextMeasurement` command.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DpeUpdateContextMeasurementResult {
    /// Rotated component context handle.
    pub component_handle: DpeContextHandle,
    /// Rotated parent context handle.
    pub parent_handle: DpeContextHandle,
}

/// TCI values returned by Caliptra `DPE_GET_TAGGED_TCI`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DpeTaggedTci {
    /// Hash of all input data measured into the tagged context.
    pub tci_cumulative: [u8; DPE_TCI_MEASUREMENT_SIZE],
    /// Most recent measurement made into the tagged context.
    pub tci_current: [u8; DPE_TCI_MEASUREMENT_SIZE],
}

/// Invoke DPE `DeriveContext`, returning the child handle and rotated parent handle.
#[inline(never)]
pub async fn dpe_derive_context<A: ScratchAlloc>(
    alloc: &A,
    params: &DpeDeriveContextParams,
) -> McuResult<DpeDeriveContextResult> {
    let req = build_invoke_dpe_req(
        alloc,
        DpeProfile::P384Sha384,
        None,
        &DeriveContextCmd::from(params),
    )?;
    let mut rsp = alloc.alloc(INVOKE_DPE_RESP_PREFIX_LEN + size_of::<DeriveContextResp>())?;
    let rsp_len = mbox_execute(CMD_INVOKE_DPE, &req, &mut rsp).await?;
    parse_derive_context_response(&rsp, rsp_len)
}

fn parse_derive_context_response(rsp: &[u8], rsp_len: usize) -> McuResult<DpeDeriveContextResult> {
    let resp_body_off = INVOKE_DPE_RESP_PREFIX_LEN;
    if rsp_len < resp_body_off + size_of::<DeriveContextResp>() {
        return Err(INTERNAL_BUG);
    }
    let body = DeriveContextResp::try_read_from_bytes(internal_slice(
        rsp,
        resp_body_off,
        size_of::<DeriveContextResp>(),
    )?)
    .map_err(|_| INTERNAL_BUG)?;
    check_dpe_response_hdr(&body.resp_hdr)?;
    Ok(DpeDeriveContextResult {
        child_handle: body.handle.0,
        parent_handle: body.parent_handle.0,
    })
}

/// Minimum size and alignment required for `cert_dst` in [`dpe_derive_context_exported_cdi`],
/// which stages the `InvokeDpeResp` framing (12 B) + `DeriveContextExportedCdiRespHdr` (80 B)
/// ahead of the leaf certificate in-place before shifting the certificate to offset 0.
pub const DERIVE_CONTEXT_EXPORTED_CDI_RESP_PREFIX_LEN: usize =
    INVOKE_DPE_RESP_PREFIX_LEN + size_of::<DeriveContextExportedCdiRespHdr>();

/// Invoke DPE `DeriveContext` with `EXPORT_CDI`, returning the child handle, rotated parent handle,
/// 32-byte exported CDI handle, and writing the emitted leaf certificate into `cert_dst`.
///
/// `cert_dst` must be 4-byte aligned and at least
/// `DERIVE_CONTEXT_EXPORTED_CDI_RESP_PREFIX_LEN + DPE_MAX_LEAF_CERT_SIZE` (`10,332`) bytes long so
/// the response can be staged in-place without a secondary scratch allocation.
#[inline(never)]
pub async fn dpe_derive_context_exported_cdi<A: ScratchAlloc>(
    alloc: &A,
    params: &DpeDeriveContextParams,
    profile: DpeProfile,
    cert_dst: &mut [u8],
) -> McuResult<DpeDeriveContextExportedCdiResult> {
    let in_place_len = DERIVE_CONTEXT_EXPORTED_CDI_RESP_PREFIX_LEN + DPE_MAX_LEAF_CERT_SIZE;
    if cert_dst.len() < in_place_len
        || !(cert_dst.as_ptr() as usize).is_multiple_of(core::mem::align_of::<u32>())
    {
        return Err(INVARIANT);
    }

    let rsp = &mut cert_dst[..in_place_len];
    let axi_response = match profile {
        // Caliptra DMAs the response into `rsp`, whose length bounds the write.
        DpeProfile::Mldsa87 => Some(AxiDmaTarget::from_mcu_sram(rsp)?.into()),
        DpeProfile::P384Sha384 => None,
    };
    let req = build_invoke_dpe_req(
        alloc,
        profile,
        axi_response,
        &DeriveContextCmd::from(params),
    )?;
    let rsp_len = mbox_execute(profile.invoke_cmd_id(), &req, rsp).await?;
    let effective_rsp_len = match profile {
        DpeProfile::Mldsa87 => {
            let data_size =
                read_le_u32(rsp, INVOKE_DPE_RESP_DATA_SIZE_OFF).map_err(|_| INVARIANT)?;
            INVOKE_DPE_RESP_PREFIX_LEN + data_size as usize
        }
        DpeProfile::P384Sha384 => rsp_len,
    };
    parse_derive_context_exported_cdi_response_in_place(rsp, effective_rsp_len)
}

fn parse_derive_context_exported_cdi_header(
    rsp: &[u8],
    rsp_len: usize,
) -> McuResult<DpeDeriveContextExportedCdiResult> {
    let resp_body_off = INVOKE_DPE_RESP_PREFIX_LEN;
    let prefix_len = size_of::<DeriveContextExportedCdiRespHdr>();
    if rsp_len < resp_body_off + size_of::<ResponseHdr>() {
        return Err(INTERNAL_BUG);
    }
    read_dpe_response_hdr(rsp, resp_body_off)?;
    if rsp_len < resp_body_off + prefix_len {
        return Err(INTERNAL_BUG);
    }
    let prefix = DeriveContextExportedCdiRespHdr::try_read_from_bytes(internal_slice(
        rsp,
        resp_body_off,
        prefix_len,
    )?)
    .map_err(|_| INTERNAL_BUG)?;

    let cert_size = prefix.certificate_size as usize;
    let cert_off = resp_body_off + prefix_len;
    if cert_off + cert_size > rsp_len || cert_size > rsp.len() {
        return Err(INTERNAL_BUG);
    }
    Ok(DpeDeriveContextExportedCdiResult {
        child_handle: prefix.handle.0,
        parent_handle: prefix.parent_handle.0,
        exported_cdi: prefix.exported_cdi,
        cert_size,
    })
}

fn parse_derive_context_exported_cdi_response_in_place(
    rsp: &mut [u8],
    rsp_len: usize,
) -> McuResult<DpeDeriveContextExportedCdiResult> {
    let result = parse_derive_context_exported_cdi_header(rsp, rsp_len)?;
    let cert_off = DERIVE_CONTEXT_EXPORTED_CDI_RESP_PREFIX_LEN;
    if result.cert_size > rsp.len() - cert_off {
        return Err(INTERNAL_BUG);
    }
    rsp.copy_within(cert_off..cert_off + result.cert_size, 0);
    Ok(result)
}

/// Invoke DPE `UpdateContextMeasurement`, returning the rotated component and parent handles.
#[inline(never)]
pub async fn dpe_update_context_measurement<A: ScratchAlloc>(
    alloc: &A,
    params: &DpeUpdateContextMeasurementParams,
) -> McuResult<DpeUpdateContextMeasurementResult> {
    let req = build_invoke_dpe_req(
        alloc,
        DpeProfile::P384Sha384,
        None,
        &UpdateContextMeasurementCmd::from(params),
    )?;
    let mut rsp =
        alloc.alloc(INVOKE_DPE_RESP_PREFIX_LEN + size_of::<UpdateContextMeasurementResp>())?;
    let rsp_len = mbox_execute(CMD_INVOKE_DPE, &req, &mut rsp).await?;
    parse_update_context_measurement_response(&rsp, rsp_len)
}

fn parse_update_context_measurement_response(
    rsp: &[u8],
    rsp_len: usize,
) -> McuResult<DpeUpdateContextMeasurementResult> {
    let resp_body_off = INVOKE_DPE_RESP_PREFIX_LEN;
    if rsp_len < resp_body_off + size_of::<UpdateContextMeasurementResp>() {
        return Err(INTERNAL_BUG);
    }
    let body = UpdateContextMeasurementResp::try_read_from_bytes(internal_slice(
        rsp,
        resp_body_off,
        size_of::<UpdateContextMeasurementResp>(),
    )?)
    .map_err(|_| INTERNAL_BUG)?;
    check_dpe_response_hdr(&body.resp_hdr)?;
    Ok(DpeUpdateContextMeasurementResult {
        component_handle: body.new_context_handle.0,
        parent_handle: body.new_parent_context_handle.0,
    })
}

/// Fetch a chunk of the Caliptra-managed DPE certificate chain via
/// the `INVOKE_DPE` (ECC-384) or `INVOKE_DPE_MLDSA87` (ML-DSA-87) mailbox command.
///
/// `dst.len()` is the requested chunk size and MUST be in
/// `1..=DPE_MAX_CHUNK_SIZE`. Returns the number of bytes Caliptra
/// actually wrote. A short read (`returned < dst.len()`) signals
/// end-of-chain; callers should stop probing.
#[inline(never)]
pub async fn dpe_get_cert_chain_chunk<A: ScratchAlloc>(
    alloc: &A,
    profile: DpeProfile,
    offset: u32,
    dst: &mut [u8],
) -> McuResult<usize> {
    if dst.is_empty() || dst.len() > DPE_MAX_CHUNK_SIZE {
        return Err(INVARIANT);
    }
    let size = dst.len() as u32;

    let req = build_invoke_dpe_req(
        alloc,
        profile,
        None,
        &GetCertificateChainCmd { offset, size },
    )?;
    let mbox_cmd = profile.invoke_cmd_id();

    // Allocate response: outer prefix + DPE response hdr + cert_size
    // + chain bytes (up to DPE_MAX_CHUNK_SIZE).
    let rsp_max = INVOKE_DPE_RESP_PREFIX_LEN + GET_CERT_CHAIN_RESP_CHAIN_OFF + DPE_MAX_CHUNK_SIZE;
    let mut rsp = alloc.alloc(rsp_max)?;
    let rsp_len = mbox_execute(mbox_cmd, &req, &mut rsp).await?;

    let outer_prefix_len = INVOKE_DPE_RESP_PREFIX_LEN;
    let dpe_hdr_off = outer_prefix_len;
    let cert_size_off = dpe_hdr_off + GET_CERT_CHAIN_RESP_CERT_SIZE_OFF;
    let chain_off = dpe_hdr_off + GET_CERT_CHAIN_RESP_CHAIN_OFF;
    if rsp_len < chain_off {
        return Err(INTERNAL_BUG);
    }

    read_dpe_response_hdr(&rsp, dpe_hdr_off)?;

    let cert_size = read_le_u32(&rsp, cert_size_off)? as usize;
    if cert_size > dst.len() || chain_off + cert_size > rsp_len {
        return Err(INTERNAL_BUG);
    }
    let out = dst.get_mut(..cert_size).ok_or(INTERNAL_BUG)?;
    let cert = internal_slice(&rsp, chain_off, cert_size)?;
    copy_bytes(out, cert)?;
    Ok(cert_size)
}

/// Fetch the complete DER leaf certificate emitted by DPE `CertifyKey`.
///
/// This composes the bounded size and slice commands so callers with smaller
/// certificate buffers do not need to implement chunking themselves.
#[inline(never)]
pub async fn dpe_certify_key<A: ScratchAlloc>(
    alloc: &A,
    profile: DpeProfile,
    handle: Option<&DpeContextHandle>,
    label: &[u8; DPE_LABEL_LEN],
    dst: &mut [u8],
) -> McuResult<(DpeContextHandle, usize)> {
    let (_, cert_size) = dpe_certify_key_cert_size(alloc, profile, handle, label).await?;
    if cert_size == 0 || cert_size > dst.len() {
        return Err(INVARIANT);
    }

    let mut offset = 0;
    let mut next_handle = None;
    while offset < cert_size {
        let end = cert_size.min(offset + DPE_MAX_CHUNK_SIZE);
        let (rotated_handle, copied) = dpe_certify_key_cert_slice(
            alloc,
            profile,
            handle,
            label,
            offset as u32,
            dst.get_mut(offset..end).ok_or(INVARIANT)?,
        )
        .await?;
        if copied == 0 || copied > end - offset {
            return Err(INTERNAL_BUG);
        }
        next_handle = Some(rotated_handle);
        offset += copied;
    }

    Ok((next_handle.ok_or(INTERNAL_BUG)?, cert_size))
}

/// Return the DER leaf certificate length emitted by DPE `CertifyKey`
/// without fetching the certificate body, along with the rotated context handle.
#[inline(never)]
pub async fn dpe_certify_key_cert_size<A: ScratchAlloc>(
    alloc: &A,
    profile: DpeProfile,
    handle: Option<&DpeContextHandle>,
    label: &[u8; DPE_LABEL_LEN],
) -> McuResult<(DpeContextHandle, usize)> {
    let prefix_len = certify_key_prefix_len(profile);
    let chunk = certify_key_chunks_response(
        alloc,
        profile,
        label,
        handle.unwrap_or(&DEFAULT_DPE_CONTEXT_HANDLE),
        0,
        prefix_len,
    )
    .await?;
    let response = chunk.chunk()?;
    validate_certify_key_prefix(response, profile)?;
    Ok((
        chunk.next_handle,
        read_le_u32(response, certify_key_cert_size_offset(profile))? as usize,
    ))
}

/// Fetch DER leaf-certificate bytes from DPE `CertifyKey`.
///
/// `cert_offset` is relative to the certificate DER bytes, not the
/// enclosing `CertifyKey` response. Returns the rotated context handle plus
/// the number of bytes copied into `dst`.
#[inline(never)]
pub async fn dpe_certify_key_cert_slice<A: ScratchAlloc>(
    alloc: &A,
    profile: DpeProfile,
    handle: Option<&DpeContextHandle>,
    label: &[u8; DPE_LABEL_LEN],
    cert_offset: u32,
    dst: &mut [u8],
) -> McuResult<(DpeContextHandle, usize)> {
    if dst.is_empty() || dst.len() > DPE_MAX_CHUNK_SIZE {
        return Err(INVARIANT);
    }

    let prefix_len = certify_key_prefix_len(profile);
    let dpe_offset = prefix_len
        .checked_add(cert_offset as usize)
        .ok_or(INVARIANT)?;
    let chunk = certify_key_chunks_response(
        alloc,
        profile,
        label,
        handle.unwrap_or(&DEFAULT_DPE_CONTEXT_HANDLE),
        dpe_offset as u32,
        dst.len(),
    )
    .await?;
    let response = chunk.chunk()?;
    if response.len() > dst.len() {
        return Err(INTERNAL_BUG);
    }
    let out = dst.get_mut(..response.len()).ok_or(INTERNAL_BUG)?;
    copy_bytes(out, response)?;
    Ok((chunk.next_handle, response.len()))
}

/// Like [`dpe_certify_key`] but also returns the derived public key
/// coordinates `(pubkey_x, pubkey_y)`, each 48 bytes for P-384.
///
/// This avoids parsing the X.509 cert when only the raw public key
/// is needed (e.g. to compute an attestation kid). Returns the rotated
/// context handle.
#[inline(never)]
pub async fn dpe_certify_key_pubkey<A: ScratchAlloc>(
    alloc: &A,
    handle: Option<&DpeContextHandle>,
    label: &[u8; DPE_LABEL_LEN],
    pubkey_x: &mut [u8; 48],
    pubkey_y: &mut [u8; 48],
) -> McuResult<DpeContextHandle> {
    let chunk = certify_key_chunks_response(
        alloc,
        DpeProfile::P384Sha384,
        label,
        handle.unwrap_or(&DEFAULT_DPE_CONTEXT_HANDLE),
        0,
        CERTIFY_KEY_P384_RESP_PREFIX_LEN,
    )
    .await?;
    let response = chunk.chunk()?;
    validate_certify_key_prefix(response, DpeProfile::P384Sha384)?;
    let pubkey_x_bytes = internal_slice(response, CERTIFY_KEY_P384_RESP_PUBKEY_X_OFF, 48)?;
    let pubkey_y_bytes = internal_slice(response, CERTIFY_KEY_P384_RESP_PUBKEY_Y_OFF, 48)?;
    copy_bytes(pubkey_x, pubkey_x_bytes)?;
    copy_bytes(pubkey_y, pubkey_y_bytes)?;
    Ok(chunk.next_handle)
}

fn extract_certify_key_mldsa87_pubkey(response: &[u8]) -> McuResult<&[u8]> {
    validate_certify_key_prefix(response, DpeProfile::Mldsa87)?;
    internal_slice(
        response,
        CERTIFY_KEY_MLDSA87_RESP_PUBKEY_OFF,
        CERTIFY_KEY_MLDSA87_PUBKEY_SIZE,
    )
}

/// Return the ML-DSA-87 public-key hash `tr` emitted by DPE `CertifyKey`,
/// along with the rotated context handle.
#[inline(never)]
pub async fn dpe_certify_key_mldsa87_tr<A: ScratchAlloc>(
    alloc: &A,
    handle: Option<&DpeContextHandle>,
    label: &[u8; DPE_LABEL_LEN],
    tr: &mut [u8; MLDSA87_TR_SIZE],
) -> McuResult<DpeContextHandle> {
    let chunk = certify_key_chunks_response(
        alloc,
        DpeProfile::Mldsa87,
        label,
        handle.unwrap_or(&DEFAULT_DPE_CONTEXT_HANDLE),
        0,
        CERTIFY_KEY_MLDSA87_RESP_PREFIX_LEN,
    )
    .await?;
    let response = chunk.chunk()?;
    let pubkey = extract_certify_key_mldsa87_pubkey(response)?;
    shake256_hash(alloc, pubkey, tr).await?;
    Ok(chunk.next_handle)
}

struct CertifyKeyChunk<B> {
    next_handle: DpeContextHandle,
    rsp: B,
    chunk_len: usize,
}

impl<B: Deref<Target = [u8]>> CertifyKeyChunk<B> {
    fn chunk(&self) -> McuResult<&[u8]> {
        internal_slice(&self.rsp, CERTIFY_KEY_CHUNKS_RESP_INFO_LEN, self.chunk_len)
    }
}

async fn certify_key_chunks_response<'a, A>(
    alloc: &'a A,
    profile: DpeProfile,
    label: &[u8; DPE_LABEL_LEN],
    handle: &[u8; DPE_CONTEXT_HANDLE_SIZE],
    dpe_resp_offset: u32,
    max_size: usize,
) -> McuResult<CertifyKeyChunk<A::Buf<'a>>>
where
    A: ScratchAlloc,
{
    if max_size == 0 || max_size > CERTIFY_KEY_CHUNKS_MAX_REQ_SIZE {
        return Err(INVARIANT);
    }

    let req =
        build_certify_key_chunks_req(alloc, profile, label, handle, dpe_resp_offset, max_size)?;
    let mut rsp = alloc.alloc(CERTIFY_KEY_CHUNKS_RESP_INFO_LEN + max_size)?;
    let rsp_len = crate::wire::mbox_execute(CMD_CERTIFY_KEY_CHUNKS, &req, &mut rsp).await?;
    if rsp_len < CERTIFY_KEY_CHUNKS_RESP_INFO_LEN {
        return Err(INTERNAL_BUG);
    }

    let next_handle = read_fixed(&rsp, CERTIFY_KEY_CHUNKS_RESP_HANDLE_OFF)?;
    let chunk_len = read_le_u32(&rsp, CERTIFY_KEY_CHUNKS_RESP_CHUNK_LEN_OFF)? as usize;
    if chunk_len > max_size || CERTIFY_KEY_CHUNKS_RESP_INFO_LEN + chunk_len > rsp_len {
        return Err(INTERNAL_BUG);
    }

    Ok(CertifyKeyChunk {
        next_handle,
        rsp,
        chunk_len,
    })
}

fn build_certify_key_chunks_req<'a, A: ScratchAlloc>(
    alloc: &'a A,
    profile: DpeProfile,
    label: &[u8; DPE_LABEL_LEN],
    handle: &[u8; DPE_CONTEXT_HANDLE_SIZE],
    offset: u32,
    max_size: usize,
) -> McuResult<A::Buf<'a>> {
    let mut req = alloc.alloc(CERTIFY_KEY_CHUNKS_REQ_LEN)?;
    req.fill(0);
    let flags: u32 = match profile {
        DpeProfile::P384Sha384 => 0,
        DpeProfile::Mldsa87 => CERTIFY_KEY_FLAG_USE_MLDSA,
    };
    write_fixed(&mut req, 4, &flags.to_le_bytes())?;
    write_fixed(
        &mut req,
        CERTIFY_KEY_CHUNKS_REQ_MAX_SIZE_OFF,
        &(max_size as u32).to_le_bytes(),
    )?;
    write_fixed(
        &mut req,
        CERTIFY_KEY_CHUNKS_REQ_OFFSET_OFF,
        &offset.to_le_bytes(),
    )?;
    write_fixed(&mut req, CERTIFY_KEY_CHUNKS_REQ_HANDLE_OFF, handle)?;
    write_fixed(
        &mut req,
        CERTIFY_KEY_CHUNKS_REQ_FORMAT_OFF,
        &DPE_CERTIFY_KEY_FORMAT_X509.to_le_bytes(),
    )?;
    write_fixed(&mut req, CERTIFY_KEY_CHUNKS_REQ_LABEL_OFF, label)?;

    let checksum = calc_checksum(CMD_CERTIFY_KEY_CHUNKS, &req);
    *req.first_chunk_mut::<4>().ok_or(INVARIANT)? = checksum.to_le_bytes();
    Ok(req)
}

/// A DPE command body that Caliptra's `INVOKE_DPE` mailbox commands can carry.
trait DpeCommand: IntoBytes + Immutable {
    /// DPE command ID placed in the `CommandHdr` ahead of the body.
    const ID: u32;
}

impl DpeCommand for DeriveContextCmd {
    const ID: u32 = Command::DERIVE_CONTEXT;
}

impl DpeCommand for UpdateContextMeasurementCmd {
    const ID: u32 = Command::UPDATE_CONTEXT_MEASUREMENT;
}

impl DpeCommand for GetCertificateChainCmd {
    const ID: u32 = Command::GET_CERTIFICATE_CHAIN;
}

impl DpeCommand for SignP384Cmd {
    const ID: u32 = Command::SIGN;
}

impl DpeCommand for SignMldsa87Cmd {
    const ID: u32 = Command::SIGN;
}

impl DpeCommand for RotateCtxCmd {
    const ID: u32 = Command::ROTATE_CONTEXT_HANDLE;
}

/// Length of a complete `INVOKE_DPE` request carrying `C`: the mailbox framing for `profile`, the DPE `CommandHdr` and the command body.
const fn invoke_dpe_req_len<C: DpeCommand>(profile: DpeProfile) -> usize {
    profile.invoke_req_prefix_len() + size_of::<CommandHdr>() + size_of::<C>()
}

/// Write a complete `INVOKE_DPE` request carrying `cmd` into the first [`invoke_dpe_req_len`] bytes of `req`: the mailbox framing for `profile`, the DPE `CommandHdr`, the command body and the mailbox checksum.
///
/// `axi_response` asks Caliptra to DMA the response to that target; only the ML-DSA-87 framing carries it.
fn write_invoke_dpe_req<C: DpeCommand>(
    req: &mut [u8],
    profile: DpeProfile,
    axi_response: Option<AxiResponseInfo>,
    cmd: &C,
) -> McuResult<()> {
    let req = checked_slice_mut(req, 0, invoke_dpe_req_len::<C>(profile))?;
    // Zeroes `hdr.chksum` for the checksum below, and the ML-DSA-87 flags and AXI target when unused.
    req.fill(0);
    let payload_len = ((size_of::<CommandHdr>() + size_of::<C>()) as u32).to_le_bytes();
    match profile {
        DpeProfile::P384Sha384 => write_fixed(req, INVOKE_DPE_REQ_DATA_SIZE_OFF, &payload_len)?,
        DpeProfile::Mldsa87 => {
            if let Some(axi_response) = axi_response {
                write_fixed(
                    req,
                    INVOKE_DPE_MLDSA87_REQ_FLAGS_OFF,
                    &InvokeDpeMldsa87Flags::EXTERNAL_AXI_RESPONSE
                        .bits()
                        .to_le_bytes(),
                )?;
                write_fixed(
                    req,
                    INVOKE_DPE_MLDSA87_REQ_AXI_RESPONSE_OFF,
                    axi_response.as_bytes(),
                )?;
            }
            write_fixed(req, INVOKE_DPE_MLDSA87_REQ_DATA_SIZE_OFF, &payload_len)?;
        }
    }
    let hdr_off = profile.invoke_req_prefix_len();
    write_fixed(
        req,
        hdr_off,
        CommandHdr::new(profile.into(), C::ID).as_bytes(),
    )?;
    write_fixed(req, hdr_off + size_of::<CommandHdr>(), cmd.as_bytes())?;
    populate_checksum(profile.invoke_cmd_id(), req)
}

/// Allocate and write a complete `INVOKE_DPE` request carrying `cmd`.
fn build_invoke_dpe_req<'a, A: ScratchAlloc, C: DpeCommand>(
    alloc: &'a A,
    profile: DpeProfile,
    axi_response: Option<AxiResponseInfo>,
    cmd: &C,
) -> McuResult<A::Buf<'a>> {
    let mut req = alloc.alloc(invoke_dpe_req_len::<C>(profile))?;
    write_invoke_dpe_req(&mut req, profile, axi_response, cmd)?;
    Ok(req)
}

/// Reject a DPE response whose header does not report success.
#[inline]
fn check_dpe_response_hdr(hdr: &ResponseHdr) -> McuResult<()> {
    if hdr.magic != DPE_RESPONSE_MAGIC || hdr.status != 0 {
        return Err(INTERNAL_BUG);
    }
    Ok(())
}

/// Copy out and validate the DPE response header at `offset`.
///
/// The header is read by value because `ResponseHdr` is 4-byte aligned and
/// `rsp` is not guaranteed to be.
#[inline]
fn read_dpe_response_hdr(rsp: &[u8], offset: usize) -> McuResult<ResponseHdr> {
    let hdr =
        ResponseHdr::try_read_from_bytes(internal_slice(rsp, offset, size_of::<ResponseHdr>())?)
            .map_err(|_| INTERNAL_BUG)?;
    check_dpe_response_hdr(&hdr)?;
    Ok(hdr)
}

#[inline]
fn write_fixed(dst: &mut [u8], offset: usize, src: &[u8]) -> McuResult<()> {
    let end = offset.checked_add(src.len()).ok_or(INVARIANT)?;
    let dst = dst.get_mut(offset..end).ok_or(INVARIANT)?;
    copy_bytes(dst, src)
}

#[inline]
fn read_le_u32(src: &[u8], offset: usize) -> McuResult<u32> {
    Ok(u32::from_le_bytes(
        *src.get(offset..)
            .and_then(|s| s.first_chunk::<4>())
            .ok_or(INTERNAL_BUG)?,
    ))
}

/// Copy `N` bytes out of `src` at `offset`.
#[inline]
fn read_fixed<const N: usize>(src: &[u8], offset: usize) -> McuResult<[u8; N]> {
    let mut out = [0u8; N];
    copy_bytes(&mut out, internal_slice(src, offset, N)?)?;
    Ok(out)
}

#[inline]
fn validate_certify_key_prefix(chunk: &[u8], profile: DpeProfile) -> McuResult<()> {
    if chunk.len() < certify_key_prefix_len(profile) {
        return Err(INTERNAL_BUG);
    }
    if read_le_u32(chunk, offset_of!(ResponseHdr, magic))? != DPE_RESPONSE_MAGIC
        || read_le_u32(chunk, offset_of!(ResponseHdr, status))? != 0
    {
        return Err(INTERNAL_BUG);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Chain walker
// ---------------------------------------------------------------------------

/// Stateful consumer for [`walk_dpe_chain`]. Receives each
/// [`DPE_MAX_CHUNK_SIZE`]-bounded chunk of the DPE cert chain in
/// order.
pub trait DpeChainSink {
    async fn on_chunk(&mut self, chunk: &[u8]) -> McuResult<()>;
}

/// Walks the entire DPE certificate chain for `profile` in
/// [`DPE_MAX_CHUNK_SIZE`]-byte chunks, feeding each chunk to `sink`.
/// Returns the total number of bytes walked. A short read
/// (`returned < DPE_MAX_CHUNK_SIZE`) ends the walk.
pub async fn walk_dpe_chain<A: ScratchAlloc, S: DpeChainSink>(
    alloc: &A,
    profile: DpeProfile,
    sink: &mut S,
) -> McuResult<u32> {
    const MAX_CHAIN_LEN: u32 = 48 * 1024;
    let mut buf = alloc.alloc(DPE_MAX_CHUNK_SIZE)?;
    let mut total: u32 = 0;
    loop {
        let n = dpe_get_cert_chain_chunk(alloc, profile, total, &mut buf).await?;
        let chunk = internal_slice(&buf, 0, n)?;
        sink.on_chunk(chunk).await?;
        total = total.checked_add(n as u32).ok_or(INVARIANT)?;
        if n < DPE_MAX_CHUNK_SIZE {
            break;
        }
        if total > MAX_CHAIN_LEN {
            return Err(INVARIANT);
        }
    }
    Ok(total)
}

/// Invoke DPE `Sign` for a typed signing input.
///
/// Supports P-384 digests and pure ML-DSA-87 messages with context.
#[inline(never)]
pub async fn dpe_sign<A: ScratchAlloc>(
    alloc: &A,
    handle: Option<&DpeContextHandle>,
    label: &[u8; DPE_LABEL_LEN],
    signing_input: SigningInput<'_>,
    signature: &mut [u8],
) -> McuResult<(DpeContextHandle, usize)> {
    match signing_input {
        SigningInput::EccP384Digest(digest) => {
            dpe_sign_ecc_p384(alloc, handle, label, digest, signature).await
        }
        SigningInput::Mldsa87Message {
            context,
            prefix,
            hash,
        } => dpe_sign_mldsa87_message(alloc, handle, label, context, prefix, hash, signature).await,
        SigningInput::Mldsa87Mu(mu) => dpe_sign_mldsa87(alloc, handle, label, mu, signature).await,
    }
}

/// Sign pure ML-DSA-87 under FIPS 204 `context` over `prefix || hash`.
#[inline(never)]
async fn dpe_sign_mldsa87_message<A: ScratchAlloc>(
    alloc: &A,
    handle: Option<&DpeContextHandle>,
    label: &[u8; DPE_LABEL_LEN],
    context: &[u8],
    prefix: &[u8],
    hash: &[u8],
    signature: &mut [u8],
) -> McuResult<(DpeContextHandle, usize)> {
    if signature.len() < DPE_MLDSA87_SIGNATURE_SIZE || context.len() > MLDSA87_CONTEXT_MAX_SIZE {
        return Err(INVARIANT);
    }

    // Verify scratch pool can hold the Sign response before CertifyKey rotates the handle.
    drop(alloc.alloc(SIGN_MLDSA87_RESP_LEN)?);

    let (next_handle, mu) = {
        let mut tr = [0u8; MLDSA87_TR_SIZE];
        let next_handle = dpe_certify_key_mldsa87_tr(alloc, handle, label, &mut tr).await?;

        let mut mu = [0u8; DPE_MLDSA87_MU_SIZE];
        mldsa87_compute_mu(alloc, &tr, context, &[prefix, hash], &mut mu).await?;

        (next_handle, mu)
    };

    dpe_sign_mldsa87(alloc, Some(&next_handle), label, &mu, signature).await
}

/// Invoke DPE `Sign` (P-384 / SHA-384) for the default context handle
/// and the given 48-byte `label`. Signs `digest` and writes the
/// concatenated (r || s) signature into `signature`.
///
/// `signature` must be at least [`DPE_P384_SIGNATURE_SIZE`] (96) bytes. Returns
/// the rotated context handle plus the signature length.
#[inline(never)]
pub async fn dpe_sign_ecc_p384<A: ScratchAlloc>(
    alloc: &A,
    handle: Option<&DpeContextHandle>,
    label: &[u8; DPE_LABEL_LEN],
    digest: &[u8],
    signature: &mut [u8],
) -> McuResult<(DpeContextHandle, usize)> {
    if signature.len() < DPE_P384_SIGNATURE_SIZE || digest.len() < DPE_P384_DIGEST_SIZE {
        return Err(INVARIANT);
    }

    let req = build_invoke_dpe_req(
        alloc,
        DpeProfile::P384Sha384,
        None,
        &SignP384Cmd {
            handle: ContextHandle(*handle.unwrap_or(&DEFAULT_DPE_CONTEXT_HANDLE)),
            label: *label,
            flags: SignFlags::empty(),
            digest: *digest
                .first_chunk::<DPE_P384_DIGEST_SIZE>()
                .ok_or(INVARIANT)?,
        },
    )?;

    let rsp_max = INVOKE_DPE_RESP_PREFIX_LEN + size_of::<SignP384Resp>();
    let mut rsp = alloc.alloc(rsp_max)?;
    let rsp_len = mbox_execute(CMD_INVOKE_DPE, &req, &mut rsp).await?;

    let outer_prefix_len = INVOKE_DPE_RESP_PREFIX_LEN;
    let resp_body_off = outer_prefix_len;
    if rsp_len < resp_body_off + size_of::<SignP384Resp>() {
        return Err(INTERNAL_BUG);
    }

    let sign_resp = SignP384Resp::try_read_from_bytes(internal_slice(
        &rsp,
        resp_body_off,
        size_of::<SignP384Resp>(),
    )?)
    .map_err(|_| INTERNAL_BUG)?;
    check_dpe_response_hdr(&sign_resp.resp_hdr)?;
    let (sig_r, rest) = signature.split_first_chunk_mut::<48>().ok_or(INVARIANT)?;
    *sig_r = sign_resp.sig_r;
    let (sig_s, _) = rest.split_first_chunk_mut::<48>().ok_or(INVARIANT)?;
    *sig_s = sign_resp.sig_s;
    Ok((sign_resp.new_context_handle.0, DPE_P384_SIGNATURE_SIZE))
}

/// Invoke DPE `Sign` for ML-DSA-87 using a precomputed external `mu`.
///
/// `signature` must provide at least [`DPE_MLDSA87_SIGNATURE_SIZE`] bytes.
/// Returns the rotated context handle and signature length.
#[inline(never)]
pub async fn dpe_sign_mldsa87<A: ScratchAlloc>(
    alloc: &A,
    handle: Option<&DpeContextHandle>,
    label: &[u8; DPE_LABEL_LEN],
    mu: &[u8; DPE_MLDSA87_MU_SIZE],
    signature: &mut [u8],
) -> McuResult<(DpeContextHandle, usize)> {
    if signature.len() < DPE_MLDSA87_SIGNATURE_SIZE {
        return Err(INVARIANT);
    }

    // The request is written into the head of the response buffer and sent from there.
    let mut response = alloc.alloc(SIGN_MLDSA87_RESP_LEN)?;
    write_invoke_dpe_req(
        &mut response,
        DpeProfile::Mldsa87,
        None,
        &SignMldsa87Cmd {
            handle: ContextHandle(*handle.unwrap_or(&DEFAULT_DPE_CONTEXT_HANDLE)),
            label: *label,
            flags: SignFlags::empty(),
            // `caliptra-dpe` names this field `digest`; for ML-DSA-87 it carries the precomputed external `mu`.
            digest: *mu,
        },
    )?;
    let response_len = mbox_execute_in_place(
        CMD_INVOKE_DPE_MLDSA87,
        SIGN_MLDSA87_REQ_LEN,
        SIGN_MLDSA87_RESP_LEN,
        &mut response,
    )
    .await?;
    parse_sign_mldsa87_response(&response, response_len, signature)
}

fn parse_sign_mldsa87_response(
    response: &[u8],
    response_len: usize,
    signature: &mut [u8],
) -> McuResult<(DpeContextHandle, usize)> {
    if signature.len() < DPE_MLDSA87_SIGNATURE_SIZE {
        return Err(INVARIANT);
    }
    let body_offset = INVOKE_DPE_RESP_PREFIX_LEN;
    if response_len < body_offset + size_of::<ResponseHdr>() {
        return Err(INTERNAL_BUG);
    }
    let dpe_header = read_dpe_response_hdr(response, body_offset)?;
    if dpe_header.profile != caliptra_dpe::DpeProfile::Mldsa87 {
        return Err(INTERNAL_BUG);
    }
    if response_len != SIGN_MLDSA87_RESP_LEN {
        return Err(INTERNAL_BUG);
    }

    // `SignMlDsaResp` is 4.6 KB, so it's addressed in place rather than copied onto the stack.
    let sign_response = internal_slice(response, body_offset, size_of::<SignMlDsaResp>())?;
    if internal_slice(sign_response, SIGN_MLDSA87_RESP_PADDING_OFF, 1)? != [0] {
        return Err(INTERNAL_BUG);
    }
    copy_bytes(
        signature
            .get_mut(..DPE_MLDSA87_SIGNATURE_SIZE)
            .ok_or(INVARIANT)?,
        internal_slice(
            sign_response,
            SIGN_MLDSA87_RESP_SIG_OFF,
            DPE_MLDSA87_SIGNATURE_SIZE,
        )?,
    )?;
    Ok((
        read_fixed(sign_response, SIGN_MLDSA87_RESP_HANDLE_OFF)?,
        DPE_MLDSA87_SIGNATURE_SIZE,
    ))
}

/// Invoke DPE `RotateContextHandle` for the default context handle,
/// returning the new (rotated) 16-byte context handle.
///
/// The request targets the default (all-zero) DPE context handle with
/// empty flags, which asks DPE to rotate that context to a freshly
/// generated, non-default handle and return it. MCU Runtime boot
/// initialization uses this to obtain a stable MCU-held handle for the
/// MCU Runtime context.
#[inline(never)]
pub async fn dpe_rotate_context_default<A: ScratchAlloc>(
    alloc: &A,
) -> McuResult<[u8; DPE_CONTEXT_HANDLE_SIZE]> {
    // The default (all-zero) context handle with empty `flags` requests a freshly generated handle.
    let req = build_invoke_dpe_req(
        alloc,
        DpeProfile::P384Sha384,
        None,
        &RotateCtxCmd {
            handle: ContextHandle::default(),
            flags: RotateCtxFlags::empty(),
        },
    )?;

    let rsp_max = INVOKE_DPE_RESP_PREFIX_LEN + size_of::<NewHandleResp>();
    let mut rsp = alloc.alloc(rsp_max)?;
    let rsp_len = mbox_execute(CMD_INVOKE_DPE, &req, &mut rsp).await?;

    let resp_body_off = INVOKE_DPE_RESP_PREFIX_LEN;
    if rsp_len < resp_body_off + size_of::<NewHandleResp>() {
        return Err(INTERNAL_BUG);
    }
    let body = NewHandleResp::try_read_from_bytes(internal_slice(
        &rsp,
        resp_body_off,
        size_of::<NewHandleResp>(),
    )?)
    .map_err(|_| INTERNAL_BUG)?;
    check_dpe_response_hdr(&body.resp_hdr)?;
    Ok(body.handle.0)
}

/// Tag the DPE context identified by `handle` with `tag` via the
/// top-level Caliptra `DPE_TAG_TCI` mailbox command.
///
/// Unlike the other DPE helpers here, `DPE_TAG_TCI` is a dedicated
/// Caliptra mailbox command rather than an `INVOKE_DPE` sub-command.
/// MCU Runtime boot initialization tags the rotated MCU Runtime
/// context so its TCI can later be read back by tag.
#[inline(never)]
pub async fn dpe_tag_tci<A: ScratchAlloc>(
    alloc: &A,
    handle: &[u8; DPE_CONTEXT_HANDLE_SIZE],
    tag: u32,
) -> McuResult<()> {
    let mut req = alloc.alloc(TAG_TCI_REQ_LEN)?;
    TagTciReq {
        hdr: MailboxReqHeader::default(),
        handle: *handle,
        tag,
    }
    .write_to(checked_slice_mut(&mut req, 0, TAG_TCI_REQ_LEN)?)
    .map_err(|_| INVARIANT)?;
    populate_checksum(CMD_DPE_TAG_TCI, &mut req)?;

    let mut rsp = alloc.alloc(MBOX_RESP_HEADER_SIZE)?;
    let rsp_len = mbox_execute(CMD_DPE_TAG_TCI, &req, &mut rsp).await?;
    if rsp_len < MBOX_RESP_HEADER_SIZE {
        return Err(INTERNAL_BUG);
    }
    Ok(())
}

/// Read cumulative and current TCI values for the DPE context associated with `tag`.
#[inline(never)]
pub async fn dpe_get_tagged_tci<A: ScratchAlloc>(alloc: &A, tag: u32) -> McuResult<DpeTaggedTci> {
    let req = build_get_tagged_tci_req(alloc, tag)?;
    let mut rsp = alloc.alloc(GET_TAGGED_TCI_RESP_LEN)?;
    let rsp_len = mbox_execute(CMD_DPE_GET_TAGGED_TCI, &req, &mut rsp).await?;
    parse_get_tagged_tci_response(&rsp, rsp_len)
}

fn build_get_tagged_tci_req<A: ScratchAlloc>(alloc: &A, tag: u32) -> McuResult<A::Buf<'_>> {
    let mut req = alloc.alloc(GET_TAGGED_TCI_REQ_LEN)?;
    GetTaggedTciReq {
        hdr: MailboxReqHeader::default(),
        tag,
    }
    .write_to(checked_slice_mut(&mut req, 0, GET_TAGGED_TCI_REQ_LEN)?)
    .map_err(|_| INVARIANT)?;
    populate_checksum(CMD_DPE_GET_TAGGED_TCI, &mut req)?;
    Ok(req)
}

fn parse_get_tagged_tci_response(rsp: &[u8], rsp_len: usize) -> McuResult<DpeTaggedTci> {
    if rsp_len < GET_TAGGED_TCI_RESP_LEN {
        return Err(INTERNAL_BUG);
    }
    let resp = internal_slice(rsp, 0, GET_TAGGED_TCI_RESP_LEN)?;
    Ok(DpeTaggedTci {
        tci_cumulative: read_fixed(resp, GET_TAGGED_TCI_RESP_CUMULATIVE_OFF)?,
        tci_current: read_fixed(resp, GET_TAGGED_TCI_RESP_CURRENT_OFF)?,
    })
}

/// Revoke a previously derived exported CDI handle in Caliptra via the
/// top-level `REVOKE_EXPORTED_CDI_HANDLE` mailbox command.
#[inline(never)]
pub async fn dpe_revoke_exported_cdi_handle<A: ScratchAlloc>(
    alloc: &A,
    exported_cdi: &[u8; EXPORTED_CDI_SIZE],
) -> McuResult<()> {
    let req = build_revoke_exported_cdi_handle_req(alloc, exported_cdi)?;
    let mut rsp = alloc.alloc(MBOX_RESP_HEADER_SIZE)?;
    let rsp_len = mbox_execute(CMD_REVOKE_EXPORTED_CDI_HANDLE, &req, &mut rsp).await?;
    if rsp_len < MBOX_RESP_HEADER_SIZE {
        return Err(INTERNAL_BUG);
    }
    Ok(())
}

fn build_revoke_exported_cdi_handle_req<'a, A: ScratchAlloc>(
    alloc: &'a A,
    exported_cdi: &[u8; EXPORTED_CDI_SIZE],
) -> McuResult<A::Buf<'a>> {
    let mut req = alloc.alloc(REVOKE_EXPORTED_CDI_HANDLE_REQ_LEN)?;
    RevokeExportedCdiHandleReq {
        hdr: MailboxReqHeader::default(),
        exported_cdi_handle: *exported_cdi,
    }
    .write_to(checked_slice_mut(
        &mut req,
        0,
        REVOKE_EXPORTED_CDI_HANDLE_REQ_LEN,
    )?)
    .map_err(|_| INVARIANT)?;
    populate_checksum(CMD_REVOKE_EXPORTED_CDI_HANDLE, &mut req)?;
    Ok(req)
}

/// Sign with an exported CDI handle for a typed [`ExportedCdiSigningInput`].
///
/// Dispatches to [`dpe_sign_with_exported_ecdsa`] (`SIGN_WITH_EXPORTED_ECDSA`) or
/// [`dpe_sign_with_exported_mldsa`] (`SIGN_WITH_EXPORTED_MLDSA`) and returns the
/// number of signature bytes written to `signature`.
#[inline(never)]
pub async fn dpe_sign_with_exported_cdi<A: ScratchAlloc>(
    alloc: &A,
    exported_cdi: &[u8; EXPORTED_CDI_SIZE],
    input: ExportedCdiSigningInput<'_>,
    signature: &mut [u8],
) -> McuResult<usize> {
    match input {
        ExportedCdiSigningInput::EccP384Digest(digest) => {
            dpe_sign_with_exported_ecdsa(alloc, exported_cdi, digest, signature).await
        }
        ExportedCdiSigningInput::Mldsa87Raw(tbs) => {
            dpe_sign_with_exported_mldsa(alloc, exported_cdi, tbs, signature).await
        }
    }
}

/// Sign a 48-byte SHA-384 digest using an exported CDI handle via
/// `SIGN_WITH_EXPORTED_ECDSA`, writing the 96-byte `(r || s)` signature into `signature`.
#[inline(never)]
pub async fn dpe_sign_with_exported_ecdsa<A: ScratchAlloc>(
    alloc: &A,
    exported_cdi: &[u8; EXPORTED_CDI_SIZE],
    digest: &[u8; DPE_P384_DIGEST_SIZE],
    signature: &mut [u8],
) -> McuResult<usize> {
    if signature.len() < DPE_P384_SIGNATURE_SIZE {
        return Err(INVARIANT);
    }
    let req = build_sign_with_exported_ecdsa_req(alloc, exported_cdi, digest)?;
    let mut rsp = alloc.alloc(SIGN_WITH_EXPORTED_ECDSA_RESP_LEN)?;
    let rsp_len = mbox_execute(CMD_SIGN_WITH_EXPORTED_ECDSA, &req, &mut rsp).await?;
    parse_sign_with_exported_ecdsa_response(&rsp, rsp_len, signature)
}

fn build_sign_with_exported_ecdsa_req<'a, A: ScratchAlloc>(
    alloc: &'a A,
    exported_cdi: &[u8; EXPORTED_CDI_SIZE],
    digest: &[u8; DPE_P384_DIGEST_SIZE],
) -> McuResult<A::Buf<'a>> {
    let mut req = alloc.alloc(SIGN_WITH_EXPORTED_ECDSA_REQ_LEN)?;
    SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader::default(),
        exported_cdi_handle: *exported_cdi,
        tbs: *digest,
    }
    .write_to(checked_slice_mut(
        &mut req,
        0,
        SIGN_WITH_EXPORTED_ECDSA_REQ_LEN,
    )?)
    .map_err(|_| INVARIANT)?;
    populate_checksum(CMD_SIGN_WITH_EXPORTED_ECDSA, &mut req)?;
    Ok(req)
}

fn parse_sign_with_exported_ecdsa_response(
    rsp: &[u8],
    rsp_len: usize,
    signature: &mut [u8],
) -> McuResult<usize> {
    if signature.len() < DPE_P384_SIGNATURE_SIZE {
        return Err(INVARIANT);
    }
    if rsp_len < SIGN_WITH_EXPORTED_ECDSA_RESP_LEN {
        return Err(INTERNAL_BUG);
    }
    // `SignWithExportedEcdsaResp` is 200 B, so only the signature halves are copied out.
    let resp = internal_slice(rsp, 0, SIGN_WITH_EXPORTED_ECDSA_RESP_LEN)?;
    let (sig_r, rest) = signature.split_first_chunk_mut::<48>().ok_or(INVARIANT)?;
    *sig_r = read_fixed(resp, SIGN_WITH_EXPORTED_ECDSA_RESP_SIG_R_OFF)?;
    let (sig_s, _) = rest.split_first_chunk_mut::<48>().ok_or(INVARIANT)?;
    *sig_s = read_fixed(resp, SIGN_WITH_EXPORTED_ECDSA_RESP_SIG_S_OFF)?;
    Ok(DPE_P384_SIGNATURE_SIZE)
}

/// Sign raw TBS bytes (up to [`EXPORTED_CDI_MAX_MLDSA87_TBS_SIZE`]) using an exported CDI
/// handle via `SIGN_WITH_EXPORTED_MLDSA`, writing the 4,627-byte signature into `signature`.
#[inline(never)]
pub async fn dpe_sign_with_exported_mldsa<A: ScratchAlloc>(
    alloc: &A,
    exported_cdi: &[u8; EXPORTED_CDI_SIZE],
    tbs: &[u8],
    signature: &mut [u8],
) -> McuResult<usize> {
    if signature.len() < DPE_MLDSA87_SIGNATURE_SIZE || tbs.len() > EXPORTED_CDI_MAX_MLDSA87_TBS_SIZE
    {
        return Err(INVARIANT);
    }
    if signature.len() >= SIGN_WITH_EXPORTED_MLDSA_RESP_LEN {
        let mbox_buf = signature
            .get_mut(..SIGN_WITH_EXPORTED_MLDSA_RESP_LEN)
            .ok_or(INVARIANT)?;
        write_sign_with_exported_mldsa_req(
            &mut mbox_buf[..SIGN_WITH_EXPORTED_MLDSA_REQ_LEN],
            exported_cdi,
            tbs,
        )?;
        let rsp_len = mbox_execute_in_place(
            CMD_SIGN_WITH_EXPORTED_MLDSA,
            SIGN_WITH_EXPORTED_MLDSA_REQ_LEN,
            SIGN_WITH_EXPORTED_MLDSA_RESP_LEN,
            mbox_buf,
        )
        .await?;
        if rsp_len < SIGN_WITH_EXPORTED_MLDSA_RESP_LEN {
            return Err(INTERNAL_BUG);
        }
        mbox_buf.copy_within(
            SIGN_WITH_EXPORTED_MLDSA_RESP_SIG_OFF
                ..SIGN_WITH_EXPORTED_MLDSA_RESP_SIG_OFF + DPE_MLDSA87_SIGNATURE_SIZE,
            0,
        );
        return Ok(DPE_MLDSA87_SIGNATURE_SIZE);
    }

    let mut buf = alloc.alloc(SIGN_WITH_EXPORTED_MLDSA_RESP_LEN)?;
    write_sign_with_exported_mldsa_req(
        &mut buf[..SIGN_WITH_EXPORTED_MLDSA_REQ_LEN],
        exported_cdi,
        tbs,
    )?;
    let rsp_len = mbox_execute_in_place(
        CMD_SIGN_WITH_EXPORTED_MLDSA,
        SIGN_WITH_EXPORTED_MLDSA_REQ_LEN,
        SIGN_WITH_EXPORTED_MLDSA_RESP_LEN,
        &mut buf,
    )
    .await?;
    parse_sign_with_exported_mldsa_response(&buf, rsp_len, signature)
}

fn write_sign_with_exported_mldsa_req(
    req: &mut [u8],
    exported_cdi: &[u8; EXPORTED_CDI_SIZE],
    tbs: &[u8],
) -> McuResult<()> {
    if tbs.len() > EXPORTED_CDI_MAX_MLDSA87_TBS_SIZE {
        return Err(INVARIANT);
    }
    let req = checked_slice_mut(req, 0, SIGN_WITH_EXPORTED_MLDSA_REQ_LEN)?;
    req.fill(0);
    write_fixed(req, SIGN_WITH_EXPORTED_MLDSA_REQ_CDI_OFF, exported_cdi)?;
    write_fixed(
        req,
        SIGN_WITH_EXPORTED_MLDSA_REQ_SIGN_TYPE_OFF,
        &(MldsaSignType::Raw as u32).to_le_bytes(),
    )?;
    write_fixed(
        req,
        SIGN_WITH_EXPORTED_MLDSA_REQ_TBS_SIZE_OFF,
        &(tbs.len() as u32).to_le_bytes(),
    )?;
    write_fixed(req, SIGN_WITH_EXPORTED_MLDSA_REQ_TBS_OFF, tbs)?;
    populate_checksum(CMD_SIGN_WITH_EXPORTED_MLDSA, req)?;
    Ok(())
}

fn parse_sign_with_exported_mldsa_response(
    rsp: &[u8],
    rsp_len: usize,
    signature: &mut [u8],
) -> McuResult<usize> {
    if signature.len() < DPE_MLDSA87_SIGNATURE_SIZE {
        return Err(INVARIANT);
    }
    if rsp_len < SIGN_WITH_EXPORTED_MLDSA_RESP_LEN {
        return Err(INTERNAL_BUG);
    }
    let sig_bytes = internal_slice(
        rsp,
        SIGN_WITH_EXPORTED_MLDSA_RESP_SIG_OFF,
        DPE_MLDSA87_SIGNATURE_SIZE,
    )?;
    copy_bytes(
        signature
            .get_mut(..DPE_MLDSA87_SIGNATURE_SIZE)
            .ok_or(INVARIANT)?,
        sig_bytes,
    )?;
    Ok(DPE_MLDSA87_SIGNATURE_SIZE)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;
    use zerocopy::FromBytes;

    /// DPE per-command-header magic, pinned independently of `caliptra-dpe` (`CommandHdr::DPE_COMMAND_MAGIC` is private there).
    const DPE_COMMAND_MAGIC: u32 = u32::from_be_bytes(*b"DPEC");

    /// Decode the leading bytes of a request as the `caliptra-api` type `T`, zero-extending its variable-length tail.
    fn decode_padded<T: FromBytes>(bytes: &[u8]) -> T {
        let mut full = std::vec![0u8; size_of::<T>()];
        full[..bytes.len()].copy_from_slice(bytes);
        T::read_from_bytes(&full).unwrap()
    }

    /// DPE payload length (`CommandHdr` + body) an `INVOKE_DPE` request carrying `C` announces in `data_size`.
    const fn dpe_payload_len<C: DpeCommand>() -> u32 {
        (size_of::<CommandHdr>() + size_of::<C>()) as u32
    }

    const GET_CERT_CHAIN_REQ_P384_LEN: usize =
        invoke_dpe_req_len::<GetCertificateChainCmd>(DpeProfile::P384Sha384);
    const GET_CERT_CHAIN_REQ_MLDSA87_LEN: usize =
        invoke_dpe_req_len::<GetCertificateChainCmd>(DpeProfile::Mldsa87);
    const GET_CERT_CHAIN_CMD: GetCertificateChainCmd = GetCertificateChainCmd {
        offset: 0x0102_0304,
        size: 0x0506_0708,
    };

    struct TestAlloc;

    impl ScratchAlloc for TestAlloc {
        type Buf<'a>
            = Vec<u8>
        where
            Self: 'a;

        fn alloc(&self, len: usize) -> McuResult<Self::Buf<'_>> {
            Ok(std::vec![0; len])
        }
    }

    #[test]
    fn rotate_ctx_wire_layout() {
        assert_eq!(RotateCtxCmd::ID, 0x0e);
        assert_eq!(size_of::<RotateCtxCmd>(), DPE_CONTEXT_HANDLE_SIZE + 4);
        assert_eq!(size_of::<NewHandleResp>(), 12 + DPE_CONTEXT_HANDLE_SIZE);
        assert_eq!(
            invoke_dpe_req_len::<RotateCtxCmd>(DpeProfile::P384Sha384),
            8 + 12 + 20
        );
        assert_eq!(dpe_payload_len::<RotateCtxCmd>(), (12 + 20) as u32);
    }

    #[test]
    fn derive_context_wire_layout() {
        assert_eq!(DeriveContextCmd::ID, 0x08);
        assert_eq!(
            DpeDeriveContextFlags::RETAIN_PARENT_CONTEXT.bits(),
            1u32 << 29
        );
        assert_eq!(
            size_of::<DeriveContextCmd>(),
            DPE_CONTEXT_HANDLE_SIZE + 48 + 4 + 4 + 4 + 4
        );
        assert_eq!(
            size_of::<DeriveContextResp>(),
            12 + DPE_CONTEXT_HANDLE_SIZE * 2
        );
        assert_eq!(
            invoke_dpe_req_len::<DeriveContextCmd>(DpeProfile::P384Sha384),
            8 + 12 + 80
        );
        assert_eq!(dpe_payload_len::<DeriveContextCmd>(), (12 + 80) as u32);
    }

    #[test]
    fn update_context_measurement_wire_layout() {
        assert_eq!(UpdateContextMeasurementCmd::ID, 0x8000_0000);
        assert_eq!(
            size_of::<UpdateContextMeasurementCmd>(),
            DPE_CONTEXT_HANDLE_SIZE + 48 + 4 + 4 + 4
        );
        assert_eq!(
            size_of::<UpdateContextMeasurementResp>(),
            12 + DPE_CONTEXT_HANDLE_SIZE * 2
        );
        assert_eq!(
            invoke_dpe_req_len::<UpdateContextMeasurementCmd>(DpeProfile::P384Sha384),
            8 + 12 + 76
        );
        assert_eq!(
            dpe_payload_len::<UpdateContextMeasurementCmd>(),
            (12 + 76) as u32
        );
    }

    #[test]
    fn tag_tci_wire_layout() {
        assert_eq!(CMD_DPE_TAG_TCI, 0x5451_4754);
        assert_eq!(TAG_TCI_REQ_LEN, 4 + DPE_CONTEXT_HANDLE_SIZE + 4);
    }

    #[test]
    fn get_tagged_tci_wire_layout() {
        assert_eq!(CMD_DPE_GET_TAGGED_TCI, 0x4754_4744);
        assert_eq!(GET_TAGGED_TCI_REQ_LEN, 8);
        assert_eq!(GET_TAGGED_TCI_RESP_LEN, 8 + DPE_TCI_MEASUREMENT_SIZE * 2);
    }

    #[test]
    fn get_tagged_tci_request_preserves_tag() {
        let alloc = TestAlloc;
        let tag = 0x1122_3344;

        let req = build_get_tagged_tci_req(&alloc, tag).unwrap();
        let mut checksum_input = req.clone();
        checksum_input[0..4].fill(0);

        assert_eq!(
            req.get(0..4).and_then(|s| s.first_chunk::<4>()),
            Some(&calc_checksum(CMD_DPE_GET_TAGGED_TCI, &checksum_input).to_le_bytes())
        );
        assert_eq!(
            req.get(4..8).and_then(|s| s.first_chunk::<4>()),
            Some(&tag.to_le_bytes())
        );
    }

    #[test]
    fn certify_key_chunks_uses_supplied_handle() {
        let handle = [0xa5u8; DPE_CONTEXT_HANDLE_SIZE];
        let label = [0x5au8; DPE_LABEL_LEN];
        let alloc = TestAlloc;

        let req =
            build_certify_key_chunks_req(&alloc, DpeProfile::P384Sha384, &label, &handle, 0, 128)
                .unwrap();

        assert_eq!(
            &req[CERTIFY_KEY_CHUNKS_REQ_HANDLE_OFF
                ..CERTIFY_KEY_CHUNKS_REQ_HANDLE_OFF + DPE_CONTEXT_HANDLE_SIZE],
            &handle
        );

        let req_mldsa =
            build_certify_key_chunks_req(&alloc, DpeProfile::Mldsa87, &label, &handle, 0, 128)
                .unwrap();
        assert_eq!(
            u32::from_le_bytes(req_mldsa[4..8].try_into().unwrap()),
            CERTIFY_KEY_FLAG_USE_MLDSA
        );
    }

    #[test]
    fn derive_context_request_preserves_fields() {
        let alloc = TestAlloc;
        let params = DpeDeriveContextParams {
            parent_handle: [0xa5u8; DPE_CONTEXT_HANDLE_SIZE],
            measurement: [0x5au8; DPE_TCI_MEASUREMENT_SIZE],
            flags: DpeDeriveContextFlags::RETAIN_PARENT_CONTEXT,
            tci_type: 0x1122_3344,
            target_locality: 0,
            svn: 7,
        };

        let req = build_invoke_dpe_req(
            &alloc,
            DpeProfile::P384Sha384,
            None,
            &DeriveContextCmd::from(&params),
        )
        .unwrap();
        let mut checksum_input = req.clone();
        checksum_input[..4].fill(0);
        assert_eq!(
            req.first_chunk::<4>(),
            Some(&calc_checksum(CMD_INVOKE_DPE, &checksum_input).to_le_bytes())
        );
        let payload_len =
            u32::from_le_bytes(*req.get(4..8).and_then(|s| s.first_chunk::<4>()).unwrap());
        let hdr = CommandHdr::read_from_bytes(&req[8..20]).unwrap();
        let cmd = DeriveContextCmd::read_from_bytes(&req[20..100]).unwrap();

        assert_eq!(payload_len, dpe_payload_len::<DeriveContextCmd>());
        assert_eq!(hdr.cmd_id, DeriveContextCmd::ID);
        assert_eq!(cmd.handle.0, params.parent_handle);
        assert_eq!(cmd.data.0, params.measurement);
        assert_eq!(cmd.flags.bits(), params.flags.bits());
        assert_eq!(cmd.tci_type, params.tci_type);
        assert_eq!(cmd.target_locality, params.target_locality);
        assert_eq!(cmd.svn, params.svn);
    }

    #[test]
    fn derive_context_mldsa87_request_preserves_fields() {
        let alloc = TestAlloc;
        let params = DpeDeriveContextParams {
            parent_handle: [0xa5u8; DPE_CONTEXT_HANDLE_SIZE],
            measurement: [0x5au8; DPE_TCI_MEASUREMENT_SIZE],
            flags: DpeDeriveContextFlags::RETAIN_PARENT_CONTEXT,
            tci_type: 0x1122_3344,
            target_locality: 0,
            svn: 7,
        };

        let axi_response = AxiDmaTarget {
            addr: 0xA8C0_1000,
            max_size: 24576,
        };
        let req = build_invoke_dpe_req(
            &alloc,
            DpeProfile::Mldsa87,
            Some(axi_response.into()),
            &DeriveContextCmd::from(&params),
        )
        .unwrap();
        let mut checksum_input = req.clone();
        checksum_input[..4].fill(0);
        assert_eq!(
            req.first_chunk::<4>(),
            Some(&calc_checksum(CMD_INVOKE_DPE_MLDSA87, &checksum_input).to_le_bytes())
        );
        let prefix: InvokeDpeMldsa87Req = decode_padded(&req);
        assert_eq!(prefix.flags.bits(), 1 << 31);
        assert!(prefix.flags.external_axi_response());
        assert_eq!(prefix.axi_response.addr_lo, 0xA8C0_1000);
        assert_eq!(prefix.axi_response.addr_hi, 0);
        assert_eq!(prefix.axi_response.max_size, 24576);
        assert_eq!(prefix.data_size, dpe_payload_len::<DeriveContextCmd>());
    }

    #[test]
    fn update_context_measurement_request_preserves_fields() {
        let alloc = TestAlloc;
        let params = DpeUpdateContextMeasurementParams {
            parent_handle: [0xa5u8; DPE_CONTEXT_HANDLE_SIZE],
            measurement: [0x5au8; DPE_TCI_MEASUREMENT_SIZE],
            tci_type: 0x1122_3344,
        };

        let req = build_invoke_dpe_req(
            &alloc,
            DpeProfile::P384Sha384,
            None,
            &UpdateContextMeasurementCmd::from(&params),
        )
        .unwrap();
        let payload_len =
            u32::from_le_bytes(*req.get(4..8).and_then(|s| s.first_chunk::<4>()).unwrap());
        let hdr = CommandHdr::read_from_bytes(&req[8..20]).unwrap();
        let cmd = UpdateContextMeasurementCmd::read_from_bytes(&req[20..96]).unwrap();

        assert_eq!(
            payload_len,
            dpe_payload_len::<UpdateContextMeasurementCmd>()
        );
        assert_eq!(hdr.cmd_id, UpdateContextMeasurementCmd::ID);
        assert_eq!(cmd.parent_handle.0, params.parent_handle);
        assert_eq!(cmd.data.0, params.measurement);
        assert_eq!(cmd.reserved, 0);
        assert_eq!(cmd.tci_type, params.tci_type);
        assert_eq!(cmd.reserved_svn, 0);
    }

    #[test]
    fn certify_key_chunks_reads_returned_handle_from_response_info() {
        let handle = [0x3cu8; DPE_CONTEXT_HANDLE_SIZE];
        let mut rsp = [0u8; CERTIFY_KEY_CHUNKS_RESP_INFO_LEN];
        rsp[CERTIFY_KEY_CHUNKS_RESP_HANDLE_OFF
            ..CERTIFY_KEY_CHUNKS_RESP_HANDLE_OFF + DPE_CONTEXT_HANDLE_SIZE]
            .copy_from_slice(&handle);

        assert_eq!(
            read_fixed::<DPE_CONTEXT_HANDLE_SIZE>(&rsp, CERTIFY_KEY_CHUNKS_RESP_HANDLE_OFF)
                .unwrap(),
            handle
        );
    }

    #[test]
    fn certify_key_mldsa87_pubkey_extractor() {
        let expected_key = [0x5au8; CERTIFY_KEY_MLDSA87_PUBKEY_SIZE];
        let mut response = std::vec![0u8; CERTIFY_KEY_MLDSA87_RESP_PREFIX_LEN];
        response[..4].copy_from_slice(&DPE_RESPONSE_MAGIC.to_le_bytes());
        response[8..12].copy_from_slice(&DPE_PROFILE_MLDSA87.to_le_bytes());
        response[CERTIFY_KEY_MLDSA87_RESP_PUBKEY_OFF
            ..CERTIFY_KEY_MLDSA87_RESP_PUBKEY_OFF + CERTIFY_KEY_MLDSA87_PUBKEY_SIZE]
            .copy_from_slice(&expected_key);

        let pubkey = extract_certify_key_mldsa87_pubkey(&response).unwrap();
        assert_eq!(pubkey, expected_key.as_slice());
    }

    #[test]
    fn sign_commands_carry_the_dpe_sign_id() {
        assert_eq!(SignP384Cmd::ID, 0x0a);
        assert_eq!(SignMldsa87Cmd::ID, 0x0a);
    }

    #[test]
    fn sign_mldsa87_response_parser_returns_handle_and_signature() {
        let handle = [0x44u8; DPE_CONTEXT_HANDLE_SIZE];
        let expected_signature = [0x55u8; DPE_MLDSA87_SIGNATURE_SIZE];
        let mut response = std::vec![0u8; SIGN_MLDSA87_RESP_LEN];
        let body_offset = INVOKE_DPE_RESP_PREFIX_LEN;
        response[body_offset..body_offset + 4].copy_from_slice(&DPE_RESPONSE_MAGIC.to_le_bytes());
        response[body_offset + 8..body_offset + 12]
            .copy_from_slice(&DPE_PROFILE_MLDSA87.to_le_bytes());
        response[body_offset + 12..body_offset + 12 + DPE_CONTEXT_HANDLE_SIZE]
            .copy_from_slice(&handle);
        let signature_offset = body_offset + 12 + DPE_CONTEXT_HANDLE_SIZE;
        response[signature_offset..signature_offset + DPE_MLDSA87_SIGNATURE_SIZE]
            .copy_from_slice(&expected_signature);

        let mut signature = std::vec![0u8; DPE_MLDSA87_SIGNATURE_SIZE];
        let result =
            parse_sign_mldsa87_response(&response, response.len(), &mut signature).unwrap();

        assert_eq!(result, (handle, DPE_MLDSA87_SIGNATURE_SIZE));
        assert_eq!(signature, expected_signature);
    }

    #[test]
    fn sign_mldsa87_response_parser_rejects_error_and_padding() {
        let mut response = std::vec![0u8; SIGN_MLDSA87_RESP_LEN];
        let body_offset = INVOKE_DPE_RESP_PREFIX_LEN;
        response[body_offset..body_offset + 4].copy_from_slice(&DPE_RESPONSE_MAGIC.to_le_bytes());
        response[body_offset + 8..body_offset + 12]
            .copy_from_slice(&DPE_PROFILE_MLDSA87.to_le_bytes());
        let mut signature = std::vec![0u8; DPE_MLDSA87_SIGNATURE_SIZE];

        response[body_offset + 4..body_offset + 8].copy_from_slice(&1u32.to_le_bytes());
        assert!(parse_sign_mldsa87_response(&response, response.len(), &mut signature).is_err());

        response[body_offset + 4..body_offset + 8].fill(0);
        *response.last_mut().unwrap() = 1;
        assert!(parse_sign_mldsa87_response(&response, response.len(), &mut signature).is_err());
    }

    #[test]
    fn derive_context_reads_child_and_parent_handles() {
        let child_handle = [0x3cu8; DPE_CONTEXT_HANDLE_SIZE];
        let parent_handle = [0xc3u8; DPE_CONTEXT_HANDLE_SIZE];
        let mut rsp = [0u8; 12 + 12 + DPE_CONTEXT_HANDLE_SIZE * 2];
        let resp_body_off = INVOKE_DPE_RESP_PREFIX_LEN;
        rsp[resp_body_off..resp_body_off + 4].copy_from_slice(&DPE_RESPONSE_MAGIC.to_le_bytes());
        rsp[resp_body_off + 8..resp_body_off + 12]
            .copy_from_slice(&DPE_PROFILE_P384_SHA384.to_le_bytes());
        rsp[resp_body_off + 12..resp_body_off + 12 + DPE_CONTEXT_HANDLE_SIZE]
            .copy_from_slice(&child_handle);
        rsp[resp_body_off + 12 + DPE_CONTEXT_HANDLE_SIZE
            ..resp_body_off + 12 + DPE_CONTEXT_HANDLE_SIZE * 2]
            .copy_from_slice(&parent_handle);

        assert_eq!(
            parse_derive_context_response(&rsp, rsp.len()).unwrap(),
            DpeDeriveContextResult {
                child_handle,
                parent_handle
            }
        );
    }

    #[test]
    fn update_context_measurement_reads_component_and_parent_handles() {
        let component_handle = [0x3cu8; DPE_CONTEXT_HANDLE_SIZE];
        let parent_handle = [0xc3u8; DPE_CONTEXT_HANDLE_SIZE];
        let mut rsp = [0u8; 12 + 12 + DPE_CONTEXT_HANDLE_SIZE * 2];
        let resp_body_off = INVOKE_DPE_RESP_PREFIX_LEN;
        rsp[resp_body_off..resp_body_off + 4].copy_from_slice(&DPE_RESPONSE_MAGIC.to_le_bytes());
        rsp[resp_body_off + 8..resp_body_off + 12]
            .copy_from_slice(&DPE_PROFILE_P384_SHA384.to_le_bytes());
        rsp[resp_body_off + 12..resp_body_off + 12 + DPE_CONTEXT_HANDLE_SIZE]
            .copy_from_slice(&component_handle);
        rsp[resp_body_off + 12 + DPE_CONTEXT_HANDLE_SIZE
            ..resp_body_off + 12 + DPE_CONTEXT_HANDLE_SIZE * 2]
            .copy_from_slice(&parent_handle);

        assert_eq!(
            parse_update_context_measurement_response(&rsp, rsp.len()).unwrap(),
            DpeUpdateContextMeasurementResult {
                component_handle,
                parent_handle
            }
        );
    }

    #[test]
    fn update_context_measurement_rejects_dpe_error_status() {
        let mut rsp = [0u8; 12 + 12 + DPE_CONTEXT_HANDLE_SIZE * 2];
        let resp_body_off = INVOKE_DPE_RESP_PREFIX_LEN;
        rsp[resp_body_off..resp_body_off + 4].copy_from_slice(&DPE_RESPONSE_MAGIC.to_le_bytes());
        rsp[resp_body_off + 4..resp_body_off + 8].copy_from_slice(&1u32.to_le_bytes());
        rsp[resp_body_off + 8..resp_body_off + 12]
            .copy_from_slice(&DPE_PROFILE_P384_SHA384.to_le_bytes());

        assert!(parse_update_context_measurement_response(&rsp, rsp.len()).is_err());
    }

    #[test]
    fn get_tagged_tci_response_reads_current_and_cumulative() {
        let cumulative = [0x11u8; DPE_TCI_MEASUREMENT_SIZE];
        let current = [0x22u8; DPE_TCI_MEASUREMENT_SIZE];
        let mut rsp = [0u8; 8 + DPE_TCI_MEASUREMENT_SIZE * 2];
        rsp[8..8 + DPE_TCI_MEASUREMENT_SIZE].copy_from_slice(&cumulative);
        rsp[8 + DPE_TCI_MEASUREMENT_SIZE..].copy_from_slice(&current);

        assert_eq!(
            parse_get_tagged_tci_response(&rsp, rsp.len()).unwrap(),
            DpeTaggedTci {
                tci_cumulative: cumulative,
                tci_current: current,
            }
        );
    }

    #[test]
    fn get_tagged_tci_response_rejects_short_response() {
        let rsp = [0u8; 8 + DPE_TCI_MEASUREMENT_SIZE * 2 - 1];

        assert!(parse_get_tagged_tci_response(&rsp, rsp.len()).is_err());
    }
    #[test]
    fn derive_context_exported_cdi_reads_handles_cdi_and_cert() {
        let child_handle = [0x11u8; DPE_CONTEXT_HANDLE_SIZE];
        let parent_handle = [0x22u8; DPE_CONTEXT_HANDLE_SIZE];
        let exported_cdi = [0x33u8; EXPORTED_CDI_SIZE];
        let cert_data = [0x55u8; 64];

        let prefix_len = size_of::<DeriveContextExportedCdiRespHdr>();
        let resp_body_off = INVOKE_DPE_RESP_PREFIX_LEN;
        let mut rsp = [0u8; 12 + 80 + 64];

        rsp[resp_body_off..resp_body_off + 4].copy_from_slice(&DPE_RESPONSE_MAGIC.to_le_bytes());
        rsp[resp_body_off + 8..resp_body_off + 12]
            .copy_from_slice(&DPE_PROFILE_P384_SHA384.to_le_bytes());
        rsp[resp_body_off + 12..resp_body_off + 12 + DPE_CONTEXT_HANDLE_SIZE]
            .copy_from_slice(&child_handle);
        rsp[resp_body_off + 12 + DPE_CONTEXT_HANDLE_SIZE
            ..resp_body_off + 12 + DPE_CONTEXT_HANDLE_SIZE * 2]
            .copy_from_slice(&parent_handle);
        rsp[resp_body_off + 12 + DPE_CONTEXT_HANDLE_SIZE * 2
            ..resp_body_off + 12 + DPE_CONTEXT_HANDLE_SIZE * 2 + EXPORTED_CDI_SIZE]
            .copy_from_slice(&exported_cdi);
        rsp[resp_body_off + 12 + DPE_CONTEXT_HANDLE_SIZE * 2 + EXPORTED_CDI_SIZE
            ..resp_body_off + prefix_len]
            .copy_from_slice(&(cert_data.len() as u32).to_le_bytes());
        rsp[resp_body_off + prefix_len..].copy_from_slice(&cert_data);

        let rsp_len = rsp.len();
        let result =
            parse_derive_context_exported_cdi_response_in_place(&mut rsp, rsp_len).unwrap();

        assert_eq!(result.child_handle, child_handle);
        assert_eq!(result.parent_handle, parent_handle);
        assert_eq!(result.exported_cdi, exported_cdi);
        assert_eq!(result.cert_size, cert_data.len());
        assert_eq!(&rsp[..cert_data.len()], &cert_data);
    }

    #[test]
    fn derive_context_flags_bitor() {
        let flags = DpeDeriveContextFlags::EXPORT_CDI
            | DpeDeriveContextFlags::CREATE_CERTIFICATE
            | DpeDeriveContextFlags::RETAIN_PARENT_CONTEXT;
        assert_eq!(flags.bits(), (1u32 << 23) | (1u32 << 22) | (1u32 << 29));
    }

    #[test]
    fn dpe_profile_command_and_profile_ids() {
        assert_eq!(DpeProfile::P384Sha384 as u32, 4);
        assert_eq!(DpeProfile::P384Sha384.invoke_cmd_id(), CMD_INVOKE_DPE);
        assert_eq!(DpeProfile::Mldsa87 as u32, 5);
        assert_eq!(DpeProfile::Mldsa87.invoke_cmd_id(), CMD_INVOKE_DPE_MLDSA87);
    }

    #[test]
    fn signing_input_selects_dpe_profile() {
        let digest = [0u8; DPE_P384_DIGEST_SIZE];
        let mu = [0u8; DPE_MLDSA87_MU_SIZE];

        assert_eq!(
            SigningInput::EccP384Digest(&digest).profile(),
            DpeProfile::P384Sha384
        );
        assert_eq!(
            SigningInput::Mldsa87Message {
                context: b"ctx",
                prefix: b"prefix",
                hash: &digest,
            }
            .profile(),
            DpeProfile::Mldsa87
        );
        assert_eq!(SigningInput::Mldsa87Mu(&mu).profile(), DpeProfile::Mldsa87);
    }

    #[test]
    fn write_invoke_dpe_req_p384_and_mldsa87() {
        assert_eq!(GET_CERT_CHAIN_REQ_P384_LEN, 8 + 12 + 8);
        assert_eq!(GET_CERT_CHAIN_REQ_MLDSA87_LEN, 24 + 12 + 8);
        let payload_len = dpe_payload_len::<GetCertificateChainCmd>();

        // Start from a dirty buffer: the writer owns every byte of the request.
        let mut buf_p384 = [0xEEu8; GET_CERT_CHAIN_REQ_P384_LEN];
        write_invoke_dpe_req(
            &mut buf_p384,
            DpeProfile::P384Sha384,
            None,
            &GET_CERT_CHAIN_CMD,
        )
        .unwrap();
        let p384_prefix: InvokeDpeReq = decode_padded(&buf_p384);
        assert_eq!(p384_prefix.data_size, payload_len);
        let p384_hdr = CommandHdr::read_from_prefix(&buf_p384[8..]).unwrap().0;
        assert_eq!(p384_hdr.magic, DPE_COMMAND_MAGIC);
        assert_eq!(p384_hdr.cmd_id, GetCertificateChainCmd::ID);
        assert_eq!(p384_hdr.cmd_id, 0x10);
        assert_eq!(p384_hdr.profile, 4);
        assert_eq!(&buf_p384[8 + 12..], GET_CERT_CHAIN_CMD.as_bytes());
        let mut checksum_input = buf_p384;
        checksum_input[..4].fill(0);
        assert_eq!(
            p384_prefix.hdr.chksum,
            calc_checksum(CMD_INVOKE_DPE, &checksum_input)
        );

        let mut buf_mldsa = [0xEEu8; GET_CERT_CHAIN_REQ_MLDSA87_LEN];
        write_invoke_dpe_req(
            &mut buf_mldsa,
            DpeProfile::Mldsa87,
            None,
            &GET_CERT_CHAIN_CMD,
        )
        .unwrap();
        let mldsa_prefix: InvokeDpeMldsa87Req = decode_padded(&buf_mldsa);
        assert_eq!(mldsa_prefix.flags.bits(), 0);
        assert_eq!(mldsa_prefix.axi_response, AxiResponseInfo::default());
        assert_eq!(mldsa_prefix.data_size, payload_len);
        let mldsa_hdr = CommandHdr::read_from_prefix(&buf_mldsa[24..]).unwrap().0;
        assert_eq!(mldsa_hdr.magic, DPE_COMMAND_MAGIC);
        assert_eq!(mldsa_hdr.cmd_id, GetCertificateChainCmd::ID);
        assert_eq!(mldsa_hdr.profile, 5);
        assert_eq!(&buf_mldsa[24 + 12..], GET_CERT_CHAIN_CMD.as_bytes());
        let mut checksum_input = buf_mldsa;
        checksum_input[..4].fill(0);
        assert_eq!(
            mldsa_prefix.hdr.chksum,
            calc_checksum(CMD_INVOKE_DPE_MLDSA87, &checksum_input)
        );

        // A buffer one byte short of the request is rejected, not partially written.
        let mut short = [0xEEu8; GET_CERT_CHAIN_REQ_P384_LEN - 1];
        assert!(write_invoke_dpe_req(
            &mut short,
            DpeProfile::P384Sha384,
            None,
            &GET_CERT_CHAIN_CMD
        )
        .is_err());
        assert_eq!(short, [0xEEu8; GET_CERT_CHAIN_REQ_P384_LEN - 1]);
    }

    #[test]
    fn exported_cdi_signing_input_selects_dpe_profile() {
        let digest = [0u8; DPE_P384_DIGEST_SIZE];
        assert_eq!(
            ExportedCdiSigningInput::EccP384Digest(&digest).profile(),
            DpeProfile::P384Sha384
        );
        assert_eq!(
            ExportedCdiSigningInput::Mldsa87Raw(b"tbs").profile(),
            DpeProfile::Mldsa87
        );
    }

    #[test]
    fn revoke_exported_cdi_handle_request_preserves_handle() {
        let alloc = TestAlloc;
        let exported_cdi = [0x77u8; EXPORTED_CDI_SIZE];
        let req = build_revoke_exported_cdi_handle_req(&alloc, &exported_cdi).unwrap();

        let mut checksum_input = req.clone();
        checksum_input[0..4].fill(0);
        assert_eq!(
            req.get(0..4).and_then(|s| s.first_chunk::<4>()),
            Some(&calc_checksum(CMD_REVOKE_EXPORTED_CDI_HANDLE, &checksum_input).to_le_bytes())
        );
        assert_eq!(&req[4..4 + EXPORTED_CDI_SIZE], &exported_cdi);
    }

    #[test]
    fn sign_with_exported_ecdsa_request_and_response() {
        let alloc = TestAlloc;
        let exported_cdi = [0x11u8; EXPORTED_CDI_SIZE];
        let digest = [0x22u8; DPE_P384_DIGEST_SIZE];
        let req = build_sign_with_exported_ecdsa_req(&alloc, &exported_cdi, &digest).unwrap();

        let mut checksum_input = req.clone();
        checksum_input[0..4].fill(0);
        assert_eq!(
            req.get(0..4).and_then(|s| s.first_chunk::<4>()),
            Some(&calc_checksum(CMD_SIGN_WITH_EXPORTED_ECDSA, &checksum_input).to_le_bytes())
        );
        assert_eq!(&req[4..4 + EXPORTED_CDI_SIZE], &exported_cdi);
        assert_eq!(&req[4 + EXPORTED_CDI_SIZE..], &digest);

        let mut rsp = [0u8; SIGN_WITH_EXPORTED_ECDSA_RESP_LEN];
        let sig_r = [0xAAu8; 48];
        let sig_s = [0xBBu8; 48];
        rsp[8 + 96..8 + 144].copy_from_slice(&sig_r);
        rsp[8 + 144..8 + 192].copy_from_slice(&sig_s);

        let mut signature = [0u8; DPE_P384_SIGNATURE_SIZE];
        let len = parse_sign_with_exported_ecdsa_response(&rsp, rsp.len(), &mut signature).unwrap();
        assert_eq!(len, DPE_P384_SIGNATURE_SIZE);
        assert_eq!(&signature[..48], &sig_r);
        assert_eq!(&signature[48..], &sig_s);
    }

    #[test]
    fn sign_with_exported_mldsa_request_and_response() {
        let exported_cdi = [0x33u8; EXPORTED_CDI_SIZE];
        let tbs = [0x44u8; 64];
        let mut req = std::vec![0u8; SIGN_WITH_EXPORTED_MLDSA_REQ_LEN];
        write_sign_with_exported_mldsa_req(&mut req, &exported_cdi, &tbs).unwrap();

        let decoded: SignWithExportedMldsaReq = decode_padded(&req);
        assert_eq!(decoded.exported_cdi_handle, exported_cdi);
        assert_eq!(decoded.sign_type, MldsaSignType::Raw as u32);
        assert_eq!(decoded.tbs_size, tbs.len() as u32);
        assert_eq!(&decoded.tbs[..tbs.len()], &tbs);
        assert!(decoded.tbs[tbs.len()..].iter().all(|byte| *byte == 0));

        let mut rsp = std::vec![0u8; SIGN_WITH_EXPORTED_MLDSA_RESP_LEN];
        let expected_sig = [0x55u8; DPE_MLDSA87_SIGNATURE_SIZE];
        rsp[SIGN_WITH_EXPORTED_MLDSA_RESP_SIG_OFF
            ..SIGN_WITH_EXPORTED_MLDSA_RESP_SIG_OFF + DPE_MLDSA87_SIGNATURE_SIZE]
            .copy_from_slice(&expected_sig);

        let mut signature = std::vec![0u8; DPE_MLDSA87_SIGNATURE_SIZE];
        let len = parse_sign_with_exported_mldsa_response(&rsp, rsp.len(), &mut signature).unwrap();
        assert_eq!(len, DPE_MLDSA87_SIGNATURE_SIZE);
        assert_eq!(signature, expected_sig);
    }

    /// Returns a sub-slice of `backing` that starts at an odd address, which
    /// is misaligned for every 4-byte-aligned `caliptra-dpe` wire type.
    fn odd_aligned(backing: &mut [u8], len: usize) -> &mut [u8] {
        let skip = if (backing.as_ptr() as usize).is_multiple_of(2) {
            1
        } else {
            0
        };
        let slice = &mut backing[skip..skip + len];
        assert!(!(slice.as_ptr() as usize).is_multiple_of(2));
        slice
    }

    #[test]
    fn dpe_wire_types_tolerate_unaligned_buffers() {
        // Request side: the DPE command header and body are written by value.
        let mut backing = [0u8; GET_CERT_CHAIN_REQ_P384_LEN + 1];
        let req = odd_aligned(&mut backing, GET_CERT_CHAIN_REQ_P384_LEN);
        write_invoke_dpe_req(req, DpeProfile::P384Sha384, None, &GET_CERT_CHAIN_CMD).unwrap();
        assert_eq!(&req[8..12], &DPE_COMMAND_MAGIC.to_le_bytes());
        assert_eq!(&req[12..16], &GetCertificateChainCmd::ID.to_le_bytes());
        assert_eq!(&req[16..20], &DPE_PROFILE_P384_SHA384.to_le_bytes());
        assert_eq!(&req[20..], GET_CERT_CHAIN_CMD.as_bytes());

        // Response side: the body is copied out by value.
        let child_handle = [0x3cu8; DPE_CONTEXT_HANDLE_SIZE];
        let parent_handle = [0xc3u8; DPE_CONTEXT_HANDLE_SIZE];
        const RSP_LEN: usize = 12 + 12 + DPE_CONTEXT_HANDLE_SIZE * 2;
        let mut backing = [0u8; RSP_LEN + 1];
        let rsp = odd_aligned(&mut backing, RSP_LEN);
        rsp[12..16].copy_from_slice(&DPE_RESPONSE_MAGIC.to_le_bytes());
        rsp[20..24].copy_from_slice(&DPE_PROFILE_P384_SHA384.to_le_bytes());
        rsp[24..24 + DPE_CONTEXT_HANDLE_SIZE].copy_from_slice(&child_handle);
        rsp[24 + DPE_CONTEXT_HANDLE_SIZE..].copy_from_slice(&parent_handle);

        assert_eq!(
            parse_derive_context_response(rsp, RSP_LEN).unwrap(),
            DpeDeriveContextResult {
                child_handle,
                parent_handle
            }
        );
    }

    #[test]
    fn dpe_response_with_unknown_profile_is_rejected() {
        let mut rsp = [0u8; 12 + 12 + DPE_CONTEXT_HANDLE_SIZE * 2];
        let resp_body_off = INVOKE_DPE_RESP_PREFIX_LEN;
        rsp[resp_body_off..resp_body_off + 4].copy_from_slice(&DPE_RESPONSE_MAGIC.to_le_bytes());

        // Profile 0 is not a `caliptra_dpe::DpeProfile`.
        assert!(parse_derive_context_response(&rsp, rsp.len()).is_err());

        rsp[resp_body_off + 8..resp_body_off + 12]
            .copy_from_slice(&DPE_PROFILE_P384_SHA384.to_le_bytes());
        assert!(parse_derive_context_response(&rsp, rsp.len()).is_ok());
    }

    #[test]
    fn top_level_requests_match_caliptra_api_layouts() {
        let alloc = TestAlloc;

        let tag = 0x1122_3344;
        let req = build_get_tagged_tci_req(&alloc, tag).unwrap();
        let decoded = GetTaggedTciReq::read_from_bytes(&req).unwrap();
        assert_eq!(decoded.tag, tag);

        let exported_cdi = [0x77u8; EXPORTED_CDI_SIZE];
        let req = build_revoke_exported_cdi_handle_req(&alloc, &exported_cdi).unwrap();
        let decoded = RevokeExportedCdiHandleReq::read_from_bytes(&req).unwrap();
        assert_eq!(decoded.exported_cdi_handle, exported_cdi);

        let digest = [0x22u8; DPE_P384_DIGEST_SIZE];
        let req = build_sign_with_exported_ecdsa_req(&alloc, &exported_cdi, &digest).unwrap();
        let decoded = SignWithExportedEcdsaReq::read_from_bytes(&req).unwrap();
        assert_eq!(decoded.exported_cdi_handle, exported_cdi);
        assert_eq!(decoded.tbs, digest);
        let mut checksum_input = req.clone();
        checksum_input[..4].fill(0);
        assert_eq!(
            decoded.hdr.chksum,
            calc_checksum(CMD_SIGN_WITH_EXPORTED_ECDSA, &checksum_input)
        );
    }

    #[test]
    fn top_level_responses_match_caliptra_api_layouts() {
        let expected = GetTaggedTciResp {
            hdr: Default::default(),
            tci_cumulative: [0x11; DPE_TCI_MEASUREMENT_SIZE],
            tci_current: [0x22; DPE_TCI_MEASUREMENT_SIZE],
            svn: 0x0102_0304,
        };
        // Only the bytes ahead of `svn` are requested from the mailbox and read.
        let rsp = &expected.as_bytes()[..GET_TAGGED_TCI_RESP_LEN];
        assert_eq!(
            parse_get_tagged_tci_response(rsp, rsp.len()).unwrap(),
            DpeTaggedTci {
                tci_cumulative: expected.tci_cumulative,
                tci_current: expected.tci_current,
            }
        );

        let expected = SignWithExportedEcdsaResp {
            hdr: Default::default(),
            derived_pubkey_x: [0x33; 48],
            derived_pubkey_y: [0x44; 48],
            signature_r: [0x55; 48],
            signature_s: [0x66; 48],
        };
        let rsp = expected.as_bytes();
        let mut signature = [0u8; DPE_P384_SIGNATURE_SIZE];
        let len = parse_sign_with_exported_ecdsa_response(rsp, rsp.len(), &mut signature).unwrap();
        assert_eq!(len, DPE_P384_SIGNATURE_SIZE);
        assert_eq!(&signature[..48], &expected.signature_r);
        assert_eq!(&signature[48..], &expected.signature_s);
    }

    #[test]
    fn mailbox_framing_tolerates_unaligned_buffers() {
        let exported_cdi = [0x5au8; EXPORTED_CDI_SIZE];
        let tbs = [0xa5u8; 33];
        let mut backing = std::vec![0u8; SIGN_WITH_EXPORTED_MLDSA_REQ_LEN + 1];
        let req = odd_aligned(&mut backing, SIGN_WITH_EXPORTED_MLDSA_REQ_LEN);
        write_sign_with_exported_mldsa_req(req, &exported_cdi, &tbs).unwrap();
        let decoded: SignWithExportedMldsaReq = decode_padded(req);
        assert_eq!(decoded.exported_cdi_handle, exported_cdi);
        assert_eq!(decoded.tbs_size, tbs.len() as u32);
        assert_eq!(&decoded.tbs[..tbs.len()], &tbs);

        let mut backing = [0u8; GET_CERT_CHAIN_REQ_MLDSA87_LEN + 1];
        let req = odd_aligned(&mut backing, GET_CERT_CHAIN_REQ_MLDSA87_LEN);
        let axi_response = AxiDmaTarget {
            addr: 0xA8C0_1000,
            max_size: 64,
        };
        write_invoke_dpe_req(
            req,
            DpeProfile::Mldsa87,
            Some(axi_response.into()),
            &GET_CERT_CHAIN_CMD,
        )
        .unwrap();
        let decoded: InvokeDpeMldsa87Req = decode_padded(req);
        assert!(decoded.flags.external_axi_response());
        assert_eq!(decoded.axi_response.addr_lo, 0xA8C0_1000);
        assert_eq!(decoded.axi_response.max_size, 64);
        assert_eq!(
            decoded.data_size,
            dpe_payload_len::<GetCertificateChainCmd>()
        );

        const RSP_LEN: usize = SIGN_WITH_EXPORTED_ECDSA_RESP_LEN;
        let mut backing = [0u8; RSP_LEN + 1];
        let rsp = odd_aligned(&mut backing, RSP_LEN);
        rsp[SIGN_WITH_EXPORTED_ECDSA_RESP_SIG_R_OFF..SIGN_WITH_EXPORTED_ECDSA_RESP_SIG_S_OFF]
            .fill(0xAA);
        rsp[SIGN_WITH_EXPORTED_ECDSA_RESP_SIG_S_OFF..].fill(0xBB);
        let mut signature = [0u8; DPE_P384_SIGNATURE_SIZE];
        parse_sign_with_exported_ecdsa_response(rsp, RSP_LEN, &mut signature).unwrap();
        assert_eq!(&signature[..48], &[0xAA; 48]);
        assert_eq!(&signature[48..], &[0xBB; 48]);
    }

    #[test]
    fn conversions_into_upstream_types() {
        assert_eq!(
            caliptra_dpe::DpeProfile::from(DpeProfile::P384Sha384),
            caliptra_dpe::DpeProfile::P384Sha384
        );
        assert_eq!(
            caliptra_dpe::DpeProfile::from(DpeProfile::Mldsa87),
            caliptra_dpe::DpeProfile::Mldsa87
        );

        assert_eq!(
            AxiResponseInfo::from(AxiDmaTarget {
                addr: 0xA8C0_1000,
                max_size: 24576,
            }),
            AxiResponseInfo {
                addr_lo: 0xA8C0_1000,
                addr_hi: 0,
                max_size: 24576,
            }
        );

        let params = DpeDeriveContextParams {
            parent_handle: [0xa5u8; DPE_CONTEXT_HANDLE_SIZE],
            measurement: [0x5au8; DPE_TCI_MEASUREMENT_SIZE],
            flags: DpeDeriveContextFlags::EXPORT_CDI | DpeDeriveContextFlags::CREATE_CERTIFICATE,
            tci_type: 0x1122_3344,
            target_locality: 0x5566_7788,
            svn: 7,
        };
        assert_eq!(
            DeriveContextCmd::from(&params),
            DeriveContextCmd {
                handle: ContextHandle(params.parent_handle),
                data: TciMeasurement(params.measurement),
                flags: params.flags,
                tci_type: params.tci_type,
                target_locality: params.target_locality,
                svn: params.svn,
            }
        );

        let params = DpeUpdateContextMeasurementParams {
            parent_handle: [0xa5u8; DPE_CONTEXT_HANDLE_SIZE],
            measurement: [0x5au8; DPE_TCI_MEASUREMENT_SIZE],
            tci_type: 0x1122_3344,
        };
        assert_eq!(
            UpdateContextMeasurementCmd::from(&params),
            UpdateContextMeasurementCmd {
                parent_handle: ContextHandle(params.parent_handle),
                data: TciMeasurement(params.measurement),
                reserved: 0,
                tci_type: params.tci_type,
                reserved_svn: 0,
            }
        );
    }
}

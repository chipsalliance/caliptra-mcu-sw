// Licensed under the Apache-2.0 license

//! DPE primitives over Caliptra's `INVOKE_DPE` mailbox command, plus
//! the dedicated top-level `DPE_TAG_TCI` tagging command.
//!
//! Mirrors the on-wire layouts from
//! `caliptra-dpe/dpe::commands` (request) and
//! `caliptra-dpe/dpe::response` (response) using slim
//! [`zerocopy::Unaligned`] structs so request / response buffers are
//! allocated from the caller's [`ApiAlloc`] — never the stack —
//! keeping async futures small.

use core::{
    mem::{offset_of, size_of},
    ops::Deref,
};
use mcu_error::codes::{INTERNAL_BUG, INVARIANT, NOT_IMPLEMENTED};
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::slice::{checked_slice, checked_slice_mut, copy_bytes, internal_slice};
use crate::wire::{
    calc_checksum, mbox_execute, populate_checksum, CMD_CERTIFY_KEY_CHUNKS, CMD_DPE_GET_TAGGED_TCI,
    CMD_DPE_TAG_TCI, CMD_INVOKE_DPE, CMD_INVOKE_DPE_MLDSA87, DPE_CMD_DERIVE_CONTEXT,
    DPE_CMD_GET_CERTIFICATE_CHAIN, DPE_CMD_ROTATE_CONTEXT_HANDLE, DPE_CMD_SIGN,
    DPE_CMD_UPDATE_CONTEXT_MEASUREMENT, DPE_COMMAND_MAGIC, DPE_PROFILE_MLDSA87,
    DPE_PROFILE_P384_SHA384, DPE_RESPONSE_MAGIC, MBOX_RESP_HEADER_SIZE,
};
use crate::ApiAlloc;

/// DPE profile identifier used for DPE command dispatch.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DpeProfile {
    P384Sha384 = DPE_PROFILE_P384_SHA384,
    Mldsa87 = DPE_PROFILE_MLDSA87,
}

impl DpeProfile {
    pub const fn profile_id(self) -> u32 {
        self as u32
    }

    pub const fn invoke_cmd_id(self) -> u32 {
        match self {
            Self::P384Sha384 => CMD_INVOKE_DPE,
            Self::Mldsa87 => CMD_INVOKE_DPE_MLDSA87,
        }
    }
}

/// Length in bytes of the DPE key/UEID label used by every
/// `CertifyKey` / `Sign` call in this crate.
pub const DPE_LABEL_LEN: usize = 48;

/// Output format selector for `CertifyKey` — we only support the
/// X.509 leaf certificate form (`dpe::commands::certify_key::CertifyKeyCommand::FORMAT_X509`).
const DPE_CERTIFY_KEY_FORMAT_X509: u32 = 0;

/// DPE context handle width (`dpe::context::ContextHandle::SIZE`).
pub const DPE_CONTEXT_HANDLE_SIZE: usize = 16;

pub type DpeContextHandle = [u8; DPE_CONTEXT_HANDLE_SIZE];

/// Exported CDI handle width.
pub const EXPORTED_CDI_SIZE: usize = 32;

/// SHA-384 TCI measurement width used by DPE P-384 / SHA-384 `DeriveContext`.
pub const DPE_TCI_MEASUREMENT_SIZE: usize = 48;

const DEFAULT_DPE_CONTEXT_HANDLE: DpeContextHandle = [0u8; DPE_CONTEXT_HANDLE_SIZE];

/// Upper bound on the X.509 leaf certificate Caliptra's DPE can
/// emit — fits both ECC-384 and ML-DSA-87 leaf certificates.
pub const DPE_MAX_LEAF_CERT_SIZE: usize = 12 * 1024;

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

/// Typed input to DPE-backed attestation signing.
///
/// Caliptra 2.0 accepts a raw ML-DSA message, while Caliptra 2.1 accepts an
/// externally computed `mu`. These forms are intentionally distinct because
/// they do not have identical context or message-size semantics.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SigningInput<'a> {
    /// SHA-384 digest for ECDSA P-384.
    EccP384Digest(&'a [u8; DPE_P384_DIGEST_SIZE]),
    /// Raw ML-DSA-87 message accepted by the Caliptra 2.0 DPE interface.
    ///
    /// The 2.0 form uses an implicit empty FIPS 204 context and limits the
    /// message to 1024 bytes.
    Mldsa87RawMessage(&'a [u8]),
    /// External ML-DSA-87 `mu` accepted by the Caliptra 2.1 DPE interface.
    Mldsa87ExternalMu(&'a [u8; DPE_MLDSA87_MU_SIZE]),
}

impl SigningInput<'_> {
    /// DPE profile required by this signing input.
    pub const fn profile(&self) -> DpeProfile {
        match self {
            Self::EccP384Digest(_) => DpeProfile::P384Sha384,
            Self::Mldsa87RawMessage(_) | Self::Mldsa87ExternalMu(_) => DpeProfile::Mldsa87,
        }
    }
}
// ---------------------------------------------------------------------------
// Slim wire types
// ---------------------------------------------------------------------------

/// Caliptra `InvokeDpeReq` prefix: `MailboxReqHeader { chksum }` +
/// `data_size`. The DPE-level payload (`CommandHdr` + command body)
/// follows immediately.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct InvokeDpeReqPrefix {
    chksum: U32,
    data_size: U32,
}

/// Caliptra `InvokeDpeMldsa87Req` prefix: `MailboxReqHeader { chksum }` +
/// `flags(4)` + `axi_response(12)` + `data_size(4)`. The DPE-level payload
/// (`CommandHdr` + command body) follows immediately.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct InvokeDpeMldsa87ReqPrefix {
    chksum: U32,
    flags: U32,
    axi_addr_lo: U32,
    axi_addr_hi: U32,
    axi_max_size: U32,
    data_size: U32,
}

/// DPE per-command header — `dpe::commands::CommandHdr`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct DpeCommandHdr {
    magic: U32,
    cmd_id: U32,
    profile: U32,
}

/// `dpe::commands::GetCertificateChainCmd`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct GetCertChainCmd {
    offset: U32,
    size: U32,
}

/// `dpe::commands::SignP384Cmd`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct SignP384Cmd {
    handle: [u8; DPE_CONTEXT_HANDLE_SIZE],
    label: [u8; DPE_LABEL_LEN],
    flags: U32,
    digest: [u8; DPE_P384_DIGEST_SIZE],
}

/// `dpe::commands::SignMldsa87Cmd`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct SignMldsa87Cmd {
    handle: [u8; DPE_CONTEXT_HANDLE_SIZE],
    label: [u8; DPE_LABEL_LEN],
    flags: U32,
    mu: [u8; DPE_MLDSA87_MU_SIZE],
}

/// `dpe::commands::DeriveContextCmd`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct DeriveContextCmd {
    handle: [u8; DPE_CONTEXT_HANDLE_SIZE],
    data: [u8; DPE_TCI_MEASUREMENT_SIZE],
    flags: U32,
    tci_type: U32,
    target_locality: U32,
    svn: U32,
}

/// `dpe::commands::UpdateContextMeasurementCmd`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct UpdateContextMeasurementCmd {
    parent_handle: [u8; DPE_CONTEXT_HANDLE_SIZE],
    data: [u8; DPE_TCI_MEASUREMENT_SIZE],
    reserved: U32,
    tci_type: U32,
    reserved_svn: U32,
}

/// `dpe::response::SignP384Resp`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct SignP384RespBody {
    _resp_hdr: [u8; 12],
    _new_context_handle: [u8; DPE_CONTEXT_HANDLE_SIZE],
    sig_r: [u8; 48],
    sig_s: [u8; 48],
}

/// `dpe::response::SignMlDsaResp`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct SignMldsa87RespBody {
    _resp_hdr: [u8; 12],
    new_context_handle: [u8; DPE_CONTEXT_HANDLE_SIZE],
    signature: [u8; DPE_MLDSA87_SIGNATURE_SIZE],
    padding: [u8; 1],
}

/// ECC P-384 signature size (r + s, 48 bytes each).
pub const DPE_P384_SIGNATURE_SIZE: usize = 96;

/// Caliptra `InvokeDpeResp` prefix: `MailboxRespHeader { chksum,
/// fips_status }` + `data_size`. The DPE-level response payload
/// follows.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct InvokeDpeRespPrefix {
    _chksum: U32,
    _fips_status: U32,
    data_size: U32,
}

/// DPE per-response header — `dpe::response::ResponseHdr`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct DpeResponseHdr {
    magic: U32,
    status: U32,
    profile: U32,
}

/// `dpe::commands::RotateCtxCmd`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct RotateCtxCmd {
    handle: [u8; DPE_CONTEXT_HANDLE_SIZE],
    flags: U32,
}

/// `dpe::response::NewHandleResp` — the rotated context handle follows
/// the response header.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct NewHandleRespBody {
    _resp_hdr: [u8; 12],
    handle: [u8; DPE_CONTEXT_HANDLE_SIZE],
}

/// `dpe::response::DeriveContextResp`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct DeriveContextRespBody {
    _resp_hdr: [u8; 12],
    handle: [u8; DPE_CONTEXT_HANDLE_SIZE],
    parent_handle: [u8; DPE_CONTEXT_HANDLE_SIZE],
}

/// `dpe::response::DeriveContextExportedCdiResp` prefix (fixed portion before certificate bytes).
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct DeriveContextExportedCdiRespPrefix {
    _resp_hdr: [u8; 12],
    handle: [u8; DPE_CONTEXT_HANDLE_SIZE],
    parent_handle: [u8; DPE_CONTEXT_HANDLE_SIZE],
    exported_cdi: [u8; EXPORTED_CDI_SIZE],
    cert_size: U32,
}

/// `dpe::response::UpdateContextMeasurementResp`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct UpdateContextMeasurementRespBody {
    _resp_hdr: [u8; 12],
    new_context_handle: [u8; DPE_CONTEXT_HANDLE_SIZE],
    new_parent_context_handle: [u8; DPE_CONTEXT_HANDLE_SIZE],
}

/// Caliptra `TagTciReq`: `chksum(4) + handle(16) + tag(4)`. The
/// `DPE_TAG_TCI` response carries no command-specific output.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct TagTciReq {
    chksum: U32,
    handle: [u8; DPE_CONTEXT_HANDLE_SIZE],
    tag: U32,
}

/// Caliptra `GetTaggedTciReq`: `chksum(4) + tag(4)`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct GetTaggedTciReq {
    chksum: U32,
    tag: U32,
}

/// Caliptra `GetTaggedTciResp`: mailbox response header plus cumulative/current TCI.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct GetTaggedTciResp {
    _chksum: U32,
    _fips_status: U32,
    tci_cumulative: [u8; DPE_TCI_MEASUREMENT_SIZE],
    tci_current: [u8; DPE_TCI_MEASUREMENT_SIZE],
}

const TAG_TCI_REQ_LEN: usize = size_of::<TagTciReq>();
const GET_TAGGED_TCI_REQ_LEN: usize = size_of::<GetTaggedTciReq>();
const GET_TAGGED_TCI_RESP_LEN: usize = size_of::<GetTaggedTciResp>();
const _: () = assert!(TAG_TCI_REQ_LEN == 4 + DPE_CONTEXT_HANDLE_SIZE + 4);
const _: () = assert!(GET_TAGGED_TCI_REQ_LEN == 4 + 4);
const _: () = assert!(GET_TAGGED_TCI_RESP_LEN == MBOX_RESP_HEADER_SIZE + 48 + 48);

const GET_CERT_CHAIN_REQ_P384_LEN: usize =
    size_of::<InvokeDpeReqPrefix>() + size_of::<DpeCommandHdr>() + size_of::<GetCertChainCmd>();
const GET_CERT_CHAIN_REQ_MLDSA87_LEN: usize = size_of::<InvokeDpeMldsa87ReqPrefix>()
    + size_of::<DpeCommandHdr>()
    + size_of::<GetCertChainCmd>();
const GET_CERT_CHAIN_DPE_PAYLOAD_LEN: u32 =
    (size_of::<DpeCommandHdr>() + size_of::<GetCertChainCmd>()) as u32;

const SIGN_REQ_LEN: usize =
    size_of::<InvokeDpeReqPrefix>() + size_of::<DpeCommandHdr>() + size_of::<SignP384Cmd>();
const SIGN_DPE_PAYLOAD_LEN: u32 = (size_of::<DpeCommandHdr>() + size_of::<SignP384Cmd>()) as u32;
const SIGN_MLDSA87_REQ_LEN: usize = size_of::<InvokeDpeMldsa87ReqPrefix>()
    + size_of::<DpeCommandHdr>()
    + size_of::<SignMldsa87Cmd>();
const SIGN_MLDSA87_DPE_PAYLOAD_LEN: u32 =
    (size_of::<DpeCommandHdr>() + size_of::<SignMldsa87Cmd>()) as u32;
const SIGN_MLDSA87_RESP_LEN: usize =
    size_of::<InvokeDpeRespPrefix>() + size_of::<SignMldsa87RespBody>();
const DERIVE_CONTEXT_REQ_LEN: usize =
    size_of::<InvokeDpeReqPrefix>() + size_of::<DpeCommandHdr>() + size_of::<DeriveContextCmd>();
const DERIVE_CONTEXT_MLDSA87_REQ_LEN: usize = size_of::<InvokeDpeMldsa87ReqPrefix>()
    + size_of::<DpeCommandHdr>()
    + size_of::<DeriveContextCmd>();
const DERIVE_CONTEXT_DPE_PAYLOAD_LEN: u32 =
    (size_of::<DpeCommandHdr>() + size_of::<DeriveContextCmd>()) as u32;
const UPDATE_CONTEXT_MEASUREMENT_REQ_LEN: usize = size_of::<InvokeDpeReqPrefix>()
    + size_of::<DpeCommandHdr>()
    + size_of::<UpdateContextMeasurementCmd>();
const UPDATE_CONTEXT_MEASUREMENT_DPE_PAYLOAD_LEN: u32 =
    (size_of::<DpeCommandHdr>() + size_of::<UpdateContextMeasurementCmd>()) as u32;
const CERTIFY_KEY_P384_RESP_PREFIX_LEN: usize =
    size_of::<DpeResponseHdr>() + DPE_CONTEXT_HANDLE_SIZE + 48 + 48 + 4;
pub const CERTIFY_KEY_MLDSA87_PUBKEY_SIZE: usize = caliptra_image_types::MLDSA87_PUB_KEY_BYTE_SIZE;
pub const CERTIFY_KEY_MLDSA87_RESP_PREFIX_LEN: usize =
    size_of::<DpeResponseHdr>() + DPE_CONTEXT_HANDLE_SIZE + CERTIFY_KEY_MLDSA87_PUBKEY_SIZE + 4;
pub const CERTIFY_KEY_FLAG_USE_MLDSA: u32 =
    caliptra_api::mailbox::CertifyKeyChunksFlags::USE_MLDSA.bits();
const CERTIFY_KEY_CHUNKS_REQ_LEN: usize = size_of::<caliptra_api::mailbox::CertifyKeyChunksReq>();
const CERTIFY_KEY_CHUNKS_RESP_INFO_LEN: usize =
    size_of::<caliptra_api::mailbox::CertifyKeyChunksRespInfo>();
const CERTIFY_KEY_CHUNKS_MAX_REQ_SIZE: usize =
    if CERTIFY_KEY_MLDSA87_RESP_PREFIX_LEN > DPE_MAX_CHUNK_SIZE {
        CERTIFY_KEY_MLDSA87_RESP_PREFIX_LEN
    } else {
        DPE_MAX_CHUNK_SIZE
    };
const CERTIFY_KEY_RESP_PUBKEY_X_OFF: usize = size_of::<DpeResponseHdr>() + DPE_CONTEXT_HANDLE_SIZE;
const CERTIFY_KEY_RESP_PUBKEY_Y_OFF: usize = CERTIFY_KEY_RESP_PUBKEY_X_OFF + 48;
const CERTIFY_KEY_RESP_CERT_SIZE_OFF: usize = CERTIFY_KEY_RESP_PUBKEY_Y_OFF + 48;

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
        DpeProfile::P384Sha384 => CERTIFY_KEY_RESP_CERT_SIZE_OFF,
        DpeProfile::Mldsa87 => {
            size_of::<DpeResponseHdr>() + DPE_CONTEXT_HANDLE_SIZE + CERTIFY_KEY_MLDSA87_PUBKEY_SIZE
        }
    }
}
const CERTIFY_KEY_CHUNKS_REQ_MAX_SIZE_OFF: usize =
    offset_of!(caliptra_api::mailbox::CertifyKeyChunksReq, max_size);
const CERTIFY_KEY_CHUNKS_REQ_OFFSET_OFF: usize =
    offset_of!(caliptra_api::mailbox::CertifyKeyChunksReq, offset);
const CERTIFY_KEY_CHUNKS_REQ_DPE_CMD_OFF: usize =
    offset_of!(caliptra_api::mailbox::CertifyKeyChunksReq, certify_key_req);
const CERTIFY_KEY_CHUNKS_REQ_HANDLE_OFF: usize = CERTIFY_KEY_CHUNKS_REQ_DPE_CMD_OFF;
const CERTIFY_KEY_CHUNKS_REQ_FORMAT_OFF: usize =
    CERTIFY_KEY_CHUNKS_REQ_DPE_CMD_OFF + DPE_CONTEXT_HANDLE_SIZE + 4;
const CERTIFY_KEY_CHUNKS_REQ_LABEL_OFF: usize = CERTIFY_KEY_CHUNKS_REQ_FORMAT_OFF + 4;
const CERTIFY_KEY_CHUNKS_RESP_HANDLE_OFF: usize = offset_of!(
    caliptra_api::mailbox::CertifyKeyChunksRespInfo,
    context_handle
);
const CERTIFY_KEY_CHUNKS_RESP_CHUNK_LEN_OFF: usize =
    offset_of!(caliptra_api::mailbox::CertifyKeyChunksRespInfo, chunk_len);

const ROTATE_CTX_REQ_LEN: usize =
    size_of::<InvokeDpeReqPrefix>() + size_of::<DpeCommandHdr>() + size_of::<RotateCtxCmd>();
const ROTATE_CTX_DPE_PAYLOAD_LEN: u32 =
    (size_of::<DpeCommandHdr>() + size_of::<RotateCtxCmd>()) as u32;

const _: () = assert!(size_of::<InvokeDpeReqPrefix>() == 8);
const _: () = assert!(size_of::<InvokeDpeMldsa87ReqPrefix>() == 24);
const _: () = assert!(size_of::<DpeCommandHdr>() == 12);
const _: () = assert!(size_of::<GetCertChainCmd>() == 8);
const _: () = assert!(size_of::<SignP384Cmd>() == DPE_CONTEXT_HANDLE_SIZE + 48 + 4 + 48);
const _: () = assert!(size_of::<SignP384RespBody>() == 12 + DPE_CONTEXT_HANDLE_SIZE + 48 + 48);
const _: () = assert!(size_of::<SignMldsa87Cmd>() == DPE_CONTEXT_HANDLE_SIZE + 48 + 4 + 64);
const _: () = assert!(
    size_of::<SignMldsa87RespBody>()
        == 12 + DPE_CONTEXT_HANDLE_SIZE + DPE_MLDSA87_SIGNATURE_SIZE + 1
);
const _: () =
    assert!(size_of::<DeriveContextCmd>() == DPE_CONTEXT_HANDLE_SIZE + 48 + 4 + 4 + 4 + 4);
const _: () =
    assert!(size_of::<UpdateContextMeasurementCmd>() == DPE_CONTEXT_HANDLE_SIZE + 48 + 4 + 4 + 4);
const _: () = assert!(
    size_of::<DeriveContextRespBody>() == 12 + DPE_CONTEXT_HANDLE_SIZE + DPE_CONTEXT_HANDLE_SIZE
);
const _: () = assert!(
    size_of::<DeriveContextExportedCdiRespPrefix>()
        == 12 + DPE_CONTEXT_HANDLE_SIZE + DPE_CONTEXT_HANDLE_SIZE + EXPORTED_CDI_SIZE + 4
);
const _: () = assert!(
    size_of::<UpdateContextMeasurementRespBody>()
        == 12 + DPE_CONTEXT_HANDLE_SIZE + DPE_CONTEXT_HANDLE_SIZE
);
const _: () = assert!(size_of::<InvokeDpeRespPrefix>() == 12);
const _: () = assert!(size_of::<DpeResponseHdr>() == 12);
const _: () = assert!(GET_CERT_CHAIN_REQ_P384_LEN == 28);
const _: () = assert!(GET_CERT_CHAIN_REQ_MLDSA87_LEN == 44);
const _: () = assert!(SIGN_REQ_LEN == 8 + 12 + 116);
const _: () = assert!(SIGN_MLDSA87_REQ_LEN == 24 + 12 + 132);
const _: () = assert!(SIGN_MLDSA87_RESP_LEN == 12 + 12 + 16 + 4627 + 1);
const _: () = assert!(SIGN_MLDSA87_RESP_LEN <= caliptra_api::mailbox::MAILBOX_SIZE);
const _: () = assert!(DERIVE_CONTEXT_REQ_LEN == 8 + 12 + 80);
const _: () = assert!(DERIVE_CONTEXT_MLDSA87_REQ_LEN == 24 + 12 + 80);
const _: () = assert!(UPDATE_CONTEXT_MEASUREMENT_REQ_LEN == 8 + 12 + 76);
const _: () = assert!(
    caliptra_api::mailbox::CertifyKeyChunksReq::CERTIFY_KEY_REQ_SIZE
        == DPE_CONTEXT_HANDLE_SIZE + 4 + 4 + 48
);
const _: () = assert!(CERTIFY_KEY_P384_RESP_PREFIX_LEN == 128);
const _: () = assert!(CERTIFY_KEY_MLDSA87_PUBKEY_SIZE == 2592);
const _: () = assert!(CERTIFY_KEY_MLDSA87_RESP_PREFIX_LEN == 2624);
const _: () = assert!(CERTIFY_KEY_CHUNKS_REQ_LEN == 92);
const _: () = assert!(CERTIFY_KEY_CHUNKS_RESP_INFO_LEN == 32);
const _: () = assert!(size_of::<RotateCtxCmd>() == DPE_CONTEXT_HANDLE_SIZE + 4);
const _: () = assert!(size_of::<NewHandleRespBody>() == 12 + DPE_CONTEXT_HANDLE_SIZE);
const _: () = assert!(ROTATE_CTX_REQ_LEN == 8 + 12 + 20);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// DPE `DeriveContext` request flags.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DpeDeriveContextFlags(u32);

impl DpeDeriveContextFlags {
    /// No request flags.
    pub const EMPTY: Self = Self(0);
    /// Create an X.509 certificate.
    pub const CREATE_CERTIFICATE: Self = Self(1u32 << 22);
    /// Derive an exported CDI.
    pub const EXPORT_CDI: Self = Self(1u32 << 23);
    /// Allow the derived child context to create X.509 certificates.
    pub const INPUT_ALLOW_X509: Self = Self(1u32 << 25);
    /// Allow the derived child context to export CDI.
    pub const ALLOW_NEW_CONTEXT_TO_EXPORT: Self = Self(1u32 << 26);
    /// Keep the parent context and return its rotated handle.
    pub const RETAIN_PARENT_CONTEXT: Self = Self(1u32 << 29);

    /// Return the raw DPE flag bits.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl core::ops::BitOr for DpeDeriveContextFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for DpeDeriveContextFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

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
pub async fn dpe_derive_context<A: ApiAlloc>(
    alloc: &A,
    params: &DpeDeriveContextParams,
) -> McuResult<DpeDeriveContextResult> {
    let (req, mbox_cmd) = build_derive_context_req(alloc, params, DpeProfile::P384Sha384, None)?;
    let mut rsp =
        alloc.alloc(size_of::<InvokeDpeRespPrefix>() + size_of::<DeriveContextRespBody>())?;
    let rsp_len = mbox_execute(mbox_cmd, &req, &mut rsp).await?;
    parse_derive_context_response(&rsp, rsp_len)
}

fn build_derive_context_req<'a, A: ApiAlloc>(
    alloc: &'a A,
    params: &DpeDeriveContextParams,
    profile: DpeProfile,
    axi_response: Option<(u32, u32)>,
) -> McuResult<(A::Buf<'a>, u32)> {
    let req_len = match profile {
        DpeProfile::Mldsa87 => DERIVE_CONTEXT_MLDSA87_REQ_LEN,
        DpeProfile::P384Sha384 => DERIVE_CONTEXT_REQ_LEN,
    };
    let mut req = alloc.alloc(req_len)?;
    req.fill(0);
    let cur = build_invoke_dpe_header_profile(
        &mut req,
        DERIVE_CONTEXT_DPE_PAYLOAD_LEN,
        DPE_CMD_DERIVE_CONTEXT,
        profile,
        axi_response,
    )?;
    {
        let cmd = DeriveContextCmd::mut_from_bytes(checked_slice_mut(
            &mut req,
            cur,
            size_of::<DeriveContextCmd>(),
        )?)
        .map_err(|_| INVARIANT)?;
        cmd.handle = params.parent_handle;
        cmd.data = params.measurement;
        cmd.flags = U32::new(params.flags.bits());
        cmd.tci_type = U32::new(params.tci_type);
        cmd.target_locality = U32::new(params.target_locality);
        cmd.svn = U32::new(params.svn);
    }
    let mbox_cmd = profile.invoke_cmd_id();
    let checksum = calc_checksum(mbox_cmd, &req);
    *req.first_chunk_mut::<4>().ok_or(INVARIANT)? = checksum.to_le_bytes();
    Ok((req, mbox_cmd))
}

fn parse_derive_context_response(rsp: &[u8], rsp_len: usize) -> McuResult<DpeDeriveContextResult> {
    let resp_body_off = size_of::<InvokeDpeRespPrefix>();
    if rsp_len < resp_body_off + size_of::<DeriveContextRespBody>() {
        return Err(INTERNAL_BUG);
    }
    let dpe_hdr = DpeResponseHdr::ref_from_bytes(internal_slice(
        rsp,
        resp_body_off,
        size_of::<DpeResponseHdr>(),
    )?)
    .map_err(|_| INTERNAL_BUG)?;
    if dpe_hdr.magic.get() != DPE_RESPONSE_MAGIC || dpe_hdr.status.get() != 0 {
        return Err(INTERNAL_BUG);
    }
    let body = DeriveContextRespBody::ref_from_bytes(internal_slice(
        rsp,
        resp_body_off,
        size_of::<DeriveContextRespBody>(),
    )?)
    .map_err(|_| INTERNAL_BUG)?;
    Ok(DpeDeriveContextResult {
        child_handle: body.handle,
        parent_handle: body.parent_handle,
    })
}

/// Invoke DPE `DeriveContext` with `EXPORT_CDI`, returning the child handle, rotated parent handle,
/// 32-byte exported CDI handle, and copying the emitted leaf certificate into `cert_dst`.
#[inline(never)]
pub async fn dpe_derive_context_exported_cdi<A: ApiAlloc>(
    alloc: &A,
    params: &DpeDeriveContextParams,
    profile: DpeProfile,
    cert_dst: &mut [u8],
) -> McuResult<DpeDeriveContextExportedCdiResult> {
    let max_resp_len = match profile {
        DpeProfile::Mldsa87 => 24 * 1024,
        DpeProfile::P384Sha384 => {
            size_of::<InvokeDpeRespPrefix>()
                + size_of::<DeriveContextExportedCdiRespPrefix>()
                + cert_dst.len().min(DPE_MAX_LEAF_CERT_SIZE)
        }
    };
    let mut rsp = alloc.alloc(max_resp_len)?;
    let axi_response = match profile {
        DpeProfile::Mldsa87 => {
            // Caliptra Subsystem Integration Spec: MCU local SRAM base is 0x4000_0000,
            // and AXI DMA base is MCI_BASE_AXI_ADDRESS (0xA800_0000) + MCU_SRAM_OFFSET (0x00C0_0000).
            const MCU_SRAM_LOCAL_BASE: u32 = 0x4000_0000;
            const MCI_BASE_AXI_ADDRESS: u32 = 0xA800_0000;
            const MCU_SRAM_AXI_OFFSET: u32 = 0x00C0_0000;
            const MCU_SRAM_AXI_BASE: u32 = MCI_BASE_AXI_ADDRESS + MCU_SRAM_AXI_OFFSET;

            let sram_offset = (rsp.as_ptr() as u32)
                .checked_sub(MCU_SRAM_LOCAL_BASE)
                .ok_or(INVARIANT)?;
            let axi_addr = MCU_SRAM_AXI_BASE
                .checked_add(sram_offset)
                .ok_or(INVARIANT)?;
            Some((axi_addr, max_resp_len as u32))
        }
        DpeProfile::P384Sha384 => None,
    };
    let (req, mbox_cmd) = build_derive_context_req(alloc, params, profile, axi_response)?;
    let rsp_len = mbox_execute(mbox_cmd, &req, &mut rsp).await?;
    let effective_rsp_len = match profile {
        DpeProfile::Mldsa87 => {
            let prefix = InvokeDpeRespPrefix::ref_from_bytes(checked_slice(
                &rsp,
                0,
                size_of::<InvokeDpeRespPrefix>(),
            )?)
            .map_err(|_| INVARIANT)?;
            size_of::<InvokeDpeRespPrefix>() + prefix.data_size.get() as usize
        }
        DpeProfile::P384Sha384 => rsp_len,
    };
    parse_derive_context_exported_cdi_response(&rsp, effective_rsp_len, cert_dst)
}

fn parse_derive_context_exported_cdi_response(
    rsp: &[u8],
    rsp_len: usize,
    cert_dst: &mut [u8],
) -> McuResult<DpeDeriveContextExportedCdiResult> {
    let resp_body_off = size_of::<InvokeDpeRespPrefix>();
    let prefix_len = size_of::<DeriveContextExportedCdiRespPrefix>();
    if rsp_len < resp_body_off + size_of::<DpeResponseHdr>() {
        return Err(INTERNAL_BUG);
    }
    let dpe_hdr = DpeResponseHdr::ref_from_bytes(internal_slice(
        rsp,
        resp_body_off,
        size_of::<DpeResponseHdr>(),
    )?)
    .map_err(|_| INTERNAL_BUG)?;
    if dpe_hdr.magic.get() != DPE_RESPONSE_MAGIC || dpe_hdr.status.get() != 0 {
        return Err(INTERNAL_BUG);
    }
    if rsp_len < resp_body_off + prefix_len {
        return Err(INTERNAL_BUG);
    }
    let prefix = DeriveContextExportedCdiRespPrefix::ref_from_bytes(internal_slice(
        rsp,
        resp_body_off,
        prefix_len,
    )?)
    .map_err(|_| INTERNAL_BUG)?;

    let cert_size = prefix.cert_size.get() as usize;
    let cert_off = resp_body_off + prefix_len;
    if cert_off + cert_size > rsp_len || cert_size > cert_dst.len() {
        return Err(INTERNAL_BUG);
    }
    let cert = internal_slice(rsp, cert_off, cert_size)?;
    let out = cert_dst.get_mut(..cert_size).ok_or(INTERNAL_BUG)?;
    copy_bytes(out, cert)?;

    Ok(DpeDeriveContextExportedCdiResult {
        child_handle: prefix.handle,
        parent_handle: prefix.parent_handle,
        exported_cdi: prefix.exported_cdi,
        cert_size,
    })
}

/// Invoke DPE `UpdateContextMeasurement`, returning the rotated component and parent handles.
#[inline(never)]
pub async fn dpe_update_context_measurement<A: ApiAlloc>(
    alloc: &A,
    params: &DpeUpdateContextMeasurementParams,
) -> McuResult<DpeUpdateContextMeasurementResult> {
    let req = build_update_context_measurement_req(alloc, params)?;
    let mut rsp = alloc
        .alloc(size_of::<InvokeDpeRespPrefix>() + size_of::<UpdateContextMeasurementRespBody>())?;
    let rsp_len = mbox_execute(CMD_INVOKE_DPE, &req, &mut rsp).await?;
    parse_update_context_measurement_response(&rsp, rsp_len)
}

fn build_update_context_measurement_req<'a, A: ApiAlloc>(
    alloc: &'a A,
    params: &DpeUpdateContextMeasurementParams,
) -> McuResult<A::Buf<'a>> {
    let mut req = alloc.alloc(UPDATE_CONTEXT_MEASUREMENT_REQ_LEN)?;
    req.fill(0);
    let cur = build_invoke_dpe_header(
        &mut req,
        UPDATE_CONTEXT_MEASUREMENT_DPE_PAYLOAD_LEN,
        DPE_CMD_UPDATE_CONTEXT_MEASUREMENT,
    )?;
    {
        let cmd = UpdateContextMeasurementCmd::mut_from_bytes(checked_slice_mut(
            &mut req,
            cur,
            size_of::<UpdateContextMeasurementCmd>(),
        )?)
        .map_err(|_| INVARIANT)?;
        cmd.parent_handle = params.parent_handle;
        cmd.data = params.measurement;
        cmd.tci_type = U32::new(params.tci_type);
    }
    let checksum = calc_checksum(CMD_INVOKE_DPE, &req);
    *req.first_chunk_mut::<4>().ok_or(INVARIANT)? = checksum.to_le_bytes();
    Ok(req)
}

fn parse_update_context_measurement_response(
    rsp: &[u8],
    rsp_len: usize,
) -> McuResult<DpeUpdateContextMeasurementResult> {
    let resp_body_off = size_of::<InvokeDpeRespPrefix>();
    if rsp_len < resp_body_off + size_of::<UpdateContextMeasurementRespBody>() {
        return Err(INTERNAL_BUG);
    }
    let dpe_hdr = DpeResponseHdr::ref_from_bytes(internal_slice(
        rsp,
        resp_body_off,
        size_of::<DpeResponseHdr>(),
    )?)
    .map_err(|_| INTERNAL_BUG)?;
    if dpe_hdr.magic.get() != DPE_RESPONSE_MAGIC || dpe_hdr.status.get() != 0 {
        return Err(INTERNAL_BUG);
    }
    let body = UpdateContextMeasurementRespBody::ref_from_bytes(internal_slice(
        rsp,
        resp_body_off,
        size_of::<UpdateContextMeasurementRespBody>(),
    )?)
    .map_err(|_| INTERNAL_BUG)?;
    Ok(DpeUpdateContextMeasurementResult {
        component_handle: body.new_context_handle,
        parent_handle: body.new_parent_context_handle,
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
pub async fn dpe_get_cert_chain_chunk<A: ApiAlloc>(
    alloc: &A,
    profile: DpeProfile,
    offset: u32,
    dst: &mut [u8],
) -> McuResult<usize> {
    if dst.is_empty() || dst.len() > DPE_MAX_CHUNK_SIZE {
        return Err(INVARIANT);
    }
    let size = dst.len() as u32;

    let req_len = match profile {
        DpeProfile::P384Sha384 => GET_CERT_CHAIN_REQ_P384_LEN,
        DpeProfile::Mldsa87 => GET_CERT_CHAIN_REQ_MLDSA87_LEN,
    };

    // Build request: prefix + DPE command header + GetCertChain body.
    let mut req = alloc.alloc(req_len)?;
    req.fill(0);
    let cur = build_invoke_dpe_header_profile(
        &mut req,
        GET_CERT_CHAIN_DPE_PAYLOAD_LEN,
        DPE_CMD_GET_CERTIFICATE_CHAIN,
        profile,
        None,
    )?;
    {
        let cmd = GetCertChainCmd::mut_from_bytes(checked_slice_mut(
            &mut req,
            cur,
            size_of::<GetCertChainCmd>(),
        )?)
        .map_err(|_| INVARIANT)?;
        cmd.offset = U32::new(offset);
        cmd.size = U32::new(size);
    }
    let mbox_cmd = profile.invoke_cmd_id();
    let checksum = calc_checksum(mbox_cmd, &req);
    *req.first_chunk_mut::<4>().ok_or(INVARIANT)? = checksum.to_le_bytes();

    // Allocate response: outer prefix + DPE response hdr + cert_size
    // + chain bytes (up to DPE_MAX_CHUNK_SIZE).
    let rsp_max =
        size_of::<InvokeDpeRespPrefix>() + size_of::<DpeResponseHdr>() + 4 + DPE_MAX_CHUNK_SIZE;
    let mut rsp = alloc.alloc(rsp_max)?;
    let rsp_len = mbox_execute(mbox_cmd, &req, &mut rsp).await?;

    let outer_prefix_len = size_of::<InvokeDpeRespPrefix>();
    let dpe_hdr_off = outer_prefix_len;
    let cert_size_off = dpe_hdr_off + size_of::<DpeResponseHdr>();
    let chain_off = cert_size_off + 4;
    if rsp_len < chain_off {
        return Err(INTERNAL_BUG);
    }

    let dpe_hdr = DpeResponseHdr::ref_from_bytes(internal_slice(
        &rsp,
        dpe_hdr_off,
        size_of::<DpeResponseHdr>(),
    )?)
    .map_err(|_| INTERNAL_BUG)?;
    if dpe_hdr.magic.get() != DPE_RESPONSE_MAGIC || dpe_hdr.status.get() != 0 {
        return Err(INTERNAL_BUG);
    }

    let cert_size = u32::from_le_bytes(
        *rsp.get(cert_size_off..)
            .and_then(|s| s.first_chunk::<4>())
            .ok_or(INTERNAL_BUG)?,
    ) as usize;
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
pub async fn dpe_certify_key<A: ApiAlloc>(
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
pub async fn dpe_certify_key_cert_size<A: ApiAlloc>(
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
        dpe_handle_or_default(handle),
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
pub async fn dpe_certify_key_cert_slice<A: ApiAlloc>(
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
        dpe_handle_or_default(handle),
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
pub async fn dpe_certify_key_pubkey<A: ApiAlloc>(
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
        dpe_handle_or_default(handle),
        0,
        CERTIFY_KEY_P384_RESP_PREFIX_LEN,
    )
    .await?;
    let response = chunk.chunk()?;
    validate_certify_key_prefix(response, DpeProfile::P384Sha384)?;
    let pubkey_x_bytes = internal_slice(response, CERTIFY_KEY_RESP_PUBKEY_X_OFF, 48)?;
    let pubkey_y_bytes = internal_slice(response, CERTIFY_KEY_RESP_PUBKEY_Y_OFF, 48)?;
    copy_bytes(pubkey_x, pubkey_x_bytes)?;
    copy_bytes(pubkey_y, pubkey_y_bytes)?;
    Ok(chunk.next_handle)
}

/// Return the raw 2,592-byte ML-DSA-87 public key emitted by DPE
/// `CertifyKey`, along with the rotated context handle.
#[inline(never)]
pub async fn dpe_certify_key_mldsa87_pubkey<A: ApiAlloc>(
    alloc: &A,
    handle: Option<&DpeContextHandle>,
    label: &[u8; DPE_LABEL_LEN],
    public_key: &mut [u8; CERTIFY_KEY_MLDSA87_PUBKEY_SIZE],
) -> McuResult<DpeContextHandle> {
    let chunk = certify_key_chunks_response(
        alloc,
        DpeProfile::Mldsa87,
        label,
        dpe_handle_or_default(handle),
        0,
        CERTIFY_KEY_MLDSA87_RESP_PREFIX_LEN,
    )
    .await?;
    parse_certify_key_mldsa87_pubkey(chunk.chunk()?, public_key)?;
    Ok(chunk.next_handle)
}

fn parse_certify_key_mldsa87_pubkey(
    response: &[u8],
    public_key: &mut [u8; CERTIFY_KEY_MLDSA87_PUBKEY_SIZE],
) -> McuResult<()> {
    validate_certify_key_prefix(response, DpeProfile::Mldsa87)?;
    copy_bytes(
        public_key,
        internal_slice(
            response,
            CERTIFY_KEY_RESP_PUBKEY_X_OFF,
            CERTIFY_KEY_MLDSA87_PUBKEY_SIZE,
        )?,
    )
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
    A: ApiAlloc,
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

    let next_handle = read_context_handle(&rsp, CERTIFY_KEY_CHUNKS_RESP_HANDLE_OFF)?;
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

fn build_certify_key_chunks_req<'a, A: ApiAlloc>(
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

fn build_invoke_dpe_header(req: &mut [u8], dpe_payload_len: u32, cmd_id: u32) -> McuResult<usize> {
    build_invoke_dpe_header_profile(req, dpe_payload_len, cmd_id, DpeProfile::P384Sha384, None)
}

fn build_invoke_dpe_header_profile(
    req: &mut [u8],
    dpe_payload_len: u32,
    cmd_id: u32,
    profile: DpeProfile,
    axi_response: Option<(u32, u32)>,
) -> McuResult<usize> {
    let cur = match profile {
        DpeProfile::Mldsa87 => {
            let prefix = InvokeDpeMldsa87ReqPrefix::mut_from_bytes(checked_slice_mut(
                req,
                0,
                size_of::<InvokeDpeMldsa87ReqPrefix>(),
            )?)
            .map_err(|_| INVARIANT)?;
            if let Some((addr_lo, max_size)) = axi_response {
                prefix.flags = U32::new(1 << 31);
                prefix.axi_addr_lo = U32::new(addr_lo);
                prefix.axi_addr_hi = U32::new(0);
                prefix.axi_max_size = U32::new(max_size);
            } else {
                prefix.flags = U32::new(0);
                prefix.axi_addr_lo = U32::new(0);
                prefix.axi_addr_hi = U32::new(0);
                prefix.axi_max_size = U32::new(0);
            }
            prefix.data_size = U32::new(dpe_payload_len);
            size_of::<InvokeDpeMldsa87ReqPrefix>()
        }
        DpeProfile::P384Sha384 => {
            let prefix = InvokeDpeReqPrefix::mut_from_bytes(checked_slice_mut(
                req,
                0,
                size_of::<InvokeDpeReqPrefix>(),
            )?)
            .map_err(|_| INVARIANT)?;
            prefix.data_size = U32::new(dpe_payload_len);
            size_of::<InvokeDpeReqPrefix>()
        }
    };

    let hdr =
        DpeCommandHdr::mut_from_bytes(checked_slice_mut(req, cur, size_of::<DpeCommandHdr>())?)
            .map_err(|_| INVARIANT)?;
    hdr.magic = U32::new(DPE_COMMAND_MAGIC);
    hdr.cmd_id = U32::new(cmd_id);
    hdr.profile = U32::new(profile.profile_id());

    Ok(cur + size_of::<DpeCommandHdr>())
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

#[inline]
fn read_context_handle(src: &[u8], offset: usize) -> McuResult<DpeContextHandle> {
    let bytes = internal_slice(src, offset, DPE_CONTEXT_HANDLE_SIZE)?;
    let mut handle = [0u8; DPE_CONTEXT_HANDLE_SIZE];
    copy_bytes(&mut handle, bytes)?;
    Ok(handle)
}

#[inline]
fn validate_certify_key_prefix(chunk: &[u8], profile: DpeProfile) -> McuResult<()> {
    if chunk.len() < certify_key_prefix_len(profile) {
        return Err(INTERNAL_BUG);
    }
    if read_le_u32(chunk, 0)? != DPE_RESPONSE_MAGIC || read_le_u32(chunk, 4)? != 0 {
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
pub async fn walk_dpe_chain<A: ApiAlloc, S: DpeChainSink>(
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
/// This Caliptra 2.1 implementation supports P-384 digests and ML-DSA-87
/// external `mu`. Raw ML-DSA-87 messages are represented for API compatibility
/// with Caliptra 2.0 and return [`NOT_IMPLEMENTED`] here.
#[inline(never)]
pub async fn dpe_sign<A: ApiAlloc>(
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
        SigningInput::Mldsa87RawMessage(_) => Err(NOT_IMPLEMENTED),
        SigningInput::Mldsa87ExternalMu(mu) => {
            dpe_sign_mldsa87(alloc, handle, label, mu, signature).await
        }
    }
}

/// Invoke DPE `Sign` (P-384 / SHA-384) for the default context handle
/// and the given 48-byte `label`. Signs `digest` and writes the
/// concatenated (r || s) signature into `signature`.
///
/// `signature` must be at least [`DPE_P384_SIGNATURE_SIZE`] (96) bytes. Returns
/// the rotated context handle plus the signature length.
#[inline(never)]
pub async fn dpe_sign_ecc_p384<A: ApiAlloc>(
    alloc: &A,
    handle: Option<&DpeContextHandle>,
    label: &[u8; DPE_LABEL_LEN],
    digest: &[u8],
    signature: &mut [u8],
) -> McuResult<(DpeContextHandle, usize)> {
    if signature.len() < DPE_P384_SIGNATURE_SIZE || digest.len() < DPE_P384_DIGEST_SIZE {
        return Err(INVARIANT);
    }

    let mut req = alloc.alloc(SIGN_REQ_LEN)?;
    req.fill(0);
    let cur = build_invoke_dpe_header(&mut req, SIGN_DPE_PAYLOAD_LEN, DPE_CMD_SIGN)?;
    {
        let cmd = SignP384Cmd::mut_from_bytes(checked_slice_mut(
            &mut req,
            cur,
            size_of::<SignP384Cmd>(),
        )?)
        .map_err(|_| INVARIANT)?;
        cmd.handle = *dpe_handle_or_default(handle);
        cmd.label = *label;
        cmd.flags = U32::new(0);
        cmd.digest = *digest
            .first_chunk::<DPE_P384_DIGEST_SIZE>()
            .ok_or(INVARIANT)?;
    }
    let checksum = calc_checksum(CMD_INVOKE_DPE, &req);
    *req.first_chunk_mut::<4>().ok_or(INVARIANT)? = checksum.to_le_bytes();

    let rsp_max = size_of::<InvokeDpeRespPrefix>() + size_of::<SignP384RespBody>();
    let mut rsp = alloc.alloc(rsp_max)?;
    let rsp_len = mbox_execute(CMD_INVOKE_DPE, &req, &mut rsp).await?;

    let outer_prefix_len = size_of::<InvokeDpeRespPrefix>();
    let resp_body_off = outer_prefix_len;
    if rsp_len < resp_body_off + size_of::<SignP384RespBody>() {
        return Err(INTERNAL_BUG);
    }

    let dpe_hdr = DpeResponseHdr::ref_from_bytes(internal_slice(
        &rsp,
        resp_body_off,
        size_of::<DpeResponseHdr>(),
    )?)
    .map_err(|_| INTERNAL_BUG)?;
    if dpe_hdr.magic.get() != DPE_RESPONSE_MAGIC || dpe_hdr.status.get() != 0 {
        return Err(INTERNAL_BUG);
    }

    let sign_resp = SignP384RespBody::ref_from_bytes(internal_slice(
        &rsp,
        resp_body_off,
        size_of::<SignP384RespBody>(),
    )?)
    .map_err(|_| INTERNAL_BUG)?;
    let (sig_r, rest) = signature.split_first_chunk_mut::<48>().ok_or(INVARIANT)?;
    *sig_r = sign_resp.sig_r;
    let (sig_s, _) = rest.split_first_chunk_mut::<48>().ok_or(INVARIANT)?;
    *sig_s = sign_resp.sig_s;
    Ok((sign_resp._new_context_handle, DPE_P384_SIGNATURE_SIZE))
}

/// Invoke DPE `Sign` for ML-DSA-87 using a precomputed external `mu`.
///
/// `signature` must provide at least [`DPE_MLDSA87_SIGNATURE_SIZE`] bytes.
/// Returns the rotated context handle and signature length.
#[inline(never)]
pub async fn dpe_sign_mldsa87<A: ApiAlloc>(
    alloc: &A,
    handle: Option<&DpeContextHandle>,
    label: &[u8; DPE_LABEL_LEN],
    mu: &[u8; DPE_MLDSA87_MU_SIZE],
    signature: &mut [u8],
) -> McuResult<(DpeContextHandle, usize)> {
    if signature.len() < DPE_MLDSA87_SIGNATURE_SIZE {
        return Err(INVARIANT);
    }

    let request = build_sign_mldsa87_req(alloc, dpe_handle_or_default(handle), label, mu)?;
    let mut response = alloc.alloc(SIGN_MLDSA87_RESP_LEN)?;
    let response_len = mbox_execute(CMD_INVOKE_DPE_MLDSA87, &request, &mut response).await?;
    parse_sign_mldsa87_response(&response, response_len, signature)
}

fn build_sign_mldsa87_req<'a, A: ApiAlloc>(
    alloc: &'a A,
    handle: &DpeContextHandle,
    label: &[u8; DPE_LABEL_LEN],
    mu: &[u8; DPE_MLDSA87_MU_SIZE],
) -> McuResult<A::Buf<'a>> {
    let mut request = alloc.alloc(SIGN_MLDSA87_REQ_LEN)?;
    request.fill(0);
    let command_offset = build_invoke_dpe_header_profile(
        &mut request,
        SIGN_MLDSA87_DPE_PAYLOAD_LEN,
        DPE_CMD_SIGN,
        DpeProfile::Mldsa87,
        None,
    )?;
    let command = SignMldsa87Cmd::mut_from_bytes(checked_slice_mut(
        &mut request,
        command_offset,
        size_of::<SignMldsa87Cmd>(),
    )?)
    .map_err(|_| INVARIANT)?;
    command.handle = *handle;
    command.label = *label;
    command.flags = U32::new(0);
    command.mu = *mu;

    let checksum = calc_checksum(CMD_INVOKE_DPE_MLDSA87, &request);
    *request.first_chunk_mut::<4>().ok_or(INVARIANT)? = checksum.to_le_bytes();
    Ok(request)
}

fn parse_sign_mldsa87_response(
    response: &[u8],
    response_len: usize,
    signature: &mut [u8],
) -> McuResult<(DpeContextHandle, usize)> {
    if signature.len() < DPE_MLDSA87_SIGNATURE_SIZE {
        return Err(INVARIANT);
    }

    let body_offset = size_of::<InvokeDpeRespPrefix>();
    if response_len < body_offset + size_of::<DpeResponseHdr>() {
        return Err(INTERNAL_BUG);
    }
    let dpe_header = DpeResponseHdr::ref_from_bytes(internal_slice(
        response,
        body_offset,
        size_of::<DpeResponseHdr>(),
    )?)
    .map_err(|_| INTERNAL_BUG)?;
    if dpe_header.magic.get() != DPE_RESPONSE_MAGIC
        || dpe_header.status.get() != 0
        || dpe_header.profile.get() != DPE_PROFILE_MLDSA87
    {
        return Err(INTERNAL_BUG);
    }
    if response_len != SIGN_MLDSA87_RESP_LEN {
        return Err(INTERNAL_BUG);
    }

    let sign_response = SignMldsa87RespBody::ref_from_bytes(internal_slice(
        response,
        body_offset,
        size_of::<SignMldsa87RespBody>(),
    )?)
    .map_err(|_| INTERNAL_BUG)?;
    if sign_response.padding != [0] {
        return Err(INTERNAL_BUG);
    }
    copy_bytes(
        signature
            .get_mut(..DPE_MLDSA87_SIGNATURE_SIZE)
            .ok_or(INVARIANT)?,
        &sign_response.signature,
    )?;
    Ok((sign_response.new_context_handle, DPE_MLDSA87_SIGNATURE_SIZE))
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
pub async fn dpe_rotate_context_default<A: ApiAlloc>(
    alloc: &A,
) -> McuResult<[u8; DPE_CONTEXT_HANDLE_SIZE]> {
    // Build request: prefix + DPE command header + RotateCtx body.
    let mut req = alloc.alloc(ROTATE_CTX_REQ_LEN)?;
    req.fill(0);
    let cur = build_invoke_dpe_header(
        &mut req,
        ROTATE_CTX_DPE_PAYLOAD_LEN,
        DPE_CMD_ROTATE_CONTEXT_HANDLE,
    )?;
    {
        // `handle` stays the default (all-zero) context handle from the zeroed
        // request buffer; empty `flags` request a freshly generated handle.
        let cmd = RotateCtxCmd::mut_from_bytes(checked_slice_mut(
            &mut req,
            cur,
            size_of::<RotateCtxCmd>(),
        )?)
        .map_err(|_| INVARIANT)?;
        cmd.flags = U32::new(0);
    }
    let checksum = calc_checksum(CMD_INVOKE_DPE, &req);
    *req.first_chunk_mut::<4>().ok_or(INVARIANT)? = checksum.to_le_bytes();

    let rsp_max = size_of::<InvokeDpeRespPrefix>() + size_of::<NewHandleRespBody>();
    let mut rsp = alloc.alloc(rsp_max)?;
    let rsp_len = mbox_execute(CMD_INVOKE_DPE, &req, &mut rsp).await?;

    let resp_body_off = size_of::<InvokeDpeRespPrefix>();
    if rsp_len < resp_body_off + size_of::<NewHandleRespBody>() {
        return Err(INTERNAL_BUG);
    }
    let dpe_hdr = DpeResponseHdr::ref_from_bytes(internal_slice(
        &rsp,
        resp_body_off,
        size_of::<DpeResponseHdr>(),
    )?)
    .map_err(|_| INTERNAL_BUG)?;
    if dpe_hdr.magic.get() != DPE_RESPONSE_MAGIC || dpe_hdr.status.get() != 0 {
        return Err(INTERNAL_BUG);
    }
    let body = NewHandleRespBody::ref_from_bytes(internal_slice(
        &rsp,
        resp_body_off,
        size_of::<NewHandleRespBody>(),
    )?)
    .map_err(|_| INTERNAL_BUG)?;
    Ok(body.handle)
}

/// Tag the DPE context identified by `handle` with `tag` via the
/// top-level Caliptra `DPE_TAG_TCI` mailbox command.
///
/// Unlike the other DPE helpers here, `DPE_TAG_TCI` is a dedicated
/// Caliptra mailbox command rather than an `INVOKE_DPE` sub-command.
/// MCU Runtime boot initialization tags the rotated MCU Runtime
/// context so its TCI can later be read back by tag.
#[inline(never)]
pub async fn dpe_tag_tci<A: ApiAlloc>(
    alloc: &A,
    handle: &[u8; DPE_CONTEXT_HANDLE_SIZE],
    tag: u32,
) -> McuResult<()> {
    let mut req = alloc.alloc(TAG_TCI_REQ_LEN)?;
    req.fill(0);
    {
        let cmd = TagTciReq::mut_from_bytes(checked_slice_mut(&mut req, 0, TAG_TCI_REQ_LEN)?)
            .map_err(|_| INVARIANT)?;
        cmd.handle = *handle;
        cmd.tag = U32::new(tag);
    }
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
pub async fn dpe_get_tagged_tci<A: ApiAlloc>(alloc: &A, tag: u32) -> McuResult<DpeTaggedTci> {
    let req = build_get_tagged_tci_req(alloc, tag)?;
    let mut rsp = alloc.alloc(GET_TAGGED_TCI_RESP_LEN)?;
    let rsp_len = mbox_execute(CMD_DPE_GET_TAGGED_TCI, &req, &mut rsp).await?;
    parse_get_tagged_tci_response(&rsp, rsp_len)
}

fn build_get_tagged_tci_req<A: ApiAlloc>(alloc: &A, tag: u32) -> McuResult<A::Buf<'_>> {
    let mut req = alloc.alloc(GET_TAGGED_TCI_REQ_LEN)?;
    req.fill(0);
    {
        let cmd = GetTaggedTciReq::mut_from_bytes(checked_slice_mut(
            &mut req,
            0,
            GET_TAGGED_TCI_REQ_LEN,
        )?)
        .map_err(|_| INVARIANT)?;
        cmd.tag = U32::new(tag);
    }
    populate_checksum(CMD_DPE_GET_TAGGED_TCI, &mut req)?;
    Ok(req)
}

fn parse_get_tagged_tci_response(rsp: &[u8], rsp_len: usize) -> McuResult<DpeTaggedTci> {
    if rsp_len < GET_TAGGED_TCI_RESP_LEN {
        return Err(INTERNAL_BUG);
    }
    let resp = GetTaggedTciResp::ref_from_bytes(internal_slice(rsp, 0, GET_TAGGED_TCI_RESP_LEN)?)
        .map_err(|_| INTERNAL_BUG)?;
    Ok(DpeTaggedTci {
        tci_cumulative: resp.tci_cumulative,
        tci_current: resp.tci_current,
    })
}

#[inline]
fn dpe_handle_or_default(handle: Option<&DpeContextHandle>) -> &DpeContextHandle {
    handle.unwrap_or(&DEFAULT_DPE_CONTEXT_HANDLE)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    struct TestAlloc;

    impl ApiAlloc for TestAlloc {
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
        assert_eq!(DPE_CMD_ROTATE_CONTEXT_HANDLE, 0x0e);
        assert_eq!(size_of::<RotateCtxCmd>(), DPE_CONTEXT_HANDLE_SIZE + 4);
        assert_eq!(size_of::<NewHandleRespBody>(), 12 + DPE_CONTEXT_HANDLE_SIZE);
        assert_eq!(ROTATE_CTX_REQ_LEN, 8 + 12 + 20);
        assert_eq!(ROTATE_CTX_DPE_PAYLOAD_LEN, (12 + 20) as u32);
    }

    #[test]
    fn derive_context_wire_layout() {
        assert_eq!(DPE_CMD_DERIVE_CONTEXT, 0x08);
        assert_eq!(
            DpeDeriveContextFlags::RETAIN_PARENT_CONTEXT.bits(),
            1u32 << 29
        );
        assert_eq!(
            size_of::<DeriveContextCmd>(),
            DPE_CONTEXT_HANDLE_SIZE + 48 + 4 + 4 + 4 + 4
        );
        assert_eq!(
            size_of::<DeriveContextRespBody>(),
            12 + DPE_CONTEXT_HANDLE_SIZE * 2
        );
        assert_eq!(DERIVE_CONTEXT_REQ_LEN, 8 + 12 + 80);
        assert_eq!(DERIVE_CONTEXT_DPE_PAYLOAD_LEN, (12 + 80) as u32);
    }

    #[test]
    fn sign_mldsa87_wire_layout() {
        assert_eq!(DPE_CMD_SIGN, 0x0a);
        assert_eq!(size_of::<SignMldsa87Cmd>(), 132);
        assert_eq!(size_of::<SignMldsa87RespBody>(), 4656);
        assert_eq!(SIGN_MLDSA87_REQ_LEN, 168);
        assert_eq!(SIGN_MLDSA87_DPE_PAYLOAD_LEN, 144);
        assert_eq!(SIGN_MLDSA87_RESP_LEN, 4668);
    }

    #[test]
    fn update_context_measurement_wire_layout() {
        assert_eq!(DPE_CMD_UPDATE_CONTEXT_MEASUREMENT, 0x8000_0000);
        assert_eq!(
            size_of::<UpdateContextMeasurementCmd>(),
            DPE_CONTEXT_HANDLE_SIZE + 48 + 4 + 4 + 4
        );
        assert_eq!(
            size_of::<UpdateContextMeasurementRespBody>(),
            12 + DPE_CONTEXT_HANDLE_SIZE * 2
        );
        assert_eq!(UPDATE_CONTEXT_MEASUREMENT_REQ_LEN, 8 + 12 + 76);
        assert_eq!(UPDATE_CONTEXT_MEASUREMENT_DPE_PAYLOAD_LEN, (12 + 76) as u32);
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

        let (req, mbox_cmd) =
            build_derive_context_req(&alloc, &params, DpeProfile::P384Sha384, None).unwrap();
        assert_eq!(mbox_cmd, CMD_INVOKE_DPE);
        let payload_len =
            u32::from_le_bytes(*req.get(4..8).and_then(|s| s.first_chunk::<4>()).unwrap());
        let hdr = DpeCommandHdr::ref_from_bytes(&req[8..20]).unwrap();
        let cmd = DeriveContextCmd::ref_from_bytes(&req[20..100]).unwrap();

        assert_eq!(payload_len, DERIVE_CONTEXT_DPE_PAYLOAD_LEN);
        assert_eq!(hdr.cmd_id.get(), DPE_CMD_DERIVE_CONTEXT);
        assert_eq!(cmd.handle, params.parent_handle);
        assert_eq!(cmd.data, params.measurement);
        assert_eq!(cmd.flags.get(), params.flags.bits());
        assert_eq!(cmd.tci_type.get(), params.tci_type);
        assert_eq!(cmd.target_locality.get(), params.target_locality);
        assert_eq!(cmd.svn.get(), params.svn);
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

        let (req, mbox_cmd) = build_derive_context_req(
            &alloc,
            &params,
            DpeProfile::Mldsa87,
            Some((0xA8C0_1000, 24576)),
        )
        .unwrap();
        assert_eq!(mbox_cmd, CMD_INVOKE_DPE_MLDSA87);
        let prefix = InvokeDpeMldsa87ReqPrefix::ref_from_bytes(
            &req[..size_of::<InvokeDpeMldsa87ReqPrefix>()],
        )
        .unwrap();
        assert_eq!(prefix.flags.get(), 1 << 31);
        assert_eq!(prefix.axi_addr_lo.get(), 0xA8C0_1000);
        assert_eq!(prefix.axi_addr_hi.get(), 0);
        assert_eq!(prefix.axi_max_size.get(), 24576);
        assert_eq!(prefix.data_size.get(), DERIVE_CONTEXT_DPE_PAYLOAD_LEN);
    }

    #[test]
    fn update_context_measurement_request_preserves_fields() {
        let alloc = TestAlloc;
        let params = DpeUpdateContextMeasurementParams {
            parent_handle: [0xa5u8; DPE_CONTEXT_HANDLE_SIZE],
            measurement: [0x5au8; DPE_TCI_MEASUREMENT_SIZE],
            tci_type: 0x1122_3344,
        };

        let req = build_update_context_measurement_req(&alloc, &params).unwrap();
        let payload_len =
            u32::from_le_bytes(*req.get(4..8).and_then(|s| s.first_chunk::<4>()).unwrap());
        let hdr = DpeCommandHdr::ref_from_bytes(&req[8..20]).unwrap();
        let cmd = UpdateContextMeasurementCmd::ref_from_bytes(&req[20..96]).unwrap();

        assert_eq!(payload_len, UPDATE_CONTEXT_MEASUREMENT_DPE_PAYLOAD_LEN);
        assert_eq!(hdr.cmd_id.get(), DPE_CMD_UPDATE_CONTEXT_MEASUREMENT);
        assert_eq!(cmd.parent_handle, params.parent_handle);
        assert_eq!(cmd.data, params.measurement);
        assert_eq!(cmd.reserved.get(), 0);
        assert_eq!(cmd.tci_type.get(), params.tci_type);
        assert_eq!(cmd.reserved_svn.get(), 0);
    }

    #[test]
    fn none_handle_maps_to_default_handle() {
        assert_eq!(dpe_handle_or_default(None), &DEFAULT_DPE_CONTEXT_HANDLE);
    }

    #[test]
    fn certify_key_chunks_reads_returned_handle_from_response_info() {
        let handle = [0x3cu8; DPE_CONTEXT_HANDLE_SIZE];
        let mut rsp = [0u8; CERTIFY_KEY_CHUNKS_RESP_INFO_LEN];
        rsp[CERTIFY_KEY_CHUNKS_RESP_HANDLE_OFF
            ..CERTIFY_KEY_CHUNKS_RESP_HANDLE_OFF + DPE_CONTEXT_HANDLE_SIZE]
            .copy_from_slice(&handle);

        assert_eq!(
            read_context_handle(&rsp, CERTIFY_KEY_CHUNKS_RESP_HANDLE_OFF).unwrap(),
            handle
        );
    }

    #[test]
    fn certify_key_mldsa87_pubkey_parser_copies_raw_key() {
        let expected_key = [0x5au8; CERTIFY_KEY_MLDSA87_PUBKEY_SIZE];
        let mut response = std::vec![0u8; CERTIFY_KEY_MLDSA87_RESP_PREFIX_LEN];
        response[..4].copy_from_slice(&DPE_RESPONSE_MAGIC.to_le_bytes());
        response[8..12].copy_from_slice(&DPE_PROFILE_MLDSA87.to_le_bytes());
        response[CERTIFY_KEY_RESP_PUBKEY_X_OFF
            ..CERTIFY_KEY_RESP_PUBKEY_X_OFF + CERTIFY_KEY_MLDSA87_PUBKEY_SIZE]
            .copy_from_slice(&expected_key);

        let mut public_key = [0u8; CERTIFY_KEY_MLDSA87_PUBKEY_SIZE];
        parse_certify_key_mldsa87_pubkey(&response, &mut public_key).unwrap();

        assert_eq!(public_key, expected_key);
    }

    #[test]
    fn sign_mldsa87_request_preserves_fields() {
        let alloc = TestAlloc;
        let handle = [0x11u8; DPE_CONTEXT_HANDLE_SIZE];
        let label = [0x22u8; DPE_LABEL_LEN];
        let mu = [0x33u8; DPE_MLDSA87_MU_SIZE];
        let request = build_sign_mldsa87_req(&alloc, &handle, &label, &mu).unwrap();

        let prefix = InvokeDpeMldsa87ReqPrefix::ref_from_prefix(&request)
            .unwrap()
            .0;
        assert_eq!(prefix.flags.get(), 0);
        assert_eq!(prefix.axi_addr_lo.get(), 0);
        assert_eq!(prefix.axi_addr_hi.get(), 0);
        assert_eq!(prefix.axi_max_size.get(), 0);
        assert_eq!(prefix.data_size.get(), SIGN_MLDSA87_DPE_PAYLOAD_LEN);

        let header_offset = size_of::<InvokeDpeMldsa87ReqPrefix>();
        let header = DpeCommandHdr::ref_from_prefix(&request[header_offset..])
            .unwrap()
            .0;
        assert_eq!(header.magic.get(), DPE_COMMAND_MAGIC);
        assert_eq!(header.cmd_id.get(), DPE_CMD_SIGN);
        assert_eq!(header.profile.get(), DPE_PROFILE_MLDSA87);

        let command_offset = header_offset + size_of::<DpeCommandHdr>();
        let command = SignMldsa87Cmd::ref_from_prefix(&request[command_offset..])
            .unwrap()
            .0;
        assert_eq!(command.handle, handle);
        assert_eq!(command.label, label);
        assert_eq!(command.flags.get(), 0);
        assert_eq!(command.mu, mu);

        let mut checksum_input = request.clone();
        checksum_input[..4].fill(0);
        assert_eq!(
            prefix.chksum.get(),
            calc_checksum(CMD_INVOKE_DPE_MLDSA87, &checksum_input)
        );
    }

    #[test]
    fn sign_mldsa87_response_parser_returns_handle_and_signature() {
        let handle = [0x44u8; DPE_CONTEXT_HANDLE_SIZE];
        let expected_signature = [0x55u8; DPE_MLDSA87_SIGNATURE_SIZE];
        let mut response = std::vec![0u8; SIGN_MLDSA87_RESP_LEN];
        let body_offset = size_of::<InvokeDpeRespPrefix>();
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
        let body_offset = size_of::<InvokeDpeRespPrefix>();
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
        let resp_body_off = size_of::<InvokeDpeRespPrefix>();
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
        let resp_body_off = size_of::<InvokeDpeRespPrefix>();
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
        let resp_body_off = size_of::<InvokeDpeRespPrefix>();
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

        let prefix_len = size_of::<DeriveContextExportedCdiRespPrefix>();
        let resp_body_off = size_of::<InvokeDpeRespPrefix>();
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

        let mut cert_dst = [0u8; 128];
        let result =
            parse_derive_context_exported_cdi_response(&rsp, rsp.len(), &mut cert_dst).unwrap();

        assert_eq!(result.child_handle, child_handle);
        assert_eq!(result.parent_handle, parent_handle);
        assert_eq!(result.exported_cdi, exported_cdi);
        assert_eq!(result.cert_size, cert_data.len());
        assert_eq!(&cert_dst[..cert_data.len()], &cert_data);
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
        assert_eq!(DpeProfile::P384Sha384.profile_id(), 4);
        assert_eq!(DpeProfile::P384Sha384.invoke_cmd_id(), CMD_INVOKE_DPE);
        assert_eq!(DpeProfile::Mldsa87.profile_id(), 5);
        assert_eq!(DpeProfile::Mldsa87.invoke_cmd_id(), CMD_INVOKE_DPE_MLDSA87);
    }

    #[test]
    fn signing_input_selects_dpe_profile() {
        let digest = [0u8; DPE_P384_DIGEST_SIZE];
        let message = [0u8; 1];
        let mu = [0u8; DPE_MLDSA87_MU_SIZE];

        assert_eq!(
            SigningInput::EccP384Digest(&digest).profile(),
            DpeProfile::P384Sha384
        );
        assert_eq!(
            SigningInput::Mldsa87RawMessage(&message).profile(),
            DpeProfile::Mldsa87
        );
        assert_eq!(
            SigningInput::Mldsa87ExternalMu(&mu).profile(),
            DpeProfile::Mldsa87
        );
    }

    #[test]
    fn build_invoke_dpe_header_profile_p384_and_mldsa87() {
        let mut buf_p384 = [0u8; GET_CERT_CHAIN_REQ_P384_LEN];
        let off_p384 = build_invoke_dpe_header_profile(
            &mut buf_p384,
            GET_CERT_CHAIN_DPE_PAYLOAD_LEN,
            DPE_CMD_GET_CERTIFICATE_CHAIN,
            DpeProfile::P384Sha384,
            None,
        )
        .unwrap();
        assert_eq!(off_p384, 8 + 12);
        let p384_prefix = InvokeDpeReqPrefix::ref_from_prefix(&buf_p384).unwrap().0;
        assert_eq!(p384_prefix.data_size.get(), GET_CERT_CHAIN_DPE_PAYLOAD_LEN);
        let p384_hdr = DpeCommandHdr::ref_from_prefix(&buf_p384[8..]).unwrap().0;
        assert_eq!(p384_hdr.magic.get(), DPE_COMMAND_MAGIC);
        assert_eq!(p384_hdr.cmd_id.get(), DPE_CMD_GET_CERTIFICATE_CHAIN);
        assert_eq!(p384_hdr.profile.get(), 4);

        let mut buf_mldsa = [0u8; GET_CERT_CHAIN_REQ_MLDSA87_LEN];
        let off_mldsa = build_invoke_dpe_header_profile(
            &mut buf_mldsa,
            GET_CERT_CHAIN_DPE_PAYLOAD_LEN,
            DPE_CMD_GET_CERTIFICATE_CHAIN,
            DpeProfile::Mldsa87,
            None,
        )
        .unwrap();
        assert_eq!(off_mldsa, 24 + 12);
        let mldsa_prefix = InvokeDpeMldsa87ReqPrefix::ref_from_prefix(&buf_mldsa)
            .unwrap()
            .0;
        assert_eq!(mldsa_prefix.flags.get(), 0);
        assert_eq!(mldsa_prefix.axi_addr_lo.get(), 0);
        assert_eq!(mldsa_prefix.axi_addr_hi.get(), 0);
        assert_eq!(mldsa_prefix.axi_max_size.get(), 0);
        assert_eq!(mldsa_prefix.data_size.get(), GET_CERT_CHAIN_DPE_PAYLOAD_LEN);
        let mldsa_hdr = DpeCommandHdr::ref_from_prefix(&buf_mldsa[24..]).unwrap().0;
        assert_eq!(mldsa_hdr.magic.get(), DPE_COMMAND_MAGIC);
        assert_eq!(mldsa_hdr.cmd_id.get(), DPE_CMD_GET_CERTIFICATE_CHAIN);
        assert_eq!(mldsa_hdr.profile.get(), 5);
    }
}

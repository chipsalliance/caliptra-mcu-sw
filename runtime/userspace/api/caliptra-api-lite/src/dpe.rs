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

use core::{mem::size_of, ops::Deref};
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::slice::{checked_slice_mut, copy_bytes, internal_slice};
use crate::wire::{
    calc_checksum, mbox_execute, populate_checksum, CMD_CERTIFY_KEY_CHUNKS, CMD_DPE_TAG_TCI,
    CMD_INVOKE_DPE, DPE_CMD_GET_CERTIFICATE_CHAIN, DPE_CMD_ROTATE_CONTEXT_HANDLE, DPE_CMD_SIGN,
    DPE_COMMAND_MAGIC, DPE_PROFILE_P384_SHA384, DPE_RESPONSE_MAGIC, MBOX_RESP_HEADER_SIZE,
};
use crate::ApiAlloc;

/// Length in bytes of the DPE key/UEID label used by every
/// `CertifyKey` / `Sign` call in this crate.
pub const DPE_LABEL_LEN: usize = 48;

/// Output format selector for `CertifyKey` — we only support the
/// X.509 leaf certificate form (`dpe::commands::certify_key::CertifyKeyCommand::FORMAT_X509`).
const DPE_CERTIFY_KEY_FORMAT_X509: u32 = 0;

/// DPE context handle width (`dpe::context::ContextHandle::SIZE`).
pub const DPE_CONTEXT_HANDLE_SIZE: usize = 16;

pub type DpeContextHandle = [u8; DPE_CONTEXT_HANDLE_SIZE];

const DEFAULT_DPE_CONTEXT_HANDLE: DpeContextHandle = [0u8; DPE_CONTEXT_HANDLE_SIZE];

/// Upper bound on the X.509 leaf certificate Caliptra's DPE can
/// emit — mirrored from `dpe::MAX_CERT_SIZE` (2 KB).
pub const DPE_MAX_LEAF_CERT_SIZE: usize = 2048;

/// Maximum bytes that may be fetched in a single
/// [`dpe_get_cert_chain_chunk`] call. Bounded well below the
/// `InvokeDpeResp::DATA_MAX_SIZE` of 8 KB so a single call fits in a
/// few bitmap-allocator slots.
pub const DPE_MAX_CHUNK_SIZE: usize = 1024;

/// Serialized `dpe::commands::CertifyKeyP384Cmd` body length carried by
/// Caliptra's `CertifyKeyChunksReq`.
const CERTIFY_KEY_CHUNKS_CERTIFY_KEY_REQ_SIZE: usize = 72;

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
    digest: [u8; DPE_LABEL_LEN], // same size as hash (48)
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

/// Caliptra `TagTciReq`: `chksum(4) + handle(16) + tag(4)`. The
/// `DPE_TAG_TCI` response carries no command-specific output.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct TagTciReq {
    chksum: U32,
    handle: [u8; DPE_CONTEXT_HANDLE_SIZE],
    tag: U32,
}

const TAG_TCI_REQ_LEN: usize = size_of::<TagTciReq>();
const _: () = assert!(TAG_TCI_REQ_LEN == 4 + DPE_CONTEXT_HANDLE_SIZE + 4);

const GET_CERT_CHAIN_REQ_LEN: usize =
    size_of::<InvokeDpeReqPrefix>() + size_of::<DpeCommandHdr>() + size_of::<GetCertChainCmd>();
const GET_CERT_CHAIN_DPE_PAYLOAD_LEN: u32 =
    (size_of::<DpeCommandHdr>() + size_of::<GetCertChainCmd>()) as u32;

const SIGN_REQ_LEN: usize =
    size_of::<InvokeDpeReqPrefix>() + size_of::<DpeCommandHdr>() + size_of::<SignP384Cmd>();
const SIGN_DPE_PAYLOAD_LEN: u32 = (size_of::<DpeCommandHdr>() + size_of::<SignP384Cmd>()) as u32;
const CERTIFY_KEY_P384_RESP_PREFIX_LEN: usize = 12 + DPE_CONTEXT_HANDLE_SIZE + 48 + 48 + 4;
const CERTIFY_KEY_CHUNKS_REQ_LEN: usize =
    4 + 4 + 4 + 4 + 4 + CERTIFY_KEY_CHUNKS_CERTIFY_KEY_REQ_SIZE;
const CERTIFY_KEY_CHUNKS_RESP_INFO_LEN: usize = 4 + 4 + DPE_CONTEXT_HANDLE_SIZE + 4 + 4;
const CERTIFY_KEY_CHUNKS_RESP_BUF_LEN: usize =
    CERTIFY_KEY_CHUNKS_RESP_INFO_LEN + CERTIFY_KEY_P384_RESP_PREFIX_LEN + DPE_MAX_LEAF_CERT_SIZE;
const CERTIFY_KEY_RESP_PUBKEY_X_OFF: usize = 12 + DPE_CONTEXT_HANDLE_SIZE;
const CERTIFY_KEY_RESP_PUBKEY_Y_OFF: usize = CERTIFY_KEY_RESP_PUBKEY_X_OFF + 48;
const CERTIFY_KEY_RESP_CERT_SIZE_OFF: usize = CERTIFY_KEY_RESP_PUBKEY_Y_OFF + 48;
const CERTIFY_KEY_CHUNKS_REQ_MAX_SIZE_OFF: usize = 12;
const CERTIFY_KEY_CHUNKS_REQ_OFFSET_OFF: usize = 16;
const CERTIFY_KEY_CHUNKS_REQ_DPE_CMD_OFF: usize = 20;
const CERTIFY_KEY_CHUNKS_REQ_HANDLE_OFF: usize = CERTIFY_KEY_CHUNKS_REQ_DPE_CMD_OFF;
const CERTIFY_KEY_CHUNKS_REQ_FORMAT_OFF: usize =
    CERTIFY_KEY_CHUNKS_REQ_DPE_CMD_OFF + DPE_CONTEXT_HANDLE_SIZE + 4;
const CERTIFY_KEY_CHUNKS_REQ_LABEL_OFF: usize = CERTIFY_KEY_CHUNKS_REQ_FORMAT_OFF + 4;
const CERTIFY_KEY_CHUNKS_RESP_HANDLE_OFF: usize = 4 + 4;
const CERTIFY_KEY_CHUNKS_RESP_CHUNK_LEN_OFF: usize = 4 + 4 + DPE_CONTEXT_HANDLE_SIZE;

const ROTATE_CTX_REQ_LEN: usize =
    size_of::<InvokeDpeReqPrefix>() + size_of::<DpeCommandHdr>() + size_of::<RotateCtxCmd>();
const ROTATE_CTX_DPE_PAYLOAD_LEN: u32 =
    (size_of::<DpeCommandHdr>() + size_of::<RotateCtxCmd>()) as u32;

const _: () = assert!(size_of::<InvokeDpeReqPrefix>() == 8);
const _: () = assert!(size_of::<DpeCommandHdr>() == 12);
const _: () = assert!(size_of::<GetCertChainCmd>() == 8);
const _: () = assert!(size_of::<SignP384Cmd>() == DPE_CONTEXT_HANDLE_SIZE + 48 + 4 + 48);
const _: () = assert!(size_of::<SignP384RespBody>() == 12 + DPE_CONTEXT_HANDLE_SIZE + 48 + 48);
const _: () = assert!(size_of::<InvokeDpeRespPrefix>() == 12);
const _: () = assert!(size_of::<DpeResponseHdr>() == 12);
const _: () = assert!(GET_CERT_CHAIN_REQ_LEN == 28);
const _: () = assert!(SIGN_REQ_LEN == 8 + 12 + 116);
const _: () =
    assert!(CERTIFY_KEY_CHUNKS_CERTIFY_KEY_REQ_SIZE == DPE_CONTEXT_HANDLE_SIZE + 4 + 4 + 48);
const _: () = assert!(CERTIFY_KEY_P384_RESP_PREFIX_LEN == 128);
const _: () = assert!(CERTIFY_KEY_CHUNKS_REQ_LEN == 92);
const _: () = assert!(CERTIFY_KEY_CHUNKS_RESP_INFO_LEN == 32);
const _: () = assert!(size_of::<RotateCtxCmd>() == DPE_CONTEXT_HANDLE_SIZE + 4);
const _: () = assert!(size_of::<NewHandleRespBody>() == 12 + DPE_CONTEXT_HANDLE_SIZE);
const _: () = assert!(ROTATE_CTX_REQ_LEN == 8 + 12 + 20);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fetch a chunk of the Caliptra-managed DPE certificate chain via
/// the `INVOKE_DPE / GetCertificateChain` mailbox command.
///
/// `dst.len()` is the requested chunk size and MUST be in
/// `1..=DPE_MAX_CHUNK_SIZE`. Returns the number of bytes Caliptra
/// actually wrote. A short read (`returned < dst.len()`) signals
/// end-of-chain; callers should stop probing.
#[inline(never)]
pub async fn dpe_get_cert_chain_chunk<A: ApiAlloc>(
    alloc: &A,
    offset: u32,
    dst: &mut [u8],
) -> McuResult<usize> {
    if dst.is_empty() || dst.len() > DPE_MAX_CHUNK_SIZE {
        return Err(INVARIANT);
    }
    let size = dst.len() as u32;

    // Build request: prefix + DPE command header + GetCertChain body.
    let mut req = alloc.alloc(GET_CERT_CHAIN_REQ_LEN)?;
    req.fill(0);
    {
        let prefix = InvokeDpeReqPrefix::mut_from_bytes(checked_slice_mut(
            &mut req,
            0,
            size_of::<InvokeDpeReqPrefix>(),
        )?)
        .map_err(|_| INVARIANT)?;
        prefix.data_size = U32::new(GET_CERT_CHAIN_DPE_PAYLOAD_LEN);
    }
    let mut cur = size_of::<InvokeDpeReqPrefix>();
    {
        let hdr = DpeCommandHdr::mut_from_bytes(checked_slice_mut(
            &mut req,
            cur,
            size_of::<DpeCommandHdr>(),
        )?)
        .map_err(|_| INVARIANT)?;
        hdr.magic = U32::new(DPE_COMMAND_MAGIC);
        hdr.cmd_id = U32::new(DPE_CMD_GET_CERTIFICATE_CHAIN);
        hdr.profile = U32::new(DPE_PROFILE_P384_SHA384);
    }
    cur += size_of::<DpeCommandHdr>();
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
    let checksum = calc_checksum(CMD_INVOKE_DPE, &req);
    *req.first_chunk_mut::<4>().ok_or(INVARIANT)? = checksum.to_le_bytes();

    // Allocate response: outer prefix + DPE response hdr + cert_size
    // + chain bytes (up to DPE_MAX_CHUNK_SIZE).
    let rsp_max =
        size_of::<InvokeDpeRespPrefix>() + size_of::<DpeResponseHdr>() + 4 + DPE_MAX_CHUNK_SIZE;
    let mut rsp = alloc.alloc(rsp_max)?;
    let rsp_len = mbox_execute(CMD_INVOKE_DPE, &req, &mut rsp).await?;

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

/// Invoke DPE `CertifyKey` (P-384 / SHA-384, X.509 format) for the
/// default context handle and the given 48-byte `label`. Writes the
/// emitted leaf certificate DER into `dst` and returns the rotated context
/// handle plus the number of bytes actually written.
///
/// Prefer [`dpe_certify_key_cert_slice`] when the caller only needs a
/// slice of the certificate.
#[inline(never)]
pub async fn dpe_certify_key<A: ApiAlloc>(
    alloc: &A,
    handle: Option<&DpeContextHandle>,
    label: &[u8; DPE_LABEL_LEN],
    dst: &mut [u8],
) -> McuResult<(DpeContextHandle, usize)> {
    if dst.is_empty() {
        return Err(INVARIANT);
    }

    let max_size = CERTIFY_KEY_P384_RESP_PREFIX_LEN
        .checked_add(dst.len())
        .ok_or(INVARIANT)?
        .min(DPE_MAX_CHUNK_SIZE);
    let chunk =
        certify_key_chunks_response(alloc, label, dpe_handle_or_default(handle), 0, max_size)
            .await?;
    let response = chunk.chunk()?;
    validate_certify_key_prefix(response)?;
    let cert_size = read_le_u32(response, CERTIFY_KEY_RESP_CERT_SIZE_OFF)? as usize;
    let cert_start = CERTIFY_KEY_P384_RESP_PREFIX_LEN;
    let cert_end = cert_start.checked_add(cert_size).ok_or(INVARIANT)?;
    let cert = internal_slice(response, cert_start, cert_end - cert_start)?;
    if cert_size > dst.len() {
        return Err(INVARIANT);
    }
    let out = dst.get_mut(..cert_size).ok_or(INTERNAL_BUG)?;
    copy_bytes(out, cert)?;

    if cert_size > dst.len() {
        return Err(INTERNAL_BUG);
    }
    Ok((chunk.next_handle, cert_size))
}

/// Return the DER leaf certificate length emitted by DPE `CertifyKey`
/// without fetching the certificate body, along with the rotated context handle.
#[inline(never)]
pub async fn dpe_certify_key_cert_size<A: ApiAlloc>(
    alloc: &A,
    handle: Option<&DpeContextHandle>,
    label: &[u8; DPE_LABEL_LEN],
) -> McuResult<(DpeContextHandle, usize)> {
    let chunk = certify_key_chunks_response(
        alloc,
        label,
        dpe_handle_or_default(handle),
        0,
        CERTIFY_KEY_P384_RESP_PREFIX_LEN,
    )
    .await?;
    let response = chunk.chunk()?;
    validate_certify_key_prefix(response)?;
    Ok((
        chunk.next_handle,
        read_le_u32(response, CERTIFY_KEY_RESP_CERT_SIZE_OFF)? as usize,
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
    handle: Option<&DpeContextHandle>,
    label: &[u8; DPE_LABEL_LEN],
    cert_offset: u32,
    dst: &mut [u8],
) -> McuResult<(DpeContextHandle, usize)> {
    if dst.is_empty() || dst.len() > DPE_MAX_CHUNK_SIZE {
        return Err(INVARIANT);
    }

    let dpe_offset = CERTIFY_KEY_P384_RESP_PREFIX_LEN
        .checked_add(cert_offset as usize)
        .ok_or(INVARIANT)?;
    let chunk = certify_key_chunks_response(
        alloc,
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
        label,
        dpe_handle_or_default(handle),
        0,
        CERTIFY_KEY_P384_RESP_PREFIX_LEN,
    )
    .await?;
    let response = chunk.chunk()?;
    validate_certify_key_prefix(response)?;
    let pubkey_x_bytes = internal_slice(response, CERTIFY_KEY_RESP_PUBKEY_X_OFF, 48)?;
    let pubkey_y_bytes = internal_slice(response, CERTIFY_KEY_RESP_PUBKEY_Y_OFF, 48)?;
    copy_bytes(pubkey_x, pubkey_x_bytes)?;
    copy_bytes(pubkey_y, pubkey_y_bytes)?;
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
    label: &[u8; DPE_LABEL_LEN],
    handle: &[u8; DPE_CONTEXT_HANDLE_SIZE],
    dpe_resp_offset: u32,
    max_size: usize,
) -> McuResult<CertifyKeyChunk<A::Buf<'a>>>
where
    A: ApiAlloc,
{
    if max_size == 0 || max_size > DPE_MAX_CHUNK_SIZE {
        return Err(INVARIANT);
    }

    let req = build_certify_key_chunks_req(alloc, label, handle, dpe_resp_offset, max_size)?;
    let mut rsp = alloc.alloc(CERTIFY_KEY_CHUNKS_RESP_BUF_LEN)?;
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
    label: &[u8; DPE_LABEL_LEN],
    handle: &[u8; DPE_CONTEXT_HANDLE_SIZE],
    offset: u32,
    max_size: usize,
) -> McuResult<A::Buf<'a>> {
    let mut req = alloc.alloc(CERTIFY_KEY_CHUNKS_REQ_LEN)?;
    req.fill(0);
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
fn validate_certify_key_prefix(chunk: &[u8]) -> McuResult<()> {
    if chunk.len() < CERTIFY_KEY_P384_RESP_PREFIX_LEN {
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

/// Walks the entire DPE certificate chain in
/// [`DPE_MAX_CHUNK_SIZE`]-byte chunks, feeding each chunk to `sink`.
/// Returns the total number of bytes walked. A short read
/// (`returned < DPE_MAX_CHUNK_SIZE`) ends the walk.
pub async fn walk_dpe_chain<A: ApiAlloc, S: DpeChainSink>(
    alloc: &A,
    sink: &mut S,
) -> McuResult<u32> {
    const MAX_CHAIN_LEN: u32 = 16 * 1024;
    let mut buf = alloc.alloc(DPE_MAX_CHUNK_SIZE)?;
    let mut total: u32 = 0;
    loop {
        let n = dpe_get_cert_chain_chunk(alloc, total, &mut buf).await?;
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
    if signature.len() < DPE_P384_SIGNATURE_SIZE || digest.len() < DPE_LABEL_LEN {
        return Err(INVARIANT);
    }

    let mut req = alloc.alloc(SIGN_REQ_LEN)?;
    req.fill(0);
    {
        let prefix = InvokeDpeReqPrefix::mut_from_bytes(checked_slice_mut(
            &mut req,
            0,
            size_of::<InvokeDpeReqPrefix>(),
        )?)
        .map_err(|_| INVARIANT)?;
        prefix.data_size = U32::new(SIGN_DPE_PAYLOAD_LEN);
    }
    let mut cur = size_of::<InvokeDpeReqPrefix>();
    {
        let hdr = DpeCommandHdr::mut_from_bytes(checked_slice_mut(
            &mut req,
            cur,
            size_of::<DpeCommandHdr>(),
        )?)
        .map_err(|_| INVARIANT)?;
        hdr.magic = U32::new(DPE_COMMAND_MAGIC);
        hdr.cmd_id = U32::new(DPE_CMD_SIGN);
        hdr.profile = U32::new(DPE_PROFILE_P384_SHA384);
    }
    cur += size_of::<DpeCommandHdr>();
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
        cmd.digest = *digest.first_chunk::<DPE_LABEL_LEN>().ok_or(INVARIANT)?;
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
    {
        let prefix = InvokeDpeReqPrefix::mut_from_bytes(checked_slice_mut(
            &mut req,
            0,
            size_of::<InvokeDpeReqPrefix>(),
        )?)
        .map_err(|_| INVARIANT)?;
        prefix.data_size = U32::new(ROTATE_CTX_DPE_PAYLOAD_LEN);
    }
    let mut cur = size_of::<InvokeDpeReqPrefix>();
    {
        let hdr = DpeCommandHdr::mut_from_bytes(checked_slice_mut(
            &mut req,
            cur,
            size_of::<DpeCommandHdr>(),
        )?)
        .map_err(|_| INVARIANT)?;
        hdr.magic = U32::new(DPE_COMMAND_MAGIC);
        hdr.cmd_id = U32::new(DPE_CMD_ROTATE_CONTEXT_HANDLE);
        hdr.profile = U32::new(DPE_PROFILE_P384_SHA384);
    }
    cur += size_of::<DpeCommandHdr>();
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
            let mut buf = Vec::new();
            buf.resize(len, 0);
            Ok(buf)
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
    fn tag_tci_wire_layout() {
        assert_eq!(CMD_DPE_TAG_TCI, 0x5451_4754);
        assert_eq!(TAG_TCI_REQ_LEN, 4 + DPE_CONTEXT_HANDLE_SIZE + 4);
    }

    #[test]
    fn certify_key_chunks_uses_supplied_handle() {
        let handle = [0xa5u8; DPE_CONTEXT_HANDLE_SIZE];
        let label = [0x5au8; DPE_LABEL_LEN];
        let alloc = TestAlloc;

        let req = build_certify_key_chunks_req(&alloc, &label, &handle, 0, 128).unwrap();

        assert_eq!(
            &req[CERTIFY_KEY_CHUNKS_REQ_HANDLE_OFF
                ..CERTIFY_KEY_CHUNKS_REQ_HANDLE_OFF + DPE_CONTEXT_HANDLE_SIZE],
            &handle
        );
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
}

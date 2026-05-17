// Licensed under the Apache-2.0 license

//! DPE primitives over Caliptra's `INVOKE_DPE` mailbox command.
//!
//! Mirrors the on-wire layouts from
//! `caliptra-dpe/dpe::commands` (request) and
//! `caliptra-dpe/dpe::response` (response) using slim
//! [`zerocopy::Unaligned`] structs so request / response buffers are
//! allocated from the caller's [`ApiAlloc`] — never the stack —
//! keeping async futures small.

use caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox;
use core::mem::size_of;
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::wire::{
    calc_checksum, CMD_INVOKE_DPE, DPE_CMD_CERTIFY_KEY, DPE_CMD_GET_CERTIFICATE_CHAIN,
    DPE_COMMAND_MAGIC, DPE_PROFILE_P384_SHA384, DPE_RESPONSE_MAGIC,
};
use crate::ApiAlloc;

/// Length in bytes of the DPE key/UEID label used by every
/// `CertifyKey` / `Sign` call in this crate.
pub const DPE_LABEL_LEN: usize = 48;

/// Output format selector for `CertifyKey` — we only support the
/// X.509 leaf certificate form (`dpe::commands::certify_key::CertifyKeyCommand::FORMAT_X509`).
const DPE_CERTIFY_KEY_FORMAT_X509: u32 = 0;

/// DPE context handle width (`dpe::context::ContextHandle::SIZE`).
const DPE_CONTEXT_HANDLE_SIZE: usize = 16;

/// Upper bound on the X.509 leaf certificate Caliptra's DPE can
/// emit — mirrored from `dpe::MAX_CERT_SIZE` (2 KB).
pub const DPE_MAX_LEAF_CERT_SIZE: usize = 2048;

/// Maximum bytes that may be fetched in a single
/// [`dpe_get_cert_chain_chunk`] call. Bounded well below the
/// `InvokeDpeResp::DATA_MAX_SIZE` of 8 KB so a single call fits in a
/// few bitmap-allocator slots.
pub const DPE_MAX_CHUNK_SIZE: usize = 1024;

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

/// `dpe::commands::CertifyKeyP384Cmd`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct CertifyKeyP384Cmd {
    handle: [u8; DPE_CONTEXT_HANDLE_SIZE],
    flags: U32,
    format: U32,
    label: [u8; DPE_LABEL_LEN],
}

/// Prefix of `dpe::response::CertifyKeyP384Resp` that precedes the
/// emitted `cert` bytes.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct CertifyKeyP384RespPrefix {
    _resp_hdr: [u8; 12],
    _new_context_handle: [u8; DPE_CONTEXT_HANDLE_SIZE],
    _derived_pubkey_x: [u8; 48],
    _derived_pubkey_y: [u8; 48],
    cert_size: U32,
}

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

const GET_CERT_CHAIN_REQ_LEN: usize = size_of::<InvokeDpeReqPrefix>()
    + size_of::<DpeCommandHdr>()
    + size_of::<GetCertChainCmd>();
const GET_CERT_CHAIN_DPE_PAYLOAD_LEN: u32 =
    (size_of::<DpeCommandHdr>() + size_of::<GetCertChainCmd>()) as u32;

const CERTIFY_KEY_REQ_LEN: usize = size_of::<InvokeDpeReqPrefix>()
    + size_of::<DpeCommandHdr>()
    + size_of::<CertifyKeyP384Cmd>();
const CERTIFY_KEY_DPE_PAYLOAD_LEN: u32 =
    (size_of::<DpeCommandHdr>() + size_of::<CertifyKeyP384Cmd>()) as u32;

const _: () = assert!(size_of::<InvokeDpeReqPrefix>() == 8);
const _: () = assert!(size_of::<DpeCommandHdr>() == 12);
const _: () = assert!(size_of::<GetCertChainCmd>() == 8);
const _: () = assert!(size_of::<CertifyKeyP384Cmd>() == DPE_CONTEXT_HANDLE_SIZE + 4 + 4 + 48);
const _: () = assert!(size_of::<InvokeDpeRespPrefix>() == 12);
const _: () = assert!(size_of::<DpeResponseHdr>() == 12);
const _: () = assert!(GET_CERT_CHAIN_REQ_LEN == 28);
const _: () = assert!(CERTIFY_KEY_REQ_LEN == 8 + 12 + 72);

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
        let prefix = InvokeDpeReqPrefix::mut_from_bytes(
            &mut req[..size_of::<InvokeDpeReqPrefix>()],
        )
        .map_err(|_| INVARIANT)?;
        prefix.data_size = U32::new(GET_CERT_CHAIN_DPE_PAYLOAD_LEN);
    }
    let mut cur = size_of::<InvokeDpeReqPrefix>();
    {
        let hdr = DpeCommandHdr::mut_from_bytes(&mut req[cur..cur + size_of::<DpeCommandHdr>()])
            .map_err(|_| INVARIANT)?;
        hdr.magic = U32::new(DPE_COMMAND_MAGIC);
        hdr.cmd_id = U32::new(DPE_CMD_GET_CERTIFICATE_CHAIN);
        hdr.profile = U32::new(DPE_PROFILE_P384_SHA384);
    }
    cur += size_of::<DpeCommandHdr>();
    {
        let cmd = GetCertChainCmd::mut_from_bytes(
            &mut req[cur..cur + size_of::<GetCertChainCmd>()],
        )
        .map_err(|_| INVARIANT)?;
        cmd.offset = U32::new(offset);
        cmd.size = U32::new(size);
    }
    let checksum = calc_checksum(CMD_INVOKE_DPE, &req);
    req[..4].copy_from_slice(&checksum.to_le_bytes());

    // Allocate response: outer prefix + DPE response hdr + cert_size
    // + chain bytes (up to DPE_MAX_CHUNK_SIZE).
    let rsp_max = size_of::<InvokeDpeRespPrefix>()
        + size_of::<DpeResponseHdr>()
        + 4
        + DPE_MAX_CHUNK_SIZE;
    let mut rsp = alloc.alloc(rsp_max)?;
    let mbox: Mailbox = Mailbox::new();
    let rsp_len = mbox
        .execute(CMD_INVOKE_DPE, &req, &mut rsp)
        .await
        .map_err(|_| INTERNAL_BUG)?;

    let outer_prefix_len = size_of::<InvokeDpeRespPrefix>();
    let dpe_hdr_off = outer_prefix_len;
    let cert_size_off = dpe_hdr_off + size_of::<DpeResponseHdr>();
    let chain_off = cert_size_off + 4;
    if rsp_len < chain_off {
        return Err(INTERNAL_BUG);
    }

    let dpe_hdr = DpeResponseHdr::ref_from_bytes(
        &rsp[dpe_hdr_off..dpe_hdr_off + size_of::<DpeResponseHdr>()],
    )
    .map_err(|_| INTERNAL_BUG)?;
    if dpe_hdr.magic.get() != DPE_RESPONSE_MAGIC || dpe_hdr.status.get() != 0 {
        return Err(INTERNAL_BUG);
    }

    let mut cert_size_buf = [0u8; 4];
    cert_size_buf.copy_from_slice(&rsp[cert_size_off..cert_size_off + 4]);
    let cert_size = u32::from_le_bytes(cert_size_buf) as usize;
    if cert_size > dst.len() || chain_off + cert_size > rsp_len {
        return Err(INTERNAL_BUG);
    }
    dst[..cert_size].copy_from_slice(&rsp[chain_off..chain_off + cert_size]);
    Ok(cert_size)
}

/// Invoke DPE `CertifyKey` (P-384 / SHA-384, X.509 format) for the
/// default context handle and the given 48-byte `label`. Writes the
/// emitted leaf certificate DER into `dst` and returns the number of
/// bytes actually written.
///
/// The DPE leaf-cert size limit is [`DPE_MAX_LEAF_CERT_SIZE`].
#[inline(never)]
pub async fn dpe_certify_key<A: ApiAlloc>(
    alloc: &A,
    label: &[u8; DPE_LABEL_LEN],
    dst: &mut [u8],
) -> McuResult<usize> {
    if dst.is_empty() || dst.len() > DPE_MAX_LEAF_CERT_SIZE {
        return Err(INVARIANT);
    }

    // Build request: prefix + DPE command header + CertifyKey body.
    let mut req = alloc.alloc(CERTIFY_KEY_REQ_LEN)?;
    req.fill(0);
    {
        let prefix = InvokeDpeReqPrefix::mut_from_bytes(
            &mut req[..size_of::<InvokeDpeReqPrefix>()],
        )
        .map_err(|_| INVARIANT)?;
        prefix.data_size = U32::new(CERTIFY_KEY_DPE_PAYLOAD_LEN);
    }
    let mut cur = size_of::<InvokeDpeReqPrefix>();
    {
        let hdr = DpeCommandHdr::mut_from_bytes(&mut req[cur..cur + size_of::<DpeCommandHdr>()])
            .map_err(|_| INVARIANT)?;
        hdr.magic = U32::new(DPE_COMMAND_MAGIC);
        hdr.cmd_id = U32::new(DPE_CMD_CERTIFY_KEY);
        hdr.profile = U32::new(DPE_PROFILE_P384_SHA384);
    }
    cur += size_of::<DpeCommandHdr>();
    {
        let cmd = CertifyKeyP384Cmd::mut_from_bytes(
            &mut req[cur..cur + size_of::<CertifyKeyP384Cmd>()],
        )
        .map_err(|_| INVARIANT)?;
        // handle: default context handle = all zeros, already filled by fill(0)
        cmd.flags = U32::new(0);
        cmd.format = U32::new(DPE_CERTIFY_KEY_FORMAT_X509);
        cmd.label.copy_from_slice(label);
    }
    let checksum = calc_checksum(CMD_INVOKE_DPE, &req);
    req[..4].copy_from_slice(&checksum.to_le_bytes());

    // Response prefix + cert bytes (cert ≤ DPE_MAX_LEAF_CERT_SIZE).
    let rsp_max = size_of::<InvokeDpeRespPrefix>()
        + size_of::<CertifyKeyP384RespPrefix>()
        + DPE_MAX_LEAF_CERT_SIZE;
    let mut rsp = alloc.alloc(rsp_max)?;
    let mbox: Mailbox = Mailbox::new();
    let rsp_len = mbox
        .execute(CMD_INVOKE_DPE, &req, &mut rsp)
        .await
        .map_err(|_| INTERNAL_BUG)?;

    let outer_prefix_len = size_of::<InvokeDpeRespPrefix>();
    let dpe_hdr_off = outer_prefix_len;
    let resp_body_off = dpe_hdr_off; // CertifyKeyP384Resp starts with ResponseHdr
    if rsp_len < resp_body_off + size_of::<CertifyKeyP384RespPrefix>() {
        return Err(INTERNAL_BUG);
    }

    let dpe_hdr = DpeResponseHdr::ref_from_bytes(
        &rsp[dpe_hdr_off..dpe_hdr_off + size_of::<DpeResponseHdr>()],
    )
    .map_err(|_| INTERNAL_BUG)?;
    if dpe_hdr.magic.get() != DPE_RESPONSE_MAGIC || dpe_hdr.status.get() != 0 {
        return Err(INTERNAL_BUG);
    }

    let resp_prefix = CertifyKeyP384RespPrefix::ref_from_bytes(
        &rsp[resp_body_off..resp_body_off + size_of::<CertifyKeyP384RespPrefix>()],
    )
    .map_err(|_| INTERNAL_BUG)?;
    let cert_size = resp_prefix.cert_size.get() as usize;
    let cert_off = resp_body_off + size_of::<CertifyKeyP384RespPrefix>();
    if cert_size > dst.len() || cert_off + cert_size > rsp_len {
        return Err(INTERNAL_BUG);
    }
    dst[..cert_size].copy_from_slice(&rsp[cert_off..cert_off + cert_size]);
    Ok(cert_size)
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
        let n = dpe_get_cert_chain_chunk(alloc, total, &mut buf[..]).await?;
        sink.on_chunk(&buf[..n]).await?;
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

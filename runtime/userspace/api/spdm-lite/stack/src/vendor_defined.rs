// Licensed under the Apache-2.0 license

//! VENDOR_DEFINED request dispatch for SPDM-Lite.

use mcu_spdm_lite_codec::{
    ReqRespCode, SpdmMsgHdrPdu, StandardsBodyId, VendorDefinedReqPdu, VendorDefinedRspPdu,
    WireReader, WireWriter,
};
use mcu_spdm_lite_traits::{PalBytes, SpdmPal, SpdmPalIo, SpdmPalIoKind, SpdmPalIoTransport};
use zerocopy::{little_endian::U16, FromBytes};

use crate::build::build_error_response;
use crate::chunk::{effective_data_transfer_size, effective_max_spdm_msg_size};
use crate::error::{
    SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_UNSPECIFIED,
    SPDM_UNSUPPORTED_REQUEST, SPDM_VERSION_MISMATCH,
};
use crate::stack::{ConnectionState, Phase};

/// Decoded VENDOR_DEFINED request context passed to a backend.
pub struct VdmRequest<'a> {
    /// Standards body registry value decoded from the SPDM envelope.
    pub standard_id: StandardsBodyId,
    /// Vendor ID bytes decoded from the SPDM envelope.
    pub vendor_id: &'a [u8],
    /// True when the transport delivered this request as a secured message.
    pub secure_session: bool,
    /// Vendor-defined payload, excluding the SPDM VENDOR_DEFINED envelope.
    pub payload: &'a [u8],
}

/// SPDM-Lite VDM extension hook for synchronous handlers.
///
/// This is the PR #1514 compatibility path. It intentionally stays
/// synchronous and object-safe; async Caliptra-backed VDM support should use
/// [`SpdmVdmBackend`] with static dispatch instead of `async_trait` or boxed
/// futures.
pub trait VdmHandler: Sync {
    fn match_id(
        &self,
        standard_id: StandardsBodyId,
        vendor_id: &[u8],
        secure_session: bool,
    ) -> bool;

    fn handle_request(&self, req: &[u8], rsp: &mut [u8]) -> SpdmResult<usize>;
}

/// Response payload buffers provided to a static-dispatch VDM backend.
///
/// `inline` is the normal one-message response payload area. `large`, when
/// present, is backed by PAL persistent large-message storage and can be used
/// for CHUNK_GET-served responses such as CSR data.
pub struct VdmResponseBuffers<'a> {
    /// Inline VDM response payload buffer.
    pub inline: &'a mut [u8],
    /// Optional large VDM response payload buffer.
    pub large: Option<&'a mut [u8]>,
}

/// VDM backend response location and payload length.
pub enum VdmResponseKind {
    /// Backend wrote this many bytes into [`VdmResponseBuffers::inline`].
    Inline(usize),
    /// Backend wrote this many bytes into [`VdmResponseBuffers::large`].
    Large(usize),
}

/// Static-dispatch VDM backend used by the spdm-lite dispatcher.
///
/// Implementations may perform async work without heap allocation because the
/// stack is generic over the backend type and the compiler builds one concrete
/// async state machine.
#[allow(async_fn_in_trait)]
pub trait SpdmVdmBackend: Sync {
    /// Returns true when this backend handles the decoded VDM request.
    fn match_request(&self, req: &VdmRequest<'_>) -> bool;

    /// Handles a matched VDM request and writes only the VDM response payload.
    async fn handle_request(
        &self,
        req: VdmRequest<'_>,
        rsp: VdmResponseBuffers<'_>,
    ) -> SpdmResult<VdmResponseKind>;
}

/// Sync-handler-table backend preserving `with_vdm_handlers` behavior.
#[derive(Clone, Copy)]
pub struct SyncVdmHandlers {
    handlers: &'static [&'static dyn VdmHandler],
}

impl SyncVdmHandlers {
    /// Creates a backend from a static table of synchronous handlers.
    pub const fn new(handlers: &'static [&'static dyn VdmHandler]) -> Self {
        Self { handlers }
    }
}

impl SpdmVdmBackend for SyncVdmHandlers {
    fn match_request(&self, req: &VdmRequest<'_>) -> bool {
        self.handlers
            .iter()
            .copied()
            .any(|handler| handler.match_id(req.standard_id, req.vendor_id, req.secure_session))
    }

    async fn handle_request(
        &self,
        req: VdmRequest<'_>,
        rsp: VdmResponseBuffers<'_>,
    ) -> SpdmResult<VdmResponseKind> {
        let Some(handler) =
            self.handlers.iter().copied().find(|handler| {
                handler.match_id(req.standard_id, req.vendor_id, req.secure_session)
            })
        else {
            return Err(SPDM_UNSUPPORTED_REQUEST);
        };
        handler
            .handle_request(req.payload, rsp.inline)
            .map(VdmResponseKind::Inline)
    }
}

pub(crate) async fn handle_vendor_defined_request<'a, Pal, Vdm>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    backend: &Vdm,
) -> SpdmResult<PalBytes<'a, Pal>>
where
    Pal: SpdmPal,
    Vdm: SpdmVdmBackend,
{
    if io.request().len() > pal.mtu() {
        return Err(SPDM_INVALID_REQUEST);
    }

    let vdm_req = match decode_vendor_defined_request::<Pal, Vdm>(state, io, io.request(), backend)
    {
        Ok(req) => req,
        Err(e) if e == SPDM_UNSUPPORTED_REQUEST => {
            return unsupported_request(pal, io, state.version)
        }
        Err(e) => return Err(e),
    };
    build_vendor_defined_response(state, pal, io, vdm_req, backend).await
}

pub(crate) async fn handle_large_vendor_defined_request<Pal, Vdm>(
    state: &ConnectionState<Pal::State>,
    io: &impl SpdmPalIo,
    req: &[u8],
    backend: &Vdm,
    out: &mut [u8],
) -> SpdmResult<usize>
where
    Pal: SpdmPal,
    Vdm: SpdmVdmBackend,
{
    let vdm_req = decode_vendor_defined_request::<Pal, Vdm>(state, io, req, backend)?;
    build_vendor_defined_response_into(state, vdm_req, backend, out).await
}

fn decode_vendor_defined_request<'a, Pal, Vdm>(
    state: &ConnectionState<Pal::State>,
    io: &impl SpdmPalIo,
    req: &'a [u8],
    backend: &Vdm,
) -> SpdmResult<VdmRequest<'a>>
where
    Pal: SpdmPal,
    Vdm: SpdmVdmBackend,
{
    if (state.phase as u8) < (Phase::AfterAlgorithms as u8) {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(SPDM_VERSION_MISMATCH);
    }

    let mut reader = WireReader::new(body);
    let req_pdu = reader.read::<VendorDefinedReqPdu>()?;
    let standard_id =
        StandardsBodyId::from_u16(req_pdu.standard_id.get()).ok_or(SPDM_INVALID_REQUEST)?;
    let Some(expected_vendor_id_len) = standard_id.vendor_id_len() else {
        return Err(SPDM_UNSUPPORTED_REQUEST);
    };
    if req_pdu.vendor_id_len != expected_vendor_id_len {
        return Err(SPDM_INVALID_REQUEST);
    }

    let vendor_id = reader.take(req_pdu.vendor_id_len as usize)?;
    let req_len = reader.read::<U16>()?.get() as usize;
    let vdm_payload = reader.take(req_len)?;
    if !reader.is_empty() {
        return Err(SPDM_INVALID_REQUEST);
    }

    let vdm_req = VdmRequest {
        standard_id,
        vendor_id,
        secure_session: io.kind() == SpdmPalIoKind::SecuredMessage,
        payload: vdm_payload,
    };
    if !backend.match_request(&vdm_req) {
        return Err(SPDM_UNSUPPORTED_REQUEST);
    }
    Ok(vdm_req)
}

fn unsupported_request<'a, Pal: SpdmPal>(
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    version: mcu_spdm_lite_codec::SpdmVersion,
) -> SpdmResult<PalBytes<'a, Pal>> {
    build_error_response(
        pal,
        io,
        version,
        SPDM_UNSUPPORTED_REQUEST.spec_byte(),
        ReqRespCode::VENDOR_DEFINED_REQUEST.0,
        &[],
    )
}

async fn build_vendor_defined_response<'a, Pal, Vdm>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    req: VdmRequest<'_>,
    backend: &Vdm,
) -> SpdmResult<PalBytes<'a, Pal>>
where
    Pal: SpdmPal,
    Vdm: SpdmVdmBackend,
{
    let vendor_id_len = req.vendor_id.len();
    let fixed_len = SpdmMsgHdrPdu::SIZE
        + VendorDefinedRspPdu::SIZE
        + vendor_id_len
        + core::mem::size_of::<U16>();
    let max_rsp_len = effective_data_transfer_size(state, pal)
        .checked_sub(fixed_len)
        .ok_or(SPDM_UNSPECIFIED)?;
    if max_rsp_len > u16::MAX as usize {
        return Err(SPDM_UNSPECIFIED);
    }

    let head = pal.header_size();
    let mut rsp = alloc_padded(pal, io, head + fixed_len + max_rsp_len)?;
    let payload_len_pos = payload_len_offset(vendor_id_len);
    let payload_len_offset = head + payload_len_pos;
    let payload_offset = payload_len_offset + core::mem::size_of::<U16>();

    encode_vendor_defined_response_prefix(
        &mut rsp[head..head + fixed_len],
        state.version,
        req.standard_id,
        req.vendor_id,
    )?;

    let large_capacity = pal.capacity();
    let large_total_len = if large_capacity >= fixed_len {
        // SAFETY: the SPDM-lite responder is single-tasked for this PAL, and
        // this mutable borrow is scoped to building one VDM response. No other
        // PAL operation accesses the persistent large-message buffer until this
        // borrow is no longer used.
        let large_rsp = unsafe { pal.large_message_mut(large_capacity)? };
        encode_vendor_defined_response_prefix(
            large_rsp,
            state.version,
            req.standard_id,
            req.vendor_id,
        )?;
        let large_payload = &mut large_rsp[fixed_len..];
        let response = backend
            .handle_request(
                req,
                VdmResponseBuffers {
                    inline: &mut rsp[payload_offset..payload_offset + max_rsp_len],
                    large: Some(large_payload),
                },
            )
            .await?;
        match response {
            VdmResponseKind::Inline(rsp_len) => {
                finish_inline_response::<Pal>(
                    &mut rsp,
                    head,
                    fixed_len,
                    pal,
                    payload_len_offset,
                    max_rsp_len,
                    rsp_len,
                )?;
                return Ok(rsp);
            }
            VdmResponseKind::Large(rsp_len) => {
                if rsp_len > large_capacity - fixed_len || rsp_len > u16::MAX as usize {
                    return Err(SPDM_UNSPECIFIED);
                }
                large_rsp[payload_len_pos..payload_len_pos + core::mem::size_of::<U16>()]
                    .copy_from_slice(&(rsp_len as u16).to_le_bytes());
                fixed_len + rsp_len
            }
        }
    } else {
        let response = backend
            .handle_request(
                req,
                VdmResponseBuffers {
                    inline: &mut rsp[payload_offset..payload_offset + max_rsp_len],
                    large: None,
                },
            )
            .await?;
        match response {
            VdmResponseKind::Inline(rsp_len) => {
                finish_inline_response::<Pal>(
                    &mut rsp,
                    head,
                    fixed_len,
                    pal,
                    payload_len_offset,
                    max_rsp_len,
                    rsp_len,
                )?;
                return Ok(rsp);
            }
            VdmResponseKind::Large(_) => return Err(SPDM_UNSPECIFIED),
        }
    };

    if large_total_len <= fixed_len + max_rsp_len {
        pal.read(0, &mut rsp[head..head + large_total_len])?;
        shrink_padded(pal, &mut rsp, head + large_total_len)?;
        return Ok(rsp);
    }

    if !state.chunking_enabled() || large_total_len > effective_max_spdm_msg_size(state, pal) {
        return Err(SPDM_UNSPECIFIED);
    }
    crate::chunk::start_buffered_large_response(state, pal, io, large_total_len)
}

async fn build_vendor_defined_response_into<Vdm>(
    state: &ConnectionState<impl Clone>,
    req: VdmRequest<'_>,
    backend: &Vdm,
    out: &mut [u8],
) -> SpdmResult<usize>
where
    Vdm: SpdmVdmBackend,
{
    let vendor_id_len = req.vendor_id.len();
    let fixed_len = SpdmMsgHdrPdu::SIZE
        + VendorDefinedRspPdu::SIZE
        + vendor_id_len
        + core::mem::size_of::<U16>();
    let max_rsp_len = out.len().checked_sub(fixed_len).ok_or(SPDM_UNSPECIFIED)?;
    if max_rsp_len > u16::MAX as usize {
        return Err(SPDM_UNSPECIFIED);
    }

    let payload_len_pos = payload_len_offset(vendor_id_len);
    let payload_offset = payload_len_pos + core::mem::size_of::<U16>();
    encode_vendor_defined_response_prefix(
        &mut out[..fixed_len],
        state.version,
        req.standard_id,
        req.vendor_id,
    )?;

    let response = backend
        .handle_request(
            req,
            VdmResponseBuffers {
                inline: &mut out[payload_offset..payload_offset + max_rsp_len],
                large: None,
            },
        )
        .await?;
    let VdmResponseKind::Inline(rsp_len) = response else {
        return Err(SPDM_UNSPECIFIED);
    };
    if rsp_len > max_rsp_len || rsp_len > u16::MAX as usize {
        return Err(SPDM_UNSPECIFIED);
    }
    out[payload_len_pos..payload_len_pos + core::mem::size_of::<U16>()]
        .copy_from_slice(&(rsp_len as u16).to_le_bytes());
    Ok(fixed_len + rsp_len)
}

#[inline]
fn payload_len_offset(vendor_id_len: usize) -> usize {
    SpdmMsgHdrPdu::SIZE + VendorDefinedRspPdu::SIZE + vendor_id_len
}

fn encode_vendor_defined_response_prefix(
    buf: &mut [u8],
    version: mcu_spdm_lite_codec::SpdmVersion,
    standard_id: StandardsBodyId,
    vendor_id: &[u8],
) -> SpdmResult<()> {
    let fixed_len = payload_len_offset(vendor_id.len()) + core::mem::size_of::<U16>();
    let mut writer = WireWriter::new(buf.get_mut(..fixed_len).ok_or(SPDM_UNSPECIFIED)?);
    writer.write(&SpdmMsgHdrPdu::new(
        version,
        ReqRespCode::VENDOR_DEFINED_RESPONSE,
    ))?;
    writer.write(&VendorDefinedRspPdu {
        param1: 0,
        param2: 0,
        standard_id: U16::new(standard_id.as_u16()),
        vendor_id_len: vendor_id.len() as u8,
    })?;
    writer.write_bytes(vendor_id)?;
    writer.write(&U16::new(0))?;
    Ok(())
}

fn finish_inline_response<Pal: SpdmPal>(
    rsp: &mut PalBytes<'_, Pal>,
    head: usize,
    fixed_len: usize,
    pal: &Pal,
    payload_len_offset: usize,
    max_rsp_len: usize,
    rsp_len: usize,
) -> SpdmResult<()> {
    if rsp_len > max_rsp_len || rsp_len > u16::MAX as usize {
        return Err(SPDM_UNSPECIFIED);
    }
    rsp[payload_len_offset..payload_len_offset + core::mem::size_of::<U16>()]
        .copy_from_slice(&(rsp_len as u16).to_le_bytes());
    shrink_padded(pal, rsp, head + fixed_len + rsp_len)?;
    Ok(())
}

fn padded_len<Pal: SpdmPal>(pal: &Pal, raw_len: usize) -> SpdmResult<usize> {
    let align = pal.send_len_alignment();
    debug_assert!(align > 0 && align.is_power_of_two());
    raw_len
        .checked_add(align - 1)
        .map(|len| len & !(align - 1))
        .ok_or(SPDM_UNSPECIFIED)
}

fn alloc_padded<'a, Pal: SpdmPal>(
    pal: &'a Pal,
    io: &Pal::Io<'_>,
    raw_len: usize,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let alloc_len = padded_len(pal, raw_len)?;
    let mut buf = pal.alloc_bytes(io, alloc_len)?;
    for b in &mut buf[raw_len..alloc_len] {
        *b = 0;
    }
    Ok(buf)
}

fn shrink_padded<Pal: SpdmPal>(
    pal: &Pal,
    rsp: &mut PalBytes<'_, Pal>,
    raw_len: usize,
) -> SpdmResult<()> {
    let shrink_len = padded_len(pal, raw_len)?;
    for b in &mut rsp[raw_len..shrink_len] {
        *b = 0;
    }
    Pal::shrink_bytes(rsp, shrink_len)?;
    Ok(())
}

// Licensed under the Apache-2.0 license

//! CHUNK_SEND large-request reassembly.

use mcu_spdm_lite_codec::{
    CapabilitiesBody, ChunkSendAckBody, ChunkSendReqBody, ReqRespCode, SpdmMsgHdrPdu, SpdmVersion,
    WireWriter, CHUNK_ACK_ATTR_EARLY_ERROR, CHUNK_ATTR_LAST_CHUNK,
};
use mcu_spdm_lite_traits::{
    PalBytes, SpdmPal, SpdmPalAlloc, SpdmPalIoTransport, SpdmVdmBackend, VdmRegistry,
};
use zerocopy::{little_endian::U16, FromBytes};

use super::WipeOnDrop;
use crate::build::alloc_padded;
use crate::error::*;
#[cfg(feature = "set-certificate")]
use crate::set_certificate;
use crate::stack::{ConnectionState, Phase};
use crate::vendor_defined;

struct ChunkInfo {
    handle: u8,
    chunk_seq_num: u16,
    complete: bool,
}

#[derive(Copy, Clone)]
struct ChunkMeta {
    handle: u8,
    chunk_seq_num: u16,
    chunk_size: usize,
    last_chunk: bool,
}

enum ChunkSendAction<'a> {
    Buffered(ChunkInfo),
    StreamBegin {
        info: ChunkInfo,
        stream_len: usize,
        first_payload: &'a [u8],
    },
    StreamChunk {
        info: ChunkInfo,
        payload: &'a [u8],
    },
}

pub(crate) async fn handle_chunk_send<'a, Pal: SpdmPal, Vdm: SpdmVdmBackend>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    vdm: &Vdm,
    req: &[u8],
    secure_session: bool,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let result = process_chunk_send(state, pal, vdm, req, secure_session);
    match result {
        Ok(ChunkSendAction::Buffered(info)) => {
            if info.complete {
                let rsp = build_final_chunk_send_ack(
                    state,
                    pal,
                    io,
                    vdm,
                    secure_session,
                    info.handle,
                    info.chunk_seq_num,
                )
                .await;
                if state.large_msg_ctx.request_in_progress() {
                    state.reset_chunk_assembly();
                }
                rsp
            } else {
                build_chunk_send_ack(
                    pal,
                    io,
                    state.version,
                    false,
                    info.handle,
                    info.chunk_seq_num,
                    &[],
                )
            }
        }
        Ok(ChunkSendAction::StreamBegin {
            info,
            stream_len,
            first_payload,
        }) => {
            if vdm
                .stream_large_request_begin(stream_len, first_payload, pal, io)
                .await
                .is_err()
            {
                state.reset_chunk_assembly();
                return build_early_error_ack(state, pal, io, info.handle, info.chunk_seq_num);
            }
            build_chunk_send_ack(
                pal,
                io,
                state.version,
                false,
                info.handle,
                info.chunk_seq_num,
                &[],
            )
        }
        Ok(ChunkSendAction::StreamChunk { info, payload }) => {
            if vdm
                .stream_large_request_chunk(payload, pal, io)
                .await
                .is_err()
            {
                state.reset_chunk_assembly();
                return build_early_error_ack(state, pal, io, info.handle, info.chunk_seq_num);
            }
            if info.complete {
                let rsp = build_final_chunk_send_ack(
                    state,
                    pal,
                    io,
                    vdm,
                    secure_session,
                    info.handle,
                    info.chunk_seq_num,
                )
                .await;
                if state.large_msg_ctx.request_in_progress() {
                    state.reset_chunk_assembly();
                }
                rsp
            } else {
                build_chunk_send_ack(
                    pal,
                    io,
                    state.version,
                    false,
                    info.handle,
                    info.chunk_seq_num,
                    &[],
                )
            }
        }
        Err(ChunkProcessError::Spdm(e)) => Err(e),
        Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        }) => build_early_error_ack(state, pal, io, handle, chunk_seq_num),
    }
}

fn build_early_error_ack<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    handle: u8,
    chunk_seq_num: u16,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let mut error = [0u8; 4];
    encode_error_pdu(state.version, SPDM_INVALID_REQUEST, &mut error);
    state.reset_chunk_assembly();
    build_chunk_send_ack(pal, io, state.version, true, handle, chunk_seq_num, &error)
}

fn build_chunk_send_ack<'a, Pal: SpdmPal>(
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    version: SpdmVersion,
    early_error: bool,
    handle: u8,
    chunk_seq_num: u16,
    response_to_large_request: &[u8],
) -> SpdmResult<PalBytes<'a, Pal>> {
    let head = pal.header_size();
    let raw_len =
        head + SpdmMsgHdrPdu::SIZE + ChunkSendAckBody::SIZE + response_to_large_request.len();
    let mut rsp = alloc_padded(pal, io, raw_len)?;
    let mut w = WireWriter::new(&mut rsp[head..]);
    w.write(&SpdmMsgHdrPdu::new(version, ReqRespCode::CHUNK_SEND_ACK))?;
    w.write(&ChunkSendAckBody {
        chunk_receiver_attr: if early_error {
            CHUNK_ACK_ATTR_EARLY_ERROR
        } else {
            0
        },
        handle,
        chunk_seq_num: U16::new(chunk_seq_num),
    })?;
    w.write_bytes(response_to_large_request)?;
    Ok(rsp)
}

/// Maximum bytes carried as `ResponseToLargeRequest` inside CHUNK_SEND_ACK.
const LARGE_REQUEST_RESPONSE_BUF_SIZE: usize = 512;

enum ChunkProcessError {
    Spdm(SpdmError),
    Early { handle: u8, chunk_seq_num: u16 },
}

fn process_chunk_send<'req, Pal: SpdmPal, Vdm: SpdmVdmBackend>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &Pal,
    vdm: &Vdm,
    req: &'req [u8],
    secure_session: bool,
) -> Result<ChunkSendAction<'req>, ChunkProcessError> {
    if state.large_msg_ctx.response_in_progress()
        || (state.phase as u8) < (Phase::AfterCapabilities as u8)
        || !state.chunking_enabled()
    {
        return Err(ChunkProcessError::Spdm(SPDM_UNEXPECTED_REQUEST));
    }

    // Ensure the incoming request message fits our standard effective bounds, not raw MTU.
    if req.len() > state.effective_data_transfer_size(pal) {
        return Err(ChunkProcessError::Spdm(SPDM_INVALID_REQUEST));
    }

    let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(req)
        .map_err(|_| ChunkProcessError::Spdm(SPDM_INVALID_REQUEST))?;
    if hdr.version != state.version.to_u8() {
        return Err(ChunkProcessError::Spdm(SPDM_VERSION_MISMATCH));
    }

    let (chunk_req, rest) = ChunkSendReqBody::ref_from_prefix(body)
        .map_err(|_| ChunkProcessError::Spdm(SPDM_INVALID_REQUEST))?;
    let meta = ChunkMeta {
        handle: chunk_req.handle,
        chunk_seq_num: chunk_req.chunk_seq_num.get(),
        chunk_size: chunk_req.chunk_size.get() as usize,
        last_chunk: (chunk_req.chunk_sender_attr & CHUNK_ATTR_LAST_CHUNK) != 0,
    };
    if chunk_req.reserved.get() != 0 || (chunk_req.chunk_sender_attr & !CHUNK_ATTR_LAST_CHUNK) != 0
    {
        return Err(ChunkProcessError::Early {
            handle: meta.handle,
            chunk_seq_num: meta.chunk_seq_num,
        });
    }

    if !state.large_msg_ctx.request_in_progress() {
        if let Some(action) = process_first_chunk(state, pal, vdm, meta, rest, secure_session)? {
            return Ok(action);
        }
    } else if state
        .large_msg_ctx
        .request()
        .and_then(|request| request.vdm_stream_kind())
        .is_some()
    {
        let payload = process_next_stream_chunk(state, meta, rest)?;
        let info = chunk_info(state, meta);
        return Ok(ChunkSendAction::StreamChunk { info, payload });
    } else {
        process_next_chunk(state, pal, meta, rest)?;
    }

    Ok(ChunkSendAction::Buffered(chunk_info(state, meta)))
}

fn chunk_info<S, L>(state: &ConnectionState<S, L>, meta: ChunkMeta) -> ChunkInfo
where
    L: core::ops::DerefMut<Target = [u8]>,
{
    ChunkInfo {
        handle: meta.handle,
        chunk_seq_num: meta.chunk_seq_num,
        complete: state
            .large_msg_ctx
            .request()
            .is_some_and(|request| request.bytes_received == request.request_size),
    }
}

fn first_chunk(meta: ChunkMeta, rest: &[u8]) -> Result<(usize, &[u8]), ChunkProcessError> {
    let Some(size_bytes) = rest.first_chunk::<4>() else {
        return Err(ChunkProcessError::Early {
            handle: meta.handle,
            chunk_seq_num: meta.chunk_seq_num,
        });
    };
    let large_msg_size = u32::from_le_bytes(*size_bytes) as usize;
    let chunk_data = &rest[4..];

    // Require exact chunk body length match inside rest payload (no trailing junk bytes).
    if chunk_data.len() != meta.chunk_size {
        return Err(ChunkProcessError::Early {
            handle: meta.handle,
            chunk_seq_num: meta.chunk_seq_num,
        });
    }
    let Some(chunk) = chunk_data.get(..meta.chunk_size) else {
        return Err(ChunkProcessError::Early {
            handle: meta.handle,
            chunk_seq_num: meta.chunk_seq_num,
        });
    };
    Ok((large_msg_size, chunk))
}

fn validate_first_chunk(
    meta: ChunkMeta,
    large_msg_size: usize,
    allow_oversized_for_streaming: bool,
    pal_large_capacity: usize,
) -> Result<(), ChunkProcessError> {
    let min_chunk_size = CapabilitiesBody::MIN_DATA_TRANSFER_SIZE as usize
        - SpdmMsgHdrPdu::SIZE
        - ChunkSendReqBody::SIZE
        - 4;

    let invalid = meta.chunk_seq_num != 0
        || meta.last_chunk
        || meta.chunk_size < min_chunk_size
        || meta.chunk_size >= large_msg_size
        || large_msg_size <= CapabilitiesBody::MIN_DATA_TRANSFER_SIZE as usize
        || (!allow_oversized_for_streaming && large_msg_size > pal_large_capacity);
    if invalid {
        return Err(ChunkProcessError::Early {
            handle: meta.handle,
            chunk_seq_num: meta.chunk_seq_num,
        });
    }
    Ok(())
}

fn process_first_chunk<'req, Pal: SpdmPal, Vdm: SpdmVdmBackend>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &Pal,
    vdm: &Vdm,
    meta: ChunkMeta,
    rest: &'req [u8],
    secure_session: bool,
) -> Result<Option<ChunkSendAction<'req>>, ChunkProcessError> {
    let (large_msg_size, chunk) = first_chunk(meta, rest)?;
    let stream = detect_vdm_stream(
        state,
        vdm,
        large_msg_size,
        chunk,
        secure_session,
        meta.handle,
        meta.chunk_seq_num,
    )?;
    validate_first_chunk(meta, large_msg_size, stream.is_some(), pal.large_capacity())?;
    if let Some(stream) = stream {
        if state
            .large_msg_ctx
            .init_vdm_stream_request(meta.handle, large_msg_size, chunk.len(), stream.active)
            .is_err()
        {
            return Err(ChunkProcessError::Early {
                handle: meta.handle,
                chunk_seq_num: meta.chunk_seq_num,
            });
        }
        return Ok(Some(ChunkSendAction::StreamBegin {
            info: chunk_info(state, meta),
            stream_len: stream.stream_len,
            first_payload: stream.first_payload,
        }));
    }
    let rent_buf = match pal.alloc_large_buf(large_msg_size) {
        Ok(buf) => buf,
        Err(_) => {
            return Err(ChunkProcessError::Early {
                handle: meta.handle,
                chunk_seq_num: meta.chunk_seq_num,
            })
        }
    };
    if state
        .large_msg_ctx
        .init_request(meta.handle, large_msg_size, chunk, rent_buf)
        .is_err()
    {
        return Err(ChunkProcessError::Early {
            handle: meta.handle,
            chunk_seq_num: meta.chunk_seq_num,
        });
    }
    Ok(None)
}

struct StreamStart<'a> {
    active: super::ActiveVdmLargeRequestStream,
    stream_len: usize,
    first_payload: &'a [u8],
}

fn detect_vdm_stream<'a, Vdm: SpdmVdmBackend, S, L>(
    state: &ConnectionState<S, L>,
    vdm: &Vdm,
    large_msg_size: usize,
    chunk: &'a [u8],
    secure_session: bool,
    handle: u8,
    chunk_seq_num: u16,
) -> Result<Option<StreamStart<'a>>, ChunkProcessError> {
    if !Vdm::USES_LARGE_REQUEST_STREAM {
        return Ok(None);
    }
    let Ok((hdr, body)) = SpdmMsgHdrPdu::ref_from_prefix(chunk) else {
        return Ok(None);
    };
    if hdr.version != state.version.to_u8() {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    }
    if hdr.code != ReqRespCode::VENDOR_DEFINED_REQUEST {
        return Ok(None);
    }
    if body.len() < 7 {
        return Ok(None);
    }
    let standard_id = u16::from_le_bytes([body[2], body[3]]);
    let vendor_id_len = body[4] as usize;
    let vendor_id_start = 5;
    let vendor_id_end = vendor_id_start + vendor_id_len;
    let req_len_end = vendor_id_end + 2;
    let Some(vendor_id) = body.get(vendor_id_start..vendor_id_end) else {
        return Ok(None);
    };
    let Some(req_len_bytes) = body.get(vendor_id_end..req_len_end) else {
        return Ok(None);
    };
    let req_payload_len = u16::from_le_bytes([req_len_bytes[0], req_len_bytes[1]]) as usize;
    let payload_offset = SpdmMsgHdrPdu::SIZE + req_len_end;
    if large_msg_size != payload_offset + req_payload_len {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    }
    let registry = VdmRegistry {
        standard_id,
        vendor_id,
        secure_session,
    };
    if !vdm.match_id(&registry) {
        return Ok(None);
    }
    let payload_prefix = &body[req_len_end.min(body.len())..];
    let Some(info) = vdm.large_request_stream_info(payload_prefix, req_payload_len) else {
        return Ok(None);
    };
    if info.stream_offset > req_payload_len
        || info.stream_offset > payload_prefix.len()
        || info.stream_offset.saturating_add(info.stream_len) != req_payload_len
    {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    }
    let active = super::ActiveVdmLargeRequestStream::new(standard_id, vendor_id).map_err(|_| {
        ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        }
    })?;
    Ok(Some(StreamStart {
        active,
        stream_len: info.stream_len,
        first_payload: &payload_prefix[info.stream_offset..],
    }))
}

fn process_next_chunk<Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    _pal: &Pal,
    meta: ChunkMeta,
    rest: &[u8],
) -> Result<(), ChunkProcessError> {
    let active = state
        .large_msg_ctx
        .request()
        .ok_or(ChunkProcessError::Early {
            handle: meta.handle,
            chunk_seq_num: meta.chunk_seq_num,
        })?;
    let bytes_received = active.bytes_received;
    let large_msg_size = active.request_size;
    let end = bytes_received.saturating_add(meta.chunk_size);

    // Require exact chunk body length match inside rest payload (no trailing junk bytes).
    if rest.len() != meta.chunk_size {
        return Err(ChunkProcessError::Early {
            handle: meta.handle,
            chunk_seq_num: meta.chunk_seq_num,
        });
    }
    let Some(chunk) = rest.get(..meta.chunk_size) else {
        return Err(ChunkProcessError::Early {
            handle: meta.handle,
            chunk_seq_num: meta.chunk_seq_num,
        });
    };
    let min_chunk_size = CapabilitiesBody::MIN_DATA_TRANSFER_SIZE as usize
        - SpdmMsgHdrPdu::SIZE
        - ChunkSendReqBody::SIZE;
    let invalid = meta.chunk_seq_num == 0
        || active.handle != meta.handle
        || active.next_seq_num != meta.chunk_seq_num
        || end > large_msg_size
        || (meta.last_chunk && end != large_msg_size)
        || (!meta.last_chunk && (end >= large_msg_size || meta.chunk_size < min_chunk_size));
    if invalid {
        return Err(ChunkProcessError::Early {
            handle: meta.handle,
            chunk_seq_num: meta.chunk_seq_num,
        });
    }
    if state
        .large_msg_ctx
        .append_request(meta.handle, meta.chunk_seq_num, chunk)
        .is_err()
    {
        return Err(ChunkProcessError::Early {
            handle: meta.handle,
            chunk_seq_num: meta.chunk_seq_num,
        });
    }

    Ok(())
}

fn process_next_stream_chunk<'a, S, L>(
    state: &mut ConnectionState<S, L>,
    meta: ChunkMeta,
    rest: &'a [u8],
) -> Result<&'a [u8], ChunkProcessError>
where
    L: core::ops::DerefMut<Target = [u8]>,
{
    let active = state
        .large_msg_ctx
        .request()
        .ok_or(ChunkProcessError::Early {
            handle: meta.handle,
            chunk_seq_num: meta.chunk_seq_num,
        })?;
    let bytes_received = active.bytes_received;
    let large_msg_size = active.request_size;
    let end = bytes_received.saturating_add(meta.chunk_size);
    let min_chunk_size = CapabilitiesBody::MIN_DATA_TRANSFER_SIZE as usize
        - SpdmMsgHdrPdu::SIZE
        - ChunkSendReqBody::SIZE;
    let invalid = meta.chunk_seq_num == 0
        || active.handle != meta.handle
        || active.next_seq_num != meta.chunk_seq_num
        || rest.len() != meta.chunk_size
        || end > large_msg_size
        || (meta.last_chunk && end != large_msg_size)
        || (!meta.last_chunk && (end >= large_msg_size || meta.chunk_size < min_chunk_size));
    if invalid {
        return Err(ChunkProcessError::Early {
            handle: meta.handle,
            chunk_seq_num: meta.chunk_seq_num,
        });
    }
    state
        .large_msg_ctx
        .append_stream_request(meta.handle, meta.chunk_seq_num, meta.chunk_size)
        .map_err(|_| ChunkProcessError::Early {
            handle: meta.handle,
            chunk_seq_num: meta.chunk_seq_num,
        })?;
    Ok(rest)
}

struct LargeRequestError {
    spdm: SpdmError,
    early_error: bool,
}

impl From<SpdmError> for LargeRequestError {
    fn from(spdm: SpdmError) -> Self {
        Self {
            spdm,
            early_error: false,
        }
    }
}

impl From<mcu_error::McuErrorCode> for LargeRequestError {
    fn from(err: mcu_error::McuErrorCode) -> Self {
        SpdmError::from(err).into()
    }
}

async fn build_final_chunk_send_ack<'a, Pal: SpdmPal, Vdm: SpdmVdmBackend>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    vdm: &Vdm,
    secure_session: bool,
    handle: u8,
    chunk_seq_num: u16,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let request = *state.large_msg_ctx.request().ok_or(SPDM_INVALID_REQUEST)?;
    let len = request.request_size;
    let mut response_to_large_request = [0u8; LARGE_REQUEST_RESPONSE_BUF_SIZE];
    let (mut response_len, early_error) = if let Some(stream) = request.vdm_stream_kind() {
        match finish_streamed_vdm_large_request(
            state,
            pal,
            io,
            vdm,
            stream,
            &mut response_to_large_request,
        )
        .await
        {
            Ok(response_len) => (response_len, false),
            Err(err) => (
                write_error_response_to_large_request(
                    &mut response_to_large_request,
                    state.version,
                    err.spdm,
                ),
                err.early_error,
            ),
        }
    } else if len < SpdmMsgHdrPdu::SIZE {
        (
            write_error_response_to_large_request(
                &mut response_to_large_request,
                state.version,
                SPDM_INVALID_REQUEST,
            ),
            false,
        )
    } else {
        match dispatch_large_request(
            state,
            pal,
            io,
            vdm,
            len,
            secure_session,
            &mut response_to_large_request,
        )
        .await
        {
            Ok(response_len) => (response_len, false),
            Err(err) => (
                write_error_response_to_large_request(
                    &mut response_to_large_request,
                    state.version,
                    err.spdm,
                ),
                err.early_error,
            ),
        }
    };

    let max_response_len = state
        .effective_data_transfer_size(pal)
        .saturating_sub(SpdmMsgHdrPdu::SIZE + ChunkSendAckBody::SIZE);
    if response_len > max_response_len {
        response_len = write_error_response_to_large_request(
            &mut response_to_large_request,
            state.version,
            SPDM_LARGE_RESPONSE,
        );
    }

    build_chunk_send_ack(
        pal,
        io,
        state.version,
        early_error,
        handle,
        chunk_seq_num,
        &response_to_large_request[..response_len],
    )
}

async fn finish_streamed_vdm_large_request<Pal: SpdmPal, Vdm: SpdmVdmBackend>(
    state: &ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    vdm: &Vdm,
    stream: super::ActiveVdmLargeRequestStream,
    out: &mut [u8],
) -> Result<usize, LargeRequestError> {
    let envelope_len = SpdmMsgHdrPdu::SIZE + 2 + 2 + 1 + stream.vendor_id().len() + 2;
    if envelope_len > out.len() {
        return Err(SPDM_UNSPECIFIED.into());
    }
    let payload_len = vdm
        .stream_large_request_finish(&mut out[envelope_len..], pal, io)
        .await?;
    if envelope_len + payload_len > out.len() {
        return Err(SPDM_UNSPECIFIED.into());
    }
    vendor_defined::write_vendor_defined_envelope(
        state.version,
        stream.standard_id,
        stream.vendor_id(),
        payload_len,
        &mut out[..envelope_len],
    )?;
    Ok(envelope_len + payload_len)
}

async fn dispatch_large_request<Pal: SpdmPal, Vdm: SpdmVdmBackend>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    vdm: &Vdm,
    len: usize,
    secure_session: bool,
    out: &mut [u8],
) -> Result<usize, LargeRequestError> {
    // Detach the buffer, but immediately place it in an auto-wiping RAII guard.
    let mut guard = WipeOnDrop {
        buf: state.large_msg_ctx.take_buffer(),
    };
    let large_buf = guard.buf.as_mut().ok_or(SPDM_INVALID_REQUEST)?;
    let buf = large_buf.as_mut();
    let large_req = buf.get(..len).ok_or(SPDM_INVALID_REQUEST)?;
    let (hdr, _) = SpdmMsgHdrPdu::ref_from_prefix(large_req).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(SPDM_INVALID_REQUEST.into());
    }
    if hdr.code == ReqRespCode::CHUNK_SEND || hdr.code == ReqRespCode::CHUNK_GET {
        return Err(LargeRequestError {
            spdm: SPDM_INVALID_REQUEST,
            early_error: true,
        });
    }

    match hdr.code {
        #[cfg(feature = "set-certificate")]
        ReqRespCode::SET_CERTIFICATE => {
            if secure_session {
                return Err(SPDM_UNSUPPORTED_REQUEST.into());
            }
            let slot_id =
                set_certificate::handle_set_certificate_request(state, pal, io, large_req).await?;
            let bytes = [
                state.version.to_u8(),
                ReqRespCode::SET_CERTIFICATE_RSP.0,
                slot_id,
                0,
            ];
            out.get_mut(..bytes.len())
                .ok_or(SPDM_UNSPECIFIED)?
                .copy_from_slice(&bytes);
            Ok(bytes.len())
        }
        ReqRespCode::VENDOR_DEFINED_REQUEST => vendor_defined::handle_large_vendor_defined_request(
            vdm,
            state,
            pal,
            io,
            large_req,
            secure_session,
            out,
        )
        .await
        .map_err(Into::into),
        _ => Err(SPDM_UNSUPPORTED_REQUEST.into()),
    }
}

fn write_error_response_to_large_request(
    out: &mut [u8],
    version: SpdmVersion,
    err: SpdmError,
) -> usize {
    let bytes = encode_error_response_to_large_request(version, err);
    let len = bytes.len();
    if let Some(dst) = out.get_mut(..len) {
        dst.copy_from_slice(&bytes);
        len
    } else {
        0
    }
}

fn encode_error_response_to_large_request(version: SpdmVersion, err: SpdmError) -> [u8; 4] {
    let mut out = [0u8; 4];
    encode_error_pdu(version, err, &mut out);
    out
}

fn encode_error_pdu(version: SpdmVersion, err: SpdmError, out: &mut [u8; 4]) {
    out[0] = version.to_u8();
    out[1] = ReqRespCode::ERROR.0;
    out[2] = err.spec_byte();
    out[3] = err.error_data();
}

#[cfg(test)]
#[path = "../tests/support.rs"]
mod support;

#[cfg(test)]
mod tests {
    extern crate std;

    use core::cell::RefCell;

    use futures::executor::block_on;
    use mcu_error::McuResult;
    use mcu_spdm_lite_codec::vendor_defined::iana::ocp::caliptra::{
        CaliptraVdmCommand, CALIPTRA_VDM_COMMAND_VERSION, CALIPTRA_VENDOR_ID,
    };
    use mcu_spdm_lite_traits::{
        SpdmPalAlloc, SpdmPalIo, SpdmVdmBackend, VdmRegistry, VdmResponse, VdmResponseBuffer,
    };
    use std::vec;
    use std::vec::Vec;

    use super::*;

    use super::support::{chunk_send_request, chunking_state, TestIo, TestPal};

    const CALIPTRA_VENDOR_ID_BYTES: [u8; 4] = CALIPTRA_VENDOR_ID.to_le_bytes();

    struct CaptureVdmBackend {
        captured_token_payload: RefCell<Option<Vec<u8>>>,
    }

    impl CaptureVdmBackend {
        fn new() -> Self {
            Self {
                captured_token_payload: RefCell::new(None),
            }
        }
    }

    impl SpdmVdmBackend for CaptureVdmBackend {
        fn match_id(&self, registry: &VdmRegistry<'_>) -> bool {
            registry.standard_id == 0x0004 && registry.vendor_id == CALIPTRA_VENDOR_ID_BYTES
        }

        async fn handle_request<Alloc, Io>(
            &self,
            req: &[u8],
            rsp: VdmResponseBuffer<'_, Alloc, Io>,
        ) -> McuResult<VdmResponse>
        where
            Alloc: SpdmPalAlloc,
            Io: SpdmPalIo,
        {
            assert_eq!(req.first().copied(), Some(CALIPTRA_VDM_COMMAND_VERSION));
            assert_eq!(
                req.get(1).copied(),
                Some(CaliptraVdmCommand::AuthorizeDebugUnlockToken as u8)
            );
            self.captured_token_payload.replace(Some(req[2..].to_vec()));
            rsp.inline[..3].copy_from_slice(&[
                CALIPTRA_VDM_COMMAND_VERSION,
                CaliptraVdmCommand::AuthorizeDebugUnlockToken as u8,
                0,
            ]);
            Ok(VdmResponse::Inline(3))
        }
    }

    fn vendor_defined_authorize_debug_unlock_request(token_payload: &[u8]) -> Vec<u8> {
        let vdm_payload_len = 2 + token_payload.len();
        let mut req = vec![
            SpdmVersion::V12.to_u8(),
            ReqRespCode::VENDOR_DEFINED_REQUEST.0,
            0,
            0,
            0x04,
            0x00,
            CALIPTRA_VENDOR_ID_BYTES.len() as u8,
        ];
        req.extend_from_slice(&CALIPTRA_VENDOR_ID_BYTES);
        req.extend_from_slice(&(vdm_payload_len as u16).to_le_bytes());
        req.push(CALIPTRA_VDM_COMMAND_VERSION);
        req.push(CaliptraVdmCommand::AuthorizeDebugUnlockToken as u8);
        req.extend_from_slice(token_payload);
        req
    }

    #[test]
    fn chunked_vendor_defined_debug_unlock_token_preserves_host_mailbox_payload() {
        let pal = TestPal::default();
        let mut state = chunking_state();
        let vdm = CaptureVdmBackend::new();

        // Host SPDM-VDM transport sends AuthorizeDebugUnlockToken as Caliptra RT
        // mailbox bytes: MailboxReqHeader/checksum followed by the token body.
        // The stack/backend must not strip, rewrite, or prepend this payload.
        let mut host_mailbox_payload = vec![0u8; 4 + 96];
        host_mailbox_payload[..4].copy_from_slice(&0xAABB_CCDDu32.to_le_bytes());
        for (i, b) in host_mailbox_payload[4..].iter_mut().enumerate() {
            *b = i as u8;
        }
        let large_req = vendor_defined_authorize_debug_unlock_request(&host_mailbox_payload);
        let (first, second) = large_req.split_at(64);
        let first_chunk = chunk_send_request(9, 0, false, Some(large_req.len()), first);
        let second_chunk = chunk_send_request(9, 1, true, None, second);

        let first_io = TestIo::message(first_chunk.clone());
        let rsp = block_on(handle_chunk_send(
            &mut state,
            &pal,
            &first_io,
            &vdm,
            &first_chunk,
            false,
        ))
        .unwrap();
        assert_eq!(
            &rsp[..],
            &[
                SpdmVersion::V12.to_u8(),
                ReqRespCode::CHUNK_SEND_ACK.0,
                0,
                9,
                0,
                0,
            ]
        );
        assert!(state.large_msg_ctx.request_in_progress());

        let second_io = TestIo::message(second_chunk.clone());
        let rsp = block_on(handle_chunk_send(
            &mut state,
            &pal,
            &second_io,
            &vdm,
            &second_chunk,
            false,
        ))
        .unwrap();
        assert_eq!(
            vdm.captured_token_payload.take(),
            Some(host_mailbox_payload)
        );
        assert!(!state.large_msg_ctx.request_in_progress());

        assert_eq!(
            &rsp[..],
            &[
                SpdmVersion::V12.to_u8(),
                ReqRespCode::CHUNK_SEND_ACK.0,
                0,
                9,
                1,
                0,
                SpdmVersion::V12.to_u8(),
                ReqRespCode::VENDOR_DEFINED_RESPONSE.0,
                0,
                0,
                0x04,
                0x00,
                CALIPTRA_VENDOR_ID_BYTES.len() as u8,
                CALIPTRA_VENDOR_ID_BYTES[0],
                CALIPTRA_VENDOR_ID_BYTES[1],
                CALIPTRA_VENDOR_ID_BYTES[2],
                CALIPTRA_VENDOR_ID_BYTES[3],
                3,
                0,
                CALIPTRA_VDM_COMMAND_VERSION,
                CaliptraVdmCommand::AuthorizeDebugUnlockToken as u8,
                0,
            ]
        );
    }
}

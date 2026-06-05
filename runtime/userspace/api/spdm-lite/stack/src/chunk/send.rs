// Licensed under the Apache-2.0 license

//! CHUNK_SEND large-request reassembly.

use mcu_spdm_lite_codec::{
    CapabilitiesBody, ChunkSendReqBody, ReqRespCode, SpdmMsgHdrPdu, SpdmVersion, StandardsBodyId,
    VendorDefinedReqPdu, VendorDefinedRspPdu, WireWriter, CHUNK_ACK_ATTR_EARLY_ERROR,
    CHUNK_ATTR_LAST_CHUNK,
};
use mcu_spdm_lite_traits::{PalBytes, SpdmPal, SpdmPalIo, SpdmPalIoTransport};
use zerocopy::{little_endian::U16, FromBytes};

use crate::build::alloc_padded;
use crate::error::{
    SpdmError, SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_UNSPECIFIED,
    SPDM_UNSUPPORTED_REQUEST, SPDM_VERSION_MISMATCH,
};
use crate::stack::{ConnectionState, Phase};
use crate::vendor_defined::{self, SpdmVdmBackend, VdmStreamRequest};

struct ChunkInfo {
    handle: u8,
    chunk_seq_num: u16,
    complete: bool,
    stream_payload: Option<StreamingPayload>,
}

struct StreamingPayload {
    stream_id: u32,
    offset: usize,
    len: usize,
    first: bool,
    total_payload_len: usize,
}

pub(crate) async fn handle_chunk_send<'a, Pal, Vdm>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    vdm_backend: &Vdm,
) -> SpdmResult<PalBytes<'a, Pal>>
where
    Pal: SpdmPal,
    Vdm: SpdmVdmBackend,
{
    let result = process_chunk_send(state, pal, io, vdm_backend);
    match result {
        Ok(info) if info.complete => {
            if let Err(e) = handle_stream_payload(io.request(), vdm_backend, &info).await {
                abort_stream(state, vdm_backend).await;
                state.chunk.reset();
                return Err(e);
            }
            build_completed_chunk_send_ack(state, pal, io, info, vdm_backend).await
        }
        Ok(info) => {
            if let Err(e) = handle_stream_payload(io.request(), vdm_backend, &info).await {
                abort_stream(state, vdm_backend).await;
                state.chunk.reset();
                return Err(e);
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
        Err(ChunkProcessError::Spdm(e)) => Err(e),
        Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        }) => {
            let mut error = [0u8; 4];
            encode_error_pdu(state.version, SPDM_INVALID_REQUEST, &mut error);
            abort_stream(state, vdm_backend).await;
            state.chunk.reset();
            build_chunk_send_ack(pal, io, state.version, true, handle, chunk_seq_num, &error)
        }
    }
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
    let raw_len = head + SpdmMsgHdrPdu::SIZE + 4 + response_to_large_request.len();
    let mut rsp = alloc_padded(pal, io, raw_len)?;
    write_chunk_send_ack_prefix(
        &mut rsp[head..],
        version,
        early_error,
        handle,
        chunk_seq_num,
    )?;
    let response_offset = head + SpdmMsgHdrPdu::SIZE + 4;
    rsp[response_offset..response_offset + response_to_large_request.len()]
        .copy_from_slice(response_to_large_request);
    Ok(rsp)
}

async fn build_completed_chunk_send_ack<'a, Pal, Vdm>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    info: ChunkInfo,
    vdm_backend: &Vdm,
) -> SpdmResult<PalBytes<'a, Pal>>
where
    Pal: SpdmPal,
    Vdm: SpdmVdmBackend,
{
    let head = pal.header_size();
    let ack_body_len = SpdmMsgHdrPdu::SIZE + 4;
    let max_response_len =
        super::effective_data_transfer_size(state, pal).saturating_sub(ack_body_len);
    let mut rsp = alloc_padded(pal, io, head + ack_body_len + max_response_len)?;

    let response_offset = head + ack_body_len;
    let response = &mut rsp[response_offset..response_offset + max_response_len];
    let response_len = if state.chunk.stream.is_some() {
        match build_response_to_streamed_request(state, vdm_backend, response).await {
            Ok(len) => len,
            Err(err) => {
                let mut error = [0u8; 4];
                encode_error_pdu(state.version, err, &mut error);
                response[..error.len()].copy_from_slice(&error);
                error.len()
            }
        }
    } else {
        match build_response_to_large_request(state, pal, io, vdm_backend, response).await {
            Ok(len) => len,
            Err(err) => {
                let mut error = [0u8; 4];
                encode_error_pdu(state.version, err, &mut error);
                response[..error.len()].copy_from_slice(&error);
                error.len()
            }
        }
    };
    state.chunk.reset();

    write_chunk_send_ack_prefix(
        &mut rsp[head..],
        state.version,
        false,
        info.handle,
        info.chunk_seq_num,
    )?;
    shrink_padded(pal, &mut rsp, response_offset + response_len)?;
    Ok(rsp)
}

fn write_chunk_send_ack_prefix(
    out: &mut [u8],
    version: SpdmVersion,
    early_error: bool,
    handle: u8,
    chunk_seq_num: u16,
) -> SpdmResult<()> {
    let mut w = WireWriter::new(out);
    w.write(&SpdmMsgHdrPdu::new(version, ReqRespCode::CHUNK_SEND_ACK))?;
    let attr = if early_error {
        CHUNK_ACK_ATTR_EARLY_ERROR
    } else {
        0
    };
    w.write(&[attr, handle])?;
    w.write(&U16::new(chunk_seq_num))?;
    Ok(())
}

enum ChunkProcessError {
    Spdm(SpdmError),
    Early { handle: u8, chunk_seq_num: u16 },
}

struct FirstChunk<'a> {
    handle: u8,
    chunk_seq_num: u16,
    chunk_size: usize,
    last_chunk: bool,
    rest: &'a [u8],
}

fn process_chunk_send<Pal, Vdm>(
    state: &mut ConnectionState<Pal::State>,
    pal: &Pal,
    io: &impl SpdmPalIo,
    vdm_backend: &Vdm,
) -> Result<ChunkInfo, ChunkProcessError>
where
    Pal: SpdmPal,
    Vdm: SpdmVdmBackend,
{
    if state.large_response.in_progress()
        || (state.phase as u8) < (Phase::AfterCapabilities as u8)
        || !state.chunking_enabled()
    {
        return Err(ChunkProcessError::Spdm(SPDM_UNEXPECTED_REQUEST));
    }

    let req = io.request();
    if req.len() > pal.mtu() {
        return Err(ChunkProcessError::Spdm(SPDM_INVALID_REQUEST));
    }

    let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(req)
        .map_err(|_| ChunkProcessError::Spdm(SPDM_INVALID_REQUEST))?;
    if hdr.version != state.version.to_u8() {
        return Err(ChunkProcessError::Spdm(SPDM_VERSION_MISMATCH));
    }

    let (chunk_req, rest) = ChunkSendReqBody::ref_from_prefix(body)
        .map_err(|_| ChunkProcessError::Spdm(SPDM_INVALID_REQUEST))?;
    let handle = chunk_req.handle;
    let chunk_seq_num = chunk_req.chunk_seq_num.get();
    let chunk_size = chunk_req.chunk_size.get() as usize;
    let last_chunk = (chunk_req.chunk_sender_attr & CHUNK_ATTR_LAST_CHUNK) != 0;
    if chunk_req.reserved.get() != 0 || (chunk_req.chunk_sender_attr & !CHUNK_ATTR_LAST_CHUNK) != 0
    {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    }

    if !state.chunk.in_use {
        process_first_chunk(
            state,
            pal,
            FirstChunk {
                handle,
                chunk_seq_num,
                chunk_size,
                last_chunk,
                rest,
            },
            io,
            vdm_backend,
        )?;
    } else {
        process_next_chunk(
            state,
            pal,
            handle,
            chunk_seq_num,
            chunk_size,
            last_chunk,
            rest,
        )?;
    }

    let stream_payload = state.chunk.stream.as_ref().map(|stream| {
        let chunk_start = SpdmMsgHdrPdu::SIZE + ChunkSendReqBody::SIZE;
        if chunk_seq_num == 0 {
            let vdm_payload_offset = streaming_payload_offset(rest).unwrap_or(chunk_size);
            StreamingPayload {
                stream_id: stream.stream_id,
                offset: chunk_start + 4 + vdm_payload_offset,
                len: chunk_size.saturating_sub(vdm_payload_offset),
                first: true,
                total_payload_len: stream_payload_len(rest).unwrap_or(0),
            }
        } else {
            StreamingPayload {
                stream_id: stream.stream_id,
                offset: chunk_start,
                len: chunk_size,
                first: false,
                total_payload_len: 0,
            }
        }
    });

    Ok(ChunkInfo {
        handle,
        chunk_seq_num,
        complete: state.chunk.in_use && state.chunk.bytes_received == state.chunk.large_msg_size,
        stream_payload,
    })
}

fn process_first_chunk<Pal, Vdm>(
    state: &mut ConnectionState<Pal::State>,
    pal: &Pal,
    first: FirstChunk<'_>,
    io: &impl SpdmPalIo,
    vdm_backend: &Vdm,
) -> Result<(), ChunkProcessError>
where
    Pal: SpdmPal,
    Vdm: SpdmVdmBackend,
{
    let FirstChunk {
        handle,
        chunk_seq_num,
        chunk_size,
        last_chunk,
        rest,
    } = first;
    let Some(size_bytes) = rest.get(..4) else {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    };
    let mut large_msg_size = [0u8; 4];
    large_msg_size.copy_from_slice(size_bytes);
    let large_msg_size = u32::from_le_bytes(large_msg_size) as usize;
    let chunk = &rest[4..];
    let min_chunk_size = CapabilitiesBody::MIN_DATA_TRANSFER_SIZE as usize
        - SpdmMsgHdrPdu::SIZE
        - ChunkSendReqBody::SIZE
        - 4;

    let invalid = chunk_seq_num != 0
        || last_chunk
        || chunk_size != chunk.len()
        || chunk_size < min_chunk_size
        || chunk_size >= large_msg_size
        || large_msg_size <= CapabilitiesBody::MIN_DATA_TRANSFER_SIZE as usize;
    if invalid {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    }

    let streaming = parse_streaming_vdm::<Pal, Vdm>(state, io, vdm_backend, chunk);
    if let Some(stream) = streaming {
        state.chunk = super::ChunkState {
            in_use: true,
            handle,
            seq_num: 0,
            bytes_received: chunk_size as u32,
            large_msg_size: large_msg_size as u32,
            stream: Some(stream),
        };
        Ok(())
    } else {
        if large_msg_size > pal.capacity() || pal.write(0, chunk).is_err() {
            return Err(ChunkProcessError::Early {
                handle,
                chunk_seq_num,
            });
        }
        state.chunk = super::ChunkState {
            in_use: true,
            handle,
            seq_num: 0,
            bytes_received: chunk_size as u32,
            large_msg_size: large_msg_size as u32,
            stream: None,
        };
        Ok(())
    }
}

fn process_next_chunk<Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State>,
    pal: &Pal,
    handle: u8,
    chunk_seq_num: u16,
    chunk_size: usize,
    last_chunk: bool,
    chunk: &[u8],
) -> Result<(), ChunkProcessError> {
    let bytes_received = state.chunk.bytes_received as usize;
    let large_msg_size = state.chunk.large_msg_size as usize;
    let end = bytes_received.saturating_add(chunk_size);
    let min_chunk_size = CapabilitiesBody::MIN_DATA_TRANSFER_SIZE as usize
        - SpdmMsgHdrPdu::SIZE
        - ChunkSendReqBody::SIZE;
    let invalid = chunk_seq_num == 0
        || state.chunk.handle != handle
        || state.chunk.seq_num.wrapping_add(1) != chunk_seq_num
        || chunk_size != chunk.len()
        || end > large_msg_size
        || (last_chunk && end != large_msg_size)
        || (!last_chunk && (end >= large_msg_size || chunk_size < min_chunk_size));
    if invalid {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    }

    if state.chunk.stream.is_none() && pal.write(bytes_received, chunk).is_err() {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    }

    state.chunk.seq_num = chunk_seq_num;
    state.chunk.bytes_received = end as u32;
    Ok(())
}

async fn abort_stream<Vdm>(state: &ConnectionState<impl Clone>, vdm_backend: &Vdm)
where
    Vdm: SpdmVdmBackend,
{
    if let Some(stream) = state.chunk.stream.as_ref() {
        vdm_backend.stream_abort(stream.stream_id).await;
    }
}

async fn handle_stream_payload<Vdm>(
    req: &[u8],
    vdm_backend: &Vdm,
    info: &ChunkInfo,
) -> SpdmResult<()>
where
    Vdm: SpdmVdmBackend,
{
    let Some(payload) = info.stream_payload.as_ref() else {
        return Ok(());
    };
    let data = req
        .get(payload.offset..payload.offset + payload.len)
        .ok_or(SPDM_INVALID_REQUEST)?;
    if payload.first {
        vdm_backend
            .stream_init(payload.stream_id, payload.total_payload_len, data)
            .await
    } else {
        vdm_backend.stream_chunk(payload.stream_id, data).await
    }
}

fn streaming_payload_offset(rest: &[u8]) -> Option<usize> {
    let chunk = rest.get(4..)?;
    parse_streaming_header(chunk).map(|parsed| parsed.payload_offset)
}

fn stream_payload_len(rest: &[u8]) -> Option<usize> {
    let chunk = rest.get(4..)?;
    parse_streaming_header(chunk).map(|parsed| parsed.payload_len)
}

struct ParsedStreamingHeader {
    standard_id: StandardsBodyId,
    vendor_id: [u8; 4],
    vendor_id_len: u8,
    command_code: u8,
    payload_offset: usize,
    payload_len: usize,
}

fn parse_streaming_header(chunk: &[u8]) -> Option<ParsedStreamingHeader> {
    if chunk.len() < SpdmMsgHdrPdu::SIZE + VendorDefinedReqPdu::SIZE {
        return None;
    }
    let hdr = SpdmMsgHdrPdu::ref_from_bytes(chunk.get(..SpdmMsgHdrPdu::SIZE)?).ok()?;
    if hdr.code != ReqRespCode::VENDOR_DEFINED_REQUEST {
        return None;
    }
    let body = &chunk[SpdmMsgHdrPdu::SIZE..];
    let req = VendorDefinedReqPdu::ref_from_bytes(body.get(..VendorDefinedReqPdu::SIZE)?).ok()?;
    let standard_id = StandardsBodyId::from_u16(req.standard_id.get())?;
    let expected_vendor_id_len = standard_id.vendor_id_len()?;
    if req.vendor_id_len != expected_vendor_id_len || req.vendor_id_len as usize > 4 {
        return None;
    }
    let vendor_id_len = req.vendor_id_len as usize;
    let vendor_start = SpdmMsgHdrPdu::SIZE + VendorDefinedReqPdu::SIZE;
    let req_len_offset = vendor_start.checked_add(vendor_id_len)?;
    let req_len_bytes = chunk.get(req_len_offset..req_len_offset + 2)?;
    let vdm_req_len = u16::from_le_bytes([req_len_bytes[0], req_len_bytes[1]]) as usize;
    if vdm_req_len < 2 {
        return None;
    }
    let vdm_header_offset = req_len_offset + 2;
    let command_code = *chunk.get(vdm_header_offset + 1)?;
    let payload_offset = vdm_header_offset + 2;
    if chunk.len() < payload_offset {
        return None;
    }
    let mut vendor_id = [0u8; 4];
    vendor_id[..vendor_id_len]
        .copy_from_slice(chunk.get(vendor_start..vendor_start + vendor_id_len)?);
    Some(ParsedStreamingHeader {
        standard_id,
        vendor_id,
        vendor_id_len: req.vendor_id_len,
        command_code,
        payload_offset,
        payload_len: vdm_req_len - 2,
    })
}

fn parse_streaming_vdm<Pal, Vdm>(
    state: &ConnectionState<Pal::State>,
    io: &impl SpdmPalIo,
    vdm_backend: &Vdm,
    chunk: &[u8],
) -> Option<super::StreamingRequest>
where
    Pal: SpdmPal,
    Vdm: SpdmVdmBackend,
{
    let parsed = parse_streaming_header(chunk)?;
    let req = VdmStreamRequest {
        standard_id: parsed.standard_id,
        vendor_id: &parsed.vendor_id[..parsed.vendor_id_len as usize],
        secure_session: io.kind() == mcu_spdm_lite_traits::SpdmPalIoKind::SecuredMessage,
        command_code: parsed.command_code,
    };
    let stream_id = vdm_backend.stream_supported(&req)?;
    // Only stream once normal VDM dispatch would be legal.
    if (state.phase as u8) < (Phase::AfterAlgorithms as u8) {
        return None;
    }
    Some(super::StreamingRequest {
        stream_id,
        standard_id: parsed.standard_id,
        vendor_id: parsed.vendor_id,
        vendor_id_len: parsed.vendor_id_len,
        command_code: parsed.command_code,
    })
}

async fn build_response_to_streamed_request<Vdm>(
    state: &ConnectionState<impl Clone>,
    vdm_backend: &Vdm,
    out: &mut [u8],
) -> SpdmResult<usize>
where
    Vdm: SpdmVdmBackend,
{
    let stream = state.chunk.stream.as_ref().ok_or(SPDM_INVALID_REQUEST)?;
    let vendor_id = &stream.vendor_id[..stream.vendor_id_len as usize];
    let fixed_len = SpdmMsgHdrPdu::SIZE
        + VendorDefinedRspPdu::SIZE
        + vendor_id.len()
        + core::mem::size_of::<U16>();
    let payload_offset = fixed_len;
    let data_offset = payload_offset + 3;
    if out.len() < data_offset {
        return Err(SPDM_UNSPECIFIED);
    }

    let data_len = vdm_backend
        .stream_finish(stream.stream_id, &mut out[data_offset..])
        .await?;
    let vdm_payload_len = 3usize.checked_add(data_len).ok_or(SPDM_UNSPECIFIED)?;
    if vdm_payload_len > u16::MAX as usize || out.len() < fixed_len + vdm_payload_len {
        return Err(SPDM_UNSPECIFIED);
    }

    let mut w = WireWriter::new(&mut out[..fixed_len]);
    w.write(&SpdmMsgHdrPdu::new(
        state.version,
        ReqRespCode::VENDOR_DEFINED_RESPONSE,
    ))?;
    w.write(&VendorDefinedRspPdu {
        param1: 0,
        param2: 0,
        standard_id: U16::new(stream.standard_id.as_u16()),
        vendor_id_len: stream.vendor_id_len,
    })?;
    w.write_bytes(vendor_id)?;
    w.write(&U16::new(vdm_payload_len as u16))?;
    out[payload_offset] = 0x01;
    out[payload_offset + 1] = stream.command_code;
    out[payload_offset + 2] = 0;
    Ok(fixed_len + vdm_payload_len)
}

async fn build_response_to_large_request<Pal, Vdm>(
    state: &ConnectionState<Pal::State>,
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    vdm_backend: &Vdm,
    out: &mut [u8],
) -> SpdmResult<usize>
where
    Pal: SpdmPal,
    Vdm: SpdmVdmBackend,
{
    let large_req_len = state.chunk.large_msg_size as usize;
    if large_req_len < SpdmMsgHdrPdu::SIZE {
        return Err(SPDM_INVALID_REQUEST);
    }
    // SAFETY: CHUNK_SEND reassembly owns the PAL large-message buffer until
    // `state.chunk` is reset after this response is built. The returned borrow
    // is used read-only to decode and dispatch the completed large request, and
    // no other PAL large-message operation is performed while it is live.
    let large_req =
        unsafe { pal.large_message_mut(large_req_len) }.map_err(|_| SPDM_INVALID_REQUEST)?;
    let (hdr, _) = SpdmMsgHdrPdu::ref_from_prefix(&*large_req).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8()
        || hdr.code == ReqRespCode::CHUNK_SEND
        || hdr.code == ReqRespCode::CHUNK_GET
    {
        return Err(SPDM_INVALID_REQUEST);
    }
    match hdr.code {
        ReqRespCode::VENDOR_DEFINED_REQUEST => {
            vendor_defined::handle_large_vendor_defined_request::<Pal, Vdm>(
                state,
                io,
                large_req,
                vdm_backend,
                out,
            )
            .await
        }
        _ => Err(SPDM_UNSUPPORTED_REQUEST),
    }
}

fn encode_error_pdu(version: SpdmVersion, err: SpdmError, out: &mut [u8; 4]) {
    out[0] = version.to_u8();
    out[1] = ReqRespCode::ERROR.0;
    out[2] = err.spec_byte();
    out[3] = err.error_data();
}

fn padded_len<Pal: SpdmPal>(pal: &Pal, raw_len: usize) -> SpdmResult<usize> {
    let align = pal.send_len_alignment();
    debug_assert!(align > 0 && align.is_power_of_two());
    raw_len
        .checked_add(align - 1)
        .map(|len| len & !(align - 1))
        .ok_or(SPDM_UNSPECIFIED)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_streaming_header_extracts_ocp_vdm_payload() {
        let mut chunk = [0u8; 32];
        chunk[0] = 0x12;
        chunk[1] = ReqRespCode::VENDOR_DEFINED_REQUEST.0;
        chunk[4..6].copy_from_slice(&(StandardsBodyId::Iana.as_u16()).to_le_bytes());
        chunk[6] = 4;
        chunk[7..11].copy_from_slice(&42623u32.to_le_bytes());
        chunk[11..13].copy_from_slice(&7u16.to_le_bytes());
        chunk[13] = 1;
        chunk[14] = 0x0b;
        chunk[15..20].copy_from_slice(&[1, 2, 3, 4, 5]);

        let parsed = parse_streaming_header(&chunk[..20]).unwrap();
        assert!(parsed.standard_id == StandardsBodyId::Iana);
        assert_eq!(
            &parsed.vendor_id[..parsed.vendor_id_len as usize],
            &42623u32.to_le_bytes()
        );
        assert_eq!(parsed.command_code, 0x0b);
        assert_eq!(parsed.payload_offset, 15);
        assert_eq!(parsed.payload_len, 5);
    }

    #[test]
    fn parse_streaming_header_rejects_non_vdm_request() {
        let chunk = [0x12, ReqRespCode::GET_VERSION.0, 0, 0];
        assert!(parse_streaming_header(&chunk).is_none());
    }
}

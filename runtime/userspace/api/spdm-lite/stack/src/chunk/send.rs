// Licensed under the Apache-2.0 license

//! CHUNK_SEND large-request reassembly.

use mcu_spdm_lite_codec::{
    CapabilitiesBody, ChunkSendAckBody, ChunkSendReqBody, ReqRespCode, SpdmMsgHdrPdu, SpdmVersion,
    WireWriter, CHUNK_ACK_ATTR_EARLY_ERROR, CHUNK_ATTR_LAST_CHUNK,
};
use mcu_spdm_lite_traits::{PalBytes, SpdmPal, SpdmPalAlloc, SpdmPalIoTransport, SpdmVdmBackend};
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

pub(crate) async fn handle_chunk_send<'a, Pal: SpdmPal, Vdm: SpdmVdmBackend>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    vdm: &Vdm,
    req: &[u8],
    secure_session: bool,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let result = process_chunk_send(state, pal, req);
    match result {
        Ok(info) => {
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
        }) => {
            let mut error = [0u8; 4];
            encode_error_pdu(state.version, SPDM_INVALID_REQUEST, &mut error);
            state.reset_chunk_assembly();
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

enum ChunkProcessError {
    Spdm(SpdmError),
    Early { handle: u8, chunk_seq_num: u16 },
}

fn process_chunk_send<Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &Pal,
    req: &[u8],
) -> Result<ChunkInfo, ChunkProcessError> {
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

    if !state.large_msg_ctx.request_in_progress() {
        process_first_chunk(
            state,
            pal,
            handle,
            chunk_seq_num,
            chunk_size,
            last_chunk,
            rest,
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

    Ok(ChunkInfo {
        handle,
        chunk_seq_num,
        complete: state.large_msg_ctx.request_in_progress()
            && state.large_msg_ctx.state.bytes_received == state.large_msg_ctx.state.large_msg_size,
    })
}

fn process_first_chunk<Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &Pal,
    handle: u8,
    chunk_seq_num: u16,
    chunk_size: usize,
    last_chunk: bool,
    rest: &[u8],
) -> Result<(), ChunkProcessError> {
    let Some(size_bytes) = rest.first_chunk::<4>() else {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    };
    let large_msg_size = u32::from_le_bytes(*size_bytes) as usize;
    let chunk_data = &rest[4..];

    // Require exact chunk body length match inside rest payload (no trailing junk bytes).
    if chunk_data.len() != chunk_size {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    }
    let Some(chunk) = chunk_data.get(..chunk_size) else {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    };
    let min_chunk_size = CapabilitiesBody::MIN_DATA_TRANSFER_SIZE as usize
        - SpdmMsgHdrPdu::SIZE
        - ChunkSendReqBody::SIZE
        - 4;

    let invalid = chunk_seq_num != 0
        || last_chunk
        || chunk_size < min_chunk_size
        || chunk_size >= large_msg_size
        || large_msg_size <= CapabilitiesBody::MIN_DATA_TRANSFER_SIZE as usize
        || large_msg_size > pal.large_capacity();
    if invalid {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    }
    let rent_buf = match pal.alloc_large_buf(large_msg_size) {
        Ok(buf) => buf,
        Err(_) => {
            return Err(ChunkProcessError::Early {
                handle,
                chunk_seq_num,
            })
        }
    };
    if state
        .large_msg_ctx
        .init_request(handle, large_msg_size, chunk, rent_buf)
        .is_err()
    {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    }
    Ok(())
}

fn process_next_chunk<Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    _pal: &Pal,
    handle: u8,
    chunk_seq_num: u16,
    chunk_size: usize,
    last_chunk: bool,
    rest: &[u8],
) -> Result<(), ChunkProcessError> {
    let bytes_received = state.large_msg_ctx.state.bytes_received as usize;
    let large_msg_size = state.large_msg_ctx.state.large_msg_size as usize;
    let end = bytes_received.saturating_add(chunk_size);

    // Require exact chunk body length match inside rest payload (no trailing junk bytes).
    if rest.len() != chunk_size {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    }
    let Some(chunk) = rest.get(..chunk_size) else {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    };
    let min_chunk_size = CapabilitiesBody::MIN_DATA_TRANSFER_SIZE as usize
        - SpdmMsgHdrPdu::SIZE
        - ChunkSendReqBody::SIZE;
    let invalid = chunk_seq_num == 0
        || state.large_msg_ctx.state.handle != handle
        || state.large_msg_ctx.state.seq_num.wrapping_add(1) != chunk_seq_num
        || end > large_msg_size
        || (last_chunk && end != large_msg_size)
        || (!last_chunk && (end >= large_msg_size || chunk_size < min_chunk_size));
    if invalid {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    }
    if state
        .large_msg_ctx
        .append_request(handle, chunk_seq_num, chunk)
        .is_err()
    {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    }

    Ok(())
}

enum ResponseToLargeRequest<'a, Pal: SpdmPal + 'a> {
    Fixed([u8; 4]),
    Allocated {
        buf: PalBytes<'a, Pal>,
        spdm_len: usize,
    },
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
    let len = state.large_msg_ctx.state.large_msg_size as usize;
    let response = if len < SpdmMsgHdrPdu::SIZE {
        ResponseToLargeRequest::Fixed(encode_error_response_to_large_request(
            state.version,
            SPDM_INVALID_REQUEST,
        ))
    } else {
        match dispatch_large_request(state, pal, io, vdm, len, secure_session).await {
            Ok(response) => response,
            Err(err) => ResponseToLargeRequest::Fixed(encode_error_response_to_large_request(
                state.version,
                err,
            )),
        }
    };

    match response {
        ResponseToLargeRequest::Fixed(bytes) => {
            build_chunk_send_ack(pal, io, state.version, false, handle, chunk_seq_num, &bytes)
        }
        ResponseToLargeRequest::Allocated { buf, spdm_len } => {
            let max_response_len = state
                .effective_data_transfer_size(pal)
                .saturating_sub(SpdmMsgHdrPdu::SIZE + ChunkSendAckBody::SIZE);
            if spdm_len > max_response_len {
                let bytes =
                    encode_error_response_to_large_request(state.version, SPDM_LARGE_RESPONSE);
                return build_chunk_send_ack(
                    pal,
                    io,
                    state.version,
                    false,
                    handle,
                    chunk_seq_num,
                    &bytes,
                );
            }

            let head = pal.header_size();
            let end = head.checked_add(spdm_len).ok_or(SPDM_UNSPECIFIED)?;
            let response = buf.get(head..end).ok_or(SPDM_UNSPECIFIED)?;
            build_chunk_send_ack(
                pal,
                io,
                state.version,
                false,
                handle,
                chunk_seq_num,
                response,
            )
        }
    }
}

async fn dispatch_large_request<'a, Pal: SpdmPal, Vdm: SpdmVdmBackend>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    vdm: &Vdm,
    len: usize,
    secure_session: bool,
) -> Result<ResponseToLargeRequest<'a, Pal>, SpdmError> {
    // Detach the buffer, but immediately place it in an auto-wiping RAII guard.
    // This addresses Issue 2 & 3: zeroization is guaranteed across all handler exit pathways!
    let mut guard = WipeOnDrop {
        buf: state.large_msg_ctx.take_buffer(),
    };
    let large_buf = guard.buf.as_mut().ok_or(SPDM_INVALID_REQUEST)?;
    let buf = large_buf.as_mut();
    let large_req = buf.get(..len).ok_or(SPDM_INVALID_REQUEST)?;
    let (hdr, _) = SpdmMsgHdrPdu::ref_from_prefix(large_req).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8()
        || hdr.code == ReqRespCode::CHUNK_SEND
        || hdr.code == ReqRespCode::CHUNK_GET
    {
        return Err(SPDM_INVALID_REQUEST);
    }
    let code = hdr.code;

    match code {
        #[cfg(feature = "set-certificate")]
        ReqRespCode::SET_CERTIFICATE => {
            if secure_session {
                return Err(SPDM_UNSUPPORTED_REQUEST);
            }
            let slot_id =
                set_certificate::handle_set_certificate_request(state, pal, io, &buf[..len])
                    .await?;
            Ok(ResponseToLargeRequest::Fixed([
                state.version.to_u8(),
                ReqRespCode::SET_CERTIFICATE_RSP.0,
                slot_id,
                0,
            ]))
        }
        ReqRespCode::VENDOR_DEFINED_REQUEST => {
            let (v_rsp, spdm_len) = vendor_defined::handle_vendor_defined_request(
                vdm,
                state,
                pal,
                io,
                &buf[..len],
                secure_session,
            )
            .await?;
            if spdm_len == 0 || v_rsp.len() < pal.header_size().saturating_add(spdm_len) {
                return Err(SPDM_UNSPECIFIED);
            }
            Ok(ResponseToLargeRequest::Allocated {
                buf: v_rsp,
                spdm_len,
            })
        }
        _ => Err(SPDM_UNSUPPORTED_REQUEST),
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
    out[3] = 0;
}

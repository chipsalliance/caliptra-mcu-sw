// Licensed under the Apache-2.0 license

//! CHUNK_SEND large-request reassembly.

use caliptra_mcu_spdm_codec::{
    CapabilitiesBody, ChunkSendAckBody, ChunkSendReqBody, ReqRespCode, SpdmMsgHdrPdu, SpdmVersion,
    VendorDefinedReqPdu, WireWriter, CHUNK_ACK_ATTR_EARLY_ERROR, CHUNK_ATTR_LAST_CHUNK,
};
use caliptra_mcu_spdm_traits::{
    PalBytes, SpdmPal, SpdmPalAlloc, SpdmPalIoTransport, SpdmVdmBackend, VdmRegistry, VdmResponse,
    VdmResponseBuffer,
};
use zerocopy::{little_endian::U16, FromBytes};

#[cfg(feature = "set-certificate")]
use super::StreamPrefixState;
#[cfg(any(test, feature = "generic-large-request"))]
use super::WipeOnDrop;
use super::{ActiveLargeRequest, VendorDefinedStreamState};
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
    let result = process_chunk_send(state, pal, io, vdm, req, secure_session).await;
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
            abort_streaming_request_if_needed(state, pal, io, vdm).await;
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

/// Maximum bytes carried as `ResponseToLargeRequest` inside CHUNK_SEND_ACK.
const LARGE_REQUEST_RESPONSE_BUF_SIZE: usize = 512;

enum ChunkProcessError {
    Spdm(SpdmError),
    Early { handle: u8, chunk_seq_num: u16 },
}

async fn process_chunk_send<Pal: SpdmPal, Vdm: SpdmVdmBackend>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    vdm: &Vdm,
    req: &[u8],
    secure_session: bool,
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
            io,
            vdm,
            handle,
            chunk_seq_num,
            chunk_size,
            last_chunk,
            rest,
            secure_session,
        )
        .await?;
    } else {
        process_next_chunk(
            state,
            pal,
            io,
            vdm,
            handle,
            chunk_seq_num,
            chunk_size,
            last_chunk,
            rest,
        )
        .await?;
    }

    Ok(ChunkInfo {
        handle,
        chunk_seq_num,
        complete: state.large_msg_ctx.request_in_progress()
            && state.large_msg_ctx.state.bytes_received == state.large_msg_ctx.state.large_msg_size,
    })
}

#[allow(clippy::too_many_arguments)]
async fn process_first_chunk<Pal: SpdmPal, Vdm: SpdmVdmBackend>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    vdm: &Vdm,
    handle: u8,
    chunk_seq_num: u16,
    chunk_size: usize,
    last_chunk: bool,
    rest: &[u8],
    secure_session: bool,
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
    #[cfg(feature = "set-certificate")]
    {
        if let Some(required_len) = required_stream_prefix_len(chunk, secure_session) {
            let mut prefix = StreamPrefixState {
                data: [0; super::STREAM_PREFIX_CAPACITY],
                len: chunk.len(),
            };
            prefix.data[..chunk.len()].copy_from_slice(chunk);
            if required_len > prefix.data.len() {
                return Err(ChunkProcessError::Early {
                    handle,
                    chunk_seq_num,
                });
            }
            state
                .large_msg_ctx
                .init_streaming_request(
                    handle,
                    large_msg_size,
                    chunk.len(),
                    ActiveLargeRequest::Prefix(prefix),
                )
                .map_err(|_| ChunkProcessError::Early {
                    handle,
                    chunk_seq_num,
                })?;
            return Ok(());
        }
    }
    if try_start_streaming_request(
        state,
        pal,
        io,
        vdm,
        handle,
        large_msg_size,
        chunk,
        secure_session,
    )
    .await
    .map_err(|_| ChunkProcessError::Early {
        handle,
        chunk_seq_num,
    })? {
        return Ok(());
    }
    #[cfg(any(test, feature = "generic-large-request"))]
    {
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
    #[cfg(not(any(test, feature = "generic-large-request")))]
    {
        Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_next_chunk<Pal: SpdmPal, Vdm: SpdmVdmBackend>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    vdm: &Vdm,
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
    #[cfg(feature = "set-certificate")]
    let algo = state.asym_algo();
    match state.large_msg_ctx.active_request_mut() {
        #[cfg(any(test, feature = "generic-large-request"))]
        Some(ActiveLargeRequest::Buffered) => {
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
        }
        #[cfg(feature = "set-certificate")]
        Some(ActiveLargeRequest::Prefix(_)) => {
            let consumed = continue_setcert_prefix(state, pal, io, handle, chunk)
                .await
                .map_err(|_| ChunkProcessError::Early {
                    handle,
                    chunk_seq_num,
                })?;
            let remaining = &chunk[consumed..];
            if !remaining.is_empty() {
                let active =
                    state
                        .large_msg_ctx
                        .active_request_mut()
                        .ok_or(ChunkProcessError::Early {
                            handle,
                            chunk_seq_num,
                        })?;
                match active {
                    #[cfg(feature = "set-certificate")]
                    ActiveLargeRequest::SetCertificate(stream) => {
                        set_certificate::continue_set_certificate_stream(
                            pal, io, algo, stream, remaining,
                        )
                        .await
                        .map_err(|_| ChunkProcessError::Early {
                            handle,
                            chunk_seq_num,
                        })?;
                    }
                    _ => {
                        return Err(ChunkProcessError::Early {
                            handle,
                            chunk_seq_num,
                        })
                    }
                }
            }
            state
                .large_msg_ctx
                .append_streaming_request(handle, chunk_seq_num, chunk.len())
                .map_err(|_| ChunkProcessError::Early {
                    handle,
                    chunk_seq_num,
                })?;
        }
        #[cfg(feature = "set-certificate")]
        Some(ActiveLargeRequest::SetCertificate(stream)) => {
            set_certificate::continue_set_certificate_stream(pal, io, algo, stream, chunk)
                .await
                .map_err(|_| ChunkProcessError::Early {
                    handle,
                    chunk_seq_num,
                })?;
            state
                .large_msg_ctx
                .append_streaming_request(handle, chunk_seq_num, chunk.len())
                .map_err(|_| ChunkProcessError::Early {
                    handle,
                    chunk_seq_num,
                })?;
        }
        #[cfg(feature = "set-certificate")]
        Some(ActiveLargeRequest::Unsupported(_)) => {
            state
                .large_msg_ctx
                .append_streaming_request(handle, chunk_seq_num, chunk.len())
                .map_err(|_| ChunkProcessError::Early {
                    handle,
                    chunk_seq_num,
                })?;
        }
        Some(ActiveLargeRequest::VendorDefined(_)) => {
            vdm.continue_streaming_request(chunk, pal, io)
                .await
                .map_err(|_| ChunkProcessError::Early {
                    handle,
                    chunk_seq_num,
                })?;
            state
                .large_msg_ctx
                .append_streaming_request(handle, chunk_seq_num, chunk.len())
                .map_err(|_| ChunkProcessError::Early {
                    handle,
                    chunk_seq_num,
                })?;
        }
        None => {
            return Err(ChunkProcessError::Early {
                handle,
                chunk_seq_num,
            })
        }
    }

    Ok(())
}

#[cfg(feature = "set-certificate")]
const SET_CERT_STREAM_PREFIX_LEN: usize =
    SpdmMsgHdrPdu::SIZE + caliptra_mcu_spdm_codec::SetCertificateReqBody::SIZE + 4 + 48;

#[cfg(feature = "set-certificate")]
fn required_stream_prefix_len(first: &[u8], secure_session: bool) -> Option<usize> {
    if secure_session || first.len() >= SET_CERT_STREAM_PREFIX_LEN {
        return None;
    }
    let (hdr, _) = SpdmMsgHdrPdu::ref_from_prefix(first).ok()?;
    (hdr.code == ReqRespCode::SET_CERTIFICATE).then_some(SET_CERT_STREAM_PREFIX_LEN)
}

#[cfg(feature = "set-certificate")]
async fn continue_setcert_prefix<Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    _handle: u8,
    chunk: &[u8],
) -> SpdmResult<usize> {
    let large_msg_size = state.large_msg_ctx.state.large_msg_size as usize;
    let mut prefix_data = [0u8; super::STREAM_PREFIX_CAPACITY];
    let (prefix_len, consumed, complete) = {
        let Some(ActiveLargeRequest::Prefix(prefix)) = state.large_msg_ctx.active_request_mut()
        else {
            return Err(SPDM_INVALID_REQUEST);
        };
        let needed = SET_CERT_STREAM_PREFIX_LEN
            .checked_sub(prefix.len)
            .ok_or(SPDM_INVALID_REQUEST)?;
        let consumed = needed.min(chunk.len());
        if prefix.len + consumed > prefix.data.len() {
            return Err(SPDM_INVALID_REQUEST);
        }
        prefix.data[prefix.len..prefix.len + consumed].copy_from_slice(&chunk[..consumed]);
        prefix.len += consumed;
        prefix_data[..prefix.len].copy_from_slice(&prefix.data[..prefix.len]);
        (
            prefix.len,
            consumed,
            prefix.len >= SET_CERT_STREAM_PREFIX_LEN,
        )
    };
    if complete {
        let stream = set_certificate::start_set_certificate_stream(
            state,
            pal,
            io,
            large_msg_size,
            &prefix_data[..prefix_len],
        )
        .await?;
        state
            .large_msg_ctx
            .replace_active_request(ActiveLargeRequest::SetCertificate(stream))?;
    }
    Ok(consumed)
}

pub(crate) async fn abort_streaming_request_if_needed<Pal: SpdmPal, Vdm: SpdmVdmBackend>(
    state: &ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    vdm: &Vdm,
) {
    match state.large_msg_ctx.active_request() {
        #[cfg(feature = "set-certificate")]
        Some(ActiveLargeRequest::SetCertificate(stream)) => {
            set_certificate::abort_set_certificate_stream(state, pal, io, stream).await;
        }
        Some(ActiveLargeRequest::VendorDefined(_)) => {
            vdm.abort_streaming_request(pal, io).await;
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
async fn try_start_streaming_request<Pal: SpdmPal, Vdm: SpdmVdmBackend>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    vdm: &Vdm,
    handle: u8,
    large_msg_size: usize,
    first: &[u8],
    secure_session: bool,
) -> SpdmResult<bool> {
    let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(first).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(SPDM_INVALID_REQUEST);
    }
    match hdr.code {
        #[cfg(feature = "set-certificate")]
        ReqRespCode::SET_CERTIFICATE => {
            if secure_session {
                state.large_msg_ctx.init_streaming_request(
                    handle,
                    large_msg_size,
                    first.len(),
                    ActiveLargeRequest::Unsupported(SPDM_UNSUPPORTED_REQUEST),
                )?;
                return Ok(true);
            }
            let stream = set_certificate::start_set_certificate_stream(
                state,
                pal,
                io,
                large_msg_size,
                first,
            )
            .await?;
            state.large_msg_ctx.init_streaming_request(
                handle,
                large_msg_size,
                first.len(),
                ActiveLargeRequest::SetCertificate(stream),
            )?;
            Ok(true)
        }
        ReqRespCode::VENDOR_DEFINED_REQUEST => {
            let (vdm_hdr, rest) =
                VendorDefinedReqPdu::ref_from_prefix(body).map_err(|_| SPDM_INVALID_REQUEST)?;
            let vendor_id_len = vdm_hdr.vendor_id_len as usize;
            if vendor_id_len > 4 {
                return Ok(false);
            }
            let vendor_id = rest.get(..vendor_id_len).ok_or(SPDM_INVALID_REQUEST)?;
            let req_len_offset = vendor_id_len;
            let req_len_bytes = rest
                .get(req_len_offset..req_len_offset + 2)
                .ok_or(SPDM_INVALID_REQUEST)?;
            let req_len = u16::from_le_bytes([req_len_bytes[0], req_len_bytes[1]]) as usize;
            let payload_start = req_len_offset + 2;
            let payload = rest.get(payload_start..).ok_or(SPDM_INVALID_REQUEST)?;
            let expected = SpdmMsgHdrPdu::SIZE
                .checked_add(VendorDefinedReqPdu::SIZE)
                .and_then(|n| n.checked_add(vendor_id_len))
                .and_then(|n| n.checked_add(2))
                .and_then(|n| n.checked_add(req_len))
                .ok_or(SPDM_INVALID_REQUEST)?;
            if expected != large_msg_size || payload.len() > req_len {
                return Err(SPDM_INVALID_REQUEST);
            }
            let registry = VdmRegistry {
                standard_id: vdm_hdr.standard_id.get(),
                vendor_id,
                secure_session,
            };
            if !vdm.match_id(&registry) {
                return Ok(false);
            }
            if !vdm
                .start_streaming_request(req_len, payload, pal, io)
                .await?
            {
                return Ok(false);
            }
            let mut vendor_id_buf = [0u8; 4];
            vendor_id_buf[..vendor_id_len].copy_from_slice(vendor_id);
            state.large_msg_ctx.init_streaming_request(
                handle,
                large_msg_size,
                first.len(),
                ActiveLargeRequest::VendorDefined(VendorDefinedStreamState {
                    standard_id: vdm_hdr.standard_id.get(),
                    vendor_id: vendor_id_buf,
                    vendor_id_len: vdm_hdr.vendor_id_len,
                }),
            )?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[cfg(any(test, feature = "generic-large-request"))]
struct LargeRequestError {
    spdm: SpdmError,
    early_error: bool,
}

#[cfg(any(test, feature = "generic-large-request"))]
impl From<SpdmError> for LargeRequestError {
    fn from(spdm: SpdmError) -> Self {
        Self {
            spdm,
            early_error: false,
        }
    }
}

async fn build_final_chunk_send_ack<'a, Pal: SpdmPal, Vdm: SpdmVdmBackend>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    vdm: &Vdm,
    _secure_session: bool,
    handle: u8,
    chunk_seq_num: u16,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let len = state.large_msg_ctx.state.large_msg_size as usize;
    let mut response_to_large_request = [0u8; LARGE_REQUEST_RESPONSE_BUF_SIZE];
    let active = state.large_msg_ctx.active_request().copied();
    let (mut response_len, early_error) = match active {
        #[cfg(feature = "set-certificate")]
        Some(ActiveLargeRequest::SetCertificate(stream)) => {
            match set_certificate::finish_set_certificate_stream(state, pal, io, &stream).await {
                Ok(slot_id) => {
                    let bytes = [
                        state.version.to_u8(),
                        ReqRespCode::SET_CERTIFICATE_RSP.0,
                        slot_id,
                        0,
                    ];
                    response_to_large_request[..bytes.len()].copy_from_slice(&bytes);
                    (bytes.len(), false)
                }
                Err(spdm) => (
                    write_error_response_to_large_request(
                        &mut response_to_large_request,
                        state.version,
                        spdm,
                    ),
                    false,
                ),
            }
        }
        #[cfg(feature = "set-certificate")]
        Some(ActiveLargeRequest::Unsupported(spdm)) => (
            write_error_response_to_large_request(
                &mut response_to_large_request,
                state.version,
                spdm,
            ),
            false,
        ),
        Some(ActiveLargeRequest::VendorDefined(stream)) => {
            let vendor_id_len = stream.vendor_id_len as usize;
            let vendor_id = &stream.vendor_id[..vendor_id_len];
            let envelope_len = SpdmMsgHdrPdu::SIZE + 2 + 2 + 1 + vendor_id_len + 2;
            if envelope_len > response_to_large_request.len() {
                (
                    write_error_response_to_large_request(
                        &mut response_to_large_request,
                        state.version,
                        SPDM_UNSPECIFIED,
                    ),
                    false,
                )
            } else {
                let mut empty_large = [];
                let outcome = vdm
                    .finish_streaming_request(VdmResponseBuffer {
                        inline: &mut response_to_large_request[envelope_len..],
                        large: &mut empty_large,
                        alloc: pal,
                        io,
                    })
                    .await;
                match outcome {
                    Ok(VdmResponse::Inline(payload_len)) => {
                        let invalid_response = envelope_len + payload_len
                            > response_to_large_request.len()
                            || vendor_defined::write_vendor_defined_envelope(
                                state.version,
                                stream.standard_id,
                                vendor_id,
                                payload_len,
                                &mut response_to_large_request[..envelope_len],
                            )
                            .is_err();
                        if invalid_response {
                            (
                                write_error_response_to_large_request(
                                    &mut response_to_large_request,
                                    state.version,
                                    SPDM_UNSPECIFIED,
                                ),
                                false,
                            )
                        } else {
                            (envelope_len + payload_len, false)
                        }
                    }
                    _ => (
                        write_error_response_to_large_request(
                            &mut response_to_large_request,
                            state.version,
                            SPDM_UNSPECIFIED,
                        ),
                        false,
                    ),
                }
            }
        }
        _ if len < SpdmMsgHdrPdu::SIZE => (
            write_error_response_to_large_request(
                &mut response_to_large_request,
                state.version,
                SPDM_INVALID_REQUEST,
            ),
            false,
        ),
        #[cfg(any(test, feature = "generic-large-request"))]
        _ => match dispatch_large_request(
            state,
            pal,
            io,
            vdm,
            len,
            _secure_session,
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
        },
        #[cfg(not(any(test, feature = "generic-large-request")))]
        _ => (
            write_error_response_to_large_request(
                &mut response_to_large_request,
                state.version,
                SPDM_UNSUPPORTED_REQUEST,
            ),
            false,
        ),
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

#[cfg(any(test, feature = "generic-large-request"))]
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

    use caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::{
        CaliptraVdmCommand, CALIPTRA_VDM_COMMAND_VERSION, CALIPTRA_VENDOR_ID,
    };
    use caliptra_mcu_spdm_traits::{
        SpdmPalAlloc, SpdmPalIo, SpdmVdmBackend, VdmRegistry, VdmResponse, VdmResponseBuffer,
    };
    use futures::executor::block_on;
    use mcu_error::McuResult;
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

        async fn start_streaming_request<Alloc, Io>(
            &self,
            _req_len: usize,
            first: &[u8],
            _alloc: &Alloc,
            _io: &Io,
        ) -> McuResult<bool>
        where
            Alloc: SpdmPalAlloc,
            Io: SpdmPalIo,
        {
            assert_eq!(first.first().copied(), Some(CALIPTRA_VDM_COMMAND_VERSION));
            assert_eq!(
                first.get(1).copied(),
                Some(CaliptraVdmCommand::AuthorizeDebugUnlockToken as u8)
            );
            self.captured_token_payload
                .replace(Some(first[2..].to_vec()));
            Ok(true)
        }

        async fn continue_streaming_request<Alloc, Io>(
            &self,
            chunk: &[u8],
            _alloc: &Alloc,
            _io: &Io,
        ) -> McuResult<()>
        where
            Alloc: SpdmPalAlloc,
            Io: SpdmPalIo,
        {
            self.captured_token_payload
                .borrow_mut()
                .as_mut()
                .expect("streaming request started")
                .extend_from_slice(chunk);
            Ok(())
        }

        async fn finish_streaming_request<Alloc, Io>(
            &self,
            rsp: VdmResponseBuffer<'_, Alloc, Io>,
        ) -> McuResult<VdmResponse>
        where
            Alloc: SpdmPalAlloc,
            Io: SpdmPalIo,
        {
            rsp.inline[..3].copy_from_slice(&[
                CALIPTRA_VDM_COMMAND_VERSION,
                CaliptraVdmCommand::AuthorizeDebugUnlockToken as u8,
                0,
            ]);
            Ok(VdmResponse::Inline(3))
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

    struct BufferedOnlyVdmBackend {
        captured_token_payload: RefCell<Option<Vec<u8>>>,
    }

    impl BufferedOnlyVdmBackend {
        fn new() -> Self {
            Self {
                captured_token_payload: RefCell::new(None),
            }
        }
    }

    impl SpdmVdmBackend for BufferedOnlyVdmBackend {
        fn match_id(&self, registry: &VdmRegistry<'_>) -> bool {
            registry.standard_id == 0x0004 && registry.vendor_id == CALIPTRA_VENDOR_ID_BYTES
        }

        async fn start_streaming_request<Alloc, Io>(
            &self,
            _req_len: usize,
            _first: &[u8],
            _alloc: &Alloc,
            _io: &Io,
        ) -> McuResult<bool>
        where
            Alloc: SpdmPalAlloc,
            Io: SpdmPalIo,
        {
            Ok(false)
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
        assert!(state.large_msg_ctx.get_buffer().is_none());

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

    #[test]
    fn chunked_vendor_defined_debug_unlock_falls_back_when_streaming_declines() {
        let pal = TestPal::default();
        let mut state = chunking_state();
        let vdm = BufferedOnlyVdmBackend::new();

        let host_mailbox_payload = vec![0x5au8; 4 + 96];
        let large_req = vendor_defined_authorize_debug_unlock_request(&host_mailbox_payload);
        let (first, second) = large_req.split_at(64);
        let first_chunk = chunk_send_request(10, 0, false, Some(large_req.len()), first);
        let second_chunk = chunk_send_request(10, 1, true, None, second);

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
                10,
                0,
                0,
            ]
        );
        assert!(state.large_msg_ctx.request_in_progress());
        assert!(state.large_msg_ctx.get_buffer().is_some());

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
        assert_eq!(rsp[1], ReqRespCode::CHUNK_SEND_ACK.0);
    }
}

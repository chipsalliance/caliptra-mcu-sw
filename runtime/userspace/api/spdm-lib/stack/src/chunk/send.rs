// Licensed under the Apache-2.0 license

//! CHUNK_SEND large-request reassembly.

use caliptra_mcu_spdm_codec::{
    CapFlags, CapabilitiesBody, ChunkSendAckBodyV13, ChunkSendAckBodyV14, ChunkSendReqBody,
    ReqRespCode, SpdmMsgHdrPdu, SpdmVersion, VendorDefinedReqPdu, VendorDefinedRspPdu, WireWriter,
    CHUNK_ACK_ATTR_EARLY_ERROR, CHUNK_ATTR_LAST_CHUNK,
};
use caliptra_mcu_spdm_traits::{
    PalBytes, SpdmPal, SpdmPalAlloc, SpdmPalIoTransport, SpdmVdmBackend, VdmRegistry, VdmResponse,
    VdmResponseBuffer,
};
use zerocopy::{
    little_endian::{U16, U32},
    FromBytes,
};

#[cfg(feature = "set-certificate")]
use super::StreamPrefixState;
#[cfg(any(test, feature = "generic-large-request"))]
use super::WipeOnDrop;
use super::{start_buffered_large_response, ActiveLargeRequest};
use crate::build::{alloc_padded, build_error_response, encode_error_response};
use crate::error::*;
#[cfg(any(test, feature = "generic-large-request"))]
use crate::key_exchange;
#[cfg(feature = "set-certificate")]
use crate::set_certificate;
use crate::stack::{ConnectionState, Phase, Sessions};
use crate::vendor_defined;

struct ChunkInfo {
    handle: u8,
    chunk_seq_num: u16,
    complete: bool,
}

/// Whether the bytes a transport delivered past the SPDM message are only framing.
///
/// A `CHUNK_SEND` frame carries `chunk_size` bytes of SPDM payload, but the
/// transport may hand up a longer buffer because its data units are coarser than
/// a byte. DOE objects are DWORD-granular, so a 634-byte message arrives as 636
/// bytes; requiring an exact match rejects every chunk whose length is not
/// already aligned.
///
/// `delivered` must be `>= payload`; callers establish that by slicing first.
fn trailing_slack_is_transport_padding<Pal: SpdmPal>(
    pal: &Pal,
    delivered: usize,
    payload: usize,
) -> bool {
    // TODO `send_len_alignment` is currently named for the outbound path,
    // but it describes the transport's frame granularity in both directions.
    // This applies to both the `SpdmPalIoTransport` and `SpdmPalTransport`.
    delivered - payload < pal.send_len_alignment()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_chunk_send<
    'a,
    Pal: SpdmPal,
    Vdm: SpdmVdmBackend,
    const MAX_SESSIONS: usize,
>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    sessions: &mut Sessions<Pal, MAX_SESSIONS>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    vdm: &Vdm,
    req: &[u8],
    session_id: Option<u32>,
    set_certificate_allowed: bool,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let result = process_chunk_send(
        state,
        pal,
        io,
        vdm,
        req,
        session_id,
        set_certificate_allowed,
    )
    .await;
    match result {
        Ok(info) => {
            if info.complete {
                let rsp = build_final_chunk_send_ack(
                    state,
                    sessions,
                    pal,
                    io,
                    vdm,
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
            abort_active_streaming_request(state, pal, io, vdm).await;
            let mut error = [0u8; 4];
            let error_len = encode_error_response(&mut error, state.version, SPDM_INVALID_REQUEST)?;
            state.reset_chunk_assembly();
            build_chunk_send_ack(
                pal,
                io,
                state.version,
                true,
                handle,
                chunk_seq_num,
                &error[..error_len],
            )
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
    let raw_len = if version <= SpdmVersion::V13 {
        head + SpdmMsgHdrPdu::SIZE + ChunkSendAckBodyV13::SIZE + response_to_large_request.len()
    } else {
        head + SpdmMsgHdrPdu::SIZE + ChunkSendAckBodyV14::SIZE + response_to_large_request.len()
    };
    let mut rsp = alloc_padded(pal, io, raw_len)?;
    let mut w = WireWriter::new(&mut rsp[head..]);
    w.write(&SpdmMsgHdrPdu::new(version, ReqRespCode::CHUNK_SEND_ACK))?;
    if version <= SpdmVersion::V13 {
        w.write(&ChunkSendAckBodyV13 {
            chunk_receiver_attr: if early_error {
                CHUNK_ACK_ATTR_EARLY_ERROR
            } else {
                0
            },
            handle,
            chunk_seq_num: U16::new(chunk_seq_num),
        })?;
    } else {
        w.write(&ChunkSendAckBodyV14 {
            chunk_receiver_attr: if early_error {
                CHUNK_ACK_ATTR_EARLY_ERROR
            } else {
                0
            },
            handle,
            chunk_seq_num: U32::new(chunk_seq_num as u32),
        })?;
    }
    w.write_bytes(response_to_large_request)?;
    Ok(rsp)
}

fn build_chunk_send_error_ack<'a, Pal: SpdmPal>(
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    version: SpdmVersion,
    handle: u8,
    chunk_seq_num: u16,
    error: SpdmError,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let mut response = [0u8; SpdmMsgHdrPdu::SIZE + 2 + CALIPTRA_EXTENDED_ERROR_SIZE];
    let response_len = encode_error_response(&mut response[..], version, error)?;
    build_chunk_send_ack(
        pal,
        io,
        version,
        false,
        handle,
        chunk_seq_num,
        &response[..response_len],
    )
}

/// Staging buffer size for `ResponseToLargeRequest` inside CHUNK_SEND_ACK.
const LARGE_REQUEST_RESPONSE_BUF_SIZE: usize = 512;
const DEBUG_UNLOCK_STANDARD_ID: u16 = 0x0004;
const DEBUG_UNLOCK_VENDOR_ID: [u8; 4] =
    caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::CALIPTRA_VENDOR_ID.to_le_bytes();

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
    session_id: Option<u32>,
    set_certificate_allowed: bool,
) -> Result<ChunkInfo, ChunkProcessError> {
    if state.large_msg_ctx.response_in_progress()
        || (state.phase as u8) < (Phase::AfterCapabilities as u8)
        || !state.chunking_enabled()
    {
        return Err(ChunkProcessError::Spdm(SPDM_UNEXPECTED_REQUEST));
    }

    if state.large_msg_ctx.request_in_progress()
        && state.large_msg_ctx.state.session_id != session_id
    {
        return Err(ChunkProcessError::Spdm(SPDM_UNEXPECTED_REQUEST));
    }

    // Incoming chunks use our DataTransferSize; the peer's limit is outbound.
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
            session_id,
            set_certificate_allowed,
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
    session_id: Option<u32>,
    set_certificate_allowed: bool,
) -> Result<(), ChunkProcessError> {
    let Some(size_bytes) = rest.first_chunk::<4>() else {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    };
    let large_msg_size = u32::from_le_bytes(*size_bytes) as usize;
    let chunk_data = &rest[4..];

    // `chunk_size` is authoritative for the SPDM message length; anything past it
    // is transport framing, not SPDM. Taking the slice first also proves
    // `chunk_data.len() >= chunk_size`, so the slack below cannot underflow.
    let Some(chunk) = chunk_data.get(..chunk_size) else {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    };
    if !trailing_slack_is_transport_padding(pal, chunk_data.len(), chunk_size) {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    }
    let min_chunk_size = CapabilitiesBody::MIN_DATA_TRANSFER_SIZE as usize
        - SpdmMsgHdrPdu::SIZE
        - ChunkSendReqBody::SIZE
        - 4;

    // CHUNK_SEND is valid only above our single-frame limit and within our
    // endpoint-wide logical request limit.
    let invalid = chunk_seq_num != 0
        || last_chunk
        || chunk_size < min_chunk_size
        || chunk_size >= large_msg_size
        || large_msg_size <= pal.mtu()
        || large_msg_size > pal.max_inbound_spdm_request_size();
    if invalid {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    }
    #[cfg(feature = "set-certificate")]
    {
        if let Some(required_len) = required_stream_prefix_len(chunk) {
            if !set_certificate_allowed {
                return Err(ChunkProcessError::Early {
                    handle,
                    chunk_seq_num,
                });
            }
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
                    session_id,
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
        session_id,
        set_certificate_allowed,
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
        // Only non-streamed requests consume the persistent scratch buffer.
        if large_msg_size > pal.large_buffered_msg_capacity() {
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
            .init_request(handle, large_msg_size, chunk, rent_buf, session_id)
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

    // See `process_first_chunk`: `chunk_size` bounds the SPDM message, and the
    // slice proves `rest.len() >= chunk_size` before the slack is computed.
    let Some(chunk) = rest.get(..chunk_size) else {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    };
    if !trailing_slack_is_transport_padding(pal, rest.len(), chunk_size) {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    }
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
        Some(ActiveLargeRequest::AuthorizeDebugUnlockToken { .. }) => {
            vdm.continue_authorize_debug_unlock_token_stream(chunk, pal, io)
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
fn required_stream_prefix_len(first: &[u8]) -> Option<usize> {
    if first.len() >= SET_CERT_STREAM_PREFIX_LEN {
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

pub(crate) async fn abort_active_streaming_request<Pal: SpdmPal, Vdm: SpdmVdmBackend>(
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
        Some(ActiveLargeRequest::AuthorizeDebugUnlockToken { .. }) => {
            vdm.abort_authorize_debug_unlock_token_stream(pal, io).await;
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
    session_id: Option<u32>,
    _set_certificate_allowed: bool,
) -> SpdmResult<bool> {
    let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(first).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(SPDM_INVALID_REQUEST);
    }
    match hdr.code {
        #[cfg(feature = "set-certificate")]
        ReqRespCode::SET_CERTIFICATE => {
            if !_set_certificate_allowed {
                return Err(SPDM_UNEXPECTED_REQUEST);
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
                session_id,
            )?;
            Ok(true)
        }
        ReqRespCode::VENDOR_DEFINED_REQUEST => {
            let (vdm_hdr, rest) =
                VendorDefinedReqPdu::ref_from_prefix(body).map_err(|_| SPDM_INVALID_REQUEST)?;
            let is_large = vdm_hdr.param1.large();
            if is_large
                && (state.version < SpdmVersion::V14
                    || !state.advertised_cap_flags.contains(CapFlags::LARGE_RESP)
                    || !state.peer_cap_flags.contains(CapFlags::LARGE_RESP))
            {
                return Err(SPDM_INVALID_REQUEST);
            }
            if vdm_hdr.param1.reserved() != 0 || vdm_hdr.param2 != 0 {
                return Err(SPDM_INVALID_REQUEST);
            }
            let vendor_id_len = vdm_hdr.vendor_id_len as usize;
            if vendor_id_len > 4 {
                return Ok(false);
            }
            let vendor_id = rest.get(..vendor_id_len).ok_or(SPDM_INVALID_REQUEST)?;
            let req_len_offset = vendor_id_len;
            let (req_len, payload_start) = if is_large {
                let rsvd_bytes = rest
                    .get(req_len_offset..req_len_offset + 2)
                    .ok_or(SPDM_INVALID_REQUEST)?;
                if u16::from_le_bytes([rsvd_bytes[0], rsvd_bytes[1]]) != 0 {
                    return Err(SPDM_INVALID_REQUEST);
                }
                let req_len_bytes = rest
                    .get(req_len_offset + 2..req_len_offset + 6)
                    .ok_or(SPDM_INVALID_REQUEST)?;
                let req_len = u32::from_le_bytes([
                    req_len_bytes[0],
                    req_len_bytes[1],
                    req_len_bytes[2],
                    req_len_bytes[3],
                ]) as usize;
                (req_len, req_len_offset + 6)
            } else {
                let req_len_bytes = rest
                    .get(req_len_offset..req_len_offset + 2)
                    .ok_or(SPDM_INVALID_REQUEST)?;
                let req_len = u16::from_le_bytes([req_len_bytes[0], req_len_bytes[1]]) as usize;
                (req_len, req_len_offset + 2)
            };
            let payload = rest.get(payload_start..).ok_or(SPDM_INVALID_REQUEST)?;
            let expected = SpdmMsgHdrPdu::SIZE
                .checked_add(VendorDefinedReqPdu::SIZE)
                .and_then(|n| n.checked_add(vendor_id_len))
                .and_then(|n| n.checked_add(if is_large { 6 } else { 2 }))
                .and_then(|n| n.checked_add(req_len))
                .ok_or(SPDM_INVALID_REQUEST)?;
            if expected != large_msg_size || payload.len() > req_len {
                return Err(SPDM_INVALID_REQUEST);
            }
            let registry = VdmRegistry {
                standard_id: vdm_hdr.standard_id.get(),
                vendor_id,
                secure_session: session_id.is_some(),
            };
            if !vdm.match_id(&registry) {
                return Ok(false);
            }
            if !vdm
                .start_authorize_debug_unlock_token_stream(req_len, payload, pal, io)
                .await?
            {
                return Ok(false);
            }
            state.large_msg_ctx.init_streaming_request(
                handle,
                large_msg_size,
                first.len(),
                ActiveLargeRequest::AuthorizeDebugUnlockToken { is_large },
                session_id,
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

// `sessions` is consumed only by the buffered KEY_EXCHANGE dispatch, which is
// compiled out when neither `test` nor `generic-large-request` is enabled.
#[cfg_attr(
    not(any(test, feature = "generic-large-request")),
    allow(unused_variables)
)]
async fn build_final_chunk_send_ack<
    'a,
    Pal: SpdmPal,
    Vdm: SpdmVdmBackend,
    const MAX_SESSIONS: usize,
>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    sessions: &mut Sessions<Pal, MAX_SESSIONS>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    vdm: &Vdm,
    handle: u8,
    chunk_seq_num: u16,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let active = state.large_msg_ctx.active_request().copied();
    let len = state.large_msg_ctx.state.large_msg_size as usize;

    #[cfg(any(test, feature = "generic-large-request"))]
    if matches!(active, Some(ActiveLargeRequest::Buffered)) {
        let is_key_exchange = state
            .large_msg_ctx
            .get_buffer()
            .and_then(|buf| buf.get(..len))
            .and_then(|req| SpdmMsgHdrPdu::ref_from_prefix(req).ok())
            .is_some_and(|(hdr, _)| hdr.code == ReqRespCode::KEY_EXCHANGE);
        // KEY_EXCHANGE_RSP may exceed the inline capacity of CHUNK_SEND_ACK.
        // Handle it directly so it can return standalone ERROR(LargeResponse).
        if is_key_exchange {
            return build_final_chunked_key_exchange_response(
                state,
                sessions,
                pal,
                io,
                handle,
                chunk_seq_num,
            )
            .await;
        }
    }

    let mut response_to_large_request =
        match SpdmPalAlloc::alloc(pal, io, [0u8; LARGE_REQUEST_RESPONSE_BUF_SIZE]) {
            Ok(response) => response,
            Err(_) => {
                match active {
                    #[cfg(any(test, feature = "generic-large-request"))]
                    Some(ActiveLargeRequest::Buffered) => {}
                    _ => abort_active_streaming_request(state, pal, io, vdm).await,
                }
                state.reset_chunk_assembly();
                return build_chunk_send_error_ack(
                    pal,
                    io,
                    state.version,
                    handle,
                    chunk_seq_num,
                    SPDM_UNSPECIFIED,
                )
                .map_err(|_| SPDM_UNSPECIFIED);
            }
        };

    let (response_len, early_error) = match active {
        #[cfg(any(test, feature = "generic-large-request"))]
        Some(ActiveLargeRequest::Buffered) => {
            finish_buffered_request(state, pal, io, vdm, len, &mut response_to_large_request[..])
                .await?
        }
        active => {
            finish_streamed_request(
                state,
                pal,
                io,
                vdm,
                active,
                len,
                &mut response_to_large_request[..],
            )
            .await?
        }
    };

    deliver_final_chunk_response(
        state,
        pal,
        io,
        handle,
        chunk_seq_num,
        early_error,
        &response_to_large_request[..response_len],
    )
}

#[cfg(any(test, feature = "generic-large-request"))]
async fn finish_buffered_request<Pal: SpdmPal, Vdm: SpdmVdmBackend>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    vdm: &Vdm,
    len: usize,
    response_to_large_request: &mut [u8],
) -> SpdmResult<(usize, bool)> {
    let secure_session = state.large_msg_ctx.state.session_id.is_some();
    match dispatch_buffered_request(
        state,
        pal,
        io,
        vdm,
        len,
        secure_session,
        response_to_large_request,
    )
    .await
    {
        Ok(response_len) => Ok((response_len, false)),
        Err(err) => Ok((
            encode_error_response(response_to_large_request, state.version, err.spdm)?,
            err.early_error,
        )),
    }
}

async fn finish_streamed_request<Pal: SpdmPal, Vdm: SpdmVdmBackend>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    vdm: &Vdm,
    active: Option<ActiveLargeRequest>,
    len: usize,
    response_to_large_request: &mut [u8],
) -> SpdmResult<(usize, bool)> {
    Ok(match active {
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
                Err(spdm) => {
                    set_certificate::abort_set_certificate_stream(state, pal, io, &stream).await;
                    (
                        encode_error_response(
                            &mut response_to_large_request[..],
                            state.version,
                            spdm,
                        )?,
                        false,
                    )
                }
            }
        }
        Some(ActiveLargeRequest::AuthorizeDebugUnlockToken { is_large }) => {
            const RSP_ENVELOPE_OVERHEAD: usize =
                VendorDefinedRspPdu::SIZE + core::mem::size_of::<u16>();
            const LARGE_RSP_ENVELOPE_OVERHEAD: usize = VendorDefinedRspPdu::SIZE
                + core::mem::size_of::<u16>()
                + core::mem::size_of::<u32>();

            let vendor_id = &DEBUG_UNLOCK_VENDOR_ID;
            let envelope_overhead = if is_large {
                LARGE_RSP_ENVELOPE_OVERHEAD
            } else {
                RSP_ENVELOPE_OVERHEAD
            };
            let envelope_len = SpdmMsgHdrPdu::SIZE + envelope_overhead + vendor_id.len();
            if envelope_len > response_to_large_request.len() {
                (
                    encode_error_response(
                        &mut response_to_large_request[..],
                        state.version,
                        SPDM_UNSPECIFIED,
                    )?,
                    false,
                )
            } else {
                let mut empty_large = [];
                let outcome = vdm
                    .finish_authorize_debug_unlock_token_stream(VdmResponseBuffer {
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
                                DEBUG_UNLOCK_STANDARD_ID,
                                vendor_id,
                                payload_len,
                                is_large,
                                &mut response_to_large_request[..envelope_len],
                            )
                            .is_err();
                        if invalid_response {
                            (
                                encode_error_response(
                                    &mut response_to_large_request[..],
                                    state.version,
                                    SPDM_UNSPECIFIED,
                                )?,
                                false,
                            )
                        } else {
                            (envelope_len + payload_len, false)
                        }
                    }
                    _ => (
                        encode_error_response(
                            &mut response_to_large_request[..],
                            state.version,
                            SPDM_UNSPECIFIED,
                        )?,
                        false,
                    ),
                }
            }
        }
        _ if len < SpdmMsgHdrPdu::SIZE => (
            encode_error_response(
                &mut response_to_large_request[..],
                state.version,
                SPDM_INVALID_REQUEST,
            )?,
            false,
        ),
        #[cfg(any(test, feature = "generic-large-request"))]
        _ => (
            encode_error_response(
                &mut response_to_large_request[..],
                state.version,
                SPDM_INVALID_REQUEST,
            )?,
            false,
        ),
        #[cfg(not(any(test, feature = "generic-large-request")))]
        _ => (
            encode_error_response(
                &mut response_to_large_request[..],
                state.version,
                SPDM_UNSUPPORTED_REQUEST,
            )?,
            false,
        ),
    })
}

fn deliver_final_chunk_response<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    handle: u8,
    chunk_seq_num: u16,
    early_error: bool,
    response_to_large_request: &[u8],
) -> SpdmResult<PalBytes<'a, Pal>> {
    let ack_body_size = if state.version <= SpdmVersion::V13 {
        ChunkSendAckBodyV13::SIZE
    } else {
        ChunkSendAckBodyV14::SIZE
    };
    let max_response_len = state
        .effective_data_transfer_size(pal)
        .saturating_sub(SpdmMsgHdrPdu::SIZE + ack_body_size);
    if let Some(handle) = state.large_msg_ctx.response().map(|a| a.handle) {
        return build_error_response(
            pal,
            io,
            state.version,
            SPDM_LARGE_RESPONSE.with_extended_data([handle]),
        );
    }

    let response_len = response_to_large_request.len();
    if response_len > max_response_len {
        let mut response = pal.alloc_large_buf(response_len)?;
        response
            .get_mut(..response_len)
            .ok_or(SPDM_UNSPECIFIED)?
            .copy_from_slice(response_to_large_request);
        state.reset_chunk_assembly();
        state.large_msg_ctx.set_buffer(response);
        return match start_buffered_large_response(state, pal, io, response_len) {
            Ok((response, _)) => Ok(response),
            Err(err) => {
                state.reset_chunk_assembly();
                Err(err)
            }
        };
    }

    build_chunk_send_ack(
        pal,
        io,
        state.version,
        early_error,
        handle,
        chunk_seq_num,
        response_to_large_request,
    )
}

#[cfg(any(test, feature = "generic-large-request"))]
async fn build_final_chunked_key_exchange_response<'a, Pal: SpdmPal, const MAX_SESSIONS: usize>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    sessions: &mut Sessions<Pal, MAX_SESSIONS>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    handle: u8,
    chunk_seq_num: u16,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let request_len = state.large_msg_ctx.state.large_msg_size as usize;
    let secure_session = state.large_msg_ctx.state.session_id.is_some();
    let guard = WipeOnDrop {
        buf: state.large_msg_ctx.take_buffer(),
    };

    let validation = guard.as_ref().and_then(|buf| {
        let req = buf.get(..request_len).ok_or(SPDM_INVALID_REQUEST)?;
        let (hdr, _) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
        if hdr.version != state.version.to_u8() {
            return Err(SPDM_VERSION_MISMATCH);
        }
        if hdr.code != ReqRespCode::KEY_EXCHANGE {
            return Err(SPDM_INVALID_REQUEST);
        }
        if secure_session {
            return Err(SPDM_UNEXPECTED_REQUEST);
        }
        Ok(())
    });

    if let Err(err) = validation {
        drop(guard);
        state.reset_chunk_assembly();
        return build_chunk_send_error_ack(pal, io, state.version, handle, chunk_seq_num, err);
    }

    // The handler may now register the response in the same large-message
    // context. It owns the request guard and releases it after transcript use.
    state.large_msg_ctx.reset();
    let ack_body_size = if state.version <= SpdmVersion::V13 {
        ChunkSendAckBodyV13::SIZE
    } else {
        ChunkSendAckBodyV14::SIZE
    };
    let inline_response_limit = state
        .effective_data_transfer_size(pal)
        .saturating_sub(SpdmMsgHdrPdu::SIZE + ack_body_size);
    match key_exchange::handle_buffered_key_exchange_req(
        state,
        sessions,
        pal,
        io,
        guard,
        request_len,
        inline_response_limit,
    )
    .await
    {
        Ok((resp, spdm_len)) => {
            if state.large_msg_ctx.response_in_progress() {
                // SPDM 1.4 requires ERROR(LargeResponse) as a standalone
                // response, not nested in ResponseToLargeRequest.
                return Ok(resp);
            }

            let head = pal.header_size();
            let spdm = resp.get(head..head + spdm_len).ok_or(SPDM_UNSPECIFIED)?;
            build_chunk_send_ack(pal, io, state.version, false, handle, chunk_seq_num, spdm)
        }
        Err(err) => build_chunk_send_error_ack(pal, io, state.version, handle, chunk_seq_num, err),
    }
}

#[cfg(any(test, feature = "generic-large-request"))]
async fn dispatch_buffered_request<Pal: SpdmPal, Vdm: SpdmVdmBackend>(
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
        // Handled before allocating the inline CHUNK_SEND_ACK response buffer.
        ReqRespCode::KEY_EXCHANGE => Err(SPDM_UNEXPECTED_REQUEST.into()),
        _ => Err(SPDM_UNSUPPORTED_REQUEST.into()),
    }
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
    use caliptra_mcu_spdm_codec::{
        KeyExchangeReqBodyFixed, ECC_P384_SIGNATURE_SIZE, ECDH_P384_EXCHANGE_DATA_SIZE,
        KEY_EXCHANGE_RANDOM_DATA_LEN, KEY_EXCHANGE_RSP_FIXED_BODY_SIZE, SHA384_HASH_SIZE,
    };
    use caliptra_mcu_spdm_traits::{
        SpdmPalAlloc, SpdmPalIo, SpdmVdmBackend, VdmRegistry, VdmResponse, VdmResponseBuffer,
    };
    use futures::executor::block_on;
    use mcu_error::McuResult;
    use std::vec;
    use std::vec::Vec;
    use zerocopy::IntoBytes;

    use super::*;

    use super::support::{chunk_send_request, chunking_state, TestHashState, TestIo, TestPal};

    const CALIPTRA_VENDOR_ID_BYTES: [u8; 4] = CALIPTRA_VENDOR_ID.to_le_bytes();

    /// Empty session manager for tests that exercise non-KEY_EXCHANGE chunked requests.
    fn test_sessions() -> Sessions<TestPal, 1> {
        crate::session::SessionManager::new()
    }

    fn key_exchange_request(exchange_data_size: usize) -> Vec<u8> {
        let fixed = KeyExchangeReqBodyFixed {
            meas_summary_hash_type: 0,
            slot_id: 0,
            req_session_id: 0x1234u16.to_le_bytes(),
            session_policy: 0,
            _reserved: 0,
            random_data: [0x5a; KEY_EXCHANGE_RANDOM_DATA_LEN],
        };
        let mut request = vec![SpdmVersion::V14.to_u8(), ReqRespCode::KEY_EXCHANGE.0];
        request.extend_from_slice(fixed.as_bytes());
        request.resize(request.len() + exchange_data_size, 0x3c);
        request.extend_from_slice(&0u16.to_le_bytes());
        request
    }

    fn init_buffered_key_exchange(
        state: &mut ConnectionState<TestHashState, Vec<u8>>,
        request: &[u8],
        handle: u8,
    ) {
        state
            .large_msg_ctx
            .init_request(
                handle,
                request.len(),
                request,
                vec![0u8; request.len()],
                None,
            )
            .unwrap();
    }

    #[test]
    fn buffered_key_exchange_inline_response_is_wrapped_in_ack() {
        let pal = TestPal {
            large_buffered_msg_capacity: 8192,
            typed_alloc_error: Some(mcu_error::codes::OUT_OF_MEMORY),
            ..Default::default()
        };
        let io = TestIo::message(Vec::new());
        let mut state = chunking_state();
        state.version = SpdmVersion::V14;
        block_on(state.transcript.append_vca(&pal, &io, &[0xaa])).unwrap();
        let request = key_exchange_request(ECDH_P384_EXCHANGE_DATA_SIZE);
        init_buffered_key_exchange(&mut state, &request, 7);
        let mut sessions = test_sessions();
        let vdm = CaptureVdmBackend::new();

        let response = block_on(build_final_chunk_send_ack(
            &mut state,
            &mut sessions,
            &pal,
            &io,
            &vdm,
            7,
            0,
        ))
        .unwrap();

        assert_eq!(response[1], ReqRespCode::CHUNK_SEND_ACK.0);
        let key_exchange_rsp_start = SpdmMsgHdrPdu::SIZE + ChunkSendAckBodyV14::SIZE;
        assert_eq!(
            response[key_exchange_rsp_start + 1],
            ReqRespCode::KEY_EXCHANGE_RSP.0
        );
        let exchange_data_start =
            key_exchange_rsp_start + SpdmMsgHdrPdu::SIZE + KEY_EXCHANGE_RSP_FIXED_BODY_SIZE;
        assert!(
            response[exchange_data_start..exchange_data_start + ECDH_P384_EXCHANGE_DATA_SIZE]
                .iter()
                .all(|&byte| byte == 0x4d)
        );
        assert!(!state.large_msg_ctx.response_in_progress());
    }

    #[test]
    fn buffered_key_exchange_accounts_for_ack_overhead() {
        let pal = TestPal {
            large_buffered_msg_capacity: 8192,
            ..Default::default()
        };
        let io = TestIo::message(Vec::new());
        let mut state = chunking_state();
        state.version = SpdmVersion::V14;
        state.peer_data_transfer_size = (SpdmMsgHdrPdu::SIZE
            + KEY_EXCHANGE_RSP_FIXED_BODY_SIZE
            + ECDH_P384_EXCHANGE_DATA_SIZE
            + 2
            + ECC_P384_SIGNATURE_SIZE
            + SHA384_HASH_SIZE) as u32;
        state.peer_max_spdm_msg_size = 8192;
        block_on(state.transcript.append_vca(&pal, &io, &[0xaa])).unwrap();
        let request = key_exchange_request(ECDH_P384_EXCHANGE_DATA_SIZE);
        init_buffered_key_exchange(&mut state, &request, 9);
        let mut sessions = test_sessions();
        let vdm = CaptureVdmBackend::new();

        let response = block_on(build_final_chunk_send_ack(
            &mut state,
            &mut sessions,
            &pal,
            &io,
            &vdm,
            9,
            0,
        ))
        .unwrap();

        assert_eq!(response[1], ReqRespCode::ERROR.0);
        assert_eq!(response[2], SPDM_LARGE_RESPONSE.spec_byte());
        assert!(state.large_msg_ctx.response_in_progress());
    }

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

        async fn start_authorize_debug_unlock_token_stream<Alloc, Io>(
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

        async fn continue_authorize_debug_unlock_token_stream<Alloc, Io>(
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

        async fn finish_authorize_debug_unlock_token_stream<Alloc, Io>(
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

    struct OversizedResponseVdmBackend;

    impl SpdmVdmBackend for OversizedResponseVdmBackend {
        fn match_id(&self, registry: &VdmRegistry<'_>) -> bool {
            registry.standard_id == 0x0004 && registry.vendor_id == CALIPTRA_VENDOR_ID_BYTES
        }

        async fn start_authorize_debug_unlock_token_stream<Alloc, Io>(
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
            _req: &[u8],
            rsp: VdmResponseBuffer<'_, Alloc, Io>,
        ) -> McuResult<VdmResponse>
        where
            Alloc: SpdmPalAlloc,
            Io: SpdmPalIo,
        {
            const RESPONSE_SIZE: usize = 40;
            rsp.inline[..RESPONSE_SIZE].fill(0x5a);
            Ok(VdmResponse::Inline(RESPONSE_SIZE))
        }
    }

    impl SpdmVdmBackend for BufferedOnlyVdmBackend {
        fn match_id(&self, registry: &VdmRegistry<'_>) -> bool {
            registry.standard_id == 0x0004 && registry.vendor_id == CALIPTRA_VENDOR_ID_BYTES
        }

        async fn start_authorize_debug_unlock_token_stream<Alloc, Io>(
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
        let pal = TestPal {
            mtu: 96,
            ..TestPal::default()
        };
        let mut state = chunking_state();
        let mut sessions = test_sessions();
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
            &mut sessions,
            &pal,
            &first_io,
            &vdm,
            &first_chunk,
            None,
            true,
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
            &mut sessions,
            &pal,
            &second_io,
            &vdm,
            &second_chunk,
            None,
            true,
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
    fn final_response_allocation_failure_returns_ack_and_resets_request() {
        let pal = TestPal {
            mtu: 96,
            typed_alloc_error: Some(mcu_error::codes::OUT_OF_MEMORY),
            ..TestPal::default()
        };
        let mut state = chunking_state();
        let mut sessions = test_sessions();
        let vdm = CaptureVdmBackend::new();
        let large_req = vendor_defined_authorize_debug_unlock_request(&[0x5a; 96]);
        let (first, second) = large_req.split_at(64);
        let first_chunk = chunk_send_request(14, 0, false, Some(large_req.len()), first);
        let second_chunk = chunk_send_request(14, 1, true, None, second);

        let first_io = TestIo::message(first_chunk.clone());
        block_on(handle_chunk_send(
            &mut state,
            &mut sessions,
            &pal,
            &first_io,
            &vdm,
            &first_chunk,
            None,
            true,
        ))
        .unwrap();
        assert!(state.large_msg_ctx.request_in_progress());

        let second_io = TestIo::message(second_chunk.clone());
        let rsp = block_on(handle_chunk_send(
            &mut state,
            &mut sessions,
            &pal,
            &second_io,
            &vdm,
            &second_chunk,
            None,
            true,
        ))
        .unwrap();

        assert!(!state.large_msg_ctx.request_in_progress());
        assert_eq!(
            &rsp[..],
            &[
                SpdmVersion::V12.to_u8(),
                ReqRespCode::CHUNK_SEND_ACK.0,
                0,
                14,
                1,
                0,
                SpdmVersion::V12.to_u8(),
                ReqRespCode::ERROR.0,
                SPDM_UNSPECIFIED.spec_byte(),
                0,
            ]
        );
    }

    #[test]
    fn oversized_response_to_large_request_is_buffered() {
        let pal = TestPal {
            mtu: 96,
            ..TestPal::default()
        };
        let mut state = chunking_state();
        let mut sessions = test_sessions();
        state.peer_data_transfer_size = CapabilitiesBody::MIN_DATA_TRANSFER_SIZE;
        let vdm = OversizedResponseVdmBackend;
        let large_req = vendor_defined_authorize_debug_unlock_request(&[0x5a; 96]);
        let (first, second) = large_req.split_at(64);
        let first_chunk = chunk_send_request(15, 0, false, Some(large_req.len()), first);
        let second_chunk = chunk_send_request(15, 1, true, None, second);

        let first_io = TestIo::message(first_chunk.clone());
        block_on(handle_chunk_send(
            &mut state,
            &mut sessions,
            &pal,
            &first_io,
            &vdm,
            &first_chunk,
            None,
            true,
        ))
        .unwrap();

        let second_io = TestIo::message(second_chunk.clone());
        let rsp = block_on(handle_chunk_send(
            &mut state,
            &mut sessions,
            &pal,
            &second_io,
            &vdm,
            &second_chunk,
            None,
            true,
        ))
        .unwrap();

        assert_eq!(rsp[1], ReqRespCode::ERROR.0);
        assert_eq!(rsp[2], SPDM_LARGE_RESPONSE.spec_byte());
        let active = state.large_msg_ctx.response().unwrap();
        assert_eq!(rsp[4], active.handle);
        assert!(
            active.response_size
                > state.effective_data_transfer_size(&pal)
                    - SpdmMsgHdrPdu::SIZE
                    - ChunkSendAckBodyV13::SIZE
        );
        let response = state.large_msg_ctx.get_buffer().unwrap();
        assert_eq!(response[0], SpdmVersion::V12.to_u8());
        assert_eq!(response[1], ReqRespCode::VENDOR_DEFINED_RESPONSE.0);
    }

    #[test]
    fn incoming_chunk_uses_local_data_transfer_size() {
        let pal = TestPal {
            mtu: 96,
            max_inbound_spdm_request_size: 256,
            ..TestPal::default()
        };
        let mut state = chunking_state();
        let mut sessions = test_sessions();
        state.peer_data_transfer_size = CapabilitiesBody::MIN_DATA_TRANSFER_SIZE;
        let vdm = CaptureVdmBackend::new();

        let host_mailbox_payload = vec![0x5au8; 4 + 96];
        let large_req = vendor_defined_authorize_debug_unlock_request(&host_mailbox_payload);
        assert!(large_req.len() > pal.mtu());

        let first_chunk = chunk_send_request(10, 0, false, Some(large_req.len()), &large_req[..64]);
        assert!(first_chunk.len() > state.peer_data_transfer_size as usize);
        assert!(first_chunk.len() <= pal.mtu());

        let first_io = TestIo::message(first_chunk.clone());
        let rsp = block_on(handle_chunk_send(
            &mut state,
            &mut sessions,
            &pal,
            &first_io,
            &vdm,
            &first_chunk,
            None,
            true,
        ))
        .unwrap();

        assert_eq!(rsp[1], ReqRespCode::CHUNK_SEND_ACK.0);
        assert_eq!(rsp[2] & CHUNK_ACK_ATTR_EARLY_ERROR, 0);
        assert!(state.large_msg_ctx.request_in_progress());
    }

    #[test]
    fn incoming_chunk_rejects_frame_over_local_data_transfer_size() {
        let pal = TestPal {
            mtu: 79,
            max_inbound_spdm_request_size: 256,
            ..TestPal::default()
        };
        let mut state = chunking_state();
        let mut sessions = test_sessions();
        let vdm = CaptureVdmBackend::new();
        let host_mailbox_payload = vec![0x5au8; 4 + 96];
        let large_req = vendor_defined_authorize_debug_unlock_request(&host_mailbox_payload);
        let first_chunk = chunk_send_request(11, 0, false, Some(large_req.len()), &large_req[..64]);
        assert!(first_chunk.len() > pal.mtu());

        let first_io = TestIo::message(first_chunk.clone());
        let err = block_on(handle_chunk_send(
            &mut state,
            &mut sessions,
            &pal,
            &first_io,
            &vdm,
            &first_chunk,
            None,
            true,
        ))
        .unwrap_err();

        assert_eq!(err, SPDM_INVALID_REQUEST);
        assert!(!state.large_msg_ctx.request_in_progress());
    }

    #[test]
    fn incoming_chunk_rejects_non_large_logical_message() {
        let pal = TestPal {
            mtu: 128,
            max_inbound_spdm_request_size: 256,
            ..TestPal::default()
        };
        let mut state = chunking_state();
        let mut sessions = test_sessions();
        let vdm = CaptureVdmBackend::new();
        let host_mailbox_payload = vec![0x5au8; 4 + 96];
        let large_req = vendor_defined_authorize_debug_unlock_request(&host_mailbox_payload);
        assert!(large_req.len() <= pal.mtu());
        let first_chunk = chunk_send_request(12, 0, false, Some(large_req.len()), &large_req[..64]);

        let first_io = TestIo::message(first_chunk.clone());
        let rsp = block_on(handle_chunk_send(
            &mut state,
            &mut sessions,
            &pal,
            &first_io,
            &vdm,
            &first_chunk,
            None,
            true,
        ))
        .unwrap();

        assert_eq!(rsp[1], ReqRespCode::CHUNK_SEND_ACK.0);
        assert_ne!(rsp[2] & CHUNK_ACK_ATTR_EARLY_ERROR, 0);
        assert!(!state.large_msg_ctx.request_in_progress());
    }

    #[test]
    fn incoming_chunk_rejects_logical_message_over_receive_limit() {
        let pal = TestPal {
            mtu: 96,
            max_inbound_spdm_request_size: 100,
            ..TestPal::default()
        };
        let mut state = chunking_state();
        let mut sessions = test_sessions();
        let vdm = CaptureVdmBackend::new();
        let host_mailbox_payload = vec![0x5au8; 4 + 96];
        let large_req = vendor_defined_authorize_debug_unlock_request(&host_mailbox_payload);
        assert!(large_req.len() > pal.max_inbound_spdm_request_size());
        let first_chunk = chunk_send_request(13, 0, false, Some(large_req.len()), &large_req[..64]);

        let first_io = TestIo::message(first_chunk.clone());
        let rsp = block_on(handle_chunk_send(
            &mut state,
            &mut sessions,
            &pal,
            &first_io,
            &vdm,
            &first_chunk,
            None,
            true,
        ))
        .unwrap();

        assert_eq!(rsp[1], ReqRespCode::CHUNK_SEND_ACK.0);
        assert_ne!(rsp[2] & CHUNK_ACK_ATTR_EARLY_ERROR, 0);
        assert!(!state.large_msg_ctx.request_in_progress());
    }

    #[test]
    fn chunked_vendor_defined_debug_unlock_falls_back_when_streaming_declines() {
        let pal = TestPal {
            mtu: 96,
            large_buffered_msg_capacity: 256,
            ..TestPal::default()
        };
        let mut state = chunking_state();
        let mut sessions = test_sessions();
        let vdm = BufferedOnlyVdmBackend::new();

        let host_mailbox_payload = vec![0x5au8; 4 + 96];
        let large_req = vendor_defined_authorize_debug_unlock_request(&host_mailbox_payload);
        let (first, second) = large_req.split_at(64);
        let first_chunk = chunk_send_request(10, 0, false, Some(large_req.len()), first);
        let second_chunk = chunk_send_request(10, 1, true, None, second);

        let first_io = TestIo::message(first_chunk.clone());
        let rsp = block_on(handle_chunk_send(
            &mut state,
            &mut sessions,
            &pal,
            &first_io,
            &vdm,
            &first_chunk,
            None,
            true,
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
            &mut sessions,
            &pal,
            &second_io,
            &vdm,
            &second_chunk,
            None,
            true,
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

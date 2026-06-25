// Licensed under the Apache-2.0 license

//! CHUNK_GET large-response transfer.

use caliptra_mcu_spdm_codec::{
    ChunkGetReqBody, ChunkResponseBody, ReqRespCode, SpdmMsgHdrPdu, WireWriter,
    CHUNK_ATTR_LAST_CHUNK, CHUNK_RESPONSE_FIXED_BODY_SIZE, LARGE_RESPONSE_SIZE_FIELD_SIZE,
};
use caliptra_mcu_spdm_traits::{PalBytes, SpdmPal, SpdmPalAlloc, SpdmPalIoTransport};
use zerocopy::{little_endian::U16, little_endian::U32, FromBytes};

use crate::build::alloc_padded;
use crate::error::{
    SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_VERSION_MISMATCH,
};
use crate::stack::{ConnectionState, Phase};

use super::LargeResponse;

pub(crate) async fn handle_chunk_get<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    req: &[u8],
) -> SpdmResult<PalBytes<'a, Pal>> {
    if (state.phase as u8) < (Phase::AfterCapabilities as u8) || !state.chunking_enabled() {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    if req.len() > pal.mtu() {
        return Err(SPDM_INVALID_REQUEST);
    }

    let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(SPDM_VERSION_MISMATCH);
    }

    let (chunk_req, _) =
        ChunkGetReqBody::ref_from_prefix(body).map_err(|_| SPDM_INVALID_REQUEST)?;
    if chunk_req.param1 != 0 {
        return Err(SPDM_INVALID_REQUEST);
    }

    let Some(active_rsp) = state.large_msg_ctx.response() else {
        return Err(SPDM_UNEXPECTED_REQUEST);
    };

    let handle = chunk_req.handle;
    let seq_num = chunk_req.chunk_seq_num.get();
    if handle != active_rsp.handle || seq_num != active_rsp.next_seq_num {
        return Err(SPDM_INVALID_REQUEST);
    }

    let large_response_size = active_rsp.response_size;
    let extra = if seq_num == 0 {
        LARGE_RESPONSE_SIZE_FIELD_SIZE
    } else {
        0
    };
    let max_chunk_size = state
        .effective_data_transfer_size(pal)
        .saturating_sub(SpdmMsgHdrPdu::SIZE + CHUNK_RESPONSE_FIXED_BODY_SIZE + extra);
    let bytes_sent = active_rsp.bytes_sent;
    if max_chunk_size == 0 || bytes_sent >= large_response_size {
        return Err(SPDM_INVALID_REQUEST);
    }

    let remaining = large_response_size - bytes_sent;
    let chunk_size = remaining.min(max_chunk_size);
    let last_chunk = chunk_size == remaining;
    let head = pal.header_size();
    let raw_len = head + SpdmMsgHdrPdu::SIZE + CHUNK_RESPONSE_FIXED_BODY_SIZE + extra + chunk_size;
    let mut rsp = alloc_padded(pal, io, raw_len)?;

    {
        let mut w = WireWriter::new(&mut rsp[head..]);
        w.write(&SpdmMsgHdrPdu::new(
            state.version,
            ReqRespCode::CHUNK_RESPONSE,
        ))?;
        w.write(&ChunkResponseBody {
            chunk_sender_attr: if last_chunk { CHUNK_ATTR_LAST_CHUNK } else { 0 },
            handle,
            chunk_seq_num: U16::new(seq_num),
            reserved: U16::new(0),
            chunk_size: U32::new(chunk_size as u32),
        })?;
        if seq_num == 0 {
            w.write(&U32::new(large_response_size as u32))?;
        }
        let chunk = w.reserve(chunk_size)?;
        match active_rsp.kind {
            LargeResponse::Certificate(cert_rsp) => {
                cert_rsp
                    .fill_chunk(pal, io, state.version, bytes_sent, chunk)
                    .await?;
                state.transcript.append_m1(pal, io, chunk).await?;
            }
            LargeResponse::Buffered => {
                let large = state
                    .large_msg_ctx
                    .buf
                    .as_deref()
                    .ok_or(crate::error::SPDM_UNSPECIFIED)?;
                let end = bytes_sent
                    .checked_add(chunk_size)
                    .ok_or(crate::error::SPDM_UNSPECIFIED)?;
                let src = large
                    .get(bytes_sent..end)
                    .ok_or(crate::error::SPDM_UNSPECIFIED)?;
                for (d, s) in chunk.iter_mut().zip(src) {
                    *d = *s;
                }
            }
        }
    }

    state.large_msg_ctx.chunk_sent(chunk_size);
    Ok(rsp)
}

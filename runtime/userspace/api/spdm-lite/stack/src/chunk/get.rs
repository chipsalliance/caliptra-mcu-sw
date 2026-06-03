// Licensed under the Apache-2.0 license

//! CHUNK_GET large-response transfer.

use mcu_spdm_lite_codec::{
    ChunkGetReqBody, ReqRespCode, SpdmMsgHdrPdu, SpdmVersion, WireWriter, CHUNK_ATTR_LAST_CHUNK,
    CHUNK_RESPONSE_FIXED_BODY_SIZE, LARGE_RESPONSE_SIZE_FIELD_SIZE,
};
use mcu_spdm_lite_traits::{PalBytes, SpdmPal, SpdmPalIo, SpdmPalIoTransport};
use zerocopy::{little_endian::U16, little_endian::U32, FromBytes};

use crate::build::alloc_padded;
use crate::certificate;
use crate::error::{
    SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_VERSION_MISMATCH,
};
use crate::stack::{ConnectionState, Phase};

use super::{
    effective_data_transfer_size, ActiveLargeResponse, CertificateLargeResponse, LargeResponse,
    CERTIFICATE_RESPONSE_HEADER_SIZE,
};

pub(crate) async fn handle_chunk_get<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    if (state.phase as u8) < (Phase::AfterCapabilities as u8) || !state.chunking_enabled() {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    let req = io.request();
    if req.len() > pal.mtu() {
        return Err(SPDM_INVALID_REQUEST);
    }

    let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(SPDM_VERSION_MISMATCH);
    }

    let (chunk_req, rest) =
        ChunkGetReqBody::ref_from_prefix(body).map_err(|_| SPDM_INVALID_REQUEST)?;
    if chunk_req.param1 != 0
        || !valid_transport_padding(pal, SpdmMsgHdrPdu::SIZE + ChunkGetReqBody::SIZE, rest)
    {
        return Err(SPDM_INVALID_REQUEST);
    }

    let Some(active_rsp) = state.large_response.response() else {
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
    let max_chunk_size = effective_data_transfer_size(state, pal)
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
        let attr = if last_chunk { CHUNK_ATTR_LAST_CHUNK } else { 0 };
        w.write(&[attr, handle])?;
        w.write(&U16::new(seq_num))?;
        w.write(&U16::new(0))?;
        w.write(&U32::new(chunk_size as u32))?;
        if seq_num == 0 {
            w.write(&U32::new(large_response_size as u32))?;
        }
        let chunk = w.reserve(chunk_size)?;
        let transcript_action =
            fill_large_response_chunk(pal, io, state.version, active_rsp, bytes_sent, chunk)
                .await?;
        if transcript_action == TranscriptAction::AppendM1 {
            state.transcript.append_m1(pal, io, chunk).await?;
        }
    }

    state.large_response.chunk_sent(chunk_size);
    Ok(rsp)
}

fn valid_transport_padding<Pal: SpdmPal>(pal: &Pal, spdm_len: usize, padding: &[u8]) -> bool {
    if padding.is_empty() {
        return true;
    }

    let align = pal.send_len_alignment();
    let expected = if align <= 1 {
        0
    } else {
        (align - (spdm_len % align)) % align
    };

    padding.len() == expected && padding.iter().all(|&b| b == 0)
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum TranscriptAction {
    None,
    AppendM1,
}

async fn fill_large_response_chunk<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    version: SpdmVersion,
    rsp: &ActiveLargeResponse,
    offset: usize,
    dst: &mut [u8],
) -> mcu_error::McuResult<TranscriptAction> {
    let end = offset
        .checked_add(dst.len())
        .ok_or(mcu_error::codes::INVARIANT)?;
    if end > rsp.response_size {
        return Err(mcu_error::codes::INVARIANT);
    }

    match rsp.kind {
        LargeResponse::Certificate(cert_rsp) => {
            fill_certificate_response_chunk(pal, io, version, &cert_rsp, offset, dst).await?;
            Ok(TranscriptAction::AppendM1)
        }
        LargeResponse::Buffered => {
            pal.read(offset, dst)?;
            Ok(TranscriptAction::None)
        }
    }
}

async fn fill_certificate_response_chunk<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    version: SpdmVersion,
    cert_rsp: &CertificateLargeResponse,
    offset: usize,
    dst: &mut [u8],
) -> mcu_error::McuResult<()> {
    let end = offset
        .checked_add(dst.len())
        .ok_or(mcu_error::codes::INVARIANT)?;
    if end > cert_rsp.response_size() {
        return Err(mcu_error::codes::INVARIANT);
    }

    let mut written = 0;
    if offset < CERTIFICATE_RESPONSE_HEADER_SIZE {
        let mut hdr = [0u8; CERTIFICATE_RESPONSE_HEADER_SIZE];
        hdr[0] = version.to_u8();
        hdr[1] = ReqRespCode::CERTIFICATE.0;
        hdr[2] = cert_rsp.slot_id;
        hdr[3] = cert_rsp.param2;
        hdr[4..6].copy_from_slice(&cert_rsp.portion_len.to_le_bytes());
        hdr[6..8].copy_from_slice(&cert_rsp.remainder_len.to_le_bytes());
        let hdr_end = CERTIFICATE_RESPONSE_HEADER_SIZE.min(end);
        let copy_len = hdr_end - offset;
        dst[..copy_len].copy_from_slice(&hdr[offset..hdr_end]);
        written = copy_len;
    }

    if written < dst.len() {
        let cert_offset =
            cert_rsp.cert_offset as usize + offset + written - CERTIFICATE_RESPONSE_HEADER_SIZE;
        certificate::fill_cert_chain_portion(
            pal,
            io,
            cert_rsp.slot_id,
            cert_rsp.asym_algo,
            cert_offset,
            &mut dst[written..],
        )
        .await?;
    }
    Ok(())
}

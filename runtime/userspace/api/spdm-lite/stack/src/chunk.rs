// Licensed under the Apache-2.0 license

//! SPDM large-message chunking (DSP0274 §10.26).

use mcu_spdm_lite_codec::{
    CapabilitiesBody, CertificateRspBody, ChunkGetReqBody, ChunkSendReqBody, ReqRespCode,
    SpdmMsgHdrPdu, SpdmVersion, WireWriter, CHUNK_ACK_ATTR_EARLY_ERROR, CHUNK_ATTR_LAST_CHUNK,
    CHUNK_RESPONSE_FIXED_BODY_SIZE, LARGE_RESPONSE_SIZE_FIELD_SIZE,
};
use mcu_spdm_lite_traits::{PalBytes, SpdmPal, SpdmPalIo, SpdmPalIoTransport};
use zerocopy::{little_endian::U16, little_endian::U32, FromBytes};

use crate::certificate;
use crate::error::{
    SpdmError, SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_UNSUPPORTED_REQUEST,
    SPDM_VERSION_MISMATCH,
};
use crate::stack::{ConnectionState, Phase};

const CERTIFICATE_RESPONSE_HEADER_SIZE: usize = SpdmMsgHdrPdu::SIZE + CertificateRspBody::SIZE;

#[derive(Copy, Clone)]
pub(crate) struct LargeResponseState {
    next_handle: u8,
    active: Option<LargeResponseKind>,
}

impl Default for LargeResponseState {
    fn default() -> Self {
        Self {
            next_handle: 1,
            active: None,
        }
    }
}

impl LargeResponseState {
    #[inline]
    pub(crate) fn reset(&mut self) {
        self.active = None;
    }

    #[inline]
    pub(crate) fn in_progress(&self) -> bool {
        self.active.is_some()
    }

    #[inline]
    pub(crate) fn start_certificate(
        &mut self,
        slot_id: u8,
        param2: u8,
        cert_offset: u16,
        portion_len: u16,
        remainder_len: u16,
    ) -> u8 {
        let handle = self.next_handle;
        self.active = Some(LargeResponseKind::Certificate(CertificateLargeResponse {
            handle,
            next_seq_num: 0,
            bytes_sent: 0,
            slot_id,
            param2,
            cert_offset,
            portion_len,
            remainder_len,
        }));
        handle
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn start_buffered(&mut self, response_size: usize) -> u8 {
        let handle = self.next_handle;
        self.active = Some(LargeResponseKind::Buffered(BufferedLargeResponse {
            handle,
            next_seq_num: 0,
            bytes_sent: 0,
            response_size: response_size as u32,
        }));
        handle
    }

    #[inline]
    fn response(self) -> Option<LargeResponseKind> {
        self.active
    }

    fn sent(&mut self, n: usize) {
        let Some(mut rsp) = self.active else {
            return;
        };
        let bytes_sent = rsp.bytes_sent() + n;
        rsp.set_bytes_sent(bytes_sent as u32);
        rsp.set_next_seq_num(rsp.next_seq_num().wrapping_add(1));
        if bytes_sent == rsp.response_size() {
            self.complete();
        } else {
            self.active = Some(rsp);
        }
    }

    #[inline]
    fn complete(&mut self) {
        self.advance_handle();
        self.reset();
    }

    #[inline]
    fn advance_handle(&mut self) {
        self.next_handle = self.next_handle.wrapping_add(1);
        if self.next_handle == 0 {
            self.next_handle = 1;
        }
    }
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
enum LargeResponseKind {
    Certificate(CertificateLargeResponse),
    Buffered(BufferedLargeResponse),
}

impl LargeResponseKind {
    #[inline]
    fn handle(self) -> u8 {
        match self {
            Self::Certificate(rsp) => rsp.handle,
            Self::Buffered(rsp) => rsp.handle,
        }
    }

    #[inline]
    fn next_seq_num(self) -> u16 {
        match self {
            Self::Certificate(rsp) => rsp.next_seq_num,
            Self::Buffered(rsp) => rsp.next_seq_num,
        }
    }

    #[inline]
    fn bytes_sent(self) -> usize {
        match self {
            Self::Certificate(rsp) => rsp.bytes_sent as usize,
            Self::Buffered(rsp) => rsp.bytes_sent as usize,
        }
    }

    #[inline]
    fn set_bytes_sent(&mut self, bytes_sent: u32) {
        match self {
            Self::Certificate(rsp) => rsp.bytes_sent = bytes_sent,
            Self::Buffered(rsp) => rsp.bytes_sent = bytes_sent,
        }
    }

    #[inline]
    fn set_next_seq_num(&mut self, next_seq_num: u16) {
        match self {
            Self::Certificate(rsp) => rsp.next_seq_num = next_seq_num,
            Self::Buffered(rsp) => rsp.next_seq_num = next_seq_num,
        }
    }

    #[inline]
    fn response_size(self) -> usize {
        match self {
            Self::Certificate(rsp) => rsp.response_size(),
            Self::Buffered(rsp) => rsp.response_size as usize,
        }
    }
}

#[derive(Copy, Clone)]
pub(crate) struct CertificateLargeResponse {
    handle: u8,
    next_seq_num: u16,
    bytes_sent: u32,
    slot_id: u8,
    param2: u8,
    cert_offset: u16,
    portion_len: u16,
    remainder_len: u16,
}

impl CertificateLargeResponse {
    #[inline]
    fn response_size(self) -> usize {
        CERTIFICATE_RESPONSE_HEADER_SIZE + self.portion_len as usize
    }
}

#[derive(Copy, Clone)]
struct BufferedLargeResponse {
    handle: u8,
    next_seq_num: u16,
    bytes_sent: u32,
    response_size: u32,
}

#[derive(Copy, Clone, Default)]
pub(crate) struct ChunkState {
    in_use: bool,
    handle: u8,
    seq_num: u16,
    bytes_received: u32,
    large_msg_size: u32,
}

impl ChunkState {
    #[inline]
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }

    #[inline]
    pub(crate) fn in_progress(&self) -> bool {
        self.in_use
    }
}

struct ChunkInfo {
    handle: u8,
    chunk_seq_num: u16,
    complete: bool,
}

pub(crate) async fn handle_chunk_send<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let result = process_chunk_send(state, pal, io);
    match result {
        Ok(info) => {
            let mut response_to_large_request = [0u8; 4];
            let response = if info.complete {
                let err = classify_large_request(state, pal);
                encode_error_pdu(state.version, err, &mut response_to_large_request);
                state.chunk.reset();
                &response_to_large_request[..]
            } else {
                &[]
            };
            build_chunk_send_ack(
                pal,
                io,
                state.version,
                false,
                info.handle,
                info.chunk_seq_num,
                response,
            )
        }
        Err(ChunkProcessError::Spdm(e)) => Err(e),
        Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        }) => {
            let mut error = [0u8; 4];
            encode_error_pdu(state.version, SPDM_INVALID_REQUEST, &mut error);
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
    let mut rsp = pal.alloc_bytes(
        io,
        head + SpdmMsgHdrPdu::SIZE + 4 + response_to_large_request.len(),
    )?;
    let mut w = WireWriter::new(&mut rsp[head..]);
    w.write(&SpdmMsgHdrPdu::new(version, ReqRespCode::CHUNK_SEND_ACK))?;
    let attr = if early_error {
        CHUNK_ACK_ATTR_EARLY_ERROR
    } else {
        0
    };
    w.write(&[attr, handle])?;
    w.write(&U16::new(chunk_seq_num))?;
    w.write_bytes(response_to_large_request)?;
    Ok(rsp)
}

pub(crate) async fn handle_chunk_get<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    if (state.phase as u8) < (Phase::AfterCapabilities as u8)
        || !state
            .cap_flags
            .contains(mcu_spdm_lite_codec::CapFlags::CHUNK)
        || !state
            .peer_cap_flags
            .contains(mcu_spdm_lite_codec::CapFlags::CHUNK)
    {
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
    if chunk_req.param1 != 0 || !rest.is_empty() {
        return Err(SPDM_INVALID_REQUEST);
    }

    let Some(large_rsp) = state.large_response.response() else {
        return Err(SPDM_UNEXPECTED_REQUEST);
    };

    let handle = chunk_req.handle;
    let seq_num = chunk_req.chunk_seq_num.get();
    if handle != large_rsp.handle() || seq_num != large_rsp.next_seq_num() {
        return Err(SPDM_INVALID_REQUEST);
    }

    let large_response_size = large_rsp.response_size();
    let extra = if seq_num == 0 {
        LARGE_RESPONSE_SIZE_FIELD_SIZE
    } else {
        0
    };
    let max_chunk_size = effective_data_transfer_size(state, pal)
        .saturating_sub(SpdmMsgHdrPdu::SIZE + CHUNK_RESPONSE_FIXED_BODY_SIZE + extra);
    let bytes_sent = large_rsp.bytes_sent();
    if max_chunk_size == 0 || bytes_sent >= large_response_size {
        return Err(SPDM_INVALID_REQUEST);
    }

    let remaining = large_response_size - bytes_sent;
    let chunk_size = remaining.min(max_chunk_size);
    let last_chunk = chunk_size == remaining;
    let head = pal.header_size();
    let mut rsp = pal.alloc_bytes(
        io,
        head + SpdmMsgHdrPdu::SIZE + CHUNK_RESPONSE_FIXED_BODY_SIZE + extra + chunk_size,
    )?;

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
        fill_large_response_chunk(pal, io, state.version, large_rsp, bytes_sent, chunk).await?;
        state.transcript.append_m1(pal, io, chunk).await?;
    }

    state.large_response.sent(chunk_size);
    Ok(rsp)
}

enum ChunkProcessError {
    Spdm(SpdmError),
    Early { handle: u8, chunk_seq_num: u16 },
}

fn process_chunk_send<Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State>,
    pal: &Pal,
    io: &impl SpdmPalIo,
) -> Result<ChunkInfo, ChunkProcessError> {
    if state.large_response.in_progress()
        || (state.phase as u8) < (Phase::AfterCapabilities as u8)
        || !state
            .cap_flags
            .contains(mcu_spdm_lite_codec::CapFlags::CHUNK)
        || !state
            .peer_cap_flags
            .contains(mcu_spdm_lite_codec::CapFlags::CHUNK)
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
        complete: state.chunk.in_use && state.chunk.bytes_received == state.chunk.large_msg_size,
    })
}

pub(crate) fn effective_data_transfer_size<Pal: SpdmPal>(
    state: &ConnectionState<Pal::State>,
    pal: &Pal,
) -> usize {
    let peer = if state.peer_data_transfer_size == 0 {
        pal.mtu()
    } else {
        state.peer_data_transfer_size as usize
    };
    pal.mtu().min(peer)
}

pub(crate) fn effective_max_spdm_msg_size<Pal: SpdmPal>(
    state: &ConnectionState<Pal::State>,
    pal: &Pal,
) -> usize {
    let local = pal.large_message_capacity().max(pal.mtu());
    let peer = if state.peer_max_spdm_msg_size == 0 {
        local
    } else {
        state.peer_max_spdm_msg_size as usize
    };
    local.min(peer)
}

async fn fill_large_response_chunk<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    version: SpdmVersion,
    rsp: LargeResponseKind,
    offset: usize,
    dst: &mut [u8],
) -> mcu_error::McuResult<()> {
    match rsp {
        LargeResponseKind::Certificate(cert_rsp) => {
            fill_certificate_response_chunk(pal, io, version, cert_rsp, offset, dst).await
        }
        LargeResponseKind::Buffered(buffered_rsp) => {
            let end = offset
                .checked_add(dst.len())
                .ok_or(mcu_error::codes::INVARIANT)?;
            if end > buffered_rsp.response_size as usize {
                return Err(mcu_error::codes::INVARIANT);
            }
            let buf = pal.large_message(buffered_rsp.response_size as usize)?;
            dst.copy_from_slice(&buf[offset..end]);
            Ok(())
        }
    }
}

async fn fill_certificate_response_chunk<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    version: SpdmVersion,
    cert_rsp: CertificateLargeResponse,
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
            cert_offset,
            &mut dst[written..],
        )
        .await?;
    }
    Ok(())
}

fn process_first_chunk<Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State>,
    pal: &Pal,
    handle: u8,
    chunk_seq_num: u16,
    chunk_size: usize,
    last_chunk: bool,
    rest: &[u8],
) -> Result<(), ChunkProcessError> {
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
        || large_msg_size <= CapabilitiesBody::MIN_DATA_TRANSFER_SIZE as usize
        || large_msg_size > pal.large_message_capacity();
    if invalid || pal.write_large_message(0, chunk).is_err() {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    }

    state.chunk = ChunkState {
        in_use: true,
        handle,
        seq_num: 0,
        bytes_received: chunk_size as u32,
        large_msg_size: large_msg_size as u32,
    };
    Ok(())
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
    if invalid || pal.write_large_message(bytes_received, chunk).is_err() {
        return Err(ChunkProcessError::Early {
            handle,
            chunk_seq_num,
        });
    }

    state.chunk.seq_num = chunk_seq_num;
    state.chunk.bytes_received = end as u32;
    Ok(())
}

fn classify_large_request<Pal: SpdmPal>(
    state: &ConnectionState<Pal::State>,
    pal: &Pal,
) -> SpdmError {
    let Ok(large_req) = pal.large_message(state.chunk.large_msg_size as usize) else {
        return SPDM_INVALID_REQUEST;
    };
    let Ok((hdr, _)) = SpdmMsgHdrPdu::ref_from_prefix(large_req) else {
        return SPDM_INVALID_REQUEST;
    };
    if hdr.version != state.version.to_u8()
        || hdr.code == ReqRespCode::CHUNK_SEND
        || hdr.code == ReqRespCode::CHUNK_GET
    {
        return SPDM_INVALID_REQUEST;
    }
    // TODO: Dispatch supported chunked large requests from `large_req` here.
    // SPDM-lite currently only uses chunking for large responses.
    SPDM_UNSUPPORTED_REQUEST
}

fn encode_error_pdu(version: SpdmVersion, err: SpdmError, out: &mut [u8; 4]) {
    out[0] = version.to_u8();
    out[1] = ReqRespCode::ERROR.0;
    out[2] = err.spec_byte();
    out[3] = 0;
}

// Licensed under the Apache-2.0 license

//! SPDM large-message chunking.

mod get;
mod send;

pub(crate) use get::handle_chunk_get;
pub(crate) use send::handle_chunk_send;

use mcu_spdm_lite_codec::{CertificateRspBody, SpdmMsgHdrPdu};
use mcu_spdm_lite_traits::{PalBytes, SpdmPal, SpdmPalAsymAlgo, SpdmPalIoTransport};

use crate::build::build_error_response;
use crate::error::{SpdmResult, SPDM_LARGE_RESPONSE, SPDM_UNSPECIFIED};
use crate::stack::ConnectionState;

const CERTIFICATE_RESPONSE_HEADER_SIZE: usize = SpdmMsgHdrPdu::SIZE + CertificateRspBody::SIZE;

#[derive(Copy, Clone)]
pub(crate) struct LargeResponseState {
    next_handle: u8,
    active: Option<ActiveLargeResponse>,
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
    pub(crate) fn start(&mut self, kind: LargeResponse, response_size: usize) -> u8 {
        let handle = self.next_handle;
        self.active = Some(ActiveLargeResponse {
            handle,
            next_seq_num: 0,
            bytes_sent: 0,
            response_size,
            kind,
        });
        handle
    }

    #[inline]
    fn response(&self) -> Option<&ActiveLargeResponse> {
        self.active.as_ref()
    }

    fn chunk_sent(&mut self, n: usize) {
        let complete = match self.active.as_mut() {
            Some(rsp) => rsp.chunk_sent(n),
            None => return,
        };
        if complete {
            self.complete();
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

#[derive(Copy, Clone)]
pub(crate) enum LargeResponse {
    Certificate(CertificateLargeResponse),
    Buffered,
}

#[derive(Copy, Clone)]
struct ActiveLargeResponse {
    handle: u8,
    next_seq_num: u16,
    bytes_sent: usize,
    response_size: usize,
    kind: LargeResponse,
}

impl ActiveLargeResponse {
    #[inline]
    fn chunk_sent(&mut self, n: usize) -> bool {
        self.bytes_sent += n;
        self.next_seq_num = self.next_seq_num.wrapping_add(1);
        self.bytes_sent == self.response_size
    }
}

#[derive(Copy, Clone)]
pub(crate) struct CertificateLargeResponse {
    slot_id: u8,
    param2: u8,
    asym_algo: SpdmPalAsymAlgo,
    cert_offset: u16,
    portion_len: u16,
    remainder_len: u16,
}

impl CertificateLargeResponse {
    #[inline]
    pub(crate) fn new(
        slot_id: u8,
        param2: u8,
        asym_algo: SpdmPalAsymAlgo,
        cert_offset: u16,
        portion_len: u16,
        remainder_len: u16,
    ) -> Self {
        Self {
            slot_id,
            param2,
            asym_algo,
            cert_offset,
            portion_len,
            remainder_len,
        }
    }

    #[inline]
    pub(crate) fn response_size(&self) -> usize {
        CERTIFICATE_RESPONSE_HEADER_SIZE + self.portion_len as usize
    }
}

#[derive(Copy, Clone, Default)]
pub(crate) struct ChunkState {
    pub(super) in_use: bool,
    pub(super) handle: u8,
    pub(super) seq_num: u16,
    pub(super) bytes_received: u32,
    pub(super) large_msg_size: u32,
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
    let local = pal.capacity().max(pal.mtu());
    let peer = if state.peer_max_spdm_msg_size == 0 {
        local
    } else {
        state.peer_max_spdm_msg_size as usize
    };
    local.min(peer)
}

pub(crate) fn validate_buffered_large_response<Pal: SpdmPal>(
    state: &ConnectionState<Pal::State>,
    pal: &Pal,
    spdm_len: usize,
) -> SpdmResult<()> {
    if state.chunk.in_progress() || !state.chunking_enabled() {
        return Err(SPDM_UNSPECIFIED);
    }
    if spdm_len > pal.capacity() || spdm_len > effective_max_spdm_msg_size(state, pal) {
        return Err(SPDM_UNSPECIFIED);
    }
    Ok(())
}

pub(crate) fn start_buffered_large_response<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    spdm_len: usize,
) -> SpdmResult<PalBytes<'a, Pal>> {
    validate_buffered_large_response(state, pal, spdm_len)?;
    let handle = state
        .large_response
        .start(LargeResponse::Buffered, spdm_len);
    build_error_response(
        pal,
        io,
        state.version,
        SPDM_LARGE_RESPONSE.spec_byte(),
        0,
        &[handle],
    )
}

// Licensed under the Apache-2.0 license

//! SPDM large-message chunking.

mod get;
mod send;

pub(crate) use get::handle_chunk_get;
pub(crate) use send::handle_chunk_send;

use mcu_spdm_lite_traits::{PalBytes, SpdmPal, SpdmPalAlloc, SpdmPalIoTransport};

use crate::build::build_error_response;
use crate::certificate::CertificateLargeResponse;
use crate::error::{
    SpdmError, SpdmResult, SPDM_INVALID_REQUEST, SPDM_LARGE_RESPONSE, SPDM_UNEXPECTED_REQUEST,
    SPDM_UNSPECIFIED,
};
use crate::stack::ConnectionState;

/// RAII guard that automatically zero-fills its contained buffer on Drop.
/// Used to securely erase sensitive reassembled request or response payload data from RAM.
pub(crate) struct WipeOnDrop<L: core::ops::DerefMut<Target = [u8]>> {
    pub(crate) buf: Option<L>,
}

impl<L: core::ops::DerefMut<Target = [u8]>> Drop for WipeOnDrop<L> {
    fn drop(&mut self) {
        if let Some(mut buf) = self.buf.take() {
            buf.fill(0);
        }
    }
}

#[derive(Copy, Clone)]
pub(crate) enum LargeResponse {
    Certificate(CertificateLargeResponse),
    Buffered,
}

#[derive(Copy, Clone)]
pub(crate) struct ActiveLargeResponse {
    pub(crate) handle: u8,
    pub(crate) next_seq_num: u16,
    pub(crate) bytes_sent: usize,
    pub(crate) response_size: usize,
    pub(crate) kind: LargeResponse,
}

impl ActiveLargeResponse {
    #[inline]
    pub(crate) fn chunk_sent(&mut self, n: usize) -> bool {
        self.bytes_sent += n;
        self.next_seq_num = self.next_seq_num.wrapping_add(1);
        self.bytes_sent == self.response_size
    }
}

#[derive(Copy, Clone, Default)]
pub(crate) struct ChunkState {
    pub(crate) in_use: bool,
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
    #[allow(dead_code)]
    pub(crate) fn in_progress(&self) -> bool {
        self.in_use
    }
}

#[derive(Copy, Clone)]
pub(crate) enum LargeMessageMode {
    Idle,
    Request,
    Response(ActiveLargeResponse),
}

pub(crate) struct LargeMessageCtx<L> {
    pub(crate) state: ChunkState,
    pub(crate) mode: LargeMessageMode,
    buf: Option<L>,
    pub(crate) next_handle: u8,
}

impl<L> LargeMessageCtx<L> {
    pub fn new() -> Self {
        Self {
            state: ChunkState::default(),
            mode: LargeMessageMode::Idle,
            buf: None,
            next_handle: 1,
        }
    }
}

impl<L: core::ops::DerefMut<Target = [u8]>> LargeMessageCtx<L> {
    pub fn reset(&mut self) {
        self.state.reset();
        self.mode = LargeMessageMode::Idle;
        if let Some(mut backing) = self.buf.take() {
            backing.fill(0);
        }
    }

    /// Securely replaces the held buffer with `buf`, ensuring any previous buffer is securely zero-wiped first.
    pub fn set_buffer(&mut self, buf: L) {
        self.reset();
        self.buf = Some(buf);
    }

    /// Securely takes the held buffer, returning it if present.
    pub fn take_buffer(&mut self) -> Option<L> {
        self.buf.take()
    }

    /// Access the underlying buffer to read or inspect.
    pub fn get_buffer(&self) -> Option<&L> {
        self.buf.as_ref()
    }

    /// Access the underlying buffer to mutably modify.
    #[allow(dead_code)]
    pub fn get_buffer_mut(&mut self) -> Option<&mut L> {
        self.buf.as_mut()
    }

    pub fn request_in_progress(&self) -> bool {
        matches!(self.mode, LargeMessageMode::Request) && self.state.in_use
    }

    pub fn response_in_progress(&self) -> bool {
        matches!(self.mode, LargeMessageMode::Response(_))
    }

    pub fn is_idle(&self) -> bool {
        matches!(self.mode, LargeMessageMode::Idle)
    }

    pub fn init_request(
        &mut self,
        handle: u8,
        total_size: usize,
        initial_chunk: &[u8],
        mut rent_buf: L,
    ) -> Result<(), SpdmError> {
        if !self.is_idle() {
            return Err(SPDM_UNEXPECTED_REQUEST);
        }

        self.mode = LargeMessageMode::Request;
        self.state = ChunkState {
            in_use: true,
            handle,
            seq_num: 0,
            bytes_received: initial_chunk.len() as u32,
            large_msg_size: total_size as u32,
        };
        let dest = rent_buf
            .get_mut(..initial_chunk.len())
            .ok_or(SPDM_INVALID_REQUEST)?;
        dest.copy_from_slice(initial_chunk);
        self.buf = Some(rent_buf);
        Ok(())
    }

    pub fn append_request(
        &mut self,
        handle: u8,
        seq_num: u16,
        chunk: &[u8],
    ) -> Result<(), SpdmError> {
        if !self.request_in_progress()
            || self.state.handle != handle
            || self.state.seq_num.wrapping_add(1) != seq_num
        {
            return Err(SPDM_INVALID_REQUEST);
        }
        let start = self.state.bytes_received as usize;
        let end = start.checked_add(chunk.len()).ok_or(SPDM_UNSPECIFIED)?;

        if end > self.state.large_msg_size as usize {
            return Err(SPDM_INVALID_REQUEST);
        }

        let buf = self.buf.as_deref_mut().ok_or(SPDM_UNSPECIFIED)?;
        let destination = buf.get_mut(start..end).ok_or(SPDM_UNSPECIFIED)?;
        destination.copy_from_slice(chunk);

        self.state.bytes_received = end as u32;
        self.state.seq_num = seq_num;
        Ok(())
    }

    /// Securely processes the fully assembled request via a scoped loan closure hook,
    /// guaranteeing zero-wipe and clean reset regardless of success or early error pathways.
    ///
    /// # Example (e.g., `SET_CERTIFICATE` reassembly dispatch):
    /// ```ignore
    /// state.large_msg_ctx.with_request_buf(len, |assembled_req| {
    ///     set_certificate::handle_set_certificate_request(state, pal, io, assembled_req).await
    /// })
    /// ```
    ///
    /// Evaluates the reassembled payload bytes within the scoped closure. On exit (success or error),
    /// the context unconditionally zero-fills the underlying memory and resets the chunk state.
    #[allow(dead_code)]
    pub fn with_request_buf<F, R>(&mut self, len: usize, op: F) -> Result<R, SpdmError>
    where
        F: FnOnce(&[u8]) -> Result<R, SpdmError>,
    {
        if !self.state.in_use
            || self.state.bytes_received as usize != self.state.large_msg_size as usize
        {
            return Err(SPDM_INVALID_REQUEST);
        }

        let buf = self.buf.as_deref_mut().ok_or(SPDM_UNSPECIFIED)?;
        let request_slice = buf.get(..len).ok_or(SPDM_INVALID_REQUEST)?;

        let result = op(request_slice);

        buf.fill(0);
        self.reset();

        result
    }

    pub(crate) fn next_handle(&self) -> u8 {
        self.next_handle
    }

    pub(crate) fn start_response(
        &mut self,
        kind: LargeResponse,
        response_size: usize,
        response_buf: Option<L>,
    ) -> Result<(), SpdmError> {
        if !self.is_idle() {
            return Err(SPDM_UNEXPECTED_REQUEST);
        }
        let handle = self.next_handle;
        self.mode = LargeMessageMode::Response(ActiveLargeResponse {
            handle,
            next_seq_num: 0,
            bytes_sent: 0,
            response_size,
            kind,
        });
        self.buf = response_buf;

        self.advance_handle();
        Ok(())
    }

    #[inline]
    pub(crate) fn response(&self) -> Option<&ActiveLargeResponse> {
        match &self.mode {
            LargeMessageMode::Response(active) => Some(active),
            _ => None,
        }
    }

    pub(crate) fn chunk_sent(&mut self, n: usize) {
        let complete = match &mut self.mode {
            LargeMessageMode::Response(active) => active.chunk_sent(n),
            _ => return,
        };
        if complete {
            self.reset();
        }
    }

    fn advance_handle(&mut self) {
        self.next_handle = self.next_handle.wrapping_add(1);
        if self.next_handle == 0 {
            self.next_handle = 1;
        }
    }
}

pub(crate) fn validate_buffered_large_response<Pal: SpdmPal>(
    state: &ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &Pal,
    large_resp_len: usize,
) -> SpdmResult<()> {
    if state.large_msg_ctx.request_in_progress()
        || state.large_msg_ctx.response_in_progress()
        || !state.chunking_enabled()
    {
        return Err(SPDM_UNSPECIFIED);
    }

    // Check against allocated buffer capacity if already active, else check remaining PAL capacity.
    // We don't double-revalidate against remaining free pool once rented.
    let capacity = if let Some(buf) = state.large_msg_ctx.get_buffer() {
        buf.len()
    } else {
        pal.large_capacity()
    };

    if large_resp_len > capacity || large_resp_len > state.effective_max_spdm_msg_size(pal) {
        return Err(SPDM_UNSPECIFIED);
    }
    Ok(())
}

pub(crate) fn start_buffered_large_response<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    large_resp_len: usize,
) -> SpdmResult<(PalBytes<'a, Pal>, usize)> {
    validate_buffered_large_response(state, pal, large_resp_len)?;
    let handle = state.large_msg_ctx.next_handle();
    let resp = build_error_response(
        pal,
        io,
        state.version,
        SPDM_LARGE_RESPONSE.spec_byte(),
        0,
        &[handle],
    )?;
    let spdm_len = resp.len() - pal.header_size();
    let rent_buf = state.large_msg_ctx.take_buffer();
    state
        .large_msg_ctx
        .start_response(LargeResponse::Buffered, large_resp_len, rent_buf)?;
    Ok((resp, spdm_len))
}

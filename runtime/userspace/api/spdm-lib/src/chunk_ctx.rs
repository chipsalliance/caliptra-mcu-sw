// Licensed under the Apache-2.0 license

use crate::commands::certificate_rsp::CertificateResponse;

#[derive(Debug, PartialEq)]
pub enum ChunkError {
    /// Error initializing a large message context
    LargeMessageInitError,
    /// No large response is currently in progress
    NoLargeResponseInProgress,
    /// Invalid chunk handle provided
    InvalidChunkHandle,
    /// Invalid chunk sequence number provided
    InvalidChunkSeqNum,
    /// Invalid message offset provided
    InvalidMessageOffset,
    /// Response data exceeds the shared buffer capacity
    BufferCapacityExceeded,
}

/// Stores state and metadata for managing ongoing large message requests and responses.
#[derive(Debug, Default)]
struct ChunkState {
    in_use: bool,
    handle: u8,
    seq_num: u16,
    bytes_transferred: usize,
    large_msg_size: usize,
}

impl ChunkState {
    pub fn reset(&mut self) {
        self.in_use = false;
        self.handle = 0;
        self.seq_num = 0;
        self.bytes_transferred = 0;
        self.large_msg_size = 0;
    }

    pub fn init(&mut self, large_msg_size: usize, handle: u8) {
        self.in_use = true;
        self.seq_num = 0;
        self.bytes_transferred = 0;
        self.large_msg_size = large_msg_size;
        self.handle = handle;
    }
}

pub type ChunkResult<T> = Result<T, ChunkError>;

/// Represents a large message response type that can be split into chunks.
/// `Buffered` responses have their data pre-serialized in the shared buffer.
/// `Certificate` responses stream from the certificate store.
pub(crate) enum LargeResponse {
    Certificate(CertificateResponse),
    /// Pre-serialized data lives in `LargeMessageCtx.buf[..data_len]`.
    /// Shared by both measurements and VDM large responses.
    Buffered,
}

/// Tracks which direction the shared buffer is currently being used for.
enum LargeMessageMode {
    /// Buffer is not in use.
    Idle,
    /// Buffer is being used to reassemble an incoming large request (CHUNK_SEND).
    Request,
    /// Buffer is being used to send a large response (CHUNK_GET).
    Response(LargeResponse),
}

/// Manages the shared buffer for both large SPDM request reassembly (CHUNK_SEND)
/// and large response chunking (CHUNK_GET).
///
/// Only one direction is active at a time: the SPDM protocol ensures that
/// CHUNK_SEND rejects if a large response is in progress, and vice versa.
///
/// TODO: Refactor `buf` to use `MessageBuf` instead of raw `&mut [u8]` to align
/// with the process_message pattern (reserve/put_data/encode) and simplify
/// header construction in vendor_defined_rsp.rs.
pub(crate) struct LargeMessageCtx<'a> {
    chunk_state: ChunkState,
    mode: LargeMessageMode,
    /// Global handle counter for large responses (incremented on each response reset)
    global_handle: u8,
    /// Number of valid bytes in `buf` (used by buffered responses)
    pub(crate) data_len: usize,
    /// App-provided shared buffer for large message data
    pub(crate) buf: &'a mut [u8],
}

impl<'a> LargeMessageCtx<'a> {
    /// Create a new context with the given app-provided shared buffer.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            chunk_state: ChunkState::default(),
            mode: LargeMessageMode::Idle,
            global_handle: 1,
            data_len: 0,
            buf,
        }
    }

    /// Take the shared buffer, leaving an empty slice in its place.
    /// The caller MUST call `replace_buf` to restore the buffer.
    pub fn take_buf(&mut self) -> &'a mut [u8] {
        core::mem::take(&mut self.buf)
    }

    /// Replace the shared buffer with the given one.
    pub fn replace_buf(&mut self, buf: &'a mut [u8]) {
        self.buf = buf;
    }

    // ── Request methods (CHUNK_SEND reassembly) ──

    /// Reset the request context. The buffer returns to idle.
    pub fn reset_request(&mut self) {
        self.chunk_state.reset();
        self.mode = LargeMessageMode::Idle;
    }

    /// Returns `true` if a large request reassembly is in progress.
    pub fn request_in_progress(&self) -> bool {
        matches!(self.mode, LargeMessageMode::Request) && self.chunk_state.in_use
    }

    pub fn request_capacity(&self) -> usize {
        self.buf.len()
    }

    /// Initialize a large request reassembly with the first chunk.
    pub fn init_request(
        &mut self,
        handle: u8,
        large_msg_size: usize,
        chunk: &[u8],
    ) -> ChunkResult<()> {
        if large_msg_size > self.buf.len() || chunk.len() > large_msg_size {
            return Err(ChunkError::LargeMessageInitError);
        }

        self.mode = LargeMessageMode::Request;
        self.chunk_state.init(large_msg_size, handle);
        self.buf[..chunk.len()].copy_from_slice(chunk);
        self.chunk_state.bytes_transferred = chunk.len();
        Ok(())
    }

    /// Append a subsequent chunk to the in-progress large request.
    pub fn append_request_chunk(
        &mut self,
        handle: u8,
        chunk_seq_num: u16,
        chunk: &[u8],
    ) -> ChunkResult<()> {
        self.validate_request_chunk(handle, chunk_seq_num)?;

        let end = self
            .chunk_state
            .bytes_transferred
            .checked_add(chunk.len())
            .ok_or(ChunkError::InvalidMessageOffset)?;
        if end > self.chunk_state.large_msg_size || end > self.buf.len() {
            return Err(ChunkError::InvalidMessageOffset);
        }

        self.buf[self.chunk_state.bytes_transferred..end].copy_from_slice(chunk);
        self.chunk_state.bytes_transferred = end;
        self.chunk_state.seq_num = self.chunk_state.seq_num.wrapping_add(1);
        Ok(())
    }

    pub fn validate_request_chunk(&self, handle: u8, chunk_seq_num: u16) -> ChunkResult<()> {
        if !self.chunk_state.in_use {
            return Err(ChunkError::NoLargeResponseInProgress);
        }
        if self.chunk_state.handle != handle {
            return Err(ChunkError::InvalidChunkHandle);
        }
        if self.chunk_state.seq_num.wrapping_add(1) != chunk_seq_num {
            return Err(ChunkError::InvalidChunkSeqNum);
        }
        Ok(())
    }

    pub fn request_size(&self) -> usize {
        self.chunk_state.large_msg_size
    }

    pub fn request_bytes_transferred(&self) -> usize {
        self.chunk_state.bytes_transferred
    }

    pub fn request_is_complete(&self) -> bool {
        self.chunk_state.in_use
            && self.chunk_state.bytes_transferred == self.chunk_state.large_msg_size
    }

    pub fn request_code(&self) -> Option<u8> {
        if self.chunk_state.large_msg_size < 2 {
            return None;
        }
        Some(self.buf[1])
    }

    // ── Response methods (CHUNK_GET chunking) ──

    /// Reset the response context. Increments global handle for next response.
    pub(crate) fn reset_response(&mut self) {
        self.chunk_state.reset();
        self.mode = LargeMessageMode::Idle;
        self.data_len = 0;
        self.global_handle = self.global_handle.wrapping_add(1);
    }

    /// Returns `true` if a large response chunking is in progress.
    pub fn response_in_progress(&self) -> bool {
        matches!(self.mode, LargeMessageMode::Response(_)) && self.chunk_state.in_use
    }

    /// Initialize the context for a large response (e.g., Certificate).
    ///
    /// # Returns
    /// The handle for this large response.
    pub fn init_response(&mut self, large_rsp: LargeResponse, large_rsp_size: usize) -> u8 {
        self.mode = LargeMessageMode::Response(large_rsp);
        self.chunk_state.init(large_rsp_size, self.global_handle);
        self.global_handle
    }

    /// Initialize a buffered large response.
    /// The caller must have already written `data_len` bytes into `self.buf`.
    ///
    /// # Returns
    /// The handle for this large response, or error if data exceeds buffer capacity.
    pub fn init_buffered_response(&mut self, data_len: usize) -> ChunkResult<u8> {
        if data_len > self.buf.len() {
            return Err(ChunkError::BufferCapacityExceeded);
        }
        self.data_len = data_len;
        self.mode = LargeMessageMode::Response(LargeResponse::Buffered);
        self.chunk_state.init(data_len, self.global_handle);
        Ok(self.global_handle)
    }

    /// Returns a reference to the valid buffered data.
    #[allow(dead_code)]
    pub fn buffered_data(&self) -> &[u8] {
        &self.buf[..self.data_len]
    }

    /// Validates that the provided chunk handle and sequence number match the expected values.
    pub fn validate_response_chunk(&self, handle: u8, chunk_seq_num: u16) -> ChunkResult<()> {
        if !self.chunk_state.in_use {
            return Err(ChunkError::NoLargeResponseInProgress);
        }
        if self.chunk_state.handle != handle {
            return Err(ChunkError::InvalidChunkHandle);
        }
        if self.chunk_state.seq_num != chunk_seq_num {
            return Err(ChunkError::InvalidChunkSeqNum);
        }
        Ok(())
    }

    /// Returns the total size of the large response being transferred.
    pub fn response_size(&self) -> usize {
        self.chunk_state.large_msg_size
    }

    /// Records that a chunk has been sent and updates internal state.
    pub fn next_chunk_sent(&mut self, chunk_size: usize) {
        self.chunk_state.bytes_transferred += chunk_size;
        self.chunk_state.seq_num = self.chunk_state.seq_num.wrapping_add(1);
        if self.chunk_state.bytes_transferred == self.chunk_state.large_msg_size {
            // Transfer complete
            self.chunk_state.reset();
            self.mode = LargeMessageMode::Idle;
            self.data_len = 0;
        }
    }

    /// Gets information about the next chunk to be sent.
    ///
    /// # Returns
    /// `Ok((is_last_chunk, remaining_size))` or `Err` if no transfer is active
    pub fn next_chunk_info(&self, chunk_size: usize) -> ChunkResult<(bool, usize)> {
        if !self.chunk_state.in_use {
            return Err(ChunkError::NoLargeResponseInProgress);
        }
        let rem_len = self.chunk_state.large_msg_size - self.chunk_state.bytes_transferred;
        Ok((rem_len <= chunk_size, rem_len))
    }

    pub fn response(&self) -> Option<&LargeResponse> {
        match &self.mode {
            LargeMessageMode::Response(r) => Some(r),
            _ => None,
        }
    }

    pub fn response_bytes_transferred(&self) -> usize {
        self.chunk_state.bytes_transferred
    }
}

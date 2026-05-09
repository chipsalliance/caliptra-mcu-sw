// Licensed under the Apache-2.0 license

use crate::commands::certificate_rsp::CertificateResponse;
use crate::commands::measurements_rsp::MeasurementsResponse;
use crate::commands::vendor_defined_rsp::VendorLargeResponse;

#[derive(Debug, PartialEq)]
pub enum ChunkError {
    /// Error initializing a large response context
    LargeResponseInitError,
    /// No large response is currently in progress
    NoLargeResponseInProgress,
    /// Invalid chunk handle provided
    InvalidChunkHandle,
    /// Invalid chunk sequence number provided
    InvalidChunkSeqNum,
    /// Invalid message offset provided
    InvalidMessageOffset,
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

/// Represents a large message response type that can be split into chunks
pub(crate) enum LargeResponse {
    Certificate(CertificateResponse),
    Measurements(MeasurementsResponse),
    Vdm(VendorLargeResponse),
}

/// Manages the context for ongoing large message responses
pub(crate) struct LargeResponseCtx {
    chunk_state: ChunkState,
    response: Option<LargeResponse>,
    /// Global handle counter for large responses (incremented for each new response)
    global_handle: u8,
}

impl Default for LargeResponseCtx {
    fn default() -> Self {
        Self {
            chunk_state: ChunkState::default(),
            response: None,
            global_handle: 1,
        }
    }
}

impl LargeResponseCtx {
    /// Reset the context to its initial state
    /// This action increments the global handle for the next large response
    pub(crate) fn reset(&mut self) {
        self.chunk_state.reset();
        self.response = None;
        // Increment global handle for next large response
        self.global_handle = self.global_handle.wrapping_add(1);
    }

    /// Initialize the context for a large response
    ///
    /// # Arguments
    /// * `large_rsp` - The large message response to be sent
    /// * `large_rsp_size` - The size of the response message
    ///
    /// # Returns
    /// The handle(u8) for this large response
    pub fn init(&mut self, large_rsp: LargeResponse, large_rsp_size: usize) -> u8 {
        self.response = Some(large_rsp);
        self.chunk_state.init(large_rsp_size, self.global_handle);
        self.global_handle
    }

    /// Is large message response in progress
    ///
    /// # Returns
    /// Returns `true` if a large response is currently in progress, otherwise `false`
    pub fn in_progress(&self) -> bool {
        self.chunk_state.in_use
    }

    /// Validates that the provided chunk handle and sequence number match the expected values
    ///
    /// # Arguments
    /// * `handle` - The chunk handle to validate
    /// * `chunk_seq_num` - The sequence number to validate
    ///
    /// # Returns
    /// `Ok(())` if valid, or a specific `ChunkError` if validation fails
    pub fn validate_chunk(&self, handle: u8, chunk_seq_num: u16) -> ChunkResult<()> {
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

    /// Returns the total size of the large response being transferred
    pub fn large_response_size(&self) -> usize {
        self.chunk_state.large_msg_size
    }

    /// Records that a chunk has been sent and updates internal state
    ///
    /// # Arguments
    /// * `chunk_size` - The size of the chunk that was sent
    pub fn next_chunk_sent(&mut self, chunk_size: usize) {
        self.chunk_state.bytes_transferred += chunk_size;
        self.chunk_state.seq_num = self.chunk_state.seq_num.wrapping_add(1);
        if self.chunk_state.bytes_transferred == self.chunk_state.large_msg_size {
            // Transfer complete - reset chunk state but keep global handle for next response
            self.chunk_state.reset();
            self.response = None;
        }
    }

    /// Gets information about the next chunk to be sent
    ///
    /// # Arguments
    /// * `chunk_size` - Maximum size allowed for a single chunk
    ///
    /// # Returns
    /// `Ok((is_last_chunk, remaining_size))` or `Err` if no transfer is active
    pub fn next_chunk_info(&self, chunk_size: usize) -> ChunkResult<(bool, usize)> {
        if !self.chunk_state.in_use {
            return Err(ChunkError::NoLargeResponseInProgress);
        }
        let rem_len = self.chunk_state.large_msg_size - self.chunk_state.bytes_transferred;

        // Check if the last chunk is reached
        Ok((rem_len <= chunk_size, rem_len))
    }

    pub fn response(&self) -> Option<&LargeResponse> {
        self.response.as_ref()
    }

    pub fn bytes_transferred(&self) -> usize {
        self.chunk_state.bytes_transferred
    }
}

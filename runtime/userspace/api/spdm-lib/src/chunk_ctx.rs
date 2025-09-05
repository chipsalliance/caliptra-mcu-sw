// Licensed under the Apache-2.0 license

use crate::commands::measurements_rsp::MeasurementsResponse;
use crate::commands::vendor_defined_rsp::VendorLargeResponse;

#[derive(Debug, PartialEq)]
pub enum ChunkError {
    LargeResponseInitError,
    NoLargeResponseInProgress,
    InvalidChunkHandle,
    InvalidChunkSeqNum,
    InvalidMessageOffset,
}

/// Stores state and metadata for managing ongoing large message requests and responses.
#[derive(Default)]
struct ChunkInfo {
    chunk_in_use: bool,
    chunk_handle: u8,
    chunk_seq_num: u16,
    bytes_transferred: usize,
    large_msg_size: usize,
}

impl ChunkInfo {
    pub fn reset(&mut self, reset_handle: bool) {
        self.chunk_in_use = false;
        if reset_handle {
            self.chunk_handle = 0;
        } else {
            self.chunk_handle = self.chunk_handle.wrapping_add(1);
        }
        self.chunk_seq_num = 0;
        self.bytes_transferred = 0;
    }

    pub fn init(&mut self, large_msg_size: usize, handle: Option<u8>) -> u8 {
        self.chunk_in_use = true;
        self.chunk_seq_num = 0;
        self.bytes_transferred = 0;
        self.large_msg_size = large_msg_size;
        if let Some(h) = handle {
            self.chunk_handle = h;
        }
        self.chunk_handle
    }
}

pub type ChunkResult<T> = Result<T, ChunkError>;

/// Represents a large message response type that can be split into chunks
pub(crate) enum LargeResponse {
    Measurements(MeasurementsResponse),
    Vdm(VendorLargeResponse),
}

/// Manages the context for ongoing large message responses
#[derive(Default)]
pub(crate) struct LargeResponseCtx {
    chunk_info: ChunkInfo,
    response: Option<LargeResponse>,
}

impl LargeResponseCtx {
    /// Reset the context to its initial state
    /// This action increments the chunk handle
    pub(crate) fn reset(&mut self) {
        self.chunk_info.reset(false);
        self.response = None;
    }

    /// Initialize the context for a large response
    ///
    /// # Arguments
    /// * `large_rsp` - The large message response to be sent
    /// * `large_rsp_size` - The size of the response message
    ///
    /// # Returns
    /// A `ChunkResult` containing the chunk handle(u8) if successful
    pub fn init(&mut self, large_rsp: LargeResponse, large_rsp_size: usize) -> u8 {
        self.response = Some(large_rsp);
        self.chunk_info.init(large_rsp_size, None)
    }

    /// Is large message response in progress
    ///
    /// # Returns
    /// Returns `true` if a large response is currently in progress, otherwise `false`
    pub fn in_progress(&self) -> bool {
        self.chunk_info.chunk_in_use
    }

    pub fn valid(&self, handle: u8, chunk_seq_num: u16) -> bool {
        self.chunk_info.chunk_in_use
            && self.chunk_info.chunk_handle == handle
            && self.chunk_info.chunk_seq_num == chunk_seq_num
    }

    pub fn large_response_size(&self) -> usize {
        self.chunk_info.large_msg_size
    }

    pub fn last_chunk(&self, chunk_size: usize) -> (bool, usize) {
        if !self.chunk_info.chunk_in_use {
            return (false, 0);
        }
        let rem_len = self.chunk_info.large_msg_size - self.chunk_info.bytes_transferred;

        // Check if the last chunk is reached and
        (rem_len <= chunk_size, rem_len)
    }

    pub fn response(&self) -> Option<&LargeResponse> {
        self.response.as_ref()
    }

    pub fn bytes_transferred(&self) -> usize {
        self.chunk_info.bytes_transferred
    }
}

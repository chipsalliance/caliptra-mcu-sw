// Licensed under the Apache-2.0 license

pub enum ChunkError {
    ChunkInUse,
    ChunkNotInUse,
    InvalidChunkHandle,
    InvalidChunkSeqNum,
    EndOfLargeMsg,
}

pub type ChunkResult<T> = Result<T, ChunkError>;

pub trait LargeMsgResponse {
    fn large_msg_size(&self) -> usize;
    fn get_chunk(&self, offset: usize, chunk_buf: &mut [u8]) -> ChunkResult<()>;
}

pub struct ChunkInfo<'a> {
    chunk_in_use: bool,
    chunk_handle: u8,
    chunk_seq_num: u16,
    bytes_transferred: usize,
    large_msg_size: usize,
    large_msg: Option<&'a dyn LargeMsgResponse>,
}

#[allow(dead_code)]
pub(crate) struct ChunkContext<'a> {
    chunk_get: ChunkInfo<'a>,
}

#[allow(dead_code)]
impl<'a> ChunkContext<'a> {
    pub fn new() -> Self {
        Self {
            chunk_get: ChunkInfo::new(),
        }
    }

    pub fn reset_chunk_get(&mut self) {
        self.chunk_get.reset(false);
    }

    pub fn init_chunk_get(&mut self, large_msg: &'a dyn LargeMsgResponse) -> ChunkResult<()> {
        self.chunk_get.init(large_msg)
    }
}

impl<'a> Default for ChunkInfo<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> ChunkInfo<'a> {
    pub fn new() -> Self {
        Self {
            chunk_in_use: false,
            chunk_handle: 0,
            chunk_seq_num: 0,
            bytes_transferred: 0,
            large_msg_size: 0,
            large_msg: None,
        }
    }

    pub fn reset(&mut self, reset_handle: bool) {
        self.chunk_in_use = false;
        if reset_handle {
            self.chunk_handle = 0;
        } else {
            self.chunk_handle = self.chunk_handle.wrapping_add(1);
        }
        self.chunk_seq_num = 0;
        self.bytes_transferred = 0;
        self.large_msg = None;
    }

    pub fn init(&mut self, large_msg: &'a dyn LargeMsgResponse) -> ChunkResult<()> {
        if self.chunk_in_use {
            return Err(ChunkError::ChunkInUse);
        }
        self.chunk_in_use = true;
        self.chunk_seq_num = 0;
        self.bytes_transferred = 0;
        self.large_msg_size = large_msg.large_msg_size();
        self.large_msg = Some(large_msg);
        Ok(())
    }
}

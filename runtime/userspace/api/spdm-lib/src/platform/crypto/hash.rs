//Licensed under the Apache-2.0 license
extern crate alloc;
use alloc::boxed::Box;
use async_trait::async_trait;

pub type SpdmHashResult<T> = Result<T, SpdmHashError>;

#[async_trait]
pub trait SpdmHash {
    async fn hash(
        &mut self,
        hash_algo: SpdmHashAlgoType,
        data: &[u8],
        hash: &mut [u8],
    ) -> SpdmHashResult<()>;
    async fn init(
        &mut self,
        hash_algo: SpdmHashAlgoType,
        data: Option<&[u8]>,
    ) -> SpdmHashResult<()>;
    async fn update(&mut self, data: &[u8]) -> SpdmHashResult<()>;
    async fn finalize(&mut self, hash: &mut [u8]) -> SpdmHashResult<()>;

    fn reset(&mut self);
    fn algo(&self) -> SpdmHashAlgoType;
}

#[derive(Debug, PartialEq)]
pub enum SpdmHashError {
    PlatformError,
    BufferTooSmall,
    InvalidAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SpdmHashAlgoType {
    SHA384,
    SHA512,
}

pub const SHA384_HASH_SIZE: usize = 48;
pub const SHA512_HASH_SIZE: usize = 64;

impl From<SpdmHashAlgoType> for u32 {
    fn from(algo: SpdmHashAlgoType) -> Self {
        match algo {
            SpdmHashAlgoType::SHA384 => 2u32,
            SpdmHashAlgoType::SHA512 => 4u32,
        }
    }
}

impl SpdmHashAlgoType {
    pub fn hash_size(&self) -> usize {
        match self {
            SpdmHashAlgoType::SHA384 => SHA384_HASH_SIZE,
            SpdmHashAlgoType::SHA512 => SHA512_HASH_SIZE,
        }
    }
}

// Licensed under the Apache-2.0 license

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;

use spdm_lib::platform::crypto::hash::{SpdmHash, SpdmHashAlgoType, SpdmHashError};
use spdm_lib::platform::crypto::provider::SpdmCryptoProvider;

use libapi_caliptra::crypto::hash::{HashAlgoType as CalAlgo, HashContext as CalHash};

/// Adapter that wraps Caliptra HashContext to implement SpdmHash.
pub struct CaliptraSpdmHash {
    inner: CalHash,
    algo: Option<SpdmHashAlgoType>,
}

impl CaliptraSpdmHash {
    pub fn new() -> Self {
        Self {
            inner: CalHash::new(),
            algo: None,
        }
    }

    fn to_cal_algo(algo: SpdmHashAlgoType) -> CalAlgo {
        match algo {
            SpdmHashAlgoType::SHA384 => CalAlgo::SHA384,
            SpdmHashAlgoType::SHA512 => CalAlgo::SHA512,
        }
    }
}

#[async_trait]
impl SpdmHash for CaliptraSpdmHash {
    async fn hash(
        &mut self,
        hash_algo: SpdmHashAlgoType,
        data: &[u8],
        hash: &mut [u8],
    ) -> Result<(), SpdmHashError> {
        // One-shot: init, update, finalize
        self.reset();
        self.init(hash_algo, None).await?;
        self.update(data).await?;
        self.finalize(hash).await
    }

    async fn init(
        &mut self,
        hash_algo: SpdmHashAlgoType,
        data: Option<&[u8]>,
    ) -> Result<(), SpdmHashError> {
        self.algo = Some(hash_algo);
        self.inner
            .init(Self::to_cal_algo(hash_algo), data)
            .await
            .map_err(|_| SpdmHashError::PlatformError)
    }

    async fn update(&mut self, data: &[u8]) -> Result<(), SpdmHashError> {
        self.inner
            .update(data)
            .await
            .map_err(|_| SpdmHashError::PlatformError)
    }

    async fn finalize(&mut self, hash: &mut [u8]) -> Result<(), SpdmHashError> {
        self.inner
            .finalize(hash)
            .await
            .map_err(|_| SpdmHashError::PlatformError)
    }

    fn reset(&mut self) {
        self.inner = CalHash::new();
        self.algo = None;
    }

    fn algo(&self) -> SpdmHashAlgoType {
        self.algo.unwrap_or(SpdmHashAlgoType::SHA384)
    }
}

/// Crypto provider that creates Caliptra-backed SPDM hashers.
pub struct CaliptraCryptoProvider;

impl CaliptraCryptoProvider {
    pub fn new() -> Self {
        Self
    }
}

impl SpdmCryptoProvider for CaliptraCryptoProvider {
    fn create_hasher(&mut self) -> Box<dyn SpdmHash> {
        Box::new(CaliptraSpdmHash::new())
    }
}

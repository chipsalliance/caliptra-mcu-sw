// Licensed under the Apache-2.0 license

use crate::commands::digests_rsp::SpdmDigest;
use crate::protocol::algorithms::BaseHashAlgoType;
use sha2::{Digest, Sha256, Sha384, Sha512};

#[derive(Debug)]
pub enum HashEngineError {
    InvalidParam,
    Sha256Failure,
    Sha384Failure,
    Sha512Failure,
    UnsupportedHashType,
}

// Represents the interface for a cryptographic hash engine used in SPDM. It can be extended to async-trait if needed.
pub trait HashEngine {
    /// Computes the hash of the entire input data in a single step.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of bytes representing the input data to be hashed.
    /// * `hash_type` - The type of hash algorithm to use (e.g., SHA-256, SHA-384).
    /// * `digest` - A mutable reference to a `SpdmDigest` where the resulting hash will be stored.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the hash computation is successful.
    /// * `Err(HashEngineError)` if an error occurs during hashing.
    fn hash_all(
        &self,
        data: &[u8],
        hash_type: BaseHashAlgoType,
        digest: &mut SpdmDigest,
    ) -> Result<(), HashEngineError>;

    /// Initializes the hash engine for incremental hashing.
    ///
    /// # Arguments
    ///
    /// * `hash_type` - The type of hash algorithm to use (e.g., SHA-256, SHA-384).
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the initialization is successful.
    /// * `Err(HashEngineError)` if an error occurs during initialization.
    fn start(&mut self, hash_type: BaseHashAlgoType) -> Result<(), HashEngineError>;

    /// Updates the hash engine with a chunk of data.
    ///
    /// This method can be called multiple times to process data incrementally.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of bytes representing the input data to be added to the hash computation.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the update is successful.
    /// * `Err(HashEngineError)` if an error occurs during the update.
    fn update(&mut self, data: &[u8]) -> Result<(), HashEngineError>;

    /// Finalizes the hash computation and produces the resulting hash.
    ///
    /// # Arguments
    ///
    /// * `digest` - A mutable reference to a `SpdmDigest` where the resulting hash will be stored.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the finalization is successful.
    /// * `Err(HashEngineError)` if an error occurs during finalization.
    fn finish(&mut self, digest: &mut SpdmDigest) -> Result<(), HashEngineError>;
}

// A concrete implementation of the `HashEngine` trait utilizing the `sha2` crate.
// This implementation is intended for development and testing purposes only.
// Future iterations should refactor this to integrate with a cryptographic service provider via a mailbox interface.
#[derive(Default)]
pub struct HashEngineImpl {
    ctx: Option<Hasher>,
}

pub enum Hasher {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl HashEngineImpl {
    pub fn new() -> HashEngineImpl {
        HashEngineImpl {
            ..Default::default()
        }
    }
}

impl HashEngine for HashEngineImpl {
    fn hash_all(
        &self,
        data: &[u8],
        hash_type: BaseHashAlgoType,
        spdm_digest: &mut SpdmDigest,
    ) -> Result<(), HashEngineError> {
        match hash_type {
            BaseHashAlgoType::TpmAlgSha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                let result = hasher.finalize_reset();
                spdm_digest.data[..result.len()].copy_from_slice(&result);
                spdm_digest.length = result.len() as u8;
            }
            BaseHashAlgoType::TpmAlgSha384 => {
                let mut hasher = Sha384::new();
                hasher.update(data);
                let result = hasher.finalize_reset();
                spdm_digest.data[..result.len()].copy_from_slice(&result);
                spdm_digest.length = result.len() as u8;
            }
            BaseHashAlgoType::TpmAlgSha512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                let result = hasher.finalize_reset();
                spdm_digest.data[..result.len()].copy_from_slice(&result);
                spdm_digest.length = result.len() as u8;
            }
            _ => {
                return Err(HashEngineError::UnsupportedHashType);
            }
        }
        Ok(())
    }

    fn start(&mut self, hash_type: BaseHashAlgoType) -> Result<(), HashEngineError> {
        // Start hash
        match hash_type {
            BaseHashAlgoType::TpmAlgSha256 => {
                self.ctx = Some(Hasher::Sha256(Sha256::new()));
            }
            BaseHashAlgoType::TpmAlgSha384 => {
                self.ctx = Some(Hasher::Sha384(Sha384::new()));
            }
            BaseHashAlgoType::TpmAlgSha512 => {
                self.ctx = Some(Hasher::Sha512(Sha512::new()));
            }
            _ => {
                return Err(HashEngineError::UnsupportedHashType);
            }
        }
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> Result<(), HashEngineError> {
        match &mut self.ctx {
            Some(Hasher::Sha256(hasher)) => {
                hasher.update(data);
                Ok(())
            }
            Some(Hasher::Sha384(hasher)) => {
                hasher.update(data);
                Ok(())
            }
            Some(Hasher::Sha512(hasher)) => {
                hasher.update(data);
                Ok(())
            }
            _ => Err(HashEngineError::UnsupportedHashType),
        }
    }

    fn finish(&mut self, digest: &mut SpdmDigest) -> Result<(), HashEngineError> {
        match &mut self.ctx {
            Some(Hasher::Sha256(hasher)) => {
                let result = hasher.finalize_reset();
                digest.data[..result.len()].copy_from_slice(&result);
                digest.length = result.len() as u8;
            }
            Some(Hasher::Sha384(hasher)) => {
                let result = hasher.finalize_reset();
                digest.data[..result.len()].copy_from_slice(&result);
                digest.length = result.len() as u8;
            }
            Some(Hasher::Sha512(hasher)) => {
                let result = hasher.finalize_reset();
                digest.data[..result.len()].copy_from_slice(&result);
                digest.length = result.len() as u8;
            }
            _ => {
                return Err(HashEngineError::UnsupportedHashType);
            }
        }
        // Reset the context after finish
        self.ctx = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_mgr::SpdmCertChainData;
    use crate::config;

    #[test]
    fn test_hash_all() {
        let hash_engine = HashEngineImpl::new();
        let hash_algo = BaseHashAlgoType::TpmAlgSha512;
        let mut spdm_cert_chain_data = SpdmCertChainData::default();
        spdm_cert_chain_data
            .add(&config::TEST_DEVID_CERT_DER)
            .unwrap();
        spdm_cert_chain_data
            .add(&config::TEST_ALIAS_CERT_DER)
            .unwrap();

        assert_eq!(
            spdm_cert_chain_data.length,
            config::TEST_DEVID_CERT_DER.len() as u16 + config::TEST_ALIAS_CERT_DER.len() as u16
        );

        let mut spdm_digest = SpdmDigest::default();
        // hash cert chain data
        hash_engine
            .hash_all(spdm_cert_chain_data.as_ref(), hash_algo, &mut spdm_digest)
            .unwrap();

        let expected_sha512: [u8; 64] = [
            0x71, 0x2b, 0xb1, 0xc2, 0x47, 0xae, 0x24, 0x38, 0xaf, 0x3b, 0xcb, 0x61, 0xd3, 0xd7,
            0x51, 0x25, 0xb0, 0xd5, 0xca, 0xd7, 0x7b, 0x48, 0xab, 0x8f, 0x60, 0xd3, 0x65, 0x9a,
            0xdc, 0xe1, 0xb3, 0x0d, 0xb3, 0x32, 0x9c, 0x22, 0xc6, 0x4c, 0x58, 0x87, 0x97, 0xdc,
            0x59, 0xad, 0x30, 0x73, 0xb5, 0x61, 0xeb, 0x86, 0x7b, 0xc7, 0xd2, 0x19, 0xda, 0x0a,
            0x22, 0x59, 0x09, 0x3d, 0x67, 0xbc, 0xae, 0x80,
        ];
        assert_eq!(spdm_digest.length, 64);
        assert_eq!(spdm_digest.data, expected_sha512);
    }

    #[test]
    fn test_incremental_hash_update() {
        let mut spdm_digest = SpdmDigest::default();
        let mut hash_engine = HashEngineImpl::new();
        let hash_algo = BaseHashAlgoType::TpmAlgSha512;

        hash_engine.start(hash_algo).unwrap();
        hash_engine.update(&config::TEST_DEVID_CERT_DER).unwrap();
        hash_engine.update(&config::TEST_ALIAS_CERT_DER).unwrap();
        hash_engine.finish(&mut spdm_digest).unwrap();

        let expected_sha512: [u8; 64] = [
            0x71, 0x2b, 0xb1, 0xc2, 0x47, 0xae, 0x24, 0x38, 0xaf, 0x3b, 0xcb, 0x61, 0xd3, 0xd7,
            0x51, 0x25, 0xb0, 0xd5, 0xca, 0xd7, 0x7b, 0x48, 0xab, 0x8f, 0x60, 0xd3, 0x65, 0x9a,
            0xdc, 0xe1, 0xb3, 0x0d, 0xb3, 0x32, 0x9c, 0x22, 0xc6, 0x4c, 0x58, 0x87, 0x97, 0xdc,
            0x59, 0xad, 0x30, 0x73, 0xb5, 0x61, 0xeb, 0x86, 0x7b, 0xc7, 0xd2, 0x19, 0xda, 0x0a,
            0x22, 0x59, 0x09, 0x3d, 0x67, 0xbc, 0xae, 0x80,
        ];
        assert_eq!(spdm_digest.length, 64);
        assert_eq!(spdm_digest.data, expected_sha512);
    }
}

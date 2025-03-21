use sha2::{Digest, Sha256, Sha384, Sha512};
//use hex_literal::hex;
use crate::commands::digests_rsp::SpdmDigest;
use crate::protocol::algorithms::BaseHashAlgoType;

pub enum HashEngineError {
    InvalidParam,
    Sha256Failure,
    Sha384Failure,
    Sha512Failure,
    UnsupportedHashType,
}

// Define the trait for hash engine
pub trait HashEngine {
    fn hash_all(
        &self,
        data: &[u8],
        hash_type: BaseHashAlgoType,
        digest: &mut SpdmDigest,
    ) -> Result<(), HashEngineError>;
}

// use SHA2 as the hash engine
#[derive(Default)]
pub struct HashEngineImpl;

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
        // Use sha2 API Digest to hash the data
        match hash_type {
            BaseHashAlgoType::TpmAlgSha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                let result = hasher.finalize_reset();
                spdm_digest.data[..result.len()].copy_from_slice(&result);
                spdm_digest.length = result.len();
            }
            BaseHashAlgoType::TpmAlgSha384 => {
                let mut hasher = Sha384::new();
                hasher.update(data);
                let result = hasher.finalize_reset();
                spdm_digest.data[..result.len()].copy_from_slice(&result);
                spdm_digest.length = result.len();
            }
            BaseHashAlgoType::TpmAlgSha512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                let result = hasher.finalize_reset();
                spdm_digest.data[..result.len()].copy_from_slice(&result);
                spdm_digest.length = result.len();
            }
            _ => {
                return Err(HashEngineError::UnsupportedHashType);
            }
        }
        Ok(())
    }
}

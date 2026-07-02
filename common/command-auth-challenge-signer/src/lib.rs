// Licensed under the Apache-2.0 license

//! Command authorization trait and implementations for Caliptra MCU.
//!
//! Provides the [`CommandAuthChallengeSigner`] trait and one implementation:
//! - [`AsymmetricCommandAuthorizer`]: Dual asymmetric verification using ECC P-384 and ML-DSA-87.

use anyhow::Result;
use caliptra_image_types::MLDSA87_SIGNATURE_BYTE_SIZE;
use caliptra_mcu_mbox_common::messages::HybridSignature;
use fips204::ml_dsa_87;
use fips204::traits::{KeyGen, Signer as MldsaSigner};
use p384::ecdsa::{signature::Signer, Signature, SigningKey};

/// Trait for authorizing Caliptra commands that require challenge-response signatures.
pub trait CommandAuthChallengeSigner: Send + Sync {
    fn authorize(
        &self,
        cmd_id: u32,
        payload: &[u8],
        challenge: &[u8; 32],
    ) -> Result<HybridSignature>;
}

/// A [`CommandAuthChallengeSigner`] that generates dual asymmetric signatures (ECC P-384 + ML-DSA-87).
pub struct AsymmetricCommandAuthorizer {
    ecc_key: SigningKey,
    mldsa_key: ml_dsa_87::PrivateKey,
}

impl AsymmetricCommandAuthorizer {
    /// Create a new authorizer using the provided ECC private key and ML-DSA seed.
    pub fn new(ecc_key: &[u8], mldsa_seed: &[u8]) -> Result<Self> {
        let ecc_key = SigningKey::from_slice(ecc_key)
            .map_err(|e| anyhow::anyhow!("Failed to load ECC private key: {}", e))?;

        let seed: &[u8; 32] = mldsa_seed
            .try_into()
            .map_err(|_| anyhow::anyhow!("ML-DSA seed must be 32 bytes"))?;

        let (_pk, mldsa_key) = ml_dsa_87::KG::keygen_from_seed(seed);

        Ok(Self { ecc_key, mldsa_key })
    }
}

impl CommandAuthChallengeSigner for AsymmetricCommandAuthorizer {
    fn authorize(
        &self,
        cmd_id: u32,
        payload: &[u8],
        challenge: &[u8; 32],
    ) -> Result<HybridSignature> {
        // Reconstruct the message: cmd_id(BE,4) || payload || challenge(32)
        let mut message = Vec::new();
        message.extend_from_slice(&cmd_id.to_be_bytes());
        message.extend_from_slice(payload);
        message.extend_from_slice(challenge);

        // 1. Sign with ECC P-384
        let ecc_sig: Signature = self.ecc_key.sign(&message);
        let ecc_sig_bytes = ecc_sig.to_bytes(); // 96 bytes

        // 2. Sign with ML-DSA-87
        let mldsa_sig = self
            .mldsa_key
            .try_sign(&message, &[])
            .map_err(|e| anyhow::anyhow!("ML-DSA signing failed: {:?}", e))?; // returns [u8; 4627]

        let mut padded_mldsa_sig = mldsa_sig.to_vec();
        padded_mldsa_sig.resize(MLDSA87_SIGNATURE_BYTE_SIZE, 0u8); // Pad to 4628 bytes

        Ok(HybridSignature {
            ecc_sig_r: ecc_sig_bytes[..48]
                .try_into()
                .map_err(|_| anyhow::anyhow!("Failed to convert ECC signature r"))?,
            ecc_sig_s: ecc_sig_bytes[48..96]
                .try_into()
                .map_err(|_| anyhow::anyhow!("Failed to convert ECC signature s"))?,
            mldsa_sig: padded_mldsa_sig
                .try_into()
                .map_err(|_| anyhow::anyhow!("Failed to convert ML-DSA signature"))?,
        })
    }
}

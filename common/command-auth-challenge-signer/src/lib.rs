// Licensed under the Apache-2.0 license

//! Command authorization trait and implementations for Caliptra MCU.
//!
//! Provides the [`CommandAuthChallengeSigner`] trait and one implementation:
//! - [`AsymmetricCommandAuthorizer`]: Dual asymmetric verification using ECC P-384 and ML-DSA-87.
//!
//! The authorized-command challenge/nonce is 48 bytes wide.

use anyhow::Result;
use caliptra_image_types::MLDSA87_SIGNATURE_BYTE_SIZE;
use caliptra_mcu_mbox_common::messages::HybridSignature;
use fips204::ml_dsa_87;
use fips204::traits::{KeyGen, Signer as MldsaSigner};
use p384::ecdsa::{signature::Signer, Signature, SigningKey};

/// Width of the authorization challenge nonce in bytes. Re-exported from
/// `caliptra-mcu-mbox-common`, the single source of truth for this size.
pub use caliptra_mcu_mbox_common::messages::AUTH_CMD_NONCE_LEN;

// The signer's wire/signing logic assumes a 48-byte nonce; assert it near the
// use site so a future change to the shared constant fails to compile here.
// (Width is fixed by the Caliptra prod-debug-unlock challenge/nonce format.)
const _: () = assert!(AUTH_CMD_NONCE_LEN == 48);

/// Trait for authorizing Caliptra commands that require challenge-response signatures.
pub trait CommandAuthChallengeSigner: Send + Sync {
    fn authorize(
        &self,
        cmd_id: u32,
        payload: &[u8],
        challenge: &[u8; AUTH_CMD_NONCE_LEN],
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
        challenge: &[u8; AUTH_CMD_NONCE_LEN],
    ) -> Result<HybridSignature> {
        // Reconstruct the message: cmd_id(BE,4) || payload || challenge(48)
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

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_image_types::MLDSA87_SIGNATURE_BYTE_SIZE;
    use fips204::traits::Verifier as MldsaVerifier;
    use p384::ecdsa::{signature::Verifier, Signature as EcdsaSignature, VerifyingKey};

    /// Test vendor keypair (matches the integration-test vector).
    const TEST_ECC_PRIV_KEY: [u8; 48] = [
        61, 169, 230, 128, 175, 245, 161, 206, 169, 106, 62, 137, 129, 2, 134, 251, 59, 48, 48,
        169, 201, 36, 173, 47, 32, 49, 160, 125, 41, 64, 82, 169, 124, 175, 161, 252, 110, 167, 96,
        164, 61, 183, 99, 202, 159, 47, 112, 54,
    ];
    const TEST_MLDSA_SEED: [u8; 32] = *b"caliptra-mcu-testing-mldsa-seed-";

    /// The signed message on this baseline is `cmd_id(BE) || payload || challenge`.
    fn message(cmd_id: u32, payload: &[u8], nonce: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&cmd_id.to_be_bytes());
        m.extend_from_slice(payload);
        m.extend_from_slice(nonce);
        m
    }

    /// Recreate the ML-DSA-87 public key from the test seed for verification.
    fn mldsa_pubkey() -> ml_dsa_87::PublicKey {
        let (pk, _sk) = ml_dsa_87::KG::keygen_from_seed(&TEST_MLDSA_SEED);
        pk
    }

    /// `authorize` accepts a 48-byte challenge and produces a well-formed
    /// `HybridSignature` whose BOTH legs verify over the signed message: the
    /// ECDSA leg against the vendor P-384 key, and the ML-DSA-87 leg against the
    /// vendor ML-DSA key.
    #[test]
    fn authorize_round_trips_both_legs() {
        let signer =
            AsymmetricCommandAuthorizer::new(&TEST_ECC_PRIV_KEY, &TEST_MLDSA_SEED).unwrap();
        let cmd_id: u32 = 0x4D43_4650; // MC_FE_PROG ("MCFP")
        let payload = [0xA5u8; 8];
        let challenge = [0x11u8; AUTH_CMD_NONCE_LEN];

        let sig = signer.authorize(cmd_id, &payload, &challenge).unwrap();
        assert_eq!(sig.ecc_sig_r.len(), 48);
        assert_eq!(sig.ecc_sig_s.len(), 48);
        assert_eq!(sig.mldsa_sig.len(), MLDSA87_SIGNATURE_BYTE_SIZE);

        let msg = message(cmd_id, &payload, &challenge);

        // ECDSA leg (p384 hashes the message with SHA-384 internally).
        let vk = VerifyingKey::from(&SigningKey::from_slice(&TEST_ECC_PRIV_KEY).unwrap());
        let mut ecc_bytes = [0u8; 96];
        ecc_bytes[..48].copy_from_slice(&sig.ecc_sig_r);
        ecc_bytes[48..].copy_from_slice(&sig.ecc_sig_s);
        assert!(vk
            .verify(&msg, &EcdsaSignature::from_slice(&ecc_bytes).unwrap())
            .is_ok());

        // ML-DSA-87 leg: fips204 sig is the first 4627 bytes (the struct pads to 4628).
        let mldsa_sig: [u8; 4627] = sig.mldsa_sig[..4627].try_into().unwrap();
        assert!(mldsa_pubkey().verify(&msg, &mldsa_sig, &[]));
    }

    /// A challenge that differs from the one signed must NOT verify on EITHER
    /// leg (freshness) — checked for ECDSA and ML-DSA-87.
    #[test]
    fn wrong_nonce_does_not_verify_either_leg() {
        let signer =
            AsymmetricCommandAuthorizer::new(&TEST_ECC_PRIV_KEY, &TEST_MLDSA_SEED).unwrap();
        let cmd_id: u32 = 0x4D43_4650;
        let payload = [0xA5u8; 8];
        let sig = signer
            .authorize(cmd_id, &payload, &[0x11u8; AUTH_CMD_NONCE_LEN])
            .unwrap();

        // Message built with a DIFFERENT nonce.
        let wrong = message(cmd_id, &payload, &[0x22u8; AUTH_CMD_NONCE_LEN]);

        let vk = VerifyingKey::from(&SigningKey::from_slice(&TEST_ECC_PRIV_KEY).unwrap());
        let mut ecc_bytes = [0u8; 96];
        ecc_bytes[..48].copy_from_slice(&sig.ecc_sig_r);
        ecc_bytes[48..].copy_from_slice(&sig.ecc_sig_s);
        assert!(vk
            .verify(&wrong, &EcdsaSignature::from_slice(&ecc_bytes).unwrap())
            .is_err());

        let mldsa_sig: [u8; 4627] = sig.mldsa_sig[..4627].try_into().unwrap();
        assert!(!mldsa_pubkey().verify(&wrong, &mldsa_sig, &[]));
    }
}

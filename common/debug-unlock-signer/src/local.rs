// Licensed under the Apache-2.0 license

use crate::{
    ProdDebugUnlockChallenge, ProdDebugUnlockToken, ECC_PUBLIC_KEY_WORD_SIZE,
    MLDSA_PUBLIC_KEY_WORD_SIZE, MLDSA_SIGNATURE_WORD_SIZE,
};
use anyhow::Result;

use crate::DebugUnlockSigner;

/// Keys needed to sign a production debug unlock token locally.
#[derive(Clone)]
pub struct DebugUnlockKeys {
    /// P-384 private key bytes (48 bytes, big-endian scalar).
    pub ecc_private_key_bytes: [u8; 48],
    /// P-384 public key as big-endian u32 words: X (12 words) || Y (12 words).
    pub ecc_public_key: [u32; ECC_PUBLIC_KEY_WORD_SIZE],
    /// ML-DSA-87 private key bytes.
    pub mldsa_private_key_bytes: Vec<u8>,
    /// ML-DSA-87 public key as little-endian u32 words.
    pub mldsa_public_key: [u32; MLDSA_PUBLIC_KEY_WORD_SIZE],
}

/// A [`DebugUnlockSigner`] that signs tokens locally using in-memory keys.
pub struct LocalDebugUnlockSigner {
    keys: DebugUnlockKeys,
}

impl LocalDebugUnlockSigner {
    pub fn new(keys: DebugUnlockKeys) -> Self {
        Self { keys }
    }
}

impl DebugUnlockSigner for LocalDebugUnlockSigner {
    fn sign_debug_unlock_token(
        &self,
        challenge: &ProdDebugUnlockChallenge,
        unlock_level: u8,
    ) -> Result<ProdDebugUnlockToken> {
        use ecdsa::signature::hazmat::PrehashSigner;
        use ecdsa::{Signature, SigningKey as EcdsaSigningKey};
        use fips204::traits::SerDes;
        use sha2::{Digest, Sha384, Sha512};

        let keys = &self.keys;

        let mut token = ProdDebugUnlockToken {
            length: ((std::mem::size_of::<ProdDebugUnlockToken>()) / 4) as u32,
            unique_device_identifier: challenge.unique_device_identifier,
            unlock_level,
            reserved: [0; 3],
            challenge: challenge.challenge,
            ecc_public_key: keys.ecc_public_key,
            mldsa_public_key: keys.mldsa_public_key,
            ..Default::default()
        };

        // --- ECDSA (P-384) signature over SHA-384 digest ---
        let mut hasher = Sha384::new();
        Digest::update(&mut hasher, token.unique_device_identifier);
        Digest::update(&mut hasher, [token.unlock_level]);
        Digest::update(&mut hasher, token.reserved);
        Digest::update(&mut hasher, token.challenge);
        let ecdsa_hash: [u8; 48] = hasher.finalize().into();

        let ecc_secret = p384::SecretKey::from_slice(&keys.ecc_private_key_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid ECC private key: {}", e))?;
        let signing_key = EcdsaSigningKey::<p384::NistP384>::from(&ecc_secret);
        let ecdsa_sig: Signature<p384::NistP384> = signing_key
            .sign_prehash(&ecdsa_hash)
            .map_err(|e| anyhow::anyhow!("ECDSA signing failed: {}", e))?;

        let r_bytes = ecdsa_sig.r().to_bytes();
        let s_bytes = ecdsa_sig.s().to_bytes();
        for (i, chunk) in r_bytes.chunks(4).enumerate() {
            token.ecc_signature[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }
        for (i, chunk) in s_bytes.chunks(4).enumerate() {
            token.ecc_signature[i + 12] = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        // --- ML-DSA-87 signature over SHA-512 digest ---
        let mut hasher = Sha512::new();
        Digest::update(&mut hasher, token.unique_device_identifier);
        Digest::update(&mut hasher, [token.unlock_level]);
        Digest::update(&mut hasher, token.reserved);
        Digest::update(&mut hasher, token.challenge);
        let mldsa_hash: [u8; 64] = hasher.finalize().into();

        let mldsa_priv_key_arr: [u8; 4896] = keys
            .mldsa_private_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| {
                anyhow::anyhow!(
                    "Invalid MLDSA private key size: expected 4896, got {}",
                    keys.mldsa_private_key_bytes.len()
                )
            })?;
        let mldsa_private_key = fips204::ml_dsa_87::PrivateKey::try_from_bytes(mldsa_priv_key_arr)
            .map_err(|_| anyhow::anyhow!("Failed to parse ML-DSA-87 private key"))?;

        use fips204::traits::Signer;
        let mldsa_sig = mldsa_private_key
            .try_sign_with_seed(&[0u8; 32], &mldsa_hash, &[])
            .map_err(|_| anyhow::anyhow!("ML-DSA-87 signing failed"))?;

        // Pad to MLDSA_SIGNATURE_WORD_SIZE * 4 bytes and write as LE u32 words.
        let mut sig_padded = [0u8; MLDSA_SIGNATURE_WORD_SIZE * 4];
        sig_padded[..mldsa_sig.len()].copy_from_slice(&mldsa_sig);
        for (i, chunk) in sig_padded.chunks(4).enumerate() {
            token.mldsa_signature[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        Ok(token)
    }
}

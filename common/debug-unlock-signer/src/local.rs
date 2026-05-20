// Licensed under the Apache-2.0 license

use crate::{
    ProdDebugUnlockChallenge, ProdDebugUnlockToken, ECC_PUBLIC_KEY_WORD_SIZE,
    MLDSA_PUBLIC_KEY_WORD_SIZE, MLDSA_SIGNATURE_WORD_SIZE,
};
use anyhow::Result;
use std::io::{Read, Write};
use std::path::Path;

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

impl DebugUnlockKeys {
    /// Serialize keys to a binary file.
    ///
    /// Format: `[ecc_priv: 48][ecc_pub: 96][mldsa_priv_len: 4][mldsa_priv: N][mldsa_pub: 2592]`
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let mut file = std::fs::File::create(path)?;
        file.write_all(&self.ecc_private_key_bytes)?;
        for word in &self.ecc_public_key {
            file.write_all(&word.to_le_bytes())?;
        }
        let mldsa_priv_len = self.mldsa_private_key_bytes.len() as u32;
        file.write_all(&mldsa_priv_len.to_le_bytes())?;
        file.write_all(&self.mldsa_private_key_bytes)?;
        for word in &self.mldsa_public_key {
            file.write_all(&word.to_le_bytes())?;
        }
        Ok(())
    }

    /// Deserialize keys from a binary file written by [`save_to_file`].
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let mut file = std::fs::File::open(path)?;

        let mut ecc_private_key_bytes = [0u8; 48];
        file.read_exact(&mut ecc_private_key_bytes)?;

        let mut ecc_public_key = [0u32; ECC_PUBLIC_KEY_WORD_SIZE];
        for word in &mut ecc_public_key {
            let mut buf = [0u8; 4];
            file.read_exact(&mut buf)?;
            *word = u32::from_le_bytes(buf);
        }

        let mut len_buf = [0u8; 4];
        file.read_exact(&mut len_buf)?;
        let mldsa_priv_len = u32::from_le_bytes(len_buf) as usize;
        // ML-DSA-87 private keys are always exactly 4896 bytes.
        const MLDSA_PRIVATE_KEY_SIZE: usize = 4896;
        if mldsa_priv_len != MLDSA_PRIVATE_KEY_SIZE {
            return Err(anyhow::anyhow!(
                "Invalid MLDSA private key size: expected {}, got {}",
                MLDSA_PRIVATE_KEY_SIZE,
                mldsa_priv_len
            ));
        }
        let mut mldsa_private_key_bytes = vec![0u8; mldsa_priv_len];
        file.read_exact(&mut mldsa_private_key_bytes)?;

        let mut mldsa_public_key = [0u32; MLDSA_PUBLIC_KEY_WORD_SIZE];
        for word in &mut mldsa_public_key {
            let mut buf = [0u8; 4];
            file.read_exact(&mut buf)?;
            *word = u32::from_le_bytes(buf);
        }

        Ok(Self {
            ecc_private_key_bytes,
            ecc_public_key,
            mldsa_private_key_bytes,
            mldsa_public_key,
        })
    }
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

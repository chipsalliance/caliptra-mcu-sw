// Licensed under the Apache-2.0 license

//! Command authorization trait and implementations for Caliptra MCU.
//!
//! Provides the [`CommandAuthChallengeSigner`] trait and one implementation:
//! - [`AsymmetricCommandAuthorizer`]: Dual asymmetric verification using ECC P-384 and ML-DSA-87.
//!
//! Both signature legs sign a digest of the raw pre-image (ECDSA over SHA-384,
//! ML-DSA over SHA-512), mirroring the prod-debug-unlock idiom.

use anyhow::Result;
use caliptra_image_types::{MLDSA87_PUB_KEY_BYTE_SIZE, MLDSA87_SIGNATURE_BYTE_SIZE};
use caliptra_mcu_mbox_common::messages::HybridSignature;
use fips204::ml_dsa_87;
use fips204::traits::{KeyGen, SerDes, Signer as MldsaSigner};
use p384::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha384, Sha512};

/// Width of the authorization challenge nonce in bytes. Re-exported from
/// `caliptra-mcu-mbox-common`, the single source of truth for this size.
pub use caliptra_mcu_mbox_common::messages::AUTH_CMD_NONCE_LEN;

// The signer's wire/signing logic assumes a 48-byte nonce; assert it near the
// use site so a future change to the shared constant fails to compile here.
const _: () = assert!(AUTH_CMD_NONCE_LEN == 48);

/// Trait for authorizing Caliptra commands that require challenge-response signatures.
pub trait CommandAuthChallengeSigner: Send + Sync {
    fn authorize(
        &self,
        cmd_id: u32,
        payload: &[u8],
        challenge: &[u8; AUTH_CMD_NONCE_LEN],
    ) -> Result<HybridSignature>;

    /// The public keys that must travel on the wire so the device can verify the
    /// signatures. The device holds only their SHA-384 anchor and checks that the
    /// received keys hash to it before using them. Returns
    /// `(ecc_pub_x, ecc_pub_y, mldsa_pub)` in standard big-endian `u8` form.
    ///
    /// On the trait so both the mailbox and SPDM validators can obtain the keys
    /// through a `Box<dyn CommandAuthChallengeSigner>`.
    fn public_keys(
        &self,
    ) -> Result<(
        [u8; ECC_P384_COORD_SIZE],
        [u8; ECC_P384_COORD_SIZE],
        [u8; MLDSA87_PUB_KEY_BYTE_SIZE],
    )>;
}

/// Size in bytes of a P-384 public-key coordinate (X or Y).
pub const ECC_P384_COORD_SIZE: usize = 48;

/// A [`CommandAuthChallengeSigner`] that generates dual asymmetric signatures (ECC P-384 + ML-DSA-87).
pub struct AsymmetricCommandAuthorizer {
    ecc_key: SigningKey,
    mldsa_key: ml_dsa_87::PrivateKey,
    /// ML-DSA-87 public key bytes, retained so the caller can transmit it on the
    /// wire (the device holds only its hash, not the key itself).
    mldsa_pub: [u8; MLDSA87_PUB_KEY_BYTE_SIZE],
}

impl AsymmetricCommandAuthorizer {
    /// Create a new authorizer using the provided ECC private key and ML-DSA seed.
    pub fn new(ecc_key: &[u8], mldsa_seed: &[u8]) -> Result<Self> {
        let ecc_key = SigningKey::from_slice(ecc_key)
            .map_err(|e| anyhow::anyhow!("Failed to load ECC private key: {}", e))?;

        let seed: &[u8; 32] = mldsa_seed
            .try_into()
            .map_err(|_| anyhow::anyhow!("ML-DSA seed must be 32 bytes"))?;

        let (pk, mldsa_key) = ml_dsa_87::KG::keygen_from_seed(seed);

        Ok(Self {
            ecc_key,
            mldsa_key,
            mldsa_pub: pk.into_bytes(),
        })
    }

    /// The device-side anchor: `SHA-384(ecc_pub_x || ecc_pub_y || mldsa_pub)` over the
    /// standard big-endian `u8` serialization of the public keys (the exact bytes
    /// returned by [`public_keys`] and transmitted on the wire). The device embeds
    /// this 48-byte digest and matches the received keys against it.
    pub fn anchor(&self) -> Result<[u8; 48]> {
        let (ecc_pub_x, ecc_pub_y, mldsa_pub) = self.public_keys()?;
        let mut hasher = Sha384::new();
        hasher.update(ecc_pub_x);
        hasher.update(ecc_pub_y);
        hasher.update(mldsa_pub);
        Ok(hasher.finalize().into())
    }
}

impl CommandAuthChallengeSigner for AsymmetricCommandAuthorizer {
    fn authorize(
        &self,
        cmd_id: u32,
        payload: &[u8],
        challenge: &[u8; AUTH_CMD_NONCE_LEN],
    ) -> Result<HybridSignature> {
        // Build the pre-image: cmd_id(BE,4) || payload || nonce(48). This mirrors the
        // prod-debug-unlock authorization idiom: each leg signs a digest of the raw
        // pre-image (ECDSA over SHA-384, ML-DSA over SHA-512), rather than signing an
        // inner-hashed transcript. The nonce TRAVELS on the wire (prod-debug-unlock
        // idiom): the device compares the wire nonce to its stored one-time challenge,
        // then rebuilds this identical pre-image from the wire copy before verifying.
        let mut pre_image = Vec::with_capacity(4 + payload.len() + AUTH_CMD_NONCE_LEN);
        pre_image.extend_from_slice(&cmd_id.to_be_bytes());
        pre_image.extend_from_slice(payload);
        pre_image.extend_from_slice(challenge);

        // 1. ECC P-384 over SHA-384(pre-image). `sign` hashes the pre-image with the
        //    curve's SHA-384 digest internally, matching the device's ECDSA verify
        //    over SHA-384(pre-image).
        let ecc_sig: Signature = self.ecc_key.sign(&pre_image);
        let ecc_sig_bytes = ecc_sig.to_bytes(); // 96 bytes

        // 2. ML-DSA-87 over SHA-512(pre-image): sign the 64-byte SHA-512 digest as the
        //    message (external pre-hash), matching the device's verify over the same
        //    digest.
        let mldsa_msg: [u8; 64] = Sha512::digest(&pre_image).into();
        let mldsa_sig = self
            .mldsa_key
            .try_sign(&mldsa_msg, &[])
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

    fn public_keys(
        &self,
    ) -> Result<(
        [u8; ECC_P384_COORD_SIZE],
        [u8; ECC_P384_COORD_SIZE],
        [u8; MLDSA87_PUB_KEY_BYTE_SIZE],
    )> {
        // P-384 public key serialized as the uncompressed SEC1 point 0x04 || X || Y;
        // X and Y are the two 48-byte coordinates.
        let point = self.ecc_key.verifying_key().to_encoded_point(false);
        let x = point
            .x()
            .ok_or_else(|| anyhow::anyhow!("ECC public key missing X coordinate"))?;
        let y = point
            .y()
            .ok_or_else(|| anyhow::anyhow!("ECC public key missing Y coordinate"))?;

        // GenericArray<u8, 48> -> [u8; 48] is infallible.
        let ecc_pub_x: [u8; ECC_P384_COORD_SIZE] = (*x).into();
        let ecc_pub_y: [u8; ECC_P384_COORD_SIZE] = (*y).into();

        Ok((ecc_pub_x, ecc_pub_y, self.mldsa_pub))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test vendor keypair. These MUST match the constants the device firmware
    /// (`auth_keys.rs`) derives its embedded `AUTH_PK_HASH` from and the integration
    /// tests sign with.
    const TEST_ECC_PRIV_KEY: [u8; 48] = [
        61, 169, 230, 128, 175, 245, 161, 206, 169, 106, 62, 137, 129, 2, 134, 251, 59, 48, 48,
        169, 201, 36, 173, 47, 32, 49, 160, 125, 41, 64, 82, 169, 124, 175, 161, 252, 110, 167, 96,
        164, 61, 183, 99, 202, 159, 47, 112, 54,
    ];
    const TEST_MLDSA_SEED: [u8; 32] = *b"caliptra-mcu-testing-mldsa-seed-";

    /// Recreate the ML-DSA-87 public key from the test seed for verification.
    fn mldsa_pubkey() -> ml_dsa_87::PublicKey {
        let (pk, _sk) = ml_dsa_87::KG::keygen_from_seed(&TEST_MLDSA_SEED);
        pk
    }

    /// `anchor()` must equal `SHA-384(ecc_pub_x || ecc_pub_y || mldsa_pub)` computed
    /// independently from `public_keys()` — the exact invariant the device relies on.
    #[test]
    fn anchor_matches_hash_of_public_keys() {
        let signer =
            AsymmetricCommandAuthorizer::new(&TEST_ECC_PRIV_KEY, &TEST_MLDSA_SEED).unwrap();
        let (x, y, mldsa) = signer.public_keys().unwrap();

        let mut hasher = Sha384::new();
        hasher.update(x);
        hasher.update(y);
        hasher.update(mldsa);
        let expected: [u8; 48] = hasher.finalize().into();

        assert_eq!(signer.anchor().unwrap(), expected);
    }

    /// Known-Answer Test: emit the device-side `AUTH_PK_HASH` for the test keypair.
    /// Run with `--nocapture` to copy the 48-byte array into `auth_keys.rs`.
    #[test]
    fn print_auth_pk_hash_for_test_keypair() {
        let signer =
            AsymmetricCommandAuthorizer::new(&TEST_ECC_PRIV_KEY, &TEST_MLDSA_SEED).unwrap();
        let anchor = signer.anchor().unwrap();
        println!("AUTH_PK_HASH (SHA-384(ecc_x||ecc_y||mldsa_pub)) for the test keypair:");
        println!("pub const AUTH_PK_HASH: [u8; 48] = [");
        for chunk in anchor.chunks(8) {
            let line: String = chunk.iter().map(|b| format!("0x{b:02x}, ")).collect();
            println!("    {line}");
        }
        println!("];");
    }

    /// Any payload size authorizes and yields the fixed-size signature struct
    /// (proves the pre-image did not blow an internal cap).
    #[test]
    fn authorizes_regardless_of_payload_size() {
        let signer =
            AsymmetricCommandAuthorizer::new(&TEST_ECC_PRIV_KEY, &TEST_MLDSA_SEED).unwrap();
        let short = signer
            .authorize(0x4D43_4650, &[0u8; 4], &[7u8; AUTH_CMD_NONCE_LEN])
            .unwrap();
        let long = signer
            .authorize(0x4D43_4650, &[0u8; 52], &[7u8; AUTH_CMD_NONCE_LEN])
            .unwrap();
        assert_eq!(short.mldsa_sig.len(), long.mldsa_sig.len());
    }

    /// The ECDSA leg verifies over SHA-384(pre-image) where
    /// pre-image = cmd_id(BE) || payload || nonce (raw, no inner payload hash) —
    /// mirroring the prod-debug-unlock idiom. Proves host/device agree on the ECC
    /// pre-image and that the 48-byte nonce is bound.
    #[test]
    fn ecdsa_leg_verifies_over_raw_preimage() {
        use p384::ecdsa::{signature::Verifier, Signature as EcdsaSignature, VerifyingKey};
        let signer =
            AsymmetricCommandAuthorizer::new(&TEST_ECC_PRIV_KEY, &TEST_MLDSA_SEED).unwrap();
        let cmd_id: u32 = 0x4D43_4650;
        let payload = [0xA5u8; 8];
        let nonce = [0x11u8; AUTH_CMD_NONCE_LEN];

        let sig = signer.authorize(cmd_id, &payload, &nonce).unwrap();

        let mut pre_image = Vec::new();
        pre_image.extend_from_slice(&cmd_id.to_be_bytes());
        pre_image.extend_from_slice(&payload);
        pre_image.extend_from_slice(&nonce);

        let vk = VerifyingKey::from(&SigningKey::from_slice(&TEST_ECC_PRIV_KEY).unwrap());
        let mut sig_bytes = [0u8; 96];
        sig_bytes[..48].copy_from_slice(&sig.ecc_sig_r);
        sig_bytes[48..].copy_from_slice(&sig.ecc_sig_s);
        let ecdsa_sig = EcdsaSignature::from_slice(&sig_bytes).unwrap();
        // `verify` hashes the message with the curve digest (SHA-384), so verifying
        // the raw pre-image proves the signature is over SHA-384(pre-image).
        assert!(vk.verify(&pre_image, &ecdsa_sig).is_ok());

        // A different nonce changes the pre-image, so the signature must not verify.
        let mut other = Vec::new();
        other.extend_from_slice(&cmd_id.to_be_bytes());
        other.extend_from_slice(&payload);
        other.extend_from_slice(&[0x22u8; AUTH_CMD_NONCE_LEN]);
        assert!(vk.verify(&other, &ecdsa_sig).is_err());
    }

    /// The ML-DSA-87 leg verifies over SHA-512(pre-image) where
    /// pre-image = cmd_id(BE) || payload || nonce — the same digest the device
    /// feeds to the Caliptra MLDSA87_SIGNATURE_VERIFY mailbox command. Proves the
    /// PQC leg is present, correct, and bound to the 48-byte nonce.
    #[test]
    fn mldsa_leg_verifies_over_sha512_preimage() {
        use fips204::traits::Verifier as MldsaVerifier;
        let signer =
            AsymmetricCommandAuthorizer::new(&TEST_ECC_PRIV_KEY, &TEST_MLDSA_SEED).unwrap();
        let cmd_id: u32 = 0x4D43_4650;
        let payload = [0xA5u8; 8];
        let nonce = [0x11u8; AUTH_CMD_NONCE_LEN];

        let sig = signer.authorize(cmd_id, &payload, &nonce).unwrap();

        let mut pre_image = Vec::new();
        pre_image.extend_from_slice(&cmd_id.to_be_bytes());
        pre_image.extend_from_slice(&payload);
        pre_image.extend_from_slice(&nonce);

        // fips204 sig is the first 4627 bytes (the HybridSignature struct pads to 4628).
        let mldsa_sig: [u8; 4627] = sig.mldsa_sig[..4627].try_into().unwrap();

        // Positive: verify over SHA-512(pre-image), the message the signer signed.
        let mldsa_msg: [u8; 64] = Sha512::digest(&pre_image).into();
        assert!(mldsa_pubkey().verify(&mldsa_msg, &mldsa_sig, &[]));

        // Negative: a different nonce changes the digest, so the leg must reject.
        let mut other = Vec::new();
        other.extend_from_slice(&cmd_id.to_be_bytes());
        other.extend_from_slice(&payload);
        other.extend_from_slice(&[0x22u8; AUTH_CMD_NONCE_LEN]);
        let wrong_msg: [u8; 64] = Sha512::digest(&other).into();
        assert!(!mldsa_pubkey().verify(&wrong_msg, &mldsa_sig, &[]));
    }
}

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
use caliptra_mcu_mbox_common::authorization::{ecc_public_key_core_bytes, AuthorizationMetadata};
use caliptra_mcu_mbox_common::messages::{
    HybridSignature, DOT_ECC_PUBLIC_KEY_COORD_SIZE, DOT_MLDSA_PUBLIC_KEY_SIZE,
};
use fips204::ml_dsa_87;
use fips204::traits::{KeyGen, SerDes, Signer as MldsaSigner};
use p384::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha384, Sha512};
use zerocopy::IntoBytes;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Width of the authorization challenge nonce in bytes. Re-exported from
/// `caliptra-mcu-mbox-common`, the single source of truth for this size.
pub use caliptra_mcu_mbox_common::messages::AUTH_CMD_NONCE_LEN;

// The signer's wire/signing logic assumes a 48-byte nonce; assert it near the
// use site so a future change to the shared constant fails to compile here.
const _: () = assert!(AUTH_CMD_NONCE_LEN == 48);

/// Trait for authorizing Caliptra commands that require challenge-response signatures.
pub trait CommandAuthChallengeSigner: Send + Sync {
    /// Sign Owner-only/Fleet metadata; use `authorize_with_metadata` for an explicit target.
    fn authorize(
        &self,
        cmd_id: u32,
        payload: &[u8],
        challenge: &[u8; AUTH_CMD_NONCE_LEN],
    ) -> Result<HybridSignature> {
        self.authorize_with_metadata(
            cmd_id,
            payload,
            &AuthorizationMetadata::default(),
            challenge,
        )
    }

    fn authorize_with_metadata(
        &self,
        cmd_id: u32,
        payload: &[u8],
        metadata: &AuthorizationMetadata,
        nonce: &[u8; AUTH_CMD_NONCE_LEN],
    ) -> Result<HybridSignature>;

    /// The public keys that must travel on the wire so the device can verify the
    /// signatures. The device holds only their SHA-384 anchor and checks that the
    /// received keys hash to it before using them. Returns
    /// `(ecc_pub_x, ecc_pub_y, mldsa_pub)` with standard big-endian ECC
    /// coordinates and the algorithm-defined ML-DSA byte representation.
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridPublicKeys {
    pub ecc_pub_x: [u8; DOT_ECC_PUBLIC_KEY_COORD_SIZE],
    pub ecc_pub_y: [u8; DOT_ECC_PUBLIC_KEY_COORD_SIZE],
    pub mldsa_pub: [u8; DOT_MLDSA_PUBLIC_KEY_SIZE],
}

impl HybridPublicKeys {
    /// Compute the DOT lock-authentication-key hash using Caliptra's public-key
    /// byte ordering: each ECC coordinate word is byte-reversed before SHA-384,
    /// while the ML-DSA public key remains in its natural wire order.
    pub fn dot_lak_hash(&self) -> [u8; 48] {
        let mut hasher = Sha384::new();
        hasher.update(ecc_public_key_core_bytes(&self.ecc_pub_x, &self.ecc_pub_y));
        hasher.update(self.mldsa_pub);
        hasher.finalize().into()
    }
}

/// Signs native command transcripts whose signature format matches the
/// authorized-command hybrid key material but whose transcript rules differ.
pub trait HybridMessageSigner: Send + Sync {
    fn dot_public_keys(&self) -> Result<HybridPublicKeys>;
    fn sign_message(&self, message: &[u8]) -> Result<HybridSignature>;
}

/// A [`CommandAuthChallengeSigner`] that generates dual asymmetric signatures (ECC P-384 + ML-DSA-87).
pub struct AsymmetricCommandAuthorizer {
    ecc_key: SigningKey,
    mldsa_key: ml_dsa_87::PrivateKey,
    /// ML-DSA-87 public key bytes, retained so the caller can transmit it on the
    /// wire (the device holds only its hash, not the key itself).
    mldsa_pub: [u8; MLDSA87_PUB_KEY_BYTE_SIZE],
}

impl Drop for AsymmetricCommandAuthorizer {
    fn drop(&mut self) {
        self.mldsa_pub.zeroize();
    }
}

// The ECC and ML-DSA private-key fields zeroize themselves on drop; the
// implementation above covers the remaining cached key material.
impl ZeroizeOnDrop for AsymmetricCommandAuthorizer {}

impl AsymmetricCommandAuthorizer {
    /// Create a new authorizer using the provided ECC private key and ML-DSA seed.
    pub fn new(ecc_key: &[u8], mldsa_seed: &[u8]) -> Result<Self> {
        let ecc_key = SigningKey::from_slice(ecc_key)
            .map_err(|e| anyhow::anyhow!("Failed to load ECC private key: {}", e))?;

        let seed = Zeroizing::new(
            <[u8; 32]>::try_from(mldsa_seed)
                .map_err(|_| anyhow::anyhow!("ML-DSA seed must be 32 bytes"))?,
        );

        let (pk, mldsa_key) = ml_dsa_87::KG::keygen_from_seed(&seed);

        Ok(Self {
            ecc_key,
            mldsa_key,
            mldsa_pub: pk.into_bytes(),
        })
    }

    /// SHA-384 of the Core-encoded ECC coordinates followed by the raw ML-DSA key.
    pub fn anchor(&self) -> Result<[u8; 48]> {
        Ok(self.dot_public_keys()?.dot_lak_hash())
    }
}

impl HybridMessageSigner for AsymmetricCommandAuthorizer {
    fn dot_public_keys(&self) -> Result<HybridPublicKeys> {
        let (ecc_pub_x, ecc_pub_y, mldsa_pub) = CommandAuthChallengeSigner::public_keys(self)?;
        Ok(HybridPublicKeys {
            ecc_pub_x,
            ecc_pub_y,
            mldsa_pub,
        })
    }

    fn sign_message(&self, message: &[u8]) -> Result<HybridSignature> {
        let ecc_sig: Signature = self.ecc_key.sign(message);
        let ecc_sig_bytes = ecc_sig.to_bytes();
        let mldsa_sig = self
            .mldsa_key
            .try_sign(message, &[])
            .map_err(|e| anyhow::anyhow!("ML-DSA signing failed: {:?}", e))?;

        let mut padded_mldsa_sig = mldsa_sig.to_vec();
        padded_mldsa_sig.resize(MLDSA87_SIGNATURE_BYTE_SIZE, 0u8);

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

impl CommandAuthChallengeSigner for AsymmetricCommandAuthorizer {
    fn authorize_with_metadata(
        &self,
        cmd_id: u32,
        payload: &[u8],
        metadata: &AuthorizationMetadata,
        nonce: &[u8; AUTH_CMD_NONCE_LEN],
    ) -> Result<HybridSignature> {
        metadata
            .validate()
            .map_err(|error| anyhow::anyhow!("Invalid authorization metadata: {error:?}"))?;
        let mut pre_image = Zeroizing::new(Vec::with_capacity(
            4 + payload.len() + metadata.as_bytes().len() + AUTH_CMD_NONCE_LEN,
        ));
        pre_image.extend_from_slice(&cmd_id.to_be_bytes());
        pre_image.extend_from_slice(payload);
        pre_image.extend_from_slice(metadata.as_bytes());
        pre_image.extend_from_slice(nonce);

        // 1. ECC P-384 over SHA-384(pre-image). `sign` hashes the pre-image with the
        //    curve's SHA-384 digest internally, matching the device's ECDSA verify
        //    over SHA-384(pre-image).
        let ecc_sig: Signature = self.ecc_key.sign(&pre_image);
        let ecc_sig_bytes = ecc_sig.to_bytes(); // 96 bytes

        // 2. ML-DSA-87 over SHA-512(pre-image): sign the 64-byte SHA-512 digest as the
        //    message (external pre-hash), matching the device's verify over the same
        //    digest.
        let mldsa_msg = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(&pre_image)));
        let mldsa_sig = self
            .mldsa_key
            .try_sign(&mldsa_msg[..], &[])
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

    /// Test keypair used by host validators and explicitly provisioned test manifests.
    const TEST_ECC_PRIV_KEY: [u8; 48] = [
        61, 169, 230, 128, 175, 245, 161, 206, 169, 106, 62, 137, 129, 2, 134, 251, 59, 48, 48,
        169, 201, 36, 173, 47, 32, 49, 160, 125, 41, 64, 82, 169, 124, 175, 161, 252, 110, 167, 96,
        164, 61, 183, 99, 202, 159, 47, 112, 54,
    ];
    const TEST_MLDSA_SEED: [u8; 32] = *b"caliptra-mcu-testing-mldsa-seed-";

    #[test]
    fn private_key_owners_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<SigningKey>();
        assert_zeroize_on_drop::<ml_dsa_87::PrivateKey>();
        assert_zeroize_on_drop::<AsymmetricCommandAuthorizer>();
    }

    /// Recreate the ML-DSA-87 public key from the test seed for verification.
    fn mldsa_pubkey() -> ml_dsa_87::PublicKey {
        let (pk, _sk) = ml_dsa_87::KG::keygen_from_seed(&TEST_MLDSA_SEED);
        pk
    }

    /// Independently reconstruct Core's key encoding rather than reuse its helper.
    #[test]
    fn anchor_matches_hash_of_public_keys() {
        let signer =
            AsymmetricCommandAuthorizer::new(&TEST_ECC_PRIV_KEY, &TEST_MLDSA_SEED).unwrap();
        let (x, y, mldsa) = signer.public_keys().unwrap();

        let mut hasher = Sha384::new();
        for coordinate in [&x, &y] {
            for word in coordinate.chunks_exact(4) {
                hasher.update([word[3], word[2], word[1], word[0]]);
            }
        }
        hasher.update(mldsa);
        let expected: [u8; 48] = hasher.finalize().into();

        assert_eq!(signer.anchor().unwrap(), expected);
    }

    /// Emit public key digests for explicit test-manifest provisioning.
    #[test]
    fn print_auth_pk_hash_for_test_keypair() {
        let signer =
            AsymmetricCommandAuthorizer::new(&TEST_ECC_PRIV_KEY, &TEST_MLDSA_SEED).unwrap();
        let anchor = signer.anchor().unwrap();
        println!("Core-compatible command-authorization anchor for the test keypair:");
        println!("pub const TEST_OWNER_COMMAND_KEY_DIGEST: [u8; 48] = [");
        for chunk in anchor.chunks(8) {
            let line: String = chunk.iter().map(|b| format!("0x{b:02x}, ")).collect();
            println!("    {line}");
        }
        println!("];");
        for label in [
            "caliptra-mcu-test-vendor-authorization-keys",
            "caliptra-mcu-test-owner-authorization-keys",
        ] {
            let mldsa_seed = sha2::Sha256::digest(label.as_bytes());
            let ecc_key = sha2::Sha384::digest([label.as_bytes(), b"\x00"].concat());
            let signer = AsymmetricCommandAuthorizer::new(&ecc_key, &mldsa_seed).unwrap();
            println!("{label}: {:02x?}", signer.anchor().unwrap());
        }
    }

    #[test]
    fn auth_pk_hash_matches_test_keypair_anchor() {
        let signer =
            AsymmetricCommandAuthorizer::new(&TEST_ECC_PRIV_KEY, &TEST_MLDSA_SEED).unwrap();
        let expected_auth_pk_hash: [u8; 48] = [
            0xb7, 0xad, 0x44, 0xdd, 0x5f, 0x13, 0xf6, 0x9e, 0x30, 0xe3, 0xf4, 0x82, 0x6d, 0xe7,
            0x30, 0xbb, 0x54, 0x2d, 0x49, 0x28, 0xb5, 0x2d, 0x85, 0xab, 0xc5, 0xb0, 0xf5, 0x92,
            0x52, 0x48, 0x92, 0xd5, 0xdd, 0x6f, 0xe7, 0xa2, 0x48, 0x16, 0x7f, 0x71, 0xb8, 0x32,
            0xf0, 0x81, 0xab, 0x0a, 0x6e, 0x9b,
        ];
        assert_eq!(signer.anchor().unwrap(), expected_auth_pk_hash);
    }

    #[test]
    fn vendor_anchor_matches_known_answer() {
        let mldsa_seed = sha2::Sha256::digest(b"caliptra-mcu-test-vendor-authorization-keys");
        let ecc_key = sha2::Sha384::digest(b"caliptra-mcu-test-vendor-authorization-keys\x00");
        let signer = AsymmetricCommandAuthorizer::new(&ecc_key, &mldsa_seed).unwrap();
        let expected_vendor_anchor: [u8; 48] = [
            0x6f, 0xbc, 0xc7, 0xbe, 0x9f, 0x97, 0xe0, 0xab, 0x6c, 0x4c, 0x54, 0x70, 0xee, 0xce,
            0x7e, 0xa9, 0x48, 0x8b, 0xab, 0xd9, 0x90, 0xfa, 0x36, 0x60, 0x82, 0xd5, 0xc1, 0xa7,
            0xc3, 0x7d, 0x6f, 0x5e, 0x9d, 0x7f, 0x6c, 0x43, 0x31, 0xea, 0xfa, 0x07, 0xfa, 0x60,
            0x3b, 0x1c, 0xf1, 0x8b, 0xec, 0x20,
        ];
        assert_eq!(signer.anchor().unwrap(), expected_vendor_anchor);
    }

    #[test]
    fn owner_anchor_matches_known_answer() {
        let mldsa_seed = sha2::Sha256::digest(b"caliptra-mcu-test-owner-authorization-keys");
        let ecc_key = sha2::Sha384::digest(b"caliptra-mcu-test-owner-authorization-keys\x00");
        let signer = AsymmetricCommandAuthorizer::new(&ecc_key, &mldsa_seed).unwrap();
        let expected_owner_anchor: [u8; 48] = [
            0xd4, 0x9b, 0x2e, 0x99, 0xc7, 0xe1, 0xa1, 0x37, 0x30, 0x91, 0xaa, 0x18, 0xbe, 0xd7,
            0x30, 0xd0, 0x1e, 0xab, 0x7f, 0xc8, 0x04, 0x07, 0x7c, 0xc7, 0x27, 0xda, 0xa8, 0x74,
            0x58, 0xb1, 0xa7, 0xfd, 0x2b, 0x12, 0x64, 0x60, 0x39, 0xe2, 0xfa, 0x85, 0xd8, 0x2b,
            0xe8, 0x08, 0xbc, 0x05, 0x78, 0xfd,
        ];
        assert_eq!(signer.anchor().unwrap(), expected_owner_anchor);
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
    /// pre-image = cmd_id(BE) || payload || metadata || nonce —
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
        pre_image.extend_from_slice(AuthorizationMetadata::default().as_bytes());
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
        other.extend_from_slice(AuthorizationMetadata::default().as_bytes());
        other.extend_from_slice(&[0x22u8; AUTH_CMD_NONCE_LEN]);
        assert!(vk.verify(&other, &ecdsa_sig).is_err());
    }

    /// The ML-DSA-87 leg verifies over SHA-512(pre-image) where
    /// pre-image = cmd_id(BE) || payload || metadata || nonce — the same digest the device
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
        pre_image.extend_from_slice(AuthorizationMetadata::default().as_bytes());
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
        other.extend_from_slice(AuthorizationMetadata::default().as_bytes());
        other.extend_from_slice(&[0x22u8; AUTH_CMD_NONCE_LEN]);
        let wrong_msg: [u8; 64] = Sha512::digest(&other).into();
        assert!(!mldsa_pubkey().verify(&wrong_msg, &mldsa_sig, &[]));
    }

    #[test]
    fn signatures_bind_authority_scope_and_nonce_in_every_mode() {
        use caliptra_mcu_mbox_common::authorization::CommandAuthority;
        use fips204::traits::Verifier as MldsaVerifier;
        use p384::ecdsa::{signature::Verifier, Signature as EcdsaSignature, VerifyingKey};

        let signer =
            AsymmetricCommandAuthorizer::new(&TEST_ECC_PRIV_KEY, &TEST_MLDSA_SEED).unwrap();
        let ecc_key = VerifyingKey::from(&SigningKey::from_slice(&TEST_ECC_PRIV_KEY).unwrap());
        let mldsa_key = mldsa_pubkey();
        let cmd_id = 0x4D43_4650u32;
        let payload = [0x15; 4];

        for authority in [CommandAuthority::VendorOwner, CommandAuthority::Owner] {
            for ueid in [[0; 16], [0x42; 16]] {
                for nonce in [[0; AUTH_CMD_NONCE_LEN], [0x73; AUTH_CMD_NONCE_LEN]] {
                    let metadata = AuthorizationMetadata::new(authority, ueid);
                    let signature = signer
                        .authorize_with_metadata(cmd_id, &payload, &metadata, &nonce)
                        .unwrap();
                    let mut ecc_signature = [0; 96];
                    ecc_signature[..48].copy_from_slice(&signature.ecc_sig_r);
                    ecc_signature[48..].copy_from_slice(&signature.ecc_sig_s);
                    let ecc_signature = EcdsaSignature::from_slice(&ecc_signature).unwrap();
                    let mldsa_signature: [u8; 4627] =
                        signature.mldsa_sig[..4627].try_into().unwrap();

                    let mut message = cmd_id.to_be_bytes().to_vec();
                    message.extend_from_slice(&payload);
                    message.extend_from_slice(metadata.as_bytes());
                    message.extend_from_slice(&nonce);
                    assert!(ecc_key.verify(&message, &ecc_signature).is_ok());
                    let digest: [u8; 64] = Sha512::digest(&message).into();
                    assert!(mldsa_key.verify(&digest, &mldsa_signature, &[]));

                    for offset in 4 + payload.len()..message.len() {
                        message[offset] ^= 1;
                        assert!(ecc_key.verify(&message, &ecc_signature).is_err());
                        let digest: [u8; 64] = Sha512::digest(&message).into();
                        assert!(!mldsa_key.verify(&digest, &mldsa_signature, &[]));
                        message[offset] ^= 1;
                    }
                }
            }
        }
    }

    #[test]
    fn dot_message_signatures_verify_raw_transcript() {
        use fips204::traits::Verifier as MldsaVerifier;
        use p384::ecdsa::{signature::Verifier, Signature as EcdsaSignature, VerifyingKey};

        let signer =
            AsymmetricCommandAuthorizer::new(&TEST_ECC_PRIV_KEY, &TEST_MLDSA_SEED).unwrap();
        let message = [0xA5; 64];
        let sig = signer.sign_message(&message).unwrap();
        let keys = signer.dot_public_keys().unwrap();

        let encoded = p384::EncodedPoint::from_affine_coordinates(
            (&keys.ecc_pub_x).into(),
            (&keys.ecc_pub_y).into(),
            false,
        );
        let verifying_key = VerifyingKey::from_encoded_point(&encoded).unwrap();
        let mut ecc_bytes = [0u8; 96];
        ecc_bytes[..48].copy_from_slice(&sig.ecc_sig_r);
        ecc_bytes[48..].copy_from_slice(&sig.ecc_sig_s);
        assert!(verifying_key
            .verify(&message, &EcdsaSignature::from_slice(&ecc_bytes).unwrap())
            .is_ok());

        let mldsa_sig: [u8; 4627] = sig.mldsa_sig[..4627].try_into().unwrap();
        assert!(mldsa_pubkey().verify(&message, &mldsa_sig, &[]));
    }

    #[test]
    fn dot_lak_hash_uses_caliptra_ecc_word_order() {
        let signer =
            AsymmetricCommandAuthorizer::new(&TEST_ECC_PRIV_KEY, &TEST_MLDSA_SEED).unwrap();
        let keys = signer.dot_public_keys().unwrap();

        let mut expected_input = Vec::new();
        for chunk in keys.ecc_pub_x.chunks_exact(4) {
            expected_input.extend(chunk.iter().rev());
        }
        for chunk in keys.ecc_pub_y.chunks_exact(4) {
            expected_input.extend(chunk.iter().rev());
        }
        expected_input.extend_from_slice(&keys.mldsa_pub);
        let expected: [u8; 48] = Sha384::digest(expected_input).into();

        let mut natural_order = Vec::new();
        natural_order.extend_from_slice(&keys.ecc_pub_x);
        natural_order.extend_from_slice(&keys.ecc_pub_y);
        natural_order.extend_from_slice(&keys.mldsa_pub);
        let natural_order_hash: [u8; 48] = Sha384::digest(natural_order).into();

        assert_eq!(keys.dot_lak_hash(), expected);
        assert_ne!(keys.dot_lak_hash(), natural_order_hash);
    }
}

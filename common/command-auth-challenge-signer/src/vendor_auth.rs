// Licensed under the Apache-2.0 license

//! Asymmetric (hybrid ECDSA-P384 + ML-DSA-87) vendor-command-auth signer — the
//! "HSM in the test". Given the Caliptra-minted HELLO nonce, a command id, and the
//! command body, it produces the opaque authorization tag the MCU relays to
//! Caliptra's `VENDOR_AUTH_CHALLENGE`:
//!
//! ```text
//!   tag = nonce(48) ‖ ecc_pub(96) ‖ mldsa_pub(2592) ‖ ecc_sig(96) ‖ mldsa_sig(4628)
//! ```
//!
//! Signed transcript (no domain separator, mirrors prod-debug-unlock):
//!   ECC-P384 : SHA-384( cmd_id(BE,4) ‖ SHA-384(body) ‖ nonce(48) )
//!   ML-DSA-87: SHA-512( cmd_id(BE,4) ‖ SHA-384(body) ‖ nonce(48) ) → little-endian
//!
//! The private keys never leave this signer, matching a real HSM boundary. The
//! anchor Caliptra checks the pubkeys against is `SHA-384(ecc_pub ‖ mldsa_pub)`,
//! enrolled from the v2 Auth Manifest Vendor Ext 0x0001 record.

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha384, Sha512};

/// 48-byte Caliptra-minted one-time nonce (from `MC_VENDOR_AUTH_HELLO`).
pub const VENDOR_AUTH_NONCE_SIZE: usize = 48;
/// ECC-P384 public key: X‖Y as big-endian u32 words (24 words = 96 bytes).
pub const ECC_PUB_WORDS: usize = 24;
/// ML-DSA-87 public key as little-endian u32 words (648 words = 2592 bytes).
pub const MLDSA_PUB_WORDS: usize = 648;
/// ECC-P384 signature: r‖s as big-endian u32 words (24 words = 96 bytes).
pub const ECC_SIG_WORDS: usize = 24;
/// ML-DSA-87 signature as little-endian u32 words (1157 words = 4628 bytes).
pub const MLDSA_SIG_WORDS: usize = 1157;
/// Raw ML-DSA-87 signature length before zero-padding to `MLDSA_SIG_WORDS * 4`.
const MLDSA_SIG_RAW_LEN: usize = 4627;
/// ML-DSA-87 private key length in bytes.
const MLDSA_PRIV_LEN: usize = 4896;

/// In-memory hybrid signing keys (the HSM's secret material).
#[derive(Clone)]
pub struct VendorAuthKeys {
    /// P-384 private scalar, 48 big-endian bytes.
    pub ecc_private_key_bytes: [u8; 48],
    /// P-384 public key X‖Y, big-endian u32 words.
    pub ecc_public_key: [u32; ECC_PUB_WORDS],
    /// ML-DSA-87 private key bytes (4896).
    pub mldsa_private_key_bytes: Vec<u8>,
    /// ML-DSA-87 public key, little-endian u32 words.
    pub mldsa_public_key: [u32; MLDSA_PUB_WORDS],
}

/// The full opaque tag the host appends after the command struct.
pub struct VendorAuthTag {
    pub nonce: [u8; VENDOR_AUTH_NONCE_SIZE],
    pub ecc_public_key: [u32; ECC_PUB_WORDS],
    pub mldsa_public_key: [u32; MLDSA_PUB_WORDS],
    pub ecc_signature: [u32; ECC_SIG_WORDS],
    pub mldsa_signature: [u32; MLDSA_SIG_WORDS],
}

impl VendorAuthTag {
    /// Serialize to the wire layout `nonce ‖ ecc_pub ‖ mldsa_pub ‖ ecc_sig ‖ mldsa_sig`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            VENDOR_AUTH_NONCE_SIZE
                + (ECC_PUB_WORDS + MLDSA_PUB_WORDS + ECC_SIG_WORDS + MLDSA_SIG_WORDS) * 4,
        );
        out.extend_from_slice(&self.nonce);
        for w in self.ecc_public_key {
            out.extend_from_slice(&w.to_le_bytes());
        }
        for w in self.mldsa_public_key {
            out.extend_from_slice(&w.to_le_bytes());
        }
        for w in self.ecc_signature {
            out.extend_from_slice(&w.to_le_bytes());
        }
        for w in self.mldsa_signature {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }
}

/// Trait so a real HSM could be dropped in later; the test uses [`LocalVendorAuthSigner`].
pub trait VendorAuthSigner {
    /// Produce a signed tag binding `(cmd_id, body, nonce)`.
    fn sign_vendor_auth(
        &self,
        cmd_id: u32,
        body: &[u8],
        nonce: &[u8; VENDOR_AUTH_NONCE_SIZE],
    ) -> Result<VendorAuthTag>;
}

/// Signs locally with in-memory keys.
pub struct LocalVendorAuthSigner {
    keys: VendorAuthKeys,
}

impl LocalVendorAuthSigner {
    pub fn new(keys: VendorAuthKeys) -> Self {
        Self { keys }
    }

    /// The trust anchor Caliptra enrolls from the manifest: raw 48-byte
    /// `SHA-384(ecc_pub_hw ‖ mldsa_pub_hw)` over the little-endian word serializations
    /// (no per-word reversal). Use this to build the v2 SoC manifest so the enrolled
    /// anchor matches what `VENDOR_AUTH_CHALLENGE` reconstructs from the pubkeys.
    pub fn anchor(&self) -> [u8; 48] {
        let mut h = Sha384::new();
        for w in self.keys.ecc_public_key {
            Digest::update(&mut h, w.to_le_bytes());
        }
        for w in self.keys.mldsa_public_key {
            Digest::update(&mut h, w.to_le_bytes());
        }
        h.finalize().into()
    }
}

impl VendorAuthSigner for LocalVendorAuthSigner {
    fn sign_vendor_auth(
        &self,
        cmd_id: u32,
        body: &[u8],
        nonce: &[u8; VENDOR_AUTH_NONCE_SIZE],
    ) -> Result<VendorAuthTag> {
        use ecdsa::signature::hazmat::PrehashSigner;
        use ecdsa::{Signature, SigningKey as EcdsaSigningKey};
        use fips204::traits::{SerDes, Signer};

        let keys = &self.keys;
        let cmd_id_be = cmd_id.to_be_bytes();

        // Inner: body_hash = SHA-384(body) — command-agnostic reduction (Option B).
        let body_hash: [u8; 48] = {
            let mut h = Sha384::new();
            Digest::update(&mut h, body);
            h.finalize().into()
        };

        // --- ECC-P384 over SHA-384( cmd_id_be ‖ body_hash ‖ nonce ) ---
        let ecc_prehash: [u8; 48] = {
            let mut h = Sha384::new();
            Digest::update(&mut h, cmd_id_be);
            Digest::update(&mut h, body_hash);
            Digest::update(&mut h, nonce);
            h.finalize().into()
        };
        let ecc_secret = p384::SecretKey::from_slice(&keys.ecc_private_key_bytes)
            .map_err(|e| anyhow!("invalid ECC private key: {e}"))?;
        let ecc_sig: Signature<p384::NistP384> = EcdsaSigningKey::<p384::NistP384>::from(&ecc_secret)
            .sign_prehash(&ecc_prehash)
            .map_err(|e| anyhow!("ECDSA signing failed: {e}"))?;
        let mut ecc_signature = [0u32; ECC_SIG_WORDS];
        for (i, chunk) in ecc_sig.r().to_bytes().chunks(4).enumerate() {
            ecc_signature[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }
        for (i, chunk) in ecc_sig.s().to_bytes().chunks(4).enumerate() {
            ecc_signature[i + 12] = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        // --- ML-DSA-87 over SHA-512( cmd_id_be ‖ body_hash ‖ nonce ) → LE words ---
        let mldsa_prehash: [u8; 64] = {
            let mut h = Sha512::new();
            Digest::update(&mut h, cmd_id_be);
            Digest::update(&mut h, body_hash);
            Digest::update(&mut h, nonce);
            h.finalize().into()
        };
        let mldsa_priv: [u8; MLDSA_PRIV_LEN] =
            keys.mldsa_private_key_bytes.as_slice().try_into().map_err(|_| {
                anyhow!(
                    "invalid ML-DSA private key size: expected {MLDSA_PRIV_LEN}, got {}",
                    keys.mldsa_private_key_bytes.len()
                )
            })?;
        let mldsa_key = fips204::ml_dsa_87::PrivateKey::try_from_bytes(mldsa_priv)
            .map_err(|_| anyhow!("failed to parse ML-DSA-87 private key"))?;
        let raw = mldsa_key
            .try_sign_with_seed(&[0u8; 32], &mldsa_prehash, &[])
            .map_err(|_| anyhow!("ML-DSA-87 signing failed"))?;
        let mut sig_padded = [0u8; MLDSA_SIG_WORDS * 4];
        sig_padded[..MLDSA_SIG_RAW_LEN].copy_from_slice(&raw[..MLDSA_SIG_RAW_LEN]);
        let mut mldsa_signature = [0u32; MLDSA_SIG_WORDS];
        for (i, chunk) in sig_padded.chunks(4).enumerate() {
            mldsa_signature[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        Ok(VendorAuthTag {
            nonce: *nonce,
            ecc_public_key: keys.ecc_public_key,
            mldsa_public_key: keys.mldsa_public_key,
            ecc_signature,
            mldsa_signature,
        })
    }
}

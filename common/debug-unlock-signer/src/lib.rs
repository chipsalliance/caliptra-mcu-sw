// Licensed under the Apache-2.0 license

//! Debug Unlock Signer trait and local implementation.
//!
//! In production systems the debug-unlock challenge is typically signed by a
//! remote HSM or signing service. The [`DebugUnlockSigner`] trait abstracts
//! over where the signing happens, while [`LocalDebugUnlockSigner`] provides a
//! reference implementation that signs locally using in-memory keys.

mod local;

use anyhow::Result;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub use local::{DebugUnlockKeys, LocalDebugUnlockSigner};

/// Size of the unique device identifier in bytes
pub const UNIQUE_DEVICE_ID_SIZE: usize = 32;

/// Size of the challenge in bytes (ECC P-384 scalar)
pub const DEBUG_UNLOCK_CHALLENGE_SIZE: usize = 48;

/// ECC public key size in u32 words (24 words = 96 bytes for P-384 X || Y)
pub const ECC_PUBLIC_KEY_WORD_SIZE: usize = 24;

/// ML-DSA public key size in u32 words
pub const MLDSA_PUBLIC_KEY_WORD_SIZE: usize = 648;

/// ECC signature size in u32 words (24 words = 96 bytes for P-384 r || s)
pub const ECC_SIGNATURE_WORD_SIZE: usize = 24;

/// ML-DSA signature size in u32 words
pub const MLDSA_SIGNATURE_WORD_SIZE: usize = 1157;

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ProdDebugUnlockChallenge {
    pub unique_device_identifier: [u8; UNIQUE_DEVICE_ID_SIZE],
    pub challenge: [u8; DEBUG_UNLOCK_CHALLENGE_SIZE],
}

impl Default for ProdDebugUnlockChallenge {
    fn default() -> Self {
        Self {
            unique_device_identifier: [0u8; UNIQUE_DEVICE_ID_SIZE],
            challenge: [0u8; DEBUG_UNLOCK_CHALLENGE_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ProdDebugUnlockToken {
    pub length: u32,
    pub unique_device_identifier: [u8; UNIQUE_DEVICE_ID_SIZE],
    pub unlock_level: u8,
    pub reserved: [u8; 3],
    pub challenge: [u8; DEBUG_UNLOCK_CHALLENGE_SIZE],
    pub ecc_public_key: [u32; ECC_PUBLIC_KEY_WORD_SIZE],
    pub mldsa_public_key: [u32; MLDSA_PUBLIC_KEY_WORD_SIZE],
    pub ecc_signature: [u32; ECC_SIGNATURE_WORD_SIZE],
    pub mldsa_signature: [u32; MLDSA_SIGNATURE_WORD_SIZE],
}

impl Default for ProdDebugUnlockToken {
    fn default() -> Self {
        Self {
            length: 0,
            unique_device_identifier: [0u8; UNIQUE_DEVICE_ID_SIZE],
            unlock_level: 0,
            reserved: [0; 3],
            challenge: [0u8; DEBUG_UNLOCK_CHALLENGE_SIZE],
            ecc_public_key: [0u32; ECC_PUBLIC_KEY_WORD_SIZE],
            mldsa_public_key: [0u32; MLDSA_PUBLIC_KEY_WORD_SIZE],
            ecc_signature: [0u32; ECC_SIGNATURE_WORD_SIZE],
            mldsa_signature: [0u32; MLDSA_SIGNATURE_WORD_SIZE],
        }
    }
}

/// Trait for signing a production debug-unlock token.
///
/// Implementors receive the challenge from the device together with
/// the requested unlock level and must return a fully-populated (and signed)
/// [`ProdDebugUnlockToken`].
pub trait DebugUnlockSigner {
    fn sign_debug_unlock_token(
        &self,
        challenge: &ProdDebugUnlockChallenge,
        unlock_level: u8,
    ) -> Result<ProdDebugUnlockToken>;
}

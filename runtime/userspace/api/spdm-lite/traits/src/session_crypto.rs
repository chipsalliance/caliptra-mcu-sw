// Licensed under the Apache-2.0 license

//! Session crypto abstraction for the SPDM-Lite stack.
//!
//! Defines [`SpdmPalSessionCrypto`], the trait that platform-specific
//! implementations must satisfy to support SPDM secure sessions
//! (KEY_EXCHANGE + FINISH + secured message framing).
//!
//! The [`Key`](SpdmPalSessionCrypto::Key) associated type is an
//! opaque handle — on Caliptra it maps to `Cmk` (128 bytes); the
//! actual key material never leaves the crypto backend.

use super::*;

/// Session cryptography backend.
///
/// Implementors provide ECDH, HKDF, HMAC, AES-GCM, key import, and
/// key deletion operations through opaque [`Self::Key`] handles.
pub trait SpdmPalSessionCrypto {
    /// Opaque key handle (e.g. `Cmk` on Caliptra).
    ///
    /// `Clone` is required so containers can hold `Option<Key>`.
    type Key: Clone;

    /// Generate an ephemeral ECDH key pair.
    ///
    /// Returns `(encrypted_context, our_exchange_data)` where the
    /// context is an opaque 76-byte blob needed by [`Self::ecdh_finish`]
    /// and exchange_data is the 96-byte P-384 public point.
    async fn ecdh_generate(
        &self,
        io: &impl SpdmPalIo,
    ) -> McuResult<([u8; 76], [u8; 96])>;

    /// Complete the ECDH key exchange, producing a key handle to the
    /// shared secret (DHE_Secret).
    async fn ecdh_finish(
        &self,
        io: &impl SpdmPalIo,
        context: &[u8; 76],
        peer_exchange_data: &[u8; 96],
    ) -> McuResult<Self::Key>;

    /// HKDF-Extract with raw-byte salt.
    ///
    /// Salt is imported into the crypto backend internally if needed.
    async fn hkdf_extract_bytes(
        &self,
        io: &impl SpdmPalIo,
        salt: &[u8],
        ikm: &Self::Key,
    ) -> McuResult<Self::Key>;

    /// HKDF-Extract with a key-handle salt.
    async fn hkdf_extract_key(
        &self,
        io: &impl SpdmPalIo,
        salt: &Self::Key,
        ikm: &Self::Key,
    ) -> McuResult<Self::Key>;

    /// HKDF-Expand producing a new key handle.
    async fn hkdf_expand(
        &self,
        io: &impl SpdmPalIo,
        prk: &Self::Key,
        key_size: u32,
        info: &[u8],
    ) -> McuResult<Self::Key>;

    /// HMAC-SHA384. Returns bytes written to `out`.
    async fn hmac(
        &self,
        io: &impl SpdmPalIo,
        key: &Self::Key,
        data: &[u8],
        out: &mut [u8],
    ) -> McuResult<usize>;

    /// Import raw key material. Returns a key handle.
    async fn import_key(
        &self,
        io: &impl SpdmPalIo,
        data: &[u8],
    ) -> McuResult<Self::Key>;

    /// Destroy a key handle in the crypto backend.
    async fn delete_key(
        &self,
        io: &impl SpdmPalIo,
        key: &Self::Key,
    ) -> McuResult<()>;

    /// SPDM AES-256-GCM encrypt.
    ///
    /// `key` is the major secret (request/response handshake or data
    /// secret). Caliptra derives the actual AES key + IV internally
    /// from (`key`, `spdm_version`, `seq`).
    ///
    /// Returns `(ciphertext_len, tag)`.
    async fn aead_encrypt(
        &self,
        io: &impl SpdmPalIo,
        key: &Self::Key,
        spdm_version: u8,
        seq: u64,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> McuResult<(usize, [u8; 16])>;

    /// SPDM AES-256-GCM decrypt with tag verification.
    ///
    /// Returns plaintext length.
    async fn aead_decrypt(
        &self,
        io: &impl SpdmPalIo,
        key: &Self::Key,
        spdm_version: u8,
        seq: u64,
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
        plaintext: &mut [u8],
    ) -> McuResult<usize>;
}

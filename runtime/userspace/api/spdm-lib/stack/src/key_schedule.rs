// Licensed under the Apache-2.0 license

//! SPDM key schedule for secure sessions.
//!
//! Implements the SPDM secure-session key derivation chain:
//! ```text
//! Shared_Secret ──HKDF-Extract(Salt_0)──▸ handshake_secret
//!   ├─ HKDF-Expand(bin_str1, TH1') ──▸ request_handshake_secret
//!   ├─ HKDF-Expand(bin_str2, TH1') ──▸ response_handshake_secret
//!   │  ├─ HKDF-Expand(bin_str7)  ──▸ request_finished_key
//!   │  └─ HKDF-Expand(bin_str7)  ──▸ response_finished_key
//!   └─ HKDF-Expand(bin_str0)    ──▸ Salt_1
//!    └─ HKDF-Extract(Salt_1, 0) ──▸ master_secret
//!      ├─ HKDF-Expand(bin_str3, TH2) ──▸ request_data_secret
//!      └─ HKDF-Expand(bin_str4, TH2) ──▸ response_data_secret
//! ```
//!
//! All crypto operations go through [`SpdmPalSessionCrypto`] so the
//! key schedule is backend-agnostic; on Caliptra the key handles are
//! opaque 128-byte `Cmk` blobs.

use caliptra_mcu_spdm_codec::SpdmVersion;
use caliptra_mcu_spdm_traits::{McuResult, SpdmPalAlloc, SpdmPalIo, SpdmPalSessionCrypto};

/// SHA-384 digest size in bytes.
pub const SHA384_HASH_SIZE: usize = 48;

/// All-zero input reused as `Salt_0` for Handshake-Secret extraction and
/// `zero_filled` for Master-Secret extraction.
static ZERO_HASH: [u8; SHA384_HASH_SIZE] = [0; SHA384_HASH_SIZE];

/// Maximum length of the HKDF info field built by [`bin_concat`].
const MAX_BIN_STR_LABEL_LEN: usize = 12;
const MAX_BIN_STR_LEN: usize = 2 + 8 + MAX_BIN_STR_LABEL_LEN + SHA384_HASH_SIZE;

/// Which session key to use for HMAC or AEAD operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SessionKeyType {
    RequestFinishedKey,
    ResponseFinishedKey,
    RequestHandshakeKey,
    ResponseHandshakeKey,
    RequestDataKey,
    ResponseDataKey,
}

/// Map negotiated [`SpdmVersion`] to the 8-byte HKDF version string
/// used by [`bin_concat`].
pub fn spdm_version_str(version: SpdmVersion) -> &'static [u8] {
    match version {
        SpdmVersion::V10 => b"spdm1.0 ",
        SpdmVersion::V11 => b"spdm1.1 ",
        SpdmVersion::V12 => b"spdm1.2 ",
        SpdmVersion::V13 => b"spdm1.3 ",
        SpdmVersion::V14 => b"spdm1.4 ",
    }
}

// ── Key schedule state ──────────────────────────────────────────────

/// SPDM key schedule state.
///
/// `K` is the opaque key-handle type from
/// [`SpdmPalSessionCrypto::Key`].
pub struct KeySchedule<K: Clone> {
    version_str: &'static [u8],
    master_ctx: MasterSecretCtx<K>,
    handshake_ctx: HandshakeSecretCtx<K>,
    data_ctx: DataSecretCtx<K>,
}

struct MasterSecretCtx<K: Clone> {
    shared_secret: Option<K>,
    handshake_secret: Option<K>,
    master_secret: Option<K>,
}

struct HandshakeSecretCtx<K: Clone> {
    request_handshake_secret: Option<K>,
    response_handshake_secret: Option<K>,
    request_finished_key: Option<K>,
    response_finished_key: Option<K>,
    request_seq: u64,
    response_seq: u64,
}

struct DataSecretCtx<K: Clone> {
    request_data_secret: Option<K>,
    response_data_secret: Option<K>,
    request_seq: u64,
    response_seq: u64,
}

impl<K: Clone> KeySchedule<K> {
    /// Create a new key schedule for the given SPDM version.
    pub fn new(version_str: &'static [u8]) -> Self {
        Self {
            version_str,
            master_ctx: MasterSecretCtx {
                shared_secret: None,
                handshake_secret: None,
                master_secret: None,
            },
            handshake_ctx: HandshakeSecretCtx {
                request_handshake_secret: None,
                response_handshake_secret: None,
                request_finished_key: None,
                response_finished_key: None,
                request_seq: 0,
                response_seq: 0,
            },
            data_ctx: DataSecretCtx {
                request_data_secret: None,
                response_data_secret: None,
                request_seq: 0,
                response_seq: 0,
            },
        }
    }

    /// Store the shared secret produced by either ECDH or ML-KEM during KEY_EXCHANGE.
    pub fn set_shared_secret(&mut self, secret: K) {
        self.master_ctx.shared_secret = Some(secret);
    }

    // ── Handshake keys ──────────────────────────────────────────────

    /// Derive handshake keys from the shared secret and TH1' hash.
    ///
    /// Produces:
    /// - request / response handshake secrets (AEAD major secrets)
    /// - request / response finished keys (HMAC keys for verify_data)
    ///
    /// Destroys the shared secret handle on success.
    #[inline(never)]
    pub async fn generate_handshake_keys<P: SpdmPalAlloc + SpdmPalSessionCrypto<Key = K>>(
        &mut self,
        pal: &P,
        io: &impl SpdmPalIo,
        th1_hash: &[u8],
    ) -> McuResult<()> {
        // handshake_secret = HKDF-Extract(Salt_0 = zeros, shared_secret)
        let shared_secret = self
            .master_ctx
            .shared_secret
            .take()
            .ok_or(mcu_error::codes::INVARIANT)?;
        let hs = pal
            .hkdf_extract_bytes(io, &ZERO_HASH, &shared_secret)
            .await?;
        self.master_ctx.handshake_secret = Some(hs);

        let hs_ref = self
            .master_ctx
            .handshake_secret
            .as_ref()
            .ok_or(mcu_error::codes::INVARIANT)?;

        // request_hs = HKDF-Expand(hs, bin_str1(th1_hash), Hash.Length)
        self.handshake_ctx.request_handshake_secret = Some(
            hkdf_expand_bin_str(
                pal,
                io,
                self.version_str,
                hs_ref,
                BinStr::Str1,
                Some(th1_hash),
            )
            .await?,
        );

        // response_hs = HKDF-Expand(hs, bin_str2(th1_hash), Hash.Length)
        self.handshake_ctx.response_handshake_secret = Some(
            hkdf_expand_bin_str(
                pal,
                io,
                self.version_str,
                hs_ref,
                BinStr::Str2,
                Some(th1_hash),
            )
            .await?,
        );

        // finished keys = HKDF-Expand(handshake_secret, bin_str7, Hash.Length)
        self.handshake_ctx.request_finished_key = Some(
            hkdf_expand_bin_str(
                pal,
                io,
                self.version_str,
                self.handshake_ctx
                    .request_handshake_secret
                    .as_ref()
                    .ok_or(mcu_error::codes::INVARIANT)?,
                BinStr::Str7,
                None,
            )
            .await?,
        );

        self.handshake_ctx.response_finished_key = Some(
            hkdf_expand_bin_str(
                pal,
                io,
                self.version_str,
                self.handshake_ctx
                    .response_handshake_secret
                    .as_ref()
                    .ok_or(mcu_error::codes::INVARIANT)?,
                BinStr::Str7,
                None,
            )
            .await?,
        );

        Ok(())
    }

    // ── Data keys ───────────────────────────────────────────────────

    /// Derive data (application) keys from handshake_secret and TH2 hash.
    ///
    /// Produces:
    /// - master_secret (intermediate, kept for export if needed)
    /// - request / response data secrets (AEAD major secrets)
    #[inline(never)]
    pub async fn generate_data_keys<P: SpdmPalAlloc + SpdmPalSessionCrypto<Key = K>>(
        &mut self,
        pal: &P,
        io: &impl SpdmPalIo,
        th2_hash: &[u8],
    ) -> McuResult<()> {
        let hs_ref = self
            .master_ctx
            .handshake_secret
            .as_ref()
            .ok_or(mcu_error::codes::INVARIANT)?;

        // Salt_1 = HKDF-Expand(hs, bin_str0, Hash.Length)
        let salt_1 =
            hkdf_expand_bin_str(pal, io, self.version_str, hs_ref, BinStr::Str0, None).await?;

        // Master-Secret = HKDF-Extract(Salt_1, zero_filled)
        let zero_cmk = pal.import_key(io, &ZERO_HASH).await?;
        self.master_ctx.master_secret = Some(pal.hkdf_extract_key(io, &salt_1, &zero_cmk).await?);

        let ms_ref = self
            .master_ctx
            .master_secret
            .as_ref()
            .ok_or(mcu_error::codes::INVARIANT)?;

        // req_data = HKDF-Expand(ms, bin_str3(th2), Hash.Length)
        self.data_ctx.request_data_secret = Some(
            hkdf_expand_bin_str(
                pal,
                io,
                self.version_str,
                ms_ref,
                BinStr::Str3,
                Some(th2_hash),
            )
            .await?,
        );

        // rsp_data = HKDF-Expand(ms, bin_str4(th2), Hash.Length)
        self.data_ctx.response_data_secret = Some(
            hkdf_expand_bin_str(
                pal,
                io,
                self.version_str,
                ms_ref,
                BinStr::Str4,
                Some(th2_hash),
            )
            .await?,
        );

        Ok(())
    }

    // ── Crypto operations ───────────────────────────────────────────

    /// Compute HMAC with the specified finished key.
    pub fn hmac_finished<'a, P: SpdmPalSessionCrypto<Key = K>>(
        &'a self,
        pal: &'a P,
        io: &'a impl SpdmPalIo,
        key_type: SessionKeyType,
        data: &'a [u8],
        out: &'a mut [u8],
    ) -> McuResult<impl core::future::Future<Output = McuResult<usize>> + 'a> {
        let key = self.finished_key(key_type)?;
        Ok(pal.hmac(io, key, data, out))
    }

    /// Encrypt with the appropriate session key.
    #[allow(clippy::too_many_arguments)]
    pub async fn encrypt<P: SpdmPalSessionCrypto<Key = K>>(
        &mut self,
        pal: &P,
        io: &impl SpdmPalIo,
        key_type: SessionKeyType,
        spdm_version: u8,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> McuResult<(usize, [u8; 16])> {
        let (key, seq) = self.aead_key_and_seq(key_type)?;
        let result = pal
            .aead_encrypt(io, key, spdm_version, *seq, aad, plaintext, ciphertext)
            .await?;
        // Increment the seq number after successful encryption.
        *seq += 1;
        Ok(result)
    }

    /// Decrypt with the appropriate session key.
    #[allow(clippy::too_many_arguments)]
    pub async fn decrypt<P: SpdmPalSessionCrypto<Key = K>>(
        &mut self,
        pal: &P,
        io: &impl SpdmPalIo,
        key_type: SessionKeyType,
        spdm_version: u8,
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
        plaintext: &mut [u8],
    ) -> McuResult<usize> {
        let (key, seq) = self.aead_key_and_seq(key_type)?;
        let result = pal
            .aead_decrypt(io, key, spdm_version, *seq, aad, ciphertext, tag, plaintext)
            .await?;
        // Increment the seq number after successful authentication and decryption.
        *seq += 1;
        Ok(result)
    }

    // ── Cleanup ─────────────────────────────────────────────────────

    /// Clear handshake-phase secrets after FINISH completes.
    ///
    /// Clears: req/rsp handshake secrets, req/rsp finished keys, and
    /// the intermediate handshake_secret.
    pub fn destroy_handshake_secrets(&mut self) {
        self.handshake_ctx.request_handshake_secret = None;
        self.handshake_ctx.response_handshake_secret = None;
        self.handshake_ctx.request_finished_key = None;
        self.handshake_ctx.response_finished_key = None;
        self.master_ctx.handshake_secret = None;
    }

    /// Clear all key blobs.
    pub fn destroy_all(&mut self) {
        self.destroy_handshake_secrets();
        self.master_ctx.shared_secret = None;
        self.master_ctx.master_secret = None;
        self.data_ctx.request_data_secret = None;
        self.data_ctx.response_data_secret = None;
    }

    fn finished_key(&self, key_type: SessionKeyType) -> McuResult<&K> {
        match key_type {
            SessionKeyType::RequestFinishedKey => self
                .handshake_ctx
                .request_finished_key
                .as_ref()
                .ok_or(mcu_error::codes::INVARIANT),
            SessionKeyType::ResponseFinishedKey => self
                .handshake_ctx
                .response_finished_key
                .as_ref()
                .ok_or(mcu_error::codes::INVARIANT),
            _ => Err(mcu_error::codes::INVARIANT),
        }
    }

    fn aead_key_and_seq(&mut self, key_type: SessionKeyType) -> McuResult<(&K, &mut u64)> {
        match key_type {
            SessionKeyType::RequestHandshakeKey => Ok((
                self.handshake_ctx
                    .request_handshake_secret
                    .as_ref()
                    .ok_or(mcu_error::codes::INVARIANT)?,
                &mut self.handshake_ctx.request_seq,
            )),
            SessionKeyType::ResponseHandshakeKey => Ok((
                self.handshake_ctx
                    .response_handshake_secret
                    .as_ref()
                    .ok_or(mcu_error::codes::INVARIANT)?,
                &mut self.handshake_ctx.response_seq,
            )),
            SessionKeyType::RequestDataKey => Ok((
                self.data_ctx
                    .request_data_secret
                    .as_ref()
                    .ok_or(mcu_error::codes::INVARIANT)?,
                &mut self.data_ctx.request_seq,
            )),
            SessionKeyType::ResponseDataKey => Ok((
                self.data_ctx
                    .response_data_secret
                    .as_ref()
                    .ok_or(mcu_error::codes::INVARIANT)?,
                &mut self.data_ctx.response_seq,
            )),
            _ => Err(mcu_error::codes::INVARIANT),
        }
    }
}

// ── bin_concat helper ───────────────────────────────────────────────

/// SPDM HKDF bin_str label identifiers.
#[derive(Copy, Clone)]
enum BinStr {
    /// `"derived"` — Salt_1 derivation
    Str0,
    /// `"req hs data"` — request handshake secret
    Str1,
    /// `"rsp hs data"` — response handshake secret
    Str2,
    /// `"req app data"` — request data secret
    Str3,
    /// `"rsp app data"` — response data secret
    Str4,
    /// `"finished"` — finished keys
    Str7,
}

impl BinStr {
    fn label(self) -> &'static [u8] {
        match self {
            BinStr::Str0 => b"derived",
            BinStr::Str1 => b"req hs data",
            BinStr::Str2 => b"rsp hs data",
            BinStr::Str3 => b"req app data",
            BinStr::Str4 => b"rsp app data",
            BinStr::Str7 => b"finished",
        }
    }
}

#[inline(never)]
async fn hkdf_expand_bin_str<P: SpdmPalAlloc + SpdmPalSessionCrypto>(
    pal: &P,
    io: &impl SpdmPalIo,
    version_str: &[u8],
    prk: &P::Key,
    bin_str: BinStr,
    context: Option<&[u8]>,
) -> McuResult<P::Key> {
    let mut info = pal.alloc_bytes(io, MAX_BIN_STR_LEN)?;
    let len = bin_concat(
        version_str,
        bin_str,
        SHA384_HASH_SIZE as u16,
        context,
        &mut info,
    )?;
    let info = info.get(..len).ok_or(mcu_error::codes::INVARIANT)?;
    pal.hkdf_expand(io, prk, SHA384_HASH_SIZE as u32, info)
        .await
}

/// Build the SPDM HKDF info field in caller-provided scratch.
///
/// Format: `length(2LE) ‖ version_str ‖ label ‖ context`.
///
/// Returns the actual length. The caller-provided buffer must be
/// [`MAX_BIN_STR_LEN`] bytes; only `[0..actual_length]` is valid.
fn bin_concat(
    version_str: &[u8],
    bin_str: BinStr,
    length: u16,
    context: Option<&[u8]>,
    buf: &mut [u8],
) -> McuResult<usize> {
    let mut pos = 0;
    let needed = 2 + version_str.len() + bin_str.label().len() + context.map_or(0, |ctx| ctx.len());
    if needed > buf.len() {
        return Err(mcu_error::codes::INVARIANT);
    }

    write_bin_str_bytes(buf, &mut pos, &length.to_le_bytes())?;

    write_bin_str_bytes(buf, &mut pos, version_str)?;

    let label = bin_str.label();
    write_bin_str_bytes(buf, &mut pos, label)?;

    if let Some(ctx) = context {
        write_bin_str_bytes(buf, &mut pos, ctx)?;
    }

    Ok(pos)
}

fn write_bin_str_bytes(buf: &mut [u8], pos: &mut usize, src: &[u8]) -> McuResult<()> {
    let end = pos
        .checked_add(src.len())
        .ok_or(mcu_error::codes::INVARIANT)?;
    let dst = buf.get_mut(*pos..end).ok_or(mcu_error::codes::INVARIANT)?;
    for (d, s) in dst.iter_mut().zip(src) {
        *d = *s;
    }
    *pos = end;
    Ok(())
}

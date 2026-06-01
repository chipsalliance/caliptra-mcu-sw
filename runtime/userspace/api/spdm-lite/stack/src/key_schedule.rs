// Licensed under the Apache-2.0 license

//! SPDM key schedule for secure sessions.
//!
//! Implements the DSP0274 key derivation chain:
//! ```text
//! DHE_Secret ──HKDF-Extract(Salt_0)──▸ handshake_secret
//!   ├─ HKDF-Expand(bin_str1, TH1') ──▸ request_handshake_secret
//!   ├─ HKDF-Expand(bin_str2, TH1') ──▸ response_handshake_secret
//!   │   ├─ HKDF-Expand(bin_str7)    ──▸ request_finished_key
//!   │   └─ HKDF-Expand(bin_str7)    ──▸ response_finished_key
//!   └─ HKDF-Expand(bin_str0)        ──▸ Salt_1
//!       └─ HKDF-Extract(Salt_1, 0)  ──▸ master_secret
//!           ├─ HKDF-Expand(bin_str3, TH2) ──▸ request_data_secret
//!           └─ HKDF-Expand(bin_str4, TH2) ──▸ response_data_secret
//! ```
//!
//! All crypto operations go through [`SpdmPalSessionCrypto`] so the
//! key schedule is backend-agnostic; on Caliptra the key handles are
//! opaque 128-byte `Cmk` blobs.

use mcu_spdm_lite_codec::SpdmVersion;
use mcu_spdm_lite_traits::{McuResult, SpdmPalIo, SpdmPalSessionCrypto};

/// SHA-384 digest size in bytes.
pub const SHA384_HASH_SIZE: usize = 48;

/// Maximum length of the HKDF info field built by [`bin_concat`].
const MAX_BIN_STR_LEN: usize = 128;

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
    dhe_secret: Option<K>,
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
                dhe_secret: None,
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

    /// Store the DHE shared secret produced by [`SpdmPalSessionCrypto::ecdh_finish`].
    pub fn set_dhe_secret(&mut self, secret: K) {
        self.master_ctx.dhe_secret = Some(secret);
    }

    // ── Handshake keys ──────────────────────────────────────────────

    /// Derive handshake keys from the DHE secret and TH1' hash.
    ///
    /// Produces:
    /// - request / response handshake secrets (AEAD major secrets)
    /// - request / response finished keys (HMAC keys for verify_data)
    ///
    /// Destroys the DHE secret handle on success.
    #[inline(never)]
    pub async fn generate_handshake_keys<P: SpdmPalSessionCrypto<Key = K>>(
        &mut self,
        pal: &P,
        io: &impl SpdmPalIo,
        th1_hash: &[u8],
    ) -> McuResult<()> {
        // handshake_secret = HKDF-Extract(Salt_0 = zeros, DHE_Secret)
        let dhe = self
            .master_ctx
            .dhe_secret
            .take()
            .ok_or(mcu_error::codes::INVARIANT)?;
        let salt_0 = [0u8; SHA384_HASH_SIZE];
        let hs = pal.hkdf_extract_bytes(io, &salt_0, &dhe).await?;
        let _ = pal.delete_key(io, &dhe).await;
        self.master_ctx.handshake_secret = Some(hs);

        let hs_ref = self
            .master_ctx
            .handshake_secret
            .as_ref()
            .ok_or(mcu_error::codes::INVARIANT)?;

        // request_hs = HKDF-Expand(hs, bin_str1(th1_hash), Hash.Length)
        let req_hs = {
            let (info, len) = bin_concat(
                self.version_str,
                BinStr::Str1,
                SHA384_HASH_SIZE as u16,
                Some(th1_hash),
            );
            pal.hkdf_expand(io, hs_ref, SHA384_HASH_SIZE as u32, &info[..len])
                .await?
        };

        // response_hs = HKDF-Expand(hs, bin_str2(th1_hash), Hash.Length)
        let rsp_hs = {
            let (info, len) = bin_concat(
                self.version_str,
                BinStr::Str2,
                SHA384_HASH_SIZE as u16,
                Some(th1_hash),
            );
            pal.hkdf_expand(io, hs_ref, SHA384_HASH_SIZE as u32, &info[..len])
                .await?
        };

        self.handshake_ctx.request_handshake_secret = Some(req_hs);
        self.handshake_ctx.response_handshake_secret = Some(rsp_hs);

        // finished keys = HKDF-Expand(handshake_secret, bin_str7, Hash.Length)
        let req_fk = {
            let (info, len) = bin_concat(
                self.version_str,
                BinStr::Str7,
                SHA384_HASH_SIZE as u16,
                None,
            );
            pal.hkdf_expand(
                io,
                self.handshake_ctx
                    .request_handshake_secret
                    .as_ref()
                    .ok_or(mcu_error::codes::INVARIANT)?,
                SHA384_HASH_SIZE as u32,
                &info[..len],
            )
            .await?
        };

        let rsp_fk = {
            let (info, len) = bin_concat(
                self.version_str,
                BinStr::Str7,
                SHA384_HASH_SIZE as u16,
                None,
            );
            pal.hkdf_expand(
                io,
                self.handshake_ctx
                    .response_handshake_secret
                    .as_ref()
                    .ok_or(mcu_error::codes::INVARIANT)?,
                SHA384_HASH_SIZE as u32,
                &info[..len],
            )
            .await?
        };

        self.handshake_ctx.request_finished_key = Some(req_fk);
        self.handshake_ctx.response_finished_key = Some(rsp_fk);

        Ok(())
    }

    // ── Data keys ───────────────────────────────────────────────────

    /// Derive data (application) keys from handshake_secret and TH2 hash.
    ///
    /// Produces:
    /// - master_secret (intermediate, kept for export if needed)
    /// - request / response data secrets (AEAD major secrets)
    #[inline(never)]
    pub async fn generate_data_keys<P: SpdmPalSessionCrypto<Key = K>>(
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
        let salt_1 = {
            let (info, len) = bin_concat(
                self.version_str,
                BinStr::Str0,
                SHA384_HASH_SIZE as u16,
                None,
            );
            pal.hkdf_expand(io, hs_ref, SHA384_HASH_SIZE as u32, &info[..len])
                .await?
        };

        // Master-Secret = HKDF-Extract(Salt_1, zero_filled)
        let zero_filled = [0u8; SHA384_HASH_SIZE];
        let zero_cmk = pal.import_key(io, &zero_filled).await?;
        let ms = pal.hkdf_extract_key(io, &salt_1, &zero_cmk).await?;
        let _ = pal.delete_key(io, &zero_cmk).await;
        let _ = pal.delete_key(io, &salt_1).await;
        self.master_ctx.master_secret = Some(ms);

        let ms_ref = self
            .master_ctx
            .master_secret
            .as_ref()
            .ok_or(mcu_error::codes::INVARIANT)?;

        // req_data = HKDF-Expand(ms, bin_str3(th2), Hash.Length)
        let req_data = {
            let (info, len) = bin_concat(
                self.version_str,
                BinStr::Str3,
                SHA384_HASH_SIZE as u16,
                Some(th2_hash),
            );
            pal.hkdf_expand(io, ms_ref, SHA384_HASH_SIZE as u32, &info[..len])
                .await?
        };

        // rsp_data = HKDF-Expand(ms, bin_str4(th2), Hash.Length)
        let rsp_data = {
            let (info, len) = bin_concat(
                self.version_str,
                BinStr::Str4,
                SHA384_HASH_SIZE as u16,
                Some(th2_hash),
            );
            pal.hkdf_expand(io, ms_ref, SHA384_HASH_SIZE as u32, &info[..len])
                .await?
        };

        self.data_ctx.request_data_secret = Some(req_data);
        self.data_ctx.response_data_secret = Some(rsp_data);

        Ok(())
    }

    // ── Crypto operations ───────────────────────────────────────────

    /// Compute HMAC with the specified finished key.
    pub async fn hmac_finished<P: SpdmPalSessionCrypto<Key = K>>(
        &self,
        pal: &P,
        io: &impl SpdmPalIo,
        key_type: SessionKeyType,
        data: &[u8],
        out: &mut [u8],
    ) -> McuResult<usize> {
        let key = self.finished_key(key_type)?;
        pal.hmac(io, key, data, out).await
    }

    /// Encrypt with the appropriate session key.
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
            .aead_encrypt(io, key, spdm_version, seq, aad, plaintext, ciphertext)
            .await?;
        self.increment_seq(key_type);
        Ok(result)
    }

    /// Decrypt with the appropriate session key.
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
            .aead_decrypt(io, key, spdm_version, seq, aad, ciphertext, tag, plaintext)
            .await?;
        self.increment_seq(key_type);
        Ok(result)
    }

    // ── Cleanup ─────────────────────────────────────────────────────

    /// Destroy handshake-phase secrets (after FINISH completes).
    ///
    /// Destroys: req/rsp handshake secrets, req/rsp finished keys,
    /// and the intermediate handshake_secret. Individual delete
    /// failures are silently ignored (best-effort cleanup).
    pub async fn destroy_handshake_secrets<P: SpdmPalSessionCrypto<Key = K>>(
        &mut self,
        pal: &P,
        io: &impl SpdmPalIo,
    ) {
        Self::delete_opt(pal, io, &mut self.handshake_ctx.request_handshake_secret).await;
        Self::delete_opt(pal, io, &mut self.handshake_ctx.response_handshake_secret).await;
        Self::delete_opt(pal, io, &mut self.handshake_ctx.request_finished_key).await;
        Self::delete_opt(pal, io, &mut self.handshake_ctx.response_finished_key).await;
        Self::delete_opt(pal, io, &mut self.master_ctx.handshake_secret).await;
    }

    /// Destroy all key handles.
    pub async fn destroy_all<P: SpdmPalSessionCrypto<Key = K>>(
        &mut self,
        pal: &P,
        io: &impl SpdmPalIo,
    ) {
        self.destroy_handshake_secrets(pal, io).await;
        Self::delete_opt(pal, io, &mut self.master_ctx.dhe_secret).await;
        Self::delete_opt(pal, io, &mut self.master_ctx.master_secret).await;
        Self::delete_opt(pal, io, &mut self.data_ctx.request_data_secret).await;
        Self::delete_opt(pal, io, &mut self.data_ctx.response_data_secret).await;
    }

    // ── Internal helpers ────────────────────────────────────────────

    async fn delete_opt<P: SpdmPalSessionCrypto<Key = K>>(
        pal: &P,
        io: &impl SpdmPalIo,
        slot: &mut Option<K>,
    ) {
        if let Some(k) = slot.take() {
            let _ = pal.delete_key(io, &k).await;
        }
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

    fn aead_key_and_seq(&self, key_type: SessionKeyType) -> McuResult<(&K, u64)> {
        match key_type {
            SessionKeyType::RequestHandshakeKey => Ok((
                self.handshake_ctx
                    .request_handshake_secret
                    .as_ref()
                    .ok_or(mcu_error::codes::INVARIANT)?,
                self.handshake_ctx.request_seq,
            )),
            SessionKeyType::ResponseHandshakeKey => Ok((
                self.handshake_ctx
                    .response_handshake_secret
                    .as_ref()
                    .ok_or(mcu_error::codes::INVARIANT)?,
                self.handshake_ctx.response_seq,
            )),
            SessionKeyType::RequestDataKey => Ok((
                self.data_ctx
                    .request_data_secret
                    .as_ref()
                    .ok_or(mcu_error::codes::INVARIANT)?,
                self.data_ctx.request_seq,
            )),
            SessionKeyType::ResponseDataKey => Ok((
                self.data_ctx
                    .response_data_secret
                    .as_ref()
                    .ok_or(mcu_error::codes::INVARIANT)?,
                self.data_ctx.response_seq,
            )),
            _ => Err(mcu_error::codes::INVARIANT),
        }
    }

    fn increment_seq(&mut self, key_type: SessionKeyType) {
        match key_type {
            SessionKeyType::RequestHandshakeKey => self.handshake_ctx.request_seq += 1,
            SessionKeyType::ResponseHandshakeKey => self.handshake_ctx.response_seq += 1,
            SessionKeyType::RequestDataKey => self.data_ctx.request_seq += 1,
            SessionKeyType::ResponseDataKey => self.data_ctx.response_seq += 1,
            _ => {}
        }
    }
}

// ── bin_concat helper ───────────────────────────────────────────────

/// SPDM HKDF bin_str label identifiers (DSP0274 Table 17).
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

/// Build the SPDM HKDF info field on the stack.
///
/// Format: `length(2LE) ‖ version_str ‖ label ‖ context`.
///
/// Returns `(buffer, actual_length)`. The buffer is
/// [`MAX_BIN_STR_LEN`] bytes; only `[0..actual_length]` is valid.
fn bin_concat(
    version_str: &[u8],
    bin_str: BinStr,
    length: u16,
    context: Option<&[u8]>,
) -> ([u8; MAX_BIN_STR_LEN], usize) {
    let mut buf = [0u8; MAX_BIN_STR_LEN];
    let mut pos = 0;

    let len_bytes = length.to_le_bytes();
    buf[pos..pos + 2].copy_from_slice(&len_bytes);
    pos += 2;

    buf[pos..pos + version_str.len()].copy_from_slice(version_str);
    pos += version_str.len();

    let label = bin_str.label();
    buf[pos..pos + label.len()].copy_from_slice(label);
    pos += label.len();

    if let Some(ctx) = context {
        buf[pos..pos + ctx.len()].copy_from_slice(ctx);
        pos += ctx.len();
    }

    (buf, pos)
}

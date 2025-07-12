// Licensed under the Apache-2.0 license

use crate::protocol::{CapabilityFlags, SpdmVersion, SHA384_HASH_SIZE};
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext};
use libapi_caliptra::error::CaliptraApiError;

#[derive(Debug, PartialEq)]
pub enum TranscriptError {
    BufferOverflow,
    InvalidState,
    CaliptraApi(CaliptraApiError),
}

pub type TranscriptResult<T> = Result<T, TranscriptError>;

struct VcaBuffer {
    data: [u8; Self::SPDM_MAX_BUFFER_SIZE],
    size: usize,
}

impl Default for VcaBuffer {
    fn default() -> Self {
        Self {
            data: [0; Self::SPDM_MAX_BUFFER_SIZE],
            size: 0,
        }
    }
}

impl VcaBuffer {
    pub const SPDM_MAX_BUFFER_SIZE: usize = 256;
    fn reset(&mut self) {
        self.data.fill(0);
        self.size = 0;
    }

    fn append(&mut self, data: &[u8]) -> TranscriptResult<()> {
        if self.size + data.len() > Self::SPDM_MAX_BUFFER_SIZE {
            return Err(TranscriptError::BufferOverflow);
        }
        self.data[self.size..self.size + data.len()].copy_from_slice(data);
        self.size += data.len();
        Ok(())
    }

    fn data(&self) -> &[u8] {
        &self.data[..self.size]
    }
}

#[derive(Clone, Copy)]
#[repr(u32)]
pub enum TranscriptContext {
    Vca = 1 << 0,
    M1 = 1 << 1,
    L1 = 1 << 2,
    KeyExchangeRspSignature = 1 << 3,
    KeyExchangeRspHmac = 1 << 4,
    FinishMutualAuthSignaure = 1 << 5,
    FinishResponderOnlyHmac = 1 << 6,
    FinishMutualAuthHmac = 1 << 7,
    FinishRspResponderOnly = 1 << 8,
    FinishRspMutualAuth = 1 << 9,
    TH2 = 1 << 10,
}

/// Transcript management for the SPDM responder.
#[derive(Default)]
pub(crate) struct TranscriptManager {
    spdm_version: SpdmVersion,
    // bit mask of enabled transcripts
    enabled_transcripts: u32,

    // TODO: compute these and keep them
    pub(crate) th1: Option<[u8; SHA384_HASH_SIZE]>,
    pub(crate) th2: Option<[u8; SHA384_HASH_SIZE]>,

    // Buffer for storing `VCA`
    // VCA or A = Concatenate (GET_VERSION, VERSION, GET_CAPABILITIES, CAPABILITIES, NEGOTIATE_ALGORITHMS, ALGORITHMS)
    vca_buf: VcaBuffer,
    // Hash context for `M1`
    // M1 = Concatenate(A, B, C)
    // where
    // B = Concatenate (GET_DIGESTS, DIGESTS, GET_CERTIFICATE, CERTIFICATE)
    // C = Concatenate (CHALLENGE, CHALLENGE_AUTH excluding signature)
    hash_ctx_m1: Option<HashContext>,
    // Hash Context for `L1`
    // L1 = Concatenate(A, M) if SPDM_VERSION >= 1.2 or L1 = Concatenate(M) if SPDM_VERSION < 1.2
    // where
    // M = Concatenate (GET_MEASUREMENTS, MEASUREMENTS\signature)
    hash_ctx_l1: Option<HashContext>,

    // we don't support PSK, so TH1 = KEY_EXCHANGE_RSP HMAC transcript

    // we don't support PSK, so TH2 = only uses key exchange
    // Hash Context for FINISH_RSP Mutual Authentication HMAC transcript
    // FRMA = Concatenate(A, B, C, D, E)
    // where
    // B = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key))
    // C = Concatenate(KEY_EXCHANGE, KEY_EXCHANGE_RSP)
    // D = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key)) if encapsulated DIGESTS is issued and MULTI_KEY_CONN_REQ is true
    // E = Concatenace(FINISH, FINISH_RSP)
    hash_ctx_th2: Option<HashContext>,

    // KEY_EXCHANGE_RSP contexts:
    // Hash Context for KEY_EXCHANGE_RSP signature transcript
    // KRS = Concatenate(A, B, C)
    // where
    // B = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key))
    // C = Concatenate(KEY_EXCHANGE, KEY_EXCHANGE_RSP excluding signature and ResponderVerifyData)
    hash_ctx_kex_rsp_sig: Option<HashContext>,
    // Hash Context for KEY_EXCHANGE_RSP HMAC transcript
    // KRH = Concatenate(A, B, C)
    // where
    // B = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key))
    // C = Concatenate(KEY_EXCHANGE, KEY_EXCHANGE_RSP excluding ResponderVerifyData)
    hash_ctx_kex_rsp_hmac: Option<HashContext>,

    // FINISH transcript contexts:
    // Hash Context for FINISH Mutual Authentication signature transcript
    // FMAS = Concatenate(A, B, C, D, E)
    // where
    // B = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key))
    // C = Concatenate(KEY_EXCHANGE, KEY_EXCHANGE_RSP)
    // D = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key)) if encapsulated DIGESTS is issued and MULTI_KEY_CONN_REQ is true
    // E = Finish SPDM Header Fields
    hash_ctx_finish_mutual_auth_signature: Option<HashContext>,
    // Hash Context for FINISH Responder Only HMAC transcript
    // FROH = Concatenate(A, B, C, D)
    // where
    // B = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key))
    // C = Concatenate(KEY_EXCHANGE, KEY_EXCHANGE_RSP)
    // D = Finish SPDM Header Fields
    hash_ctx_finish_responder_only_hmac: Option<HashContext>,
    // Hash Context for FINISH Mutual Authentication HMAC transcript
    // FMAH = Concatenate(A, B, C, D, E, F)
    // where
    // B = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key))
    // C = Concatenate(KEY_EXCHANGE, KEY_EXCHANGE_RSP)
    // D = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key)) if encapsulated DIGESTS is issued and MULTI_KEY_CONN_REQ is true
    // E = Finish SPDM Header Fields
    // F = Finish SPDM Signature
    hash_ctx_finish_mutual_auth_hmac: Option<HashContext>,

    // FINISH_RSP transcript contexts:
    // Hash Context for FINISH_RSP Responder Only HMAC transcript
    // FRRO = Concatenate(A, B, C, D, E)
    // where
    // B = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key))
    // C = Concatenate(KEY_EXCHANGE, KEY_EXCHANGE_RSP)
    // D = FINISH
    // E = FINISH_RSP SPDM Header Fields
    hash_ctx_finish_rsp_responder_only: Option<HashContext>,
    // Hash Context for FINISH_RSP Mutual Authentication HMAC transcript
    // FRMA = Concatenate(A, B, C, D, E, F)
    // where
    // B = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key))
    // C = Concatenate(KEY_EXCHANGE, KEY_EXCHANGE_RSP)
    // D = Concatenate(DIGESTS, Hash(cert chain DER) or Hash(pub key)) if encapsulated DIGESTS is issued and MULTI_KEY_CONN_REQ is true
    // E = FINISH
    // F = FINISH_RSP SPDM Header Fields
    hash_ctx_finish_rsp_mutual_auth: Option<HashContext>,
}

impl TranscriptManager {
    pub fn new() -> Self {
        let enabled_transcripts = (TranscriptContext::Vca as u32)
            | (TranscriptContext::M1 as u32)
            | (TranscriptContext::L1 as u32);
        Self {
            spdm_version: SpdmVersion::V10,
            enabled_transcripts,
            ..Default::default()
        }
    }

    pub fn update_capabilities(
        &mut self,
        capabilities: CapabilityFlags,
        peer_capabilities: CapabilityFlags,
    ) {
        // Since each transcript context takes SHA calls to maintain after each message,
        // we only enable the ones that are possible based on our joint capabilities.
        let key_ex = (capabilities.key_ex_cap() & peer_capabilities.key_ex_cap()) != 0;
        if !key_ex {
            return;
        }
        self.enabled_transcripts |= TranscriptContext::KeyExchangeRspSignature as u32;
        self.enabled_transcripts |= TranscriptContext::KeyExchangeRspHmac as u32;

        let mutual_auth = (capabilities.mut_auth_cap() & peer_capabilities.mut_auth_cap()) != 0;
        if mutual_auth {
            // no mutual authentication will be possible, so we only enable responder-only transcripts
            self.enabled_transcripts |= TranscriptContext::FinishResponderOnlyHmac as u32;
            self.enabled_transcripts |= TranscriptContext::FinishRspResponderOnly as u32;
        } else {
            // mutual authentication will be requested, so we enable those transcripts
            // TODO: determine which of signature or HMAC will be used
            self.enabled_transcripts |= TranscriptContext::FinishMutualAuthSignaure as u32;
            self.enabled_transcripts |= TranscriptContext::FinishMutualAuthHmac as u32;
            self.enabled_transcripts |= TranscriptContext::FinishRspMutualAuth as u32;
        }
    }

    /// Set the SPDM version selected by the SPDM responder.
    ///
    /// # Arguments
    /// * `spdm_version` - The SPDM version to set.
    pub fn set_spdm_version(&mut self, spdm_version: SpdmVersion) {
        self.spdm_version = spdm_version;
    }

    /// Reset a transcript context or all contexts.
    ///
    /// # Arguments
    /// * `context` - The context to reset. If `None`, all contexts are reset.
    pub fn reset(&mut self) {
        self.spdm_version = SpdmVersion::V10;
        self.vca_buf.reset();
        self.hash_ctx_m1 = None;
        self.hash_ctx_l1 = None;
    }

    /// Reset a transcript context.
    ///
    /// # Arguments
    /// * `context` - The context to reset. If `None`, all contexts are reset.
    pub fn reset_context(&mut self, context: TranscriptContext) {
        match context {
            TranscriptContext::Vca => self.vca_buf.reset(),
            TranscriptContext::M1 => self.hash_ctx_m1 = None,
            TranscriptContext::L1 => self.hash_ctx_l1 = None,
            TranscriptContext::TH2 => self.hash_ctx_th2 = None,
            TranscriptContext::KeyExchangeRspSignature => self.hash_ctx_kex_rsp_hmac = None,
            TranscriptContext::KeyExchangeRspHmac => self.hash_ctx_kex_rsp_hmac = None,
            TranscriptContext::FinishMutualAuthSignaure => {
                self.hash_ctx_finish_mutual_auth_signature = None
            }
            TranscriptContext::FinishResponderOnlyHmac => {
                self.hash_ctx_finish_responder_only_hmac = None
            }
            TranscriptContext::FinishMutualAuthHmac => self.hash_ctx_finish_mutual_auth_hmac = None,
            TranscriptContext::FinishRspMutualAuth => self.hash_ctx_finish_rsp_mutual_auth = None,
            TranscriptContext::FinishRspResponderOnly => {
                self.hash_ctx_finish_rsp_responder_only = None
            }
        }
    }

    /// Append data to a transcript context.
    ///
    /// # Arguments
    /// * `context` - The context to append data to.
    /// * `data` - The data to append.
    ///
    /// # Returns
    /// * `TranscriptResult<()>` - Result indicating success or failure.
    pub async fn append(
        &mut self,
        context: TranscriptContext,
        data: &[u8],
    ) -> TranscriptResult<()> {
        let ctx = match context {
            TranscriptContext::Vca => {
                self.vca_buf.append(data)?;
                return Ok(());
            }
            TranscriptContext::M1 => &mut self.hash_ctx_m1,
            TranscriptContext::L1 => &mut self.hash_ctx_l1,
            TranscriptContext::TH2 => &mut self.hash_ctx_th2,
            TranscriptContext::KeyExchangeRspSignature => &mut self.hash_ctx_kex_rsp_sig,
            TranscriptContext::KeyExchangeRspHmac => &mut self.hash_ctx_kex_rsp_hmac,
            TranscriptContext::FinishMutualAuthSignaure => {
                &mut self.hash_ctx_finish_mutual_auth_signature
            }
            TranscriptContext::FinishResponderOnlyHmac => {
                &mut self.hash_ctx_finish_responder_only_hmac
            }
            TranscriptContext::FinishMutualAuthHmac => &mut self.hash_ctx_finish_mutual_auth_hmac,
            TranscriptContext::FinishRspResponderOnly => {
                &mut self.hash_ctx_finish_rsp_responder_only
            }
            TranscriptContext::FinishRspMutualAuth => &mut self.hash_ctx_finish_rsp_mutual_auth,
        };

        if let Some(ctx) = ctx {
            ctx.update(data).await.map_err(TranscriptError::CaliptraApi)
        } else {
            let mut hash_ctx = HashContext::new();
            hash_ctx
                .init(HashAlgoType::SHA384, Some(self.vca_buf.data()))
                .await
                .map_err(TranscriptError::CaliptraApi)?;
            hash_ctx
                .update(data)
                .await
                .map_err(TranscriptError::CaliptraApi)?;
            ctx.replace(hash_ctx);
            Ok(())
        }
    }

    /// Append data to multiple transcript contexts.
    ///
    /// # Arguments
    /// * `contexts` - The contexts to append data to.
    /// * `data` - The data to append.
    ///
    /// # Returns
    /// * `TranscriptResult<()>` - Result indicating success or failure.
    pub async fn append_multiple(
        &mut self,
        contexts: &[TranscriptContext],
        data: &[u8],
    ) -> TranscriptResult<()> {
        for context in contexts.iter().copied() {
            if self.is_transcript_enabled(context) {
                self.append(context, data).await?;
            }
        }
        Ok(())
    }

    pub(crate) fn enable_transcript(&mut self, context: TranscriptContext) {
        self.enabled_transcripts |= context as u32;
    }

    pub(crate) fn disable_transcript(&mut self, context: TranscriptContext) {
        self.enabled_transcripts &= !(context as u32);
    }

    pub(crate) fn is_transcript_enabled(&self, context: TranscriptContext) -> bool {
        self.enabled_transcripts & (context as u32) != 0
    }

    /// Finalize the hash for a given context.
    ///
    /// # Arguments
    /// * `context` - The context to finalize the hash for.
    /// * `hash` - The buffer to store the resulting hash.
    ///
    /// # Returns
    /// * `TranscriptResult<()>` - Result indicating success or failure.
    pub async fn hash(
        &mut self,
        context: TranscriptContext,
        hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> TranscriptResult<()> {
        let hash_ctx = match context {
            TranscriptContext::Vca => return Err(TranscriptError::InvalidState),
            TranscriptContext::M1 => self.hash_ctx_m1.as_mut().take(),
            TranscriptContext::L1 => self.hash_ctx_l1.as_mut().take(),
            TranscriptContext::TH2 => self.hash_ctx_th2.as_mut().take(),
            TranscriptContext::FinishMutualAuthSignaure => {
                self.hash_ctx_finish_mutual_auth_signature.as_mut().take()
            }
            TranscriptContext::FinishResponderOnlyHmac => {
                self.hash_ctx_finish_responder_only_hmac.as_mut().take()
            }
            TranscriptContext::FinishMutualAuthHmac => {
                self.hash_ctx_finish_mutual_auth_hmac.as_mut().take()
            }
            TranscriptContext::KeyExchangeRspSignature => self.hash_ctx_kex_rsp_sig.as_mut().take(),
            TranscriptContext::KeyExchangeRspHmac => self.hash_ctx_kex_rsp_hmac.as_mut().take(),
            TranscriptContext::FinishRspMutualAuth => {
                self.hash_ctx_finish_rsp_mutual_auth.as_mut().take()
            }
            TranscriptContext::FinishRspResponderOnly => {
                self.hash_ctx_finish_rsp_responder_only.as_mut().take()
            }
        };

        if let Some(ctx) = hash_ctx {
            ctx.finalize(hash)
                .await
                .map_err(TranscriptError::CaliptraApi)?;
        } else {
            return Err(TranscriptError::InvalidState);
        }

        match context {
            TranscriptContext::KeyExchangeRspHmac => {
                // this is TH1 since we don't support PSK
                let mut copy_hash = [0u8; SHA384_HASH_SIZE];
                copy_hash.copy_from_slice(hash);
                self.th1.replace(copy_hash);
            }
            TranscriptContext::TH2 => {
                let mut copy_hash = [0u8; SHA384_HASH_SIZE];
                copy_hash.copy_from_slice(hash);
                self.th2.replace(copy_hash);
            }
            _ => {}
        }
        Ok(())
    }
}

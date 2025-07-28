// Licensed under the Apache-2.0 license

use crate::cert_store::MAX_CERT_SLOTS_SUPPORTED;
use crate::protocol::SpdmVersion;
use crate::session::SessionInfo;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext, SHA384_HASH_SIZE};
use libapi_caliptra::error::CaliptraApiError;

#[derive(Debug, PartialEq)]
pub enum TranscriptError {
    BufferOverflow,
    InvalidState,
    MissingSessionInfo,
    CaliptraApi(CaliptraApiError),
}

pub type TranscriptResult<T> = Result<T, TranscriptError>;

// Generic buffer implementation to eliminate code duplication
struct Buffer<const N: usize> {
    data: [u8; N],
    size: usize,
}

impl<const N: usize> Default for Buffer<N> {
    fn default() -> Self {
        Self {
            data: [0; N],
            size: 0,
        }
    }
}

impl<const N: usize> Buffer<N> {
    fn from_slice(data: &[u8]) -> TranscriptResult<Self> {
        let mut buffer = Buffer::default();
        if data.len() > N {
            Err(TranscriptError::BufferOverflow)?
        }
        buffer.data[..data.len()].copy_from_slice(data);
        buffer.size = data.len();
        Ok(buffer)
    }

    fn reset(&mut self) {
        self.data.fill(0);
        self.size = 0;
    }

    fn append(&mut self, data: &[u8]) -> TranscriptResult<()> {
        if self.size + data.len() > N {
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

// Type aliases for specific buffer types with their respective sizes
const VCA_BUFFER_SIZE: usize = 256;
const DIGESTS_BUFFER_SIZE: usize = 4
    + (SHA384_HASH_SIZE + MAX_CERT_SLOTS_SUPPORTED as usize)
    + 4 * MAX_CERT_SLOTS_SUPPORTED as usize;

type VcaBuffer = Buffer<VCA_BUFFER_SIZE>;
type DigestsBuffer = Buffer<DIGESTS_BUFFER_SIZE>;

pub enum TranscriptContext {
    Vca,
    Digests,
    M1,
    L1,
    Th,
}

/// Transcript management for the SPDM responder.
pub(crate) struct Transcript {
    spdm_version: SpdmVersion,
    // Buffer for storing `VCA`
    // VCA or A = Concatenate (GET_VERSION, VERSION, GET_CAPABILITIES, CAPABILITIES, NEGOTIATE_ALGORITHMS, ALGORITHMS)
    vca_buf: VcaBuffer,
    // Digests Buffer
    // Digests = DIGESTS if MULTI_KEY_CONN_RSP is true
    digests_buf: Option<DigestsBuffer>,
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
}

impl Transcript {
    pub fn new() -> Self {
        Self {
            spdm_version: SpdmVersion::V10,
            vca_buf: VcaBuffer::default(),
            digests_buf: None,
            hash_ctx_m1: None,
            hash_ctx_l1: None,
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
        self.digests_buf = None;
        self.hash_ctx_m1 = None;
        self.hash_ctx_l1 = None;
    }

    /// Reset a transcript context.
    ///
    /// # Arguments
    /// * `context` - The context to reset.
    pub fn reset_context(&mut self, context: TranscriptContext) {
        match context {
            TranscriptContext::Vca => self.vca_buf.reset(),
            TranscriptContext::Digests => self.digests_buf = None,
            TranscriptContext::M1 => self.hash_ctx_m1 = None,
            TranscriptContext::L1 => self.hash_ctx_l1 = None,
            _ => {}
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
        session_info: Option<&mut SessionInfo>,
        data: &[u8],
    ) -> TranscriptResult<()> {
        match context {
            TranscriptContext::Vca => self.vca_buf.append(data),
            TranscriptContext::Digests => self.append_digests(data),
            TranscriptContext::M1 => self.append_m1(data).await,
            TranscriptContext::L1 => self.append_l1(self.spdm_version, session_info, data).await,
            TranscriptContext::Th => {
                if let Some(session) = session_info {
                    self.append_th(session, data).await
                } else {
                    Err(TranscriptError::MissingSessionInfo)
                }
            } 
        }
    }

    /// Finalize the hash for a given context.
    ///
    /// # Arguments
    /// * `context` - The context to finalize the hash for.
    /// * `session_info` - Session info for session-specific contexts (required for TH)
    /// * `hash` - The buffer to store the resulting hash.
    /// * `finish_hash` - Indicates if the hash is final or intermediate.
    ///
    /// # Returns
    /// * `TranscriptResult<()>` - Result indicating success or failure.
    pub async fn hash(
        &mut self,
        context: TranscriptContext,
        session_info: Option<&mut SessionInfo>,
        hash: &mut [u8; SHA384_HASH_SIZE],
        finish_hash: bool,
    ) -> TranscriptResult<()> {
        match context {
            TranscriptContext::M1 => {
                // M1 always uses global hash context
                if let Some(ctx) = &mut self.hash_ctx_m1 {
                    ctx.finalize(hash)
                        .await
                        .map_err(TranscriptError::CaliptraApi)?;
                    if finish_hash {
                        self.hash_ctx_m1 = None;
                    }
                    Ok(())
                } else {
                    Err(TranscriptError::InvalidState)
                }
            }
            TranscriptContext::L1 => {
                match session_info {
                    Some(session) => {
                        // Use session-specific L1 hash context
                        if let Some(ctx) = &mut session.session_transcript.hash_ctx_l1 {
                            ctx.finalize(hash)
                                .await
                                .map_err(TranscriptError::CaliptraApi)?;
                            if finish_hash {
                                session.session_transcript.hash_ctx_l1 = None;
                            }
                            Ok(())
                        } else {
                            Err(TranscriptError::InvalidState)
                        }
                    }
                    None => {
                        // Use global L1 hash context
                        if let Some(ctx) = &mut self.hash_ctx_l1 {
                            ctx.finalize(hash)
                                .await
                                .map_err(TranscriptError::CaliptraApi)?;
                            if finish_hash {
                                self.hash_ctx_l1 = None;
                            }
                            Ok(())
                        } else {
                            Err(TranscriptError::InvalidState)
                        }
                    }
                }
            }
            TranscriptContext::Th => {
                // TH requires session_info - error if None
                match session_info {
                    Some(session) => {
                        if let Some(ctx) = &mut session.session_transcript.hash_ctx_th {
                            ctx.finalize(hash)
                                .await
                                .map_err(TranscriptError::CaliptraApi)?;
                            if finish_hash {
                                session.session_transcript.hash_ctx_th = None;
                            }
                            Ok(())
                        } else {
                            Err(TranscriptError::InvalidState)
                        }
                    }
                    None => {
                        // TH context requires session_info
                        Err(TranscriptError::MissingSessionInfo)
                    }
                }
            }
            _ => Err(TranscriptError::InvalidState),
        }
    }

    fn append_digests(&mut self, data: &[u8]) -> TranscriptResult<()> {
        let digests_buf = DigestsBuffer::from_slice(data)?;
        self.digests_buf = Some(digests_buf);
        Ok(())
    }

    async fn append_m1(&mut self, data: &[u8]) -> TranscriptResult<()> {
        if let Some(ctx) = &mut self.hash_ctx_m1 {
            ctx.update(data).await.map_err(TranscriptError::CaliptraApi)
        } else {
            let vca_data = self.vca_buf.data();
            let mut ctx = HashContext::new();
            ctx.init(HashAlgoType::SHA384, Some(vca_data))
                .await
                .map_err(TranscriptError::CaliptraApi)?;
            ctx.update(data)
                .await
                .map_err(TranscriptError::CaliptraApi)?;
            self.hash_ctx_m1 = Some(ctx);
            Ok(())
        }
    }

    async fn append_l1(
        &mut self,
        spdm_version: SpdmVersion,
        session_info: Option<&mut SessionInfo>,
        data: &[u8],
    ) -> TranscriptResult<()> {
        match session_info {
            Some(session) => {
                // Use session-specific hash context
                if let Some(ctx) = &mut session.session_transcript.hash_ctx_l1 {
                    ctx.update(data).await.map_err(TranscriptError::CaliptraApi)
                } else {
                    let vca_data = if spdm_version >= SpdmVersion::V12 {
                        Some(self.vca_buf.data())
                    } else {
                        None
                    };

                    let mut ctx = HashContext::new();
                    ctx.init(HashAlgoType::SHA384, vca_data)
                        .await
                        .map_err(TranscriptError::CaliptraApi)?;
                    ctx.update(data)
                        .await
                        .map_err(TranscriptError::CaliptraApi)?;
                    session.session_transcript.hash_ctx_l1 = Some(ctx);
                    Ok(())
                }
            }
            None => {
                // Use global hash context
                if let Some(ctx) = &mut self.hash_ctx_l1 {
                    ctx.update(data).await.map_err(TranscriptError::CaliptraApi)
                } else {
                    let vca_data = if spdm_version >= SpdmVersion::V12 {
                        Some(self.vca_buf.data())
                    } else {
                        None
                    };

                    let mut ctx = HashContext::new();
                    ctx.init(HashAlgoType::SHA384, vca_data)
                        .await
                        .map_err(TranscriptError::CaliptraApi)?;
                    ctx.update(data)
                        .await
                        .map_err(TranscriptError::CaliptraApi)?;
                    self.hash_ctx_l1 = Some(ctx);
                    Ok(())
                }
            }
        }
    }

    async fn append_th(
        &mut self,
        session_info: &mut SessionInfo,
        data: &[u8],
    ) -> TranscriptResult<()> {
        if let Some(ctx) = &mut session_info.session_transcript.hash_ctx_th {
            ctx.update(data).await.map_err(TranscriptError::CaliptraApi)
        } else {
            let vca_data = self.vca_buf.data();
            let digests_data = self
                .digests_buf
                .as_ref()
                .map(|buf| buf.data())
                .unwrap_or(&[]);
            let mut ctx = HashContext::new();
            ctx.init(HashAlgoType::SHA384, Some(vca_data))
                .await
                .map_err(TranscriptError::CaliptraApi)?;
            ctx.update(digests_data)
                .await
                .map_err(TranscriptError::CaliptraApi)?;
            ctx.update(data)
                .await
                .map_err(TranscriptError::CaliptraApi)?;
            session_info.session_transcript.hash_ctx_th = Some(ctx);
            Ok(())
        }
    }
}

// Transcript for within a session
#[derive(Default)]
pub(crate) struct SessionTranscript {
    // Hash Context for `L1`
    // L1 = Concatenate(A, M) if SPDM_VERSION >= 1.2 or L1 = Concatenate(M) if SPDM_VERSION < 1.2
    // where
    // M = Concatenate (GET_MEASUREMENTS, MEASUREMENTS\signature)
    hash_ctx_l1: Option<HashContext>,
    // Hash Context for `TH1/TH2`
    // TH1 = Concatenate(A, D, Ct, Ksig/Khmac)
    // where
    // D  = DIGESTS if MULTI_KEY_CONN_RSP is true
    // Ct = Hash of the Cert Chain
    // Ksig = Concateneate(KEY_EXCHANGE, KEY_EXCHANGE_RSP exclusing signature, ResponderVerifyData)
    // Khmac = Concatenate(KEY_EXCHANGE, KEY_EXCHANGE_RSP excluding ResponderVerifyData)
    //
    // TH2 = TODO
    hash_ctx_th: Option<HashContext>,
}

impl SessionTranscript {
    pub fn new() -> Self {
        Self {
            hash_ctx_l1: None,
            hash_ctx_th: None,
        }
    }
}

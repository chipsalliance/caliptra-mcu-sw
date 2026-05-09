// Licensed under the Apache-2.0 license

//! SPDM Key Schedule
//! Handles secret, key derivation and management for SPDM secure sessions.
//!

use crate::protocol::SpdmVersion;
use arrayvec::ArrayVec;
use caliptra_api::mailbox::Cmk;
use libapi_caliptra::crypto::aes_gcm::{Aes256GcmTag, AesGcm};
use libapi_caliptra::crypto::asym::ecdh::{CmKeyUsage, Ecdh, CMB_ECDH_EXCHANGE_DATA_MAX_SIZE};
use libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use libapi_caliptra::crypto::hmac::{HkdfSalt, Hmac};
use libapi_caliptra::crypto::import::Import;
use libapi_caliptra::error::CaliptraApiError;

#[derive(Debug, PartialEq)]
pub enum KeyScheduleError {
    BufferTooSmall,
    InvalidSessionKeyType,
    DheSecretNotFound,
    HandshakeSecretNotFound,
    MasterSecretNotFound,
    DataSecretNotFound,
    CaliptraApi(CaliptraApiError),
}

pub type KeyScheduleResult<T> = Result<T, KeyScheduleError>;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SessionKeyType {
    RequestFinishedKey,
    ResponseFinishedKey,
    RequestHandshakeEncDecKey,
    ResponseHandshakeEncDecKey,
    RequestDataEncDecKey,
    ResponseDataEncDecKey,
}

#[derive(Default)]
pub(crate) struct KeySchedule {
    spdm_version: SpdmVersion,
    master_secret_ctx: MasterSecretCtx,
    handshake_secret_ctx: HandshakeSecretCtx,
    data_secret_ctx: DataSecretCtx,
    export_master_secret: Option<Cmk>,
}

impl KeySchedule {
    const MAX_BIN_STR_LEN: usize = 128;

    pub fn set_spdm_version(&mut self, version: SpdmVersion) {
        self.spdm_version = version;
    }

    pub async fn compute_dhe_secret(
        &mut self,
        peer_exch_data: &[u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
    ) -> KeyScheduleResult<[u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE]> {
        let mut self_exch_data = [0u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE];

        // Generate an ephemeral key pair
        let generate_resp = Ecdh::ecdh_generate()
            .await
            .map_err(KeyScheduleError::CaliptraApi)?;

        self_exch_data.copy_from_slice(&generate_resp.exchange_data);

        // Finish the ECDH key exchange to generate the shared secret
        let shared_secret = Ecdh::ecdh_finish(CmKeyUsage::Hmac, &generate_resp, peer_exch_data)
            .await
            .map_err(KeyScheduleError::CaliptraApi)?;

        // Store the shared secret in the session context
        self.master_secret_ctx.dhe_secret = Some(shared_secret);

        Ok(self_exch_data)
    }

    pub async fn generate_session_handshake_key(
        &mut self,
        th1_transcript_hash: &[u8],
    ) -> KeyScheduleResult<()> {
        self.generate_handshake_secret().await?;
        self.generate_req_rsp_handshake_secret(th1_transcript_hash)
            .await?;
        self.generate_req_rsp_finished_key().await
    }

    pub async fn generate_session_data_key(
        &mut self,
        th2_transcript_hash: &[u8],
    ) -> KeyScheduleResult<()> {
        self.generate_master_secret().await?;
        self.generate_req_rsp_data_secret(th2_transcript_hash)
            .await?;
        self.generate_export_master_secret(th2_transcript_hash)
            .await
    }

    pub async fn hmac(
        &self,
        key_type: SessionKeyType,
        data: &[u8],
    ) -> KeyScheduleResult<[u8; SHA384_HASH_SIZE]> {
        let key = match key_type {
            SessionKeyType::RequestFinishedKey => self
                .handshake_secret_ctx
                .request_finished_key
                .as_ref()
                .ok_or(KeyScheduleError::HandshakeSecretNotFound)?,
            SessionKeyType::ResponseFinishedKey => self
                .handshake_secret_ctx
                .response_finished_key
                .as_ref()
                .ok_or(KeyScheduleError::HandshakeSecretNotFound)?,
            _ => Err(KeyScheduleError::InvalidSessionKeyType)?,
        };

        // Compute HMAC using the specified key
        let hmac = Hmac::hmac(key, data)
            .await
            .map_err(KeyScheduleError::CaliptraApi)?;

        let mut hmac_bytes = [0u8; SHA384_HASH_SIZE];
        hmac_bytes.copy_from_slice(&hmac.mac[..SHA384_HASH_SIZE]);

        Ok(hmac_bytes)
    }

    pub async fn encrypt_message(
        &mut self,
        session_key_type: SessionKeyType,
        aad_data: &[u8],
        plaintext_message: &[u8],
        encrypted_message: &mut [u8],
    ) -> KeyScheduleResult<(usize, Aes256GcmTag)> {
        let major_secret = self.get_major_secret(session_key_type)?;
        let sequence_num_bytes = self.get_sequence_number(session_key_type)?.to_le_bytes();

        let mut aes_gcm = AesGcm::new();

        let result = aes_gcm
            .spdm_message_encrypt(
                major_secret,
                self.spdm_version.into(),
                sequence_num_bytes,
                true,
                aad_data,
                plaintext_message,
                encrypted_message,
            )
            .await
            .map_err(KeyScheduleError::CaliptraApi)?;

        // Increment the sequence number after encryption
        self.increment_sequence_number(session_key_type)?;

        Ok(result)
    }

    pub async fn decrypt_message(
        &mut self,
        session_key_type: SessionKeyType,
        aad_data: &[u8],
        encrypted_msg: &[u8],
        plaintext_msg: &mut [u8],
        tag: Aes256GcmTag,
    ) -> KeyScheduleResult<usize> {
        let major_secret = self.get_major_secret(session_key_type)?;
        let sequence_num_bytes = self.get_sequence_number(session_key_type)?.to_le_bytes();

        let mut aes_gcm = AesGcm::new();

        let decrypted_size = aes_gcm
            .spdm_message_decrypt(
                major_secret,
                self.spdm_version.into(),
                sequence_num_bytes,
                true,
                aad_data,
                encrypted_msg,
                tag,
                plaintext_msg,
            )
            .await
            .map_err(KeyScheduleError::CaliptraApi)?;

        // Increment the sequence number after decryption
        self.increment_sequence_number(session_key_type)?;

        Ok(decrypted_size)
    }

    fn get_sequence_number(&self, session_key_type: SessionKeyType) -> KeyScheduleResult<u64> {
        match session_key_type {
            SessionKeyType::RequestHandshakeEncDecKey => {
                Ok(self.handshake_secret_ctx.request_sequence_num)
            }
            SessionKeyType::ResponseHandshakeEncDecKey => {
                Ok(self.handshake_secret_ctx.response_sequence_num)
            }
            SessionKeyType::RequestDataEncDecKey => Ok(self.data_secret_ctx.request_sequence_num),
            SessionKeyType::ResponseDataEncDecKey => Ok(self.data_secret_ctx.response_sequence_num),
            _ => Err(KeyScheduleError::InvalidSessionKeyType),
        }
    }

    fn get_major_secret(&self, session_key_type: SessionKeyType) -> KeyScheduleResult<Cmk> {
        match session_key_type {
            SessionKeyType::RequestHandshakeEncDecKey => self
                .handshake_secret_ctx
                .request_handshake_secret
                .clone()
                .ok_or(KeyScheduleError::HandshakeSecretNotFound),
            SessionKeyType::ResponseHandshakeEncDecKey => self
                .handshake_secret_ctx
                .response_handshake_secret
                .clone()
                .ok_or(KeyScheduleError::HandshakeSecretNotFound),
            SessionKeyType::RequestDataEncDecKey => self
                .data_secret_ctx
                .request_data_secret
                .clone()
                .ok_or(KeyScheduleError::DataSecretNotFound),
            SessionKeyType::ResponseDataEncDecKey => self
                .data_secret_ctx
                .response_data_secret
                .clone()
                .ok_or(KeyScheduleError::DataSecretNotFound),
            _ => Err(KeyScheduleError::InvalidSessionKeyType),
        }
    }

    fn increment_sequence_number(
        &mut self,
        session_key_type: SessionKeyType,
    ) -> KeyScheduleResult<()> {
        match session_key_type {
            SessionKeyType::RequestHandshakeEncDecKey => {
                self.handshake_secret_ctx.request_sequence_num += 1;
            }
            SessionKeyType::ResponseHandshakeEncDecKey => {
                self.handshake_secret_ctx.response_sequence_num += 1;
            }
            SessionKeyType::RequestDataEncDecKey => {
                self.data_secret_ctx.request_sequence_num += 1;
            }
            SessionKeyType::ResponseDataEncDecKey => {
                self.data_secret_ctx.response_sequence_num += 1;
            }
            _ => return Err(KeyScheduleError::InvalidSessionKeyType),
        }

        Ok(())
    }

    // Generates the handshake secret using the DHE Secret and Salt_0
    async fn generate_handshake_secret(&mut self) -> KeyScheduleResult<()> {
        let salt_0 = [0u8; SHA384_HASH_SIZE];

        // Handshake-Secret = HKDF-Extract(Salt_0, DHE-Secret)
        if let Some(dhe_secret) = &self.master_secret_ctx.dhe_secret {
            let extract = Hmac::hkdf_extract(HkdfSalt::Data(&salt_0), dhe_secret)
                .await
                .map_err(KeyScheduleError::CaliptraApi)?;

            // Store the handshake secret.
            self.master_secret_ctx.handshake_secret = Some(extract.prk);
            // TODO: Should we set dhe_secret to None after extracting?

            Ok(())
        } else {
            Err(KeyScheduleError::DheSecretNotFound)
        }
    }

    // Generate the request/response direction handshake secret
    async fn generate_req_rsp_handshake_secret(
        &mut self,
        th1_transcript_hash: &[u8],
    ) -> KeyScheduleResult<()> {
        let bin_str1 = self.bin_concat(
            SpdmBinStr::BinStr1,
            SHA384_HASH_SIZE as u16,
            Some(th1_transcript_hash),
        )?;
        let bin_str2 = self.bin_concat(
            SpdmBinStr::BinStr2,
            SHA384_HASH_SIZE as u16,
            Some(th1_transcript_hash),
        )?;

        // Request-Handshake-Secret = HKDF-Expand(Handshake-Secret, bin_str1, Hash.Length)
        let expand_req = Hmac::hkdf_expand(
            self.master_secret_ctx
                .handshake_secret
                .as_ref()
                .ok_or(KeyScheduleError::HandshakeSecretNotFound)?,
            CmKeyUsage::Hmac,
            SHA384_HASH_SIZE as u32,
            bin_str1.as_slice(),
        )
        .await
        .map_err(KeyScheduleError::CaliptraApi)?;

        // Response-Handshake-Secret = HKDF-Expand(Handshake-Secret, bin_str2, Hash.Length)
        let expand_rsp = Hmac::hkdf_expand(
            self.master_secret_ctx
                .handshake_secret
                .as_ref()
                .ok_or(KeyScheduleError::HandshakeSecretNotFound)?,
            CmKeyUsage::Hmac,
            SHA384_HASH_SIZE as u32,
            bin_str2.as_slice(),
        )
        .await
        .map_err(KeyScheduleError::CaliptraApi)?;

        self.handshake_secret_ctx.request_handshake_secret = Some(expand_req.okm);
        self.handshake_secret_ctx.response_handshake_secret = Some(expand_rsp.okm);

        Ok(())
    }

    async fn generate_req_rsp_finished_key(&mut self) -> KeyScheduleResult<()> {
        let bin_str7 = self.bin_concat(SpdmBinStr::BinStr7, SHA384_HASH_SIZE as u16, None)?;

        // Request-Finished-Key = HKDF-Expand(Request-Handshake-Secret, bin_str7, Hash.Length)
        let expand_req = Hmac::hkdf_expand(
            self.handshake_secret_ctx
                .request_handshake_secret
                .as_ref()
                .ok_or(KeyScheduleError::HandshakeSecretNotFound)?,
            CmKeyUsage::Hmac,
            SHA384_HASH_SIZE as u32,
            bin_str7.as_slice(),
        )
        .await
        .map_err(KeyScheduleError::CaliptraApi)?;

        // Response-Finished-Key = HKDF-Expand(Response-Handshake-Secret, bin_str7, Hash.Length)
        let expand_rsp = Hmac::hkdf_expand(
            self.handshake_secret_ctx
                .response_handshake_secret
                .as_ref()
                .ok_or(KeyScheduleError::HandshakeSecretNotFound)?,
            CmKeyUsage::Hmac,
            SHA384_HASH_SIZE as u32,
            bin_str7.as_slice(),
        )
        .await
        .map_err(KeyScheduleError::CaliptraApi)?;

        self.handshake_secret_ctx.request_finished_key = Some(expand_req.okm);
        self.handshake_secret_ctx.response_finished_key = Some(expand_rsp.okm);
        Ok(())
    }

    async fn generate_master_secret(&mut self) -> KeyScheduleResult<()> {
        let bin_str0 = self.bin_concat(SpdmBinStr::BinStr0, SHA384_HASH_SIZE as u16, None)?;

        // Salt_1 = HKDF-Expand(Handshake-Secret, bin_str0, Hash.Length)
        let expand_rsp = Hmac::hkdf_expand(
            self.master_secret_ctx
                .handshake_secret
                .as_ref()
                .ok_or(KeyScheduleError::HandshakeSecretNotFound)?,
            CmKeyUsage::Hmac,
            SHA384_HASH_SIZE as u32,
            bin_str0.as_slice(),
        )
        .await
        .map_err(KeyScheduleError::CaliptraApi)?;

        let salt_1 = expand_rsp.okm;

        // Master-Secret = HKDF-Extract(Salt_1, 0_filled)
        let zero_filled = [0u8; SHA384_HASH_SIZE];
        let zero_filled_ikm_cmk = Import::import(CmKeyUsage::Hmac, &zero_filled)
            .await
            .map_err(KeyScheduleError::CaliptraApi)?;

        let extract_rsp = Hmac::hkdf_extract(HkdfSalt::Cmk(&salt_1), &zero_filled_ikm_cmk.cmk)
            .await
            .map_err(KeyScheduleError::CaliptraApi)?;

        // Store the master secret
        self.master_secret_ctx.master_secret = Some(extract_rsp.prk);

        Ok(())
    }

    async fn generate_req_rsp_data_secret(
        &mut self,
        th2_transcript_hash: &[u8],
    ) -> KeyScheduleResult<()> {
        let bin_str3 = self.bin_concat(
            SpdmBinStr::BinStr3,
            SHA384_HASH_SIZE as u16,
            Some(th2_transcript_hash),
        )?;

        let bin_str4 = self.bin_concat(
            SpdmBinStr::BinStr4,
            SHA384_HASH_SIZE as u16,
            Some(th2_transcript_hash),
        )?;

        // Request-Direction-Data-Secret = HKDF-Expand(Master-Secret, bin_str3, Hash.Length)
        let expand_req = Hmac::hkdf_expand(
            self.master_secret_ctx
                .master_secret
                .as_ref()
                .ok_or(KeyScheduleError::MasterSecretNotFound)?,
            CmKeyUsage::Hmac,
            SHA384_HASH_SIZE as u32,
            bin_str3.as_slice(),
        )
        .await
        .map_err(KeyScheduleError::CaliptraApi)?;

        // Response-Direction-Data-Secret = HKDF-Expand(Master-Secret, bin_str4, Hash.Length)
        let expand_rsp = Hmac::hkdf_expand(
            self.master_secret_ctx
                .master_secret
                .as_ref()
                .ok_or(KeyScheduleError::MasterSecretNotFound)?,
            CmKeyUsage::Hmac,
            SHA384_HASH_SIZE as u32,
            bin_str4.as_slice(),
        )
        .await
        .map_err(KeyScheduleError::CaliptraApi)?;

        self.data_secret_ctx.request_data_secret = Some(expand_req.okm);
        self.data_secret_ctx.response_data_secret = Some(expand_rsp.okm);

        Ok(())
    }

    async fn generate_export_master_secret(
        &mut self,
        th2_transcript_hash: &[u8],
    ) -> KeyScheduleResult<()> {
        let bin_str8 = self.bin_concat(
            SpdmBinStr::BinStr8,
            SHA384_HASH_SIZE as u16,
            Some(th2_transcript_hash),
        )?;

        // Export-Master-Secret = HKDF-Expand(Master-Secret, bin_str8, Hash.Length)
        let expand_rsp = Hmac::hkdf_expand(
            self.master_secret_ctx
                .master_secret
                .as_ref()
                .ok_or(KeyScheduleError::MasterSecretNotFound)?,
            CmKeyUsage::Hmac,
            SHA384_HASH_SIZE as u32,
            bin_str8.as_slice(),
        )
        .await
        .map_err(KeyScheduleError::CaliptraApi)?;

        self.export_master_secret = Some(expand_rsp.okm);

        Ok(())
    }

    fn bin_concat(
        &self,
        bin_str_type: SpdmBinStr,
        length: u16,
        context: Option<&[u8]>,
    ) -> KeyScheduleResult<ArrayVec<u8, { Self::MAX_BIN_STR_LEN }>> {
        let mut bin_str_buf = ArrayVec::<u8, { Self::MAX_BIN_STR_LEN }>::new();
        let length_bytes = length.to_le_bytes();
        let version_bytes = self.version_str().as_bytes();
        let label_bytes = bin_str_type.label().as_bytes();

        bin_str_buf
            .try_extend_from_slice(&length_bytes)
            .map_err(|_| KeyScheduleError::BufferTooSmall)?;
        bin_str_buf
            .try_extend_from_slice(version_bytes)
            .map_err(|_| KeyScheduleError::BufferTooSmall)?;
        bin_str_buf
            .try_extend_from_slice(label_bytes)
            .map_err(|_| KeyScheduleError::BufferTooSmall)?;
        if let Some(context) = context {
            bin_str_buf
                .try_extend_from_slice(context)
                .map_err(|_| KeyScheduleError::BufferTooSmall)?;
        }

        Ok(bin_str_buf)
    }

    fn version_str(&self) -> &str {
        match self.spdm_version {
            SpdmVersion::V10 => "spdm1.0 ",
            SpdmVersion::V11 => "spdm1.1 ",
            SpdmVersion::V12 => "spdm1.2 ",
            SpdmVersion::V13 => "spdm1.3 ",
        }
    }
}

#[derive(Default)]
struct MasterSecretCtx {
    // DHE secret
    dhe_secret: Option<Cmk>,
    // Handshake secret
    handshake_secret: Option<Cmk>,
    // Master secret
    master_secret: Option<Cmk>,
}

#[derive(Default)]
struct HandshakeSecretCtx {
    // Request direction handshake secret
    request_handshake_secret: Option<Cmk>,
    // Response direction handshake secret
    response_handshake_secret: Option<Cmk>,
    // Request direction finished key
    request_finished_key: Option<Cmk>,
    // Response direction finished key
    response_finished_key: Option<Cmk>,
    // Request direction sequence number
    request_sequence_num: u64,
    // Response direction sequence number
    response_sequence_num: u64,
}

#[derive(Default)]
struct DataSecretCtx {
    // Request direction data secret
    request_data_secret: Option<Cmk>,
    // Response direction data secret
    response_data_secret: Option<Cmk>,
    // Request direction sequence number
    request_sequence_num: u64,
    // Response direction sequence number
    response_sequence_num: u64,
}

#[allow(dead_code)]
enum SpdmBinStr {
    BinStr0,
    BinStr1,
    BinStr2,
    BinStr3,
    BinStr4,
    BinStr5,
    BinStr6,
    BinStr7,
    BinStr8,
    BinStr9,
}

impl SpdmBinStr {
    fn label(&self) -> &'static str {
        match self {
            SpdmBinStr::BinStr0 => "derived",
            SpdmBinStr::BinStr1 => "req hs data",
            SpdmBinStr::BinStr2 => "rsp hs data",
            SpdmBinStr::BinStr3 => "req app data",
            SpdmBinStr::BinStr4 => "rsp app data",
            SpdmBinStr::BinStr5 => "key",
            SpdmBinStr::BinStr6 => "iv",
            SpdmBinStr::BinStr7 => "finished",
            SpdmBinStr::BinStr8 => "exp master",
            SpdmBinStr::BinStr9 => "traffic upd",
        }
    }
}

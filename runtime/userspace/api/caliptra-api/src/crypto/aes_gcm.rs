// Licensed under the Apache-2.0 license

use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::mailbox_api::execute_mailbox_cmd;
use caliptra_api::mailbox::{
    CmAesGcmDecryptFinalReq, CmAesGcmDecryptFinalResp, CmAesGcmDecryptInitReq,
    CmAesGcmDecryptInitResp, CmAesGcmDecryptUpdateReq, CmAesGcmDecryptUpdateResp,
    CmAesGcmEncryptFinalReq, CmAesGcmEncryptFinalResp, CmAesGcmEncryptInitReq,
    CmAesGcmEncryptInitResp, CmAesGcmEncryptUpdateReq, CmAesGcmEncryptUpdateResp,
    CmAesGcmSpdmDecryptInitReq, CmAesGcmSpdmDecryptInitResp, CmAesGcmSpdmEncryptInitReq,
    CmAesGcmSpdmEncryptInitResp, Cmk, MailboxReqHeader, Request,
    CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE, MAX_CMB_DATA_SIZE,
};
use core::mem::size_of;
use libsyscall_caliptra::mailbox::Mailbox;
use zerocopy::{FromBytes, IntoBytes};

pub type Aes256GcmIv = [u32; 3];
pub type Aes256GcmTag = [u32; 4];

pub struct AesGcm {
    context: Option<[u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE]>,
    encrypt: bool,
}

impl Default for AesGcm {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SpdmInfo {
    pub version: u8,
    pub sequence_number: u64,
}

impl AesGcm {
    pub fn new() -> Self {
        AesGcm {
            context: None,
            encrypt: true,
        }
    }

    pub fn reset(&mut self) {
        self.context = None;
        self.encrypt = true;
    }

    /// Initialize Encrypt context for AesGcm
    ///
    /// # Arguments
    /// * `cmk` - The CMK of the key to use for encryption.
    /// * `aad` - Additional authenticated data to include in the encryption.
    ///
    /// # Returns
    /// * Aes256GcmIv on success or error
    pub async fn encrypt_init(&mut self, cmk: Cmk, aad: &[u8]) -> CaliptraApiResult<Aes256GcmIv> {
        let mailbox = Mailbox::new();

        if aad.len() > MAX_CMB_DATA_SIZE {
            Err(CaliptraApiError::AesGcmInvalidAadLength)?;
        }
        let mut req = CmAesGcmEncryptInitReq {
            hdr: MailboxReqHeader::default(),
            cmk,
            ..Default::default()
        };

        req.aad[..aad.len()].copy_from_slice(aad);
        req.aad_size = aad.len() as u32;

        let req_bytes = req.as_mut_bytes();

        let resp_bytes = &mut [0u8; size_of::<CmAesGcmEncryptInitResp>()];

        execute_mailbox_cmd(
            &mailbox,
            CmAesGcmEncryptInitReq::ID.0,
            req_bytes,
            resp_bytes,
        )
        .await?;

        let init_resp = CmAesGcmEncryptInitResp::ref_from_bytes(resp_bytes)
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        self.context = Some(init_resp.context);
        self.encrypt = true;
        let iv = Aes256GcmIv::read_from_bytes(init_resp.iv.as_bytes())
            .map_err(|_| CaliptraApiError::InvalidResponse)?;
        Ok(iv)
    }

    /// Initializes the SPDM AES-GCM encryption/decryption context.
    /// Derives the Key and IV as per SPDM 1.4 and Secured Messages using SPDM 1.1 specification.
    ///
    /// # Arguments
    /// * `spdm_version` - The SPDM version to use for key and iv derivation
    /// * `seq_number` - Sequence number to use for per-message nonce derivation
    /// * `seq_number_le` - Flag to indicate if the sequence number should be encoded as
    ///   little endian(true) or big endian(false) in memory.
    /// * `aad` - Additional authenticated data to include in the encryption/decryption.
    /// * `enc` - Flag to indicate if this is an encryption operation (true) or decryption (false).
    ///
    /// # Returns
    /// * `Ok(())` - If the initialization was successful.
    /// * `Err(CaliptraApiError)` - If there was an error during initialization.
    pub async fn spdm_crypt_init(
        &mut self,
        cmk: Cmk,
        spdm_version: u8,
        seq_number: [u8; 8],
        seq_number_le: bool,
        aad: &[u8],
        enc: bool,
    ) -> CaliptraApiResult<()> {
        let mailbox = Mailbox::new();

        if aad.len() > MAX_CMB_DATA_SIZE {
            Err(CaliptraApiError::AesGcmInvalidAadLength)?;
        }

        let spdm_flags: u32 =
            spdm_version as u32 | (if seq_number_le { 0x0 } else { 0x1 << 8 }) as u32;

        if enc {
            let mut req = CmAesGcmSpdmEncryptInitReq {
                hdr: MailboxReqHeader::default(),
                spdm_flags,
                spdm_counter: seq_number,
                cmk,
                aad_size: aad.len() as u32,
                ..Default::default()
            };
            req.aad[..aad.len()].copy_from_slice(aad);

            let resp_bytes = &mut [0u8; size_of::<CmAesGcmSpdmEncryptInitResp>()];

            execute_mailbox_cmd(
                &mailbox,
                CmAesGcmSpdmEncryptInitReq::ID.0,
                req.as_mut_bytes(),
                resp_bytes,
            )
            .await?;

            let init_resp = CmAesGcmSpdmEncryptInitResp::ref_from_bytes(resp_bytes)
                .map_err(|_| CaliptraApiError::InvalidResponse)?;

            self.context = Some(init_resp.context);
            self.encrypt = true;
        } else {
            let mut req = CmAesGcmSpdmDecryptInitReq {
                hdr: MailboxReqHeader::default(),
                spdm_flags,
                spdm_counter: seq_number,
                cmk,
                aad_size: aad.len() as u32,
                ..Default::default()
            };
            req.aad[..aad.len()].copy_from_slice(aad);

            let resp_bytes = &mut [0u8; size_of::<CmAesGcmSpdmDecryptInitResp>()];

            execute_mailbox_cmd(
                &mailbox,
                CmAesGcmSpdmDecryptInitReq::ID.0,
                req.as_mut_bytes(),
                resp_bytes,
            )
            .await?;

            let init_resp = CmAesGcmSpdmDecryptInitResp::ref_from_bytes(resp_bytes)
                .map_err(|_| CaliptraApiError::InvalidResponse)?;

            self.context = Some(init_resp.context);
            self.encrypt = false;
        }

        Ok(())
    }

    /// Encrypts the given plaintext using AES-256-GCM in an update operation.
    /// The context must be initialized with `encrypt_init` before calling this method.
    ///
    /// # Arguments
    /// * `plaintext` - The plaintext data to encrypt.
    /// * `ciphertext` - The buffer to store the resulting ciphertext. Must be the same length as `plaintext`.
    ///
    /// # Returns
    /// * `Ok(usize)` - The size of the encrypted data.
    /// * `Err(CaliptraApiError)` - on failure.
    pub async fn encrypt_update(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> CaliptraApiResult<usize> {
        if plaintext.len() > MAX_CMB_DATA_SIZE || plaintext.len() > ciphertext.len() {
            Err(CaliptraApiError::AesGcmInvalidDataLength)?;
        }

        if !self.encrypt {
            Err(CaliptraApiError::AesGcmInvalidOperation)?;
        }
        let context = match self.context {
            Some(ctx) => ctx,
            None => Err(CaliptraApiError::AesGcmInvalidContext)?,
        };

        let mailbox = Mailbox::new();

        let mut req = CmAesGcmEncryptUpdateReq {
            hdr: MailboxReqHeader::default(),
            context,
            plaintext: [0; MAX_CMB_DATA_SIZE],
            plaintext_size: plaintext.len() as u32,
        };

        req.plaintext[..plaintext.len()].copy_from_slice(plaintext);

        let resp_bytes = &mut [0u8; size_of::<CmAesGcmEncryptUpdateResp>()];

        execute_mailbox_cmd(
            &mailbox,
            CmAesGcmEncryptUpdateReq::ID.0,
            req.as_mut_bytes(),
            resp_bytes,
        )
        .await?;

        let update_resp = CmAesGcmEncryptUpdateResp::ref_from_bytes(resp_bytes)
            .map_err(|_| CaliptraApiError::InvalidResponse)?;
        let update_hdr = &update_resp.hdr;

        let encryptdata_size = update_hdr.ciphertext_size as usize;

        self.context = Some(update_hdr.context);
        if encryptdata_size > ciphertext.len() {
            Err(CaliptraApiError::InvalidResponse)?;
        }

        ciphertext[..encryptdata_size].copy_from_slice(&update_resp.ciphertext[..encryptdata_size]);

        Ok(encryptdata_size)
    }

    /// Completes the encryption process and generates the authentication tag.
    /// The context must be initialized with `encrypt_init` before calling this method.
    ///
    /// # Arguments
    /// * `plaintext` - Optional final plaintext data to encrypt.
    /// * `ciphertext` - Optional buffer to store the final ciphertext.
    ///
    /// # Returns
    /// * `Ok(Aes256GcmTag)` - The 16-byte authentication tag for the entire encrypted message.
    /// * `Err(CaliptraApiError)` - on failure.
    ///
    /// # Note
    /// This method resets the context after completion.
    pub async fn encrypt_final(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> CaliptraApiResult<(usize, Aes256GcmTag)> {
        let mailbox = Mailbox::new();
        if !self.encrypt {
            Err(CaliptraApiError::AesGcmInvalidOperation)?;
        }

        let context = self.context.ok_or(CaliptraApiError::AesGcmInvalidContext)?;

        let mut req = CmAesGcmEncryptFinalReq {
            hdr: MailboxReqHeader::default(),
            context,
            plaintext_size: 0,
            ..Default::default()
        };

        if plaintext.len() > MAX_CMB_DATA_SIZE {
            Err(CaliptraApiError::AesGcmInvalidDataLength)?;
        }
        req.plaintext[..plaintext.len()].copy_from_slice(plaintext);
        req.plaintext_size = plaintext.len() as u32;

        let resp_bytes = &mut [0u8; size_of::<CmAesGcmEncryptFinalResp>()];

        execute_mailbox_cmd(
            &mailbox,
            CmAesGcmEncryptFinalReq::ID.0,
            req.as_mut_bytes(),
            resp_bytes,
        )
        .await?;

        let final_resp = CmAesGcmEncryptFinalResp::ref_from_bytes(resp_bytes)
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        let final_hdr = &final_resp.hdr;
        let encryptdata_size = final_hdr.ciphertext_size as usize;
        if encryptdata_size > ciphertext.len() {
            Err(CaliptraApiError::InvalidResponse)?;
        }
        ciphertext[..encryptdata_size].copy_from_slice(&final_resp.ciphertext[..encryptdata_size]);

        self.reset();

        let tag = Aes256GcmTag::read_from_bytes(final_hdr.tag.as_bytes())
            .map_err(|_| CaliptraApiError::AesGcmInvalidDataLength)?;
        Ok((encryptdata_size, tag))
    }

    /// Initializes the AES-GCM decryption context.
    ///
    /// # Arguments
    /// * `cmk` - The CMK of the key to use for decryption.
    /// * `aad` - Additional authenticated data to include in the decryption.
    /// * `iv` - Aes256GcmIv to use for decryption
    ///
    /// # Returns
    /// * Aes256GcmIv on success or error
    pub async fn decrypt_init(
        &mut self,
        cmk: Cmk,
        iv: Aes256GcmIv,
        aad: &[u8],
    ) -> CaliptraApiResult<Aes256GcmIv> {
        let mailbox = Mailbox::new();

        if aad.len() > MAX_CMB_DATA_SIZE {
            Err(CaliptraApiError::AesGcmInvalidAadLength)?;
        }

        let iv = <[u32; 3]>::read_from_bytes(iv.as_bytes())
            .map_err(|_| CaliptraApiError::AesGcmInvalidAadLength)?;
        let mut req = CmAesGcmDecryptInitReq {
            hdr: MailboxReqHeader::default(),
            cmk,
            iv,
            ..Default::default()
        };

        req.aad[..aad.len()].copy_from_slice(aad);
        req.aad_size = aad.len() as u32;

        let req_bytes = req.as_mut_bytes();

        let resp_bytes = &mut [0u8; size_of::<CmAesGcmDecryptInitResp>()];

        execute_mailbox_cmd(
            &mailbox,
            CmAesGcmDecryptInitReq::ID.0,
            req_bytes,
            resp_bytes,
        )
        .await?;

        let init_resp = CmAesGcmDecryptInitResp::ref_from_bytes(resp_bytes)
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        self.context = Some(init_resp.context);
        self.encrypt = false;
        let iv = Aes256GcmIv::read_from_bytes(init_resp.iv.as_bytes())
            .map_err(|_| CaliptraApiError::InvalidResponse)?;
        Ok(iv)
    }

    /// Decrypts the given ciphertext using AES-256-GCM in an update operation.
    /// The context must be initialized with `init` (enc=false) before calling this method.
    ///
    /// # Arguments
    /// * `ciphertext` - The ciphertext data to decrypt.
    /// * `plaintext` - The buffer to store the resulting plaintext. Must be the same length as `ciphertext`.
    ///
    /// # Returns
    /// * `Ok(())` - If the decryption was successful and `plaintext` is filled with the decrypted data.
    /// * `Err(CaliptraApiError)` - on failure.
    pub async fn decrypt_update(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> CaliptraApiResult<usize> {
        if ciphertext.len() > MAX_CMB_DATA_SIZE || plaintext.len() < ciphertext.len() {
            Err(CaliptraApiError::AesGcmInvalidDataLength)?;
        }

        if self.encrypt {
            Err(CaliptraApiError::AesGcmInvalidOperation)?;
        }

        let context = self.context.ok_or(CaliptraApiError::AesGcmInvalidContext)?;

        let mailbox = Mailbox::new();

        let mut req = CmAesGcmDecryptUpdateReq {
            hdr: MailboxReqHeader::default(),
            context,
            ciphertext: [0; MAX_CMB_DATA_SIZE],
            ciphertext_size: ciphertext.len() as u32,
        };

        req.ciphertext[..ciphertext.len()].copy_from_slice(ciphertext);

        let resp_bytes = &mut [0u8; size_of::<CmAesGcmDecryptUpdateResp>()];

        execute_mailbox_cmd(
            &mailbox,
            CmAesGcmDecryptUpdateReq::ID.0,
            req.as_mut_bytes(),
            resp_bytes,
        )
        .await?;

        let update_resp = CmAesGcmDecryptUpdateResp::ref_from_bytes(resp_bytes)
            .map_err(|_| CaliptraApiError::InvalidResponse)?;
        let update_hdr = &update_resp.hdr;

        self.context = Some(update_hdr.context);
        let decrypted_size = update_hdr.plaintext_size as usize;
        if decrypted_size > plaintext.len() {
            return Err(CaliptraApiError::InvalidResponse);
        }

        plaintext[..decrypted_size].copy_from_slice(&update_resp.plaintext[..decrypted_size]);

        Ok(decrypted_size)
    }

    /// Completes the decryption process.
    /// The context must be initialized with `init` (enc=false) before calling this method.
    ///
    /// # Returns
    /// * `Ok(())` - If the decryption was completed successfully and tag verification passed.
    /// * `Err(CaliptraApiError)` - on failure or tag verification failure.
    ///
    /// # Note
    /// This method resets the context after completion. Tag verification is handled
    /// internally by the hardware during the decrypt operations.
    pub async fn decrypt_final(
        &mut self,
        tag: Aes256GcmTag,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> CaliptraApiResult<usize> {
        let mailbox = Mailbox::new();
        if self.encrypt {
            return Err(CaliptraApiError::AesGcmInvalidOperation);
        }

        let context = self.context.ok_or(CaliptraApiError::AesGcmInvalidContext)?;

        let mut req = CmAesGcmDecryptFinalReq {
            hdr: MailboxReqHeader::default(),
            context,
            tag_len: size_of::<Aes256GcmTag>() as u32,
            tag,
            ciphertext_size: 0,
            ciphertext: [0; MAX_CMB_DATA_SIZE],
        };

        req.ciphertext[..ciphertext.len()].copy_from_slice(ciphertext);
        req.ciphertext_size = ciphertext.len() as u32;

        let resp_bytes = &mut [0u8; size_of::<CmAesGcmDecryptFinalResp>()];

        execute_mailbox_cmd(
            &mailbox,
            CmAesGcmDecryptFinalReq::ID.0,
            req.as_mut_bytes(),
            resp_bytes,
        )
        .await?;

        let final_resp = CmAesGcmDecryptFinalResp::ref_from_bytes(resp_bytes)
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        let final_hdr = &final_resp.hdr;
        let decrypted_size = final_hdr.plaintext_size as usize;
        if decrypted_size > plaintext.len() {
            Err(CaliptraApiError::InvalidResponse)?;
        }
        plaintext[..decrypted_size].copy_from_slice(&final_resp.plaintext[..decrypted_size]);

        if final_hdr.tag_verified == 0 {
            Err(CaliptraApiError::AesGcmTagVerifyFailed)?
        }

        self.reset();
        Ok(decrypted_size)
    }

    /// Convenience method to encrypt data in one shot
    ///
    /// # Arguments
    /// * `cmk` - The CMK of the key to use for encryption
    /// * `aad` - Additional authenticated data
    /// * `plaintext` - The plaintext data to encrypt
    /// * `ciphertext` - Buffer to store the encrypted ciphertext
    ///
    /// # Returns
    /// * `Ok((usize, Aes256GcmIv, Aes256GcmTag))` - Total bytes encrypted, IV, and authentication tag
    /// * `Err(CaliptraApiError)` - on failure
    pub async fn encrypt(
        &mut self,
        cmk: Cmk,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> CaliptraApiResult<(usize, Aes256GcmIv, Aes256GcmTag)> {
        if plaintext.len() > ciphertext.len() {
            return Err(CaliptraApiError::AesGcmInvalidDataLength);
        }

        let iv = self.encrypt_init(cmk, aad).await?;
        let chunk_size = MAX_CMB_DATA_SIZE;
        let mut total_encrypted = 0;

        // Process full chunks with encrypt_update
        let full_chunks = plaintext.len() / chunk_size;
        for i in 0..full_chunks {
            let start = i * chunk_size;
            let end = start + chunk_size;
            let chunk = &plaintext[start..end];
            let cipher_chunk = &mut ciphertext[total_encrypted..];

            let encrypted_size = self.encrypt_update(chunk, cipher_chunk).await?;
            total_encrypted += encrypted_size;
        }

        // Process the last chunk (or all data if less than chunk_size) with encrypt_final
        let remaining_start = full_chunks * chunk_size;
        let tag = if remaining_start < plaintext.len() {
            let last_chunk = &plaintext[remaining_start..];
            let final_cipher_chunk = &mut ciphertext[total_encrypted..];

            let (final_size, tag) = self.encrypt_final(last_chunk, final_cipher_chunk).await?;
            total_encrypted += final_size;
            tag
        } else {
            // No remaining data, call final with empty chunks
            let (_final_size, tag) = self.encrypt_final(&[], &mut []).await?;
            tag
        };

        Ok((total_encrypted, iv, tag))
    }

    /// Convenience method to decrypt data in one shot
    ///
    /// # Arguments
    /// * `cmk` - The CMK of the key to use for decryption
    /// * `iv` - The initialization vector for decryption
    /// * `aad` - Additional authenticated data
    /// * `ciphertext` - The ciphertext data to decrypt
    /// * `tag` - The authentication tag to verify
    /// * `plaintext` - Buffer to store the decrypted plaintext
    ///
    /// # Returns
    /// * `Ok(usize)` - Total number of bytes decrypted
    /// * `Err(CaliptraApiError)` - on failure or tag verification failure.
    ///
    /// # Note
    /// This method resets the context after completion. Tag verification is handled
    /// internally by the hardware during the decrypt operations.
    pub async fn decrypt(
        &mut self,
        cmk: Cmk,
        iv: Aes256GcmIv,
        aad: &[u8],
        ciphertext: &[u8],
        tag: Aes256GcmTag,
        plaintext: &mut [u8],
    ) -> CaliptraApiResult<usize> {
        if ciphertext.len() > plaintext.len() {
            return Err(CaliptraApiError::AesGcmInvalidDataLength);
        }

        let _iv = self.decrypt_init(cmk, iv, aad).await?;
        let chunk_size = MAX_CMB_DATA_SIZE;
        let mut total_decrypted = 0;

        // Process full chunks with decrypt_update
        let full_chunks = ciphertext.len() / chunk_size;
        for i in 0..full_chunks {
            let start = i * chunk_size;
            let end = start + chunk_size;
            let chunk = &ciphertext[start..end];
            let plain_chunk = &mut plaintext[total_decrypted..];

            let decrypted_size = self.decrypt_update(chunk, plain_chunk).await?;
            total_decrypted += decrypted_size;
        }

        // Process the last chunk (or all data if less than chunk_size) with decrypt_final
        let remaining_start = full_chunks * chunk_size;
        if remaining_start < ciphertext.len() {
            let last_chunk = &ciphertext[remaining_start..];
            let final_plain_chunk = &mut plaintext[total_decrypted..];

            let final_size = self
                .decrypt_final(tag, last_chunk, final_plain_chunk)
                .await?;
            total_decrypted += final_size;
        } else {
            // No remaining data, call final with empty chunks
            let final_size = self.decrypt_final(tag, &[], &mut []).await?;
            total_decrypted += final_size;
        }

        Ok(total_decrypted)
    }

    /// SPDM-specific convenience method to encrypt messages in one shot
    /// Uses SPDM key and IV derivation instead of user-provided key
    ///
    /// # Arguments
    /// * `spdm_version` - The SPDM version to use for key and iv derivation
    /// * `seq_number` - Sequence number to use for per-message nonce derivation
    /// * `seq_number_le` - Flag to indicate if the sequence number should be encoded as
    ///   little endian(true) or big endian(false) in memory.
    /// * `aad` - Additional authenticated data
    /// * `plaintext` - The plaintext data to encrypt
    /// * `ciphertext` - Buffer to store the encrypted ciphertext
    ///
    /// # Returns
    /// * `Ok((usize, Aes256GcmTag))` - Total bytes encrypted and authentication tag
    /// * `Err(CaliptraApiError)` - on failure
    #[allow(clippy::too_many_arguments)]
    pub async fn spdm_message_encrypt(
        &mut self,
        cmk: Cmk,
        spdm_version: u8,
        seq_number: [u8; 8],
        seq_number_le: bool,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> CaliptraApiResult<(usize, Aes256GcmTag)> {
        if plaintext.len() > ciphertext.len() {
            return Err(CaliptraApiError::AesGcmInvalidDataLength);
        }

        // Initialize SPDM encryption context
        self.spdm_crypt_init(cmk, spdm_version, seq_number, seq_number_le, aad, true)
            .await?;

        let chunk_size = MAX_CMB_DATA_SIZE;
        let mut total_encrypted = 0;

        // Process full chunks with encrypt_update
        let full_chunks = plaintext.len() / chunk_size;
        for i in 0..full_chunks {
            let start = i * chunk_size;
            let end = start + chunk_size;
            let chunk = &plaintext[start..end];
            let cipher_chunk = &mut ciphertext[total_encrypted..];

            let encrypted_size = self.encrypt_update(chunk, cipher_chunk).await?;
            total_encrypted += encrypted_size;
        }

        // Process the last chunk (or all data if less than chunk_size) with encrypt_final
        let remaining_start = full_chunks * chunk_size;
        let tag = if remaining_start < plaintext.len() {
            let last_chunk = &plaintext[remaining_start..];
            let final_cipher_chunk = &mut ciphertext[total_encrypted..];

            let (final_size, tag) = self.encrypt_final(last_chunk, final_cipher_chunk).await?;
            total_encrypted += final_size;
            tag
        } else {
            // No remaining data, call final with empty chunks
            let (_final_size, tag) = self.encrypt_final(&[], &mut []).await?;
            tag
        };

        Ok((total_encrypted, tag))
    }

    /// SPDM-specific convenience method to decrypt messages in one shot
    /// Uses SPDM key and IV derivation instead of user-provided key and IV
    ///
    /// # Arguments
    /// * `spdm_version` - The SPDM version to use for key and iv derivation
    /// * `seq_number` - Sequence number to use for per-message nonce derivation
    /// * `seq_number_le` - Flag to indicate if the sequence number should be encoded as
    ///   little endian(true) or big endian(false) in memory.
    /// * `aad` - Additional authenticated data
    /// * `ciphertext` - The ciphertext data to decrypt
    /// * `tag` - The authentication tag to verify
    /// * `plaintext` - Buffer to store the decrypted plaintext
    ///
    /// # Returns
    /// * `Ok(usize)` - Total number of bytes decrypted
    /// * `Err(CaliptraApiError)` - on failure or tag verification failure.
    ///
    /// # Note
    /// This method resets the context after completion. Tag verification is handled
    /// internally by the hardware during the decrypt operations.
    #[allow(clippy::too_many_arguments)]
    pub async fn spdm_message_decrypt(
        &mut self,
        cmk: Cmk,
        spdm_version: u8,
        seq_number: [u8; 8],
        seq_number_le: bool,
        aad: &[u8],
        ciphertext: &[u8],
        tag: Aes256GcmTag,
        plaintext: &mut [u8],
    ) -> CaliptraApiResult<usize> {
        if ciphertext.len() > plaintext.len() {
            return Err(CaliptraApiError::AesGcmInvalidDataLength);
        }

        // Initialize SPDM decryption context
        self.spdm_crypt_init(cmk, spdm_version, seq_number, seq_number_le, aad, false)
            .await?;

        let chunk_size = MAX_CMB_DATA_SIZE;
        let mut total_decrypted = 0;

        // Process full chunks with decrypt_update
        let full_chunks = ciphertext.len() / chunk_size;
        for i in 0..full_chunks {
            let start = i * chunk_size;
            let end = start + chunk_size;
            let chunk = &ciphertext[start..end];
            let plain_chunk = &mut plaintext[total_decrypted..];

            let decrypted_size = self.decrypt_update(chunk, plain_chunk).await?;
            total_decrypted += decrypted_size;
        }

        // Process the last chunk (or all data if less than chunk_size) with decrypt_final
        let remaining_start = full_chunks * chunk_size;
        if remaining_start < ciphertext.len() {
            let last_chunk = &ciphertext[remaining_start..];
            let final_plain_chunk = &mut plaintext[total_decrypted..];

            let final_size = self
                .decrypt_final(tag, last_chunk, final_plain_chunk)
                .await?;
            total_decrypted += final_size;
        } else {
            // No remaining data, call final with empty chunks
            let final_size = self.decrypt_final(tag, &[], &mut []).await?;
            total_decrypted += final_size;
        }

        Ok(total_decrypted)
    }
}

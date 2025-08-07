// Licensed under the Apache-2.0 license

use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::mailbox_api::execute_mailbox_cmd;
use caliptra_api::mailbox::{
    CmAesGcmDecryptFinalReq, CmAesGcmDecryptFinalResp, CmAesGcmDecryptInitReq,
    CmAesGcmDecryptInitResp, CmAesGcmDecryptUpdateReq, CmAesGcmDecryptUpdateResp,
    CmAesGcmEncryptFinalReq, CmAesGcmEncryptFinalResp, CmAesGcmEncryptInitReq,
    CmAesGcmEncryptInitResp, CmAesGcmEncryptUpdateReq, CmAesGcmEncryptUpdateResp, Cmk,
    MailboxReqHeader, Request, CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE, MAX_CMB_DATA_SIZE,
};
use libsyscall_caliptra::mailbox::Mailbox;
use zerocopy::{FromBytes, IntoBytes};

pub type Aes256GcmIv = [u8; 12];
pub type Aes256GcmTag = [u8; 16];

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
        Ok(init_resp.iv)
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
        _spdm_version: u8,
        _seq_number: [u8; 8],
        _seq_number_le: bool,
        _aad: &[u8],
        _enc: bool,
    ) -> CaliptraApiResult<()> {
        todo!("Implement SPDM AES-GCM encryption initialization");
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
        plaintext: Option<&[u8]>,
        ciphertext: Option<&mut [u8]>,
    ) -> CaliptraApiResult<(usize, Aes256GcmTag)> {
        let mailbox = Mailbox::new();
        if !self.encrypt {
            Err(CaliptraApiError::AesGcmInvalidOperation)?;
        }

        let context = self.context.ok_or(CaliptraApiError::AesGcmInvalidContext)?;

        if plaintext.is_none() && ciphertext.is_some()
            || plaintext.is_some() && ciphertext.is_none()
        {
            return Err(CaliptraApiError::InvalidArgument("invalid data buffers"));
        }

        let mut req = CmAesGcmEncryptFinalReq {
            hdr: MailboxReqHeader::default(),
            context,
            plaintext_size: 0,
            ..Default::default()
        };

        if let Some(plaintext) = plaintext {
            if plaintext.len() > MAX_CMB_DATA_SIZE {
                Err(CaliptraApiError::AesGcmInvalidDataLength)?;
            }
            req.plaintext[..plaintext.len()].copy_from_slice(plaintext);
            req.plaintext_size = plaintext.len() as u32;
        }

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
        let mut encryptdata_size = 0;
        if let Some(ciphertext) = ciphertext {
            encryptdata_size = final_hdr.ciphertext_size as usize;
            if encryptdata_size > ciphertext.len() {
                Err(CaliptraApiError::InvalidResponse)?;
            }
            ciphertext[..encryptdata_size]
                .copy_from_slice(&final_resp.ciphertext[..encryptdata_size]);
        }

        self.reset();

        Ok((encryptdata_size, final_hdr.tag))
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
        Ok(init_resp.iv)
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
        ciphertext: Option<&[u8]>,
        plaintext: Option<&mut [u8]>,
    ) -> CaliptraApiResult<usize> {
        let mailbox = Mailbox::new();
        if self.encrypt {
            return Err(CaliptraApiError::AesGcmInvalidOperation);
        }

        let context = self.context.ok_or(CaliptraApiError::AesGcmInvalidContext)?;

        if ciphertext.is_none() && plaintext.is_some()
            || ciphertext.is_some() && plaintext.is_none()
        {
            return Err(CaliptraApiError::InvalidArgument("invalid data buffers"));
        }

        let mut req = CmAesGcmDecryptFinalReq {
            hdr: MailboxReqHeader::default(),
            context,
            tag_len: tag.len() as u32,
            tag,
            ciphertext_size: 0,
            ciphertext: [0; MAX_CMB_DATA_SIZE],
        };

        if let Some(ciphertext) = ciphertext {
            req.ciphertext[..ciphertext.len()].copy_from_slice(ciphertext);
            req.ciphertext_size = ciphertext.len() as u32;
        }

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
        let mut decrypted_size = 0;
        if let Some(plaintext) = plaintext {
            decrypted_size = final_hdr.plaintext_size as usize;
            if decrypted_size > plaintext.len() {
                Err(CaliptraApiError::InvalidResponse)?;
            }
            plaintext[..decrypted_size].copy_from_slice(&final_resp.plaintext[..decrypted_size]);
        }

        if final_hdr.tag_verified != 1 {
            Err(CaliptraApiError::AesGcmTagVerifyFailed)?
        }

        self.reset();
        Ok(decrypted_size)
    }
}

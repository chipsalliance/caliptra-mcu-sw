// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CmHashAlgorithm, CmShaFinalReq, CmShaFinalResp, CmShaInitReq, CmShaInitResp, CmShaUpdateReq,
    MailboxReqHeader, Request, CMB_SHA_CONTEXT_SIZE, MAX_CMB_DATA_SIZE,
};
use core::mem::size_of;
use libsyscall_caliptra::mailbox::Mailbox;
use zerocopy::{FromBytes, IntoBytes};

use crate::crypto::error::{CryptoError, CryptoResult};

pub const MAX_HASH_SIZE: usize = 64; // SHA512

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashAlgoType {
    SHA384,
    SHA512,
}

impl From<HashAlgoType> for u32 {
    fn from(algo: HashAlgoType) -> Self {
        match algo {
            HashAlgoType::SHA384 => CmHashAlgorithm::Sha384 as u32,
            HashAlgoType::SHA512 => CmHashAlgorithm::Sha512 as u32,
        }
    }
}

impl HashAlgoType {
    pub fn hash_size(&self) -> usize {
        match self {
            HashAlgoType::SHA384 => 48,
            HashAlgoType::SHA512 => 64,
        }
    }
}

pub struct HashContext {
    algo: Option<HashAlgoType>,
    ctx: Option<[u8; CMB_SHA_CONTEXT_SIZE]>,
    mbox: Mailbox,
}

impl Default for HashContext {
    fn default() -> Self {
        HashContext::new()
    }
}

impl HashContext {
    pub fn new() -> Self {
        HashContext {
            algo: None,
            ctx: None,
            mbox: Mailbox::new(),
        }
    }

    pub async fn hash_all(
        hash_algo: HashAlgoType,
        data: &[u8],
        hash: &mut [u8],
    ) -> CryptoResult<()> {
        let mut ctx = HashContext::new();
        if hash.len() < hash_algo.hash_size() {
            Err(CryptoError::InvalidArgument("Hash buffer too small"))?;
        }
        ctx.init(hash_algo, Some(data)).await?;
        ctx.finalize(hash).await
    }

    pub fn hash_algo(&self) -> Option<HashAlgoType> {
        self.algo
    }

    pub async fn init(&mut self, hash_algo: HashAlgoType, data: Option<&[u8]>) -> CryptoResult<()> {
        self.algo = Some(hash_algo);

        let mut init_req = CmShaInitReq {
            hdr: MailboxReqHeader::default(),
            hash_algorithm: hash_algo.into(),
            input_size: 0,
            ..Default::default()
        };

        let mut data_size = 0;

        if let Some(data) = data {
            data_size = data.len().min(MAX_CMB_DATA_SIZE);
            init_req.input_size = data_size as u32;
            init_req.input[..data_size].copy_from_slice(&data[..data_size]);
        }

        let req_bytes = init_req.as_mut_bytes();
        self.mbox
            .populate_checksum(CmShaInitReq::ID.0, req_bytes)
            .map_err(CryptoError::SyscallError)?;

        let init_rsp_bytes = &mut [0u8; size_of::<CmShaInitResp>()];

        self.mbox
            .execute(CmShaInitReq::ID.0, init_req.as_bytes(), init_rsp_bytes)
            .await
            .map_err(CryptoError::MailboxError)?;

        let init_rsp = CmShaInitResp::ref_from_bytes(init_rsp_bytes)
            .map_err(|_| CryptoError::InvalidResponse)?;

        self.ctx = Some(init_rsp.context);

        if let Some(data) = data {
            if data_size < data.len() {
                self.update(&data[data_size..]).await?;
            }
        }

        Ok(())
    }

    pub async fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        let mut data_offset = 0;

        while data_offset < data.len() {
            let ctx = self
                .ctx
                .ok_or(CryptoError::InvalidOperation("Context not initialized"))?;

            let mut update_req = CmShaUpdateReq {
                hdr: MailboxReqHeader::default(),
                context: ctx,
                ..Default::default()
            };

            let remaining_data = &data[data_offset..];
            let data_size = remaining_data.len().min(MAX_CMB_DATA_SIZE);
            update_req.input_size = data_size as u32;
            update_req.input[..data_size].copy_from_slice(&remaining_data[..data_size]);

            let req_bytes = update_req.as_mut_bytes();
            self.mbox
                .populate_checksum(CmShaUpdateReq::ID.0, req_bytes)
                .map_err(CryptoError::SyscallError)?;

            let update_rsp_bytes = &mut [0u8; size_of::<CmShaInitResp>()];

            self.mbox
                .execute(
                    CmShaUpdateReq::ID.0,
                    update_req.as_bytes(),
                    update_rsp_bytes,
                )
                .await
                .map_err(CryptoError::MailboxError)?;

            let update_rsp = CmShaInitResp::ref_from_bytes(update_rsp_bytes)
                .map_err(|_| CryptoError::InvalidResponse)?;
            self.ctx = Some(update_rsp.context);

            data_offset += data_size;
        }

        Ok(())
    }

    pub async fn finalize(&mut self, hash: &mut [u8]) -> CryptoResult<()> {
        let ctx = self
            .ctx
            .ok_or(CryptoError::InvalidOperation("Context not initialized"))?;

        let hash_size = self
            .algo
            .as_ref()
            .ok_or(CryptoError::InvalidOperation(
                "Hash algorithm not initialized",
            ))?
            .hash_size();

        if hash.len() < hash_size {
            return Err(CryptoError::InvalidArgument("Hash buffer too small"));
        }

        let mut final_req = CmShaFinalReq {
            hdr: MailboxReqHeader::default(),
            context: ctx,
            ..Default::default()
        };

        let req_bytes = final_req.as_mut_bytes();
        self.mbox
            .populate_checksum(CmShaFinalReq::ID.0, req_bytes)
            .map_err(CryptoError::SyscallError)?;

        let final_rsp_bytes = &mut [0u8; size_of::<CmShaFinalResp>()];

        self.mbox
            .execute(CmShaFinalReq::ID.0, final_req.as_bytes(), final_rsp_bytes)
            .await
            .map_err(CryptoError::MailboxError)?;

        let final_rsp = CmShaFinalResp::ref_from_bytes(final_rsp_bytes)
            .map_err(|_| CryptoError::InvalidResponse)?;

        hash[..hash_size].copy_from_slice(&final_rsp.hash[..hash_size]);

        Ok(())
    }
}

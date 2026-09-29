// Licensed under the Apache-2.0 license

use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::mailbox_api::execute_mailbox_cmd;
use crate::ocp_lock::{EndorsementAlgorithm, OcpLockSigner};
use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_api::mailbox::{
    CommandId, MailboxReqHeader, MldsaSignType, SignWithExportedEcdsaReq,
    SignWithExportedEcdsaResp, SignWithExportedMldsaReq, SignWithExportedMldsaResp,
};
use caliptra_mcu_libsyscall_caliptra::dpe_handle_store::{
    DpeHandleStore, DPE_HANDLE_STORE_DRIVER_NUM, EXPORTED_CDI_SIZE,
};
use caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use core::mem::size_of;
use dpe::commands::Command;
use mcu_caliptra_api::ApiAlloc;
use zerocopy::FromBytes;

#[async_trait]
pub trait DpeTransport: Send + Sync {
    async fn invoke(&self, cmd: &Command, resp_buf: &mut [u8]) -> CaliptraApiResult<usize>;
}

/// DPE-backed OCP LOCK signer using the caller task's scratch allocator for
/// mailbox request and response buffers.
pub struct CaliptraDpeSigner<'a, A: ApiAlloc> {
    mailbox: &'a Mailbox,
    algorithm: EndorsementAlgorithm,
    scratch: &'a A,
}

impl<'a, A: ApiAlloc> CaliptraDpeSigner<'a, A> {
    pub fn new(mailbox: &'a Mailbox, scratch: &'a A) -> Self {
        Self {
            mailbox,
            algorithm: EndorsementAlgorithm::EcdsaP384Sha384,
            scratch,
        }
    }

    pub fn with_algorithm(
        mailbox: &'a Mailbox,
        algorithm: EndorsementAlgorithm,
        scratch: &'a A,
    ) -> Self {
        Self {
            mailbox,
            algorithm,
            scratch,
        }
    }
}

impl<A: ApiAlloc> OcpLockSigner for CaliptraDpeSigner<'_, A> {
    fn algorithm(&self) -> EndorsementAlgorithm {
        self.algorithm
    }

    fn signature_size(&self) -> usize {
        match self.algorithm {
            EndorsementAlgorithm::EcdsaP384Sha384 => 96,
            EndorsementAlgorithm::MlDsa87 => SignWithExportedMldsaResp::SIG_SIZE,
        }
    }

    async fn sign(
        &self,
        _label: &[u8],
        data: &[u8],
        signature: &mut [u8],
    ) -> CaliptraApiResult<()> {
        let sig_size = self.signature_size();
        if signature.len() < sig_size {
            return Err(CaliptraApiError::InvalidArgBufferTooSmall);
        }

        let dpe_store = DpeHandleStore::<DefaultSyscalls>::new(DPE_HANDLE_STORE_DRIVER_NUM);
        let mut exported_cdi = [0u8; EXPORTED_CDI_SIZE];
        dpe_store
            .read_exported_cdi(&mut exported_cdi)
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        if exported_cdi == [0u8; EXPORTED_CDI_SIZE] {
            return Err(CaliptraApiError::InvalidResponse);
        }

        match self.algorithm {
            EndorsementAlgorithm::EcdsaP384Sha384 => {
                let digest: [u8; 48] = data
                    .try_into()
                    .map_err(|_| CaliptraApiError::InvalidArgDigestSize)?;

                let mut req_bytes = self
                    .scratch
                    .alloc(size_of::<SignWithExportedEcdsaReq>())
                    .map_err(|_| CaliptraApiError::BufferTooSmall)?;
                req_bytes.fill(0);
                let req = SignWithExportedEcdsaReq::mut_from_bytes(&mut req_bytes)
                    .map_err(|_| CaliptraApiError::InvalidResponse)?;
                req.hdr = MailboxReqHeader::default();
                req.exported_cdi_handle = exported_cdi;
                req.tbs = digest;

                let mut resp_bytes = self
                    .scratch
                    .alloc(size_of::<SignWithExportedEcdsaResp>())
                    .map_err(|_| CaliptraApiError::BufferTooSmall)?;
                resp_bytes.fill(0);
                execute_mailbox_cmd(
                    self.mailbox,
                    CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
                    &mut req_bytes,
                    &mut resp_bytes,
                )
                .await?;

                let (resp, _) = SignWithExportedEcdsaResp::read_from_prefix(&resp_bytes)
                    .map_err(|_| CaliptraApiError::InvalidResponse)?;

                signature[0..48].copy_from_slice(&resp.signature_r);
                signature[48..96].copy_from_slice(&resp.signature_s);

                Ok(())
            }
            EndorsementAlgorithm::MlDsa87 => {
                if data.len() > SignWithExportedMldsaReq::MAX_TBS_SIZE {
                    return Err(CaliptraApiError::InvalidArgDigestSize);
                }

                let mut req_bytes = self
                    .scratch
                    .alloc(size_of::<SignWithExportedMldsaReq>())
                    .map_err(|_| CaliptraApiError::BufferTooSmall)?;
                req_bytes.fill(0);
                let req = SignWithExportedMldsaReq::mut_from_bytes(&mut req_bytes)
                    .map_err(|_| CaliptraApiError::InvalidResponse)?;
                req.hdr = MailboxReqHeader::default();
                req.exported_cdi_handle = exported_cdi;
                req.sign_type = MldsaSignType::Raw as u32;
                req.tbs_size = data.len() as u32;
                req.tbs[..data.len()].copy_from_slice(data);

                let mut resp_bytes = self
                    .scratch
                    .alloc(size_of::<SignWithExportedMldsaResp>())
                    .map_err(|_| CaliptraApiError::BufferTooSmall)?;
                resp_bytes.fill(0);
                execute_mailbox_cmd(
                    self.mailbox,
                    CommandId::SIGN_WITH_EXPORTED_MLDSA.into(),
                    &mut req_bytes,
                    &mut resp_bytes,
                )
                .await?;

                let (resp, _) = SignWithExportedMldsaResp::read_from_prefix(&resp_bytes)
                    .map_err(|_| CaliptraApiError::InvalidResponse)?;

                signature[..SignWithExportedMldsaResp::SIG_SIZE].copy_from_slice(&resp.signature);

                Ok(())
            }
        }
    }
}

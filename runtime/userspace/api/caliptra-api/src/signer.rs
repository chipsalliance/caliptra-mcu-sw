// Licensed under the Apache-2.0 license

use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::ocp_lock::{EndorsementAlgorithm, OcpLockSigner};
use crate::ScratchAlloc;
use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_api::mailbox::{
    CommandId, MailboxReqHeader, MldsaSignType, SignWithExportedEcdsaReq,
    SignWithExportedEcdsaResp, SignWithExportedMldsaReq, SignWithExportedMldsaResp,
};
use caliptra_mcu_libsyscall_caliptra::dpe_handle_store::{
    DpeHandleStore, DPE_HANDLE_STORE_DRIVER_NUM, EXPORTED_CDI_SIZE,
};
use caliptra_mcu_libsyscall_caliptra::mailbox::{Mailbox, MailboxError};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_platform::ErrorCode;
use core::mem::size_of;
use dpe::commands::Command;
use zerocopy::FromBytes;

#[async_trait]
pub trait DpeTransport: Send + Sync {
    async fn invoke(&self, cmd: &Command, resp_buf: &mut [u8]) -> CaliptraApiResult<usize>;
}

/// DPE-backed OCP LOCK signer using the caller task's scratch allocator for
/// mailbox request and response buffers.
pub struct CaliptraDpeSigner<'a, A: ScratchAlloc> {
    mailbox: &'a Mailbox,
    algorithm: EndorsementAlgorithm,
    scratch: &'a A,
}

impl<'a, A: ScratchAlloc> CaliptraDpeSigner<'a, A> {
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

impl<A: ScratchAlloc> OcpLockSigner for CaliptraDpeSigner<'_, A> {
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

                let req_len = size_of::<SignWithExportedEcdsaReq>();
                let resp_len = size_of::<SignWithExportedEcdsaResp>();
                let mut mbox_buf = self
                    .scratch
                    .alloc(req_len.max(resp_len))
                    .map_err(|_| CaliptraApiError::BufferTooSmall)?;
                mbox_buf[..req_len].fill(0);
                let req = SignWithExportedEcdsaReq::mut_from_bytes(&mut mbox_buf[..req_len])
                    .map_err(|_| CaliptraApiError::InvalidResponse)?;
                req.hdr = MailboxReqHeader::default();
                req.exported_cdi_handle = exported_cdi;
                req.tbs = digest;

                let cmd = CommandId::SIGN_WITH_EXPORTED_ECDSA.into();
                self.mailbox
                    .populate_checksum(cmd, &mut mbox_buf[..req_len])
                    .map_err(CaliptraApiError::Syscall)?;
                self.mailbox
                    .execute_in_place(cmd, req_len, resp_len, &mut mbox_buf)
                    .await
                    .map_err(|e| match e {
                        MailboxError::ErrorCode(ErrorCode::Busy) => CaliptraApiError::MailboxBusy,
                        _ => CaliptraApiError::Mailbox(e),
                    })?;

                let (resp, _) = SignWithExportedEcdsaResp::read_from_prefix(&mbox_buf[..resp_len])
                    .map_err(|_| CaliptraApiError::InvalidResponse)?;

                signature[0..48].copy_from_slice(&resp.signature_r);
                signature[48..96].copy_from_slice(&resp.signature_s);

                Ok(())
            }
            EndorsementAlgorithm::MlDsa87 => {
                if data.len() > SignWithExportedMldsaReq::MAX_TBS_SIZE {
                    return Err(CaliptraApiError::InvalidArgDigestSize);
                }

                let req_len = size_of::<SignWithExportedMldsaReq>();
                let resp_len = size_of::<SignWithExportedMldsaResp>();
                let buf_len = req_len.max(resp_len);
                // Stage the mailbox request/response directly in `signature` when
                // the caller passes a 4-byte-aligned buffer >= 7,228 B (e.g. the
                // full response buffer before splitting), avoiding a scratch allocation.
                let use_in_place = signature.len() >= buf_len
                    && (signature.as_ptr() as usize)
                        .is_multiple_of(core::mem::align_of::<SignWithExportedMldsaReq>());
                let mut scratch_buf = if use_in_place {
                    None
                } else {
                    Some(
                        self.scratch
                            .alloc(buf_len)
                            .map_err(|_| CaliptraApiError::BufferTooSmall)?,
                    )
                };
                let mbox_buf: &mut [u8] = match scratch_buf.as_mut() {
                    Some(buf) => &mut buf[..buf_len],
                    None => &mut signature[..buf_len],
                };
                mbox_buf[..req_len].fill(0);
                let req = SignWithExportedMldsaReq::mut_from_bytes(&mut mbox_buf[..req_len])
                    .map_err(|_| CaliptraApiError::InvalidResponse)?;
                req.hdr = MailboxReqHeader::default();
                req.exported_cdi_handle = exported_cdi;
                req.sign_type = MldsaSignType::Raw as u32;
                req.tbs_size = data.len() as u32;
                req.tbs[..data.len()].copy_from_slice(data);

                let cmd = CommandId::SIGN_WITH_EXPORTED_MLDSA.into();
                self.mailbox
                    .populate_checksum(cmd, &mut mbox_buf[..req_len])
                    .map_err(CaliptraApiError::Syscall)?;
                self.mailbox
                    .execute_in_place(cmd, req_len, resp_len, mbox_buf)
                    .await
                    .map_err(|e| match e {
                        MailboxError::ErrorCode(ErrorCode::Busy) => CaliptraApiError::MailboxBusy,
                        _ => CaliptraApiError::Mailbox(e),
                    })?;

                let sig_off = core::mem::offset_of!(SignWithExportedMldsaResp, signature);
                let sig_end = sig_off + SignWithExportedMldsaResp::SIG_SIZE;
                if resp_len < sig_end {
                    return Err(CaliptraApiError::InvalidResponse);
                }
                match scratch_buf.as_ref() {
                    Some(buf) => {
                        signature[..SignWithExportedMldsaResp::SIG_SIZE]
                            .copy_from_slice(&buf[sig_off..sig_end]);
                    }
                    None => {
                        signature.copy_within(sig_off..sig_end, 0);
                    }
                }

                Ok(())
            }
        }
    }
}

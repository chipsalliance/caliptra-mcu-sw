// Licensed under the Apache-2.0 license

use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::mailbox_api::execute_mailbox_cmd;
use crate::ocp_lock::OcpLockSigner;
use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_api::mailbox::{
    CommandId, MailboxReqHeader, SignWithExportedEcdsaReq, SignWithExportedEcdsaResp,
};
use caliptra_mcu_libsyscall_caliptra::dpe_handle_store::{
    DpeHandleStore, DPE_HANDLE_STORE_DRIVER_NUM, EXPORTED_CDI_SIZE,
};
use caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use core::mem::size_of;
use dpe::commands::Command;
use zerocopy::{FromBytes, IntoBytes};

#[async_trait]
pub trait DpeTransport: Send + Sync {
    async fn invoke(&self, cmd: &Command, resp_buf: &mut [u8]) -> CaliptraApiResult<usize>;
}

pub struct CaliptraDpeSigner<'a> {
    mailbox: &'a Mailbox,
}

impl<'a> CaliptraDpeSigner<'a> {
    pub fn new(mailbox: &'a Mailbox) -> Self {
        Self { mailbox }
    }
}

#[async_trait]
impl<'a> OcpLockSigner for CaliptraDpeSigner<'a> {
    async fn sign(
        &self,
        _label: &[u8],
        data: &[u8],
        signature: &mut [u8],
    ) -> CaliptraApiResult<()> {
        if signature.len() < 96 {
            return Err(CaliptraApiError::InvalidArgBufferTooSmall);
        }

        let digest: [u8; 48] = data
            .try_into()
            .map_err(|_| CaliptraApiError::InvalidArgDigestSize)?;

        let dpe_store = DpeHandleStore::<DefaultSyscalls>::new(DPE_HANDLE_STORE_DRIVER_NUM);
        let mut exported_cdi = [0u8; EXPORTED_CDI_SIZE];
        dpe_store
            .read_exported_cdi(&mut exported_cdi)
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        if exported_cdi == [0u8; EXPORTED_CDI_SIZE] {
            return Err(CaliptraApiError::InvalidResponse);
        }

        let mut req = SignWithExportedEcdsaReq {
            hdr: MailboxReqHeader::default(),
            exported_cdi_handle: exported_cdi,
            tbs: digest,
        };

        let mut resp_bytes = [0u8; size_of::<SignWithExportedEcdsaResp>()];
        execute_mailbox_cmd(
            self.mailbox,
            CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
            req.as_mut_bytes(),
            &mut resp_bytes,
        )
        .await?;

        let (resp, _) = SignWithExportedEcdsaResp::read_from_prefix(&resp_bytes)
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        signature[0..48].copy_from_slice(&resp.signature_r);
        signature[48..96].copy_from_slice(&resp.signature_s);

        Ok(())
    }

    fn signature_size(&self) -> usize {
        96
    }
}

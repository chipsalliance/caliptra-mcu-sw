// Licensed under the Apache-2.0 license

use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::ocp_lock::OcpLockSigner;
use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_mcu_libsyscall_caliptra::dpe_handle_store::{
    DpeHandleRecord, DpeHandleStore, DPE_HANDLE_STORE_DRIVER_NUM,
};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use core::mem::size_of;
use dpe::commands::{Command, SignP384Cmd};
use dpe::response::SignP384Resp;
use zerocopy::TryFromBytes;

#[async_trait]
pub trait DpeTransport: Send + Sync {
    async fn invoke(&self, cmd: &Command, resp_buf: &mut [u8]) -> CaliptraApiResult<usize>;
}

pub struct CaliptraDpeSigner<'a> {
    transport: &'a dyn DpeTransport,
}

impl<'a> CaliptraDpeSigner<'a> {
    pub fn new(transport: &'a dyn DpeTransport) -> Self {
        Self { transport }
    }
}

#[async_trait]
impl<'a> OcpLockSigner for CaliptraDpeSigner<'a> {
    async fn sign(&self, label: &[u8], data: &[u8], signature: &mut [u8]) -> CaliptraApiResult<()> {
        if signature.len() < 96 {
            return Err(CaliptraApiError::InvalidArgBufferTooSmall);
        }

        let digest: [u8; 48] = data
            .try_into()
            .map_err(|_| CaliptraApiError::InvalidArgDigestSize)?;

        let mut label_padded = [0u8; 48];
        if label.len() > 48 {
            return Err(CaliptraApiError::InvalidArgSize);
        }
        label_padded[..label.len()].copy_from_slice(label);

        let dpe_store = DpeHandleStore::<DefaultSyscalls>::new(DPE_HANDLE_STORE_DRIVER_NUM);
        let mut target = DpeHandleRecord::default();
        let handle = if dpe_store.read_attestation_target(&mut target).is_ok() {
            dpe::context::ContextHandle(target.context_handle)
        } else {
            dpe::context::ContextHandle::default()
        };

        let dpe_cmd = SignP384Cmd {
            handle,
            label: label_padded,
            flags: dpe::commands::SignFlags::empty(),
            digest,
        };

        let command = Command::from(&dpe_cmd);

        let mut resp_buf = [0u8; size_of::<SignP384Resp>()];
        let len = self.transport.invoke(&command, &mut resp_buf).await?;

        let dpe_resp = SignP384Resp::try_ref_from_bytes(&resp_buf[..len])
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        if target.context_handle != [0u8; 16] {
            target.context_handle = dpe_resp.new_context_handle.0;
            let _ = dpe_store.write_record(target.fw_id, &target);
        }

        signature[0..48].clone_from_slice(&dpe_resp.sig_r);
        signature[48..96].clone_from_slice(&dpe_resp.sig_s);

        Ok(())
    }

    fn signature_size(&self) -> usize {
        96
    }
}

// Licensed under the Apache-2.0 license

use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::ocp_lock::OcpLockSigner;
use alloc::boxed::Box;
use async_trait::async_trait;
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

        let dpe_cmd = SignP384Cmd {
            handle: dpe::context::ContextHandle::default(),
            label: label_padded,
            flags: dpe::commands::SignFlags::empty(),
            digest,
        };

        let command = Command::from(&dpe_cmd);

        let mut resp_buf = [0u8; size_of::<SignP384Resp>()];
        let len = self.transport.invoke(&command, &mut resp_buf).await?;

        let dpe_resp = SignP384Resp::try_ref_from_bytes(&resp_buf[..len])
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        signature[0..48].clone_from_slice(&dpe_resp.sig_r);
        signature[48..96].clone_from_slice(&dpe_resp.sig_s);

        Ok(())
    }

    fn signature_size(&self) -> usize {
        96
    }
}

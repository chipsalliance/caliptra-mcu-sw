// Licensed under the Apache-2.0 license

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use core::mem::size_of;
use dpe::commands::{Command, CommandHdr, SignP384Cmd};
use dpe::response::SignP384Resp;
use dpe::DpeProfile;
use libapi_caliptra::error::{CaliptraApiError, CaliptraApiResult};
use libapi_caliptra::mailbox_api::{execute_mailbox_cmd, DpeEcResp, MAX_DPE_RESP_DATA_SIZE};
use libapi_caliptra::ocp_lock::{InvokeDpeReq, OcpLockSigner, Request};
use libsyscall_caliptra::mailbox::Mailbox;
use zerocopy::{IntoBytes, TryFromBytes};

pub struct EmulatorSigner<'a> {
    mailbox: &'a Mailbox,
}

impl<'a> EmulatorSigner<'a> {
    pub fn new(mailbox: &'a Mailbox) -> Self {
        Self { mailbox }
    }
}

#[async_trait]
impl<'a> OcpLockSigner for EmulatorSigner<'a> {
    async fn sign(&self, data: &[u8], signature: &mut [u8]) -> CaliptraApiResult<()> {
        if data.len() != 48 {
            return Err(CaliptraApiError::InvalidArgument("Invalid digest size"));
        }
        let mut digest = [0u8; 48];
        digest.copy_from_slice(data);

        const DPE_LABEL: &[u8; 23] = b"MCU FW HPKE Endorsement";
        let label = {
            let mut label = [0u8; 48];
            label[..DPE_LABEL.len()].clone_from_slice(DPE_LABEL);
            label
        };

        let dpe_cmd = SignP384Cmd {
            handle: dpe::context::ContextHandle::default(),
            label,
            flags: dpe::commands::SignFlags::empty(),
            digest,
        };

        let command = Command::from(&dpe_cmd);
        let mut mbox_req = InvokeDpeReq::default();
        let cmd_hdr = CommandHdr::new(DpeProfile::P384Sha384, command.id());

        let cmd_hdr_bytes = cmd_hdr.as_bytes();
        mbox_req.data[..cmd_hdr_bytes.len()].copy_from_slice(cmd_hdr_bytes);

        let dpe_cmd_bytes = command.as_bytes();
        mbox_req.data[cmd_hdr_bytes.len()..cmd_hdr_bytes.len() + dpe_cmd_bytes.len()]
            .copy_from_slice(dpe_cmd_bytes);
        mbox_req.data_size = (cmd_hdr_bytes.len() + dpe_cmd_bytes.len()) as u32;

        let mut mbox_resp = DpeEcResp::default();

        execute_mailbox_cmd(
            self.mailbox,
            InvokeDpeReq::ID.into(),
            mbox_req.as_mut_bytes(),
            mbox_resp.as_mut_bytes(),
        )
        .await?;

        let resp_data = &mbox_resp.data[..MAX_DPE_RESP_DATA_SIZE.min(mbox_resp.data_size as usize)];
        let dpe_resp = SignP384Resp::try_read_from_bytes(&resp_data[..size_of::<SignP384Resp>()])
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        if signature.len() < 97 {
            return Err(CaliptraApiError::InvalidArgument("Buffer too small"));
        }

        signature[0] = 0x4;
        signature[1..49].clone_from_slice(&dpe_resp.sig_r);
        signature[49..97].clone_from_slice(&dpe_resp.sig_s);

        Ok(())
    }

    fn signature_size(&self) -> usize {
        97
    }
}

// Licensed under the Apache-2.0 license

use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::mailbox_api::execute_mailbox_cmd;
use caliptra_api::mailbox::{
    CommandId, FwInfoResp, GetImageInfoReq, GetImageInfoResp, MailboxReqHeader,
};
use core::mem::size_of;
use libsyscall_caliptra::mailbox::Mailbox;
use zerocopy::{FromBytes, IntoBytes};

pub struct DeviceState;

impl DeviceState {
    pub async fn fw_info() -> CaliptraApiResult<FwInfoResp> {
        let mailbox = Mailbox::new();
        let mut req = MailboxReqHeader::default();
        let req_bytes = req.as_mut_bytes();

        let mut rsp_bytes = [0u8; size_of::<FwInfoResp>()];

        let size = execute_mailbox_cmd(
            &mailbox,
            u32::from(CommandId::FW_INFO),
            req_bytes,
            &mut rsp_bytes,
        )
        .await?;
        if size != size_of::<FwInfoResp>() {
            return Err(CaliptraApiError::InvalidResponse);
        }

        let resp = FwInfoResp::read_from_bytes(&rsp_bytes)
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        Ok(resp)
    }

    pub async fn image_info(image_id: u32) -> CaliptraApiResult<GetImageInfoResp> {
        let mailbox = Mailbox::new();
        let mut req = GetImageInfoReq {
            hdr: MailboxReqHeader::default(),
            fw_id: image_id.to_le_bytes(),
        };
        let req_bytes = req.as_mut_bytes();

        let mut resp_bytes = [0u8; size_of::<GetImageInfoResp>()];

        let size = execute_mailbox_cmd(
            &mailbox,
            u32::from(CommandId::GET_IMAGE_INFO),
            req_bytes,
            &mut resp_bytes,
        )
        .await?;

        if size != size_of::<GetImageInfoResp>() {
            return Err(CaliptraApiError::InvalidResponse);
        }

        let resp = GetImageInfoResp::read_from_bytes(&resp_bytes)
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        Ok(resp)
    }
}

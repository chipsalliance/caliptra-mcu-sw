// Licensed under the Apache-2.0 license

use crate::error::CaliptraApiResult;
use crate::mailbox_api::execute_mailbox_cmd;
use caliptra_api::mailbox::{
    CmEcdhFinishReq, CmEcdhFinishResp, CmEcdhGenerateReq, CmEcdhGenerateResp, Cmk,
    MailboxReqHeader, Request,
};
use libsyscall_caliptra::mailbox::Mailbox;
use zerocopy::IntoBytes;

// re-export
pub use caliptra_api::mailbox::{CmKeyUsage, CMB_ECDH_EXCHANGE_DATA_MAX_SIZE};

pub struct Ecdh;

impl Ecdh {
    pub async fn ecdh_generate() -> CaliptraApiResult<CmEcdhGenerateResp> {
        let mailbox = Mailbox::new();

        let mut req = CmEcdhGenerateReq {
            hdr: MailboxReqHeader::default(),
        };

        let mut rsp = CmEcdhGenerateResp::default();
        let rsp_bytes = rsp.as_mut_bytes();
        execute_mailbox_cmd(
            &mailbox,
            CmEcdhGenerateReq::ID.0,
            req.as_mut_bytes(),
            rsp_bytes,
        )
        .await?;
        Ok(rsp)
    }

    pub async fn ecdh_finish(
        key_usage: CmKeyUsage,
        generate_resp: &CmEcdhGenerateResp,
        incoming_exchange_data: &[u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
    ) -> CaliptraApiResult<Cmk> {
        let mailbox = Mailbox::new();

        let mut req = CmEcdhFinishReq {
            hdr: MailboxReqHeader::default(),
            context: generate_resp.context,
            key_usage: key_usage.into(),
            incoming_exchange_data: *incoming_exchange_data,
        };

        let mut rsp = CmEcdhFinishResp::default();
        let rsp_bytes = rsp.as_mut_bytes();
        execute_mailbox_cmd(
            &mailbox,
            CmEcdhFinishReq::ID.0,
            req.as_mut_bytes(),
            rsp_bytes,
        )
        .await?;
        Ok(rsp.output)
    }
}

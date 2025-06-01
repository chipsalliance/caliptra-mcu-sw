// Licensed under the Apache-2.0 license

use crate::crypto::rng::Rng;
use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::mailbox_api::execute_mailbox_cmd;
use caliptra_api::mailbox::{
    MailboxReqHeader, MailboxRespHeader, QuotePcrsFlags, QuotePcrsReq, QuotePcrsResp, Request,
};
use core::mem::size_of;
use libsyscall_caliptra::mailbox::Mailbox;
use zerocopy::{FromBytes, IntoBytes};

const PCR_QUOTE_RSP_START: usize = size_of::<MailboxRespHeader>();
pub const PCR_QUOTE_SIZE: usize = size_of::<QuotePcrsResp>() - PCR_QUOTE_RSP_START;

pub struct Evidence;

impl Evidence {
    pub async fn pcr_quote(buffer: &mut [u8; PCR_QUOTE_SIZE]) -> CaliptraApiResult<()> {
        let mailbox: Mailbox = Mailbox::new();

        let mut req = QuotePcrsReq {
            hdr: MailboxReqHeader::default(),
            nonce: [0; 32],
            flags: QuotePcrsFlags::ECC_SIGNATURE | QuotePcrsFlags::MLDSA_SIGNATURE,
        };
        Rng::generate_random_number(&mut req.nonce).await?;
        let req_bytes = req.as_mut_bytes();
        let response_bytes = &mut [0u8; core::mem::size_of::<QuotePcrsResp>()];

        execute_mailbox_cmd(&mailbox, QuotePcrsReq::ID.0, req_bytes, response_bytes).await?;

        let resp = QuotePcrsResp::ref_from_bytes(response_bytes)
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        if resp.nonce != req.nonce {
            Err(CaliptraApiError::InvalidResponse)?;
        }

        buffer[..PCR_QUOTE_SIZE].copy_from_slice(&response_bytes[PCR_QUOTE_RSP_START..]);
        Ok(())
    }
}

// Licensed under the Apache-2.0 license

use crate::crypto::rng::Rng;
use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::mailbox_api::execute_mailbox_cmd;
use caliptra_api::mailbox::{
    MailboxReqHeader, MailboxRespHeader, QuotePcrsEcc384Req, QuotePcrsEcc384Resp,
    QuotePcrsMldsa87Req, QuotePcrsMldsa87Resp, Request,
};
use core::mem::size_of;
use libsyscall_caliptra::mailbox::Mailbox;
use zerocopy::{FromBytes, IntoBytes};

const PCR_QUOTE_RSP_START: usize = size_of::<MailboxRespHeader>();
const ECC384_QUOTE_RSP_LEN: usize = size_of::<QuotePcrsEcc384Resp>() - PCR_QUOTE_RSP_START;
const MLDSA87_QUOTE_RSP_LEN: usize = size_of::<QuotePcrsMldsa87Resp>() - PCR_QUOTE_RSP_START;
pub const PCR_QUOTE_BUFFER_SIZE: usize = MLDSA87_QUOTE_RSP_LEN;

pub struct PcrQuote;

impl PcrQuote {
    pub async fn pcr_quote(
        nonce: Option<&[u8]>,
        buffer: &mut [u8],
        with_pqc_sig: bool,
    ) -> CaliptraApiResult<usize> {
        if with_pqc_sig {
            Self::pcr_quote_mldsa(nonce, buffer).await
        } else {
            Self::pcr_quote_ecc384(nonce, buffer).await
        }
    }

    async fn pcr_quote_mldsa(nonce: Option<&[u8]>, buffer: &mut [u8]) -> CaliptraApiResult<usize> {
        let mailbox = Mailbox::new();

        if buffer.len() < MLDSA87_QUOTE_RSP_LEN {
            return Err(CaliptraApiError::InvalidArgument("Buffer too small"));
        }

        let mut req = QuotePcrsMldsa87Req {
            hdr: MailboxReqHeader::default(),
            nonce: [0; 32],
        };

        if let Some(nonce) = nonce {
            req.nonce.copy_from_slice(nonce);
        } else {
            Rng::generate_random_number(&mut req.nonce).await?;
        }

        let mut rsp_bytes = [0u8; size_of::<QuotePcrsMldsa87Resp>()];
        let req_bytes = req.as_mut_bytes();
        let size = execute_mailbox_cmd(
            &mailbox,
            QuotePcrsMldsa87Req::ID.0,
            req_bytes,
            &mut rsp_bytes,
        )
        .await?;
        if size != size_of::<QuotePcrsMldsa87Resp>() {
            return Err(CaliptraApiError::InvalidResponse);
        }

        let resp = QuotePcrsMldsa87Resp::ref_from_bytes(&rsp_bytes)
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        if resp.nonce != req.nonce {
            Err(CaliptraApiError::InvalidResponse)?;
        }

        buffer.copy_from_slice(
            &rsp_bytes[PCR_QUOTE_RSP_START..PCR_QUOTE_RSP_START + MLDSA87_QUOTE_RSP_LEN],
        );
        Ok(MLDSA87_QUOTE_RSP_LEN)
    }

    async fn pcr_quote_ecc384(nonce: Option<&[u8]>, buffer: &mut [u8]) -> CaliptraApiResult<usize> {
        let mailbox = Mailbox::new();

        if buffer.len() < ECC384_QUOTE_RSP_LEN {
            return Err(CaliptraApiError::InvalidArgument("Buffer too small"));
        }

        let mut req = QuotePcrsEcc384Req {
            hdr: MailboxReqHeader::default(),
            nonce: [0; 32],
        };

        if let Some(nonce) = nonce {
            req.nonce.copy_from_slice(nonce);
        } else {
            Rng::generate_random_number(&mut req.nonce).await?;
        }

        let req_bytes = req.as_mut_bytes();
        let mut resp_bytes = [0u8; size_of::<QuotePcrsEcc384Resp>()];

        let size = execute_mailbox_cmd(
            &mailbox,
            QuotePcrsEcc384Req::ID.0,
            req_bytes,
            &mut resp_bytes,
        )
        .await?;
        if size != size_of::<QuotePcrsEcc384Resp>() {
            return Err(CaliptraApiError::InvalidResponse);
        }

        let resp = QuotePcrsEcc384Resp::ref_from_bytes(&resp_bytes)
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        if resp.nonce != req.nonce {
            Err(CaliptraApiError::InvalidResponse)?;
        }

        buffer[..ECC384_QUOTE_RSP_LEN].copy_from_slice(
            &resp_bytes[PCR_QUOTE_RSP_START..PCR_QUOTE_RSP_START + ECC384_QUOTE_RSP_LEN],
        );
        Ok(ECC384_QUOTE_RSP_LEN)
    }

    pub fn len(with_pqc_sig: bool) -> usize {
        match with_pqc_sig {
            true => MLDSA87_QUOTE_RSP_LEN,
            false => ECC384_QUOTE_RSP_LEN,
        }
    }
}

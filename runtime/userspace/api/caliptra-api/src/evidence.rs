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

pub const PCR_QUOTE_RSP_START: usize = size_of::<MailboxRespHeader>();
pub const PCR_QUOTE_BUFFER_SIZE: usize = size_of::<QuotePcrsMldsa87Resp>();

// const MLDSA87_SIGNATURE_BYTE_SIZE: usize = 4628;
// const MLDSA_DIGEST_BYTE_SIZE: usize = 64;
// const ECC_SIGNATURE_BYTE_SIZE: usize = 96;
// const ECC_DIGEST_BYTE_SIZE: usize = 48;
// const MLDSA87_DGST_SIG_SIZE: usize = MLDSA_DIGEST_BYTE_SIZE + MLDSA87_SIGNATURE_BYTE_SIZE;
// const ECC_DGST_SIG_SIZE: usize = ECC_DIGEST_BYTE_SIZE + ECC_SIGNATURE_BYTE_SIZE;

// const PCR_QUOTE_FIXED_FIELDS_SIZE: usize =
//     PCR_QUOTE_SIZE - MLDSA87_DGST_SIG_SIZE - ECC_DGST_SIG_SIZE;

pub struct Evidence;

impl Evidence {
    pub async fn pcr_quote(buffer: &mut [u8], with_pqc_sig: bool) -> CaliptraApiResult<usize> {
        if with_pqc_sig {
            Self::pcr_quote_mldsa(buffer).await
        } else {
            Self::pcr_quote_ecc384(buffer).await
        }
    }

    async fn pcr_quote_mldsa(buffer: &mut [u8]) -> CaliptraApiResult<usize> {
        let mailbox = Mailbox::new();

        let quote_len = size_of::<QuotePcrsMldsa87Resp>();

        if buffer.len() < quote_len {
            return Err(CaliptraApiError::InvalidArgument("Buffer too small"));
        }

        let mut req = QuotePcrsEcc384Req {
            hdr: MailboxReqHeader::default(),
            nonce: [0; 32],
        };
        Rng::generate_random_number(&mut req.nonce).await?;
        let req_bytes = req.as_mut_bytes();
        let size =
            execute_mailbox_cmd(&mailbox, QuotePcrsMldsa87Req::ID.0, req_bytes, buffer).await?;
        if size != quote_len {
            return Err(CaliptraApiError::InvalidResponse);
        }

        let resp = QuotePcrsMldsa87Resp::ref_from_bytes(&buffer[..quote_len])
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        if resp.nonce != req.nonce {
            Err(CaliptraApiError::InvalidResponse)?;
        }
        Ok(size_of::<QuotePcrsMldsa87Resp>())
    }

    async fn pcr_quote_ecc384(buffer: &mut [u8]) -> CaliptraApiResult<usize> {
        let mailbox = Mailbox::new();

        let quote_len = size_of::<QuotePcrsEcc384Resp>();

        if buffer.len() < quote_len {
            return Err(CaliptraApiError::InvalidArgument("Buffer too small"));
        }

        let mut req = QuotePcrsEcc384Req {
            hdr: MailboxReqHeader::default(),
            nonce: [0; 32],
        };
        Rng::generate_random_number(&mut req.nonce).await?;
        let req_bytes = req.as_mut_bytes();

        let size =
            execute_mailbox_cmd(&mailbox, QuotePcrsEcc384Req::ID.0, req_bytes, buffer).await?;
        if size != quote_len {
            return Err(CaliptraApiError::InvalidResponse);
        }
        let resp = QuotePcrsEcc384Resp::ref_from_bytes(&buffer[..quote_len])
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        if resp.nonce != req.nonce {
            Err(CaliptraApiError::InvalidResponse)?;
        }
        Ok(size_of::<QuotePcrsEcc384Resp>())
    }

    pub fn pcr_quote_size(with_pqc_sig: bool) -> usize {
        match with_pqc_sig {
            true => size_of::<QuotePcrsMldsa87Resp>(),
            false => size_of::<QuotePcrsEcc384Resp>(),
        }
    }
}

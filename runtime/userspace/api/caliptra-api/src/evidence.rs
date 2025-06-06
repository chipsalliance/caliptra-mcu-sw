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

const MLDSA87_SIGNATURE_BYTE_SIZE: usize = 4628;
const MLDSA_DIGEST_BYTE_SIZE: usize = 64;
const ECC_SIGNATURE_BYTE_SIZE: usize = 96;
const ECC_DIGEST_BYTE_SIZE: usize = 48;
const MLDSA87_DGST_SIG_SIZE: usize = MLDSA_DIGEST_BYTE_SIZE + MLDSA87_SIGNATURE_BYTE_SIZE;
const ECC_DGST_SIG_SIZE: usize = ECC_DIGEST_BYTE_SIZE + ECC_SIGNATURE_BYTE_SIZE;

const PCR_QUOTE_FIXED_FIELDS_SIZE: usize =
    PCR_QUOTE_SIZE - MLDSA87_DGST_SIG_SIZE - ECC_DGST_SIG_SIZE;

pub struct Evidence;

impl Evidence {
    pub async fn pcr_quote(buffer: &mut [u8], with_pqc_sig: bool) -> CaliptraApiResult<usize> {
        let mailbox = Mailbox::new();
        let flags = if with_pqc_sig {
            QuotePcrsFlags::MLDSA_SIGNATURE
        } else {
            QuotePcrsFlags::ECC_SIGNATURE
        };

        let quote_len = Evidence::pcr_quote_size(with_pqc_sig).await;

        if buffer.len() < quote_len {
            return Err(CaliptraApiError::InvalidArgument("Buffer too small"));
        }

        let mut req = QuotePcrsReq {
            hdr: MailboxReqHeader::default(),
            nonce: [0; 32],
            flags,
        };
        Rng::generate_random_number(&mut req.nonce).await?;
        let req_bytes = req.as_mut_bytes();
        let mut response_bytes = [0u8; core::mem::size_of::<QuotePcrsResp>()];

        execute_mailbox_cmd(&mailbox, QuotePcrsReq::ID.0, req_bytes, &mut response_bytes).await?;

        let resp = QuotePcrsResp::ref_from_bytes(&response_bytes)
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        if resp.nonce != req.nonce {
            Err(CaliptraApiError::InvalidResponse)?;
        }

        // Fixed fields are always present in the response
        let start = PCR_QUOTE_RSP_START;
        let end = start + PCR_QUOTE_FIXED_FIELDS_SIZE;
        buffer[..PCR_QUOTE_FIXED_FIELDS_SIZE].copy_from_slice(&response_bytes[start..end]);

        let (dgst_sig_start, dgst_sig_size) = if with_pqc_sig {
            (end + ECC_DGST_SIG_SIZE, MLDSA87_DGST_SIG_SIZE)
        } else {
            (end, ECC_DGST_SIG_SIZE)
        };

        buffer[PCR_QUOTE_FIXED_FIELDS_SIZE..PCR_QUOTE_FIXED_FIELDS_SIZE + dgst_sig_size]
            .copy_from_slice(&response_bytes[dgst_sig_start..dgst_sig_start + dgst_sig_size]);
        let data_len = PCR_QUOTE_FIXED_FIELDS_SIZE + dgst_sig_size;

        Ok(data_len)
    }

    pub async fn pcr_quote_size(with_pqc_sig: bool) -> usize {
        match with_pqc_sig {
            true => PCR_QUOTE_FIXED_FIELDS_SIZE + MLDSA87_DGST_SIG_SIZE,
            false => PCR_QUOTE_FIXED_FIELDS_SIZE + ECC_DGST_SIG_SIZE,
        }
    }
}

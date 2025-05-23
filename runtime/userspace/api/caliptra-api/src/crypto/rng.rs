// Licensed under the Apache-2.0 license

use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::mailbox_api::{
    execute_mailbox_cmd, RandomGenerateResp, RandomStirReq, MAX_RANDOM_NUM_SIZE,
    MAX_RANDOM_STIR_SIZE,
};
use caliptra_api::mailbox::{
    CmRandomGenerateReq, CmRandomStirReq, MailboxReqHeader, MailboxRespHeader,
    MailboxRespHeaderVarSize, Request,
};
use core::mem::size_of;
use libsyscall_caliptra::mailbox::Mailbox;
use zerocopy::{FromBytes, IntoBytes};

pub struct Rng;

impl Rng {
    pub async fn generate_random_number(random_number: &mut [u8]) -> CaliptraApiResult<()> {
        if random_number.len() > MAX_RANDOM_NUM_SIZE {
            return Err(CaliptraApiError::InvalidArgument("Invalid size"));
        }

        let mailbox = Mailbox::new();

        let mut rand_gen_req = CmRandomGenerateReq {
            hdr: MailboxReqHeader::default(),
            size: random_number.len() as u32,
        };

        let mut rand_gen_rsp = RandomGenerateResp::default();
        let rsp_bytes = rand_gen_rsp.as_mut_bytes();
        execute_mailbox_cmd(
            &mailbox,
            CmRandomGenerateReq::ID.0,
            rand_gen_req.as_mut_bytes(),
            rsp_bytes,
        )
        .await?;

        const VAR_HEADER_SIZE: usize = size_of::<MailboxRespHeaderVarSize>();
        let hdr = MailboxRespHeaderVarSize::read_from_bytes(&rsp_bytes[..VAR_HEADER_SIZE])
            .map_err(|_| CaliptraApiError::InvalidResponse)?;
        if hdr.data_len > random_number.len() as u32 {
            return Err(CaliptraApiError::InvalidResponse);
        }
        random_number
            .copy_from_slice(&rsp_bytes[VAR_HEADER_SIZE..VAR_HEADER_SIZE + hdr.data_len as usize]);
        Ok(())
    }

    pub async fn add_random_stir(random_stir: &[u8]) -> CaliptraApiResult<()> {
        if random_stir.len() > MAX_RANDOM_STIR_SIZE {
            return Err(CaliptraApiError::InvalidArgument("Invalid size"));
        }
        let mailbox = Mailbox::new();

        let mut rand_stir_req = RandomStirReq {
            hdr: MailboxReqHeader::default(),
            input_size: random_stir.len() as u32,
            input: [0; MAX_RANDOM_STIR_SIZE],
        };

        rand_stir_req.input[..random_stir.len()].copy_from_slice(random_stir);

        let req_bytes = rand_stir_req.as_mut_bytes();
        let mut rsp_bytes = [0u8; size_of::<MailboxRespHeader>()];
        execute_mailbox_cmd(&mailbox, CmRandomStirReq::ID.0, req_bytes, &mut rsp_bytes).await?;
        Ok(())
    }
}

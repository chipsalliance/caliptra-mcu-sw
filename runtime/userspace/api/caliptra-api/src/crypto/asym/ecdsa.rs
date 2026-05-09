// Licensed under the Apache-2.0 license

use crate::crypto::asym::{ECC_P384_PARAM_X_SIZE, ECC_P384_PARAM_Y_SIZE, ECC_P384_SIGNATURE_SIZE};
use crate::crypto::hash::SHA384_HASH_SIZE;
use crate::error::CaliptraApiResult;
use crate::mailbox_api::execute_mailbox_cmd;
use caliptra_api::mailbox::{EcdsaVerifyReq, MailboxReqHeader, MailboxRespHeader, Request};
use libsyscall_caliptra::mailbox::Mailbox;
use zerocopy::IntoBytes;

pub struct Ecdsa;

impl Ecdsa {
    pub async fn ecdsa_verify(
        pub_key_x: [u8; ECC_P384_PARAM_X_SIZE],
        pub_key_y: [u8; ECC_P384_PARAM_Y_SIZE],
        signature: &[u8; ECC_P384_SIGNATURE_SIZE],
        msg_hash: [u8; SHA384_HASH_SIZE],
    ) -> CaliptraApiResult<()> {
        let mailbox = Mailbox::new();

        let mut sig_r = [0u8; 48];
        let mut sig_s = [0u8; 48];
        sig_r.copy_from_slice(&signature[..48]);
        sig_s.copy_from_slice(&signature[48..]);

        let mut req = EcdsaVerifyReq {
            hdr: MailboxReqHeader::default(),
            pub_key_x,
            pub_key_y,
            signature_r: sig_r,
            signature_s: sig_s,
            hash: msg_hash,
        };

        let mut rsp = MailboxRespHeader::default();
        let rsp_bytes = rsp.as_mut_bytes();
        execute_mailbox_cmd(
            &mailbox,
            EcdsaVerifyReq::ID.0,
            req.as_mut_bytes(),
            rsp_bytes,
        )
        .await?;
        Ok(())
    }
}

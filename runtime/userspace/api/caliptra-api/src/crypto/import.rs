// Licensed under the Apache-2.0 license

use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::mailbox_api::execute_mailbox_cmd;
use caliptra_api::mailbox::{CmImportReq, CmImportResp, Request};
use libsyscall_caliptra::mailbox::Mailbox;
use zerocopy::IntoBytes;

// re-export
pub use caliptra_api::mailbox::{CmKeyUsage, CMB_ECDH_EXCHANGE_DATA_MAX_SIZE};

pub struct Import;

impl Import {
    pub async fn import(key_usage: CmKeyUsage, data: &[u8]) -> CaliptraApiResult<CmImportResp> {
        let mailbox = Mailbox::new();

        let mut req = CmImportReq {
            key_usage: key_usage as u32,
            input_size: data.len() as u32,
            ..Default::default()
        };
        if data.len() > req.input.len() {
            return Err(CaliptraApiError::InvalidArgument(
                "Info size exceeds maximum allowed",
            ));
        }
        req.input[..data.len()].copy_from_slice(data);

        let mut rsp = CmImportResp::default();
        let rsp_bytes = rsp.as_mut_bytes();
        execute_mailbox_cmd(&mailbox, CmImportReq::ID.0, req.as_mut_bytes(), rsp_bytes).await?;
        Ok(rsp)
    }
}

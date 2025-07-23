// Licensed under the Apache-2.0 license

use crate::crypto::import::Import;
use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::mailbox_api::execute_mailbox_cmd;
use caliptra_api::mailbox::{
    CmHashAlgorithm, CmHkdfExpandReq, CmHkdfExpandResp, CmHkdfExtractReq, CmHkdfExtractResp,
    CmHmacReq, CmHmacResp, CmKeyUsage, Cmk, Request, MAX_CMB_DATA_SIZE,
};
use libsyscall_caliptra::mailbox::Mailbox;
use zerocopy::IntoBytes;

pub struct Hmac;

pub enum HkdfSalt<'a> {
    Cmk(&'a Cmk),
    Data(&'a [u8]),
}

impl Hmac {
    pub async fn hmac(cmk: &Cmk, data: &[u8]) -> CaliptraApiResult<CmHmacResp> {
        let mailbox = Mailbox::new();

        let mut req = CmHmacReq {
            hash_algorithm: CmHashAlgorithm::Sha384 as u32,
            data_size: data.len() as u32,
            ..Default::default()
        };
        req.cmk.0.copy_from_slice(&cmk.0);
        if data.len() > req.data.len() {
            return Err(CaliptraApiError::InvalidArgument(
                "Data size exceeds maximum allowed",
            ));
        }
        req.data[..data.len()].copy_from_slice(data);

        let mut rsp = CmHmacResp::default();
        let rsp_bytes = rsp.as_mut_bytes();
        execute_mailbox_cmd(&mailbox, CmHmacReq::ID.0, req.as_mut_bytes(), rsp_bytes).await?;
        Ok(rsp)
    }

    pub async fn hkdf_extract(
        salt: HkdfSalt<'_>,
        ikm: &Cmk,
    ) -> CaliptraApiResult<CmHkdfExtractResp> {
        let mailbox = Mailbox::new();

        let mut req = CmHkdfExtractReq {
            hash_algorithm: CmHashAlgorithm::Sha384 as u32,
            ..Default::default()
        };
        req.ikm.0.copy_from_slice(&ikm.0);
        match salt {
            HkdfSalt::Cmk(cmk) => {
                req.salt.0.copy_from_slice(&cmk.0);
            }
            HkdfSalt::Data(data) => {
                if data.len() > MAX_CMB_DATA_SIZE {
                    return Err(CaliptraApiError::InvalidArgument(
                        "Salt size exceeds maximum allowed",
                    ));
                }
                let salt_cmk = Import::import(CmKeyUsage::Hmac, data).await?;
                req.salt.0.copy_from_slice(&salt_cmk.cmk.0);
            }
        }
        let mut rsp = CmHkdfExtractResp::default();
        let rsp_bytes = rsp.as_mut_bytes();
        execute_mailbox_cmd(
            &mailbox,
            CmHkdfExtractReq::ID.0,
            req.as_mut_bytes(),
            rsp_bytes,
        )
        .await?;
        Ok(rsp)
    }

    pub async fn hkdf_expand(
        prk: &Cmk,
        key_usage: CmKeyUsage,
        key_size: u32,
        info: &[u8],
    ) -> CaliptraApiResult<CmHkdfExpandResp> {
        let mailbox = Mailbox::new();

        let mut req = CmHkdfExpandReq {
            hash_algorithm: CmHashAlgorithm::Sha384 as u32,
            key_usage: key_usage as u32,
            key_size,
            info_size: info.len() as u32,
            ..Default::default()
        };
        if info.len() > req.info.len() {
            return Err(CaliptraApiError::InvalidArgument(
                "Info size exceeds maximum allowed",
            ));
        }
        req.prk.0.copy_from_slice(&prk.0);
        req.info[..info.len()].copy_from_slice(info);
        let mut rsp = CmHkdfExpandResp::default();
        let rsp_bytes = rsp.as_mut_bytes();
        execute_mailbox_cmd(
            &mailbox,
            CmHkdfExpandReq::ID.0,
            req.as_mut_bytes(),
            rsp_bytes,
        )
        .await?;
        Ok(rsp)
    }
}

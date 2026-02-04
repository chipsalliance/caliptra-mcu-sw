// Licensed under the Apache-2.0 license

use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::mailbox_api::{
    execute_mailbox_cmd, CertificateChainResp, CertifyEcKeyResp, DpeEcResp, DpeResponse,
    MAX_DPE_RESP_DATA_SIZE, MAX_ECC_CERT_SIZE,
};
use caliptra_api::mailbox::{
    CommandId, GetFmcAliasEcc384CertReq, GetIdevCsrReq, GetIdevCsrResp, GetLdevEcc384CertReq,
    GetRtAliasEcc384CertReq, InvokeDpeReq, MailboxReqHeader, MailboxRespHeader,
    PopulateIdevEcc384CertReq, Request, MAX_RESP_DATA_SIZE,
};
use dpe::commands::{
    CertifyKeyCommand, CertifyKeyFlags, CertifyKeyP384Cmd as CertifyKeyCmd, Command, CommandHdr,
    GetCertificateChainCmd, SignFlags, SignP384Cmd as SignCmd,
};
use dpe::context::ContextHandle;
use dpe::response::{SignP384Resp, SignResp};
use dpe::DpeProfile;

use libsyscall_caliptra::mailbox::Mailbox;
use zerocopy::{FromZeros, IntoBytes, TryFromBytes};

pub const IDEV_ECC_CSR_MAX_SIZE: usize = GetIdevCsrResp::DATA_MAX_SIZE;
pub const MAX_MAILBOX_GET_CERT_RESP_SIZE: usize = MAX_RESP_DATA_SIZE;
pub const MAX_CERT_CHUNK_SIZE: usize = 1024;
pub const KEY_LABEL_SIZE: usize = DpeProfile::P384Sha384.hash_size();

pub enum CertType {
    Ecc,
}

pub struct CertContext {
    mbox: Mailbox,
}

impl Default for CertContext {
    fn default() -> Self {
        CertContext::new()
    }
}

impl CertContext {
    pub fn new() -> Self {
        CertContext {
            mbox: Mailbox::new(),
        }
    }

    pub async fn get_idev_csr(
        &mut self,
        csr_der: &mut [u8; IDEV_ECC_CSR_MAX_SIZE],
    ) -> CaliptraApiResult<usize> {
        let mut req = GetIdevCsrReq::default();

        let mut resp = GetIdevCsrResp {
            hdr: MailboxRespHeader::default(),
            data: [0; GetIdevCsrResp::DATA_MAX_SIZE],
            data_size: 0,
        };

        let req_bytes = req.as_mut_bytes();
        let resp_bytes = resp.as_mut_bytes();

        execute_mailbox_cmd(&self.mbox, GetIdevCsrReq::ID.0, req_bytes, resp_bytes).await?;

        let resp = GetIdevCsrResp::try_ref_from_bytes(resp_bytes)
            .map_err(|_| CaliptraApiError::InvalidResponse)?;
        if resp.data_size == u32::MAX {
            Err(CaliptraApiError::UnprovisionedCsr)?;
        }

        if resp.data_size == 0 || resp.data_size > IDEV_ECC_CSR_MAX_SIZE as u32 {
            return Err(CaliptraApiError::InvalidResponse);
        }

        csr_der[..resp.data_size as usize].copy_from_slice(&resp.data[..resp.data_size as usize]);
        Ok(resp.data_size as usize)
    }

    pub async fn populate_idev_ecc384_cert(&mut self, cert: &[u8]) -> CaliptraApiResult<()> {
        if cert.len() > PopulateIdevEcc384CertReq::MAX_CERT_SIZE {
            return Err(CaliptraApiError::InvalidArgument("Invalid cert size"));
        }
        let cmd = CommandId::POPULATE_IDEV_ECC384_CERT.into();
        let mut req = PopulateIdevEcc384CertReq {
            cert_size: cert.len() as u32,
            ..Default::default()
        };
        req.cert[..cert.len()].copy_from_slice(cert);

        let req_bytes = req.as_mut_bytes();
        let mut resp = MailboxRespHeader::default();
        let resp_bytes = resp.as_mut_bytes();

        execute_mailbox_cmd(&self.mbox, cmd, req_bytes, resp_bytes).await?;
        Ok(())
    }

    pub async fn get_ldev_ecc384_cert(
        &mut self,
        cert: &mut [u8; MAX_ECC_CERT_SIZE],
    ) -> CaliptraApiResult<usize> {
        let resp = self.get_cert::<GetLdevEcc384CertReq>().await?;
        if resp.data_size > MAX_MAILBOX_GET_CERT_RESP_SIZE as u32 {
            return Err(CaliptraApiError::InvalidResponse);
        }
        cert[..resp.data_size as usize].copy_from_slice(&resp.data[..resp.data_size as usize]);
        Ok(resp.data_size as usize)
    }

    pub async fn get_fmc_alias_ecc384_cert(
        &mut self,
        cert: &mut [u8; MAX_ECC_CERT_SIZE],
    ) -> CaliptraApiResult<usize> {
        let resp = self.get_cert::<GetFmcAliasEcc384CertReq>().await?;
        if resp.data_size > MAX_MAILBOX_GET_CERT_RESP_SIZE as u32 {
            return Err(CaliptraApiError::InvalidResponse);
        }
        cert[..resp.data_size as usize].copy_from_slice(&resp.data[..resp.data_size as usize]);
        Ok(resp.data_size as usize)
    }

    pub async fn get_rt_alias_384cert(
        &mut self,
        cert: &mut [u8; MAX_ECC_CERT_SIZE],
    ) -> CaliptraApiResult<usize> {
        let resp = self.get_cert::<GetRtAliasEcc384CertReq>().await?;
        if resp.data_size > MAX_MAILBOX_GET_CERT_RESP_SIZE as u32 {
            return Err(CaliptraApiError::InvalidResponse);
        }
        cert[..resp.data_size as usize].copy_from_slice(&resp.data[..resp.data_size as usize]);
        Ok(resp.data_size as usize)
    }

    pub async fn certify_key(
        &mut self,
        cert: &mut [u8],
        label: Option<&[u8; KEY_LABEL_SIZE]>,
        derived_pubkey_x: Option<&mut [u8]>,
        derived_pubkey_y: Option<&mut [u8]>,
    ) -> CaliptraApiResult<usize> {
        if let Some(ref x) = derived_pubkey_x {
            if x.len() != DpeProfile::P384Sha384.tci_size() {
                Err(CaliptraApiError::InvalidArgument("Invalid pubkey size"))?;
            }
        }
        if let Some(ref y) = derived_pubkey_y {
            if y.len() != DpeProfile::P384Sha384.tci_size() {
                Err(CaliptraApiError::InvalidArgument("Invalid pubkey size"))?;
            }
        }

        let mut dpe_cmd = CertifyKeyCmd {
            handle: ContextHandle::default(),
            flags: CertifyKeyFlags::empty(),
            format: CertifyKeyCommand::FORMAT_X509,
            label: [0; KEY_LABEL_SIZE],
        };

        if let Some(label) = label {
            dpe_cmd.label[..label.len()].copy_from_slice(label);
        }

        let resp = self.execute_dpe_cmd(&mut Command::from(&dpe_cmd)).await?;

        if let DpeResponse::CertifyKey(certify_key_resp) = resp {
            let cert_len = certify_key_resp.cert_size as usize;
            if cert_len > cert.len() {
                return Err(CaliptraApiError::InvalidResponse);
            }

            cert[..cert_len].copy_from_slice(&certify_key_resp.cert[..cert_len]);

            if let Some(derived_pubkey_x) = derived_pubkey_x {
                derived_pubkey_x.copy_from_slice(&certify_key_resp.derived_pubkey_x);
            }
            if let Some(derived_pubkey_y) = derived_pubkey_y {
                derived_pubkey_y.copy_from_slice(&certify_key_resp.derived_pubkey_y);
            }
            Ok(cert_len)
        } else {
            Err(CaliptraApiError::InvalidResponse)
        }
    }

    pub async fn sign(
        &mut self,
        key_label: Option<&[u8; KEY_LABEL_SIZE]>,
        digest: &[u8],
        signature: &mut [u8],
    ) -> CaliptraApiResult<usize> {
        if digest.len() != DpeProfile::P384Sha384.hash_size() {
            return Err(CaliptraApiError::InvalidArgument("Invalid digest size"));
        }

        if signature.len() < DpeProfile::P384Sha384.tci_size() {
            return Err(CaliptraApiError::InvalidArgument("Invalid signature size"));
        }

        let mut dpe_cmd = SignCmd {
            handle: ContextHandle::default(),
            label: [0; KEY_LABEL_SIZE],
            flags: SignFlags::empty(),
            digest: [0; DpeProfile::P384Sha384.hash_size()],
        };
        dpe_cmd.digest[..digest.len()].copy_from_slice(digest);
        if let Some(label) = key_label {
            dpe_cmd.label[..label.len()].copy_from_slice(label);
        }

        let resp = self.execute_dpe_cmd(&mut Command::from(&dpe_cmd)).await?;
        match resp {
            DpeResponse::Sign(SignResp::P384(sign_resp)) => {
                let sig_r_size = sign_resp.sig_r.len();
                let sig_s_size = sign_resp.sig_s.len();
                signature[..sig_r_size].copy_from_slice(&sign_resp.sig_r[..]);
                signature[sig_r_size..sig_r_size + sig_s_size]
                    .copy_from_slice(&sign_resp.sig_s[..]);
                Ok(sig_r_size + sig_s_size)
            }
            _ => Err(CaliptraApiError::InvalidResponse),
        }
    }

    pub fn max_cert_chain_chunk_size(&mut self) -> usize {
        MAX_CERT_CHUNK_SIZE
    }

    pub async fn cert_chain_chunk(
        &mut self,
        offset: usize,
        cert_chunk: &mut [u8],
    ) -> CaliptraApiResult<usize> {
        let size = cert_chunk.len();
        if size > MAX_CERT_CHUNK_SIZE {
            Err(CaliptraApiError::InvalidArgument("Chunk size is too large"))?;
        }

        let dpe_cmd = GetCertificateChainCmd {
            offset: offset as u32,
            size: size as u32,
        };

        let resp = self
            .execute_dpe_cmd(&mut Command::GetCertificateChain(&dpe_cmd))
            .await?;

        match resp {
            DpeResponse::GetCertificateChain(cert_chain_resp) => {
                if cert_chain_resp.certificate_size > cert_chunk.len() as u32 {
                    return Err(CaliptraApiError::InvalidResponse);
                }

                let cert_chain_resp_len = cert_chain_resp.certificate_size as usize;

                cert_chunk[..cert_chain_resp_len]
                    .copy_from_slice(&cert_chain_resp.certificate_chain[..cert_chain_resp_len]);
                Ok(cert_chain_resp_len)
            }
            _ => Err(CaliptraApiError::InvalidResponse),
        }
    }

    async fn get_cert<R: Request + Default>(&mut self) -> CaliptraApiResult<R::Resp> {
        let mut req = R::default();
        let mut resp = R::Resp::new_zeroed();
        let resp_bytes = resp.as_mut_bytes();
        let req_bytes = req.as_mut_bytes();
        // let resp_bytes = resp.as_mut_bytes();
        let cmd = R::ID.into();
        execute_mailbox_cmd(&self.mbox, cmd, req_bytes, resp_bytes).await?;

        let mut resp = R::Resp::new_zeroed();
        resp.as_mut_bytes()[..].copy_from_slice(&resp_bytes[..]);

        Ok(resp)
    }

    async fn execute_dpe_cmd(
        &mut self,
        dpe_cmd: &mut Command<'_>,
    ) -> CaliptraApiResult<DpeResponse> {
        let mut cmd_data: [u8; InvokeDpeReq::DATA_MAX_SIZE] = [0; InvokeDpeReq::DATA_MAX_SIZE];

        let cmd_hdr = CommandHdr::new(DpeProfile::P384Sha384, dpe_cmd.id());

        let cmd_hdr_bytes = cmd_hdr.as_bytes();
        cmd_data[..cmd_hdr_bytes.len()].copy_from_slice(cmd_hdr_bytes);

        let dpe_cmd_bytes = dpe_cmd.as_bytes();
        cmd_data[cmd_hdr_bytes.len()..cmd_hdr_bytes.len() + dpe_cmd_bytes.len()]
            .copy_from_slice(dpe_cmd_bytes);
        let cmd_data_len = cmd_hdr_bytes.len() + dpe_cmd_bytes.len();

        let mut mbox_req = InvokeDpeReq {
            hdr: MailboxReqHeader { chksum: 0 },
            data_size: cmd_data_len as u32,
            data: cmd_data,
        };

        let mut mbox_resp = DpeEcResp::default();

        execute_mailbox_cmd(
            &self.mbox,
            InvokeDpeReq::ID.0,
            mbox_req.as_mut_bytes(),
            mbox_resp.as_mut_bytes(),
        )
        .await?;

        let mut resp = DpeEcResp::new_zeroed();
        let resp_size = size_of::<DpeEcResp>();
        resp.as_mut_bytes()[..].copy_from_slice(&mbox_resp.as_mut_bytes()[..resp_size]);
        self.parse_dpe_response(dpe_cmd, &resp)
    }

    fn parse_dpe_response(
        &self,
        cmd: &mut Command,
        resp: &DpeEcResp,
    ) -> CaliptraApiResult<DpeResponse> {
        let data_size = MAX_DPE_RESP_DATA_SIZE.min(resp.data_size as usize);
        let data = &resp.data[..data_size];

        match cmd {
            Command::CertifyKey(_) => Ok(DpeResponse::CertifyKey(
                CertifyEcKeyResp::try_read_from_bytes(&data[..size_of::<CertifyEcKeyResp>()])
                    .map_err(|_| CaliptraApiError::InvalidResponse)?,
            )),
            Command::Sign(_) => Ok(DpeResponse::Sign(SignResp::P384(
                SignP384Resp::try_read_from_bytes(&data[..size_of::<SignP384Resp>()])
                    .map_err(|_| CaliptraApiError::InvalidResponse)?,
            ))),
            Command::GetCertificateChain(_) => Ok(DpeResponse::GetCertificateChain(
                CertificateChainResp::try_read_from_bytes(
                    &data[..size_of::<CertificateChainResp>()],
                )
                .map_err(|_| CaliptraApiError::InvalidResponse)?,
            )),
            _ => Err(CaliptraApiError::InvalidResponse),
        }
    }
}

// Licensed under the Apache-2.0 license

use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::mailbox_api::{
    execute_mailbox_cmd, CertificateChainResp, CertifyEcKeyResp, DpeEcResp, DpeResponse,
    MAX_CERT_CHUNK_SIZE, MAX_ECC_CERT_SIZE,
};
use caliptra_api::mailbox::{
    CommandId, GetFmcAliasEcc384CertReq, GetIdevCsrReq, GetIdevCsrResp, GetLdevEcc384CertReq,
    GetRtAliasEcc384CertReq, InvokeDpeReq, MailboxRespHeader, PopulateIdevEcc384CertReq, Request,
    MAX_RESP_DATA_SIZE,
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

        execute_mailbox_cmd(
            &self.mbox,
            GetIdevCsrReq::ID.0,
            req.as_mut_bytes(),
            resp.as_mut_bytes(),
        )
        .await?;

        if resp.data_size == u32::MAX {
            Err(CaliptraApiError::UnprovisionedCsr)?;
        }

        let data_size = resp.data_size as usize;
        if data_size == 0 {
            return Err(CaliptraApiError::InvalidResponse);
        }

        let src = resp
            .data
            .get(..data_size)
            .ok_or(CaliptraApiError::InvalidResponse)?;
        csr_der
            .get_mut(..data_size)
            .ok_or(CaliptraApiError::InvalidResponse)?
            .copy_from_slice(src);
        Ok(data_size)
    }

    pub async fn populate_idev_ecc384_cert(&mut self, cert: &[u8]) -> CaliptraApiResult<()> {
        let mut req = PopulateIdevEcc384CertReq {
            cert_size: cert.len() as u32,
            ..Default::default()
        };
        req.cert
            .get_mut(..cert.len())
            .ok_or(CaliptraApiError::InvalidArgument("Invalid cert size"))?
            .copy_from_slice(cert);

        let mut resp = MailboxRespHeader::default();

        execute_mailbox_cmd(
            &self.mbox,
            CommandId::POPULATE_IDEV_ECC384_CERT.into(),
            req.as_mut_bytes(),
            resp.as_mut_bytes(),
        )
        .await?;
        Ok(())
    }

    pub async fn get_ldev_ecc384_cert(
        &mut self,
        cert: &mut [u8; MAX_ECC_CERT_SIZE],
    ) -> CaliptraApiResult<usize> {
        let resp = self.get_cert::<GetLdevEcc384CertReq>().await?;
        let data_size = resp.data_size as usize;
        let src = resp
            .data
            .get(..data_size)
            .ok_or(CaliptraApiError::InvalidResponse)?;
        cert.get_mut(..data_size)
            .ok_or(CaliptraApiError::InvalidResponse)?
            .copy_from_slice(src);
        Ok(data_size)
    }

    pub async fn get_fmc_alias_ecc384_cert(
        &mut self,
        cert: &mut [u8; MAX_ECC_CERT_SIZE],
    ) -> CaliptraApiResult<usize> {
        let resp = self.get_cert::<GetFmcAliasEcc384CertReq>().await?;
        let data_size = resp.data_size as usize;
        let src = resp
            .data
            .get(..data_size)
            .ok_or(CaliptraApiError::InvalidResponse)?;
        cert.get_mut(..data_size)
            .ok_or(CaliptraApiError::InvalidResponse)?
            .copy_from_slice(src);
        Ok(data_size)
    }

    pub async fn get_rt_alias_384cert(
        &mut self,
        cert: &mut [u8; MAX_ECC_CERT_SIZE],
    ) -> CaliptraApiResult<usize> {
        let resp = self.get_cert::<GetRtAliasEcc384CertReq>().await?;
        let data_size = resp.data_size as usize;
        let src = resp
            .data
            .get(..data_size)
            .ok_or(CaliptraApiError::InvalidResponse)?;
        cert.get_mut(..data_size)
            .ok_or(CaliptraApiError::InvalidResponse)?
            .copy_from_slice(src);
        Ok(data_size)
    }

    #[inline(never)]
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
            dpe_cmd
                .label
                .get_mut(..label.len())
                .ok_or(CaliptraApiError::InvalidArgument("Invalid label size"))?
                .copy_from_slice(label);
        }

        let resp = self.execute_dpe_cmd(&mut Command::from(&dpe_cmd)).await?;

        if let DpeResponse::CertifyKey(certify_key_resp) = resp {
            let cert_len = certify_key_resp.cert_size as usize;
            let src = certify_key_resp
                .cert
                .get(..cert_len)
                .ok_or(CaliptraApiError::InvalidResponse)?;
            cert.get_mut(..cert_len)
                .ok_or(CaliptraApiError::InvalidResponse)?
                .copy_from_slice(src);

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

    #[inline(never)]
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
        dpe_cmd
            .digest
            .get_mut(..digest.len())
            .ok_or(CaliptraApiError::InvalidArgument("Invalid digest size"))?
            .copy_from_slice(digest);
        if let Some(label) = key_label {
            dpe_cmd
                .label
                .get_mut(..label.len())
                .ok_or(CaliptraApiError::InvalidArgument("Invalid label size"))?
                .copy_from_slice(label);
        }

        let resp = self.execute_dpe_cmd(&mut Command::from(&dpe_cmd)).await?;
        match resp {
            DpeResponse::Sign(SignResp::P384(sign_resp)) => {
                let sig_r_size = sign_resp.sig_r.len();
                let sig_s_size = sign_resp.sig_s.len();
                signature
                    .get_mut(..sig_r_size)
                    .ok_or(CaliptraApiError::InvalidResponse)?
                    .copy_from_slice(&sign_resp.sig_r[..]);
                signature
                    .get_mut(sig_r_size..sig_r_size + sig_s_size)
                    .ok_or(CaliptraApiError::InvalidResponse)?
                    .copy_from_slice(&sign_resp.sig_s[..]);
                Ok(sig_r_size + sig_s_size)
            }
            _ => Err(CaliptraApiError::InvalidResponse),
        }
    }

    pub fn max_cert_chain_chunk_size(&mut self) -> usize {
        MAX_CERT_CHUNK_SIZE
    }

    #[inline(never)]
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
                let cert_chain_resp_len = cert_chain_resp.certificate_size as usize;
                let src = cert_chain_resp
                    .certificate_chain
                    .get(..cert_chain_resp_len)
                    .ok_or(CaliptraApiError::InvalidResponse)?;
                cert_chunk
                    .get_mut(..cert_chain_resp_len)
                    .ok_or(CaliptraApiError::InvalidResponse)?
                    .copy_from_slice(src);
                Ok(cert_chain_resp_len)
            }
            _ => Err(CaliptraApiError::InvalidResponse),
        }
    }

    #[inline(never)]
    async fn get_cert<R: Request + Default>(&mut self) -> CaliptraApiResult<R::Resp> {
        let mut req = R::default();
        let mut resp = R::Resp::new_zeroed();
        execute_mailbox_cmd(
            &self.mbox,
            R::ID.into(),
            req.as_mut_bytes(),
            resp.as_mut_bytes(),
        )
        .await?;

        Ok(resp)
    }

    #[inline(never)]
    async fn execute_dpe_cmd(
        &mut self,
        dpe_cmd: &mut Command<'_>,
    ) -> CaliptraApiResult<DpeResponse> {
        let mut mbox_req = InvokeDpeReq::new_zeroed();

        let cmd_hdr = CommandHdr::new(DpeProfile::P384Sha384, dpe_cmd.id());

        let cmd_hdr_bytes = cmd_hdr.as_bytes();
        mbox_req
            .data
            .get_mut(..cmd_hdr_bytes.len())
            .ok_or(CaliptraApiError::InvalidArgument("Invalid command header"))?
            .copy_from_slice(cmd_hdr_bytes);

        let dpe_cmd_bytes = dpe_cmd.as_bytes();
        mbox_req
            .data
            .get_mut(cmd_hdr_bytes.len()..cmd_hdr_bytes.len() + dpe_cmd_bytes.len())
            .ok_or(CaliptraApiError::InvalidArgument(
                "Invalid DPE command size",
            ))?
            .copy_from_slice(dpe_cmd_bytes);
        mbox_req.data_size = (cmd_hdr_bytes.len() + dpe_cmd_bytes.len()) as u32;

        let mut mbox_resp = DpeEcResp::default();

        execute_mailbox_cmd(
            &self.mbox,
            InvokeDpeReq::ID.0,
            mbox_req.as_mut_bytes(),
            mbox_resp.as_mut_bytes(),
        )
        .await?;

        self.parse_dpe_response(dpe_cmd, &mbox_resp)
    }

    fn parse_dpe_response(
        &self,
        cmd: &mut Command,
        resp: &DpeEcResp,
    ) -> CaliptraApiResult<DpeResponse> {
        let data_size = resp.data_size as usize;
        let data = resp
            .data
            .get(..data_size)
            .ok_or(CaliptraApiError::InvalidResponse)?;

        match cmd {
            Command::CertifyKey(_) => {
                let mut certify_key_resp = CertifyEcKeyResp::new_zeroed();
                certify_key_resp
                    .as_mut_bytes()
                    .get_mut(..data_size)
                    .ok_or(CaliptraApiError::InvalidResponse)?
                    .copy_from_slice(data);
                Ok(DpeResponse::CertifyKey(certify_key_resp))
            }
            Command::Sign(_) => {
                let size = core::mem::size_of::<SignP384Resp>();
                let sub_data = data.get(..size).ok_or(CaliptraApiError::InvalidResponse)?;
                Ok(DpeResponse::Sign(SignResp::P384(
                    SignP384Resp::try_read_from_bytes(sub_data)
                        .map_err(|_| CaliptraApiError::InvalidResponse)?,
                )))
            }
            Command::GetCertificateChain(_) => {
                let mut cert_chain_resp = CertificateChainResp::new_zeroed();
                cert_chain_resp
                    .as_mut_bytes()
                    .get_mut(..data_size)
                    .ok_or(CaliptraApiError::InvalidResponse)?
                    .copy_from_slice(data);
                Ok(DpeResponse::GetCertificateChain(cert_chain_resp))
            }
            _ => Err(CaliptraApiError::InvalidResponse),
        }
    }
}

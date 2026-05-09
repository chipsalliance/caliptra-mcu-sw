// Licensed under the Apache-2.0 license

use crate::crypto::hash::{HashAlgoType, HashContext, SHA384_HASH_SIZE};
use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::mailbox_api::{execute_mailbox_cmd, DpeEcResp, MAX_DPE_RESP_DATA_SIZE};
pub use caliptra_api::mailbox::{
    HpkeAlgorithms, HpkeHandle, InvokeDpeReq, OcpLockClearKeyCacheReq, OcpLockClearKeyCacheResp,
    OcpLockDeriveMekReq, OcpLockDeriveMekResp, OcpLockEnableMpkReq, OcpLockEnableMpkResp,
    OcpLockEnumerateHpkeHandlesReq, OcpLockEnumerateHpkeHandlesResp, OcpLockGenerateMekReq,
    OcpLockGenerateMekResp, OcpLockGenerateMpkReq, OcpLockGenerateMpkResp, OcpLockGetAlgorithmsReq,
    OcpLockGetAlgorithmsResp, OcpLockGetHpkePubKeyReq, OcpLockGetHpkePubKeyResp,
    OcpLockGetStatusReq, OcpLockGetStatusResp, OcpLockInitializeMekSecretReq,
    OcpLockInitializeMekSecretResp, OcpLockMixMpkReq, OcpLockMixMpkResp,
    OcpLockReportHekMetadataReq, OcpLockReportHekMetadataResp, OcpLockRewrapMpkReq,
    OcpLockRewrapMpkResp, OcpLockRotateHpkeKeyReq, OcpLockRotateHpkeKeyResp,
    OcpLockTestAccessKeyReq, OcpLockTestAccessKeyResp, OcpLockUnloadMekReq, OcpLockUnloadMekResp,
    Request, Response, SealedAccessKey, WrappedKey,
};
use core::mem::size_of;
use core::str::FromStr;
use dpe::commands::{Command, CommandHdr, SignFlags, SignP384Cmd};
use dpe::context::ContextHandle;
use dpe::response::SignP384Resp;
use dpe::DpeProfile;
use libsyscall_caliptra::mailbox::Mailbox;
use romtime::ocp_lock::Error as OcpLockError;

use zerocopy::{IntoBytes, TryFromBytes};

use const_oid::db::rfc5912::{ECDSA_WITH_SHA_384, ID_EC_PUBLIC_KEY, SECP_384_R_1};
use der::{
    asn1::{BitStringRef, GeneralizedTime},
    AnyRef, DateTime, Encode, Sequence, Tag,
};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

// TODO(clundin): Should this be documented somewhere?
// TODO(clundin): Do we need to allow externally supplied labels (I don't think so)?

/// Label used for DPE KDF
const DPE_LABEL: &[u8; 23] = b"MCU FW HPKE Endorsement";

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Validity {
    pub not_before: GeneralizedTime,
    pub not_after: GeneralizedTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TbsCertificate<'a> {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", constructed = "true")]
    pub version: u8,
    pub serial_number: u32,
    pub signature: AlgorithmIdentifier<AnyRef<'a>>,
    pub issuer: AnyRef<'a>,
    pub validity: Validity,
    pub subject: AnyRef<'a>,
    pub subject_public_key_info: SubjectPublicKeyInfo<AnyRef<'a>, BitStringRef<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Certificate<'a> {
    pub tbs_certificate: TbsCertificate<'a>,
    pub signature_algorithm: AlgorithmIdentifier<AnyRef<'a>>,
    pub signature: BitStringRef<'a>,
}

pub struct OcpLock<'a> {
    mailbox: &'a Mailbox,
}

impl OcpLock<'_> {
    pub const MAX_ENDORSEMENT_CERT_SIZE: usize = 8096;
}

impl<'a> OcpLock<'a> {
    pub fn new(mailbox: &'a Mailbox) -> Self {
        Self { mailbox }
    }

    async fn execute<R: Request>(&self, req: &mut R) -> CaliptraApiResult<R::Resp>
    where
        R::Resp: Default,
    {
        let mut resp = R::Resp::default();
        execute_mailbox_cmd(
            self.mailbox,
            R::ID.into(),
            req.as_mut_bytes(),
            resp.as_mut_bytes(),
        )
        .await?;
        Ok(resp)
    }

    pub async fn report_hek_metadata(
        &self,
        req: &mut OcpLockReportHekMetadataReq,
    ) -> CaliptraApiResult<OcpLockReportHekMetadataResp> {
        self.execute(req).await
    }

    pub async fn get_algorithms(&self) -> CaliptraApiResult<OcpLockGetAlgorithmsResp> {
        let mut req = OcpLockGetAlgorithmsReq::default();
        self.execute(&mut req).await
    }

    pub async fn initialize_mek_secret(
        &self,
        req: &mut OcpLockInitializeMekSecretReq,
    ) -> CaliptraApiResult<OcpLockInitializeMekSecretResp> {
        self.execute(req).await
    }

    pub async fn mix_mpk(
        &self,
        req: &mut OcpLockMixMpkReq,
    ) -> CaliptraApiResult<OcpLockMixMpkResp> {
        self.execute(req).await
    }

    pub async fn derive_mek(
        &self,
        req: &mut OcpLockDeriveMekReq,
    ) -> CaliptraApiResult<OcpLockDeriveMekResp> {
        self.execute(req).await
    }

    pub async fn enumerate_hpke_handles(
        &self,
    ) -> CaliptraApiResult<OcpLockEnumerateHpkeHandlesResp> {
        let mut req = OcpLockEnumerateHpkeHandlesReq::default();
        self.execute(&mut req).await
    }

    pub async fn rotate_hpke_key(
        &self,
        req: &mut OcpLockRotateHpkeKeyReq,
    ) -> CaliptraApiResult<OcpLockRotateHpkeKeyResp> {
        self.execute(req).await
    }

    pub async fn generate_mek(&self) -> CaliptraApiResult<OcpLockGenerateMekResp> {
        let mut req = OcpLockGenerateMekReq::default();
        self.execute(&mut req).await
    }

    pub async fn get_hpke_pub_key(
        &self,
        req: &mut OcpLockGetHpkePubKeyReq,
    ) -> CaliptraApiResult<OcpLockGetHpkePubKeyResp> {
        self.execute(req).await
    }

    async fn execute_dpe_cmd(&self, dpe_cmd: &mut Command<'_>) -> CaliptraApiResult<DpeEcResp> {
        let mut mbox_req = InvokeDpeReq::default();
        let cmd_hdr = CommandHdr::new(DpeProfile::P384Sha384, dpe_cmd.id());

        let cmd_hdr_bytes = cmd_hdr.as_bytes();
        mbox_req.data[..cmd_hdr_bytes.len()].copy_from_slice(cmd_hdr_bytes);

        let dpe_cmd_bytes = dpe_cmd.as_bytes();
        mbox_req.data[cmd_hdr_bytes.len()..cmd_hdr_bytes.len() + dpe_cmd_bytes.len()]
            .copy_from_slice(dpe_cmd_bytes);
        mbox_req.data_size = (cmd_hdr_bytes.len() + dpe_cmd_bytes.len()) as u32;

        let mut mbox_resp = DpeEcResp::default();

        execute_mailbox_cmd(
            self.mailbox,
            InvokeDpeReq::ID.into(),
            mbox_req.as_mut_bytes(),
            mbox_resp.as_mut_bytes(),
        )
        .await?;

        Ok(mbox_resp)
    }

    // TODO(clundin): Support ML-DSA
    pub async fn sign_with_dpe(&self, dpe_cmd: SignP384Cmd) -> CaliptraApiResult<SignP384Resp> {
        let mbox_resp = self.execute_dpe_cmd(&mut Command::from(&dpe_cmd)).await?;
        let data = &mbox_resp.data[..MAX_DPE_RESP_DATA_SIZE.min(mbox_resp.data_size as usize)];
        let signature = SignP384Resp::try_read_from_bytes(&data[..size_of::<SignP384Resp>()])
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        Ok(signature)
    }

    /// TODO(clundin): Add HPKE Identifiers
    /// TODO(clundin): This certificate should pass the test parser in caliptra-sw. I think a
    /// mailbox command to return it should unblock those tests.
    /// TODO(clundin): Support ML-DSA endorsement
    /// Wraps `hpke_handle` with an x509 certificate The certificate is signed by the MCU FW DPE context.
    pub async fn get_hpke_public_key_x509(
        &self,
        serial_number: u32,
        subject_name: &[u8],
        handle: &HpkeHandle,
        cert_buf: &mut [u8],
    ) -> CaliptraApiResult<usize> {
        let mut req = OcpLockGetHpkePubKeyReq {
            hpke_handle: handle.handle,
            ..Default::default()
        };

        let resp = self.get_hpke_pub_key(&mut req).await?;
        let pub_key =
            resp.pub_key
                .get(..resp.pub_key_len as usize)
                .ok_or(CaliptraApiError::OcpLock(
                    OcpLockError::RUNTIME_HPKE_PUB_KEY_EMPTY,
                ))?;

        let spki = match handle.hpke_algorithm {
            HpkeAlgorithms::ECDH_P384_HKDF_SHA384_AES_256_GCM => SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    oid: ID_EC_PUBLIC_KEY,
                    parameters: Some(AnyRef::from(&SECP_384_R_1)),
                },
                subject_public_key: BitStringRef::new(0, pub_key)?,
            },
            // TODO(clundin): Support ML-KEM & Hybrid public keys
            _ => Err(CaliptraApiError::OcpLock(
                OcpLockError::RUNTIME_HPKE_UNSUPPORTED_ALGORITHM,
            ))?,
        };

        let subject = AnyRef::new(Tag::Sequence, subject_name)?;
        let tbs = TbsCertificate {
            version: 2,
            serial_number,
            signature: AlgorithmIdentifier {
                oid: ECDSA_WITH_SHA_384,
                parameters: None,
            },
            // TODO(clundin): Get issuer from DPE Certify Key
            issuer: subject,
            validity: Validity {
                // TODO(clundin): Use a newer date ?
                not_before: GeneralizedTime::from_date_time(DateTime::from_str(
                    "2023-01-01T00:00:00Z",
                )?),
                not_after: GeneralizedTime::from_date_time(DateTime::from_str(
                    "9999-12-31T23:59:59Z",
                )?),
            },
            subject,
            subject_public_key_info: spki,
        };

        // TODO(clundin): Unique error codes for buffer sizes.
        let tbs_len: usize = tbs.encoded_len()?.try_into()?;

        // Defer checking if this buffer is sufficient in size to the `der::SliceWriter`.
        let mut tbs_der = [0u8; OcpLock::MAX_ENDORSEMENT_CERT_SIZE];
        let mut writer = der::SliceWriter::new(&mut tbs_der);
        writer.encode(&tbs)?;

        let mut digest = [0u8; SHA384_HASH_SIZE];
        HashContext::hash_all(HashAlgoType::SHA384, &tbs_der[..tbs_len], &mut digest).await?;

        let label = {
            let mut label = [0; 48];
            label[..DPE_LABEL.len()].clone_from_slice(DPE_LABEL);
            label
        };

        let dpe_cmd = SignP384Cmd {
            handle: ContextHandle::default(),
            label,
            flags: SignFlags::empty(),
            digest,
        };

        let dpe_resp = self.sign_with_dpe(dpe_cmd).await?;
        let signature_bytes = {
            let mut signature_bytes = [0; 97];
            signature_bytes[0] = 0x4;
            signature_bytes[1..49].clone_from_slice(&dpe_resp.sig_r);
            signature_bytes[49..].clone_from_slice(&dpe_resp.sig_s);
            signature_bytes
        };

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: AlgorithmIdentifier {
                oid: ECDSA_WITH_SHA_384,
                parameters: None,
            },
            signature: BitStringRef::new(0, &signature_bytes)?,
        };

        let mut writer = der::SliceWriter::new(cert_buf);
        writer.encode(&cert)?;

        let cert_len: usize = cert.encoded_len()?.try_into()?;
        Ok(cert_len)
    }

    pub async fn generate_mpk(
        &self,
        req: &mut OcpLockGenerateMpkReq,
    ) -> CaliptraApiResult<OcpLockGenerateMpkResp> {
        self.execute(req).await
    }

    pub async fn rewrap_mpk(
        &self,
        req: &mut OcpLockRewrapMpkReq,
    ) -> CaliptraApiResult<OcpLockRewrapMpkResp> {
        self.execute(req).await
    }

    pub async fn enable_mpk(
        &self,
        req: &mut OcpLockEnableMpkReq,
    ) -> CaliptraApiResult<OcpLockEnableMpkResp> {
        self.execute(req).await
    }

    pub async fn test_access_key(
        &self,
        req: &mut OcpLockTestAccessKeyReq,
    ) -> CaliptraApiResult<OcpLockTestAccessKeyResp> {
        self.execute(req).await
    }

    pub async fn get_status(&self) -> CaliptraApiResult<OcpLockGetStatusResp> {
        let mut req = OcpLockGetStatusReq::default();
        self.execute(&mut req).await
    }

    pub async fn clear_key_cache(
        &self,
        req: &mut OcpLockClearKeyCacheReq,
    ) -> CaliptraApiResult<OcpLockClearKeyCacheResp> {
        self.execute(req).await
    }

    pub async fn unload_mek(
        &self,
        req: &mut OcpLockUnloadMekReq,
    ) -> CaliptraApiResult<OcpLockUnloadMekResp> {
        self.execute(req).await
    }
}

// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::crypto::hash::SHA384_HASH_SIZE;
use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::mailbox_api::{execute_mailbox_cmd, DpeEcResp, DPE_PROFILE};
use crate::signer::DpeTransport;
use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_api::mailbox::MailboxRespHeader;
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
use caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox;
use caliptra_mcu_libsyscall_caliptra::mailbox::MailboxError;
use caliptra_mcu_libtock_platform::ErrorCode;
use caliptra_mcu_romtime::ocp_lock::{Error as OcpLockError, RuntimeConfig};
use core::mem::size_of;
use core::str::FromStr;
use dpe::commands::{Command, CommandHdr};
use dpe::response::ResponseHdr;

use zerocopy::{IntoBytes, TryFromBytes};

use const_oid::db::rfc5912::{ECDSA_WITH_SHA_384, ID_EC_PUBLIC_KEY, SECP_384_R_1};
use der::{
    asn1::{BitStringRef, GeneralizedTime, ObjectIdentifier, SetOf, UintRef},
    AnyRef, DateTime, Decode, Encode, Sequence, Tag, ValueOrd,
};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

const TCG_HPKE_IDENTIFIERS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.21.1.1");

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct HpkeIdentifiers {
    pub kem_id: u16,
    pub kdf_id: u16,
    pub aead_id: u16,
}

impl TryFrom<HpkeIdentifiers> for HpkeAlgorithms {
    type Error = CaliptraApiError;

    fn try_from(idents: HpkeIdentifiers) -> Result<Self, Self::Error> {
        match (idents.kem_id, idents.kdf_id, idents.aead_id) {
            (0x0011, 2, 2) => Ok(HpkeAlgorithms::ECDH_P384_HKDF_SHA384_AES_256_GCM),
            (0x0042, 2, 2) => Ok(HpkeAlgorithms::ML_KEM_1024_HKDF_SHA384_AES_256_GCM),
            (0x0051, 2, 2) => Ok(HpkeAlgorithms::ML_KEM_1024_ECDH_P384_HKDF_SHA384_AES_256_GCM),
            _ => Err(CaliptraApiError::OcpLock(
                OcpLockError::RUNTIME_HPKE_UNSUPPORTED_ALGORITHM,
            )),
        }
    }
}

impl TryFrom<HpkeAlgorithms> for HpkeIdentifiers {
    type Error = CaliptraApiError;

    fn try_from(alg: HpkeAlgorithms) -> Result<Self, Self::Error> {
        match alg {
            HpkeAlgorithms::ECDH_P384_HKDF_SHA384_AES_256_GCM => Ok(HpkeIdentifiers {
                kem_id: 0x0011,
                kdf_id: 0x0002,
                aead_id: 0x0002,
            }),
            HpkeAlgorithms::ML_KEM_1024_HKDF_SHA384_AES_256_GCM => Ok(HpkeIdentifiers {
                kem_id: 0x0042,
                kdf_id: 0x0002,
                aead_id: 0x0002,
            }),
            HpkeAlgorithms::ML_KEM_1024_ECDH_P384_HKDF_SHA384_AES_256_GCM => Ok(HpkeIdentifiers {
                kem_id: 0x0051,
                kdf_id: 0x0002,
                aead_id: 0x0002,
            }),
            _ => Err(CaliptraApiError::OcpLock(
                OcpLockError::RUNTIME_HPKE_UNSUPPORTED_ALGORITHM,
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Extension<'a> {
    pub extn_id: ObjectIdentifier,
    #[asn1(default = "Default::default")]
    pub critical: bool,
    #[asn1(type = "OCTET STRING")]
    pub extn_value: &'a [u8],
}
// TODO(clundin): Should this be documented somewhere?
// TODO(clundin): Do we need to allow externally supplied labels (I don't think so)?

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EcdsaSignature<'a> {
    pub r: der::asn1::UintRef<'a>,
    pub s: der::asn1::UintRef<'a>,
}

fn strip_leading_zeros(mut bytes: &[u8]) -> &[u8] {
    while !bytes.is_empty() && bytes[0] == 0 {
        bytes = &bytes[1..];
    }
    if bytes.is_empty() {
        &[0]
    } else {
        bytes
    }
}

const ID_CE_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const ID_CE_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct BasicConstraints {
    pub ca: Option<bool>,
    pub path_len: Option<u8>,
}

/// Label used for DPE KDF

#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct AttributeTypeAndValue<'a> {
    pub oid: ObjectIdentifier,
    pub value: AnyRef<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Validity {
    pub not_before: GeneralizedTime,
    pub not_after: GeneralizedTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TbsCertificate<'a> {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", constructed = "true")]
    pub version: u8,
    pub serial_number: UintRef<'a>,
    pub signature: AlgorithmIdentifier<AnyRef<'a>>,
    pub issuer: AnyRef<'a>,
    pub validity: Validity,
    pub subject: AnyRef<'a>,
    pub subject_public_key_info: SubjectPublicKeyInfo<AnyRef<'a>, BitStringRef<'a>>,
    #[asn1(
        context_specific = "3",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub extensions: Option<[Extension<'a>; 3]>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Certificate<'a> {
    pub tbs_certificate: TbsCertificate<'a>,
    pub signature_algorithm: AlgorithmIdentifier<AnyRef<'a>>,
    pub signature: BitStringRef<'a>,
}

#[async_trait]
pub trait OcpLockSigner: Send + Sync {
    async fn sign(&self, label: &[u8], data: &[u8], signature: &mut [u8]) -> CaliptraApiResult<()>;
    fn signature_size(&self) -> usize;
}

pub struct OcpLock<'a> {
    mailbox: &'a Mailbox,
    config: &'static dyn RuntimeConfig,
}

impl OcpLock<'_> {
    pub const MAX_ENDORSEMENT_CERT_SIZE: usize = 2048;
    pub const DPE_LABEL: &'static [u8] = b"MCU FW HPKE Endorsement";
    pub const ENDORSEMENT_CERT_CN: &'static [u8] = b"Caliptra MCU OCP LOCK Endorsement";
    pub const ENDORSEMENT_CERT_ISSUER_CN: &'static [u8] = b"DPE Leaf";
    pub const KEY_USAGE_KEY_ENCIPHERMENT: &'static [u8] = &[0x20];

    pub const X509_VERSION_3: u8 = 2; // v3 is encoded as 2
    pub const VALIDITY_NOT_BEFORE: &'static str = "2023-01-01T00:00:00Z";
    pub const VALIDITY_NOT_AFTER: &'static str = "9999-12-31T23:59:59Z";

    // P384 signature components size
    pub const P384_SCALAR_SIZE: usize = 48;
    pub const P384_SIGNATURE_SIZE: usize = 96;

    // Temp buffer sizes
    pub const SUBJECT_DER_BUF_SIZE: usize = 64;
    pub const ISSUER_DER_BUF_SIZE: usize = 64;
    pub const HPKE_IDENTS_DER_BUF_SIZE: usize = 32;
    pub const BASIC_CONSTRAINTS_DER_BUF_SIZE: usize = 16;
    pub const KEY_USAGE_DER_BUF_SIZE: usize = 16;
    pub const SIGNATURE_DER_BUF_SIZE: usize = 128;
    pub const MAX_SIGNATURE_BYTES: usize = 128;
}

impl<'a> OcpLock<'a> {
    pub fn new(mailbox: &'a Mailbox, config: &'static dyn RuntimeConfig) -> Self {
        Self { mailbox, config }
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

    async fn execute_in_place<R: Request>(
        &self,
        req: &mut R,
        resp: &mut R::Resp,
    ) -> CaliptraApiResult<()> {
        execute_mailbox_cmd(
            self.mailbox,
            R::ID.into(),
            req.as_mut_bytes(),
            resp.as_mut_bytes(),
        )
        .await?;
        Ok(())
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
        resp: &mut OcpLockEnumerateHpkeHandlesResp,
    ) -> CaliptraApiResult<()> {
        let mut req = OcpLockEnumerateHpkeHandlesReq::default();
        self.execute_in_place(&mut req, resp).await
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

    #[inline(never)]
    fn serialize_and_hash_tbs(
        tbs: &TbsCertificate,
        digest: &mut [u8; SHA384_HASH_SIZE],
    ) -> CaliptraApiResult<()> {
        let mut tbs_der = [0u8; OcpLock::MAX_ENDORSEMENT_CERT_SIZE];
        let mut writer = der::SliceWriter::new(&mut tbs_der[..]);
        writer.encode(tbs)?;
        let tbs_len = tbs.encoded_len()?.try_into()?;

        use sha2::{Digest, Sha384};
        let mut hasher = Sha384::new();
        hasher.update(&tbs_der[..tbs_len]);
        digest.copy_from_slice(&hasher.finalize());
        Ok(())
    }

    /// TODO(clundin): Support ML-DSA endorsement
    /// Wraps `hpke_handle` with an x509 certificate The certificate is signed by the MCU FW DPE context.
    pub async fn get_hpke_public_key_x509(
        &self,
        handle: &HpkeHandle,
        cert_buf: &mut [u8],
        signer: &dyn OcpLockSigner,
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

        let mut subject_der = [0u8; Self::SUBJECT_DER_BUF_SIZE];
        let subject = encode_subject_name(Self::ENDORSEMENT_CERT_CN, &mut subject_der)?;

        let mut issuer_der = [0u8; Self::ISSUER_DER_BUF_SIZE];
        let issuer = encode_subject_name(Self::ENDORSEMENT_CERT_ISSUER_CN, &mut issuer_der)?;

        let hpke_idents = HpkeIdentifiers::try_from(handle.hpke_algorithm.clone())?;

        let mut hpke_idents_der = [0u8; Self::HPKE_IDENTS_DER_BUF_SIZE];
        let mut writer = der::SliceWriter::new(&mut hpke_idents_der);
        writer.encode(&hpke_idents)?;
        let hpke_idents_der_len: usize = hpke_idents.encoded_len()?.try_into()?;
        let hpke_idents_der_slice = &hpke_idents_der[..hpke_idents_der_len];

        let basic_constraints = BasicConstraints {
            ca: None,
            path_len: None,
        };
        let mut bc_der = [0u8; Self::BASIC_CONSTRAINTS_DER_BUF_SIZE];
        let mut writer = der::SliceWriter::new(&mut bc_der);
        writer.encode(&basic_constraints)?;
        let bc_der_len: usize = basic_constraints.encoded_len()?.try_into()?;
        let bc_der_slice = &bc_der[..bc_der_len];

        let key_usage = BitStringRef::new(0, Self::KEY_USAGE_KEY_ENCIPHERMENT)?; // keyEncipherment (bit 2)
        let mut ku_der = [0u8; Self::KEY_USAGE_DER_BUF_SIZE];
        let mut writer = der::SliceWriter::new(&mut ku_der);
        writer.encode(&key_usage)?;
        let ku_der_len: usize = key_usage.encoded_len()?.try_into()?;
        let ku_der_slice = &ku_der[..ku_der_len];

        let ext_hpke = Extension {
            extn_id: TCG_HPKE_IDENTIFIERS,
            critical: false,
            extn_value: hpke_idents_der_slice,
        };

        let ext_bc = Extension {
            extn_id: ID_CE_BASIC_CONSTRAINTS,
            critical: true,
            extn_value: bc_der_slice,
        };

        let ext_ku = Extension {
            extn_id: ID_CE_KEY_USAGE,
            critical: true,
            extn_value: ku_der_slice,
        };
        let tbs = TbsCertificate {
            version: Self::X509_VERSION_3,
            serial_number: UintRef::new(self.config.endorsement_cert_serial_number())?,
            signature: AlgorithmIdentifier {
                oid: ECDSA_WITH_SHA_384,
                parameters: None,
            },
            // TODO(clundin): Get issuer from DPE Certify Key
            issuer,
            validity: Validity {
                // TODO(clundin): Use a newer date ?
                not_before: GeneralizedTime::from_date_time(DateTime::from_str(
                    Self::VALIDITY_NOT_BEFORE,
                )?),
                not_after: GeneralizedTime::from_date_time(DateTime::from_str(
                    Self::VALIDITY_NOT_AFTER,
                )?),
            },
            subject,
            subject_public_key_info: spki,
            extensions: Some([ext_hpke, ext_bc, ext_ku]),
        };

        let mut digest = [0u8; SHA384_HASH_SIZE];
        Self::serialize_and_hash_tbs(&tbs, &mut digest)?;

        let sig_len = signer.signature_size();

        let mut signature_bytes = [0u8; Self::MAX_SIGNATURE_BYTES];
        if sig_len > signature_bytes.len() {
            return Err(CaliptraApiError::InvalidResponse);
        }

        signer
            .sign(Self::DPE_LABEL, &digest, &mut signature_bytes[..sig_len])
            .await?;

        let r_raw = &signature_bytes[..Self::P384_SCALAR_SIZE];
        let s_raw = &signature_bytes[Self::P384_SCALAR_SIZE..Self::P384_SIGNATURE_SIZE];

        let r_stripped = strip_leading_zeros(r_raw);
        let s_stripped = strip_leading_zeros(s_raw);

        let r = der::asn1::UintRef::new(r_stripped)?;
        let s = der::asn1::UintRef::new(s_stripped)?;

        let sig = EcdsaSignature { r, s };

        let mut sig_der = [0u8; Self::SIGNATURE_DER_BUF_SIZE];
        let mut writer = der::SliceWriter::new(&mut sig_der);
        writer.encode(&sig)?;
        let sig_der_len = sig.encoded_len()?.try_into()?;
        let sig_der_slice = &sig_der[..sig_der_len];

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: AlgorithmIdentifier {
                oid: ECDSA_WITH_SHA_384,
                parameters: None,
            },
            signature: BitStringRef::new(0, sig_der_slice)?,
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
#[async_trait]
impl DpeTransport for Mailbox {
    async fn invoke(&self, cmd: &Command, resp_buf: &mut [u8]) -> CaliptraApiResult<usize> {
        let mut mbox_req = InvokeDpeReq::default();
        let cmd_hdr = CommandHdr::new(DPE_PROFILE, cmd.id());

        let cmd_hdr_bytes = cmd_hdr.as_bytes();
        let dpe_cmd_bytes = cmd.as_bytes();
        let total_req_len = cmd_hdr_bytes.len() + dpe_cmd_bytes.len();
        if total_req_len > mbox_req.data.len() {
            return Err(CaliptraApiError::InvalidArgBufferTooSmall);
        }
        mbox_req.data[..cmd_hdr_bytes.len()].copy_from_slice(cmd_hdr_bytes);
        mbox_req.data[cmd_hdr_bytes.len()..total_req_len].copy_from_slice(dpe_cmd_bytes);
        mbox_req.data_size = total_req_len as u32;

        let mut mbox_resp = DpeEcResp::default();

        self.populate_checksum(InvokeDpeReq::ID.into(), mbox_req.as_mut_bytes())
            .map_err(CaliptraApiError::Syscall)?;

        let size = self
            .execute(
                InvokeDpeReq::ID.into(),
                mbox_req.as_mut_bytes(),
                mbox_resp.as_mut_bytes(),
            )
            .await
            .map_err(|e| match e {
                MailboxError::ErrorCode(ErrorCode::Busy) => CaliptraApiError::MailboxBusy,
                _ => CaliptraApiError::Mailbox(e),
            })?;

        let dpe_resp_len = mbox_resp.data_size as usize;
        let expected_min_mbox_size = size_of::<MailboxRespHeader>() + size_of::<u32>(); // MailboxRespHeader + data_size field
        if size < expected_min_mbox_size || dpe_resp_len < size_of::<ResponseHdr>() {
            return Err(CaliptraApiError::InvalidResponse);
        }

        let hdr = ResponseHdr::try_read_from_bytes(&mbox_resp.data[..size_of::<ResponseHdr>()])
            .map_err(|_| CaliptraApiError::InvalidResponse)?;

        if hdr.status != 0 {
            return Err(CaliptraApiError::InvalidResponse);
        }

        if resp_buf.len() < dpe_resp_len {
            return Err(CaliptraApiError::InvalidArgBufferTooSmall);
        }
        resp_buf[..dpe_resp_len].copy_from_slice(&mbox_resp.data[..dpe_resp_len]);

        Ok(dpe_resp_len)
    }
}

fn encode_subject_name<'a>(cn: &[u8], buf: &'a mut [u8]) -> CaliptraApiResult<AnyRef<'a>> {
    let cn_oid = ObjectIdentifier::new_unwrap("2.5.4.3"); // Common Name
    let cn_val = AnyRef::new(Tag::Utf8String, cn)?;
    let atav = AttributeTypeAndValue {
        oid: cn_oid,
        value: cn_val,
    };
    let rdn = SetOf::try_from([atav])?;
    let subject_name = [rdn];

    let mut writer = der::SliceWriter::new(buf);
    writer.encode(&subject_name)?;
    let len: usize = subject_name.encoded_len()?.try_into()?;
    let bytes = &buf[..len];
    Ok(AnyRef::from_der(bytes)?)
}

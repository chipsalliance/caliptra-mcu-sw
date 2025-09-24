// Licensed under the Apache-2.0 license

use crate::error::SpdmError;
use bitfield::bitfield;
use libapi_caliptra::crypto::hash::HashAlgoType;
use zerocopy::{FromBytes, Immutable, IntoBytes};

// Caliptra Hash Priority table
pub static HASH_PRIORITY_TABLE: &[BaseHashAlgoType] = &[
    BaseHashAlgoType::TpmAlgSha512,
    BaseHashAlgoType::TpmAlgSha384,
    BaseHashAlgoType::TpmAlgSha256,
];

pub(crate) trait Prioritize<T>
where
    Self: Sized,
    T: Copy + Into<Self>,
{
    fn prioritize(&self, peer: &Self, priority_table: Option<&[T]>) -> Self;
}

impl<T> Prioritize<T> for u8
where
    T: Copy + Into<u8>,
{
    fn prioritize(&self, peer: &Self, priority_table: Option<&[T]>) -> Self {
        let common = self & peer;
        match common {
            0 => 0,
            _ => {
                if let Some(priority_table) = priority_table {
                    for &priority in priority_table {
                        let priority_alg: u8 = priority.into();
                        if common & priority_alg != 0 {
                            return priority_alg;
                        }
                    }
                }
                // If priority_table is None or the values in the priority table do not match the common algorithms,
                // we will default to returning the first common algorithm (First common bit from LSB).
                1 << common.trailing_zeros()
            }
        }
    }
}

impl<T> Prioritize<T> for u16
where
    T: Copy + Into<u16>,
{
    fn prioritize(&self, peer: &Self, priority_table: Option<&[T]>) -> Self {
        let common = self & peer;
        match common {
            0 => 0,
            _ => {
                if let Some(priority_table) = priority_table {
                    for &priority in priority_table {
                        let priority_alg: u16 = priority.into();
                        if common & priority_alg != 0 {
                            return priority_alg;
                        }
                    }
                }
                // If priority_table is None or the values in the priority table do not match the common algorithms,
                // we will default to returning the first common algorithm (First common bit from LSB).
                1 << common.trailing_zeros()
            }
        }
    }
}

impl<T> Prioritize<T> for u32
where
    T: Copy + Into<u32>,
{
    fn prioritize(&self, peer: &Self, priority_table: Option<&[T]>) -> Self {
        let common = self & peer;
        match common {
            0 => 0,
            _ => {
                if let Some(priority_table) = priority_table {
                    for &priority in priority_table {
                        let priority_alg: u32 = priority.into();
                        if common & priority_alg != 0 {
                            return priority_alg;
                        }
                    }
                }
                // If priority_table is None or the values in the priority table do not match the common algorithms,
                // we will default to returning the first common algorithm (First common bit from LSB).
                1 << common.trailing_zeros()
            }
        }
    }
}

// Measurement Specification field
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Default, Clone, Copy)]
#[repr(C)]
pub struct MeasurementSpecification(u8);
impl Debug;
u8;
pub dmtf_measurement_spec, set_dmtf_measurement_spec: 0,0;
reserved, _: 7,1;
}

#[derive(Debug, Clone, Copy)]
pub enum MeasurementSpecificationType {
    DmtfMeasurementSpec,
}

impl From<MeasurementSpecificationType> for u8 {
    fn from(measurement_specification_type: MeasurementSpecificationType) -> u8 {
        match measurement_specification_type {
            MeasurementSpecificationType::DmtfMeasurementSpec => MeasurementSpecification(1 << 0).0,
        }
    }
}

// Other Param Support Field for request and response
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Default, Clone, Copy)]
#[repr(C)]
pub struct OtherParamSupport(u8);
impl Debug;
u8;
pub opaque_data_fmt0, set_opaque_data_fmt0: 0,0;
pub opaque_data_fmt1, set_opaque_data_fmt1: 1,1;
pub reserved1, _: 3,2;
pub multi_key_conn, set_multi_key_conn: 4,4;
pub reserved2, _: 7,5;
}

impl From<OpaqueDataFormatType> for u8 {
    fn from(other_param_support_type: OpaqueDataFormatType) -> u8 {
        match other_param_support_type {
            OpaqueDataFormatType::OpaqueDataFmt0 => OtherParamSupport(1 << 0).0,
            OpaqueDataFormatType::OpaqueDataFmt1 => OtherParamSupport(1 << 1).0,
        }
    }
}

// Opaque Data Format field type
#[derive(Debug, Clone, Copy)]
pub enum OpaqueDataFormatType {
    // Opaque Data Format 0
    OpaqueDataFmt0,
    // Opaque Data Format 1
    OpaqueDataFmt1,
}

// Measurement Hash Algorithm field
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Default, Clone, Copy)]
#[repr(C)]
pub struct MeasurementHashAlgo(u32);
impl Debug;
u8;
pub raw_bit_stream, set_raw_bit_stream: 0,0;
pub tpm_alg_sha_256, set_tpm_alg_sha_256: 1,1;
pub tpm_alg_sha_384, set_tpm_alg_sha_384: 2,2;
pub tpm_alg_sha_512, set_tpm_alg_sha_512: 3,3;
pub tpm_alg_sha3_256, set_tpm_alg_sha3_256: 4,4;
pub tpm_alg_sha3_384, set_tpm_alg_sha3_384: 5,5;
pub tpm_alg_sha3_512, set_tpm_alg_sha3_512: 6,6;
pub tpm_alg_sm3_256, set_tpm_alg_sm3_256: 7,7;
reserved, _: 31,8;
}

// Base Asymmetric Algorithm field
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Default, Clone, Copy)]
#[repr(C)]
pub struct BaseAsymAlgo(u32);
impl Debug;
u8;
pub tpm_alg_rsassa_2048, set_tpm_alg_rsassa_2048: 0,0;
pub tpm_alg_rsapss_2048, set_tpm_alg_rsapss_2048: 1,1;
pub tpm_alg_rsassa_3072, set_tpm_alg_rsassa_3072: 2,2;
pub tpm_alg_rsapss_3072, set_tpm_alg_rsapss_3072: 3,3;
pub tpm_alg_ecdsa_ecc_nist_p256, set_tpm_alg_ecdsa_ecc_nist_p256: 4,4;
pub tpm_alg_rsassa_4096, set_tpm_alg_rsassa_4096: 5,5;
pub tpm_alg_rsapss_4096, set_tpm_alg_rsapss_4096: 6,6;
pub tpm_alg_ecdsa_ecc_nist_p384, set_tpm_alg_ecdsa_ecc_nist_p384: 7,7;
pub tpm_alg_ecdsa_ecc_nist_p521, set_tpm_alg_ecdsa_ecc_nist_p521: 8,8;
pub tpm_alg_sm2_ecc_sm2_p256, set_tpm_alg_sm2_ecc_sm2_p256: 9,9;
pub eddsa_ed25519, set_eddsa_ed25519: 10,10;
pub eddsa_ed448, set_eddsa_ed448: 11,11;
reserved, _: 31,12;
}

impl From<BaseAsymAlgoType> for u32 {
    fn from(base_asym_algo_type: BaseAsymAlgoType) -> u32 {
        match base_asym_algo_type {
            BaseAsymAlgoType::TpmAlgRsassa2048 => BaseAsymAlgo(1 << 0).0,
            BaseAsymAlgoType::TpmAlgRsapss2048 => BaseAsymAlgo(1 << 1).0,
            BaseAsymAlgoType::TpmAlgRsassa3072 => BaseAsymAlgo(1 << 2).0,
            BaseAsymAlgoType::TpmAlgRsapss3072 => BaseAsymAlgo(1 << 3).0,
            BaseAsymAlgoType::TpmAlgEcdsaEccNistP256 => BaseAsymAlgo(1 << 4).0,
            BaseAsymAlgoType::TpmAlgRsassa4096 => BaseAsymAlgo(1 << 5).0,
            BaseAsymAlgoType::TpmAlgRsapss4096 => BaseAsymAlgo(1 << 6).0,
            BaseAsymAlgoType::TpmAlgEcdsaEccNistP384 => BaseAsymAlgo(1 << 7).0,
            BaseAsymAlgoType::TpmAlgEcdsaEccNistP521 => BaseAsymAlgo(1 << 8).0,
            BaseAsymAlgoType::TpmAlgSm2EccSm2P256 => BaseAsymAlgo(1 << 9).0,
            BaseAsymAlgoType::EddsaEd25519 => BaseAsymAlgo(1 << 10).0,
            BaseAsymAlgoType::EddsaEd448 => BaseAsymAlgo(1 << 11).0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum BaseAsymAlgoType {
    TpmAlgRsassa2048,
    TpmAlgRsapss2048,
    TpmAlgRsassa3072,
    TpmAlgRsapss3072,
    TpmAlgEcdsaEccNistP256,
    TpmAlgRsassa4096,
    TpmAlgRsapss4096,
    TpmAlgEcdsaEccNistP384,
    TpmAlgEcdsaEccNistP521,
    TpmAlgSm2EccSm2P256,
    EddsaEd25519,
    EddsaEd448,
}

// Base Hash Algorithm field
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Default, Clone, Copy)]
#[repr(C)]
pub struct BaseHashAlgo(u32);
impl Debug;
u8;
pub tpm_alg_sha_256, set_tpm_alg_sha_256: 0,0;
pub tpm_alg_sha_384, set_tpm_alg_sha_384: 1,1;
pub tpm_alg_sha_512, set_tpm_alg_sha_512: 2,2;
pub tpm_alg_sha3_256, set_tpm_alg_sha3_256: 3,3;
pub tpm_alg_sha3_384, set_tpm_alg_sha3_384: 4,4;
pub tpm_alg_sha3_512, set_tpm_alg_sha3_512: 5,5;
pub tpm_alg_sm3_256, set_tpm_alg_sm3_256: 6,6;
reserved, _: 31,7;
}

impl From<BaseHashAlgoType> for BaseHashAlgo {
    fn from(base_hash_algo_type: BaseHashAlgoType) -> Self {
        match base_hash_algo_type {
            BaseHashAlgoType::TpmAlgSha256 => BaseHashAlgo(1 << 0),
            BaseHashAlgoType::TpmAlgSha384 => BaseHashAlgo(1 << 1),
            BaseHashAlgoType::TpmAlgSha512 => BaseHashAlgo(1 << 2),
            BaseHashAlgoType::TpmAlgSha3_256 => BaseHashAlgo(1 << 3),
            BaseHashAlgoType::TpmAlgSha3_384 => BaseHashAlgo(1 << 4),
            BaseHashAlgoType::TpmAlgSha3_512 => BaseHashAlgo(1 << 5),
            BaseHashAlgoType::TpmAlgSm3_256 => BaseHashAlgo(1 << 6),
        }
    }
}

impl Prioritize<BaseHashAlgoType> for BaseHashAlgo {
    fn prioritize(&self, peer: &Self, priority_table: Option<&[BaseHashAlgoType]>) -> Self {
        let common = self.0 & peer.0;
        if let Some(priority_table) = priority_table {
            for &priority in priority_table {
                let priority_alg: BaseHashAlgo = priority.into();
                if common & priority_alg.0 != 0 {
                    return BaseHashAlgo(priority_alg.0);
                }
            }
        } else {
            // If priority_table is None, we assume the default behavior
            // of returning the first common base hash algo.
            if common != 0 {
                return BaseHashAlgo(common & (!common + 1));
            }
        }
        BaseHashAlgo::default()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum BaseHashAlgoType {
    TpmAlgSha256,
    TpmAlgSha384,
    TpmAlgSha512,
    TpmAlgSha3_256,
    TpmAlgSha3_384,
    TpmAlgSha3_512,
    TpmAlgSm3_256,
}

impl TryFrom<u8> for BaseHashAlgoType {
    type Error = SpdmError;

    fn try_from(value: u8) -> Result<Self, SpdmError> {
        match value {
            0 => Ok(BaseHashAlgoType::TpmAlgSha256),
            1 => Ok(BaseHashAlgoType::TpmAlgSha384),
            2 => Ok(BaseHashAlgoType::TpmAlgSha512),
            3 => Ok(BaseHashAlgoType::TpmAlgSha3_256),
            4 => Ok(BaseHashAlgoType::TpmAlgSha3_384),
            5 => Ok(BaseHashAlgoType::TpmAlgSha3_512),
            6 => Ok(BaseHashAlgoType::TpmAlgSm3_256),
            _ => Err(SpdmError::InvalidParam),
        }
    }
}

impl TryFrom<BaseHashAlgoType> for HashAlgoType {
    type Error = SpdmError;
    fn try_from(value: BaseHashAlgoType) -> Result<HashAlgoType, SpdmError> {
        match value {
            BaseHashAlgoType::TpmAlgSha384 => Ok(HashAlgoType::SHA384),
            BaseHashAlgoType::TpmAlgSha512 => Ok(HashAlgoType::SHA512),
            _ => Err(SpdmError::InvalidParam),
        }
    }
}

// Measurement Extension Log Specification field
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Default, Clone, Copy)]
#[repr(C)]
pub struct MelSpecification(u8);
impl Debug;
u8;
pub dmtf_mel_spec, set_dmtf_mel_spec: 0,0;
reserved, _: 7,1;
}

#[derive(Debug, Clone, Copy)]
pub enum MelSpecificationType {
    DmtfMelSpec,
}

impl From<MelSpecificationType> for u8 {
    fn from(mel_specification_type: MelSpecificationType) -> u8 {
        match mel_specification_type {
            MelSpecificationType::DmtfMelSpec => MelSpecification(1 << 0).0,
        }
    }
}

// AlgSupported field for AEAD cipher suite
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Default, Clone, Copy)]
#[repr(C)]
pub struct DheNamedGroup(u16);
impl Debug;
u8;
pub ffdhe2048, set_ffdhe2048: 0,0;
pub ffdhe3072, set_ffdhe3072: 1,1;
pub ffdhe4096, set_ffdhe4096: 2,2;
pub secp256r1, set_secp256r1: 3,3;
pub secp384r1, set_secp384r1: 4,4;
pub secp521r1, set_secp521r1: 5,5;
pub sm2_p256, set_sm2_p256: 6,6;
reserved, _: 15,7;
}

impl From<DheGroupType> for u16 {
    fn from(dhe_group_type: DheGroupType) -> u16 {
        match dhe_group_type {
            DheGroupType::Ffdhe2048 => DheNamedGroup(1 << 0).0,
            DheGroupType::Ffdhe3072 => DheNamedGroup(1 << 1).0,
            DheGroupType::Ffdhe4096 => DheNamedGroup(1 << 2).0,
            DheGroupType::Secp256r1 => DheNamedGroup(1 << 3).0,
            DheGroupType::Secp384r1 => DheNamedGroup(1 << 4).0,
            DheGroupType::Secp521r1 => DheNamedGroup(1 << 5).0,
            DheGroupType::Sm2P256 => DheNamedGroup(1 << 6).0,
        }
    }
}

// AlgSupported type for DHE group
#[derive(Debug, Clone, Copy)]
pub enum DheGroupType {
    // ffdhe2048
    Ffdhe2048,
    // ffdhe3072
    Ffdhe3072,
    // ffdhe4096
    Ffdhe4096,
    // secp256r1
    Secp256r1,
    // secp384r1
    Secp384r1,
    // secp521r1
    Secp521r1,
    // SM2_P256
    Sm2P256,
}

// AlgSupported field for AEAD cipher suite
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Default, Clone, Copy)]
#[repr(C)]
pub struct AeadCipherSuite(u16);
impl Debug;
u8;
pub aes128_gcm, set_aes128_gcm: 0,0;
pub aes256_gcm, set_aes256_gcm: 1,1;
pub chacha20_poly1305, set_chacha20_poly1305: 2,2;
pub aead_sm4_gcm, set_aead_sm4_gcm: 3,3;
reserved, _: 15,4;
}

impl From<AeadCipherSuiteType> for u16 {
    fn from(aead_cipher_suite_type: AeadCipherSuiteType) -> u16 {
        match aead_cipher_suite_type {
            AeadCipherSuiteType::Aes128Gcm => AeadCipherSuite(1 << 0).0,
            AeadCipherSuiteType::Aes256Gcm => AeadCipherSuite(1 << 1).0,
            AeadCipherSuiteType::Chacha20Poly1305 => AeadCipherSuite(1 << 2).0,
            AeadCipherSuiteType::AeadSm4Gcm => AeadCipherSuite(1 << 3).0,
        }
    }
}

// AlgSupported type for AEAD cipher suite
#[derive(Debug, Clone, Copy)]
pub enum AeadCipherSuiteType {
    // AES-128-GCM
    Aes128Gcm,
    // AES-256-GCM
    Aes256Gcm,
    // CHACHA20-POLY1305
    Chacha20Poly1305,
    // AEAD_SM4_GCM
    AeadSm4Gcm,
}

// AlgSupported field for Request Base Asym Algorithm
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Default, Clone, Copy)]
#[repr(C)]
pub struct ReqBaseAsymAlg(u16);
impl Debug;
u8;
pub tpm_alg_rsa_ssa_2048, set_tpm_alg_rsa_ssa_2048: 0,0;
pub tpm_alg_rsa_pss_2048, set_tpm_alg_rsa_pss_2048: 1,1;
pub tpm_alg_rsa_ssa_3072, set_tpm_alg_rsa_ssa_3072: 2,2;
pub tpm_alg_rsa_pss_3072, set_tpm_alg_rsa_pss_3072: 3,3;
pub tpm_alg_ecdsa_ecc_nist_p256, set_tpm_alg_ecdsa_ecc_nist_p256: 4,4;
pub tpm_alg_rsa_ssa_4096, set_tpm_alg_rsa_ssa_4096: 5,5;
pub tpm_alg_rsa_pss_4096, set_tpm_alg_rsa_pss_4096: 6,6;
pub tpm_alg_ecdsa_ecc_nist_p384, set_tpm_alg_ecdsa_ecc_nist_p384: 7,7;
pub tpm_alg_ecdsa_ecc_nist_p521, set_tpm_alg_ecdsa_ecc_nist_p521: 8,8;
pub tpm_alg_sm2_ecc_sm2_p256, set_tpm_alg_sm2_ecc_sm2_p256: 9,9;
pub eddsa_ed25519, set_eddsa_ed25519: 10,10;
pub eddsa_ed448, set_eddsa_ed448: 11,11;
reserved, _: 15,12;
}

impl From<ReqBaseAsymAlgType> for u16 {
    fn from(req_base_asym_alg_type: ReqBaseAsymAlgType) -> u16 {
        match req_base_asym_alg_type {
            ReqBaseAsymAlgType::TpmAlgRsaSsa2048 => ReqBaseAsymAlg(1 << 0).0,
            ReqBaseAsymAlgType::TpmAlgRsaPss2048 => ReqBaseAsymAlg(1 << 1).0,
            ReqBaseAsymAlgType::TpmAlgRsaSsa3072 => ReqBaseAsymAlg(1 << 2).0,
            ReqBaseAsymAlgType::TpmAlgRsaPss3072 => ReqBaseAsymAlg(1 << 3).0,
            ReqBaseAsymAlgType::TpmAlgEcdsaEccNistP256 => ReqBaseAsymAlg(1 << 4).0,
            ReqBaseAsymAlgType::TpmAlgRsaSsa4096 => ReqBaseAsymAlg(1 << 5).0,
            ReqBaseAsymAlgType::TpmAlgRsaPss4096 => ReqBaseAsymAlg(1 << 6).0,
            ReqBaseAsymAlgType::TpmAlgEcdsaEccNistP384 => ReqBaseAsymAlg(1 << 7).0,
            ReqBaseAsymAlgType::TpmAlgEcdsaEccNistP521 => ReqBaseAsymAlg(1 << 8).0,
            ReqBaseAsymAlgType::TpmAlgSm2EccSm2P256 => ReqBaseAsymAlg(1 << 9).0,
            ReqBaseAsymAlgType::EddsaEd25519 => ReqBaseAsymAlg(1 << 10).0,
            ReqBaseAsymAlgType::EddsaEd448 => ReqBaseAsymAlg(1 << 11).0,
        }
    }
}

// AlgSupported type for Request Base Asym Algorithm
#[derive(Debug, Clone, Copy)]
pub enum ReqBaseAsymAlgType {
    // TPM_ALG_RSASSA_2048
    TpmAlgRsaSsa2048,
    // TPM_ALG_RSAPSS_2048
    TpmAlgRsaPss2048,
    // TPM_ALG_RSASSA_3072
    TpmAlgRsaSsa3072,
    // TPM_ALG_RSAPSS_3072
    TpmAlgRsaPss3072,
    // TPM_ALG_ECDSA_ECC_NIST_P256
    TpmAlgEcdsaEccNistP256,
    // TPM_ALG_RSASSA_4096
    TpmAlgRsaSsa4096,
    // TPM_ALG_RSAPSS_4096
    TpmAlgRsaPss4096,
    // TPM_ALG_ECDSA_ECC_NIST_P384
    TpmAlgEcdsaEccNistP384,
    // TPM_ALG_ECDSA_ECC_NIST_P521
    TpmAlgEcdsaEccNistP521,
    // TPM_ALG_SM2_ECC_SM2_P256
    TpmAlgSm2EccSm2P256,
    // EdDSA ed25519
    EddsaEd25519,
    // EdDSA ed448
    EddsaEd448,
}

// AlgSupported field for Key Schedule
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Default, Clone, Copy)]
#[repr(C)]
pub struct KeySchedule(u16);
impl Debug;
u8;
pub spdm_key_schedule, set_spdm_key_schedule: 0,0;
pub reserved, _: 15,1;
}

impl From<KeyScheduleType> for u16 {
    fn from(key_schedule_type: KeyScheduleType) -> u16 {
        match key_schedule_type {
            KeyScheduleType::SpdmKeySchedule => KeySchedule(1 << 0).0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum KeyScheduleType {
    // SPDM Key Schedule
    SpdmKeySchedule,
}

#[derive(Debug, Clone)]
pub struct DeviceAlgorithms {
    pub measurement_spec: MeasurementSpecification,
    pub other_param_support: OtherParamSupport,
    pub measurement_hash_algo: MeasurementHashAlgo,
    pub base_asym_algo: BaseAsymAlgo,
    pub base_hash_algo: BaseHashAlgo,
    pub mel_specification: MelSpecification,
    pub dhe_group: DheNamedGroup,
    pub aead_cipher_suite: AeadCipherSuite,
    pub req_base_asym_algo: ReqBaseAsymAlg,
    pub key_schedule: KeySchedule,
}

impl Default for DeviceAlgorithms {
    fn default() -> Self {
        let mut measurement_spec = MeasurementSpecification(0);
        measurement_spec.set_dmtf_measurement_spec(1);

        let other_param_support = OtherParamSupport::default();

        let mut measurement_hash_algo = MeasurementHashAlgo::default();
        measurement_hash_algo.set_tpm_alg_sha_384(1);

        let mut base_asym_algo = BaseAsymAlgo::default();
        base_asym_algo.set_tpm_alg_ecdsa_ecc_nist_p384(1);

        let mut base_hash_algo = BaseHashAlgo::default();
        base_hash_algo.set_tpm_alg_sha_384(1);

        let mut mel_specification = MelSpecification::default();
        mel_specification.set_dmtf_mel_spec(1);

        let dhe_group = DheNamedGroup::default();
        let aead_cipher_suite = AeadCipherSuite::default();
        let req_base_asym_algo = ReqBaseAsymAlg::default();
        let key_schedule = KeySchedule::default();

        DeviceAlgorithms {
            measurement_spec,
            other_param_support,
            measurement_hash_algo,
            base_asym_algo,
            base_hash_algo,
            mel_specification,
            dhe_group,
            aead_cipher_suite,
            req_base_asym_algo,
            key_schedule,
        }
    }
}

impl DeviceAlgorithms {
    pub fn num_alg_struct_tables(&self) -> usize {
        let mut num = 0;
        if self.dhe_group.0 != 0 {
            num += 1;
        }
        if self.aead_cipher_suite.0 != 0 {
            num += 1;
        }
        if self.req_base_asym_algo.0 != 0 {
            num += 1;
        }
        if self.key_schedule.0 != 0 {
            num += 1;
        }
        num
    }

    pub fn set_dhe_group(&mut self) {
        let mut dhe_named_group = DheNamedGroup::default();
        dhe_named_group.set_secp384r1(1);
        self.dhe_group = dhe_named_group;
    }

    pub fn set_aead_cipher_suite(&mut self) {
        let mut aead_cipher_suite = AeadCipherSuite::default();
        aead_cipher_suite.set_aes256_gcm(1);
        self.aead_cipher_suite = aead_cipher_suite;
    }

    pub fn set_spdm_key_schedule(&mut self) {
        let mut key_schedule = KeySchedule::default();
        key_schedule.set_spdm_key_schedule(1);
        self.key_schedule = key_schedule;
    }

    pub fn set_other_param_support(&mut self) {
        let mut other_param = OtherParamSupport::default();
        other_param.set_opaque_data_fmt1(1);
        self.other_param_support = other_param;
    }
}

// Algorithm Priority Table set by the responder
// to indicate the priority of the selected algorithms
pub struct AlgorithmPriorityTable<'a> {
    pub measurement_specification: Option<&'a [MeasurementSpecificationType]>,
    pub opaque_data_format: Option<&'a [OpaqueDataFormatType]>,
    pub base_asym_algo: Option<&'a [BaseAsymAlgoType]>,
    pub base_hash_algo: Option<&'a [BaseHashAlgoType]>,
    pub mel_specification: Option<&'a [MelSpecificationType]>,
    pub dhe_group: Option<&'a [DheGroupType]>,
    pub aead_cipher_suite: Option<&'a [AeadCipherSuiteType]>,
    pub req_base_asym_algo: Option<&'a [ReqBaseAsymAlgType]>,
    pub key_schedule: Option<&'a [KeyScheduleType]>,
}

pub struct LocalDeviceAlgorithms<'a> {
    pub device_algorithms: DeviceAlgorithms,
    pub algorithm_priority_table: AlgorithmPriorityTable<'a>,
}

impl Default for LocalDeviceAlgorithms<'_> {
    fn default() -> Self {
        LocalDeviceAlgorithms {
            device_algorithms: DeviceAlgorithms::default(),
            algorithm_priority_table: AlgorithmPriorityTable {
                measurement_specification: None,
                opaque_data_format: None,
                base_asym_algo: None,
                base_hash_algo: Some(HASH_PRIORITY_TABLE),
                mel_specification: None,
                dhe_group: None,
                aead_cipher_suite: None,
                req_base_asym_algo: None,
                key_schedule: None,
            },
        }
    }
}

impl LocalDeviceAlgorithms<'_> {
    pub fn new(device_algorithms: DeviceAlgorithms) -> Self {
        LocalDeviceAlgorithms {
            device_algorithms,
            algorithm_priority_table: AlgorithmPriorityTable {
                measurement_specification: None,
                opaque_data_format: None,
                base_asym_algo: None,
                base_hash_algo: Some(HASH_PRIORITY_TABLE),
                mel_specification: None,
                dhe_group: None,
                aead_cipher_suite: None,
                req_base_asym_algo: None,
                key_schedule: None,
            },
        }
    }
}

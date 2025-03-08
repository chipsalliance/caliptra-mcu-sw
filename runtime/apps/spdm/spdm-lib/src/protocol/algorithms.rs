// Licensed under the Apache-2.0 license

use crate::error::{SpdmError, SpdmResult};
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};
pub(crate) trait Prioritize<T> {
    fn prioritize(self, peer: Self, priority_table: Option<&[T]>) -> Self;
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

impl From<MeasurementSpecificationType> for MeasurementSpecification {
    fn from(measurement_specification_type: MeasurementSpecificationType) -> Self {
        match measurement_specification_type {
            MeasurementSpecificationType::DmtfMeasurementSpec => MeasurementSpecification(1 << 0),
        }
    }
}

impl Prioritize<MeasurementSpecificationType> for MeasurementSpecification {
    fn prioritize(
        self,
        peer: Self,
        priority_table: Option<&[MeasurementSpecificationType]>,
    ) -> Self {
        let common = self.0 & peer.0;
        if let Some(priority_table) = priority_table {
            for &priority in priority_table {
                let priority_spec: MeasurementSpecification = priority.into();
                if common & priority_spec.0 != 0 {
                    return MeasurementSpecification(priority_spec.0);
                }
            }
        } else {
            // If priority_table is None, we assume the default behavior
            // of returning the first common measurement specification.
            if common != 0 {
                return MeasurementSpecification(common & (!common + 1));
            }
        }

        MeasurementSpecification::default()
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

impl From<OpaqueDataFormatType> for OtherParamSupport {
    fn from(other_param_support_type: OpaqueDataFormatType) -> Self {
        match other_param_support_type {
            OpaqueDataFormatType::OpaqueDataFmt0 => OtherParamSupport(1 << 0),
            OpaqueDataFormatType::OpaqueDataFmt1 => OtherParamSupport(1 << 1),
        }
    }
}

impl Prioritize<OpaqueDataFormatType> for OtherParamSupport {
    fn prioritize(self, peer: Self, priority_table: Option<&[OpaqueDataFormatType]>) -> Self {
        let common = self.0 & peer.0;
        if let Some(priority_table) = priority_table {
            for &priority in priority_table {
                let priority_spec: OtherParamSupport = priority.into();
                if common & priority_spec.0 != 0 {
                    return OtherParamSupport(priority_spec.0);
                }
            }
        } else {
            // If priority_table is None, we assume the default behavior
            // of returning the first common other param support.
            if common != 0 {
                return OtherParamSupport(common & (!common + 1));
            }
        }

        OtherParamSupport::default()
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

// //TODO : check why is this not needed
// #[derive(Debug, Clone, Copy)]
// pub enum MeasurementHashAlgoType {
//     RawBitStream,
//     TpmAlgSha256,
//     TpmAlgSha384,
//     TpmAlgSha512,
//     TpmAlgSha3_256,
//     TpmAlgSha3_384,
//     TpmAlgSha3_512,
//     TpmAlgSm3_256,
// }

// impl From<MeasurementHashAlgoType> for MeasurementHashAlgo {
//     fn from(measurement_hash_algo_type: MeasurementHashAlgoType) -> Self {
//         match measurement_hash_algo_type {
//             MeasurementHashAlgoType::RawBitStream => MeasurementHashAlgo(1 << 0),
//             MeasurementHashAlgoType::TpmAlgSha256 => MeasurementHashAlgo(1 << 1),
//             MeasurementHashAlgoType::TpmAlgSha384 => MeasurementHashAlgo(1 << 2),
//             MeasurementHashAlgoType::TpmAlgSha512 => MeasurementHashAlgo(1 << 3),
//             MeasurementHashAlgoType::TpmAlgSha3_256 => MeasurementHashAlgo(1 << 4),
//             MeasurementHashAlgoType::TpmAlgSha3_384 => MeasurementHashAlgo(1 << 5),
//             MeasurementHashAlgoType::TpmAlgSha3_512 => MeasurementHashAlgo(1 << 6),
//             MeasurementHashAlgoType::TpmAlgSm3_256 => MeasurementHashAlgo(1 << 7),
//         }
//     }
// }

// impl Prioritize<MeasurementHashAlgoType> for MeasurementHashAlgo {
//     fn prioritize(self, peer: Self, priority_table: &[MeasurementHashAlgoType]) -> Self {
//         let common = self.0 & peer.0;
//         for &priority in priority_table {
//             let priority_spec: MeasurementHashAlgo = priority.into();
//             if common & priority_spec.0 != 0 {
//                 return MeasurementHashAlgo(priority_spec.0);
//             }
//         }
//         MeasurementHashAlgo::default()
//     }
// }

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

impl From<BaseAsymAlgoType> for BaseAsymAlgo {
    fn from(base_asym_algo_type: BaseAsymAlgoType) -> Self {
        match base_asym_algo_type {
            BaseAsymAlgoType::TpmAlgRsassa2048 => BaseAsymAlgo(1 << 0),
            BaseAsymAlgoType::TpmAlgRsapss2048 => BaseAsymAlgo(1 << 1),
            BaseAsymAlgoType::TpmAlgRsassa3072 => BaseAsymAlgo(1 << 2),
            BaseAsymAlgoType::TpmAlgRsapss3072 => BaseAsymAlgo(1 << 3),
            BaseAsymAlgoType::TpmAlgEcdsaEccNistP256 => BaseAsymAlgo(1 << 4),
            BaseAsymAlgoType::TpmAlgRsassa4096 => BaseAsymAlgo(1 << 5),
            BaseAsymAlgoType::TpmAlgRsapss4096 => BaseAsymAlgo(1 << 6),
            BaseAsymAlgoType::TpmAlgEcdsaEccNistP384 => BaseAsymAlgo(1 << 7),
            BaseAsymAlgoType::TpmAlgEcdsaEccNistP521 => BaseAsymAlgo(1 << 8),
            BaseAsymAlgoType::TpmAlgSm2EccSm2P256 => BaseAsymAlgo(1 << 9),
            BaseAsymAlgoType::EddsaEd25519 => BaseAsymAlgo(1 << 10),
            BaseAsymAlgoType::EddsaEd448 => BaseAsymAlgo(1 << 11),
        }
    }
}

impl Prioritize<BaseAsymAlgoType> for BaseAsymAlgo {
    fn prioritize(self, peer: Self, priority_table: Option<&[BaseAsymAlgoType]>) -> Self {
        let common = self.0 & peer.0;
        if let Some(priority_table) = priority_table {
            for &priority in priority_table {
                let priority_spec: BaseAsymAlgo = priority.into();
                if common & priority_spec.0 != 0 {
                    return BaseAsymAlgo(priority_spec.0);
                }
            }
        } else {
            // If priority_table is None, we assume the default behavior
            // of returning the first common base asym algo.
            if common != 0 {
                return BaseAsymAlgo(common & (!common + 1));
            }
        }

        BaseAsymAlgo::default()
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
    fn prioritize(self, peer: Self, priority_table: Option<&[BaseHashAlgoType]>) -> Self {
        let common = self.0 & peer.0;
        if let Some(priority_table) = priority_table {
            for &priority in priority_table {
                let priority_spec: BaseHashAlgo = priority.into();
                if common & priority_spec.0 != 0 {
                    return BaseHashAlgo(priority_spec.0);
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

impl From<MelSpecificationType> for MelSpecification {
    fn from(mel_specification_type: MelSpecificationType) -> Self {
        match mel_specification_type {
            MelSpecificationType::DmtfMelSpec => MelSpecification(1 << 0),
        }
    }
}

impl Prioritize<MelSpecificationType> for MelSpecification {
    fn prioritize(self, peer: Self, priority_table: Option<&[MelSpecificationType]>) -> Self {
        let common = self.0 & peer.0;
        if let Some(priority_table) = priority_table {
            for &priority in priority_table {
                let priority_spec: MelSpecification = priority.into();
                if common & priority_spec.0 != 0 {
                    return MelSpecification(priority_spec.0);
                }
            }
        } else {
            // If priority_table is None, we assume the default behavior
            // of returning the first common mel specification.
            if common != 0 {
                return MelSpecification(common & (!common + 1));
            }
        }
        MelSpecification::default()
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

impl From<DheGroupType> for DheNamedGroup {
    fn from(dhe_group_type: DheGroupType) -> Self {
        match dhe_group_type {
            DheGroupType::Ffdhe2048 => DheNamedGroup(1 << 0),
            DheGroupType::Ffdhe3072 => DheNamedGroup(1 << 1),
            DheGroupType::Ffdhe4096 => DheNamedGroup(1 << 2),
            DheGroupType::Secp256r1 => DheNamedGroup(1 << 3),
            DheGroupType::Secp384r1 => DheNamedGroup(1 << 4),
            DheGroupType::Secp521r1 => DheNamedGroup(1 << 5),
            DheGroupType::Sm2P256 => DheNamedGroup(1 << 6),
        }
    }
}

impl Prioritize<DheGroupType> for DheNamedGroup {
    fn prioritize(self, peer: Self, priority_table: Option<&[DheGroupType]>) -> Self {
        let common = self.0 & peer.0;
        if let Some(priority_table) = priority_table {
            for &priority in priority_table {
                let priority_spec: DheNamedGroup = priority.into();
                if common & priority_spec.0 != 0 {
                    return DheNamedGroup(priority_spec.0);
                }
            }
        } else {
            // If priority_table is None, we assume the default behavior
            // of returning the first common DHE group.
            if common != 0 {
                return DheNamedGroup(common & (!common + 1));
            }
        }
        DheNamedGroup::default()
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

impl From<AeadCipherSuiteType> for AeadCipherSuite {
    fn from(aead_cipher_suite_type: AeadCipherSuiteType) -> Self {
        match aead_cipher_suite_type {
            AeadCipherSuiteType::Aes128Gcm => AeadCipherSuite(1 << 0),
            AeadCipherSuiteType::Aes256Gcm => AeadCipherSuite(1 << 1),
            AeadCipherSuiteType::Chacha20Poly1305 => AeadCipherSuite(1 << 2),
            AeadCipherSuiteType::AeadSm4Gcm => AeadCipherSuite(1 << 3),
        }
    }
}

impl Prioritize<AeadCipherSuiteType> for AeadCipherSuite {
    fn prioritize(self, peer: Self, priority_table: Option<&[AeadCipherSuiteType]>) -> Self {
        let common = self.0 & peer.0;
        if let Some(priority_table) = priority_table {
            for &priority in priority_table {
                let priority_spec: AeadCipherSuite = priority.into();
                if common & priority_spec.0 != 0 {
                    return AeadCipherSuite(priority_spec.0);
                }
            }
        } else {
            // If priority_table is None, we assume the default behavior
            // of returning the first common AEAD cipher suite.
            if common != 0 {
                return AeadCipherSuite(common & (!common + 1));
            }
        }
        AeadCipherSuite::default()
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

impl From<ReqBaseAsymAlgType> for ReqBaseAsymAlg {
    fn from(req_base_asym_alg_type: ReqBaseAsymAlgType) -> Self {
        match req_base_asym_alg_type {
            ReqBaseAsymAlgType::TpmAlgRsaSsa2048 => ReqBaseAsymAlg(1 << 0),
            ReqBaseAsymAlgType::TpmAlgRsaPss2048 => ReqBaseAsymAlg(1 << 1),
            ReqBaseAsymAlgType::TpmAlgRsaSsa3072 => ReqBaseAsymAlg(1 << 2),
            ReqBaseAsymAlgType::TpmAlgRsaPss3072 => ReqBaseAsymAlg(1 << 3),
            ReqBaseAsymAlgType::TpmAlgEcdsaEccNistP256 => ReqBaseAsymAlg(1 << 4),
            ReqBaseAsymAlgType::TpmAlgRsaSsa4096 => ReqBaseAsymAlg(1 << 5),
            ReqBaseAsymAlgType::TpmAlgRsaPss4096 => ReqBaseAsymAlg(1 << 6),
            ReqBaseAsymAlgType::TpmAlgEcdsaEccNistP384 => ReqBaseAsymAlg(1 << 7),
            ReqBaseAsymAlgType::TpmAlgEcdsaEccNistP521 => ReqBaseAsymAlg(1 << 8),
            ReqBaseAsymAlgType::TpmAlgSm2EccSm2P256 => ReqBaseAsymAlg(1 << 9),
            ReqBaseAsymAlgType::EddsaEd25519 => ReqBaseAsymAlg(1 << 10),
            ReqBaseAsymAlgType::EddsaEd448 => ReqBaseAsymAlg(1 << 11),
        }
    }
}

impl Prioritize<ReqBaseAsymAlgType> for ReqBaseAsymAlg {
    fn prioritize(self, peer: Self, priority_table: Option<&[ReqBaseAsymAlgType]>) -> Self {
        let common = self.0 & peer.0;
        if let Some(priority_table) = priority_table {
            for &priority in priority_table {
                let priority_spec: ReqBaseAsymAlg = priority.into();
                if common & priority_spec.0 != 0 {
                    return ReqBaseAsymAlg(priority_spec.0);
                }
            }
        } else {
            // If priority_table is None, we assume the default behavior
            // of returning the first common request base asym algorithm.
            if common != 0 {
                return ReqBaseAsymAlg(common & (!common + 1));
            }
        }
        ReqBaseAsymAlg::default()
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

impl From<KeyScheduleType> for KeySchedule {
    fn from(key_schedule_type: KeyScheduleType) -> Self {
        match key_schedule_type {
            KeyScheduleType::SpdmKeySchedule => KeySchedule(1 << 0),
        }
    }
}

impl Prioritize<KeyScheduleType> for KeySchedule {
    fn prioritize(self, peer: Self, priority_table: Option<&[KeyScheduleType]>) -> Self {
        let common = self.0 & peer.0;
        if let Some(priority_table) = priority_table {
            for &priority in priority_table {
                let priority_spec: KeySchedule = priority.into();
                if common & priority_spec.0 != 0 {
                    return KeySchedule(priority_spec.0);
                }
            }
        } else {
            // If priority_table is None, we assume the default behavior
            // of returning the first common key schedule.
            if common != 0 {
                return KeySchedule(common & (!common + 1));
            }
        }
        KeySchedule::default()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum KeyScheduleType {
    // SPDM Key Schedule
    SpdmKeySchedule,
}

#[derive(Debug, Clone, Copy, Default)]
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

impl DeviceAlgorithms {
    pub fn num_alg_struct_tables(&self) -> usize {
        let mut num = 0;
        if self.dhe_group.0.count_ones() > 0 {
            num += 1;
        }
        if self.aead_cipher_suite.0.count_ones() > 0 {
            num += 1;
        }
        if self.req_base_asym_algo.0.count_ones() > 0 {
            num += 1;
        }
        if self.key_schedule.0.count_ones() > 0 {
            num += 1;
        }
        num
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

pub(crate) fn validate_device_algorithms(
    local_device_algorithms: &LocalDeviceAlgorithms,
) -> SpdmResult<()> {
    let local_algorithms = &local_device_algorithms.device_algorithms;

    // If responder supports the measurements, then exactly one bit should be set in the MeasurementHashAlgo
    let measurement_hash_algo = local_algorithms.measurement_hash_algo;
    if measurement_hash_algo.0.count_ones() > 1 {
        return Err(SpdmError::InvalidParam);
    }

    Ok(())
}

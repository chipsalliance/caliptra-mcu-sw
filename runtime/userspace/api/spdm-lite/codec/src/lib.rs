// Licensed under the Apache-2.0 license

//! Zero-copy SPDM PDU codec for SPDM-Lite.

#![no_std]
#![forbid(unsafe_code)]

mod algorithms;
mod builder;
mod capabilities;
mod certificate;
mod challenge;
mod digests;
pub mod errors;
mod flag_macros;
mod header;
mod set_certificate;
mod version;
mod wire;

pub use algorithms::{
    alg_type, AeadAlgos, AlgStructEntry, AlgorithmsRsp, AlgorithmsRspBodyFixed, AsymAlgos,
    DheAlgos, HashAlgos, KeyScheduleAlgos, MeasHashAlgos, MeasSpec,
    NegotiateAlgorithmsReqBodyFixed, OtherParamSupport, MAX_ALG_STRUCT_ENTRIES,
};
pub use builder::ResponseBody;
pub use capabilities::{CapFlags, CapabilitiesBody, CapabilitiesRsp};
pub use certificate::{
    CertificateRsp, CertificateRspBody, GetCertificateReqBody, ATTR_SLOT_SIZE_REQUESTED,
};
pub use challenge::{ChallengeAuthRsp, ChallengeReqBody};
pub use digests::{DigestsRsp, DigestsRspBody};
pub use header::{
    ReqRespCode, SpdmMsgHdrPdu, ECC_P384_SIGNATURE_SIZE, REQUESTER_CONTEXT_LEN, SHA384_HASH_SIZE,
    SPDM_CONTEXT_LEN, SPDM_MSG_HDR_SIZE, SPDM_NONCE_LEN, SPDM_PREFIX_LEN, SPDM_SIGNING_CONTEXT_LEN,
};
pub use set_certificate::{SetCertificateReqBody, SetCertificateRsp, SetCertificateRspBody};
pub use version::{SpdmVersion, VersionNumberEntry, VersionRsp, VersionRspBody};
pub use wire::{WireError, WireReader, WireWriter};

// Licensed under the Apache-2.0 license

//! Zero-copy SPDM PDU codec for SPDM-Lite.

#![no_std]
#![forbid(unsafe_code)]

mod algorithms;
mod builder;
mod capabilities;
mod certificate;
mod digests;
pub mod errors;
mod flag_macros;
mod header;
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
pub use digests::{DigestsRsp, DigestsRspBody};
pub use header::{ReqRespCode, SpdmMsgHdrPdu, SPDM_MSG_HDR_SIZE};
pub use version::{SpdmVersion, VersionNumberEntry, VersionRsp, VersionRspBody};
pub use wire::{WireError, WireReader, WireWriter};

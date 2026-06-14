// Licensed under the Apache-2.0 license

//! Zero-copy SPDM PDU codec for SPDM-Lite.

#![no_std]
#![forbid(unsafe_code)]

mod algorithms;
mod builder;
mod capabilities;
mod certificate;
mod challenge;
mod chunk;
mod digests;
mod end_session;
pub mod errors;
mod finish;
mod flag_macros;
mod header;
mod key_exchange;
mod measurements;
mod opaque;
mod secured_message;
mod set_certificate;
mod vendor_defined;
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
pub use chunk::{
    ChunkGetReqBody, ChunkResponseBody, ChunkSendAckBody, ChunkSendReqBody,
    CHUNK_ACK_ATTR_EARLY_ERROR, CHUNK_ATTR_LAST_CHUNK, CHUNK_RESPONSE_FIXED_BODY_SIZE,
    LARGE_RESPONSE_SIZE_FIELD_SIZE,
};
pub use digests::{DigestsRsp, DigestsRspBody};
pub use end_session::{EndSessionAck, EndSessionReqBody};
pub use finish::{FinishReqBody, FinishRsp};
pub use header::{
    ReqRespCode, SpdmMsgHdrPdu, ECC_P384_SIGNATURE_SIZE, REQUESTER_CONTEXT_LEN, SHA384_HASH_SIZE,
    SPDM_CONTEXT_LEN, SPDM_MSG_HDR_SIZE, SPDM_NONCE_LEN, SPDM_PREFIX_LEN, SPDM_SIGNING_CONTEXT_LEN,
};
pub use key_exchange::{
    KeyExchangeReqBody, KeyExchangeRsp, ECDH_P384_EXCHANGE_DATA_SIZE, KEY_EXCHANGE_RANDOM_DATA_LEN,
};
pub use measurements::{
    DmtfMeasurementBlockHeader, GetMeasurementsReqBody, MeasurementsRsp, MEAS_BLOCK_METADATA_SIZE,
    SPDM_MAX_MEASUREMENT_RECORD_SIZE,
};
pub use set_certificate::{SetCertificateReqBody, SetCertificateRsp, SetCertificateRspBody};
pub use vendor_defined::{
    decode_vendor_defined_req, StandardsBodyId, VendorDefinedReq, VendorDefinedReqPdu,
    VendorDefinedRspBody, VendorDefinedRspPdu,
};
pub use version::{SpdmVersion, VersionNumberEntry, VersionRsp, VersionRspBody};
pub use wire::{WireError, WireReader, WireWriter};

pub use opaque::{
    encode_version_selection, parse_supported_versions, select_version, SmVersion,
    SupportedVersions, OPAQUE_VERSION_SELECTION_SIZE,
};
pub use secured_message::{
    encode_aad, SecuredMessageHeader, AES_256_GCM_TAG_SIZE, SECURED_MSG_HDR_SIZE,
};

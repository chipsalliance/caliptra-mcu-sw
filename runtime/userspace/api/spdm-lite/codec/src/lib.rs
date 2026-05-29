// Licensed under the Apache-2.0 license

//! Zero-copy SPDM PDU codec for SPDM-Lite.

#![no_std]
#![forbid(unsafe_code)]

mod algorithms;
mod builder;
mod capabilities;
mod certificate;
mod chunk;
mod digests;
pub mod errors;
mod flag_macros;
mod header;
mod ide_km;
mod pci_sig;
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
pub use chunk::{
    ChunkGetReqBody, ChunkSendReqBody, CHUNK_ACK_ATTR_EARLY_ERROR, CHUNK_ATTR_LAST_CHUNK,
    CHUNK_RESPONSE_FIXED_BODY_SIZE, LARGE_RESPONSE_SIZE_FIELD_SIZE,
};
pub use digests::{DigestsRsp, DigestsRspBody};
pub use header::{ReqRespCode, SpdmMsgHdrPdu, SPDM_MSG_HDR_SIZE};
pub use ide_km::{
    AddrAssociationRegBlock, IdeAddrAssociationReg1, IdeAddrAssociationReg2,
    IdeAddrAssociationReg3, IdeCapabilityReg, IdeControlReg, IdeKmCommand, IdeKmHdr, IdeRegBlock,
    KeyData, KeyInfo, KeyProg, KeySetGoStop, LinkIdeStreamControlReg, LinkIdeStreamRegBlock,
    LinkIdeStreamStatusReg, PortConfig, Query, SelectiveIdeRidAssociationReg1,
    SelectiveIdeRidAssociationReg2, SelectiveIdeStreamCapabilityReg, SelectiveIdeStreamControlReg,
    SelectiveIdeStreamRegBlock, SelectiveIdeStreamStatusReg, IDE_KM_PROTOCOL_ID,
    IDE_STREAM_IV_SIZE_DW, IDE_STREAM_KEY_SIZE_DW, MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT,
};
pub use pci_sig::PciSigProtocolHdr;
pub use vendor_defined::{StandardsBodyId, VendorDefinedReqPdu, VendorDefinedRspPdu};
pub use version::{SpdmVersion, VersionNumberEntry, VersionRsp, VersionRspBody};
pub use wire::{WireError, WireReader, WireWriter};

// Licensed under the Apache-2.0 license

use crate::codec::CommonCodec;
use crate::error::{SpdmError, SpdmResult};
use crate::protocol::version::SpdmVersion;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const NONCE_LEN: usize = 32;

pub const REQUESTER_CONTEXT_LEN: usize = 8;

#[derive(Debug, Clone, Copy)]
pub(crate) enum ReqRespCode {
    GetVersion = 0x84,
    Version = 0x04,
    GetCapabilities = 0xE1,
    Capabilities = 0x61,
    NegotiateAlgorithms = 0xE3,
    Algorithms = 0x63,
    GetDigests = 0x81,
    Digests = 0x01,
    GetCertificate = 0x82,
    Certificate = 0x02,
    Challenge = 0x83,
    ChallengeAuth = 0x03,
    Error = 0x7F,
}

impl TryFrom<u8> for ReqRespCode {
    type Error = SpdmError;
    fn try_from(value: u8) -> Result<Self, SpdmError> {
        match value {
            0x84 => Ok(ReqRespCode::GetVersion),
            0x04 => Ok(ReqRespCode::Version),
            0xE1 => Ok(ReqRespCode::GetCapabilities),
            0x61 => Ok(ReqRespCode::Capabilities),
            0xE3 => Ok(ReqRespCode::NegotiateAlgorithms),
            0x63 => Ok(ReqRespCode::Algorithms),
            0x81 => Ok(ReqRespCode::GetDigests),
            0x01 => Ok(ReqRespCode::Digests),
            0x82 => Ok(ReqRespCode::GetCertificate),
            0x02 => Ok(ReqRespCode::Certificate),
            0x83 => Ok(ReqRespCode::Challenge),
            0x03 => Ok(ReqRespCode::ChallengeAuth),
            0x7F => Ok(ReqRespCode::Error),
            _ => Err(SpdmError::UnsupportedRequest),
        }
    }
}

impl From<ReqRespCode> for u8 {
    fn from(code: ReqRespCode) -> Self {
        code as u8
    }
}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct SpdmMsgHdr {
    version: u8,
    req_resp_code: u8,
}

impl SpdmMsgHdr {
    pub(crate) fn new(version: SpdmVersion, req_resp_code: ReqRespCode) -> Self {
        Self {
            version: version.into(),
            req_resp_code: req_resp_code.into(),
        }
    }

    pub(crate) fn version(&self) -> SpdmResult<SpdmVersion> {
        self.version.try_into()
    }

    pub(crate) fn req_resp_code(&self) -> SpdmResult<ReqRespCode> {
        self.req_resp_code.try_into()
    }
}

impl CommonCodec for SpdmMsgHdr {
    // const DATA_KIND: DataKind = DataKind::Header;
}

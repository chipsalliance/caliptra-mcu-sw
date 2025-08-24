// Licensed under the Apache-2.0 license

use crate::codec::CommonCodec;
use crate::error::{SpdmError, SpdmResult};
use crate::protocol::{version::SpdmVersion, REQUESTER_CONTEXT_LEN, SPDM_CONTEXT_LEN};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(Debug, Clone, Copy, PartialEq)]
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
    GetMeasurements = 0xE0,
    Measurements = 0x60,
    ChunkGet = 0x86,
    ChunkResponse = 0x06,
    KeyExchange = 0xE4,
    KeyExchangeRsp = 0x64,
    Finish = 0xE5,
    FinishRsp = 0x65,
    EndSession = 0xEC,
    EndSessionAck = 0x6C,
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
            0xE0 => Ok(ReqRespCode::GetMeasurements),
            0x60 => Ok(ReqRespCode::Measurements),
            0x86 => Ok(ReqRespCode::ChunkGet),
            0x06 => Ok(ReqRespCode::ChunkResponse),
            0x7F => Ok(ReqRespCode::Error),
            0xE4 => Ok(ReqRespCode::KeyExchange),
            0xE5 => Ok(ReqRespCode::Finish),
            0x65 => Ok(ReqRespCode::FinishRsp),
            0xEC => Ok(ReqRespCode::EndSession),
            0x6C => Ok(ReqRespCode::EndSessionAck),
            _ => Err(SpdmError::UnsupportedRequest),
        }
    }
}

impl From<ReqRespCode> for u8 {
    fn from(code: ReqRespCode) -> Self {
        code as u8
    }
}

impl ReqRespCode {
    pub(crate) fn spdm_context_string(&self) -> SpdmResult<[u8; SPDM_CONTEXT_LEN]> {
        let mut context = [0u8; SPDM_CONTEXT_LEN];
        let ctx_str = match self {
            ReqRespCode::ChallengeAuth => "responder-challenge_auth signing",
            ReqRespCode::Measurements => "responder-measurements signing",
            ReqRespCode::KeyExchangeRsp => "responder-key_exchange_rsp signing",
            _ => return Err(SpdmError::UnsupportedRequest),
        };

        if ctx_str.len() > SPDM_CONTEXT_LEN {
            return Err(SpdmError::InvalidParam);
        }
        let zero_pad_size = SPDM_CONTEXT_LEN - ctx_str.len();
        context[zero_pad_size..].copy_from_slice(ctx_str.as_bytes());

        Ok(context)
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

impl CommonCodec for SpdmMsgHdr {}

// Requester context (used for SPDM 1.3 and later versions)
#[derive(FromBytes, IntoBytes, Immutable, Debug)]
#[repr(C)]
pub(crate) struct RequesterContext([u8; REQUESTER_CONTEXT_LEN]);
impl CommonCodec for RequesterContext {}

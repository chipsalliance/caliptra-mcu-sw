// Licensed under the Apache-2.0 license

use crate::codec::CommonCodec;
use crate::error::{SpdmError, SpdmResult};
use crate::protocol::version::SpdmVersion;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const NONCE_LEN: usize = 32;

pub const REQUESTER_CONTEXT_LEN: usize = 8;

// This is the `combined_spdm_prefix` length for signing context
pub const SPDM_SIGNING_CONTEXT_LEN: usize = SPDM_PREFIX_LEN + SPDM_CONTEXT_LEN;

const SPDM_PREFIX_LEN: usize = 64;
const SPDM_CONTEXT_LEN: usize = 36;

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

impl ReqRespCode {
    pub(crate) fn spdm_context_string(&self) -> SpdmResult<[u8; SPDM_CONTEXT_LEN]> {
        let mut context = [0u8; SPDM_CONTEXT_LEN];
        match self {
            ReqRespCode::ChallengeAuth => {
                let ctx_str = "responder-challenge_auth signing";
                if ctx_str.len() > SPDM_CONTEXT_LEN {
                    Err(SpdmError::InvalidParam)?;
                }
                let zero_pad_size = SPDM_CONTEXT_LEN - ctx_str.len();
                context[zero_pad_size..].copy_from_slice(ctx_str.as_bytes());
            }
            _ => {
                Err(SpdmError::UnsupportedRequest)?;
            }
        }
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

pub(crate) fn create_responder_signing_context(
    spdm_version: SpdmVersion,
    opcode: ReqRespCode,
) -> SpdmResult<[u8; SPDM_SIGNING_CONTEXT_LEN]> {
    if spdm_version < SpdmVersion::V12 {
        Err(SpdmError::UnsupportedVersion)?;
    }

    let mut combined_spdm_prefix = [0u8; SPDM_SIGNING_CONTEXT_LEN];

    let base_str = b"dmtf-spdm-v";
    let version_str = spdm_version.to_str().as_bytes();
    let mut spdm_prefix = [0u8; SPDM_PREFIX_LEN];

    let mut pos = 0;
    for _ in 0..4 {
        spdm_prefix[pos..pos + base_str.len()].copy_from_slice(base_str);
        pos += base_str.len();
        spdm_prefix[pos..pos + version_str.len()].copy_from_slice(version_str);
        pos += version_str.len();
        if pos % 16 != 0 {
            Err(SpdmError::BufferTooSmall)?;
        }
    }

    let spdm_context = opcode.spdm_context_string()?;
    combined_spdm_prefix[..SPDM_PREFIX_LEN].copy_from_slice(&spdm_prefix);
    combined_spdm_prefix[SPDM_PREFIX_LEN..].copy_from_slice(&spdm_context);

    Ok(combined_spdm_prefix)
}

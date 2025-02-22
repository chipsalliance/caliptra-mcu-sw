// Licensed under the Apache-2.0 license

use crate::codec::{Codec, CodecError, CodecResult, MessageBuf};
use crate::error::{SpdmError, SpdmResult};
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const MAX_SPDM_MSG_SIZE: usize = 1024;
pub const MAX_NUM_SUPPORTED_SPDM_VERSIONS: usize = 2;
pub const MAX_SUPORTED_VERSION: SpdmVersion = SpdmVersion::V13;

#[derive(Debug, Default, PartialEq, Clone, Copy, PartialOrd)]
pub enum SpdmVersion {
    #[default]
    V10,
    V11,
    V12,
    V13,
}

impl TryFrom<u8> for SpdmVersion {
    type Error = SpdmError;
    fn try_from(value: u8) -> Result<Self, SpdmError> {
        match value {
            0x10 => Ok(SpdmVersion::V10),
            0x11 => Ok(SpdmVersion::V11),
            0x12 => Ok(SpdmVersion::V12),
            0x13 => Ok(SpdmVersion::V13),
            _ => Err(SpdmError::UnsupportedVersion),
        }
    }
}

impl From<SpdmVersion> for u8 {
    fn from(version: SpdmVersion) -> Self {
        version.to_u8()
    }
}

impl SpdmVersion {
    fn to_u8(self) -> u8 {
        match self {
            SpdmVersion::V10 => 0x10,
            SpdmVersion::V11 => 0x11,
            SpdmVersion::V12 => 0x12,
            SpdmVersion::V13 => 0x13,
        }
    }

    pub fn major(&self) -> u8 {
        self.to_u8() >> 4
    }

    pub fn minor(&self) -> u8 {
        self.to_u8() & 0x0F
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ReqRespCode {
    GetVersion = 0x84,
    Version = 0x04,
    Error = 0x7F,
}

impl TryFrom<u8> for ReqRespCode {
    type Error = SpdmError;
    fn try_from(value: u8) -> Result<Self, SpdmError> {
        match value {
            0x84 => Ok(ReqRespCode::GetVersion),
            0x04 => Ok(ReqRespCode::Version),
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
    pub fn response_code(&self) -> SpdmResult<ReqRespCode> {
        match self {
            ReqRespCode::GetVersion => Ok(ReqRespCode::Version),
            ReqRespCode::Error => Ok(ReqRespCode::Error),
            _ => Err(SpdmError::UnsupportedRequest),
        }
    }
}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub struct SpdmMsgHdr {
    version: u8,
    req_resp_code: u8,
}

impl SpdmMsgHdr {
    pub fn new(version: SpdmVersion, req_resp_code: ReqRespCode) -> Self {
        Self {
            version: version.into(),
            req_resp_code: req_resp_code.into(),
        }
    }

    pub fn set_version(&mut self, version: SpdmVersion) {
        self.version = version.into();
    }

    pub fn set_req_resp_code(&mut self, req_resp_code: ReqRespCode) {
        self.req_resp_code = req_resp_code.into();
    }

    pub fn version(&self) -> SpdmResult<SpdmVersion> {
        self.version.try_into()
    }

    pub fn req_resp_code(&self) -> SpdmResult<ReqRespCode> {
        self.req_resp_code.try_into()
    }
}

impl Codec for SpdmMsgHdr {
    fn encode(&self, buf: &mut MessageBuf) -> CodecResult<usize> {
        let len = core::mem::size_of::<Self>();
        buf.push_data(len)?;
        let header = buf.data_mut(len)?;
        self.write_to(header).map_err(|_| CodecError::WriteError)?;

        Ok(len)
    }

    fn decode(buf: &mut MessageBuf) -> CodecResult<Self> {
        let len = core::mem::size_of::<Self>();
        if buf.data_len() < len {
            Err(CodecError::BufferTooSmall)?;
        }
        let hdr_bytes = buf.data(len)?;

        let hdr = SpdmMsgHdr::read_from_bytes(hdr_bytes).map_err(|_| CodecError::ReadError)?;
        buf.pull_data(len)?;
        Ok(hdr)
    }
}

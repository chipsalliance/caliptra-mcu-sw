// Licensed under the Apache-2.0 license

use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::message_buf::{Codec, CodecError, CodecResult, MessageBuf};
use crate::req_resp_codes::ReqRespCode;
use crate::version_rsp::SpdmVersion;

pub const SPDM_MSG_HEADER_SIZE: usize = 2;

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

    pub fn version(&self) -> SpdmVersion {
        self.version.into()
    }

    pub fn req_resp_code(&self) -> ReqRespCode {
        // assert!(self.req_resp_code != 0);
        self.req_resp_code.into()
    }
}

impl Codec for SpdmMsgHdr {
    fn encode(&self, buf: &mut MessageBuf) -> CodecResult<usize> {
        let len = core::mem::size_of::<Self>();

        buf.push_data(len)?;

        let header = buf.data_mut(len)?;

        let mut buf_hdr: SpdmMsgHdr =
            SpdmMsgHdr::read_from_bytes(header).map_err(|_| CodecError::ReadError)?;
        buf_hdr.set_version(self.version());
        buf_hdr.set_req_resp_code(self.req_resp_code());

        Ok(len)
    }

    fn decode(buf: &mut MessageBuf) -> CodecResult<Self> {
        let len = core::mem::size_of::<Self>();
        if buf.len() < len {
            Err(CodecError::BufferTooSmall)?;
        }
        let hdr_bytes = buf.data(len)?;

        let hdr = SpdmMsgHdr::read_from_bytes(hdr_bytes).map_err(|_| CodecError::ReadError)?;
        assert!(hdr.version == 0x10);
        buf.pull_data(len)?;
        Ok(hdr)
    }
}

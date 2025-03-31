// Licensed under the Apache-2.0 license

use crate::cert_mgr::{
    SpdmCertChainBaseBuffer, SpdmCertChainData, SpdmDigest, SPDM_MAX_CERT_CHAIN_SLOTS,
    SPDM_MAX_HASH_SIZE,
};
use crate::codec::{Codec, CodecError, CodecResult, CommonCodec, DataKind, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::config;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult, SpdmError, SpdmResult};
use crate::protocol::algorithms::BaseHashAlgoType;
use crate::protocol::common::SpdmMsgHdr;
use crate::state::ConnectionState;
use libtock_platform::Syscalls;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C)]
pub struct GetDigestsReq {
    param1: u8,
    param2: u8,
}

impl CommonCodec for GetDigestsReq {
    const DATA_KIND: DataKind = DataKind::Payload;
}

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C)]
pub struct GetDigestsRespCommon {
    pub param1: u8,
    pub slot_mask: u8,
}

impl CommonCodec for GetDigestsRespCommon {
    const DATA_KIND: DataKind = DataKind::Payload;
}

pub struct GetDigestsResp {
    pub common: GetDigestsRespCommon,
    pub digests: [SpdmDigest; SPDM_MAX_CERT_CHAIN_SLOTS],
}

impl Default for GetDigestsResp {
    fn default() -> Self {
        Self {
            common: GetDigestsRespCommon::default(),
            digests: core::array::from_fn(|_| SpdmDigest::default()),
        }
    }
}

impl GetDigestsResp {
    pub fn new(slot_mask: u8, digests: &[SpdmDigest]) -> Self {
        let mut resp = Self::default();
        resp.common.slot_mask = slot_mask;
        let slot_cnt = slot_mask.count_ones() as usize;
        for (i, digest) in digests.iter().enumerate().take(slot_cnt) {
            resp.digests[i] = digest.clone();
        }
        resp
    }
}

impl Codec for GetDigestsResp {
    fn encode(&self, buffer: &mut MessageBuf) -> CodecResult<usize> {
        let mut len = self.common.encode(buffer)?;
        let slot_cnt = self.common.slot_mask.count_ones() as usize;
        for digest in self.digests.iter().take(slot_cnt) {
            len += digest.encode(buffer)?;
        }
        Ok(len)
    }

    fn decode(_data: &mut MessageBuf) -> CodecResult<Self> {
        // Decoding is not required for SPDM responder
        unimplemented!()
    }
}

impl Codec for SpdmDigest {
    fn encode(&self, buffer: &mut MessageBuf) -> CodecResult<usize> {
        let hash_len = self.length.min(SPDM_MAX_HASH_SIZE as u8);
        // iterates over the data and encode into the buffer
        buffer.put_data(hash_len.into())?;

        if buffer.data_len() < hash_len.into() {
            Err(CodecError::BufferTooSmall)?;
        }

        let payload = buffer.data_mut(hash_len.into())?;

        self.data[..hash_len as usize]
            .write_to(payload)
            .map_err(|_| CodecError::WriteError)?;
        buffer.pull_data(hash_len.into())?;
        Ok(hash_len.into())
    }

    fn decode(_data: &mut MessageBuf) -> CodecResult<Self> {
        // Decoding is not required for SPDM responder
        unimplemented!()
    }
}

pub(crate) fn handle_digests<'a, S: Syscalls>(
    ctx: &mut SpdmContext<'a, S>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Validate the state
    if ctx.state.connection_info.state() < ConnectionState::AfterNegotiateAlgorithms {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    // Validate the version
    let connection_version = ctx.state.connection_info.version_number();
    match spdm_hdr.version() {
        Ok(version) if version == connection_version => {}
        _ => Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?,
    }

    let req = GetDigestsReq::decode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    // Reserved fields must be zero - or unexpected request error
    if req.param1 != 0 || req.param2 != 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    // Check if the certificate capability is supported
    if ctx.local_capabilities.flags.cert_cap() == 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnsupportedRequest, 0, None))?;
    }

    // TODO: transcript manager and session support

    let hash_algo = ctx
        .get_select_hash_algo()
        .map_err(|_| ctx.generate_error_response(req_payload, ErrorCode::Unspecified, 0, None))?;

    let slot_mask = config::CERT_CHAIN_SLOT_MASK;
    let mut digest = SpdmDigest::default();

    // Get the digest of the certificate chain 0
    get_certificate_chain_digest(ctx, hash_algo, &mut digest)
        .map_err(|_| ctx.generate_error_response(req_payload, ErrorCode::Unspecified, 0, None))?;

    // Prepare the response buffer
    ctx.prepare_response_buffer(req_payload)?;

    // Fill the response buffer
    fill_digests_response(ctx, slot_mask, &[digest], req_payload)?;

    if ctx.state.connection_info.state() < ConnectionState::AfterDigest {
        ctx.state
            .connection_info
            .set_state(ConnectionState::AfterDigest);
    }

    Ok(())
}

fn fill_digests_response<S: Syscalls>(
    ctx: &SpdmContext<S>,
    slot_mask: u8,
    digests: &[SpdmDigest],
    rsp: &mut MessageBuf,
) -> CommandResult<()> {
    // Construct the response
    let resp = GetDigestsResp::new(slot_mask, digests);

    let payload_len = resp
        .encode(rsp)
        .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None))?;

    // Push data offset up by total payload length
    rsp.push_data(payload_len)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    Ok(())
}

fn get_certificate_chain_digest<S: Syscalls>(
    ctx: &mut SpdmContext<S>,
    hash_type: BaseHashAlgoType,
    digest: &mut SpdmDigest,
) -> SpdmResult<()> {
    let mut cert_chain_data = SpdmCertChainData::default();
    let mut root_hash = SpdmDigest::default();

    let root_cert_len = ctx
        .device_certs_manager
        .get_certificate_chain_data(&mut cert_chain_data)?;

    // Get the hash of root_cert
    ctx.hash_engine
        .hash_all(
            &cert_chain_data.as_ref()[..root_cert_len],
            hash_type,
            &mut root_hash,
        )
        .map_err(SpdmError::HashEngine)?;

    // Construct the cert chain base buffer
    let cert_chain_base_buf =
        SpdmCertChainBaseBuffer::new(cert_chain_data.length as usize, root_hash.as_ref())?;

    // Start the hash operation
    ctx.hash_engine
        .start(hash_type)
        .map_err(SpdmError::HashEngine)?;

    // Hash the cert chain base
    ctx.hash_engine
        .update(cert_chain_base_buf.as_ref())
        .map_err(SpdmError::HashEngine)?;

    // Hash the cert chain data
    ctx.hash_engine
        .update(cert_chain_data.as_ref())
        .map_err(SpdmError::HashEngine)?;

    // Finalize the hash operation
    ctx.hash_engine
        .finish(digest)
        .map_err(SpdmError::HashEngine)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_encode_digests_response() {
        let slot_mask = 0b00000011; // Two slots enabled
        let digest1 = SpdmDigest::new(&[0xAA; SPDM_MAX_HASH_SIZE]);
        let digest2 = SpdmDigest::new(&[0xBB; SPDM_MAX_HASH_SIZE]);
        let digests = [digest1, digest2];

        let resp = GetDigestsResp::new(slot_mask, &digests);
        let mut bytes = [0u8; 1024];
        let mut buffer = MessageBuf::new(&mut bytes);
        let encode_result = resp.encode(&mut buffer);

        assert!(encode_result.is_ok());
        let encoded_len = encode_result.unwrap();
        assert_eq!(encoded_len, buffer.msg_len());
        assert_eq!(encoded_len, buffer.data_offset());

        // Verify the encoded data
        let expected_len = 2 + (SPDM_MAX_HASH_SIZE * 2);
        assert_eq!(encoded_len, expected_len);

        // Verify the contents in the message buffer
        assert_eq!(buffer.total_message()[0], 0); // param1
        assert_eq!(buffer.total_message()[1], slot_mask); // slot_mask
        assert_eq!(
            buffer.total_message()[2..2 + SPDM_MAX_HASH_SIZE],
            [0xAA; SPDM_MAX_HASH_SIZE]
        ); // digest1
        assert_eq!(
            buffer.total_message()[2 + SPDM_MAX_HASH_SIZE..],
            [0xBB; SPDM_MAX_HASH_SIZE]
        ); // digest2
    }
}

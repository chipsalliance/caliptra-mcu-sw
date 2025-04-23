// Licensed under the Apache-2.0 license

use crate::cert_mgr::{SPDM_MAX_CERT_CHAIN_SLOTS, SPDM_MAX_HASH_SIZE};
use crate::codec::{Codec, CodecError, CodecResult, CommonCodec, DataKind, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::common::SpdmMsgHdr;
use crate::state::ConnectionState;
use libapi_caliptra::crypto::hash::HashAlgoType;
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
    pub supported_slot_mask: u8,   // param1: introduced in v13
    pub provisioned_slot_mask: u8, // param2
}

impl CommonCodec for GetDigestsRespCommon {
    const DATA_KIND: DataKind = DataKind::Payload;
}

#[derive(Debug, Clone)]
pub struct SpdmDigest {
    pub data: [u8; SPDM_MAX_HASH_SIZE],
    pub length: u8,
}

impl Default for SpdmDigest {
    fn default() -> Self {
        Self {
            data: [0u8; SPDM_MAX_HASH_SIZE],
            length: 0u8,
        }
    }
}
impl AsRef<[u8]> for SpdmDigest {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.length as usize]
    }
}

impl SpdmDigest {
    pub fn new(digest: &[u8]) -> Self {
        let mut data = [0u8; SPDM_MAX_HASH_SIZE];
        let length = digest.len().min(SPDM_MAX_HASH_SIZE);
        data[..length].copy_from_slice(&digest[..length]);
        Self {
            data,
            length: length as u8,
        }
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

// TODO: Add key_pair_id, cert_info, and key_usage_bit_mask if needed
pub struct GetDigestsResp<'a> {
    pub common: GetDigestsRespCommon,
    pub digests: &'a [SpdmDigest],
}

impl<'a> GetDigestsResp<'a> {
    pub fn new(
        supported_slot_mask: u8,
        provisioned_slot_mask: u8,
        digests: &'a [SpdmDigest],
    ) -> Self {
        Self {
            common: GetDigestsRespCommon {
                supported_slot_mask,
                provisioned_slot_mask,
            },
            digests,
        }
    }
}

impl<'a> Codec for GetDigestsResp<'a> {
    fn encode(&self, buffer: &mut MessageBuf) -> CodecResult<usize> {
        let mut len = self.common.encode(buffer)?;
        let slot_cnt = self.common.provisioned_slot_mask.count_ones() as usize;
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

pub(crate) async fn handle_digests<'a>(
    ctx: &mut SpdmContext<'a>,
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

    // Get the supported and provisioned slot masks.
    let (supported_mask, provisioned_mask) = ctx
        .device_certs_manager
        .get_cert_chain_slot_mask()
        .map_err(|_| ctx.generate_error_response(req_payload, ErrorCode::Unspecified, 0, None))?;

    // No slots provisioned
    let slot_cnt = provisioned_mask.count_ones() as usize;
    if slot_cnt == 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::Unspecified, 0, None))?;
    }

    let mut digests: [SpdmDigest; SPDM_MAX_CERT_CHAIN_SLOTS] =
        core::array::from_fn(|_| SpdmDigest::default());

    let caliptra_hash_algo: HashAlgoType = hash_algo
        .try_into()
        .map_err(|_| ctx.generate_error_response(req_payload, ErrorCode::Unspecified, 0, None))?;

    for (slot_id, digest) in digests.iter_mut().take(slot_cnt).enumerate() {
        digest.length = caliptra_hash_algo.hash_size() as u8;
        ctx.device_certs_manager
            .cert_chain_digest(slot_id as u8, hash_algo, &mut digest.data)
            .await
            .map_err(|_| {
                ctx.generate_error_response(req_payload, ErrorCode::Unspecified, 0, None)
            })?;
    }

    // Prepare the response buffer
    ctx.prepare_response_buffer(req_payload)?;

    // Fill the response buffer
    fill_digests_response(
        ctx,
        supported_mask,
        provisioned_mask,
        &digests[..slot_cnt],
        req_payload,
    )?;

    if ctx.state.connection_info.state() < ConnectionState::AfterDigest {
        ctx.state
            .connection_info
            .set_state(ConnectionState::AfterDigest);
    }

    Ok(())
}

fn fill_digests_response(
    ctx: &SpdmContext,
    supported_slot_mask: u8,
    provisioned_slot_mask: u8,
    digests: &[SpdmDigest],
    rsp: &mut MessageBuf,
) -> CommandResult<()> {
    // Construct the response
    let resp = GetDigestsResp::new(supported_slot_mask, provisioned_slot_mask, digests);

    let payload_len = resp
        .encode(rsp)
        .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None))?;

    // Push data offset up by total payload length
    rsp.push_data(payload_len)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

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

        let resp = GetDigestsResp::new(slot_mask, slot_mask, &digests);
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
        assert_eq!(buffer.total_message()[0], slot_mask); // param1
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

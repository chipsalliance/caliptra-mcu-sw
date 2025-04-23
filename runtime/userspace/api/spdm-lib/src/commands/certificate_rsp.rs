// Licensed under the Apache-2.0 license

use crate::cert_mgr::{CertChainSlotState, SPDM_MAX_CERT_CHAIN_SLOTS};
use crate::codec::{Codec, CodecError, CodecResult, CommonCodec, DataKind, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::config::MAX_SPDM_CERT_PORTION_LEN;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult, SpdmError, SpdmResult};
use crate::protocol::common::SpdmMsgHdr;
use crate::protocol::version::SpdmVersion;
use crate::state::ConnectionState;
use zerocopy::{FromBytes, Immutable, IntoBytes};

const GET_CERTIFICATE_REQUEST_ATTRIBUTES_SLOT_SIZE_REQUESTED: u8 = 0x01;

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(packed)]
pub struct GetCertificateReq {
    pub slot_id: u8,
    pub param2: u8,
    pub offset: u16,
    pub length: u16,
}

impl GetCertificateReq {
    pub fn new(slot_id: u8, param2: u8, offset: u16, length: u16) -> Self {
        Self {
            slot_id,
            param2,
            offset,
            length,
        }
    }
}

impl CommonCodec for GetCertificateReq {
    const DATA_KIND: DataKind = DataKind::Payload;
}

#[derive(IntoBytes, FromBytes, Immutable)]
#[repr(packed)]
pub struct GetCertificateRespCommon {
    pub slot_id: u8,
    pub param2: u8,
    pub portion_length: u16,
    pub remainder_length: u16,
}

impl CommonCodec for GetCertificateRespCommon {
    const DATA_KIND: DataKind = DataKind::Payload;
}

pub struct GetCertificateResp<'a> {
    pub common: GetCertificateRespCommon,
    pub cert_chain_portion: &'a [u8],
}

impl<'a> GetCertificateResp<'a> {
    pub fn new(
        slot_id: u8,
        param2: u8,
        cert_chain_portion: &'a [u8],
        remainder_length: u16,
    ) -> SpdmResult<Self> {
        if cert_chain_portion.len() > crate::config::MAX_SPDM_CERT_PORTION_LEN {
            return Err(SpdmError::InvalidParam);
        }
        let common = GetCertificateRespCommon {
            slot_id,
            param2,
            portion_length: cert_chain_portion.len() as u16,
            remainder_length,
        };
        Ok(Self {
            common,
            cert_chain_portion,
        })
    }
}

impl<'a> Codec for GetCertificateResp<'a> {
    fn encode(&self, buffer: &mut MessageBuf) -> CodecResult<usize> {
        let mut len = 0;
        len += self.common.encode(buffer)?;

        let portion_length =
            (self.common.portion_length as usize).min(self.cert_chain_portion.len());
        buffer.put_data(portion_length)?;

        let payload = buffer.data_mut(portion_length)?;
        self.cert_chain_portion[..portion_length]
            .write_to(payload)
            .map_err(|_| CodecError::WriteError)?;

        buffer.pull_data(portion_length)?;
        len += portion_length;

        Ok(len)
    }

    fn decode(_data: &mut MessageBuf) -> CodecResult<Self> {
        // Decoding is not required for SPDM responder
        unimplemented!()
    }
}

pub(crate) async fn handle_certificates<'a>(
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
    if spdm_hdr.version().ok() != Some(connection_version) {
        Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?;
    }

    // Check if the certificate capability is supported.
    if ctx.local_capabilities.flags.cert_cap() == 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnsupportedRequest, 0, None))?;
    }

    let req = GetCertificateReq::decode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    let slot_id = req.slot_id;
    if slot_id >= SPDM_MAX_CERT_CHAIN_SLOTS as u8 {
        return Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None));
    }

    // Check if the slot is provisioned. Otherwise, return an InvalidRequest error.
    let slot_mask = 1 << slot_id;
    let (_, provisioned_slot_mask) = ctx
        .device_certs_manager
        .get_cert_chain_slot_mask()
        .map_err(|_| ctx.generate_error_response(req_payload, ErrorCode::Unspecified, 0, None))?;
    if provisioned_slot_mask & slot_mask == 0 {
        return Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None));
    }

    let hash_type = ctx
        .get_select_hash_algo()
        .map_err(|_| ctx.generate_error_response(req_payload, ErrorCode::Unspecified, 0, None))?;

    let cert_chain_buffer = ctx
        .device_certs_manager
        .construct_cert_chain_buffer(hash_type, slot_id)
        .await
        .map_err(|_| ctx.generate_error_response(req_payload, ErrorCode::Unspecified, 0, None))?;

    let mut offset = req.offset;
    let mut length = req.length;

    // When SlotSizeRequested=1b in the GET_CERTIFICATE request, the Responder shall return
    // the number of bytes available for certificate chain storage in the RemainderLength field of the response.
    if connection_version >= SpdmVersion::V13
        && req.param2 & GET_CERTIFICATE_REQUEST_ATTRIBUTES_SLOT_SIZE_REQUESTED != 0
    {
        offset = 0;
        length = 0;
    }

    if offset >= cert_chain_buffer.length {
        Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
    }

    if length > MAX_SPDM_CERT_PORTION_LEN as u16 && ctx.local_capabilities.flags.chunk_cap() == 0 {
        length = MAX_SPDM_CERT_PORTION_LEN as u16;
    }

    if length > cert_chain_buffer.length - offset {
        length = cert_chain_buffer.length - offset;
    }

    let portion_length = length;
    let remainder_length = cert_chain_buffer.length - (length + offset);

    // construct the portion of cert data
    let mut cert_portion = [0u8; MAX_SPDM_CERT_PORTION_LEN];
    cert_portion[..portion_length as usize].copy_from_slice(
        &cert_chain_buffer.as_ref()[offset as usize..(offset + portion_length) as usize],
    );

    // Prepare the response buffer
    ctx.prepare_response_buffer(req_payload)?;

    // Set the param2 field if the connection version is V13 or higher and multi-key capability is supported
    let mut param2 = 0;
    if connection_version >= SpdmVersion::V13 && ctx.local_capabilities.flags.multi_key_cap() != 0 {
        let mut cert_chain_slot_state = CertChainSlotState::default();
        ctx.device_certs_manager
            .get_cert_chain_slot_state(slot_id, &mut cert_chain_slot_state)
            .map_err(|_| {
                ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
            })?;

        if let Some(cert_model) = cert_chain_slot_state.cert_model {
            param2 = cert_model as u8;
        }
    }

    // Fill the response buffer
    fill_certificate_response(
        ctx,
        slot_id,
        param2,
        &cert_portion[..portion_length as usize],
        remainder_length,
        req_payload,
    )?;

    // TODO: transcript manager and session support

    // Set the connection state to AfterCertificate
    if ctx.state.connection_info.state() < ConnectionState::AfterCertificate {
        ctx.state
            .connection_info
            .set_state(ConnectionState::AfterCertificate);
    }

    Ok(())
}

fn fill_certificate_response(
    ctx: &SpdmContext,
    slot_id: u8,
    param2: u8,
    cert_chain_portion: &[u8],
    remainder_length: u16,
    rsp: &mut MessageBuf,
) -> CommandResult<()> {
    // Construct the response
    let resp = GetCertificateResp::new(slot_id, param2, cert_chain_portion, remainder_length)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;
    let payload_len = resp
        .encode(rsp)
        .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None))?;

    // Push data offset up by total payload length
    rsp.push_data(payload_len)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_get_cert_chain_resp() {
        let cert_chain_portion = [0xaau8; MAX_SPDM_CERT_PORTION_LEN];
        let remainder_length = 0;
        let slot_id = 0;

        let resp =
            GetCertificateResp::new(slot_id, 0, &cert_chain_portion, remainder_length).unwrap();
        let mut bytes = [0u8; 1024];
        let mut buffer = MessageBuf::new(&mut bytes);
        let encoded_len = resp.encode(&mut buffer).unwrap();

        assert_eq!(
            encoded_len,
            core::mem::size_of::<GetCertificateRespCommon>() + cert_chain_portion.len() as usize
        );
        assert_eq!(encoded_len, buffer.msg_len());
        assert_eq!(encoded_len, buffer.data_offset());

        // Verify the encoded data
        assert_eq!(buffer.total_message()[0], resp.common.slot_id);
        assert_eq!(buffer.total_message()[1], resp.common.param2);
        assert_eq!(
            buffer.total_message()[2..4],
            resp.common.portion_length.to_le_bytes()
        );
        assert_eq!(
            buffer.total_message()[4..6],
            resp.common.remainder_length.to_le_bytes()
        );
        assert_eq!(
            buffer.total_message()[core::mem::size_of::<GetCertificateRespCommon>()..],
            cert_chain_portion
        );
    }
}

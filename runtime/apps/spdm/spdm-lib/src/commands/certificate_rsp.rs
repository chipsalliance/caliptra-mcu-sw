// Licensed under the Apache-2.0 license

use crate::cert_mgr::{SpdmCertChainBuffer, SpdmCertChainData, SpdmDigest};
use crate::codec::{Codec, CodecError, CodecResult, CommonCodec, DataKind, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult, SpdmError, SpdmResult};
use crate::protocol::algorithms::BaseHashAlgoType;
use crate::protocol::common::SpdmMsgHdr;
use crate::state::ConnectionState;
use libtock_platform::Syscalls;
use zerocopy::{FromBytes, Immutable, IntoBytes};

const MAX_SPDM_CERT_PORTION_LEN: usize = 512;
const GET_CERTIFICATE_SLOT_ID_MASK: u8 = 0xF;

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(packed)]
pub struct GetCertificateReq {
    pub slot_id: u8,
    pub param2: u8,
    pub offset: u16,
    pub length: u16,
}

impl GetCertificateReq {
    pub fn new(slot_id: u8, offset: u16, length: u16) -> Self {
        Self {
            slot_id,
            param2: 0,
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

pub struct GetCertificateResp {
    pub common: GetCertificateRespCommon,
    pub cert_chain: [u8; MAX_SPDM_CERT_PORTION_LEN],
}

impl Default for GetCertificateResp {
    fn default() -> Self {
        Self {
            common: GetCertificateRespCommon {
                slot_id: 0,
                param2: 0,
                portion_length: 0,
                remainder_length: 0,
            },
            cert_chain: [0u8; MAX_SPDM_CERT_PORTION_LEN],
        }
    }
}

impl GetCertificateResp {
    pub fn new(slot_id: u8, cert_chain_portion: &[u8], remainder_length: u16) -> SpdmResult<Self> {
        let portion_length = cert_chain_portion.len() as u16;
        if portion_length > MAX_SPDM_CERT_PORTION_LEN as u16 {
            return Err(SpdmError::InvalidParam);
        }
        let mut cert_chain = [0u8; MAX_SPDM_CERT_PORTION_LEN];
        cert_chain[..portion_length as usize].copy_from_slice(cert_chain_portion);
        let common = GetCertificateRespCommon {
            slot_id,
            param2: 0,
            portion_length,
            remainder_length,
        };
        Ok(Self { common, cert_chain })
    }
}

impl Codec for GetCertificateResp {
    fn encode(&self, buffer: &mut MessageBuf) -> CodecResult<usize> {
        let mut len = 0;
        len += self.common.encode(buffer)?;

        let portion_length = (self.common.portion_length as usize).min(MAX_SPDM_CERT_PORTION_LEN);
        buffer.put_data(portion_length)?;

        let payload = buffer.data_mut(portion_length)?;
        self.cert_chain[..portion_length]
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

pub(crate) fn handle_certificates<'a, S: Syscalls>(
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

    let req = GetCertificateReq::decode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    // Reserved field should be zero.
    if req.param2 != 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
    }

    // Check if the certificate capability is supported.
    if ctx.local_capabilities.flags.cert_cap() == 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnsupportedRequest, 0, None))?;
    }

    // TODO: transcript manager and session support

    let slot_id = req.slot_id;
    // Only slot_id 0 is supported for now.
    if slot_id & GET_CERTIFICATE_SLOT_ID_MASK != 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
    }

    let hash_type = ctx
        .get_select_hash_algo()
        .map_err(|_| ctx.generate_error_response(req_payload, ErrorCode::Unspecified, 0, None))?;

    let cert_chain_buffer = construct_cert_chain_buffer(ctx, hash_type)
        .map_err(|_| ctx.generate_error_response(req_payload, ErrorCode::Unspecified, 0, None))?;

    let mut length = req.length;
    if length > MAX_SPDM_CERT_PORTION_LEN as u16 {
        length = MAX_SPDM_CERT_PORTION_LEN as u16;
    }

    let offset = req.offset;
    if offset >= cert_chain_buffer.length {
        Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
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

    // Fill the response buffer
    fill_certificate_response(
        ctx,
        slot_id,
        &cert_portion[..],
        remainder_length,
        req_payload,
    )?;

    // Set the connection state to AfterCertificate
    if ctx.state.connection_info.state() < ConnectionState::AfterCertificate {
        ctx.state
            .connection_info
            .set_state(ConnectionState::AfterCertificate);
    }

    Ok(())
}

fn construct_cert_chain_buffer<S: Syscalls>(
    ctx: &mut SpdmContext<S>,
    hash_type: BaseHashAlgoType,
) -> SpdmResult<SpdmCertChainBuffer> {
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

    // Construct the cert chain buffer
    let cert_chain_buffer = SpdmCertChainBuffer::new(cert_chain_data.as_ref(), root_hash.as_ref())
        .map_err(|_| SpdmError::InvalidParam)?;

    Ok(cert_chain_buffer)
}

fn fill_certificate_response<S: Syscalls>(
    ctx: &SpdmContext<S>,
    slot_id: u8,
    cert_chain_portion: &[u8],
    remainder_length: u16,
    rsp: &mut MessageBuf,
) -> CommandResult<()> {
    // Construct the response
    let resp = GetCertificateResp::new(slot_id, cert_chain_portion, remainder_length).unwrap();

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

        let resp = GetCertificateResp::new(slot_id, &cert_chain_portion, remainder_length).unwrap();
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

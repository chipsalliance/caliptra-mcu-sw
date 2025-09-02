// Licensed under the Apache-2.0 license

use crate::codec::{decode_u8_slice, Codec, CodecError, CodecResult, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::*;
use crate::session::SessionState;
use crate::state::ConnectionState;
use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes};

const MAX_VENDOR_DEFINED_REQ_SIZE: usize = 256;

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
struct VendorDefReqRespHdr {
    param1: u8,
    param2: u8,
    standard_id: u16,
    vendor_id_len: u8,
    vendor_id: [u8; MAX_SPDM_VENDOR_ID_LEN as usize],
    req_len: u16,
}

impl Default for VendorDefReqRespHdr {
    fn default() -> Self {
        Self {
            param1: 0,
            param2: 0,
            standard_id: 0,
            vendor_id_len: 0,
            vendor_id: [0; MAX_SPDM_VENDOR_ID_LEN as usize],
            req_len: 0,
        }
    }
}

impl VendorDefReqRespHdr {
    fn new(large_req_rsp: bool, standard_id: u16, vendor_id: &[u8], req_len: u16) -> Self {
        let mut vid = [0u8; MAX_SPDM_VENDOR_ID_LEN as usize];
        vid[..vendor_id.len()].copy_from_slice(vendor_id);
        Self {
            param1: large_req_rsp as u8,
            param2: 0,
            standard_id,
            vendor_id_len: vendor_id.len() as u8,
            vendor_id: vid,
            req_len,
        }
    }

    fn len(&self) -> usize {
        size_of::<u8>() // param1
            + size_of::<u8>() // param2
            + size_of::<u16>() // standard_id
            + size_of::<u8>() // vendor_id_len
            + self.vendor_id_len as usize // vendor_id
            + size_of::<u16>() // req_len
    }
}

// This is treated as a header kind
impl Codec for VendorDefReqRespHdr {
    fn encode(&self, buffer: &mut MessageBuf) -> CodecResult<usize> {
        let len = self.len();
        buffer.push_data(len)?;
        let header = buffer.data_mut(len)?;
        self.write_to(header).map_err(|_| CodecError::WriteError)?;
        buffer.push_head(len)?;
        Ok(len)
    }

    fn decode(buffer: &mut MessageBuf) -> CodecResult<Self> {
        let mut hdr = VendorDefReqRespHdr::default();
        hdr.param1 = u8::decode(buffer)?;
        hdr.param2 = u8::decode(buffer)?;
        hdr.standard_id = u16::decode(buffer)?;
        hdr.vendor_id_len = u8::decode(buffer)?;
        decode_u8_slice(buffer, &mut hdr.vendor_id[..hdr.vendor_id_len as usize])?;
        hdr.req_len = u16::decode(buffer)?;
        let len = hdr.len();
        buffer.pull_data(len)?;
        buffer.pull_head(len)?;
        Ok(hdr)
    }
}

struct VendorDefRespCtx {
    spdm_version: SpdmVersion,
    secure_session: bool,
    standard_id: StandardsBodyId,
    vendor_id_len: u8,
    vendor_id: [u8; MAX_SPDM_VENDOR_ID_LEN as usize],
    req_len: u16,
    request_payload: [u8; MAX_VENDOR_DEFINED_REQ_SIZE],
}

fn process_vendor_defined_request<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<VendorDefRespCtx> {
    // Process the vendor-defined request
    let connection_version = ctx.state.connection_info.version_number();
    if spdm_hdr.version().ok() != Some(connection_version) {
        Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?;
    }

    let req_hdr =
        VendorDefReqRespHdr::decode(req_payload).map_err(|e| (false, CommandError::Codec(e)))?;

    let standards_body_id: StandardsBodyId = req_hdr.standard_id.try_into().map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    if let Ok(expected_len) = standards_body_id.vendor_id_len() {
        if expected_len != req_hdr.vendor_id_len {
            Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
        }
    }

    let vendor_id = &req_hdr.vendor_id[..req_hdr.vendor_id_len as usize];

    let in_secure_session = ctx.session_mgr.active_session_id().is_some();

    // Validate if the standards body commands are supported.
    if !ctx
        .vdm_handlers
        .iter()
        .any(|handler| handler.match_id(standards_body_id, vendor_id, in_secure_session))
    {
        return Err(ctx.generate_error_response(
            req_payload,
            ErrorCode::UnsupportedRequest,
            0,
            None,
        ));
    }

    let mut vendor_id = [0u8; MAX_SPDM_VENDOR_ID_LEN as usize];
    decode_u8_slice(
        req_payload,
        &mut vendor_id[..req_hdr.vendor_id_len as usize],
    )
    .map_err(|e| (false, CommandError::Codec(e)))?;

    let payload_len = u16::decode(req_payload).map_err(|e| (false, CommandError::Codec(e)))?;

    if payload_len as usize > MAX_VENDOR_DEFINED_REQ_SIZE {
        Err((false, CommandError::BufferTooSmall))?;
    }

    let mut payload = [0u8; MAX_VENDOR_DEFINED_REQ_SIZE];
    decode_u8_slice(req_payload, &mut payload[..payload_len as usize])
        .map_err(|e| (false, CommandError::Codec(e)))?;

    Ok(VendorDefRespCtx {
        spdm_version: connection_version,
        secure_session: in_secure_session,
        standard_id: standards_body_id,
        vendor_id_len: req_hdr.vendor_id_len,
        vendor_id,
        req_len: payload_len,
        request_payload: payload,
    })
}

async fn generate_vendor_defined_response<'a>(
    ctx: &mut SpdmContext<'a>,
    resp_ctx: VendorDefRespCtx,
) -> CommandResult<()> {
    // Generate the vendor-defined response

    let vdm_handler = ctx
        .vdm_handlers
        .iter()
        .find(|handler| {
            handler.match_id(
                resp_ctx.standard_id,
                &resp_ctx.vendor_id[..resp_ctx.vendor_id_len as usize],
                resp_ctx.secure_session,
            )
        })
        .ok_or_else(|| (false, CommandError::UnsupportedRequest))?;
    todo!()
}

pub(crate) async fn handle_vendor_defined_request<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Check if the connection state is valid
    if ctx.state.connection_info.state() < ConnectionState::AlgorithmsNegotiated {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    let session_id = ctx.session_mgr.active_session_id();
    if let Some(session_id) = session_id {
        let session_info = ctx.session_mgr.session_info(session_id).map_err(|_| {
            ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None)
        })?;
        if session_info.session_state != SessionState::Established {
            return Err(ctx.generate_error_response(
                req_payload,
                ErrorCode::UnexpectedRequest,
                0,
                None,
            ));
        }
    }

    // Process VENDOR_DEFINED_REQUEST
    let vendor_def_res_ctx = process_vendor_defined_request(ctx, spdm_hdr, req_payload)?;

    // Generate VENDOR_DEFINED_RESPONSE
    ctx.prepare_response_buffer(req_payload)?;
    generate_vendor_defined_response(ctx, vendor_def_res_ctx).await?;

    todo!("Implement vendor-defined request handling");
}

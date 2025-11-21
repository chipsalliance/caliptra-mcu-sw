// Licensed under the Apache-2.0 license

use crate::chunk_ctx::LargeResponse;
use crate::codec::*;
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::*;
use crate::session::SessionState;
use crate::state::ConnectionState;
use crate::vdm_handler::{VdmError, VdmLargeRespCtx};
use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes};

const MAX_VENDOR_DEFINED_REQ_SIZE: usize = 256;

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
struct VendorDefReqHdr {
    param1: u8,
    param2: u8,
    standard_id: u16,
    vendor_id_len: u8,
}

impl CommonCodec for VendorDefReqHdr {}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
struct VendorDefRespHdr {
    spdm_version: u8,
    resp_code: u8,
    param1: u8,
    param2: u8,
    standard_id: u16,
    vendor_id_len: u8,
    vendor_id: [u8; MAX_SPDM_VENDOR_ID_LEN as usize],
    resp_len: u16,
}

impl Default for VendorDefRespHdr {
    fn default() -> Self {
        VendorDefRespHdr {
            spdm_version: 0,
            resp_code: 0,
            param1: 0,
            param2: 0,
            standard_id: 0,
            vendor_id_len: 0,
            vendor_id: [0; MAX_SPDM_VENDOR_ID_LEN as usize],
            resp_len: 0,
        }
    }
}

impl VendorDefRespHdr {
    fn new(spdm_version: SpdmVersion, standard_id: u16, vendor_id: &[u8]) -> Self {
        let mut vid = [0u8; MAX_SPDM_VENDOR_ID_LEN as usize];
        assert!(vendor_id.len() <= MAX_SPDM_VENDOR_ID_LEN as usize);
        vid[..vendor_id.len()].copy_from_slice(vendor_id);
        Self {
            spdm_version: spdm_version.into(),
            resp_code: ReqRespCode::VendorDefinedResponse as u8,
            param1: 0,
            param2: 0,
            standard_id,
            vendor_id_len: vendor_id.len() as u8,
            vendor_id: vid,
            resp_len: 0,
        }
    }

    fn set_resp_len(&mut self, resp_len: u16) {
        self.resp_len = resp_len;
    }

    fn len(&self) -> usize {
        size_of::<VendorDefRespHdr>() - MAX_SPDM_VENDOR_ID_LEN as usize
            + self.vendor_id_len as usize
    }
}

// This is treated as a header kind
impl Codec for VendorDefRespHdr {
    fn encode(&self, buffer: &mut MessageBuf) -> CodecResult<usize> {
        let len = self.len();
        let vendor_id_len = self.vendor_id_len as usize;
        // Sanity check
        if vendor_id_len > MAX_SPDM_VENDOR_ID_LEN as usize {
            Err(CodecError::BufferOverflow)?;
        }
        // Allocate space for header at front of payload region
        buffer.push_data(len)?;
        let header = buffer.data_mut(len)?;
        // Sequentially write fields
        let mut offset = 0;
        header[offset] = self.spdm_version;
        offset += 1;
        header[offset] = self.resp_code;
        offset += 1;
        header[offset] = self.param1;
        offset += 1;
        header[offset] = self.param2;
        offset += 1;
        header[offset..offset + 2].copy_from_slice(&self.standard_id.to_le_bytes());
        offset += 2;
        header[offset] = self.vendor_id_len;
        offset += 1;
        // Copy exactly vendor_id_len bytes of vendor_id
        header[offset..offset + vendor_id_len].copy_from_slice(&self.vendor_id[..vendor_id_len]);
        offset += vendor_id_len;
        header[offset..offset + 2].copy_from_slice(&self.resp_len.to_le_bytes());
        offset += 2; // offset now equals full header length
        debug_assert_eq!(
            offset, len,
            "VendorDefRespHdr encode length mismatch: {} != {}",
            offset, len
        );
        buffer.push_head(len)?;
        Ok(len)
    }

    fn decode(buffer: &mut MessageBuf) -> CodecResult<Self> {
        let spdm_version = u8::decode(buffer)?;
        let resp_code = u8::decode(buffer)?;
        let param1 = u8::decode(buffer)?;
        let param2 = u8::decode(buffer)?;
        let standard_id = u16::decode(buffer)?;
        let vendor_id_len = u8::decode(buffer)?;
        if vendor_id_len as usize > MAX_SPDM_VENDOR_ID_LEN as usize {
            Err(CodecError::BufferOverflow)?;
        }
        let mut vendor_id = [0u8; MAX_SPDM_VENDOR_ID_LEN as usize];
        decode_u8_slice(buffer, &mut vendor_id[..vendor_id_len as usize])?;
        let resp_len = u16::decode(buffer)?;
        let hdr = VendorDefRespHdr {
            spdm_version,
            resp_code,
            param1,
            param2,
            standard_id,
            vendor_id_len,
            vendor_id,
            resp_len,
        };
        let len = hdr.len();
        buffer.pull_data(len)?;
        buffer.pull_head(len)?;
        Ok(hdr)
    }
}

#[allow(dead_code)]
pub(crate) struct VendorLargeResponse {
    spdm_version: SpdmVersion,
    standard_id: StandardsBodyId,
    vendor_id_len: u8,
    vendor_id: [u8; MAX_SPDM_VENDOR_ID_LEN as usize],
    request_ctx: VdmLargeRespCtx,
}

impl VendorLargeResponse {
    fn new(
        spdm_version: SpdmVersion,
        standard_id: StandardsBodyId,
        vendor_id: &[u8],
        request_ctx: VdmLargeRespCtx,
    ) -> Self {
        let mut vendor_id_data = [0u8; MAX_SPDM_VENDOR_ID_LEN as usize];
        vendor_id_data[..vendor_id.len()].copy_from_slice(vendor_id);
        Self {
            spdm_version,
            standard_id,
            vendor_id_len: vendor_id.len() as u8,
            vendor_id: vendor_id_data,
            request_ctx,
        }
    }
}

async fn process_vendor_defined_request<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<(
    StandardsBodyId,
    [u8; MAX_SPDM_VENDOR_ID_LEN as usize],
    [u8; MAX_VENDOR_DEFINED_REQ_SIZE],
    usize,
)> {
    let connection_version = ctx.state.connection_info.version_number();
    if spdm_hdr.version().ok() != Some(connection_version) {
        Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?;
    }

    let req_hdr =
        VendorDefReqHdr::decode(req_payload).map_err(|e| (false, CommandError::Codec(e)))?;

    let standards_body_id: StandardsBodyId = req_hdr.standard_id.try_into().map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    if let Ok(expected_len) = standards_body_id.vendor_id_len() {
        if expected_len != req_hdr.vendor_id_len {
            Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
        }
    }

    let mut vendor_id = [0u8; MAX_SPDM_VENDOR_ID_LEN as usize];
    decode_u8_slice(
        req_payload,
        &mut vendor_id[..req_hdr.vendor_id_len as usize],
    )
    .map_err(|e| (false, CommandError::Codec(e)))?;

    let in_secure_session = ctx.session_mgr.active_session_id().is_some();

    // Check if any handler matches the request.
    let handler_found = ctx.vdm_handlers.as_ref().is_some_and(|handlers| {
        handlers.iter().any(|handler| {
            handler.match_id(
                standards_body_id,
                &vendor_id[..req_hdr.vendor_id_len as usize],
                in_secure_session,
            )
        })
    });

    if !handler_found {
        return Err(ctx.generate_error_response(
            req_payload,
            ErrorCode::UnsupportedRequest,
            ReqRespCode::VendorDefinedRequest as u8,
            None,
        ));
    }

    // Decode the VDM request length
    let vdm_req_len = u16::decode(req_payload).map_err(|e| (false, CommandError::Codec(e)))?;
    if vdm_req_len as usize > MAX_VENDOR_DEFINED_REQ_SIZE {
        Err((false, CommandError::BufferTooSmall))?;
    }

    // Decode the VDM request
    let mut vdm_req = [0u8; MAX_VENDOR_DEFINED_REQ_SIZE];
    decode_u8_slice(req_payload, &mut vdm_req[..vdm_req_len as usize])
        .map_err(|e| (false, CommandError::Codec(e)))?;

    Ok((standards_body_id, vendor_id, vdm_req, vdm_req_len as usize))
}

async fn generate_vendor_defined_response<'a>(
    ctx: &mut SpdmContext<'a>,
    standard_id: StandardsBodyId,
    vendor_id: [u8; MAX_SPDM_VENDOR_ID_LEN as usize],
    vdm_req_buf: &mut MessageBuf<'_>,
    rsp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    let vendor_id_len = standard_id
        .vendor_id_len()
        .map_err(|_| (false, CommandError::UnsupportedRequest))?;

    let connection_version = ctx.state.connection_info.version_number();
    let in_secure_session = ctx.session_mgr.active_session_id().is_some();

    let mut resp_hdr = VendorDefRespHdr::new(
        connection_version,
        standard_id as u16,
        &vendor_id[..vendor_id_len as usize],
    );
    let resp_hdr_len = resp_hdr.len();

    // Reserve headroom for the response header. This will be encoded once the response is generated.
    rsp.reserve(resp_hdr_len)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    let vdm_handler = ctx.vdm_handlers.as_mut().and_then(|handlers| {
        handlers.iter_mut().find(|handler| {
            handler.match_id(
                standard_id,
                &vendor_id[..vendor_id_len as usize],
                in_secure_session,
            )
        })
    });
    let vdm_handler = match vdm_handler {
        Some(handler) => handler,
        None => {
            return Err((false, CommandError::MissingVdmHandler));
        }
    };
    match vdm_handler.handle_request(vdm_req_buf, rsp).await {
        Ok(len) => {
            resp_hdr.set_resp_len(len as u16);
            resp_hdr
                .encode(rsp)
                .map_err(|e| (false, CommandError::Codec(e)))?;
            Ok(())
        }
        Err(VdmError::LargeResp(large_rsp_len, resp_ctx)) => {
            // Only allow supported large response types
            match &resp_ctx {
                VdmLargeRespCtx::EnvelopeSignedCsr(_) | VdmLargeRespCtx::Evidence(_) => {
                    // Supported large response types, return context for chunking
                    let large_rsp_ctx = VendorLargeResponse::new(
                        connection_version,
                        standard_id,
                        &vendor_id[..vendor_id_len as usize],
                        resp_ctx,
                    );
                    let large_rsp = LargeResponse::Vdm(large_rsp_ctx);
                    let handle = ctx.large_resp_context.init(large_rsp, large_rsp_len);
                    Err(ctx.generate_error_response(rsp, ErrorCode::LargeResponse, handle, None))
                }
                _ => {
                    // Unsupported large response type
                    Err((false, CommandError::UnsupportedLargeResponse))
                }
            }
        }
        Err(e) => {
            // Handle all other errors
            Err((false, CommandError::Vdm(e)))
        }
    }
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
            ctx.generate_error_response(req_payload, ErrorCode::SessionRequired, 0, None)
        })?;
        if session_info.session_state != SessionState::Established {
            Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
        }
    }

    // Process VENDOR_DEFINED_REQUEST
    let (standard_id, vendor_id, mut vdm_req, vdm_req_len) =
        process_vendor_defined_request(ctx, spdm_hdr, req_payload).await?;

    let mut vdm_req_buf = MessageBuf::from(&mut vdm_req[..vdm_req_len]);
    ctx.prepare_response_buffer(req_payload)?;

    // Generate VENDOR_DEFINED_RESPONSE
    generate_vendor_defined_response(ctx, standard_id, vendor_id, &mut vdm_req_buf, req_payload)
        .await
}

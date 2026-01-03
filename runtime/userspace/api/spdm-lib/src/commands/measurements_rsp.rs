// Licensed under the Apache-2.0 license

use crate::cert_store::SpdmCertStore;
use crate::chunk_ctx::{ChunkError, LargeResponse};
use crate::codec::{encode_u8_slice, Codec, CommonCodec, MessageBuf};
use crate::commands::algorithms_rsp::selected_measurement_specification;
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::measurements::{MeasurementsError, SpdmMeasurements};
use crate::protocol::*;
use crate::session::SessionInfo;
use crate::state::ConnectionState;
use crate::transcript::{Transcript, TranscriptContext};
use bitfield::bitfield;
use libapi_caliptra::crypto::asym::*;
use libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use libapi_caliptra::crypto::rng::Rng;
use zerocopy::{FromBytes, Immutable, IntoBytes};

const RESPONSE_FIXED_FIELDS_SIZE: usize = 8;
const MAX_RESPONSE_VARIABLE_FIELDS_SIZE: usize =
    SPDM_NONCE_LEN + size_of::<u32>() + size_of::<RequesterContext>();

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct GetMeasurementsReqCommon {
    req_attr: GetMeasurementsReqAttr,
    meas_op: u8,
}
impl CommonCodec for GetMeasurementsReqCommon {}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct GetMeasurementsReqSignature {
    requester_nonce: [u8; SPDM_NONCE_LEN],
    slot_id: u8,
}
impl CommonCodec for GetMeasurementsReqSignature {}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    struct GetMeasurementsReqAttr(u8);
    impl Debug;
    u8;
    pub signature_requested, _: 0, 0;
    pub raw_bitstream_requested, _: 1, 1;
    pub new_measurement_requested, _: 2, 2;
    reserved, _: 7, 3;
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    struct MeasurementsRspFixed([u8]);
    impl Debug;
    u8;
    pub spdm_version, set_spdm_version: 7, 0;
    pub req_resp_code, set_req_resp_code: 15, 8;
    pub total_measurement_indices, set_total_measurement_indices: 23, 16;
    pub slot_id, set_slot_id: 27, 24;
    pub content_changed, set_content_changed: 29, 28;
    reserved, _: 31, 30;
    pub num_blocks, set_num_blocks: 39, 32;
    pub measurement_record_len_byte0, set_measurement_record_len_byte0: 47, 40;
    pub measurement_record_len_byte1, set_measurement_record_len_byte1: 55, 48;
    pub measurement_record_len_byte2, set_measurement_record_len_byte2: 63, 56;
}

impl MeasurementsRspFixed<[u8; RESPONSE_FIXED_FIELDS_SIZE]> {
    pub fn set_measurement_record_len(&mut self, len: u32) {
        self.set_measurement_record_len_byte0((len & 0xFF) as u8);
        self.set_measurement_record_len_byte1(((len >> 8) & 0xFF) as u8);
        self.set_measurement_record_len_byte2(((len >> 16) & 0xFF) as u8);
    }
}

impl Default for MeasurementsRspFixed<[u8; RESPONSE_FIXED_FIELDS_SIZE]> {
    fn default() -> Self {
        Self([0; RESPONSE_FIXED_FIELDS_SIZE])
    }
}

impl CommonCodec for MeasurementsRspFixed<[u8; RESPONSE_FIXED_FIELDS_SIZE]> {}

#[derive(Debug)]
pub(crate) struct MeasurementsResponse {
    spdm_version: SpdmVersion,
    req_attr: GetMeasurementsReqAttr,
    meas_op: u8,
    slot_id: Option<u8>,
    requester_context: Option<RequesterContext>,
    asym_algo: AsymAlgo,
}

impl MeasurementsResponse {
    pub async fn get_chunk(
        &self,
        measurements: &mut SpdmMeasurements<'_>,
        shared_transcript: &mut Transcript,
        cert_store: &dyn SpdmCertStore,
        offset: usize,
        chunk_buf: &mut [u8],
        mut session_info: Option<&mut SessionInfo>,
    ) -> CommandResult<usize> {
        // Calculate the size of the response
        let response_size = self.response_size(measurements).await?;

        // Check if the offset is valid
        if offset >= response_size {
            return Err((false, CommandError::Chunk(ChunkError::InvalidMessageOffset)));
        }

        // Calculate the size of the chunk to return
        let mut rem_len = (response_size - offset).min(chunk_buf.len());

        let raw_bitstream_requested = self.req_attr.raw_bitstream_requested() == 1;

        let measurement_record_len = measurements
            .measurement_block_size(self.meas_op, raw_bitstream_requested)
            .await
            .map_err(|e| (false, CommandError::Measurement(e)))?;
        // Fill the chunk buffer with the appropriate response sections
        // Instead of a while loop, use a single-pass approach for clarity and efficiency.
        let mut copied = 0;

        // 1. Copy from the fixed response fields
        if offset < RESPONSE_FIXED_FIELDS_SIZE {
            let fixed_fields = self.response_fixed_fields(measurements).await?;
            let start = offset;
            let end = (RESPONSE_FIXED_FIELDS_SIZE).min(start + rem_len);
            let copy_len = end - start;
            chunk_buf[copied..copied + copy_len].copy_from_slice(&fixed_fields[start..end]);
            copied += copy_len;
            rem_len -= copy_len;
        }

        // 2. Copy from the measurement record
        let record_start = RESPONSE_FIXED_FIELDS_SIZE;
        let record_end = record_start + measurement_record_len;
        if rem_len > 0 && offset + copied < record_end {
            let meas_block_offset = (offset + copied).saturating_sub(record_start);
            let bytes_to_copy = (measurement_record_len - meas_block_offset).min(rem_len);
            let bytes_filled = measurements
                .measurement_block(
                    self.meas_op,
                    raw_bitstream_requested,
                    meas_block_offset,
                    &mut chunk_buf[copied..copied + bytes_to_copy],
                )
                .await
                .map_err(|e| (false, CommandError::Measurement(e)))?;
            copied += bytes_filled;
            rem_len -= bytes_filled;
        }

        // 3. Copy from the variable/trailer fields
        let trailer_start = record_end;
        if rem_len > 0 && offset + copied >= trailer_start {
            let trailer_offset = (offset + copied) - trailer_start;
            let (variable_fields, trailer_len) = self.response_variable_fields().await?;
            let end = (trailer_len).min(trailer_offset + rem_len);
            let copy_len = end - trailer_offset;
            chunk_buf[copied..copied + copy_len]
                .copy_from_slice(&variable_fields[trailer_offset..end]);
            copied += copy_len;
            rem_len -= copy_len;
        }
        // Append the chunk to the L1 transcript
        shared_transcript
            .append(
                TranscriptContext::L1,
                session_info.as_deref_mut(),
                &chunk_buf[..copied],
            )
            .await
            .map_err(|e| (false, CommandError::Transcript(e)))?;

        // 4. Copy from the signature if requested
        let signature_start = trailer_start + self.response_variable_fields().await?.1;
        if rem_len > 0
            && self.req_attr.signature_requested() == 1
            && offset + copied >= signature_start
        {
            let signature = self
                .l1_signature(self.asym_algo, shared_transcript, session_info, cert_store)
                .await?;
            let sig_offset = (offset + copied) - signature_start;
            let copy_len = (signature.len() - sig_offset).min(rem_len);
            chunk_buf[copied..copied + copy_len]
                .copy_from_slice(&signature[sig_offset..sig_offset + copy_len]);
            copied += copy_len;
        }

        Ok(copied)
    }

    async fn response_fixed_fields(
        &self,
        measurements: &mut SpdmMeasurements<'_>,
    ) -> CommandResult<[u8; RESPONSE_FIXED_FIELDS_SIZE]> {
        let mut fixed_rsp_fields = [0u8; RESPONSE_FIXED_FIELDS_SIZE];
        let mut fixed_rsp_buf = MessageBuf::new(&mut fixed_rsp_fields);
        _ = self
            .encode_response_fixed_fields(&mut fixed_rsp_buf, measurements)
            .await?;
        Ok(fixed_rsp_fields)
    }

    async fn encode_response_fixed_fields(
        &self,
        buf: &mut MessageBuf<'_>,
        measurements: &mut SpdmMeasurements<'_>,
    ) -> CommandResult<usize> {
        let measurement_record_size = measurements
            .measurement_block_size(self.meas_op, self.req_attr.raw_bitstream_requested() == 1)
            .await
            .map_err(|e| (false, CommandError::Measurement(e)))?;
        let total_measurement_count = measurements.total_measurement_count() as u8;

        let (total_meas_indices, num_of_meas_blocks_in_record, meas_record_len) = match self.meas_op
        {
            0x00 => (total_measurement_count, 0, 0),
            0xFF => (0, total_measurement_count, measurement_record_size),
            _ => (0, 1, measurement_record_size),
        };

        if meas_record_len > SPDM_MAX_MEASUREMENT_RECORD_SIZE as usize {
            Err((
                false,
                CommandError::Measurement(MeasurementsError::InvalidSize),
            ))?;
        }

        let change_detected = if self.req_attr.signature_requested() == 1 {
            MeasurementChangeStatus::DetectedNoChange as u8
        } else {
            MeasurementChangeStatus::NoDetection as u8
        };

        // Encode the common response fields
        let mut rsp_common = MeasurementsRspFixed::default();
        rsp_common.set_spdm_version(self.spdm_version.into());
        rsp_common.set_req_resp_code(ReqRespCode::Measurements.into());
        rsp_common.set_total_measurement_indices(total_meas_indices);
        rsp_common.set_slot_id(self.slot_id.unwrap_or(0));
        rsp_common.set_content_changed(change_detected);
        rsp_common.set_num_blocks(num_of_meas_blocks_in_record);
        rsp_common.set_measurement_record_len(meas_record_len as u32);

        let len = rsp_common
            .encode(buf)
            .map_err(|e| (false, CommandError::Codec(e)))?;

        Ok(len)
    }

    async fn response_variable_fields(
        &self,
    ) -> CommandResult<([u8; MAX_RESPONSE_VARIABLE_FIELDS_SIZE], usize)> {
        let mut trailer_rsp = [0u8; MAX_RESPONSE_VARIABLE_FIELDS_SIZE];
        let mut trailer_buf = MessageBuf::new(&mut trailer_rsp);
        let len = self
            .encode_response_variable_fields(&mut trailer_buf)
            .await?;
        Ok((trailer_rsp, len))
    }

    async fn encode_response_variable_fields(
        &self,
        buf: &mut MessageBuf<'_>,
    ) -> CommandResult<usize> {
        // Encode the nonce
        let mut nonce = [0u8; SPDM_NONCE_LEN];
        Rng::generate_random_number(&mut nonce)
            .await
            .map_err(|e| (false, CommandError::CaliptraApi(e)))?;
        let mut len = encode_u8_slice(&nonce, buf).map_err(|e| (false, CommandError::Codec(e)))?;

        // Encode the opaque data length (always 0 in this case)
        let opaque_data_len = 0u16;
        let opaque_data_len_bytes = opaque_data_len.to_le_bytes();
        len += encode_u8_slice(&opaque_data_len_bytes, buf)
            .map_err(|e| (false, CommandError::Codec(e)))?;

        // Encode the requester context if present
        if let Some(context) = &self.requester_context {
            len += context
                .encode(buf)
                .map_err(|e| (false, CommandError::Codec(e)))?;
        }

        Ok(len)
    }

    async fn l1_signature(
        &self,
        asym_algo: AsymAlgo,
        transcript: &mut Transcript,
        session_info: Option<&mut SessionInfo>,
        cert_store: &dyn SpdmCertStore,
    ) -> CommandResult<[u8; ECC_P384_SIGNATURE_SIZE]> {
        let mut signature = [0u8; ECC_P384_SIGNATURE_SIZE];
        let mut signature_buf = MessageBuf::new(&mut signature);
        let _ = self
            .encode_l1_signature(
                asym_algo,
                transcript,
                session_info,
                cert_store,
                &mut signature_buf,
            )
            .await?;

        Ok(signature)
    }

    async fn encode_l1_signature(
        &self,
        asym_algo: AsymAlgo,
        transcript: &mut Transcript,
        session_info: Option<&mut SessionInfo>,
        cert_store: &dyn SpdmCertStore,
        buf: &mut MessageBuf<'_>,
    ) -> CommandResult<usize> {
        // Get the L1 transcript hash
        let mut l1_transcript_hash = [0u8; SHA384_HASH_SIZE];

        transcript
            .hash(
                TranscriptContext::L1,
                session_info,
                &mut l1_transcript_hash,
                true,
            )
            .await
            .map_err(|e| (false, CommandError::Transcript(e)))?;

        // Get TBS via response code
        let tbs = get_tbs_via_response_code(
            self.spdm_version,
            ReqRespCode::Measurements,
            l1_transcript_hash,
        )
        .await
        .map_err(|e| (false, CommandError::SignCtx(e)))?;

        let slot_id = self.slot_id.ok_or((
            false,
            CommandError::Measurement(MeasurementsError::InvalidSlotId),
        ))?;

        let mut signature = [0u8; ECC_P384_SIGNATURE_SIZE];
        cert_store
            .sign_hash(slot_id, asym_algo, &tbs, &mut signature)
            .await
            .map_err(|e| (false, CommandError::CertStore(e)))?;

        buf.put_data(signature.len())
            .map_err(|e| (false, CommandError::Codec(e)))?;
        let signature_buf = buf
            .data_mut(signature.len())
            .map_err(|e| (false, CommandError::Codec(e)))?;
        signature_buf.copy_from_slice(&signature);
        buf.pull_data(signature.len())
            .map_err(|e| (false, CommandError::Codec(e)))?;

        Ok(signature.len())
    }

    async fn response_size(&self, measurements: &mut SpdmMeasurements<'_>) -> CommandResult<usize> {
        // Calculate the size of the response based on the request attributes
        let mut rsp_size = RESPONSE_FIXED_FIELDS_SIZE;

        if self.meas_op > 0 {
            // return the size of a measurement block or all measurement blocks
            rsp_size += measurements
                .measurement_block_size(self.meas_op, false)
                .await
                .map_err(|e| (false, CommandError::Measurement(e)))?;
        };

        // Nonce is always present
        rsp_size += SPDM_NONCE_LEN;

        // Only length of opaque data length field(2 bytes). There's no opaque data in this response.
        rsp_size += size_of::<u16>();

        // Requester context is optional and only present for version >= 1.3
        if self.requester_context.is_some() {
            rsp_size += size_of::<RequesterContext>();
        }
        // If signature is requested, add the size of the signature
        if self.req_attr.signature_requested() == 1 {
            rsp_size += self.asym_algo.signature_size();
        }
        Ok(rsp_size)
    }
}

async fn process_get_measurements<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<MeasurementsResponse> {
    // Validate the version
    let connection_version = ctx.validate_spdm_version(&spdm_hdr, req_payload)?;

    // Decode the request
    let req_common = GetMeasurementsReqCommon::decode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    let slot_id = if req_common.req_attr.signature_requested() == 0 {
        if GetMeasurementsReqSignature::decode(req_payload).is_ok() {
            // If signature is not requested, the signature fields must not be present
            Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
        }
        None
    } else {
        // check if responder capabilities support signature
        if ctx.local_capabilities.flags.meas_cap()
            != MeasCapability::MeasurementsWithSignature as u8
        {
            Err(ctx.generate_error_response(req_payload, ErrorCode::UnsupportedRequest, 0, None))?;
        }

        // Decode the requester nonce and slot ID
        let req_signature_fields =
            GetMeasurementsReqSignature::decode(req_payload).map_err(|_| {
                ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
            })?;
        // Set the nonce in the measurements module
        ctx.measurements
            .set_nonce(req_signature_fields.requester_nonce);
        Some(req_signature_fields.slot_id)
    };

    // Decode the requester context if version is >= 1.3
    let requester_context = if connection_version >= SpdmVersion::V13 {
        Some(RequesterContext::decode(req_payload).map_err(|_| {
            ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
        })?)
    } else {
        None
    };

    // Reset the transcript for the GET_MEASUREMENTS request
    ctx.reset_transcript_via_req_code(ReqRespCode::GetMeasurements);

    let session_id = ctx.session_mgr.active_session_id();

    // Append the request to the transcript (TODO: check session_info)
    ctx.append_message_to_transcript(req_payload, TranscriptContext::L1, session_id)
        .await?;

    let asym_algo = ctx.validate_negotiated_base_asym_algo(req_payload)?;

    let get_meas_req_context = MeasurementsResponse {
        spdm_version: connection_version,
        req_attr: req_common.req_attr,
        meas_op: req_common.meas_op,
        slot_id,
        requester_context,
        asym_algo,
    };

    Ok(get_meas_req_context)
}

pub(crate) async fn generate_measurements_response<'a>(
    ctx: &mut SpdmContext<'a>,
    rsp_ctx: MeasurementsResponse,
    rsp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    let rsp_len = rsp_ctx.response_size(&mut ctx.measurements).await?;

    if rsp_len > ctx.min_data_transfer_size() {
        // If the response is larger than the minimum data transfer size, use chunked response
        let large_rsp = LargeResponse::Measurements(rsp_ctx);
        let handle = ctx.large_resp_context.init(large_rsp, rsp_len);
        Err(ctx.generate_error_response(rsp, ErrorCode::LargeResponse, 0, Some(&[handle])))?
    } else {
        let session_info = match ctx.session_mgr.active_session_id() {
            Some(session_id) => match ctx.session_mgr.session_info_mut(session_id) {
                Ok(info) => Some(info),
                Err(e) => Err((false, CommandError::Session(e)))?,
            },
            None => None,
        };

        // If the response fits in a single message, prepare it directly
        // Encode the response fixed fields
        rsp.put_data(rsp_len)
            .map_err(|e| (false, CommandError::Codec(e)))?;
        let rsp_buf = rsp
            .data_mut(rsp_len)
            .map_err(|e| (false, CommandError::Codec(e)))?;
        let payload_len = rsp_ctx
            .get_chunk(
                &mut ctx.measurements,
                &mut ctx.shared_transcript,
                ctx.device_certs_store,
                0,
                rsp_buf,
                session_info,
            )
            .await?;
        if rsp_len != payload_len {
            Err((
                false,
                CommandError::Measurement(MeasurementsError::InvalidBuffer),
            ))?;
        }
        rsp.pull_data(payload_len)
            .map_err(|e| (false, CommandError::Codec(e)))?;

        rsp.push_data(payload_len)
            .map_err(|e| (false, CommandError::Codec(e)))
    }
}

pub(crate) async fn handle_get_measurements<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    // Check that the connection state is Negotiated
    if ctx.state.connection_info.state() < ConnectionState::AlgorithmsNegotiated {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    // Check if the measurement capability is supported
    if ctx.local_capabilities.flags.meas_cap() == MeasCapability::NoMeasurement as u8 {
        return Err(ctx.generate_error_response(
            req_payload,
            ErrorCode::UnsupportedRequest,
            0,
            None,
        ));
    }

    // Verify that the DMTF measurement spec is selected and the measurement hash algorithm is SHA384
    let meas_spec_sel = selected_measurement_specification(ctx);
    if meas_spec_sel.dmtf_measurement_spec() == 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }
    ctx.validate_negotiated_hash_algo(req_payload)?;

    // Process GET_MEASUREMENTS request
    let rsp_ctx = process_get_measurements(ctx, spdm_hdr, req_payload).await?;

    // Generate MEASUREMENTS response
    ctx.prepare_response_buffer(req_payload)?;
    generate_measurements_response(ctx, rsp_ctx, req_payload).await?;
    Ok(())
}

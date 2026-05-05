// Licensed under the Apache-2.0 license

use crate::codec::{Codec, CommonCodec, DataKind, MessageBuf};
use crate::commands::error_rsp::{encode_error_response, ErrorCode};
use crate::context::{SpdmContext, MAX_SPDM_RESPONDER_BUF_SIZE};
use crate::error::{CommandError, CommandResult};
use crate::protocol::*;
use crate::state::ConnectionState;
use bitfield::bitfield;
use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
struct ChunkSendReq {
    chunk_sender_attr: ChunkSenderAttr,
    handle: u8,
    chunk_seq_num: u16,
    reserved: u16,
    chunk_size: u32,
}
impl CommonCodec for ChunkSendReq {}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
struct ChunkSendAckHdr {
    spdm_version: u8,
    req_resp_code: u8,
    chunk_receiver_attr: ChunkReceiverAttr,
    handle: u8,
    chunk_seq_num: u16,
}
impl CommonCodec for ChunkSendAckHdr {
    const DATA_KIND: DataKind = DataKind::Header;
}

bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Clone, Copy)]
#[repr(C)]
struct ChunkSenderAttr(u8);
impl Debug;
u8;
pub last_chunk, set_last_chunk: 0, 0;
reserved, _: 7, 1;
}

bitfield! {
#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct ChunkReceiverAttr(u8);
impl Debug;
u8;
pub early_error_detected, set_early_error_detected: 0, 0;
reserved, _: 7, 1;
}

struct ChunkSendInfo {
    handle: u8,
    chunk_seq_num: u16,
    complete: bool,
}

enum ChunkSendProcessResult {
    Ack(ChunkSendInfo),
    EarlyError { handle: u8, chunk_seq_num: u16 },
}

fn append_bytes_without_advancing_data(rsp: &mut MessageBuf<'_>, data: &[u8]) -> CommandResult<()> {
    rsp.put_data(data.len())
        .map_err(|e| (false, CommandError::Codec(e)))?;
    let dst = rsp
        .data_mut(data.len())
        .map_err(|e| (false, CommandError::Codec(e)))?;
    dst.copy_from_slice(data);
    Ok(())
}

fn encode_error_response_to_slice(
    spdm_version: SpdmVersion,
    error_code: ErrorCode,
    out: &mut [u8],
) -> CommandResult<usize> {
    let mut error_msg = MessageBuf::new(out);
    let (send_response, command_error) =
        encode_error_response(&mut error_msg, spdm_version, error_code, 0, None);
    if !send_response {
        return Err((false, command_error));
    }
    Ok(error_msg.data_len())
}

fn append_error_response(
    spdm_version: SpdmVersion,
    error_code: ErrorCode,
    rsp: &mut MessageBuf<'_>,
) -> CommandResult<usize> {
    let mut error_buf = [0u8; 64];
    let error_len = encode_error_response_to_slice(spdm_version, error_code, &mut error_buf)?;
    append_bytes_without_advancing_data(rsp, &error_buf[..error_len])?;
    Ok(error_len)
}

fn encode_chunk_send_ack_hdr(
    version: SpdmVersion,
    early_error_detected: bool,
    handle: u8,
    chunk_seq_num: u16,
    rsp: &mut MessageBuf<'_>,
) -> CommandResult<usize> {
    let mut chunk_receiver_attr = ChunkReceiverAttr(0);
    if early_error_detected {
        chunk_receiver_attr.set_early_error_detected(1);
    }

    let ack = ChunkSendAckHdr {
        spdm_version: version.into(),
        req_resp_code: ReqRespCode::ChunkSendAck.into(),
        chunk_receiver_attr,
        handle,
        chunk_seq_num,
    };

    ack.encode(rsp).map_err(|e| (false, CommandError::Codec(e)))
}

fn validate_common(
    ctx: &SpdmContext<'_>,
    spdm_hdr: &SpdmMsgHdr,
    req: &mut MessageBuf<'_>,
) -> CommandResult<SpdmVersion> {
    let connection_version = ctx.validate_spdm_version(spdm_hdr, req)?;

    if connection_version < SpdmVersion::V12 {
        Err(ctx.generate_error_response(
            req,
            ErrorCode::UnsupportedRequest,
            ReqRespCode::ChunkSend.into(),
            None,
        ))?;
    }

    if ctx.state.connection_info.state() < ConnectionState::AfterCapabilities
        || !ctx.support_large_msg_chunking()
        || ctx.large_resp_context.in_progress()
    {
        Err(ctx.generate_error_response(req, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    Ok(connection_version)
}

fn process_chunk_send(
    ctx: &mut SpdmContext<'_>,
    spdm_hdr: SpdmMsgHdr,
    req: &mut MessageBuf<'_>,
) -> CommandResult<ChunkSendProcessResult> {
    validate_common(ctx, &spdm_hdr, req)?;

    let chunk_send_req = ChunkSendReq::decode(req)
        .map_err(|_| ctx.generate_error_response(req, ErrorCode::InvalidRequest, 0, None))?;
    let handle = chunk_send_req.handle;
    let chunk_seq_num = chunk_send_req.chunk_seq_num;
    let chunk_size = chunk_send_req.chunk_size as usize;
    let last_chunk = chunk_send_req.chunk_sender_attr.last_chunk() != 0;
    let has_reserved_bits =
        chunk_send_req.reserved != 0 || chunk_send_req.chunk_sender_attr.reserved() != 0;

    let available_chunk_len = req.data_len();
    let chunk_send_msg_len =
        size_of::<SpdmMsgHdr>() + size_of::<ChunkSendReq>() + available_chunk_len;

    let invalid = if has_reserved_bits {
        true
    } else if !ctx.large_req_context.in_progress() {
        if available_chunk_len < size_of::<u32>() {
            true
        } else {
            let large_message_size = u32::decode(req)
                .map_err(|_| ctx.generate_error_response(req, ErrorCode::InvalidRequest, 0, None))?
                as usize;
            let available_chunk_len = req.data_len();
            let min_first_chunk_size = MIN_DATA_TRANSFER_SIZE_V12 as usize
                - size_of::<SpdmMsgHdr>()
                - size_of::<ChunkSendReq>()
                - size_of::<u32>();

            let invalid = chunk_seq_num != 0
                || last_chunk
                || chunk_size < min_first_chunk_size
                || chunk_size != available_chunk_len
                || chunk_send_msg_len > ctx.local_capabilities.data_transfer_size as usize
                || large_message_size > ctx.local_capabilities.max_spdm_msg_size as usize
                || large_message_size > ctx.large_req_context.capacity()
                || large_message_size <= MIN_DATA_TRANSFER_SIZE_V12 as usize
                || chunk_size > large_message_size;

            if !invalid {
                let chunk = req
                    .data(chunk_size)
                    .map_err(|e| (false, CommandError::Codec(e)))?;
                ctx.large_req_context
                    .init(handle, large_message_size, chunk)
                    .is_err()
            } else {
                true
            }
        }
    } else {
        let min_chunk_size = MIN_DATA_TRANSFER_SIZE_V12 as usize
            - size_of::<SpdmMsgHdr>()
            - size_of::<ChunkSendReq>();
        let transferred = ctx.large_req_context.bytes_transferred();
        let large_message_size = ctx.large_req_context.large_request_size();
        let end = transferred.saturating_add(chunk_size);

        let invalid = chunk_seq_num == 0
            || chunk_size != available_chunk_len
            || chunk_send_msg_len > ctx.local_capabilities.data_transfer_size as usize
            || ctx
                .large_req_context
                .validate_chunk(handle, chunk_seq_num)
                .is_err()
            || end > large_message_size
            || (last_chunk && end != large_message_size)
            || (!last_chunk && (end >= large_message_size || chunk_size < min_chunk_size));

        if !invalid {
            let chunk = req
                .data(chunk_size)
                .map_err(|e| (false, CommandError::Codec(e)))?;
            ctx.large_req_context
                .append_chunk(handle, chunk_seq_num, chunk)
                .is_err()
        } else {
            true
        }
    };

    if invalid {
        ctx.large_req_context.reset();
        return Ok(ChunkSendProcessResult::EarlyError {
            handle,
            chunk_seq_num,
        });
    }

    Ok(ChunkSendProcessResult::Ack(ChunkSendInfo {
        handle,
        chunk_seq_num,
        complete: ctx.large_req_context.is_complete(),
    }))
}

async fn process_large_request<'a>(
    ctx: &mut SpdmContext<'a>,
    req: &mut MessageBuf<'a>,
    response: &mut [u8],
) -> CommandResult<usize> {
    let version = ctx.state.connection_info.version_number();
    let request_code = ctx.large_req_context.request_code();

    if matches!(
        request_code,
        Some(code) if code == ReqRespCode::ChunkSend.into() || code == ReqRespCode::ChunkGet.into()
    ) {
        ctx.large_req_context.reset();
        return encode_error_response_to_slice(version, ErrorCode::InvalidRequest, response);
    }

    if ctx.large_req_context.copy_message_to(req).is_err() {
        ctx.large_req_context.reset();
        return encode_error_response_to_slice(version, ErrorCode::RequestTooLarge, response);
    }
    ctx.large_req_context.reset();

    match ctx.handle_large_request_payload(req).await {
        Ok(()) => {}
        Err((true, _)) => {}
        Err((false, _)) => {
            return encode_error_response_to_slice(version, ErrorCode::InvalidRequest, response);
        }
    }

    let response_len = req.data_len();
    if response_len > response.len() {
        return encode_error_response_to_slice(version, ErrorCode::ResponseTooLarge, response);
    }
    let inner_response = req
        .data(response_len)
        .map_err(|e| (false, CommandError::Codec(e)))?;
    response[..response_len].copy_from_slice(inner_response);
    Ok(response_len)
}

async fn generate_chunk_send_ack<'a>(
    ctx: &mut SpdmContext<'a>,
    info: ChunkSendInfo,
    rsp: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    let version = ctx.state.connection_info.version_number();
    let mut response_to_large_request = [0u8; MAX_SPDM_RESPONDER_BUF_SIZE];
    let response_to_large_request_len = if info.complete {
        Some(process_large_request(ctx, rsp, &mut response_to_large_request).await?)
    } else {
        None
    };

    ctx.prepare_response_buffer(rsp)?;
    let header_size = size_of::<ChunkSendAckHdr>();
    rsp.reserve(header_size)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    if let Some(len) = response_to_large_request_len {
        append_bytes_without_advancing_data(rsp, &response_to_large_request[..len])?;
    }

    encode_chunk_send_ack_hdr(version, false, info.handle, info.chunk_seq_num, rsp)?;
    Ok(())
}

fn generate_chunk_send_early_error_ack(
    ctx: &mut SpdmContext<'_>,
    handle: u8,
    chunk_seq_num: u16,
    rsp: &mut MessageBuf<'_>,
) -> CommandResult<()> {
    let version = ctx.state.connection_info.version_number();
    let header_size = size_of::<ChunkSendAckHdr>();
    rsp.reserve(header_size)
        .map_err(|e| (false, CommandError::Codec(e)))?;
    append_error_response(version, ErrorCode::InvalidRequest, rsp)?;
    encode_chunk_send_ack_hdr(version, true, handle, chunk_seq_num, rsp)?;
    Ok(())
}

pub(crate) async fn handle_chunk_send<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    let result = process_chunk_send(ctx, spdm_hdr, req)?;

    ctx.prepare_response_buffer(req)?;
    match result {
        ChunkSendProcessResult::Ack(info) => generate_chunk_send_ack(ctx, info, req).await,
        ChunkSendProcessResult::EarlyError {
            handle,
            chunk_seq_num,
        } => generate_chunk_send_early_error_ack(ctx, handle, chunk_seq_num, req),
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use crate::cert_store::{CertStoreError, CertStoreResult, SpdmCertStore};
    use crate::measurements::{MeasurementsResult, SpdmMeasurementValue};
    use crate::protocol::algorithms::LocalDeviceAlgorithms;
    use crate::transport::common::{SpdmTransport, TransportError, TransportResult};
    use alloc::boxed::Box;
    use async_trait::async_trait;
    use caliptra_mcu_libapi_caliptra::crypto::asym::{AsymAlgo, ECC_P384_SIGNATURE_SIZE};
    use caliptra_mcu_libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;

    const TEST_MAX_SPDM_MSG_SIZE: usize = 2048;

    struct TestTransport;

    #[async_trait]
    impl SpdmTransport for TestTransport {
        async fn send_request<'a>(
            &mut self,
            _dest_eid: u8,
            _req: &mut MessageBuf<'a>,
            _secure: Option<bool>,
        ) -> TransportResult<()> {
            Err(TransportError::OperationNotSupported)
        }

        async fn receive_response<'a>(
            &mut self,
            _rsp: &mut MessageBuf<'a>,
        ) -> TransportResult<bool> {
            Err(TransportError::OperationNotSupported)
        }

        async fn receive_request<'a>(
            &mut self,
            _req: &mut MessageBuf<'a>,
        ) -> TransportResult<bool> {
            Err(TransportError::OperationNotSupported)
        }

        async fn send_response<'a>(
            &mut self,
            _resp: &mut MessageBuf<'a>,
            _secure: bool,
        ) -> TransportResult<()> {
            Err(TransportError::OperationNotSupported)
        }

        fn max_message_size(&self) -> TransportResult<usize> {
            Ok(64)
        }

        fn header_size(&self) -> usize {
            0
        }
    }

    struct TestCertStore;

    struct TestMeasurements;

    static SPDM_VERSIONS: &[SpdmVersion] = &[SpdmVersion::V12];

    #[async_trait]
    impl SpdmCertStore for TestCertStore {
        fn slot_count(&self) -> u8 {
            0
        }

        async fn is_provisioned(&self, _slot_id: u8) -> bool {
            false
        }

        async fn cert_chain_len(
            &self,
            _asym_algo: AsymAlgo,
            _slot_id: u8,
        ) -> CertStoreResult<usize> {
            Err(CertStoreError::UnprovisionedSlot)
        }

        async fn get_cert_chain<'a>(
            &self,
            _slot_id: u8,
            _asym_algo: AsymAlgo,
            _offset: usize,
            _cert_portion: &'a mut [u8],
        ) -> CertStoreResult<usize> {
            Err(CertStoreError::UnprovisionedSlot)
        }

        async fn root_cert_hash<'a>(
            &self,
            _slot_id: u8,
            _asym_algo: AsymAlgo,
            _cert_hash: &'a mut [u8; SHA384_HASH_SIZE],
        ) -> CertStoreResult<()> {
            Err(CertStoreError::UnprovisionedSlot)
        }

        async fn sign_hash<'a>(
            &self,
            _slot_id: u8,
            _asym_algo: AsymAlgo,
            _hash: &'a [u8; SHA384_HASH_SIZE],
            _signature: &'a mut [u8; ECC_P384_SIGNATURE_SIZE],
        ) -> CertStoreResult<()> {
            Err(CertStoreError::UnprovisionedSlot)
        }

        async fn key_pair_id(&self, _slot_id: u8) -> Option<u8> {
            None
        }

        async fn cert_info(&self, _slot_id: u8) -> Option<CertificateInfo> {
            None
        }

        async fn key_usage_mask(&self, _slot_id: u8) -> Option<KeyUsageMask> {
            None
        }
    }

    #[async_trait]
    impl SpdmMeasurementValue for TestMeasurements {
        async fn get_measurement_value(
            &mut self,
            _index: u8,
            _nonce: &[u8],
            _asym_algo: AsymAlgo,
            _measurement: &mut [u8],
        ) -> MeasurementsResult<usize> {
            Ok(0)
        }
    }

    fn test_context<'a>(
        transport: &'a mut TestTransport,
        cert_store: &'a TestCertStore,
        measurements: &'a mut TestMeasurements,
        large_resp_buf: &'a mut [u8],
        large_req_buf: &'a mut [u8],
    ) -> SpdmContext<'a> {
        let mut flags = CapabilityFlags::default();
        flags.set_chunk_cap(1);
        let capabilities = DeviceCapabilities {
            ct_exponent: 0,
            flags,
            data_transfer_size: 64,
            max_spdm_msg_size: TEST_MAX_SPDM_MSG_SIZE as u32,
        };

        let mut ctx = SpdmContext::new(
            SPDM_VERSIONS,
            SPDM_VERSIONS,
            transport,
            capabilities,
            LocalDeviceAlgorithms::default(),
            cert_store,
            crate::measurements::SpdmMeasurements::new(&[], measurements),
            None,
            large_resp_buf,
            large_req_buf,
        )
        .expect("test context should be valid");
        ctx.state
            .connection_info
            .set_version_number(SpdmVersion::V12);
        ctx.state
            .connection_info
            .set_state(ConnectionState::AfterCapabilities);
        ctx.state
            .connection_info
            .set_peer_capabilities(capabilities);
        ctx
    }

    fn decode_header(buf: &mut MessageBuf<'_>) -> SpdmMsgHdr {
        SpdmMsgHdr::decode(buf).expect("SPDM header should decode")
    }

    fn build_chunk_send<'a>(
        storage: &'a mut [u8],
        sender_attr: u8,
        seq: u16,
        reserved: u16,
        large_message_size: Option<u32>,
        chunk: &[u8],
        extra_payload: &[u8],
    ) -> MessageBuf<'a> {
        let mut offset = 0;
        storage[offset] = SpdmVersion::V12.into();
        storage[offset + 1] = ReqRespCode::ChunkSend.into();
        offset += size_of::<SpdmMsgHdr>();
        storage[offset] = sender_attr;
        storage[offset + 1] = 7;
        storage[offset + 2..offset + 4].copy_from_slice(&seq.to_le_bytes());
        storage[offset + 4..offset + 6].copy_from_slice(&reserved.to_le_bytes());
        storage[offset + 6..offset + 10].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
        offset += size_of::<ChunkSendReq>();
        if let Some(size) = large_message_size {
            storage[offset..offset + size_of::<u32>()].copy_from_slice(&size.to_le_bytes());
            offset += size_of::<u32>();
        }
        storage[offset..offset + chunk.len()].copy_from_slice(chunk);
        offset += chunk.len();
        storage[offset..offset + extra_payload.len()].copy_from_slice(extra_payload);
        offset += extra_payload.len();

        MessageBuf::from(&mut storage[..offset])
    }

    #[test]
    fn test_process_chunk_send_accepts_two_chunk_large_request() {
        let mut transport = TestTransport;
        let cert_store = TestCertStore;
        let mut measurements = TestMeasurements;
        let mut large_resp_buf = [0u8; 1024];
        let mut large_req_buf = [0u8; 2048];
        let mut ctx = test_context(
            &mut transport,
            &cert_store,
            &mut measurements,
            &mut large_resp_buf,
            &mut large_req_buf,
        );

        let first_chunk = [0xAA; 30];
        let mut first_storage = [0u8; 96];
        let mut first_msg =
            build_chunk_send(&mut first_storage, 0, 0, 0, Some(80), &first_chunk, &[]);
        let first_hdr = decode_header(&mut first_msg);
        let first_result = process_chunk_send(&mut ctx, first_hdr, &mut first_msg)
            .expect("first chunk should be accepted");

        match first_result {
            ChunkSendProcessResult::Ack(info) => {
                assert_eq!(info.handle, 7);
                assert_eq!(info.chunk_seq_num, 0);
                assert!(!info.complete);
            }
            ChunkSendProcessResult::EarlyError { .. } => panic!("unexpected early error"),
        }
        assert_eq!(ctx.large_req_context.bytes_transferred(), 30);

        let second_chunk = [0xBB; 50];
        let mut second_storage = [0u8; 96];
        let mut second_msg =
            build_chunk_send(&mut second_storage, 1, 1, 0, None, &second_chunk, &[]);
        let second_hdr = decode_header(&mut second_msg);
        let second_result = process_chunk_send(&mut ctx, second_hdr, &mut second_msg)
            .expect("last chunk should be accepted");

        match second_result {
            ChunkSendProcessResult::Ack(info) => {
                assert_eq!(info.handle, 7);
                assert_eq!(info.chunk_seq_num, 1);
                assert!(info.complete);
            }
            ChunkSendProcessResult::EarlyError { .. } => panic!("unexpected early error"),
        }
        assert_eq!(ctx.large_req_context.bytes_transferred(), 80);
    }

    #[test]
    fn test_process_chunk_send_rejects_unexpected_sequence() {
        let mut transport = TestTransport;
        let cert_store = TestCertStore;
        let mut measurements = TestMeasurements;
        let mut large_resp_buf = [0u8; 1024];
        let mut large_req_buf = [0u8; 2048];
        let mut ctx = test_context(
            &mut transport,
            &cert_store,
            &mut measurements,
            &mut large_resp_buf,
            &mut large_req_buf,
        );

        let first_chunk = [0xAA; 30];
        let mut first_storage = [0u8; 96];
        let mut first_msg =
            build_chunk_send(&mut first_storage, 0, 0, 0, Some(80), &first_chunk, &[]);
        let first_hdr = decode_header(&mut first_msg);
        process_chunk_send(&mut ctx, first_hdr, &mut first_msg)
            .expect("first chunk should be accepted");

        let second_chunk = [0xBB; 50];
        let mut second_storage = [0u8; 96];
        let mut second_msg =
            build_chunk_send(&mut second_storage, 1, 2, 0, None, &second_chunk, &[]);
        let second_hdr = decode_header(&mut second_msg);
        let second_result = process_chunk_send(&mut ctx, second_hdr, &mut second_msg)
            .expect("bad chunk should produce early-error ack state");

        match second_result {
            ChunkSendProcessResult::Ack(_) => panic!("bad sequence should not be accepted"),
            ChunkSendProcessResult::EarlyError {
                handle,
                chunk_seq_num,
            } => {
                assert_eq!(handle, 7);
                assert_eq!(chunk_seq_num, 2);
            }
        }
        assert!(!ctx.large_req_context.in_progress());
    }

    #[test]
    fn test_process_chunk_send_rejects_reserved_fields() {
        let mut transport = TestTransport;
        let cert_store = TestCertStore;
        let mut measurements = TestMeasurements;
        let mut large_resp_buf = [0u8; 1024];
        let mut large_req_buf = [0u8; 2048];
        let mut ctx = test_context(
            &mut transport,
            &cert_store,
            &mut measurements,
            &mut large_resp_buf,
            &mut large_req_buf,
        );

        let first_chunk = [0xAA; 30];
        let mut storage = [0u8; 96];
        let mut msg = build_chunk_send(&mut storage, 0b10, 0, 1, Some(80), &first_chunk, &[]);
        let hdr = decode_header(&mut msg);
        let result = process_chunk_send(&mut ctx, hdr, &mut msg)
            .expect("reserved fields should produce early-error ack state");

        match result {
            ChunkSendProcessResult::Ack(_) => panic!("reserved fields should not be accepted"),
            ChunkSendProcessResult::EarlyError {
                handle,
                chunk_seq_num,
            } => {
                assert_eq!(handle, 7);
                assert_eq!(chunk_seq_num, 0);
            }
        }
        assert!(!ctx.large_req_context.in_progress());
    }

    #[test]
    fn test_process_chunk_send_rejects_extra_payload() {
        let mut transport = TestTransport;
        let cert_store = TestCertStore;
        let mut measurements = TestMeasurements;
        let mut large_resp_buf = [0u8; 1024];
        let mut large_req_buf = [0u8; 2048];
        let mut ctx = test_context(
            &mut transport,
            &cert_store,
            &mut measurements,
            &mut large_resp_buf,
            &mut large_req_buf,
        );

        let first_chunk = [0xAA; 30];
        let extra_payload = [0xCC; 1];
        let mut storage = [0u8; 96];
        let mut msg = build_chunk_send(
            &mut storage,
            0,
            0,
            0,
            Some(80),
            &first_chunk,
            &extra_payload,
        );
        let hdr = decode_header(&mut msg);
        let result = process_chunk_send(&mut ctx, hdr, &mut msg)
            .expect("extra payload should produce early-error ack state");

        match result {
            ChunkSendProcessResult::Ack(_) => panic!("extra payload should not be accepted"),
            ChunkSendProcessResult::EarlyError {
                handle,
                chunk_seq_num,
            } => {
                assert_eq!(handle, 7);
                assert_eq!(chunk_seq_num, 0);
            }
        }
        assert!(!ctx.large_req_context.in_progress());
    }

    #[test]
    fn test_generate_chunk_send_early_error_ack_embeds_error_response() {
        let mut transport = TestTransport;
        let cert_store = TestCertStore;
        let mut measurements = TestMeasurements;
        let mut large_resp_buf = [0u8; 1024];
        let mut large_req_buf = [0u8; 2048];
        let mut ctx = test_context(
            &mut transport,
            &cert_store,
            &mut measurements,
            &mut large_resp_buf,
            &mut large_req_buf,
        );
        let mut storage = [0u8; 64];
        let mut msg = MessageBuf::new(&mut storage);
        ctx.prepare_response_buffer(&mut msg)
            .expect("reserve transport header");

        generate_chunk_send_early_error_ack(&mut ctx, 9, 3, &mut msg)
            .expect("early-error ack should encode");

        let len = msg.data_len();
        let data = msg.data(len).expect("encoded response");
        assert_eq!(data[0], SpdmVersion::V12.into());
        assert_eq!(data[1], ReqRespCode::ChunkSendAck.into());
        assert_eq!(data[2] & 1, 1);
        assert_eq!(data[3], 9);
        assert_eq!(&data[4..6], &3u16.to_le_bytes());
        assert_eq!(data[6], SpdmVersion::V12.into());
        assert_eq!(data[7], ReqRespCode::Error.into());
        assert_eq!(data[8], ErrorCode::InvalidRequest.into());
    }
}

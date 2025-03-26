// Import the DeviceCertsMgrError type
// Licensed under the Apache-2.0 license

use crate::cert_mgr;
use crate::codec::{Codec, CodecError, CodecResult, CommonCodec, DataKind, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::CommandError;
use crate::error::{CommandResult, SpdmError};
use crate::protocol::algorithms::{
    BaseHashAlgoType, Prioritize, SPDM_MAX_HASH_SIZE, SPDM_MAX_SLOT_NUMBER,
};
use crate::protocol::cert::{SpdmCertChainBaseBuffer, SpdmCertChainData};
use crate::protocol::common::SpdmMsgHdr;
use crate::state::ConnectionState;
use libtock_platform::Syscalls;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use core::fmt::Write;

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C)]
pub struct GetDigestsReq {
    param1: u8, //reserved
    param2: u8, //reserved
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
        // Not needed in SPDM responder
        unimplemented!()
    }
}

pub struct GetDigestsResp {
    pub common: GetDigestsRespCommon,
    pub digests: [SpdmDigest; SPDM_MAX_SLOT_NUMBER],
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

        // Get slot count from slot_mask, slot mask is bit field
        let slot_cnt = self.common.slot_mask.count_ones() as usize;

        for digest in self.digests.iter().take(slot_cnt) {
            len += digest.encode(buffer)?;
        }

        Ok(len)
    }

    fn decode(_data: &mut MessageBuf) -> CodecResult<Self> {
        // Not needed in SPDM responder
        unimplemented!()
    }
}

pub(crate) fn handle_digests<'a, S: Syscalls>(
    ctx: &mut SpdmContext<'a, S>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    //println!("[xs debug] handle_digests start");
    writeln!(ctx.cw, "[xs debug] handle_digests start").unwrap();

    // Validate the state
    if ctx.state.connection_info.state() != ConnectionState::AfterNegotiateAlgorithms {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    // Validate the version
    let connection_version = ctx.state.connection_info.version_number();
    match spdm_hdr.version() {
        Ok(version) if version == connection_version => {}
        _ => Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?,
    }

    // Decode the request
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

    // TODO: Session handling

    // TODO: transcript message handling

    // Get digest size based on the base hash algorithm
    let hash_algo = get_hash_algo_from_context(ctx);

    let mut digest = SpdmDigest::default();

    // Get the digest of the certificate chain
    get_certificate_chain_digest(ctx, hash_algo, &mut digest)
        .map_err(|_| ctx.generate_error_response(req_payload, ErrorCode::Unspecified, 0, None))?;

    let slot_mask = 1u8; // Only 1 slot is supported

    // Construct the response
    let resp = GetDigestsResp::new(slot_mask, &[digest]);

    writeln!(ctx.cw, "[xs debug] handle_digests: prepare_response_buffer").unwrap();

    // Prepare the response buffer
    ctx.prepare_response_buffer(req_payload)?;

    let payload_len = resp.encode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    // Push data offset up by total payload length
    req_payload
        .push_data(payload_len)
        .map_err(|_| (false, CommandError::BufferTooSmall))?;

    // Set the connection state to AfterAlgorithms
    ctx.state
        .connection_info
        .set_state(ConnectionState::AfterDigest);

    writeln!(
        ctx.cw,
        "[xs debug] handle_digests end, payload_len: {:?}",
        payload_len
    )
    .unwrap();

    Ok(())
}

// Helper function to get the hash size based on the base hash algorithm
fn get_hash_algo_from_context<'a, S: Syscalls>(ctx: &SpdmContext<'a, S>) -> BaseHashAlgoType {
    // Get the hash size based on the base hash algorithm and prioritize algorithm table
    let peer_algorithms = ctx.state.connection_info.peer_algorithms();
    let local_algorithms = &ctx.local_algorithms.device_algorithms;
    let algorithm_priority_table = &ctx.local_algorithms.algorithm_priority_table;

    // BaseHashSel
    let base_hash_sel = local_algorithms.base_hash_algo.prioritize(
        &peer_algorithms.base_hash_algo,
        algorithm_priority_table.base_hash_algo,
    );

    // BaseHashSel should only have 1 bit set
    if base_hash_sel.0.count_ones() != 1 {
        panic!("Invalid selected hash algorithm");
    }
    // Ensure the selected hash algorithm is valid
    let hash_algo = BaseHashAlgoType::try_from(base_hash_sel.0.trailing_zeros() as u8)
        .expect("Invalid selected hash algorithm");

    hash_algo
}

fn get_certificate_chain_digest<'a, S: Syscalls>(
    ctx: &mut SpdmContext<'a, S>,
    hash_type: BaseHashAlgoType,
    digest: &mut SpdmDigest,
) -> Result<(), SpdmError> {
    // Create an array containing 4 DerCerts with default values
    let mut cert_chain_data = SpdmCertChainData::default();
    let mut root_hash = SpdmDigest::default();

    let root_cert_len =
        cert_mgr::get_certificate_list(ctx.device_certs_manager, &mut cert_chain_data)?;

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

    // Start the hash engine
    ctx.hash_engine
        .start(hash_type)
        .map_err(SpdmError::HashEngine)?;

    // Hash the cert chain base
    ctx.hash_engine
        .update(cert_chain_base_buf.as_ref())
        .map_err(SpdmError::HashEngine)?;

    // Hash the cert chain data
    ctx.hash_engine
        .update(&cert_chain_data.as_ref())
        .map_err(SpdmError::HashEngine)?;

    // Finalize the hash engine
    ctx.hash_engine
        .finish(digest)
        .map_err(SpdmError::HashEngine)?;

    writeln!(
        ctx.cw,
        "[xs debug] get_certificate_chain_digest: {:?}",
        digest
    )
    .unwrap();
    Ok(())
}

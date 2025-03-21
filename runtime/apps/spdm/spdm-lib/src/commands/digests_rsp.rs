// Import the DeviceCertsMgrError type
// Licensed under the Apache-2.0 license

use crate::cert_mgr::{DerCert, DeviceCertsManager, DeviceKeys};
use crate::codec::{Codec, CodecError, CodecResult, CommonCodec, DataKind, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandResult, SpdmError};
use crate::protocol::algorithms::{
    BaseHashAlgoType, Prioritize, SPDM_MAX_HASH_SIZE, SPDM_MAX_SLOT_NUMBER,
};
use crate::protocol::common::SpdmMsgHdr;
use crate::state::ConnectionState;
use libtock_platform::Syscalls;
use zerocopy::{FromBytes, Immutable, IntoBytes};

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
    pub length: usize,
}

impl Default for SpdmDigest {
    fn default() -> Self {
        Self {
            data: [0u8; SPDM_MAX_HASH_SIZE],
            length: 0,
        }
    }
}

impl SpdmDigest {
    pub fn new(digest: &[u8]) -> Self {
        let mut data = [0u8; SPDM_MAX_HASH_SIZE];
        let length = digest.len().min(SPDM_MAX_HASH_SIZE);
        data[..length].copy_from_slice(&digest[..length]);
        Self { data, length }
    }
}

impl Codec for SpdmDigest {
    fn encode(&self, buffer: &mut MessageBuf) -> CodecResult<usize> {
        let hash_len = self.length.min(SPDM_MAX_HASH_SIZE);
        // iterates over the data and encode into the buffer
        buffer.put_data(hash_len)?;

        if buffer.data_len() < hash_len {
            Err(CodecError::BufferTooSmall)?;
        }

        let payload = buffer.data_mut(hash_len)?;

        self.data[..hash_len]
            .write_to(payload)
            .map_err(|_| CodecError::WriteError)?;
        buffer.pull_data(hash_len)?;
        Ok(hash_len)
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

/*
 * Process the SPDM GET_DIGESTS request.
 *
 * @param spdm_responder SPDM responder instance.
 * @param request GET_DIGESTS request to process.
 *
 * @return 0 if the request was processed successfully or an error code.
 */
/*
int spdm_get_digests (const struct cmd_interface_spdm_responder *spdm_responder,
    struct cmd_interface_msg *request)
{
    int status;
    int spdm_error;
    struct spdm_get_digests_request *spdm_request;
    struct spdm_get_digests_response *spdm_response;
    uint8_t spdm_version;
    uint32_t response_size;
    int hash_size;
    const struct spdm_transcript_manager *transcript_manager;
    struct spdm_state *state;
    const struct spdm_device_capability *local_capabilities;
    const struct hash_engine *hash_engine;
    enum hash_type hash_type;
    const struct riot_key_manager *key_manager;
    struct spdm_secure_session_manager *session_manager;
    struct spdm_secure_session *session = NULL;

    if ((spdm_responder == NULL) || (request == NULL)) {
        return CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT;
    }

    transcript_manager = spdm_responder->transcript_manager;
    state = spdm_responder->state;
    local_capabilities = spdm_responder->local_capabilities;
    key_manager = spdm_responder->key_manager;
    hash_engine = spdm_responder->hash_engine[0];
    hash_type = spdm_get_hash_type (state->connection_info.peer_algorithms.base_hash_algo);
    session_manager = spdm_responder->session_manager;

    /* Validate the request. */
    if (request->payload_length < sizeof (struct spdm_get_digests_request)) {
        status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
        spdm_error = SPDM_ERROR_INVALID_REQUEST;
        goto exit;
    }
    spdm_request = (struct spdm_get_digests_request*) request->payload;
    spdm_version = SPDM_MAKE_VERSION (spdm_request->header.spdm_major_version,
        spdm_request->header.spdm_minor_version);
    if (spdm_version != spdm_get_connection_version (state)) {
        status = CMD_HANDLER_SPDM_RESPONDER_VERSION_MISMATCH;
        spdm_error = SPDM_ERROR_VERSION_MISMATCH;
        goto exit;
    }

    /* Verify SPDM state. */
    if (state->response_state != SPDM_RESPONSE_STATE_NORMAL) {
        spdm_handle_response_state (state, &spdm_error);
        status = CMD_HANDLER_SPDM_RESPONDER_INTERNAL_ERROR;
        goto exit;
    }
    if (state->connection_info.connection_state < SPDM_CONNECTION_STATE_NEGOTIATED) {
        status = CMD_HANDLER_SPDM_RESPONDER_UNEXPECTED_REQUEST;
        spdm_error = SPDM_ERROR_UNEXPECTED_REQUEST;
        goto exit;
    }

    /* Check if the certificate capability is supported. */
    if (local_capabilities->flags.cert_cap == 0) {
        status = CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY;
        spdm_error = SPDM_ERROR_UNSUPPORTED_REQUEST;
        goto exit;
    }

    /* Check if a session is ongoing. */
    if ((session_manager != NULL) &&
        (session_manager->is_last_session_id_valid (session_manager) == true)) {
        session = session_manager->get_session (session_manager,
            session_manager->get_last_session_id (session_manager));
        if (session == NULL) {
            status = CMD_HANDLER_SPDM_RESPONDER_INVALID_SESSION_STATE;
            spdm_error = SPDM_ERROR_UNEXPECTED_REQUEST;
            goto exit;
        }

        /* Check session state. */
        if (session->session_state != SPDM_SESSION_STATE_ESTABLISHED) {
            status = CMD_HANDLER_SPDM_RESPONDER_INVALID_SESSION_STATE;
            spdm_error = SPDM_ERROR_UNEXPECTED_REQUEST;
            goto exit;
        }
    }

    /* Reset transcript manager state as per request code. */
    spdm_reset_transcript_via_request_code (state, transcript_manager, SPDM_REQUEST_GET_DIGESTS);

    /* Add request to M1M2 hash context. */
    if (session == NULL) {
        status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
            request->payload, sizeof (struct spdm_get_digests_request), false,
            SPDM_MAX_SESSION_COUNT);
        if (status != 0) {
            spdm_error = SPDM_ERROR_UNSPECIFIED;
            goto exit;
        }
    }

    /* Construct the response. */
    hash_size = hash_get_hash_length (hash_type);
    if (hash_size == HASH_ENGINE_UNKNOWN_HASH) {
        status = HASH_ENGINE_UNKNOWN_HASH;
        spdm_error = SPDM_ERROR_UNSPECIFIED;
        goto exit;
    }

    response_size = sizeof (struct spdm_get_digests_response) + hash_size;
    if (response_size > cmd_interface_msg_get_max_response (request)) {
        status = CMD_HANDLER_SPDM_RESPONDER_RESPONSE_TOO_LARGE;
        spdm_error = SPDM_ERROR_UNSPECIFIED;
        goto exit;
    }

    spdm_response = (struct spdm_get_digests_response*) request->payload;
    memset (spdm_response, 0, response_size);

    spdm_populate_header (&spdm_response->header, SPDM_RESPONSE_GET_DIGESTS,
        SPDM_GET_MINOR_VERSION (spdm_version));
    spdm_response->slot_mask = 1;

    /* Get the digest of the certificate chain. */
    status = spdm_get_certificate_chain_digest (key_manager, hash_engine, hash_type,
        (uint8_t*) (spdm_response + 1));
    if (status != 0) {
        spdm_error = SPDM_ERROR_UNSPECIFIED;
        goto exit;
    }

    /* Add response to M1M2 hash context. */
    if (session == NULL) {
        status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
            (uint8_t*) spdm_response, response_size, false, SPDM_MAX_SESSION_COUNT);
        if (status != 0) {
            spdm_error = SPDM_ERROR_UNSPECIFIED;
            goto exit;
        }
    }

    /* Set the payload length. */
    cmd_interface_msg_set_message_payload_length (request, response_size);

    /* Update connection state */
    if (state->connection_info.connection_state < SPDM_CONNECTION_STATE_AFTER_DIGESTS) {
        spdm_set_connection_state (state, SPDM_CONNECTION_STATE_AFTER_DIGESTS);
    }

exit:
    if (status != 0) {
        spdm_generate_error_response (request, state->connection_info.version.minor_version,
            spdm_error, 0x00, NULL, 0, SPDM_REQUEST_GET_DIGESTS, status);
    }

    return 0;
} */

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
    let hash_size = get_hash_size_from_context(ctx);

    // todo!
    Ok(())
}

// Helper function to get the hash size based on the base hash algorithm
fn get_hash_size_from_context<'a, S: Syscalls>(ctx: &SpdmContext<'a, S>) -> usize {
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

    // Get digest size
    hash_algo.hash_size()
}

// helper function to get certificate list
fn get_certificate_list<'a>(
    device_certs_mgr: &'a dyn DeviceCertsManager,
    cert_chain: &mut [DerCert],
) -> Result<usize, SpdmError> {
    let mut cert_count = 0;

    if device_certs_mgr.is_root_ca_present() {
        if let Some(cert) = cert_chain.get_mut(cert_count) {
            device_certs_mgr
                .get_root_ca(cert)
                .map_err(SpdmError::CertMgr)?;
            cert_count += 1;
        } else {
            return Err(SpdmError::InvalidParam);
        }
    }

    if device_certs_mgr.is_intermediate_ca_present() {
        if let Some(cert) = cert_chain.get_mut(cert_count) {
            device_certs_mgr
                .get_intermediate_ca(cert)
                .map_err(|e| SpdmError::CertMgr(e))?;
            cert_count += 1;
        } else {
            return Err(SpdmError::InvalidParam);
        }
    }

    let mut device_keys = DeviceKeys::default();

    device_certs_mgr
        .get_device_keys(&mut device_keys)
        .map_err(|e| SpdmError::CertMgr(e))?;

    if let Some(cert) = cert_chain.get_mut(cert_count) {
        *cert = DerCert::new(&device_keys.devid_cert[..device_keys.devid_cert_length])?;
        cert_count += 1;
    } else {
        return Err(SpdmError::InvalidParam);
    }

    if let Some(cert) = cert_chain.get_mut(cert_count) {
        *cert = DerCert::new(&device_keys.alias_cert[..device_keys.alias_cert_length])?;
        cert_count += 1;
    } else {
        return Err(SpdmError::InvalidParam);
    }

    Ok(cert_count)
}

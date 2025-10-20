// Licensed under the Apache-2.0 license
use crate::codec::{Codec, CommonCodec, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandError, CommandResult};
use crate::protocol::*;
use crate::state::ConnectionState;
use crate::transcript::TranscriptContext;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C)]
pub(crate) struct GetCapabilitiesBase {
    param1: u8,
    param2: u8,
}

impl CommonCodec for GetCapabilitiesBase {}

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C, packed)]
#[allow(dead_code)]
pub(crate) struct GetCapabilitiesV11 {
    reserved: u8,
    ct_exponent: u8,
    reserved2: u8,
    reserved3: u8,
    flags: CapabilityFlags,
}

impl GetCapabilitiesV11 {
    pub fn new(ct_exponent: u8, flags: CapabilityFlags) -> Self {
        Self {
            reserved: 0,
            ct_exponent,
            reserved2: 0,
            reserved3: 0,
            flags,
        }
    }
}

impl CommonCodec for GetCapabilitiesV11 {}

#[derive(IntoBytes, FromBytes, Immutable)]
#[repr(C, packed)]
pub(crate) struct GetCapabilitiesV12 {
    data_transfer_size: u32,
    max_spdm_msg_size: u32,
}

impl CommonCodec for GetCapabilitiesV12 {}

fn req_flag_compatible(version: SpdmVersion, flags: &CapabilityFlags) -> bool {
    // Checks common to 1.1 and higher
    if version >= SpdmVersion::V11 {
        // Illegal to return reserved values (2 and 3)
        if flags.psk_cap() >= PskCapability::PskWithContext as u8 {
            return false;
        }

        // Checks that originate from key exchange capabilities
        if flags.key_ex_cap() == 1 || flags.psk_cap() != PskCapability::NoPsk as u8 {
            if flags.mac_cap() == 0 && flags.encrypt_cap() == 0 {
                return false;
            }
        } else {
            if flags.mac_cap() == 1
                || flags.encrypt_cap() == 1
                || flags.handshake_in_the_clear_cap() == 1
                || flags.hbeat_cap() == 1
                || flags.key_upd_cap() == 1
            {
                return false;
            }

            if version >= SpdmVersion::V13 && flags.event_cap() == 1 {
                return false;
            }
        }

        if flags.key_ex_cap() == 0
            && flags.psk_cap() == PskCapability::PskWithNoContext as u8
            && flags.handshake_in_the_clear_cap() == 1
        {
            return false;
        }

        // Checks that originate from certificate or public key capabilities
        if flags.cert_cap() == 1 || flags.pub_key_id_cap() == 1 {
            // Certificate capabilities and public key capabilities can not both be set
            if flags.cert_cap() == 1 && flags.pub_key_id_cap() == 1 {
                return false;
            }

            if flags.chal_cap() == 0 && flags.pub_key_id_cap() == 1 {
                return false;
            }
        } else {
            // If certificates or public keys are not enabled then these capabilities are not allowed
            if flags.chal_cap() == 1 || flags.mut_auth_cap() == 1 {
                return false;
            }

            if version >= SpdmVersion::V13
                && flags.ep_info_cap() == EpInfoCapability::EpInfoWithSignature as u8
            {
                return false;
            }
        }

        // Checks that originate from mutual authentication capabilities
        if flags.mut_auth_cap() == 1 {
            // Mutual authentication with asymmetric keys can only occur through the basic mutual
            // authentication flow (CHAL_CAP == 1) or the session-based mutual authentication flow
            // (KEY_EX_CAP == 1)
            if flags.cert_cap() == 0 && flags.pub_key_id_cap() == 0 {
                return false;
            }
        }
    }

    // Checks specific to 1.1
    if version == SpdmVersion::V11 && flags.mut_auth_cap() == 1 && flags.encap_cap() == 0 {
        return false;
    }

    // Checks specific to 1.3 and higher
    if version >= SpdmVersion::V13 {
        // Illegal to return reserved values
        if flags.ep_info_cap() == EpInfoCapability::Reserved as u8 || flags.multi_key_cap() == 3 {
            return false;
        }

        // Check multi_key_cap and pub_key_id_cap
        if flags.multi_key_cap() != 0 && flags.pub_key_id_cap() == 1 {
            return false;
        }
    }

    true
}

async fn process_get_capabilities<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    let version = match spdm_hdr.version() {
        Ok(v) => v,
        Err(_) => {
            Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?
        }
    };

    // Check if version is supported and set it
    let version = match ctx.supported_versions.iter().find(|&&v| v == version) {
        Some(&v) => {
            ctx.state.connection_info.set_version_number(v);
            v
        }
        None => Err(ctx.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))?,
    };

    let base_req = GetCapabilitiesBase::decode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    // Reserved fields must be zero - or unexpected request error
    if base_req.param1 != 0 || base_req.param2 != 0 {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    if version > SpdmVersion::V10 {
        let mut max_spdm_msg_size = 0;
        let mut data_transfer_size = 0;

        let req_11 = GetCapabilitiesV11::decode(req_payload).map_err(|_| {
            ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
        })?;

        let flags = req_11.flags;
        if !req_flag_compatible(version, &flags) {
            Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
        }

        if req_11.ct_exponent > MAX_CT_EXPONENT {
            Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
        }

        if version >= SpdmVersion::V12 {
            let req_12 = GetCapabilitiesV12::decode(req_payload).map_err(|_| {
                ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
            })?;

            max_spdm_msg_size = req_12.max_spdm_msg_size;
            data_transfer_size = req_12.data_transfer_size;

            // Check data transfer size
            if data_transfer_size < MIN_DATA_TRANSFER_SIZE_V12
                || data_transfer_size > req_12.max_spdm_msg_size
            {
                Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
            }

            // If no large message transfer supported, the data transfer size must be the same as
            // the max SPDM message size
            if flags.chunk_cap() == 0 && data_transfer_size != max_spdm_msg_size {
                Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
            }
        }

        if version >= SpdmVersion::V11 {
            // Check ct_exponent
            if req_11.ct_exponent > MAX_CT_EXPONENT {
                Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
            }
        }

        // Save the requester capabilities in the connection info
        let peer_capabilities = DeviceCapabilities {
            ct_exponent: req_11.ct_exponent,
            flags: req_11.flags,
            data_transfer_size,
            max_spdm_msg_size,
        };

        ctx.state
            .connection_info
            .set_peer_capabilities(peer_capabilities);
    }

    // Reset the transcript depending on request code
    ctx.reset_transcript_via_req_code(ReqRespCode::GetCapabilities);

    // Set the SPDM version in the transcript manager
    ctx.shared_transcript
        .set_spdm_version(ctx.state.connection_info.version_number());

    let spdm_version = ctx.state.connection_info.version_number();
    ctx.shared_transcript.set_spdm_version(spdm_version);
    ctx.measurements.set_spdm_version(spdm_version);

    // Append GET_CAPABILITIES to the transcript VCA context
    ctx.append_message_to_transcript(req_payload, TranscriptContext::Vca, None)
        .await
}

async fn generate_capabilities_response<'a>(
    ctx: &mut SpdmContext<'a>,
    rsp_buf: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    let version = ctx.state.connection_info.version_number();
    let local_capabilities = ctx.local_capabilities;

    // Fill SPDM common header
    let spdm_resp_hdr = SpdmMsgHdr::new(version, ReqRespCode::Capabilities);
    let mut payload_len = spdm_resp_hdr
        .encode(rsp_buf)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    let rsp_common = GetCapabilitiesBase::default();
    payload_len += rsp_common
        .encode(rsp_buf)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    let rsp_11 = GetCapabilitiesV11::new(local_capabilities.ct_exponent, local_capabilities.flags);

    payload_len += rsp_11
        .encode(rsp_buf)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    if version >= SpdmVersion::V12 {
        let rsp_12 = GetCapabilitiesV12 {
            data_transfer_size: local_capabilities.data_transfer_size,
            max_spdm_msg_size: local_capabilities.max_spdm_msg_size,
        };

        payload_len += rsp_12
            .encode(rsp_buf)
            .map_err(|e| (false, CommandError::Codec(e)))?;
    }

    // Append CAPABILITIES to the transcript VCA context
    ctx.append_message_to_transcript(rsp_buf, TranscriptContext::Vca, None)
        .await?;

    rsp_buf
        .push_data(payload_len)
        .map_err(|e| (false, CommandError::Codec(e)))?;
    Ok(())
}

pub(crate) async fn handle_get_capabilities<'a>(
    ctx: &mut SpdmContext<'a>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    if ctx.state.connection_info.state() != ConnectionState::AfterVersion {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }

    // Process GET_CAPABILITIES request
    process_get_capabilities(ctx, spdm_hdr, req_payload).await?;

    // Generate CAPABILITIES response
    ctx.prepare_response_buffer(req_payload)?;
    generate_capabilities_response(ctx, req_payload).await?;

    // Set handshake_in_the_clear flag based on local and peer capabilities
    let local_flags = ctx.local_capabilities.flags;
    let peer_flags = ctx.state.connection_info.peer_capabilities().flags;
    if local_flags.handshake_in_the_clear_cap() != 0 && peer_flags.handshake_in_the_clear_cap() != 0
    {
        ctx.state.connection_info.set_handshake_in_the_clear();
    }

    // Set state to AfterCapabilities
    ctx.state
        .connection_info
        .set_state(ConnectionState::AfterCapabilities);
    Ok(())
}

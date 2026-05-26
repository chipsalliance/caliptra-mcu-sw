// Licensed under the Apache-2.0 license

//! GET_MEASUREMENTS / MEASUREMENTS handler (DSP0274 §10.11).

use mcu_spdm_lite_codec::{
    DmtfMeasurementBlockHeader, GetMeasurementsReqBody, MeasurementsRsp, ResponseBody,
    SpdmMsgHdrPdu, SpdmVersion, ECC_P384_SIGNATURE_SIZE, MEAS_BLOCK_METADATA_SIZE,
    REQUESTER_CONTEXT_LEN, SHA384_HASH_SIZE, SPDM_CONTEXT_LEN, SPDM_PREFIX_LEN,
    SPDM_SIGNING_CONTEXT_LEN,
};
use mcu_spdm_lite_traits::*;
use zerocopy::{FromBytes, IntoBytes};

use crate::build::build_response;
use crate::error::{SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_UNSPECIFIED};
use crate::stack::{ConnectionState, Phase};

/// Maximum measurement record buffer size (stack-allocated).
/// Sized for kid-mode COSE_Sign1 (~600 B) with margin.
const MEAS_RECORD_BUF_SIZE: usize = 1024;

pub(crate) async fn handle_get_measurements<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    // Phase: must be after algorithms negotiation.
    if (state.phase as u8) < (Phase::AfterAlgorithms as u8) {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    // Validate version matches negotiated.
    let req = io.request();
    let (hdr, rest) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(crate::error::SPDM_VERSION_MISMATCH);
    }

    // Decode GET_MEASUREMENTS body.
    let (meas_req, after) =
        GetMeasurementsReqBody::ref_from_prefix(rest).map_err(|_| SPDM_INVALID_REQUEST)?;

    let signature_requested = meas_req.signature_requested();
    let _raw_bitstream = meas_req.raw_bitstream_requested();
    let meas_op = meas_req.measurement_operation;

    // If signature requested, parse Nonce + SlotID.
    let mut requester_nonce = [0u8; SPDM_NONCE_LEN];
    let mut slot_id: u8 = 0;
    let mut after_sig_fields = after;

    if signature_requested {
        if after.len() < SPDM_NONCE_LEN + 1 {
            return Err(SPDM_INVALID_REQUEST);
        }
        requester_nonce.copy_from_slice(&after[..SPDM_NONCE_LEN]);
        slot_id = after[SPDM_NONCE_LEN] & 0x0F;
        after_sig_fields = &after[SPDM_NONCE_LEN + 1..];

        // Validate slot_id.
        if slot_id >= MAX_SLOTS || (pal.provisioned_slots() & (1 << slot_id)) == 0 {
            return Err(SPDM_INVALID_REQUEST);
        }
    }

    // Parse RequesterContext for V1.3+.
    let mut requester_context = None;
    if state.version >= SpdmVersion::V13 {
        if after_sig_fields.len() < REQUESTER_CONTEXT_LEN {
            return Err(SPDM_INVALID_REQUEST);
        }
        let mut ctx = [0u8; REQUESTER_CONTEXT_LEN];
        ctx.copy_from_slice(&after_sig_fields[..REQUESTER_CONTEXT_LEN]);
        requester_context = Some(ctx);
    }

    // Measurement enumeration from PAL.
    let meas_info = pal.measurement_info();
    let total_count = meas_info.len() as u8;

    // Nonce for measurement providers (Some when signature requested).
    let meas_nonce: Option<&[u8; SPDM_NONCE_LEN]> = if signature_requested {
        Some(&requester_nonce)
    } else {
        None
    };

    // Build measurement record based on operation.
    let mut meas_record_buf = pal
        .alloc_bytes(io, MEAS_RECORD_BUF_SIZE)
        .map_err(|_| SPDM_UNSPECIFIED)?;
    meas_record_buf.fill(0);
    let mut meas_record_len: usize = 0;
    let mut number_of_blocks: u8 = 0;

    match meas_op {
        // Op=0: return total count, no record.
        0x00 => {
            // No measurement record.
        }
        // Op=0xFF: return all measurement blocks.
        0xFF => {
            for info in meas_info.iter() {
                let written = write_measurement_block(
                    pal,
                    io,
                    info,
                    meas_nonce,
                    &mut meas_record_buf[meas_record_len..],
                )
                .await?;
                meas_record_len += written;
                number_of_blocks += 1;
            }
        }
        // Op=1..0xFE: return specific measurement block.
        idx => {
            let info = meas_info
                .iter()
                .find(|m| m.index == idx)
                .ok_or(SPDM_INVALID_REQUEST)?;
            let written = write_measurement_block(
                pal,
                io,
                info,
                meas_nonce,
                &mut meas_record_buf[meas_record_len..],
            )
            .await?;
            meas_record_len += written;
            number_of_blocks = 1;
        }
    }

    let measurement_record = &meas_record_buf[..meas_record_len];

    // If signature requested, append GET_MEASUREMENTS request to L1 transcript.
    // Only the actual SPDM bytes — strip any DOE DWORD padding at the end.
    if signature_requested {
        let spdm_req_len = SpdmMsgHdrPdu::SIZE
            + core::mem::size_of::<GetMeasurementsReqBody>()
            + SPDM_NONCE_LEN
            + 1 // SlotIDParam
            + if requester_context.is_some() { REQUESTER_CONTEXT_LEN } else { 0 };
        state
            .transcript
            .append_l1(pal, io, &req[..spdm_req_len])
            .await?;
    }

    // Generate responder nonce.
    let mut nonce = [0u8; SPDM_NONCE_LEN];
    pal.generate_nonce(io, &mut nonce)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;

    // Content changed: 2 = no change detected (when signature requested).
    let content_changed = if signature_requested { 2u8 } else { 0u8 };

    // SPDM 1.2+ DSP0274 §10.11.1: Param1 always reports total count.
    let total_number_of_measurement = total_count;

    // Build response without signature first (for L1 transcript).
    let body_no_sig = MeasurementsRsp {
        total_number_of_measurement,
        slot_id,
        content_changed,
        number_of_blocks,
        measurement_record,
        nonce: &nonce,
        opaque_data: &[],
        requester_context: requester_context.as_ref(),
        signature: &[],
    };

    let resp = build_response(pal, io, state.version, &body_no_sig)
        .map_err(|_| SPDM_UNSPECIFIED)?;

    if !signature_requested {
        return Ok(resp);
    }

    // Append MEASUREMENTS response (without signature) to L1.
    let head = pal.header_size();
    let spdm_len = body_no_sig.encoded_size();
    state
        .transcript
        .append_l1(pal, io, &resp[head..head + spdm_len])
        .await?;
    drop(resp); // Free scratch before allocating full response.

    // Finalize L1 transcript hash.
    let mut l1_hash = [0u8; SHA384_HASH_SIZE];
    state
        .transcript
        .finalize_l1(pal, io, &mut l1_hash)
        .await?;

    // Build signing context and compute TBS hash.
    let signing_ctx = build_signing_context(state.version);
    let tbs_hash = compute_tbs_hash(pal, io, &signing_ctx, &l1_hash)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;

    // Sign the TBS hash.
    let asym_algo = state.asym_algo();
    let mut signature = [0u8; ECC_P384_SIGNATURE_SIZE];
    let sig_len = pal
        .sign_hash(io, slot_id, asym_algo, &tbs_hash, &mut signature)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;
    if sig_len != ECC_P384_SIGNATURE_SIZE {
        return Err(SPDM_UNSPECIFIED);
    }

    // Rebuild full response with signature.
    let full_body = MeasurementsRsp {
        total_number_of_measurement,
        slot_id,
        content_changed,
        number_of_blocks,
        measurement_record,
        nonce: &nonce,
        opaque_data: &[],
        requester_context: requester_context.as_ref(),
        signature: &signature,
    };

    let full_resp = build_response(pal, io, state.version, &full_body)
        .map_err(|_| SPDM_UNSPECIFIED)?;

    Ok(full_resp)
}

/// Write a single DMTF measurement block (header + value) into `out`.
/// Returns total bytes written.
async fn write_measurement_block<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    info: &MeasurementInfo,
    nonce: Option<&[u8; SPDM_NONCE_LEN]>,
    out: &mut [u8],
) -> SpdmResult<usize> {
    if out.len() < MEAS_BLOCK_METADATA_SIZE {
        return Err(SPDM_UNSPECIFIED);
    }

    // Write measurement value after the header.
    let value_buf = &mut out[MEAS_BLOCK_METADATA_SIZE..];
    let value_len = pal
        .get_measurement_value(io, info.index, nonce, value_buf)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;

    // Build and write the block header.
    let block_hdr =
        DmtfMeasurementBlockHeader::new(info.index, info.is_raw, info.value_type, value_len as u16);
    out[..MEAS_BLOCK_METADATA_SIZE].copy_from_slice(block_hdr.as_bytes());

    Ok(MEAS_BLOCK_METADATA_SIZE + value_len)
}

/// Build the 100-byte SPDM signing context for MEASUREMENTS.
fn build_signing_context(version: SpdmVersion) -> [u8; SPDM_SIGNING_CONTEXT_LEN] {
    let mut ctx = [0u8; SPDM_SIGNING_CONTEXT_LEN];

    let base = b"dmtf-spdm-v";
    let ver = match version {
        SpdmVersion::V10 => b"1.0.*",
        SpdmVersion::V11 => b"1.1.*",
        SpdmVersion::V12 => b"1.2.*",
        SpdmVersion::V13 => b"1.3.*",
    };
    let mut pos = 0;
    for _ in 0..4 {
        ctx[pos..pos + base.len()].copy_from_slice(base);
        pos += base.len();
        ctx[pos..pos + ver.len()].copy_from_slice(ver);
        pos += ver.len();
    }

    // Operation context for measurements.
    let op = b"responder-measurements signing";
    let pad = SPDM_CONTEXT_LEN - op.len();
    ctx[SPDM_PREFIX_LEN + pad..SPDM_PREFIX_LEN + pad + op.len()].copy_from_slice(op);

    ctx
}

/// Hash(signing_context || L1_hash) → TBS digest for signing.
async fn compute_tbs_hash<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    signing_ctx: &[u8; SPDM_SIGNING_CONTEXT_LEN],
    l1_hash: &[u8; SHA384_HASH_SIZE],
) -> mcu_error::McuResult<[u8; SHA384_HASH_SIZE]> {
    let mut state = pal
        .hash_init(io, SpdmPalHashAlgo::Sha384, signing_ctx)
        .await?;
    pal.hash_update(io, &mut state, l1_hash).await?;
    let mut tbs = [0u8; SHA384_HASH_SIZE];
    pal.hash_finish(io, &mut state, &mut tbs).await?;
    Ok(tbs)
}

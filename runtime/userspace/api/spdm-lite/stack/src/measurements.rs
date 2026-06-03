// Licensed under the Apache-2.0 license

//! GET_MEASUREMENTS / MEASUREMENTS handler.

use mcu_spdm_lite_codec::{
    DmtfMeasurementBlockHeader, GetMeasurementsReqBody, ReqRespCode, SpdmMsgHdrPdu, SpdmVersion,
    WireWriter, ECC_P384_SIGNATURE_SIZE, MEAS_BLOCK_METADATA_SIZE, REQUESTER_CONTEXT_LEN,
    SHA384_HASH_SIZE, SPDM_CONTEXT_LEN, SPDM_PREFIX_LEN, SPDM_SIGNING_CONTEXT_LEN,
};
use mcu_spdm_lite_traits::*;
use zerocopy::{FromBytes, IntoBytes};

use crate::build::alloc_padded;
use crate::chunk;
use crate::error::{SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_UNSPECIFIED};
use crate::stack::{ConnectionState, Phase};

const MEASUREMENTS_FIXED_BODY_SIZE: usize = 1 + 1 + 1 + 3;
const OPAQUE_DATA_LEN_SIZE: usize = 2;

struct MeasurementsResponseCtx<'a> {
    meas_info: &'a [MeasurementInfo],
    meas_op: u8,
    meas_nonce: Option<&'a [u8; SPDM_NONCE_LEN]>,
    signature_requested: bool,
    slot_id: u8,
    total_number_of_measurement: u8,
    content_changed: u8,
    number_of_blocks: u8,
    measurement_record_len: usize,
    nonce: &'a [u8; SPDM_NONCE_LEN],
    requester_context: Option<&'a [u8; REQUESTER_CONTEXT_LEN]>,
    spdm_len: usize,
}

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
    if meas_req.attributes & !0x07 != 0 {
        return Err(SPDM_INVALID_REQUEST);
    }

    // If signature requested, parse Nonce + SlotID.
    let mut requester_nonce = [0u8; SPDM_NONCE_LEN];
    let mut slot_id: u8 = 0;
    let mut after_sig_fields = after;
    let requester_context_len = if state.version >= SpdmVersion::V13 {
        REQUESTER_CONTEXT_LEN
    } else {
        0
    };

    if signature_requested {
        if after.len() < SPDM_NONCE_LEN + 1 {
            return Err(SPDM_INVALID_REQUEST);
        }
        requester_nonce.copy_from_slice(&after[..SPDM_NONCE_LEN]);
        slot_id = after[SPDM_NONCE_LEN] & 0x0F;
        after_sig_fields = &after[SPDM_NONCE_LEN + 1..];

        // Caliptra supports measurement signing only through provisioned
        // certificate slots; slot 0xF (public-key-only signing) is not supported.
        if slot_id >= MAX_SLOTS || (pal.provisioned_slots() & (1 << slot_id)) == 0 {
            return Err(SPDM_INVALID_REQUEST);
        }
    }

    // Parse RequesterContext for V1.3+.
    let mut requester_context = None;
    if requester_context_len != 0 {
        if after_sig_fields.len() < REQUESTER_CONTEXT_LEN {
            return Err(SPDM_INVALID_REQUEST);
        }
        let mut ctx = [0u8; REQUESTER_CONTEXT_LEN];
        ctx.copy_from_slice(&after_sig_fields[..REQUESTER_CONTEXT_LEN]);
        requester_context = Some(ctx);
    }

    let spdm_req_len = SpdmMsgHdrPdu::SIZE
        + core::mem::size_of::<GetMeasurementsReqBody>()
        + if signature_requested {
            SPDM_NONCE_LEN + 1 // SlotIDParam
        } else {
            0
        }
        + requester_context_len;
    if req.len() != spdm_req_len {
        return Err(SPDM_INVALID_REQUEST);
    }

    // Measurement enumeration from PAL.
    let meas_info = pal.measurement_info();
    let total_count = total_measurement_count(meas_info)?;

    // Nonce for measurement providers (Some when signature requested).
    let meas_nonce: Option<&[u8; SPDM_NONCE_LEN]> = if signature_requested {
        Some(&requester_nonce)
    } else {
        None
    };

    let (measurement_record_len, number_of_blocks) = measurement_record_shape(meas_info, meas_op)?;

    // If signature requested, append GET_MEASUREMENTS request to L1 transcript.
    // Only the actual SPDM bytes — strip any DOE DWORD padding at the end.
    if signature_requested {
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

    // Param1 reports total count only for the measurement-count query.
    let total_number_of_measurement = if meas_op == 0x00 { total_count } else { 0 };

    let body_len_without_sig = MEASUREMENTS_FIXED_BODY_SIZE
        + measurement_record_len
        + SPDM_NONCE_LEN
        + OPAQUE_DATA_LEN_SIZE
        + requester_context_len;
    let signature_len = if signature_requested {
        ECC_P384_SIGNATURE_SIZE
    } else {
        0
    };
    let spdm_len_without_sig = SpdmMsgHdrPdu::SIZE + body_len_without_sig;
    let spdm_len = spdm_len_without_sig + signature_len;
    if spdm_len > chunk::effective_data_transfer_size(state, pal) {
        let plan = MeasurementsResponseCtx {
            meas_info,
            meas_op,
            meas_nonce,
            signature_requested,
            slot_id,
            total_number_of_measurement,
            content_changed,
            number_of_blocks,
            measurement_record_len,
            nonce: &nonce,
            requester_context: requester_context.as_ref(),
            spdm_len,
        };
        return handle_large_measurements_response(state, pal, io, &plan).await;
    }

    let head = pal.header_size();
    let raw_len = head + spdm_len;
    let mut resp = alloc_padded(pal, io, raw_len).map_err(|_| SPDM_UNSPECIFIED)?;

    let signature_offset;
    {
        let mut w = WireWriter::new(&mut resp[head..]);
        w.write(&SpdmMsgHdrPdu::new(
            state.version,
            ReqRespCode::MEASUREMENTS,
        ))?;
        w.write_bytes(&[total_number_of_measurement])?;
        let param2 = (slot_id & 0x0F) | ((content_changed & 0x03) << 4);
        w.write_bytes(&[param2])?;
        w.write_bytes(&[number_of_blocks])?;
        write_u24_le(&mut w, measurement_record_len)?;

        let record = w.reserve(measurement_record_len)?;
        let written_blocks =
            write_measurement_record(pal, io, meas_info, meas_op, meas_nonce, record).await?;
        if written_blocks != number_of_blocks {
            return Err(SPDM_UNSPECIFIED);
        }

        w.write_bytes(&nonce)?;
        w.write_bytes(&0u16.to_le_bytes())?;
        if let Some(ctx) = requester_context.as_ref() {
            w.write_bytes(ctx)?;
        }

        if w.position() != spdm_len_without_sig {
            return Err(SPDM_UNSPECIFIED);
        }
        signature_offset = head + spdm_len_without_sig;
        if signature_requested {
            w.reserve(ECC_P384_SIGNATURE_SIZE)?.fill(0);
        }
    }

    if !signature_requested {
        return Ok(resp);
    }

    // Append MEASUREMENTS response (without signature) to L1.
    state
        .transcript
        .append_l1(pal, io, &resp[head..head + spdm_len_without_sig])
        .await?;

    // Finalize L1 transcript hash.
    let mut l1_hash = [0u8; SHA384_HASH_SIZE];
    state.transcript.finalize_l1(pal, io, &mut l1_hash).await?;

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

    resp[signature_offset..signature_offset + ECC_P384_SIGNATURE_SIZE].copy_from_slice(&signature);

    Ok(resp)
}

async fn handle_large_measurements_response<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    plan: &MeasurementsResponseCtx<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    chunk::validate_buffered_large_response(state, pal, plan.spdm_len)?;

    let mut offset = 0usize;
    let hdr = SpdmMsgHdrPdu::new(state.version, ReqRespCode::MEASUREMENTS);
    offset = write_large_measurement_bytes(pal, offset, hdr.as_bytes())?;

    let mut fixed = [0u8; MEASUREMENTS_FIXED_BODY_SIZE];
    fixed[0] = plan.total_number_of_measurement;
    fixed[1] = (plan.slot_id & 0x0F) | ((plan.content_changed & 0x03) << 4);
    fixed[2] = plan.number_of_blocks;
    fixed[3..6].copy_from_slice(&u24_le(plan.measurement_record_len)?);
    offset = write_large_measurement_bytes(pal, offset, &fixed)?;

    let (next_offset, written_blocks) = write_measurement_record_large(
        pal,
        io,
        plan.meas_info,
        plan.meas_op,
        plan.meas_nonce,
        offset,
    )
    .await?;
    if written_blocks != plan.number_of_blocks {
        return Err(SPDM_UNSPECIFIED);
    }
    offset = next_offset;

    offset = write_large_measurement_bytes(pal, offset, plan.nonce)?;
    offset = write_large_measurement_bytes(pal, offset, &0u16.to_le_bytes())?;
    if let Some(ctx) = plan.requester_context {
        offset = write_large_measurement_bytes(pal, offset, ctx)?;
    }

    let signature_offset = offset;
    if plan.signature_requested {
        append_buffered_l1(state, pal, io, signature_offset).await?;

        let mut l1_hash = [0u8; SHA384_HASH_SIZE];
        state.transcript.finalize_l1(pal, io, &mut l1_hash).await?;

        let signing_ctx = build_signing_context(state.version);
        let tbs_hash = compute_tbs_hash(pal, io, &signing_ctx, &l1_hash)
            .await
            .map_err(|_| SPDM_UNSPECIFIED)?;

        let asym_algo = state.asym_algo();
        let mut signature = [0u8; ECC_P384_SIGNATURE_SIZE];
        let sig_len = pal
            .sign_hash(io, plan.slot_id, asym_algo, &tbs_hash, &mut signature)
            .await
            .map_err(|_| SPDM_UNSPECIFIED)?;
        if sig_len != ECC_P384_SIGNATURE_SIZE {
            return Err(SPDM_UNSPECIFIED);
        }
        pal.write(signature_offset, &signature)
            .map_err(|_| SPDM_UNSPECIFIED)?;
        offset += ECC_P384_SIGNATURE_SIZE;
    }

    if offset != plan.spdm_len {
        return Err(SPDM_UNSPECIFIED);
    }

    chunk::start_buffered_large_response(state, pal, io, plan.spdm_len)
}

fn measurement_record_shape(info: &[MeasurementInfo], meas_op: u8) -> SpdmResult<(usize, u8)> {
    let mut len = 0usize;
    let mut blocks = 0u8;
    match meas_op {
        0x00 => {}
        0xFF => {
            for entry in info {
                len = len
                    .checked_add(MEAS_BLOCK_METADATA_SIZE + entry.value_size as usize)
                    .ok_or(SPDM_UNSPECIFIED)?;
                blocks = blocks.checked_add(1).ok_or(SPDM_UNSPECIFIED)?;
            }
        }
        idx => {
            let entry = info
                .iter()
                .find(|m| m.index == idx)
                .ok_or(SPDM_INVALID_REQUEST)?;
            len = MEAS_BLOCK_METADATA_SIZE + entry.value_size as usize;
            blocks = 1;
        }
    }
    Ok((len, blocks))
}

fn total_measurement_count(info: &[MeasurementInfo]) -> SpdmResult<u8> {
    let count = u8::try_from(info.len()).map_err(|_| SPDM_UNSPECIFIED)?;
    if count == 0xFF {
        return Err(SPDM_UNSPECIFIED);
    }

    for entry in info {
        if entry.index == 0 || entry.index == 0xFF {
            return Err(SPDM_UNSPECIFIED);
        }
    }

    Ok(count)
}

pub(crate) async fn measurement_summary_hash<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    measurement_summary_hash_type: u8,
    out: &mut [u8; SHA384_HASH_SIZE],
) -> SpdmResult<()> {
    if measurement_summary_hash_type != 1 && measurement_summary_hash_type != 0xFF {
        return Err(SPDM_INVALID_REQUEST);
    }

    let mut hash_state = None;
    for entry in pal.measurement_info() {
        if measurement_summary_hash_type == 1 && !entry.is_tcb {
            continue;
        }

        let block_len = MEAS_BLOCK_METADATA_SIZE
            .checked_add(entry.value_size as usize)
            .ok_or(SPDM_UNSPECIFIED)?;
        let mut block = pal
            .alloc_bytes(io, block_len)
            .map_err(|_| SPDM_UNSPECIFIED)?;
        let written = write_measurement_block(pal, io, entry, None, &mut block).await?;
        if written != block_len {
            return Err(SPDM_UNSPECIFIED);
        }

        match hash_state.as_mut() {
            Some(state) => pal.hash_update(io, state, &block).await?,
            None => {
                hash_state = Some(pal.hash_init(io, SpdmPalHashAlgo::Sha384, &block).await?);
            }
        }
    }

    let mut state = hash_state.ok_or(SPDM_UNSPECIFIED)?;
    pal.hash_finish(io, &mut state, out).await?;
    Ok(())
}

async fn write_measurement_record_large<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    info: &[MeasurementInfo],
    meas_op: u8,
    nonce: Option<&[u8; SPDM_NONCE_LEN]>,
    mut offset: usize,
) -> SpdmResult<(usize, u8)> {
    let mut blocks = 0u8;
    match meas_op {
        0x00 => {}
        0xFF => {
            for entry in info {
                offset = write_measurement_block_large(pal, io, entry, nonce, offset).await?;
                blocks = blocks.checked_add(1).ok_or(SPDM_UNSPECIFIED)?;
            }
        }
        idx => {
            let entry = info
                .iter()
                .find(|m| m.index == idx)
                .ok_or(SPDM_INVALID_REQUEST)?;
            offset = write_measurement_block_large(pal, io, entry, nonce, offset).await?;
            blocks = 1;
        }
    }
    Ok((offset, blocks))
}

async fn write_measurement_block_large<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    info: &MeasurementInfo,
    nonce: Option<&[u8; SPDM_NONCE_LEN]>,
    mut offset: usize,
) -> SpdmResult<usize> {
    let block_hdr =
        DmtfMeasurementBlockHeader::new(info.index, info.is_raw, info.value_type, info.value_size);
    offset = write_large_measurement_bytes(pal, offset, block_hdr.as_bytes())?;

    let value_size = info.value_size as usize;
    if value_size == 0 {
        return Ok(offset);
    }

    let mut value = pal.alloc_bytes(io, value_size)?;
    let value_len = pal
        .get_measurement_value(io, info.index, nonce, &mut value)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;
    if value_len != value_size {
        return Err(SPDM_UNSPECIFIED);
    }

    write_large_measurement_bytes(pal, offset, &value)
}

fn write_large_measurement_bytes<Pal: SpdmPal>(
    pal: &Pal,
    offset: usize,
    bytes: &[u8],
) -> SpdmResult<usize> {
    let next = offset.checked_add(bytes.len()).ok_or(SPDM_UNSPECIFIED)?;
    pal.write(offset, bytes).map_err(|_| SPDM_UNSPECIFIED)?;
    Ok(next)
}

async fn append_buffered_l1<Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State>,
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    len: usize,
) -> SpdmResult<()> {
    let mut offset = 0usize;
    let mut buf = [0u8; 128];
    while offset < len {
        let n = (len - offset).min(buf.len());
        pal.read(offset, &mut buf[..n])
            .map_err(|_| SPDM_UNSPECIFIED)?;
        state.transcript.append_l1(pal, io, &buf[..n]).await?;
        offset += n;
    }
    Ok(())
}

async fn write_measurement_record<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    info: &[MeasurementInfo],
    meas_op: u8,
    nonce: Option<&[u8; SPDM_NONCE_LEN]>,
    out: &mut [u8],
) -> SpdmResult<u8> {
    let mut offset = 0usize;
    let mut blocks = 0u8;
    match meas_op {
        0x00 => {}
        0xFF => {
            for entry in info {
                let written =
                    write_measurement_block(pal, io, entry, nonce, &mut out[offset..]).await?;
                offset += written;
                blocks = blocks.checked_add(1).ok_or(SPDM_UNSPECIFIED)?;
            }
        }
        idx => {
            let entry = info
                .iter()
                .find(|m| m.index == idx)
                .ok_or(SPDM_INVALID_REQUEST)?;
            offset += write_measurement_block(pal, io, entry, nonce, &mut out[offset..]).await?;
            blocks = 1;
        }
    }
    if offset != out.len() {
        return Err(SPDM_UNSPECIFIED);
    }
    Ok(blocks)
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
    let value_size = info.value_size as usize;
    if out.len() < MEAS_BLOCK_METADATA_SIZE + value_size {
        return Err(SPDM_UNSPECIFIED);
    }

    // Write measurement value after the header.
    let value_buf = &mut out[MEAS_BLOCK_METADATA_SIZE..MEAS_BLOCK_METADATA_SIZE + value_size];
    let value_len = pal
        .get_measurement_value(io, info.index, nonce, value_buf)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;
    if value_len != value_size {
        return Err(SPDM_UNSPECIFIED);
    }

    // Build and write the block header.
    let block_hdr =
        DmtfMeasurementBlockHeader::new(info.index, info.is_raw, info.value_type, info.value_size);
    out[..MEAS_BLOCK_METADATA_SIZE].copy_from_slice(block_hdr.as_bytes());

    Ok(MEAS_BLOCK_METADATA_SIZE + value_size)
}

fn write_u24_le(w: &mut WireWriter<'_>, len: usize) -> SpdmResult<()> {
    w.write_bytes(&u24_le(len)?)?;
    Ok(())
}

fn u24_le(len: usize) -> SpdmResult<[u8; 3]> {
    let len = u32::try_from(len).map_err(|_| SPDM_UNSPECIFIED)?;
    if len > mcu_spdm_lite_codec::SPDM_MAX_MEASUREMENT_RECORD_SIZE {
        return Err(SPDM_UNSPECIFIED);
    }
    Ok([
        (len & 0xFF) as u8,
        ((len >> 8) & 0xFF) as u8,
        ((len >> 16) & 0xFF) as u8,
    ])
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

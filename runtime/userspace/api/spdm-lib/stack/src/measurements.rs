// Licensed under the Apache-2.0 license

//! GET_MEASUREMENTS / MEASUREMENTS handler.

use caliptra_mcu_spdm_codec::{
    DmtfMeasurementBlockHeader, GetMeasurementsReqBody, ReqRespCode, SpdmMsgHdrPdu, SpdmVersion,
    MEAS_BLOCK_METADATA_SIZE, REQUESTER_CONTEXT_LEN, SHA384_HASH_SIZE,
};
use caliptra_mcu_spdm_traits::SpdmPalAlloc;
use caliptra_mcu_spdm_traits::*;
use zerocopy::{FromBytes, IntoBytes};

use crate::build::{align_send_len, finish_buffered_response, sign_transcript};
use crate::chunk;
use crate::error::{SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_UNSPECIFIED};
use crate::stack::{ConnectionState, Phase};

const MEASUREMENTS_FIXED_BODY_SIZE: usize = 1 + 1 + 1 + 3;
const OPAQUE_DATA_LEN_SIZE: usize = 2;
const SIGNATURE_REQUEST_FIELDS_SIZE: usize = SPDM_NONCE_LEN + 1; // Nonce + SlotIDParam

struct MeasurementsResponseCtx<'a> {
    meas_info: &'a [MeasurementInfo],
    meas_op: u8,
    meas_nonce: Option<&'a [u8; SPDM_NONCE_LEN]>,
    signature_requested: bool,
    slot_id: u8,
    total_number_of_measurement: u8,
    content_changed: u8,
    number_of_blocks: u8,
    nonce: &'a [u8; SPDM_NONCE_LEN],
    requester_context: Option<&'a [u8]>,
    max_spdm_len: usize,
}

pub(crate) async fn handle_get_measurements_req<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    req: &[u8],
) -> SpdmResult<(PalBytes<'a, Pal>, usize)> {
    // Phase: must be after algorithms negotiation.
    if (state.phase as u8) < (Phase::AfterAlgorithms as u8) {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }
    // Validate version matches negotiated.
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
    let mut requester_nonce = None;
    let mut slot_id: u8 = 0;
    let mut after_sig_fields = after;
    let requester_context_len = if state.version >= SpdmVersion::V13 {
        REQUESTER_CONTEXT_LEN
    } else {
        0
    };

    if signature_requested {
        if after.len() < SIGNATURE_REQUEST_FIELDS_SIZE {
            return Err(SPDM_INVALID_REQUEST);
        }
        requester_nonce = Some(
            after[..SPDM_NONCE_LEN]
                .try_into()
                .map_err(|_| SPDM_INVALID_REQUEST)?,
        );
        slot_id = after[SPDM_NONCE_LEN] & 0x0F;
        after_sig_fields = &after[SIGNATURE_REQUEST_FIELDS_SIZE..];

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
        requester_context = Some(&after_sig_fields[..REQUESTER_CONTEXT_LEN]);
    }

    let spdm_req_len = SpdmMsgHdrPdu::SIZE
        + core::mem::size_of::<GetMeasurementsReqBody>()
        + if signature_requested {
            SIGNATURE_REQUEST_FIELDS_SIZE
        } else {
            0
        }
        + requester_context_len;
    if req.len() < spdm_req_len {
        return Err(SPDM_INVALID_REQUEST);
    }

    // Measurement enumeration from PAL.
    let meas_info = pal.measurement_info();
    let total_count = total_measurement_count(meas_info)?;

    // Nonce for measurement providers (Some when signature requested).
    let (measurement_record_len, number_of_blocks) = measurement_record_shape(meas_info, meas_op)?;

    // If signature requested, append GET_MEASUREMENTS request to L1 transcript.
    if signature_requested {
        state
            .transcript
            .append_l1(pal, io, &req[..spdm_req_len])
            .await?;
    }

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
        state.asym_algo().signature_size()
    } else {
        0
    };
    let spdm_max_len = SpdmMsgHdrPdu::SIZE + body_len_without_sig + signature_len;
    let mut nonce = [0u8; SPDM_NONCE_LEN];
    pal.generate_nonce(io, &mut nonce)
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;
    let plan = MeasurementsResponseCtx {
        meas_info,
        meas_op,
        meas_nonce: requester_nonce,
        signature_requested,
        slot_id,
        total_number_of_measurement,
        content_changed,
        number_of_blocks,
        nonce: &nonce,
        requester_context,
        max_spdm_len: spdm_max_len,
    };
    handle_measurements_response(state, pal, io, &plan).await
}

async fn handle_measurements_response<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    plan: &MeasurementsResponseCtx<'_>,
) -> SpdmResult<(PalBytes<'a, Pal>, usize)> {
    let head = pal.header_size();
    let raw_max_len = head
        .checked_add(plan.max_spdm_len)
        .ok_or(SPDM_UNSPECIFIED)?;
    let padded_max_len = align_send_len(pal, raw_max_len)?;
    let mut guard = chunk::WipeOnDrop {
        buf: Some(pal.alloc_large_buf(padded_max_len)?),
    };
    let buf = guard.buf.as_mut().ok_or(SPDM_UNSPECIFIED)?;

    let mut offset = head;
    let hdr = SpdmMsgHdrPdu::new(state.version, ReqRespCode::MEASUREMENTS);
    offset = write_into_slice(buf, offset, hdr.as_bytes())?;

    let mut fixed = [0u8; MEASUREMENTS_FIXED_BODY_SIZE];
    fixed[0] = plan.total_number_of_measurement;
    fixed[1] = (plan.slot_id & 0x0F) | ((plan.content_changed & 0x03) << 4);
    fixed[2] = plan.number_of_blocks;
    fixed[3..6].fill(0);
    let record_len_offset = offset + 3;
    offset = write_into_slice(buf, offset, &fixed)?;

    let record_start = offset;
    let (next_offset, written_blocks) = write_measurement_record_into_slice(
        pal,
        io,
        plan.meas_info,
        plan.meas_op,
        plan.meas_nonce,
        buf,
        offset,
    )
    .await?;
    if written_blocks != plan.number_of_blocks {
        return Err(SPDM_UNSPECIFIED);
    }
    offset = next_offset;
    let actual_measurement_record_len = offset.checked_sub(record_start).ok_or(SPDM_UNSPECIFIED)?;
    let len_bytes = u24_le(actual_measurement_record_len)?;
    buf.get_mut(record_len_offset..record_len_offset + 3)
        .ok_or(SPDM_UNSPECIFIED)?
        .copy_from_slice(&len_bytes);

    offset = write_into_slice(buf, offset, plan.nonce)?;
    offset = write_into_slice(buf, offset, &0u16.to_le_bytes())?;
    if let Some(ctx) = plan.requester_context {
        offset = write_into_slice(buf, offset, ctx)?;
    }

    let signature_offset = offset;
    let spdm_len_without_sig = signature_offset.checked_sub(head).ok_or(SPDM_UNSPECIFIED)?;
    let asym_algo = state.asym_algo();
    let signature_len = if plan.signature_requested {
        asym_algo.signature_size()
    } else {
        0
    };
    let spdm_len = spdm_len_without_sig
        .checked_add(signature_len)
        .ok_or(SPDM_UNSPECIFIED)?;
    let raw_len = head.checked_add(spdm_len).ok_or(SPDM_UNSPECIFIED)?;
    let use_normal_response = spdm_len <= state.effective_data_transfer_size(pal);
    if !use_normal_response {
        chunk::validate_buffered_large_response_with_capacity(
            state,
            spdm_len,
            pal.large_buffered_msg_capacity(),
        )?;
    }

    if plan.signature_requested {
        let transcript_rsp = buf.get(head..signature_offset).ok_or(SPDM_UNSPECIFIED)?;
        state.transcript.append_l1(pal, io, transcript_rsp).await?;

        let mut hash = [0u8; SHA384_HASH_SIZE];
        state.transcript.finalize_l1(pal, io, &mut hash).await?;

        let signature = buf
            .get_mut(signature_offset..signature_offset + signature_len)
            .ok_or(SPDM_UNSPECIFIED)?;
        sign_transcript(
            pal,
            io,
            plan.slot_id,
            asym_algo,
            state.version,
            MEASUREMENTS_SIGNING_CONTEXT,
            &mut hash,
            signature,
            signature_len,
        )
        .await?;
    }

    let padded_len = if use_normal_response {
        align_send_len(pal, raw_len)?
    } else {
        0
    };
    finish_buffered_response(
        state,
        pal,
        io,
        guard,
        head,
        spdm_len,
        raw_len,
        padded_len,
        use_normal_response,
    )
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
        let block = block.get(..written).ok_or(SPDM_UNSPECIFIED)?;

        match hash_state.as_mut() {
            Some(state) => pal.hash_update(io, state, block).await?,
            None => {
                hash_state = Some(pal.hash_init(io, SpdmPalHashAlgo::Sha384, block).await?);
            }
        }
    }

    let mut state = hash_state.ok_or(SPDM_UNSPECIFIED)?;
    pal.hash_finish(io, &mut state, out).await?;
    Ok(())
}

async fn write_measurement_record_into_slice<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    info: &[MeasurementInfo],
    meas_op: u8,
    nonce: Option<&[u8; SPDM_NONCE_LEN]>,
    out: &mut [u8],
    mut offset: usize,
) -> SpdmResult<(usize, u8)> {
    let mut blocks = 0u8;
    match meas_op {
        0x00 => {}
        0xFF => {
            for entry in info {
                offset =
                    write_measurement_record_block_into_slice(pal, io, entry, nonce, out, offset)
                        .await?;
                blocks = blocks.checked_add(1).ok_or(SPDM_UNSPECIFIED)?;
            }
        }
        idx => {
            let entry = info
                .iter()
                .find(|m| m.index == idx)
                .ok_or(SPDM_INVALID_REQUEST)?;
            offset = write_measurement_record_block_into_slice(pal, io, entry, nonce, out, offset)
                .await?;
            blocks = 1;
        }
    }
    Ok((offset, blocks))
}

async fn write_measurement_record_block_into_slice<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    info: &MeasurementInfo,
    nonce: Option<&[u8; SPDM_NONCE_LEN]>,
    out: &mut [u8],
    mut offset: usize,
) -> SpdmResult<usize> {
    let value_size = info.value_size as usize;
    let header_start = offset;
    let value_start = offset
        .checked_add(MEAS_BLOCK_METADATA_SIZE)
        .ok_or(SPDM_UNSPECIFIED)?;
    let value_end = value_start
        .checked_add(value_size)
        .ok_or(SPDM_UNSPECIFIED)?;
    let value_len = {
        let value = out
            .get_mut(value_start..value_end)
            .ok_or(SPDM_UNSPECIFIED)?;
        pal.get_measurement_value(io, info.index, nonce, value)
            .await
            .map_err(|_| SPDM_UNSPECIFIED)?
    };
    if value_len > value_size {
        return Err(SPDM_UNSPECIFIED);
    }
    let value_len_u16 = u16::try_from(value_len).map_err(|_| SPDM_UNSPECIFIED)?;

    let block_hdr =
        DmtfMeasurementBlockHeader::new(info.index, info.is_raw, info.value_type, value_len_u16);
    offset = write_into_slice(out, header_start, block_hdr.as_bytes())?;
    offset.checked_add(value_len).ok_or(SPDM_UNSPECIFIED)
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
    if value_len > value_size {
        return Err(SPDM_UNSPECIFIED);
    }
    let value_len_u16 = u16::try_from(value_len).map_err(|_| SPDM_UNSPECIFIED)?;

    // Build and write the block header.
    let block_hdr =
        DmtfMeasurementBlockHeader::new(info.index, info.is_raw, info.value_type, value_len_u16);
    for (d, s) in out.iter_mut().zip(block_hdr.as_bytes()) {
        *d = *s;
    }

    Ok(MEAS_BLOCK_METADATA_SIZE + value_len)
}

fn u24_le(len: usize) -> SpdmResult<[u8; 3]> {
    let len = u32::try_from(len).map_err(|_| SPDM_UNSPECIFIED)?;
    if len > caliptra_mcu_spdm_codec::SPDM_MAX_MEASUREMENT_RECORD_SIZE {
        return Err(SPDM_UNSPECIFIED);
    }
    Ok([
        (len & 0xFF) as u8,
        ((len >> 8) & 0xFF) as u8,
        ((len >> 16) & 0xFF) as u8,
    ])
}

fn write_into_slice(out: &mut [u8], offset: usize, bytes: &[u8]) -> SpdmResult<usize> {
    let next = offset.checked_add(bytes.len()).ok_or(SPDM_UNSPECIFIED)?;
    out.get_mut(offset..next)
        .ok_or(SPDM_UNSPECIFIED)?
        .copy_from_slice(bytes);
    Ok(next)
}

/// FIPS 204 signing context for MEASUREMENTS (DSP0274 1.4 Table 51).
const MEASUREMENTS_SIGNING_CONTEXT: &[u8] = b"responder-measurements signing";

#[cfg(test)]
fn signing_context(
    version: SpdmVersion,
) -> [u8; caliptra_mcu_spdm_codec::SPDM_SIGNING_CONTEXT_LEN] {
    crate::build::spdm_signing_context(version, MEASUREMENTS_SIGNING_CONTEXT).unwrap()
}

#[cfg(test)]
#[path = "tests/support.rs"]
pub(crate) mod support;

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::build::SPDM_SIGNING_CONTEXT_LEN;
    use caliptra_mcu_spdm_traits::SpdmPalIo;
    use futures::executor::block_on;
    use std::vec::Vec;
    use zerocopy::IntoBytes;

    static MEASUREMENT_INFO: [MeasurementInfo; 1] = [MeasurementInfo {
        index: 0xFD,
        value_size: 300,
        value_type: 0,
        is_raw: false,
        is_tcb: true,
    }];
    static MEASUREMENT_VALUE: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

    /// Build a GET_MEASUREMENTS request. Bit 0 of `attributes` requests a
    /// signature, which appends Nonce + SlotIDParam; V1.3+ then appends the
    /// 8-byte RequesterContext.
    fn get_measurements_request(version: SpdmVersion, signed: bool) -> Vec<u8> {
        let mut req = Vec::new();
        let hdr = SpdmMsgHdrPdu::new(version, ReqRespCode::GET_MEASUREMENTS);
        let body = GetMeasurementsReqBody {
            attributes: if signed { 1 } else { 0 },
            measurement_operation: 0xFD,
        };
        req.extend_from_slice(hdr.as_bytes());
        req.extend_from_slice(body.as_bytes());
        if signed {
            req.extend_from_slice(&[0xCD; SPDM_NONCE_LEN]);
            req.push(0); // SlotIDParam
        }
        if version >= SpdmVersion::V13 {
            req.extend_from_slice(&[0x22; REQUESTER_CONTEXT_LEN]);
        }
        req
    }

    /// SPDM 1.4 PQC negotiation: `BaseAsymSel` zeroed, `PqcAsymSel` = ML-DSA-87.
    fn mldsa_state(version: SpdmVersion) -> ConnectionState<support::TestHashState, Vec<u8>> {
        let mut state = support::negotiated_state(version);
        state.negotiated_base_asym_sel = caliptra_mcu_spdm_codec::AsymAlgos::EMPTY;
        state.negotiated_pqc_asym_sel = caliptra_mcu_spdm_codec::PqcAsymAlgos::ML_DSA_87;
        state
    }

    #[test]
    fn measurements_v14_ecdsa_emits_96_byte_signature() {
        let pal = support::TestPal {
            mtu: 8192,
            large_buffered_msg_capacity: 8192,
            measurement_info: &MEASUREMENT_INFO,
            measurement_value: &MEASUREMENT_VALUE,
            ..Default::default()
        };
        let mut state = support::negotiated_state(SpdmVersion::V14);

        let io = support::TestIo::message(get_measurements_request(SpdmVersion::V14, true));
        block_on(state.transcript.append_vca(&pal, &io, &[0xAA, 0xBB])).unwrap();
        let (resp, spdm_len) = block_on(handle_get_measurements_req(
            &mut state,
            &pal,
            &io,
            io.request(),
        ))
        .unwrap();

        assert_eq!(resp[1], ReqRespCode::MEASUREMENTS.0);

        let ops = pal.sign_ops.borrow();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].algo, SpdmPalAsymAlgo::EccP384);
        assert_eq!(ops[0].sig_len, 96);

        // The 96-byte signature is the tail of the response.
        let sig = &resp[spdm_len - 96..spdm_len];
        assert!(sig.iter().all(|&b| b == 0x77));
    }

    #[test]
    fn measurements_v14_mldsa87_emits_4627_byte_signature() {
        let pal = support::TestPal {
            mtu: 16384,
            large_buffered_msg_capacity: 16384,
            measurement_info: &MEASUREMENT_INFO,
            measurement_value: &MEASUREMENT_VALUE,
            ..Default::default()
        };
        let mut state = mldsa_state(SpdmVersion::V14);

        let io = support::TestIo::message(get_measurements_request(SpdmVersion::V14, true));
        block_on(state.transcript.append_vca(&pal, &io, &[0xAA, 0xBB])).unwrap();
        let (resp, spdm_len) = block_on(handle_get_measurements_req(
            &mut state,
            &pal,
            &io,
            io.request(),
        ))
        .unwrap();

        assert_eq!(resp[1], ReqRespCode::MEASUREMENTS.0);

        let ops = pal.sign_ops.borrow();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].algo, SpdmPalAsymAlgo::MlDsa87);
        assert_eq!(ops[0].sig_len, 4627);

        let sig = &resp[spdm_len - 4627..spdm_len];
        assert!(sig.iter().all(|&b| b == 0x77));
    }

    /// DSP0274 1.4 §15.5: `M = combined_spdm_prefix || L1_hash`, and the
    /// FIPS 204 `ctx` is the unpadded `spdm_context` string.
    #[test]
    fn measurements_v14_mldsa87_signs_prefix_and_l1_hash_with_spdm_context() {
        let pal = support::TestPal {
            mtu: 16384,
            large_buffered_msg_capacity: 16384,
            measurement_info: &MEASUREMENT_INFO,
            measurement_value: &MEASUREMENT_VALUE,
            ..Default::default()
        };
        let mut state = mldsa_state(SpdmVersion::V14);

        let io = support::TestIo::message(get_measurements_request(SpdmVersion::V14, true));
        block_on(state.transcript.append_vca(&pal, &io, &[0xAA, 0xBB])).unwrap();
        block_on(handle_get_measurements_req(
            &mut state,
            &pal,
            &io,
            io.request(),
        ))
        .unwrap();

        let ops = pal.sign_ops.borrow();
        let support::RecordedSigningInput::Mldsa87Message { context, message } = &ops[0].input
        else {
            panic!("expected ML-DSA message signing input");
        };

        assert_eq!(context.as_slice(), b"responder-measurements signing");
        assert_eq!(message.len(), SPDM_SIGNING_CONTEXT_LEN + SHA384_HASH_SIZE);
        assert_eq!(
            &message[..SPDM_SIGNING_CONTEXT_LEN],
            signing_context(SpdmVersion::V14).as_slice()
        );
        assert!(message.starts_with(b"dmtf-spdm-v1.4.*"));
    }

    #[test]
    fn measurements_v14_mldsa87_response_is_chunked_when_over_data_transfer_size() {
        let pal = support::TestPal {
            mtu: 1024,
            large_buffered_msg_capacity: 16384,
            measurement_info: &MEASUREMENT_INFO,
            measurement_value: &MEASUREMENT_VALUE,
            ..Default::default()
        };
        let mut state = mldsa_state(SpdmVersion::V14);
        state.peer_cap_flags = caliptra_mcu_spdm_codec::CapFlags::CHUNK;
        state.peer_data_transfer_size = 1024;
        state.peer_max_spdm_msg_size = 16384;

        let io = support::TestIo::message(get_measurements_request(SpdmVersion::V14, true));
        block_on(state.transcript.append_vca(&pal, &io, &[0xAA, 0xBB])).unwrap();
        let (err_rsp, _) = block_on(handle_get_measurements_req(
            &mut state,
            &pal,
            &io,
            io.request(),
        ))
        .unwrap();

        assert_eq!(err_rsp[1], ReqRespCode::ERROR.0);
        let handle = err_rsp[4];

        let drain_io = support::TestIo::message(Vec::new());
        let msg = block_on(support::drain_chunked_response(
            &mut state, &pal, &drain_io, handle,
        ))
        .unwrap();

        assert_eq!(msg[1], ReqRespCode::MEASUREMENTS.0);
        let sig = &msg[msg.len() - 4627..];
        assert!(sig.iter().all(|&b| b == 0x77));
    }

    #[test]
    fn measurements_without_signature_is_algorithm_independent() {
        let pal = support::TestPal {
            mtu: 8192,
            large_buffered_msg_capacity: 8192,
            measurement_info: &MEASUREMENT_INFO,
            measurement_value: &MEASUREMENT_VALUE,
            ..Default::default()
        };
        let mut state = mldsa_state(SpdmVersion::V14);

        let io = support::TestIo::message(get_measurements_request(SpdmVersion::V14, false));
        let (resp, _) = block_on(handle_get_measurements_req(
            &mut state,
            &pal,
            &io,
            io.request(),
        ))
        .unwrap();

        assert_eq!(resp[1], ReqRespCode::MEASUREMENTS.0);
        assert!(pal.sign_ops.borrow().is_empty());
    }

    #[test]
    fn advertised_measurement_max_does_not_force_large_response_when_actual_fits() {
        let pal = support::TestPal {
            mtu: 64,
            measurement_info: &MEASUREMENT_INFO,
            measurement_value: &MEASUREMENT_VALUE,
            ..Default::default()
        };
        let mut state: ConnectionState<support::TestHashState, Vec<u8>> =
            ConnectionState::caliptra();
        state.phase = Phase::AfterAlgorithms;
        state.version = SpdmVersion::V12;

        let mut req = Vec::new();
        let hdr = SpdmMsgHdrPdu::new(SpdmVersion::V12, ReqRespCode::GET_MEASUREMENTS);
        let body = GetMeasurementsReqBody {
            attributes: 0,
            measurement_operation: 0xFD,
        };
        req.extend_from_slice(hdr.as_bytes());
        req.extend_from_slice(body.as_bytes());
        let io = support::TestIo::message(req);

        let (resp, spdm_len) = block_on(handle_get_measurements_req(
            &mut state,
            &pal,
            &io,
            io.request(),
        ))
        .unwrap();

        assert!(spdm_len <= pal.mtu());
        assert_eq!(resp[1], ReqRespCode::MEASUREMENTS.0);
        assert_eq!(resp[4], 1);
        assert_eq!(
            &resp[5..8],
            &(MEAS_BLOCK_METADATA_SIZE as u32 + 4).to_le_bytes()[..3]
        );
    }
}

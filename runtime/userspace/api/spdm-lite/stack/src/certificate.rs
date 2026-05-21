// Licensed under the Apache-2.0 license

//! GET_CERTIFICATE handler.
//!
//! Builds the SPDM certificate chain wire format on demand:
//! a 52-byte SPDM cert-chain header (Length, Reserved, RootHash) followed by
//! the DER chain exposed by the PAL. Pagination is handled by slicing that
//! virtual byte string at the request's Offset/Length.
//!
//! The handler avoids heap allocations and avoids keeping the full chain in
//! memory; only the requested portion is allocated from the PAL's per-I/O
//! allocator. The largest fixed scratch object here is the 52-byte header, no
//! stack-allocated `[u8; N]` array for cert payload.

use mcu_spdm_lite_codec::{
    CapFlags, CertificateRsp, CertificateRspBody, GetCertificateReqBody, ResponseBody,
    SpdmMsgHdrPdu, SpdmVersion, ATTR_SLOT_SIZE_REQUESTED,
};
use mcu_spdm_lite_traits::{
    PalBytes, SpdmPal, SpdmPalAsymAlgo, SpdmPalIo, SpdmPalIoTransport, MAX_SLOTS,
};
use zerocopy::FromBytes;

use crate::build::{build_error_response, build_response};
use crate::chunk;
use crate::error::{
    SpdmResult, SPDM_INVALID_REQUEST, SPDM_LARGE_RESPONSE, SPDM_UNEXPECTED_REQUEST,
    SPDM_UNSPECIFIED,
};
use crate::stack::{ConnectionState, Phase};

/// Size of the SPDM cert-chain wire header that prepends every cert
/// chain in a CERTIFICATE response (DSP0274 §10.6.1 Table 28):
/// `Length:u16 || Reserved:u16 || RootHash:48` for SHA-384.
const SPDM_CERT_CHAIN_HDR_LEN: usize = 4 + SHA384_DIGEST_SIZE;
const SHA384_DIGEST_SIZE: usize = 48;

/// Handle a GET_CERTIFICATE request.
pub(crate) async fn handle_get_certificate<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    if (state.phase as u8) < (Phase::AfterAlgorithms as u8) {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    let req = io.request();
    if req.len() > pal.mtu() {
        return Err(SPDM_INVALID_REQUEST);
    }

    let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(crate::error::SPDM_VERSION_MISMATCH);
    }

    let (req_body, rest) = GetCertificateReqBody::ref_from_prefix(body)
        .map_err(|_| SPDM_INVALID_REQUEST)?;
    if !rest.is_empty() {
        return Err(SPDM_INVALID_REQUEST);
    }

    let slot_id = req_body.slot_id;
    if slot_id >= MAX_SLOTS || (pal.provisioned_slots() & (1u8 << slot_id)) == 0 {
        return Err(SPDM_INVALID_REQUEST);
    }

    let slot_size_only =
        state.version >= SpdmVersion::V13 && (req_body.attributes & ATTR_SLOT_SIZE_REQUESTED) != 0;

    // Total SPDM cert chain length = 52-byte header + raw DER chain.
    let asym_algo = state.asym_algo();
    let der_len = pal
        .cert_chain_len(io, slot_id, asym_algo)
        .await
        .map_err(|_| SPDM_INVALID_REQUEST)?;
    let total_len_usize = SPDM_CERT_CHAIN_HDR_LEN
        .checked_add(der_len)
        .ok_or(SPDM_UNSPECIFIED)?;
    let total_len = u16::try_from(total_len_usize).map_err(|_| SPDM_UNSPECIFIED)?;

    let single_frame_portion = chunk::effective_data_transfer_size(state, pal)
        .saturating_sub(SpdmMsgHdrPdu::SIZE + CertificateRspBody::SIZE);

    let (offset, portion_len, remainder_len) = if slot_size_only {
        // V1.3 SlotSizeRequested: report total in RemainderLength.
        (0u16, 0u16, total_len)
    } else {
        let off = req_body.offset.get() as usize;
        if off > total_len_usize {
            return Err(SPDM_INVALID_REQUEST);
        }
        let remaining = total_len_usize - off;
        let chunking = state.cap_flags.contains(CapFlags::CHUNK)
            && state.peer_cap_flags.contains(CapFlags::CHUNK);
        let max_portion = if chunking {
            chunk::effective_max_spdm_msg_size(state, pal)
                .saturating_sub(SpdmMsgHdrPdu::SIZE + CertificateRspBody::SIZE)
        } else {
            single_frame_portion
        };
        let portion = (req_body.length.get() as usize)
            .min(remaining)
            .min(max_portion)
            .min(u16::MAX as usize);
        let remainder = remaining - portion;
        (off as u16, portion as u16, remainder as u16)
    };

    if !slot_size_only && (portion_len as usize) > single_frame_portion {
        let handle = state.large_response.start_certificate(
            slot_id,
            asym_algo,
            0,
            offset,
            portion_len,
            remainder_len,
        );
        let resp = build_error_response(
            pal,
            io,
            state.version,
            SPDM_LARGE_RESPONSE.spec_byte(),
            0,
            &[handle],
        )?;

        state.transcript.append_m1(pal, io, io.request()).await?;
        state.phase = Phase::AfterCertificate;
        return Ok(resp);
    }

    if portion_len == 0 {
        let cert_body = CertificateRsp {
            slot_id,
            param2: 0,
            portion_length: 0,
            remainder_length: remainder_len,
            chain_portion: &[],
        };
        let spdm_len = cert_body.encoded_size();
        let resp = build_response(pal, io, state.version, &cert_body)?;

        let head = pal.header_size();
        state.transcript.append_m1(pal, io, io.request()).await?;
        state
            .transcript
            .append_m1(pal, io, &resp[head..head + spdm_len])
            .await?;

        state.phase = Phase::AfterCertificate;
        return Ok(resp);
    }

    // Allocate the portion buffer from the per-IO pool. Bytes
    // are spliced in below: [0, 52) from the SPDM cert-chain
    // header, [52, total_len) from the raw DER chain.
    let mut portion = pal.alloc_bytes(io, portion_len as usize)?;
    fill_cert_chain_portion(pal, io, slot_id, asym_algo, offset as usize, &mut portion).await?;

    let cert_body = CertificateRsp {
        slot_id,
        param2: 0,
        portion_length: portion_len,
        remainder_length: remainder_len,
        chain_portion: &portion,
    };
    let spdm_len = cert_body.encoded_size();

    let resp = build_response(pal, io, state.version, &cert_body)?;

    let head = pal.header_size();
    state.transcript.append_m1(pal, io, io.request()).await?;
    state
        .transcript
        .append_m1(pal, io, &resp[head..head + spdm_len])
        .await?;

    state.phase = Phase::AfterCertificate;
    Ok(resp)
}

/// Fill a slice of the virtual SPDM cert-chain byte string.
///
/// The destination covers `[offset, offset + dst.len())` in the
/// full SPDM cert-chain wire layout (header + DER).
pub(crate) async fn fill_cert_chain_portion<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    slot: u8,
    asym_algo: SpdmPalAsymAlgo,
    offset: usize,
    dst: &mut [u8],
) -> mcu_error::McuResult<()> {
    let der_len = pal.cert_chain_len(io, slot, asym_algo).await?;
    let total_len = SPDM_CERT_CHAIN_HDR_LEN + der_len;
    let end = offset
        .checked_add(dst.len())
        .ok_or(mcu_error::codes::INVARIANT)?;
    if end > total_len {
        return Err(mcu_error::codes::INVARIANT);
    }

    let mut written = 0usize;
    if offset < SPDM_CERT_CHAIN_HDR_LEN {
        let mut hdr = [0u8; SPDM_CERT_CHAIN_HDR_LEN];
        hdr[0..2].copy_from_slice(&(total_len as u16).to_le_bytes());
        // hdr[2..4] Reserved = 0
        pal.root_cert_hash(
            io,
            slot,
            asym_algo,
            mcu_spdm_lite_traits::SpdmPalHashAlgo::Sha384,
            &mut hdr[4..4 + SHA384_DIGEST_SIZE],
        )
        .await?;

        let hdr_end = SPDM_CERT_CHAIN_HDR_LEN.min(end);
        let copy_len = hdr_end - offset;
        dst[..copy_len].copy_from_slice(&hdr[offset..hdr_end]);
        written = copy_len;
    }

    if written < dst.len() {
        let der_offset = (offset + written) - SPDM_CERT_CHAIN_HDR_LEN;
        let n = pal
            .read_cert_chain(io, slot, asym_algo, der_offset, &mut dst[written..])
            .await?;
        if n != dst.len() - written {
            return Err(mcu_error::codes::INVARIANT);
        }
    }

    Ok(())
}

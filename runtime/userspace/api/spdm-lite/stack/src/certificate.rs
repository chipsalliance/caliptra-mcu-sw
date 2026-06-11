// Licensed under the Apache-2.0 license

//! GET_CERTIFICATE → CERTIFICATE handler (DSP0274 §10.8).
//!
//! Splices the 52-byte SPDM cert-chain header (Length | Reserved |
//! RootHash) with raw DER bytes from the cert store into a single
//! `[offset, offset + portion_length)` slice that the codec writes
//! into the response.
//!
//! The portion buffer comes from the per-IO bitmap pool — no
//! stack-allocated `[u8; N]` array for cert payload.

use mcu_spdm_lite_codec::{
    CertificateRsp, CertificateRspBody, GetCertificateReqBody, ReqRespCode, ResponseBody,
    SpdmMsgHdrPdu, SpdmVersion, WireWriter, ATTR_SLOT_SIZE_REQUESTED,
};
use mcu_spdm_lite_traits::{
    PalBytes, SpdmPal, SpdmPalAsymAlgo, SpdmPalIo, SpdmPalIoTransport, MAX_SLOTS,
};
use zerocopy::{little_endian::U16, FromBytes};

use crate::build::{build_error_response, build_response};
use crate::chunk::LargeResponse;
use crate::error::{
    SpdmResult, SPDM_INVALID_REQUEST, SPDM_LARGE_RESPONSE, SPDM_UNEXPECTED_REQUEST,
    SPDM_UNSPECIFIED,
};
use crate::stack::{multi_key_conn_rsp, ConnectionState, Phase};

/// Size of the SPDM cert-chain wire header that prepends every cert
/// chain (DSP0274 §10.6.1 Table 33):
/// `Length(2) | Reserved(2) | RootHash(48)`.
const SPDM_CERT_CHAIN_HDR_LEN: usize = 4 + 48;
const SHA384_DIGEST_SIZE: usize = 48;
const CERTIFICATE_RESPONSE_HEADER_SIZE: usize = SpdmMsgHdrPdu::SIZE + CertificateRspBody::SIZE;

#[derive(Copy, Clone)]
pub(crate) struct CertificateLargeResponse {
    slot_id: u8,
    param2: u8,
    asym_algo: SpdmPalAsymAlgo,
    cert_offset: u16,
    portion_len: u16,
    remainder_len: u16,
}

impl CertificateLargeResponse {
    #[inline]
    pub(crate) fn new(
        slot_id: u8,
        param2: u8,
        asym_algo: SpdmPalAsymAlgo,
        cert_offset: u16,
        portion_len: u16,
        remainder_len: u16,
    ) -> Self {
        Self {
            slot_id,
            param2,
            asym_algo,
            cert_offset,
            portion_len,
            remainder_len,
        }
    }

    #[inline]
    pub(crate) fn response_size(&self) -> usize {
        CERTIFICATE_RESPONSE_HEADER_SIZE + self.portion_len as usize
    }

    pub(crate) async fn fill_chunk<Pal: SpdmPal>(
        &self,
        pal: &Pal,
        io: &<Pal as SpdmPalIoTransport>::Io<'_>,
        version: SpdmVersion,
        offset: usize,
        dst: &mut [u8],
    ) -> mcu_error::McuResult<()> {
        let end = offset
            .checked_add(dst.len())
            .ok_or(mcu_error::codes::INVARIANT)?;
        if end > self.response_size() {
            return Err(mcu_error::codes::INVARIANT);
        }

        let mut written = 0;
        if offset < CERTIFICATE_RESPONSE_HEADER_SIZE {
            let mut hdr = [0u8; CERTIFICATE_RESPONSE_HEADER_SIZE];
            let mut writer = WireWriter::new(&mut hdr);
            writer
                .write(&SpdmMsgHdrPdu::new(version, ReqRespCode::CERTIFICATE))
                .map_err(|_| mcu_error::codes::INVARIANT)?;
            writer
                .write(&CertificateRspBody {
                    slot_id: self.slot_id,
                    param2: self.param2,
                    portion_length: U16::new(self.portion_len),
                    remainder_length: U16::new(self.remainder_len),
                })
                .map_err(|_| mcu_error::codes::INVARIANT)?;
            let hdr_end = CERTIFICATE_RESPONSE_HEADER_SIZE.min(end);
            let copy_len = hdr_end - offset;
            let src = hdr
                .get(offset..hdr_end)
                .ok_or(mcu_error::codes::INVARIANT)?;
            let dst_head = dst.get_mut(..copy_len).ok_or(mcu_error::codes::INVARIANT)?;
            for (d, s) in dst_head.iter_mut().zip(src) {
                *d = *s;
            }
            written = copy_len;
        }

        if written < dst.len() {
            let cert_offset =
                self.cert_offset as usize + offset + written - CERTIFICATE_RESPONSE_HEADER_SIZE;
            fill_cert_chain_portion(
                pal,
                io,
                self.slot_id,
                self.asym_algo,
                cert_offset,
                &mut dst[written..],
            )
            .await?;
        }
        Ok(())
    }
}

pub(crate) async fn handle_get_certificate<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    // GET_CERTIFICATE is legal once algorithms are negotiated, and
    // any number of times after (pagination, re-requests).
    if (state.phase as u8) < (Phase::AfterAlgorithms as u8) {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    // Decode the 6-byte request body.
    let req = io.request();
    let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(crate::error::SPDM_VERSION_MISMATCH);
    }
    let req_body = GetCertificateReqBody::ref_from_bytes(
        body.get(..GetCertificateReqBody::SIZE)
            .ok_or(SPDM_INVALID_REQUEST)?,
    )
    .map_err(|_| SPDM_INVALID_REQUEST)?;

    let slot_id = req_body.slot_id & 0x0F;
    if slot_id >= MAX_SLOTS {
        return Err(SPDM_INVALID_REQUEST);
    }
    let provisioned = pal.provisioned_slots();
    let slot_size_only =
        state.version >= SpdmVersion::V13 && (req_body.attributes & ATTR_SLOT_SIZE_REQUESTED) != 0;
    if provisioned & (1 << slot_id) == 0 && !slot_size_only {
        return Err(SPDM_INVALID_REQUEST);
    }

    // Total SPDM cert chain length = 52-byte header + raw DER chain.
    let asym_algo = state.asym_algo();
    let der_len = if slot_size_only {
        pal.cert_chain_slot_size(io, slot_id, asym_algo).await
    } else {
        pal.cert_chain_len(io, slot_id, asym_algo).await
    }
    .map_err(|_| SPDM_INVALID_REQUEST)?;
    let total_len_usize = SPDM_CERT_CHAIN_HDR_LEN
        .checked_add(der_len)
        .ok_or(SPDM_UNSPECIFIED)?;
    let total_len = u16::try_from(total_len_usize).map_err(|_| SPDM_UNSPECIFIED)?;

    let single_frame_portion = state
        .effective_data_transfer_size(pal)
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
        let chunking = state.chunking_enabled();
        let max_portion = if chunking {
            state
                .effective_max_spdm_msg_size(pal)
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

    let cert_info = if multi_key_conn_rsp(state)? {
        pal.cert_info(slot_id).unwrap_or_default()
    } else {
        0
    };

    if !slot_size_only && (portion_len as usize) > single_frame_portion {
        let cert_rsp = CertificateLargeResponse::new(
            slot_id,
            cert_info,
            asym_algo,
            offset,
            portion_len,
            remainder_len,
        );
        let handle = state.large_response.next_handle();
        let resp = build_error_response(
            pal,
            io,
            state.version,
            SPDM_LARGE_RESPONSE.spec_byte(),
            0,
            &[handle],
        )?;

        state.transcript.append_m1(pal, io, io.request()).await?;
        state.large_response.start(
            LargeResponse::Certificate(cert_rsp),
            cert_rsp.response_size(),
        );
        state.phase = Phase::AfterCertificate;
        return Ok(resp);
    }

    if portion_len == 0 {
        let resp = build_response(
            pal,
            io,
            state.version,
            &CertificateRsp {
                slot_id,
                param2: cert_info,
                portion_length: 0,
                remainder_length: remainder_len,
                chain_portion: &[],
            },
        )?;

        let head = pal.header_size();
        state.transcript.append_m1(pal, io, io.request()).await?;
        state.transcript.append_m1(pal, io, &resp[head..]).await?;

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
        param2: cert_info,
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

/// Splice the SPDM cert-chain header (first 52 bytes) with raw DER
/// (bytes 52..) into the destination buffer.
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
    if dst.is_empty() {
        return Ok(());
    }
    let der_len = pal.cert_chain_len(io, slot, asym_algo).await?;
    let total_len = SPDM_CERT_CHAIN_HDR_LEN + der_len;
    let end = offset
        .checked_add(dst.len())
        .ok_or(mcu_error::codes::INVARIANT)?;
    if end > total_len {
        return Err(mcu_error::codes::INVARIANT);
    }

    // Bytes from the SPDM cert-chain header (if any) come first.
    let mut written = 0;
    if offset < SPDM_CERT_CHAIN_HDR_LEN {
        let mut hdr = [0u8; SPDM_CERT_CHAIN_HDR_LEN];
        let len_bytes = (total_len as u16).to_le_bytes();
        for (d, s) in hdr.iter_mut().take(len_bytes.len()).zip(&len_bytes) {
            *d = *s;
        }
        // bytes 2..4 (Reserved) stay zero
        let root_hash = hdr
            .get_mut(4..4 + SHA384_DIGEST_SIZE)
            .ok_or(mcu_error::codes::INVARIANT)?;
        pal.root_cert_hash(
            io,
            slot,
            asym_algo,
            mcu_spdm_lite_traits::SpdmPalHashAlgo::Sha384,
            root_hash,
        )
        .await?;
        let hdr_end = SPDM_CERT_CHAIN_HDR_LEN.min(end);
        let copy_len = hdr_end - offset;
        let src = hdr
            .get(offset..hdr_end)
            .ok_or(mcu_error::codes::INVARIANT)?;
        let dst_head = dst.get_mut(..copy_len).ok_or(mcu_error::codes::INVARIANT)?;
        for (d, s) in dst_head.iter_mut().zip(src) {
            *d = *s;
        }
        written = copy_len;
    }

    // Remaining bytes (if any) come from the raw DER chain.
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

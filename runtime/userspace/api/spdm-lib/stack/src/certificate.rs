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

use caliptra_mcu_spdm_codec::{
    CapFlags, CertificateLargeRsp, CertificateLargeRspBody, CertificateRsp, CertificateRspBody,
    GetCertificateParam1, GetCertificateReq, ReqRespCode, ResponseBody, SpdmMsgHdrPdu, SpdmVersion,
    WireWriter,
};
use caliptra_mcu_spdm_traits::{
    PalBytes, SpdmPal, SpdmPalAlloc, SpdmPalAsymAlgo, SpdmPalIo, SpdmPalIoTransport, MAX_SLOTS,
};
use zerocopy::{little_endian::U16, FromBytes};

use crate::build::{build_error_response, build_response};
use crate::chunk::LargeResponse;
use crate::error::{
    SpdmResult, SPDM_DATA_TOO_LARGE, SPDM_INVALID_REQUEST, SPDM_LARGE_RESPONSE,
    SPDM_UNEXPECTED_REQUEST, SPDM_UNSPECIFIED, SPDM_UNSUPPORTED_REQUEST,
};
use crate::stack::{multi_key_conn_rsp, ConnectionState, Phase};

/// Size of the currently supported SPDM cert-chain wire header:
/// `Length(4) | RootHash(48)`.
///
/// Through SPDM 1.3 the leading field is `Length(2) | Reserved(2)`
/// with `Reserved` required to be zero. SPDM 1.4 absorbs `Reserved`
/// into `Length`, making it a 32-bit little-endian value. The two
/// encodings are byte-identical for chains under 64 KiB, so the
/// header is always emitted as a little-endian `u32`.
const SPDM_CERT_CHAIN_HDR_LEN: usize = 4 + 48;
const SHA384_DIGEST_SIZE: usize = 48;
const CERTIFICATE_RESPONSE_HEADER_SIZE: usize = SpdmMsgHdrPdu::SIZE + CertificateRspBody::SIZE;
const CERTIFICATE_LARGE_RESPONSE_HEADER_SIZE: usize =
    SpdmMsgHdrPdu::SIZE + CertificateLargeRspBody::SIZE;

/// Largest total cert-chain length the chain format can express.
///
/// The chain-format `Length` field is 16 bits through SPDM 1.3 and 32
/// bits from 1.4 onward. This is independent of whether the requester
/// used the `LargeCertChain` request form, which bounds the offset and
/// portion fields — see `GetCertificateReq::max_length_cap`.
pub(crate) fn max_cert_chain_len(version: SpdmVersion) -> usize {
    if version >= SpdmVersion::V14 {
        u32::MAX as usize
    } else {
        u16::MAX as usize
    }
}

/// Encode the leading `Length` field of the SPDM cert-chain header.
///
/// Always a little-endian `u32`; for pre-1.4 chains the upper two
/// bytes are zero, which is exactly the required `Reserved` encoding.
///
/// Every producer of the chain header must use this so that the bytes
/// served by GET_CERTIFICATE and the bytes hashed for GET_DIGESTS,
/// CHALLENGE_AUTH and KEY_EXCHANGE_RSP agree.
///
/// # Why this takes no `SpdmVersion`
///
/// Deliberately version-independent. The encoding is a property of the
/// stored chain, not of the connection it is served over, because this
/// header feeds the cert-chain hash that goes into the CHALLENGE_AUTH
/// and KEY_EXCHANGE_RSP transcripts. A requester verifies those
/// signatures against the chain as it holds it, so the same chain must
/// hash identically no matter which version is negotiated; encoding it
/// per-version would break verification for a requester using a chain
/// cached from an earlier session.
///
/// This costs nothing below 64 KiB, where the 1.4 `u32` and the pre-1.4
/// `Length(2) | Reserved(2) = 0` encodings are byte-identical. The
/// version-dependent *bound* belongs at the serving path instead — see
/// [`max_cert_chain_len`] — since that is where 16-bit offset and
/// portion addressing actually constrains what can be transferred.
pub(crate) fn cert_chain_length_field(total_len: usize) -> mcu_error::McuResult<[u8; 4]> {
    let length = u32::try_from(total_len).map_err(|_| mcu_error::codes::INVARIANT)?;
    Ok(length.to_le_bytes())
}

#[derive(Copy, Clone)]
pub(crate) struct CertificateLargeResponse {
    slot_id: u8,
    param2: u8,
    asym_algo: SpdmPalAsymAlgo,
    cert_offset: u32,
    portion_len: u32,
    remainder_len: u32,
    large: bool,
}

impl CertificateLargeResponse {
    #[inline]
    pub(crate) fn new(
        slot_id: u8,
        param2: u8,
        asym_algo: SpdmPalAsymAlgo,
        cert_offset: u32,
        portion_len: u32,
        remainder_len: u32,
        large: bool,
    ) -> Self {
        Self {
            slot_id,
            param2,
            asym_algo,
            cert_offset,
            portion_len,
            remainder_len,
            large,
        }
    }

    #[inline]
    pub(crate) fn header_size(&self) -> usize {
        if self.large {
            CERTIFICATE_LARGE_RESPONSE_HEADER_SIZE
        } else {
            CERTIFICATE_RESPONSE_HEADER_SIZE
        }
    }

    #[inline]
    pub(crate) fn response_size(&self) -> usize {
        self.header_size() + self.portion_len as usize
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

        let hdr_size = self.header_size();
        let mut written = 0;
        if offset < hdr_size {
            let mut hdr = [0u8; CERTIFICATE_LARGE_RESPONSE_HEADER_SIZE];
            let mut writer = WireWriter::new(&mut hdr[..hdr_size]);
            writer
                .write(&SpdmMsgHdrPdu::new(version, ReqRespCode::CERTIFICATE))
                .map_err(|_| mcu_error::codes::INVARIANT)?;
            if self.large {
                writer
                    .write(&CertificateLargeRspBody {
                        param1: GetCertificateParam1::new()
                            .with_slot_id(self.slot_id)
                            .with_large_cert_chain(true),
                        param2: self.param2,
                        portion_length: U16::new(0),
                        remainder_length: U16::new(0),
                        large_portion_length: zerocopy::little_endian::U32::new(self.portion_len),
                        large_remainder_length: zerocopy::little_endian::U32::new(
                            self.remainder_len,
                        ),
                    })
                    .map_err(|_| mcu_error::codes::INVARIANT)?;
            } else {
                writer
                    .write(&CertificateRspBody {
                        slot_id: self.slot_id,
                        param2: self.param2,
                        portion_length: U16::new(self.portion_len as u16),
                        remainder_length: U16::new(self.remainder_len as u16),
                    })
                    .map_err(|_| mcu_error::codes::INVARIANT)?;
            }
            let hdr_end = hdr_size.min(end);
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
            let cert_offset = self.cert_offset as usize + offset + written - hdr_size;
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
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let (resp, _) = handle_get_certificate_req(state, pal, io, io.request()).await?;
    Ok(resp)
}

pub(crate) async fn handle_get_certificate_req<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    spdm_msg: &[u8],
) -> SpdmResult<(PalBytes<'a, Pal>, usize)> {
    // GET_CERTIFICATE is legal once algorithms are negotiated, and
    // any number of times after (pagination, re-requests).
    if (state.phase as u8) < (Phase::AfterAlgorithms as u8) {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(spdm_msg).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(crate::error::SPDM_VERSION_MISMATCH);
    }

    let req = GetCertificateReq::parse(body).map_err(|_| SPDM_INVALID_REQUEST)?;

    // A LargeCertChain GET_CERTIFICATE is only defined in SPDM 1.4+, and
    // only when the responder advertised LARGE_RESP_CAP. Below 1.4 the
    // param1 bit is reserved, so the request is malformed (InvalidRequest);
    // at 1.4+ without the capability it is UnsupportedRequest (DSP0274).
    if req.is_large() {
        if state.version < SpdmVersion::V14 {
            return Err(SPDM_INVALID_REQUEST);
        }
        if !state.advertised_cap_flags.contains(CapFlags::LARGE_RESP) {
            return Err(SPDM_UNSUPPORTED_REQUEST);
        }
    }

    let slot_id = req.slot_id();
    if slot_id >= MAX_SLOTS {
        return Err(SPDM_INVALID_REQUEST);
    }
    let slot_size_only = state.version >= SpdmVersion::V13 && req.is_slot_size_requested();
    let asym_algo = state.asym_algo();
    let provisioned = pal.provisioned_slots(asym_algo);
    if provisioned & (1 << slot_id) == 0 && !slot_size_only {
        return Err(SPDM_INVALID_REQUEST);
    }

    // Total SPDM cert chain length = 52-byte header + raw DER chain.
    let der_len = if slot_size_only {
        pal.cert_chain_slot_size(io, slot_id, asym_algo).await
    } else {
        pal.cert_chain_len(io, slot_id, asym_algo).await
    }
    .map_err(|_| SPDM_INVALID_REQUEST)?;
    let total_len_usize = SPDM_CERT_CHAIN_HDR_LEN
        .checked_add(der_len)
        .ok_or(SPDM_UNSPECIFIED)?;

    let max_chain_len = max_cert_chain_len(state.version).min(req.max_length_cap());
    if total_len_usize > max_chain_len {
        if state.version >= SpdmVersion::V14 {
            let actual_size = u32::try_from(total_len_usize).map_err(|_| SPDM_UNSPECIFIED)?;
            return Err(SPDM_DATA_TOO_LARGE.with_extended_data(actual_size.to_le_bytes()));
        }
        return Err(SPDM_UNSPECIFIED);
    }

    let single_frame_portion = state
        .effective_data_transfer_size(pal)
        .saturating_sub(SpdmMsgHdrPdu::SIZE + req.rsp_header_body_size());

    let (offset, portion_len, remainder_len) = if slot_size_only {
        (0u32, 0u32, total_len_usize as u32)
    } else {
        if req.offset() > total_len_usize {
            return Err(SPDM_INVALID_REQUEST);
        }
        let remaining = total_len_usize - req.offset();
        let chunking = state.chunking_enabled();
        let max_portion = if chunking {
            state
                .peer_max_spdm_message_size()?
                .saturating_sub(SpdmMsgHdrPdu::SIZE + req.rsp_header_body_size())
        } else {
            single_frame_portion
        };
        let portion = req
            .length()
            .min(remaining)
            .min(max_portion)
            .min(req.max_length_cap());
        let remainder = remaining - portion;
        (req.offset() as u32, portion as u32, remainder as u32)
    };

    let cert_info = if multi_key_conn_rsp(state)? {
        pal.cert_info(slot_id, asym_algo).unwrap_or_default()
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
            req.is_large(),
        );
        let handle = state.large_msg_ctx.next_handle();
        let resp = build_error_response(
            pal,
            io,
            state.version,
            SPDM_LARGE_RESPONSE.with_extended_data([handle]),
        )?;

        state.transcript.append_m1(pal, io, spdm_msg).await?;
        state.large_msg_ctx.start_response(
            LargeResponse::Certificate(cert_rsp),
            cert_rsp.response_size(),
            None,
        )?;
        state.phase = Phase::AfterCertificate;
        return Ok((resp, SpdmMsgHdrPdu::SIZE + 2 + 1));
    }

    let portion = if portion_len > 0 {
        let mut p = pal.alloc_bytes(io, portion_len as usize)?;
        fill_cert_chain_portion(pal, io, slot_id, asym_algo, offset as usize, &mut p).await?;
        Some(p)
    } else {
        None
    };
    let chain_slice: &[u8] = match &portion {
        Some(p) => p.as_ref(),
        None => &[],
    };

    let (resp, spdm_len) = if req.is_large() {
        let cert_body = CertificateLargeRsp {
            slot_id,
            param2: cert_info,
            large_portion_length: portion_len,
            large_remainder_length: remainder_len,
            chain_portion: chain_slice,
        };
        let spdm_len = cert_body.encoded_size();
        let resp = build_response(pal, io, state.version, &cert_body)?;
        (resp, spdm_len)
    } else {
        let cert_body = CertificateRsp {
            slot_id,
            param2: cert_info,
            portion_length: portion_len as u16,
            remainder_length: remainder_len as u16,
            chain_portion: chain_slice,
        };
        let spdm_len = cert_body.encoded_size();
        let resp = build_response(pal, io, state.version, &cert_body)?;
        (resp, spdm_len)
    };

    let head = pal.header_size();
    state.transcript.append_m1(pal, io, spdm_msg).await?;
    state
        .transcript
        .append_m1(pal, io, &resp[head..head + spdm_len])
        .await?;

    state.phase = Phase::AfterCertificate;
    Ok((resp, spdm_len))
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
    let total_len = SPDM_CERT_CHAIN_HDR_LEN
        .checked_add(der_len)
        .ok_or(mcu_error::codes::INVARIANT)?;
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
        hdr[..4].copy_from_slice(&cert_chain_length_field(total_len)?);
        let root_hash = hdr
            .get_mut(4..4 + SHA384_DIGEST_SIZE)
            .ok_or(mcu_error::codes::INVARIANT)?;
        pal.root_cert_hash(
            io,
            slot,
            asym_algo,
            caliptra_mcu_spdm_traits::SpdmPalHashAlgo::Sha384,
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

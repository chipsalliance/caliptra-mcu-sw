// Licensed under the Apache-2.0 license

//! GET_DIGESTS → DIGESTS handler (DSP0274 §10.5).
//!
//! Streams each provisioned slot's SPDM cert-chain wire bytes
//! through the negotiated hash and emits a concatenated digest
//! array. Chunk buffers come from the per-IO bitmap pool — no
//! stack-allocated `[u8; N]` arrays for cert content.

use mcu_spdm_lite_codec::{DigestsRsp, SpdmMsgHdrPdu};
use mcu_spdm_lite_traits::{
    PalBytes, SpdmPal, SpdmPalHashAlgo, SpdmPalIo, SpdmPalIoTransport, MAX_SLOTS,
};
use zerocopy::FromBytes;

use crate::build::build_response;
use crate::error::{SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_UNSPECIFIED};
use crate::stack::{ConnectionState, Phase};

/// Streaming chunk size when hashing a cert chain — comes from the
/// per-IO bitmap pool, not the stack.
const CERT_CHUNK_SIZE: usize = 256;

pub(crate) async fn handle_get_digests<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    if state.phase != Phase::AfterAlgorithms && state.phase != Phase::AfterDigests {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    // DSP0274 §10.5 Table 24: GET_DIGESTS header version shall match
    // the negotiated VCA version.
    let req = io.request();
    let (hdr, rest) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(crate::error::SPDM_VERSION_MISMATCH);
    }
    if rest.len() < 2 || rest[0] != 0 || rest[1] != 0 {
        return Err(SPDM_INVALID_REQUEST);
    }

    let provisioned = pal.provisioned_slots();
    let supported = provisioned; // we don't advertise unprovisioned slots
    let digest_size = SpdmPalHashAlgo::Sha384.hash_size();
    let num_slots = provisioned.count_ones() as usize;
    let digests_len = num_slots * digest_size;

    // Compute digests directly into a pool-allocated buffer; the
    // codec then copies these bytes into the response body via
    // `DigestsRsp::digests` slice.
    let mut digests = pal.alloc_bytes(io, digests_len).map_err(|_| SPDM_UNSPECIFIED)?;
    let mut cursor = 0;
    for slot in 0..MAX_SLOTS {
        if provisioned & (1 << slot) == 0 {
            continue;
        }
        let dst = &mut digests[cursor..cursor + digest_size];
        if let Some(cached) = pal.cached_chain_digest(slot, SpdmPalHashAlgo::Sha384) {
            dst.copy_from_slice(&cached[..digest_size]);
        } else {
            cert_chain_hash(pal, io, slot, SpdmPalHashAlgo::Sha384, dst)
                .await
                .map_err(|_| SPDM_UNSPECIFIED)?;
            pal.cache_chain_digest(slot, SpdmPalHashAlgo::Sha384, dst);
        }
        cursor += digest_size;
    }

    let resp = build_response(
        pal,
        io,
        state.version,
        &DigestsRsp {
            supported_slots: supported,
            provisioned_slots: provisioned,
            digests: &digests,
        },
    )?;

    // DSP0274 Table 47: GET_DIGESTS + DIGESTS contribute to M1 (the
    // `B` portion of `M1 = A ∥ B ∥ C`). The first append forks M1
    // from VCA via `Transcript::append_m1`.
    let head = pal.header_size();
    state.transcript.append_m1(pal, io, io.request()).await?;
    state.transcript.append_m1(pal, io, &resp[head..]).await?;

    state.phase = Phase::AfterDigests;
    Ok(resp)
}

/// Stream a slot's SPDM cert-chain bytes through the negotiated
/// hash and write the digest into `out`.
///
/// The SPDM cert-chain wire format (DSP0274 §10.6.1 Table 33) is
/// `Length(2) | Reserved(2) | RootHash(48) | DER chain[..]`. We
/// build the 52-byte header on the stack (the user explicitly
/// allowed this small allocation) and stream the variable-length
/// DER bytes from a pool-allocated chunk buffer.
#[inline(never)]
async fn cert_chain_hash<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    slot: u8,
    algo: SpdmPalHashAlgo,
    out: &mut [u8],
) -> mcu_error::McuResult<()> {
    let der_len = pal.cert_chain_len(io, slot).await?;
    let digest_size = algo.hash_size();

    // 52-byte SPDM cert-chain header on the stack. Per the user:
    // allocating 52 B on the stack is fine.
    let mut hdr = [0u8; 4 + 48];
    let total = (hdr.len() + der_len) as u16;
    hdr[0..2].copy_from_slice(&total.to_le_bytes());
    // bytes 2..4 (Reserved) already zero
    pal.root_cert_hash(io, slot, algo, &mut hdr[4..4 + digest_size])
        .await?;

    let mut state = pal.hash_init(io, algo, &hdr).await?;

    let mut offset = 0;
    loop {
        let mut buf = pal.alloc_bytes(io, CERT_CHUNK_SIZE)?;
        let n = pal.read_cert_chain(io, slot, offset, &mut buf).await?;
        if n == 0 {
            break;
        }
        pal.hash_update(io, &mut state, &buf[..n]).await?;
        offset += n;
        if n < buf.len() {
            break;
        }
    }

    pal.hash_finish(io, &mut state, out).await
}

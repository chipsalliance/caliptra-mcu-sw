// Licensed under the Apache-2.0 license

//! GET_DIGESTS → DIGESTS handler (DSP0274 §10.5).
//!
//! Streams each provisioned slot's SPDM cert-chain wire bytes
//! through the negotiated hash and emits a concatenated digest
//! array. Chunk buffers come from the per-IO bitmap pool — no
//! stack-allocated `[u8; N]` arrays for cert content.

use caliptra_mcu_spdm_codec::{DigestsRsp, ResponseBody, SpdmMsgHdrPdu, SHA384_HASH_SIZE};
use caliptra_mcu_spdm_traits::{
    PalBytes, SpdmPal, SpdmPalAlloc, SpdmPalAsymAlgo, SpdmPalHashAlgo, SpdmPalIo,
    SpdmPalIoTransport, MAX_SLOTS,
};
use zerocopy::FromBytes;

use crate::build::{build_response, write_fixed};
use crate::error::{SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_UNSPECIFIED};
use crate::stack::{multi_key_conn_rsp, ConnectionState, Phase};

/// Streaming chunk size when hashing a cert chain — comes from the
/// per-IO bitmap pool, not the stack.
const CERT_CHUNK_SIZE: usize = 1024;

pub(crate) async fn handle_get_digests<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let (resp, _) = handle_get_digests_req(state, pal, io, io.request()).await?;
    Ok(resp)
}

pub(crate) async fn handle_get_digests_req<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State, <Pal as SpdmPalAlloc>::LargeBuf>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    spdm_msg: &[u8],
) -> SpdmResult<(PalBytes<'a, Pal>, usize)> {
    if (state.phase as u8) < (Phase::AfterAlgorithms as u8) {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    // DSP0274 §10.5 Table 24: GET_DIGESTS header version shall match
    // the negotiated VCA version.
    let (hdr, rest) = SpdmMsgHdrPdu::ref_from_prefix(spdm_msg).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(crate::error::SPDM_VERSION_MISMATCH);
    }
    if rest.len() < 2 || rest[0] != 0 || rest[1] != 0 {
        return Err(SPDM_INVALID_REQUEST);
    }

    let supported = pal.supported_slots();
    let provisioned = pal.provisioned_slots();
    let digest_size = SpdmPalHashAlgo::Sha384.hash_size();
    let num_slots = provisioned.count_ones() as usize;
    let digests_len = num_slots * digest_size;
    let asym_algo = state.asym_algo();
    let multi_key = multi_key_conn_rsp(state)?;
    let multi_key_len = if multi_key { num_slots * 4 } else { 0 };

    // Compute digests directly into a pool-allocated response-tail buffer.
    // For SPDM 1.3 MultiKeyConnRsp, append KeyPairIDs, CertificateInfos, and
    // KeyUsageMasks after the digest array without copying DER bytes.
    let mut tail = pal
        .alloc_bytes(io, digests_len + multi_key_len)
        .map_err(|_| SPDM_UNSPECIFIED)?;
    let mut cursor = 0;
    for slot in 0..MAX_SLOTS {
        if provisioned & (1 << slot) == 0 {
            continue;
        }
        let dst = tail
            .get_mut(cursor..cursor + digest_size)
            .ok_or(SPDM_UNSPECIFIED)?;
        if let Some(cached) = pal.cached_chain_digest(slot, SpdmPalHashAlgo::Sha384) {
            let dst = dst
                .first_chunk_mut::<SHA384_HASH_SIZE>()
                .ok_or(SPDM_UNSPECIFIED)?;
            *dst = cached;
        } else {
            cert_chain_hash(pal, io, slot, asym_algo, SpdmPalHashAlgo::Sha384, dst)
                .await
                .map_err(|_| SPDM_UNSPECIFIED)?;
            pal.cache_chain_digest(slot, SpdmPalHashAlgo::Sha384, dst);
        }
        cursor += digest_size;
    }
    if multi_key {
        fill_multi_key_conn_rsp_data(pal, provisioned, &mut tail[digests_len..]);
    }

    let digests_body = DigestsRsp {
        supported_slots: supported,
        provisioned_slots: provisioned,
        digests: &tail,
    };
    let spdm_len = digests_body.encoded_size();

    let resp = build_response(pal, io, state.version, &digests_body)?;

    let head = pal.header_size();
    state.transcript.append_m1(pal, io, spdm_msg).await?;
    state
        .transcript
        .append_m1(pal, io, &resp[head..head + spdm_len])
        .await?;

    state.phase = Phase::AfterDigests;
    Ok((resp, spdm_len))
}

fn fill_multi_key_conn_rsp_data<Pal: SpdmPal>(pal: &Pal, provisioned: u8, dst: &mut [u8]) {
    let slot_cnt = provisioned.count_ones() as usize;
    debug_assert_eq!(dst.len(), slot_cnt * 4);
    let (key_pair_ids, rest) = dst.split_at_mut(slot_cnt);
    let (cert_infos, key_usage_masks) = rest.split_at_mut(slot_cnt);

    let mut index = 0;
    for slot in 0..MAX_SLOTS {
        if provisioned & (1 << slot) == 0 {
            continue;
        }
        key_pair_ids[index] = pal.key_pair_id(slot).unwrap_or_default();
        cert_infos[index] = pal.cert_info(slot).unwrap_or_default() & 0x07;
        let usage = index * 2;
        write_fixed(
            key_usage_masks,
            usage,
            &pal.key_usage_mask(slot).unwrap_or_default().to_le_bytes(),
        );
        index += 1;
    }
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
pub(crate) async fn cert_chain_hash<Pal: SpdmPal>(
    pal: &Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    slot: u8,
    asym_algo: SpdmPalAsymAlgo,
    algo: SpdmPalHashAlgo,
    out: &mut [u8],
) -> mcu_error::McuResult<()> {
    let der_len = pal.cert_chain_len(io, slot, asym_algo).await?;
    let digest_size = algo.hash_size();

    // 52-byte SPDM cert-chain header on the stack. Per the user:
    // allocating 52 B on the stack is fine.
    let mut hdr = [0u8; 4 + 48];
    let total = (hdr.len() + der_len) as u16;
    write_fixed(&mut hdr, 0, &total.to_le_bytes());
    // bytes 2..4 (Reserved) already zero
    pal.root_cert_hash(io, slot, asym_algo, algo, &mut hdr[4..4 + digest_size])
        .await?;

    let mut state = pal.hash_init(io, algo, &hdr).await?;

    let mut offset = 0;
    loop {
        let mut buf = pal.alloc_bytes(io, CERT_CHUNK_SIZE)?;
        let n = pal
            .read_cert_chain(io, slot, asym_algo, offset, &mut buf)
            .await?;
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

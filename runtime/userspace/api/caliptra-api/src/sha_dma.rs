// Licensed under the Apache-2.0 license

//! Caliptra `SHA_DMA` mailbox helper.
//!
//! Caliptra reads an AXI range with its DMA engine, hashes it with the SHA
//! accelerator and returns the digest, so the data never passes through the
//! mailbox.

use caliptra_api::mailbox::{CommandId, MailboxRespHeaderVarSize, ShaDmaReq, ShaDmaResp};
use core::mem::{offset_of, size_of};
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::sha::algo_code;
use crate::slice::{checked_slice_mut, copy_bytes, internal_slice};
use crate::wire::{mbox_execute, populate_checksum, CMD_SHA_DMA};
use crate::{HashAlgo, ScratchAlloc};

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct ShaDmaWireReq {
    chksum: U32,
    flags: U32,
    hash_algorithm: U32,
    axi_addr_lo: U32,
    axi_addr_hi: U32,
    length: U32,
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct ShaDmaWireRespHeader {
    _chksum: U32,
    _fips_status: U32,
    data_len: U32,
}

const REQ_LEN: usize = size_of::<ShaDmaWireReq>();
const RESP_HEADER_LEN: usize = size_of::<ShaDmaWireRespHeader>();
const RESP_MAX_LEN: usize = RESP_HEADER_LEN + HashAlgo::Sha512.hash_size();

// Anchor the command ID and the slim wire structs to Caliptra's own types.
const _: () = assert!(CMD_SHA_DMA == CommandId::SHA_DMA.0);
const _: () = assert!(REQ_LEN == size_of::<ShaDmaReq>());
const _: () = assert!(offset_of!(ShaDmaReq, flags) == offset_of!(ShaDmaWireReq, flags));
const _: () =
    assert!(offset_of!(ShaDmaReq, hash_algorithm) == offset_of!(ShaDmaWireReq, hash_algorithm));
const _: () = assert!(offset_of!(ShaDmaReq, axi_addr_lo) == offset_of!(ShaDmaWireReq, axi_addr_lo));
const _: () = assert!(offset_of!(ShaDmaReq, axi_addr_hi) == offset_of!(ShaDmaWireReq, axi_addr_hi));
const _: () = assert!(offset_of!(ShaDmaReq, length) == offset_of!(ShaDmaWireReq, length));
const _: () = assert!(RESP_HEADER_LEN == size_of::<MailboxRespHeaderVarSize>());
const _: () = assert!(
    offset_of!(MailboxRespHeaderVarSize, data_len) == offset_of!(ShaDmaWireRespHeader, data_len)
);
const _: () = assert!(offset_of!(ShaDmaResp, hash) == RESP_HEADER_LEN);
const _: () = assert!(RESP_MAX_LEN == size_of::<ShaDmaResp>());

/// Hash `len` bytes at `axi_addr` with Caliptra's `SHA_DMA` and write the
/// digest to `out`, which must be exactly `algo.hash_size()` bytes.
///
/// `axi_addr` is the address as seen by Caliptra's DMA. Caliptra requires a
/// non-zero length, 4-byte alignment and a range within one 4 GiB block.
#[inline(never)]
pub async fn sha_dma<A: ScratchAlloc>(
    alloc: &A,
    algo: HashAlgo,
    axi_addr: u64,
    len: u32,
    out: &mut [u8],
) -> McuResult<()> {
    if out.len() != algo.hash_size() {
        return Err(INVARIANT);
    }
    let req = build_sha_dma_req(alloc, algo, axi_addr, len)?;
    let mut rsp = alloc.alloc(RESP_MAX_LEN)?;
    let rsp_len = mbox_execute(CMD_SHA_DMA, &req, &mut rsp).await?;
    parse_sha_dma_resp(&rsp, rsp_len, algo, out)
}

fn build_sha_dma_req<A: ScratchAlloc>(
    alloc: &A,
    algo: HashAlgo,
    axi_addr: u64,
    len: u32,
) -> McuResult<A::Buf<'_>> {
    let mut req = alloc.alloc(REQ_LEN)?;
    req.fill(0);
    {
        let cmd = ShaDmaWireReq::mut_from_bytes(checked_slice_mut(&mut req, 0, REQ_LEN)?)
            .map_err(|_| INVARIANT)?;
        cmd.hash_algorithm = U32::new(algo_code(algo));
        cmd.axi_addr_lo = U32::new(axi_addr as u32);
        cmd.axi_addr_hi = U32::new((axi_addr >> 32) as u32);
        cmd.length = U32::new(len);
    }
    populate_checksum(CMD_SHA_DMA, &mut req)?;
    Ok(req)
}

fn parse_sha_dma_resp(rsp: &[u8], rsp_len: usize, algo: HashAlgo, out: &mut [u8]) -> McuResult<()> {
    let digest_len = algo.hash_size();
    if rsp_len != RESP_HEADER_LEN + digest_len {
        return Err(INTERNAL_BUG);
    }
    let header = ShaDmaWireRespHeader::ref_from_bytes(internal_slice(rsp, 0, RESP_HEADER_LEN)?)
        .map_err(|_| INTERNAL_BUG)?;
    if header.data_len.get() as usize != digest_len {
        return Err(INTERNAL_BUG);
    }
    copy_bytes(out, internal_slice(rsp, RESP_HEADER_LEN, digest_len)?)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::wire::calc_checksum;
    use std::vec::Vec;

    struct TestAlloc;

    impl ScratchAlloc for TestAlloc {
        type Buf<'a>
            = Vec<u8>
        where
            Self: 'a;

        fn alloc(&self, len: usize) -> McuResult<Self::Buf<'_>> {
            Ok(std::vec![0; len])
        }
    }

    fn response(algo: HashAlgo, data_len: u32) -> Vec<u8> {
        let mut rsp = std::vec![0u8; RESP_MAX_LEN];
        rsp[8..12].copy_from_slice(&data_len.to_le_bytes());
        for (i, b) in rsp[RESP_HEADER_LEN..].iter_mut().enumerate() {
            *b = i as u8;
        }
        rsp.truncate(RESP_HEADER_LEN + algo.hash_size());
        rsp
    }

    #[test]
    fn request_encodes_address_length_and_algorithm() {
        for (algo, code) in [(HashAlgo::Sha384, 1), (HashAlgo::Sha512, 2)] {
            let req = build_sha_dma_req(&TestAlloc, algo, 0x1_2345_6780, 0x1004).unwrap();
            let cmd = ShaDmaWireReq::ref_from_bytes(&req).unwrap();
            assert_eq!(cmd.flags.get(), 0);
            assert_eq!(cmd.hash_algorithm.get(), code);
            assert_eq!(cmd.axi_addr_lo.get(), 0x2345_6780);
            assert_eq!(cmd.axi_addr_hi.get(), 1);
            assert_eq!(cmd.length.get(), 0x1004);
            assert_eq!(cmd.chksum.get(), calc_checksum(CMD_SHA_DMA, &req[4..]));
        }
    }

    #[test]
    fn response_with_matching_digest_length_is_copied() {
        for algo in [HashAlgo::Sha384, HashAlgo::Sha512] {
            let rsp = response(algo, algo.hash_size() as u32);
            let mut out = std::vec![0u8; algo.hash_size()];
            assert_eq!(parse_sha_dma_resp(&rsp, rsp.len(), algo, &mut out), Ok(()));
            assert_eq!(out, rsp[RESP_HEADER_LEN..]);
        }
    }

    #[test]
    fn malformed_response_is_rejected() {
        let algo = HashAlgo::Sha384;
        let mut out = [0u8; 48];
        let rsp = response(algo, 64);
        assert_eq!(
            parse_sha_dma_resp(&rsp, rsp.len(), algo, &mut out),
            Err(INTERNAL_BUG)
        );
        let rsp = response(algo, 48);
        assert_eq!(
            parse_sha_dma_resp(&rsp, rsp.len() - 4, algo, &mut out),
            Err(INTERNAL_BUG)
        );
        let rsp = response(HashAlgo::Sha512, 64);
        assert_eq!(
            parse_sha_dma_resp(&rsp, rsp.len(), algo, &mut out),
            Err(INTERNAL_BUG)
        );
    }

    #[test]
    fn wrong_output_size_is_rejected_before_the_mailbox() {
        use core::future::Future;
        use core::task::{Context, Poll, Waker};

        let mut out = [0u8; 64];
        let future = core::pin::pin!(sha_dma(&TestAlloc, HashAlgo::Sha384, 0, 4, &mut out));
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(future.poll(&mut context), Poll::Ready(Err(INVARIANT)));
    }
}

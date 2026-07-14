// Licensed under the Apache-2.0 license

//! Random number generation via Caliptra `CM_RANDOM_GENERATE`.

use core::mem::size_of;
use mcu_error::codes::INVARIANT;
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::wire::{calc_checksum, CMD_CM_RANDOM_GENERATE, MBOX_RESP_HEADER_SIZE};
use crate::ApiAlloc;

/// Maximum random bytes per call (Caliptra limit).
const MAX_RANDOM_SIZE: usize = 48;

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct RandomGenReq {
    chksum: U32,
    size: U32,
}

const REQ_SIZE: usize = size_of::<RandomGenReq>();
const _: () = assert!(REQ_SIZE == 8);

/// Response: `chksum(4) + fips_status(4) + data_len(4) + data[N]`.
const RSP_HEADER_SIZE: usize = MBOX_RESP_HEADER_SIZE + 4; // +data_len field

/// Generate `out.len()` random bytes from Caliptra RNG.
#[inline(never)]
pub async fn rng_generate<A: ApiAlloc>(_alloc: &A, out: &mut [u8]) -> McuResult<()> {
    if out.is_empty() || out.len() > MAX_RANDOM_SIZE {
        return Err(INVARIANT);
    }

    // The fixed request and bounded 60-byte response are cheaper inline.
    let mut req = [0u8; REQ_SIZE];
    req.fill(0);
    {
        let r = RandomGenReq::mut_from_bytes(&mut req[..REQ_SIZE]).map_err(|_| INVARIANT)?;
        r.size = U32::new(out.len() as u32);
    }
    let checksum = calc_checksum(CMD_CM_RANDOM_GENERATE, &req);
    *req.first_chunk_mut::<4>().ok_or(INVARIANT)? = checksum.to_le_bytes();

    let mut rsp = [0u8; RSP_HEADER_SIZE + MAX_RANDOM_SIZE];
    let rsp_len = crate::wire::mbox_execute(CMD_CM_RANDOM_GENERATE, &req, &mut rsp).await?;

    // Parse data_len from response.
    if rsp_len < RSP_HEADER_SIZE {
        return Err(INVARIANT);
    }
    let data_len =
        U32::ref_from_bytes(&rsp[MBOX_RESP_HEADER_SIZE..RSP_HEADER_SIZE]).map_err(|_| INVARIANT)?;
    let n = data_len.get() as usize;
    if n != out.len() || RSP_HEADER_SIZE + n > rsp_len {
        return Err(INVARIANT);
    }
    out.copy_from_slice(&rsp[RSP_HEADER_SIZE..RSP_HEADER_SIZE + n]);
    Ok(())
}

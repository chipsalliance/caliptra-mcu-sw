// Licensed under the Apache-2.0 license

//! ECDSA P-384 signature verification via Caliptra `ECDSA384_SIGNATURE_VERIFY`.

use core::mem::size_of;
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::wire::{
    mbox_execute, populate_checksum, CMD_ECDSA384_SIGNATURE_VERIFY, MBOX_RESP_HEADER_SIZE,
};
use crate::ApiAlloc;

pub const ECDSA_P384_COORD_SIZE: usize = 48;
pub const ECDSA_P384_SIGNATURE_SIZE: usize = 96;

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct EcdsaVerifyReq {
    checksum: U32,
    pubkey_x: [u8; ECDSA_P384_COORD_SIZE],
    pubkey_y: [u8; ECDSA_P384_COORD_SIZE],
    signature_r: [u8; ECDSA_P384_COORD_SIZE],
    signature_s: [u8; ECDSA_P384_COORD_SIZE],
    hash: [u8; ECDSA_P384_COORD_SIZE],
}

const _: () = assert!(size_of::<EcdsaVerifyReq>() == 4 + 5 * ECDSA_P384_COORD_SIZE);

#[inline(never)]
pub async fn ecdsa_verify<A: ApiAlloc>(
    alloc: &A,
    pubkey_x: &[u8; ECDSA_P384_COORD_SIZE],
    pubkey_y: &[u8; ECDSA_P384_COORD_SIZE],
    signature: &[u8; ECDSA_P384_SIGNATURE_SIZE],
    hash: &[u8; ECDSA_P384_COORD_SIZE],
) -> McuResult<()> {
    let mut req = alloc.alloc(size_of::<EcdsaVerifyReq>())?;
    req.fill(0);
    let request = EcdsaVerifyReq::mut_from_bytes(&mut req).map_err(|_| INVARIANT)?;
    request.pubkey_x = *pubkey_x;
    request.pubkey_y = *pubkey_y;
    request.signature_r = *signature
        .first_chunk::<ECDSA_P384_COORD_SIZE>()
        .ok_or(INVARIANT)?;
    request.signature_s = *signature
        .get(ECDSA_P384_COORD_SIZE..)
        .and_then(|bytes| bytes.first_chunk::<ECDSA_P384_COORD_SIZE>())
        .ok_or(INVARIANT)?;
    request.hash = *hash;
    populate_checksum(CMD_ECDSA384_SIGNATURE_VERIFY, &mut req)?;

    let mut rsp = alloc.alloc(MBOX_RESP_HEADER_SIZE)?;
    let rsp_len = mbox_execute(CMD_ECDSA384_SIGNATURE_VERIFY, &req, &mut rsp).await?;
    if rsp_len != MBOX_RESP_HEADER_SIZE {
        return Err(INTERNAL_BUG);
    }
    Ok(())
}

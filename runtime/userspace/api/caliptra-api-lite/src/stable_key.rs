// Licensed under the Apache-2.0 license

//! `CM_DERIVE_STABLE_KEY` mailbox command.

use core::mem::size_of;
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::types::{Cmk, CMK_SIZE};
use crate::wire::{
    mbox_execute, populate_checksum, CMD_CM_DERIVE_STABLE_KEY, MBOX_RESP_HEADER_SIZE,
};

pub const CM_STABLE_KEY_INFO_SIZE: usize = 32;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StableKeyType {
    IDevId = 1,
    LDevId = 2,
    Owner = 3,
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct DeriveStableKeyReq {
    chksum: U32,
    key_type: U32,
    info: [u8; CM_STABLE_KEY_INFO_SIZE],
}

const _: () = assert!(size_of::<DeriveStableKeyReq>() == 4 + 4 + CM_STABLE_KEY_INFO_SIZE);
const DERIVE_STABLE_KEY_RSP_SIZE: usize = MBOX_RESP_HEADER_SIZE + CMK_SIZE;

pub async fn derive_stable_key(
    key_type: StableKeyType,
    info: &[u8; CM_STABLE_KEY_INFO_SIZE],
) -> McuResult<Cmk> {
    let mut req = DeriveStableKeyReq {
        chksum: U32::ZERO,
        key_type: U32::new(key_type as u32),
        info: *info,
    };
    populate_checksum(CMD_CM_DERIVE_STABLE_KEY, req.as_mut_bytes())?;

    let mut rsp = [0u8; DERIVE_STABLE_KEY_RSP_SIZE];
    let rsp_len = mbox_execute(CMD_CM_DERIVE_STABLE_KEY, req.as_bytes(), &mut rsp).await?;
    if rsp_len != DERIVE_STABLE_KEY_RSP_SIZE {
        return Err(INTERNAL_BUG);
    }
    let cmk: [u8; CMK_SIZE] = rsp[MBOX_RESP_HEADER_SIZE..]
        .try_into()
        .map_err(|_| INVARIANT)?;
    Ok(Cmk(cmk))
}

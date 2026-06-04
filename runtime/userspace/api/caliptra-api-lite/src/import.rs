// Licensed under the Apache-2.0 license

//! `CM_IMPORT` and `CM_DELETE` mailbox commands.
//!
//! `cm_import` imports raw key material into the Caliptra key vault,
//! returning an opaque [`Cmk`] handle.  `cm_delete` destroys a
//! previously issued handle.

use core::mem::size_of;
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::types::{CmKeyUsage, Cmk, CMK_SIZE};
use crate::wire::{
    mbox_execute, pad4, populate_checksum, CMD_CM_DELETE, CMD_CM_IMPORT, MBOX_RESP_HEADER_SIZE,
};
use crate::ApiAlloc;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Maximum raw-key bytes accepted by `CM_IMPORT` (512-bit key).
const CM_IMPORT_MAX_KEY_SIZE: usize = 64;

/// Request prefix: `chksum(4) + key_usage(4) + input_size(4)`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct ImportReqPrefix {
    chksum: U32,
    key_usage: U32,
    input_size: U32,
}

const _: () = assert!(size_of::<ImportReqPrefix>() == 12);

/// Delete request: `chksum(4) + cmk(128)`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct DeleteReq {
    chksum: U32,
    cmk: [u8; CMK_SIZE],
}

const _: () = assert!(size_of::<DeleteReq>() == 4 + CMK_SIZE);

/// Response for both Import and Delete: starts with `chksum(4) + fips(4)`,
/// then (for Import only) `cmk(128)`.
const IMPORT_RSP_SIZE: usize = MBOX_RESP_HEADER_SIZE + CMK_SIZE;
const DELETE_RSP_SIZE: usize = MBOX_RESP_HEADER_SIZE;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Import raw key material into the Caliptra key vault.
///
/// `data` must be ≤ 64 bytes (512-bit max key).
#[inline(never)]
pub async fn cm_import<A: ApiAlloc>(alloc: &A, usage: CmKeyUsage, data: &[u8]) -> McuResult<Cmk> {
    if data.len() > CM_IMPORT_MAX_KEY_SIZE {
        return Err(INVARIANT);
    }
    let prefix_len = size_of::<ImportReqPrefix>();
    let wire_len = pad4(prefix_len + data.len());

    let mut req = alloc.alloc(wire_len)?;
    req.fill(0);
    let pfx = ImportReqPrefix::mut_from_bytes(&mut req[..prefix_len]).map_err(|_| INVARIANT)?;
    pfx.key_usage = U32::new(usage as u32);
    pfx.input_size = U32::new(data.len() as u32);
    req[prefix_len..prefix_len + data.len()].copy_from_slice(data);
    populate_checksum(CMD_CM_IMPORT, &mut req)?;

    let mut rsp = alloc.alloc(IMPORT_RSP_SIZE)?;
    let rsp_len = mbox_execute(CMD_CM_IMPORT, &req, &mut rsp).await?;
    if rsp_len < IMPORT_RSP_SIZE {
        return Err(INTERNAL_BUG);
    }

    let mut cmk = Cmk::default();
    cmk.0
        .copy_from_slice(&rsp[MBOX_RESP_HEADER_SIZE..IMPORT_RSP_SIZE]);
    Ok(cmk)
}

/// Destroy a CMK handle in the Caliptra key vault.
#[inline(never)]
pub async fn cm_delete<A: ApiAlloc>(alloc: &A, cmk: &Cmk) -> McuResult<()> {
    let wire_len = size_of::<DeleteReq>();

    let mut req = alloc.alloc(wire_len)?;
    req.fill(0);
    let r = DeleteReq::mut_from_bytes(&mut req[..wire_len]).map_err(|_| INVARIANT)?;
    r.cmk.copy_from_slice(&cmk.0);
    populate_checksum(CMD_CM_DELETE, &mut req)?;

    let mut rsp = alloc.alloc(DELETE_RSP_SIZE)?;
    let rsp_len = mbox_execute(CMD_CM_DELETE, &req, &mut rsp).await?;
    if rsp_len < DELETE_RSP_SIZE {
        return Err(INTERNAL_BUG);
    }
    Ok(())
}

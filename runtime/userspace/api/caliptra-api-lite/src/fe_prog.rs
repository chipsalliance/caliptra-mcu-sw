// Licensed under the Apache-2.0 license

//! `FE_PROG` (field-entropy program) mailbox command.

use mcu_error::McuResult;

use crate::wire::{calc_checksum, CMD_FE_PROG, MBOX_RESP_HEADER_SIZE};
use crate::ApiAlloc;

/// Request layout: `chksum(4) | partition(4)` = 8 B.
const FE_PROG_REQ_LEN: usize = 8;

/// Program field entropy for `partition`. Returns once Caliptra has
/// completed the operation.
#[inline(never)]
pub async fn fe_prog<A: ApiAlloc>(alloc: &A, partition: u32) -> McuResult<()> {
    let mut req = alloc.alloc(FE_PROG_REQ_LEN)?;
    req.fill(0);
    req[4..8].copy_from_slice(&partition.to_le_bytes());
    let checksum = calc_checksum(CMD_FE_PROG, &req[4..]);
    req[..4].copy_from_slice(&checksum.to_le_bytes());

    let mut rsp = alloc.alloc(MBOX_RESP_HEADER_SIZE)?;
    let _rsp_len = crate::wire::mbox_execute(CMD_FE_PROG, &req, &mut rsp).await?;
    Ok(())
}

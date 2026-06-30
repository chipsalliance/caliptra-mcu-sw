// Licensed under the Apache-2.0 license

//! `FE_PROG` (field-entropy program) mailbox command.

use mcu_error::McuResult;

use crate::wire::{calc_checksum, CMD_FE_PROG, MBOX_RESP_HEADER_SIZE};
use crate::ApiAlloc;

/// Request layout: `chksum(4) | partition(4)` = 8 B.
const FE_PROG_REQ_LEN: usize = 8;
/// Core response layout: `MailboxRespHeader(8) | dpe_result(4)` = 12 B.
const FE_PROG_RESP_LEN: usize = MBOX_RESP_HEADER_SIZE + 4;

/// Program field entropy for `partition`. Returns once Caliptra has
/// completed the operation.
#[inline(never)]
pub async fn fe_prog<A: ApiAlloc>(alloc: &A, partition: u32) -> McuResult<()> {
    let mut req = alloc.alloc(FE_PROG_REQ_LEN)?;
    req.fill(0);
    req[4..8].copy_from_slice(&partition.to_le_bytes());
    let checksum = calc_checksum(CMD_FE_PROG, &req[4..]);
    req[..4].copy_from_slice(&checksum.to_le_bytes());

    let mut rsp = alloc.alloc(FE_PROG_RESP_LEN)?;
    let rsp_len = crate::wire::mbox_execute(CMD_FE_PROG, &req, &mut rsp).await?;
    if rsp_len > MBOX_RESP_HEADER_SIZE && rsp_len < FE_PROG_RESP_LEN {
        return Err(mcu_error::codes::INTERNAL_BUG);
    }
    if rsp_len >= FE_PROG_RESP_LEN {
        let dpe_result = u32::from_le_bytes([rsp[8], rsp[9], rsp[10], rsp[11]]);
        if dpe_result != 0 {
            return Err(mcu_error::codes::INTERNAL_BUG);
        }
    }
    Ok(())
}

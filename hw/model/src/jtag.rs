// Licensed under the Apache-2.0 license

use std::thread;
use std::time::Duration;

use caliptra_api::checksum::calc_checksum;
use caliptra_api::mailbox::CommandId;
use caliptra_hw_model::jtag::CaliptraCoreReg;
use caliptra_hw_model::openocd::openocd_jtag_tap::OpenOcdJtagTap;

use anyhow::{Context, Result};
use zerocopy::IntoBytes;

/// Wait for Caliptra Core mailbox response over JTAG TAP.
///
/// Returns the mbox_status.status bit field.
pub fn jtag_wait_for_caliptra_mailbox_resp(tap: &mut OpenOcdJtagTap) -> Result<u32> {
    loop {
        let mbox_status = tap.read_reg(&CaliptraCoreReg::MboxStatus)?;
        if (mbox_status & 0xf) != 0x0 {
            let status = mbox_status & 0xf;
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Acquire Caliptra Core mailbox lock over JTAG TAP.
///
/// This function blocks until the lock is acquired.
pub fn jtag_acquire_caliptra_mailbox_lock(tap: &mut OpenOcdJtagTap) -> Result<()> {
    loop {
        let mbox_lock = tap.read_reg(&CaliptraCoreReg::MboxLock)?;
        if (mbox_lock & 0x1) == 0 {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Send a mailbox command to Caliptra Core over JTAG TAP.
pub fn jtag_send_caliptra_mailbox_cmd(
    tap: &mut OpenOcdJtagTap,
    cmd: CommandId,
    payload: &[u32],
) -> Result<()> {
    let _ = jtag_acquire_caliptra_mailbox_lock(tap)?;
    let checksum = calc_checksum(cmd.0, &payload.as_bytes());

    // Write: cmd, length, checksum, payload, execute.
    tap.write_reg(&CaliptraCoreReg::MboxCmd, cmd.0)
        .context("Unable to write MboxCmd reg.")?;
    tap.write_reg(
        &CaliptraCoreReg::MboxDlen,
        // Add 4-bytes to the payload to account for the checksum.
        (payload.len() * 4 + 4).try_into().unwrap(),
    )
    .context("Unable to write MboxDlen reg.")?;
    tap.write_reg(&CaliptraCoreReg::MboxDin, checksum)
        .context("Unable to write checksum to MboxDin register.")?;
    for word in payload {
        tap.write_reg(&CaliptraCoreReg::MboxDin, *word)
            .context("Unable to write to MboxDin register.")?;
    }
    tap.write_reg(&CaliptraCoreReg::MboxExecute, 0x1)
        .context("Unable to write to MboxExecute register.")?;

    Ok(())
}

// Licensed under the Apache-2.0 license

use std::mem::offset_of;
use std::thread;
use std::time::{Duration, SystemTime};

use caliptra_api::checksum::calc_checksum;
use caliptra_api::mailbox::CommandId;
use caliptra_hw_model::jtag::{CaliptraCoreReg, CsrReg};
use caliptra_hw_model::openocd::openocd_jtag_tap::OpenOcdJtagTap;

use anyhow::{anyhow, Context, Result};
use caliptra_mcu_registers_generated::mci::regs::Mci;
use int_enum::IntEnum;
use zerocopy::{FromBytes, IntoBytes};

#[repr(u32)]
#[derive(Debug, PartialEq, IntEnum)]
pub enum CoreMailboxStatus {
    CmdBusy = 0x0,
    DataReady = 0x1,
    CmdComplete = 0x2,
    CmdFailure = 0x3,
}

const TIMEOUT_MS: Duration = Duration::from_millis(1000); // 1 second

/// Acquire Caliptra Core mailbox lock over JTAG TAP.
///
/// This function blocks until the lock is acquired.
pub fn jtag_acquire_caliptra_mailbox_lock(tap: &mut OpenOcdJtagTap) -> Result<()> {
    let now = SystemTime::now();
    while now.elapsed().unwrap() < TIMEOUT_MS {
        let mbox_lock = tap.read_reg(&CaliptraCoreReg::MboxLock)?;
        if (mbox_lock & 0x1) == 0 {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(anyhow!(
        "Timeout: waiting to acquire Caliptra Core mailbox."
    ))
}

/// Send a mailbox command to Caliptra Core over JTAG TAP.
pub fn jtag_send_caliptra_mailbox_cmd(
    tap: &mut OpenOcdJtagTap,
    cmd: CommandId,
    payload: &[u8],
) -> Result<()> {
    let _ = jtag_acquire_caliptra_mailbox_lock(tap)?;
    let checksum = calc_checksum(cmd.0, payload);

    // Write: cmd, length, checksum, payload, execute.
    tap.write_reg(&CaliptraCoreReg::MboxCmd, cmd.0)
        .context("Unable to write MboxCmd reg.")?;
    tap.write_reg(
        &CaliptraCoreReg::MboxDlen,
        // Add 4-bytes to the payload to account for the checksum.
        (payload.len() + 4).try_into().unwrap(),
    )
    .context("Unable to write MboxDlen reg.")?;
    tap.write_reg(&CaliptraCoreReg::MboxDin, checksum)
        .context("Unable to write checksum to MboxDin register.")?;
    let word_payload = <[u32]>::ref_from_bytes(payload).unwrap();
    for word in word_payload {
        tap.write_reg(&CaliptraCoreReg::MboxDin, *word)
            .context("Unable to write to MboxDin register.")?;
    }
    tap.write_reg(&CaliptraCoreReg::MboxExecute, 0x1)
        .context("Unable to set MboxExecute.")?;

    Ok(())
}

/// Wait for Caliptra Core mailbox response over JTAG TAP.
///
/// Returns the mbox_status.status bit field.
pub fn jtag_wait_for_caliptra_mailbox_resp(tap: &mut OpenOcdJtagTap) -> Result<CoreMailboxStatus> {
    let now = SystemTime::now();
    while now.elapsed().unwrap() < TIMEOUT_MS {
        let mbox_status =
            CoreMailboxStatus::try_from(tap.read_reg(&CaliptraCoreReg::MboxStatus)? & 0xf)
                .expect("Invalid Caliptra Core mailbox status.");
        if mbox_status != CoreMailboxStatus::CmdBusy {
            return Ok(mbox_status);
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(anyhow!(
        "Timeout: waiting to acquire Caliptra Core mailbox."
    ))
}

/// Get Caliptra Core mailbox response over JTAG TAP.
///
/// Also clears the MboxExecute bit after reading the response.
///
/// Returns the response as a vector of bytes.
pub fn jtag_get_caliptra_mailbox_resp(tap: &mut OpenOcdJtagTap) -> Result<Vec<u8>> {
    let mbox_status = jtag_wait_for_caliptra_mailbox_resp(tap)?;
    if mbox_status != CoreMailboxStatus::DataReady {
        return Err(anyhow!(
            "No response data in the mailbox (status = {:?}).",
            mbox_status
        ));
    }
    let num_rsp_bytes = tap.read_reg(&CaliptraCoreReg::MboxDlen)? as usize;
    let mut rsp_bytes = vec![0; num_rsp_bytes];
    for i in 0..num_rsp_bytes / 4 {
        let word = tap
            .read_reg(&CaliptraCoreReg::MboxDout)
            .expect("Failed to read response value.");
        rsp_bytes[i * 4..i * 4 + 4].copy_from_slice(word.as_bytes());
    }
    tap.write_reg(&CaliptraCoreReg::MboxExecute, 0x0)
        .context("Unable to clear MboxExecute.")?;
    Ok(rsp_bytes)
}

pub fn sideload_binary(
    tap: &mut OpenOcdJtagTap,
    bytes: &[u8],
    offset: u32,
    mci_base_addr: u32,
) -> Result<()> {
    // Disable watchdog timers to prevent reset during JTAG sideloading
    tap.write_memory_32(
        mci_base_addr + offset_of!(Mci, mci_reg_wdt_timer1_en) as u32,
        0,
    )?;
    tap.write_memory_32(
        mci_base_addr + offset_of!(Mci, mci_reg_wdt_timer2_en) as u32,
        0,
    )?;

    let mut words = Vec::with_capacity((bytes.len() + 3) / 4);
    for chunk in bytes.chunks(4) {
        let mut word_bytes = [0u8; 4];
        word_bytes[..chunk.len()].copy_from_slice(chunk);
        words.push(u32::from_le_bytes(word_bytes));
    }

    for (i, word) in words.iter().enumerate() {
        let addr = offset + (i as u32) * 4;
        tap.write_memory_32(addr, *word)?;
    }

    tap.write_csr_reg(CsrReg::Dpc, offset)?;

    Ok(())
}

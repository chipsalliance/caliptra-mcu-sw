// Licensed under the Apache-2.0 license
//
// MCI Mailbox Command Handler for Fuse Provisioning
//
// Receives fuse provisioning commands from MCI mailbox CSRs, verifies
// checksums, dispatches to the DAI-backed handlers in otp_provision,
// and writes caliptra-compatible responses (chksum + fips_status).
//

use crate::otp_provision::{
    fuse_lock_partition_dai, fuse_read_dai, fuse_write_dai, FuseError, FIPS_STATUS_APPROVED,
    MAX_FUSE_DATA_WORDS, MC_FUSE_LOCK_PARTITION_CMD, MC_FUSE_READ_CMD, MC_FUSE_WRITE_CMD,
};
use crate::{HexWord, Mci, Otp};
use core::cmp::Ordering;
use registers_generated::mci;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

// ---------------------------------------------------------------------------
// Per-command maximum input dlen (rejects oversized requests early to avoid
// iterating over arbitrarily large SRAM payloads during checksum verification)
// ---------------------------------------------------------------------------
const MAX_DLEN_FUSE_READ: u32 = 12; // chksum + partition + entry
const MAX_DLEN_FUSE_LOCK: u32 = 8; // chksum + partition
const MAX_DLEN_FUSE_WRITE: u32 = 20 + (MAX_FUSE_DATA_WORDS * 4) as u32; // header + data

// ---------------------------------------------------------------------------
// Mailbox register bundle (works for either mbox0 or mbox1)
// ---------------------------------------------------------------------------

struct FuseMboxRegs<'a> {
    execute: &'a tock_registers::registers::ReadWrite<u32, mci::bits::MboxExecute::Register>,
    status: &'a tock_registers::registers::ReadWrite<u32, mci::bits::MboxCmdStatus::Register>,
    dlen: &'a tock_registers::registers::ReadWrite<u32>,
    cmd: &'a tock_registers::registers::ReadWrite<u32>,
    sram: &'a [tock_registers::registers::ReadWrite<u32>],
}

// ---------------------------------------------------------------------------
// Checksum helpers operating directly on SRAM registers
// ---------------------------------------------------------------------------

/// Verify the caliptra-style request checksum.
///
/// Layout: SRAM\[0\] = chksum, SRAM\[1..\] = payload.
/// chksum == calc_checksum(cmd, LE-bytes-of(SRAM\[1..dlen/4\]))
fn verify_request_checksum(
    cmd: u32,
    sram: &[tock_registers::registers::ReadWrite<u32>],
    dlen: u32,
) -> bool {
    if dlen < 4 {
        return false;
    }
    let expected_chksum = sram[0].get();

    let mut sum = 0u32;
    for &c in cmd.to_le_bytes().iter() {
        sum = sum.wrapping_add(c as u32);
    }

    let payload_bytes = (dlen as usize) - 4;
    let full_words = payload_bytes / 4;
    let tail_bytes = payload_bytes % 4;

    for i in 0..full_words {
        for &b in sram[1 + i].get().to_le_bytes().iter() {
            sum = sum.wrapping_add(b as u32);
        }
    }
    if tail_bytes > 0 {
        let w = sram[1 + full_words].get();
        for (j, &b) in w.to_le_bytes().iter().enumerate() {
            if j < tail_bytes {
                sum = sum.wrapping_add(b as u32);
            }
        }
    }

    0u32.wrapping_sub(sum) == expected_chksum
}

/// Compute and write the caliptra-style response checksum into SRAM\[0\].
///
/// Covers bytes in SRAM\[1..resp_words\]; cmd = 0 for responses.
fn write_response_checksum(sram: &[tock_registers::registers::ReadWrite<u32>], resp_words: usize) {
    let mut sum: u32 = 0;
    for reg in sram.iter().take(resp_words).skip(1) {
        let w = reg.get();
        for &b in w.to_le_bytes().iter() {
            sum = sum.wrapping_add(b as u32);
        }
    }
    sram[0].set(0u32.wrapping_sub(sum));
}

/// Write a complete fuse-command response into SRAM.
///
/// Returns the total number of SRAM words written (chksum + fips_status +
/// optional data).
fn write_fuse_response(
    sram: &[tock_registers::registers::ReadWrite<u32>],
    fips_status: u32,
    data: Option<&[u32]>,
) -> usize {
    // SRAM[1] = fips_status
    sram[1].set(fips_status);

    let mut resp_words: usize = 2; // chksum + fips_status

    if let Some(d) = data {
        for (i, &w) in d.iter().enumerate() {
            sram[2 + i].set(w);
        }
        resp_words += d.len();
    }

    // SRAM[0] = chksum (over everything after it, cmd = 0)
    write_response_checksum(sram, resp_words);

    resp_words
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

/// MC_FUSE_READ handler.
///
/// Input  SRAM: chksum(u32), partition(u32), entry(u32)   — 12 bytes min
/// Output SRAM: chksum(u32), fips_status(u32), length_bits(u32), data…
fn handle_fuse_read(cmd: u32, input_dlen: u32, mbox: &FuseMboxRegs, otp: &Otp) {
    crate::println!("[mci-mbox] Processing MC_FUSE_READ (IFPR)");

    if input_dlen < 12 {
        crate::println!(
            "[mci-mbox] IFPR: dlen too short {} (minimum 12)",
            input_dlen
        );
        let n = write_fuse_response(mbox.sram, FuseError::InputTooShort.as_u32(), None);
        mbox.dlen.set((n * 4) as u32);
        mbox.status
            .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
        return;
    } else if input_dlen > MAX_DLEN_FUSE_READ {
        crate::println!(
            "[mci-mbox] IFPR: dlen too large {} (max {})",
            input_dlen,
            MAX_DLEN_FUSE_READ
        );
        let n = write_fuse_response(mbox.sram, FuseError::InvalidLength.as_u32(), None);
        mbox.dlen.set((n * 4) as u32);
        mbox.status
            .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
        return;
    }

    if !verify_request_checksum(cmd, mbox.sram, input_dlen) {
        crate::println!("[mci-mbox] IFPR: checksum mismatch");
        let n = write_fuse_response(mbox.sram, FuseError::ChecksumError.as_u32(), None);
        mbox.dlen.set((n * 4) as u32);
        mbox.status
            .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
        return;
    }

    let partition = mbox.sram[1].get();
    let entry = mbox.sram[2].get();
    crate::println!(
        "[mci-mbox] IFPR: partition={}, entry={}",
        HexWord(partition),
        entry
    );

    let mut data_buf = [0u32; MAX_FUSE_DATA_WORDS];

    match fuse_read_dai(otp, partition, entry, &mut data_buf) {
        Ok(length_bits) => {
            let data_words = ((length_bits + 31) / 32) as usize;
            // Build payload: length_bits, then data words
            let mut payload = [0u32; MAX_FUSE_DATA_WORDS + 1];
            payload[0] = length_bits;
            payload[1..(data_words + 1)].copy_from_slice(&data_buf[..data_words]);
            let n = write_fuse_response(
                mbox.sram,
                FIPS_STATUS_APPROVED,
                Some(&payload[..1 + data_words]),
            );
            mbox.dlen.set((n * 4) as u32);
            mbox.status
                .write(mci::bits::MboxCmdStatus::Status::DataReady);
            crate::println!("[mci-mbox] IFPR: success, {} bits", length_bits);
        }
        Err(e) => {
            let n = write_fuse_response(mbox.sram, e.as_u32(), None);
            mbox.dlen.set((n * 4) as u32);
            mbox.status
                .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
            crate::println!("[mci-mbox] IFPR: failed {}", HexWord(e.as_u32()));
        }
    }
}

/// MC_FUSE_WRITE handler.
///
/// Input  SRAM: chksum(u32), partition(u32), entry(u32),
///              start_bit(u32), length(u32), data…   — 20+ bytes
/// Output SRAM: chksum(u32), fips_status(u32)
fn handle_fuse_write(cmd: u32, input_dlen: u32, mbox: &FuseMboxRegs, otp: &Otp) {
    crate::println!("[mci-mbox] Processing MC_FUSE_WRITE (IFPW)");

    if input_dlen < 20 {
        crate::println!(
            "[mci-mbox] IFPW: dlen too short {} (minimum 20)",
            input_dlen
        );
        let n = write_fuse_response(mbox.sram, FuseError::InputTooShort.as_u32(), None);
        mbox.dlen.set((n * 4) as u32);
        mbox.status
            .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
        return;
    } else if input_dlen > MAX_DLEN_FUSE_WRITE {
        crate::println!(
            "[mci-mbox] IFPW: dlen too large {} (max {})",
            input_dlen,
            MAX_DLEN_FUSE_WRITE
        );
        let n = write_fuse_response(mbox.sram, FuseError::InvalidLength.as_u32(), None);
        mbox.dlen.set((n * 4) as u32);
        mbox.status
            .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
        return;
    }

    if !verify_request_checksum(cmd, mbox.sram, input_dlen) {
        crate::println!("[mci-mbox] IFPW: checksum mismatch");
        let n = write_fuse_response(mbox.sram, FuseError::ChecksumError.as_u32(), None);
        mbox.dlen.set((n * 4) as u32);
        mbox.status
            .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
        return;
    }

    let partition = mbox.sram[1].get();
    let entry = mbox.sram[2].get();
    let start_bit = mbox.sram[3].get();
    let length = mbox.sram[4].get();

    crate::println!(
        "[mci-mbox] IFPW: partition={}, entry={}, start_bit={}, length={}",
        HexWord(partition),
        entry,
        start_bit,
        length
    );

    // Checked arithmetic: length + 7 and 20 + data_bytes can wrap on crafted inputs.
    let data_bytes = match length.checked_add(7) {
        Some(v) => (v / 8) as usize,
        None => {
            crate::println!("[mci-mbox] IFPW: length overflow");
            let n = write_fuse_response(mbox.sram, FuseError::InvalidLength.as_u32(), None);
            mbox.dlen.set((n * 4) as u32);
            mbox.status
                .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
            return;
        }
    };
    let data_words = (data_bytes + 3) / 4;

    if data_words > MAX_FUSE_DATA_WORDS {
        crate::println!(
            "[mci-mbox] IFPW: data too large ({} words > max {})",
            data_words,
            MAX_FUSE_DATA_WORDS
        );
        let n = write_fuse_response(mbox.sram, FuseError::DataTooLarge.as_u32(), None);
        mbox.dlen.set((n * 4) as u32);
        mbox.status
            .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
        return;
    }

    let expected_dlen = match 20u32.checked_add(data_bytes as u32) {
        Some(v) => v,
        None => {
            crate::println!("[mci-mbox] IFPW: expected dlen overflow");
            let n = write_fuse_response(mbox.sram, FuseError::InvalidLength.as_u32(), None);
            mbox.dlen.set((n * 4) as u32);
            mbox.status
                .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
            return;
        }
    };

    match input_dlen.cmp(&expected_dlen) {
        Ordering::Less => {
            crate::println!(
                "[mci-mbox] IFPW: input too short for data ({} < {})",
                input_dlen,
                expected_dlen
            );
            let n = write_fuse_response(mbox.sram, FuseError::InputTooShort.as_u32(), None);
            mbox.dlen.set((n * 4) as u32);
            mbox.status
                .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
            return;
        }
        Ordering::Greater => {
            crate::println!(
                "[mci-mbox] IFPW: input too long for data ({} > {})",
                input_dlen,
                expected_dlen
            );
            let n = write_fuse_response(mbox.sram, FuseError::InvalidLength.as_u32(), None);
            mbox.dlen.set((n * 4) as u32);
            mbox.status
                .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
            return;
        }
        Ordering::Equal => {}
    }

    let mut data = [0u32; MAX_FUSE_DATA_WORDS];
    for (i, slot) in data.iter_mut().enumerate().take(data_words) {
        *slot = mbox.sram[5 + i].get();
    }

    let result = fuse_write_dai(
        otp,
        partition,
        entry,
        start_bit,
        length,
        &data[..data_words],
    );

    let fips = if result.is_success() {
        FIPS_STATUS_APPROVED
    } else {
        result.as_u32()
    };
    let n = write_fuse_response(mbox.sram, fips, None);
    mbox.dlen.set((n * 4) as u32);

    if result.is_success() {
        mbox.status
            .write(mci::bits::MboxCmdStatus::Status::DataReady);
        crate::println!("[mci-mbox] IFPW: success");
    } else {
        mbox.status
            .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
        crate::println!("[mci-mbox] IFPW: failed {}", HexWord(result.as_u32()));
    }
}

/// MC_FUSE_LOCK_PARTITION handler.
///
/// Input  SRAM: chksum(u32), partition(u32)   — 8 bytes min
/// Output SRAM: chksum(u32), fips_status(u32)
fn handle_fuse_lock_partition(cmd: u32, input_dlen: u32, mbox: &FuseMboxRegs, otp: &Otp) {
    crate::println!("[mci-mbox] Processing MC_FUSE_LOCK_PARTITION (IFPK)");

    if input_dlen < 8 {
        crate::println!("[mci-mbox] IFPK: dlen too short {} (minimum 8)", input_dlen);
        let n = write_fuse_response(mbox.sram, FuseError::InputTooShort.as_u32(), None);
        mbox.dlen.set((n * 4) as u32);
        mbox.status
            .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
        return;
    } else if input_dlen > MAX_DLEN_FUSE_LOCK {
        crate::println!(
            "[mci-mbox] IFPK: dlen too large {} (max {})",
            input_dlen,
            MAX_DLEN_FUSE_LOCK
        );
        let n = write_fuse_response(mbox.sram, FuseError::InvalidLength.as_u32(), None);
        mbox.dlen.set((n * 4) as u32);
        mbox.status
            .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
        return;
    }

    if !verify_request_checksum(cmd, mbox.sram, input_dlen) {
        crate::println!("[mci-mbox] IFPK: checksum mismatch");
        let n = write_fuse_response(mbox.sram, FuseError::ChecksumError.as_u32(), None);
        mbox.dlen.set((n * 4) as u32);
        mbox.status
            .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
        return;
    }

    let partition = mbox.sram[1].get();
    crate::println!("[mci-mbox] IFPK: partition={}", HexWord(partition));

    let result = fuse_lock_partition_dai(otp, partition);

    let fips = if result.is_success() {
        FIPS_STATUS_APPROVED
    } else {
        result.as_u32()
    };
    let n = write_fuse_response(mbox.sram, fips, None);
    mbox.dlen.set((n * 4) as u32);

    if result.is_success() {
        mbox.status
            .write(mci::bits::MboxCmdStatus::Status::DataReady);
        crate::println!("[mci-mbox] IFPK: success");
    } else {
        mbox.status
            .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
        crate::println!("[mci-mbox] IFPK: failed {}", HexWord(result.as_u32()));
    }
}

/// Handle an unrecognised command code.
fn handle_unknown_cmd(cmd: u32, mbox: &FuseMboxRegs) {
    crate::println!("[mci-mbox] Unknown fuse command: {}", HexWord(cmd));
    let n = write_fuse_response(mbox.sram, FuseError::UnknownCommand.as_u32(), None);
    mbox.dlen.set((n * 4) as u32);
    mbox.status
        .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
}

// ---------------------------------------------------------------------------
// Main mailbox processing loop
// ---------------------------------------------------------------------------

/// Process fuse provisioning commands arriving on MCI mailbox 0 / 1.
///
/// Polls both mailboxes; when `MBOX_EXECUTE` is asserted the command is
/// dispatched to the appropriate handler.  The loop runs indefinitely
/// (the caller decides when to invoke it and when to move on).
pub fn process_fuse_mbox_commands(mci: &Mci, otp: &Otp) {
    crate::println!("[mci-mbox] Waiting for fuse provisioning commands (IFPR/IFPW/IFPK)");

    let notif0 = &mci.registers.intr_block_rf_notif0_internal_intr_r;

    // Mailbox 0 registers
    let mbox0_execute = &mci.registers.mcu_mbox0_csr_mbox_execute;
    let mbox0_status = &mci.registers.mcu_mbox0_csr_mbox_cmd_status;
    let mbox0_dlen = &mci.registers.mcu_mbox0_csr_mbox_dlen;
    let mbox0_cmd = &mci.registers.mcu_mbox0_csr_mbox_cmd;
    let mbox0_sram = &mci.registers.mcu_mbox0_csr_mbox_sram;

    // Mailbox 1 registers
    let mbox1_execute = &mci.registers.mcu_mbox1_csr_mbox_execute;
    let mbox1_status = &mci.registers.mcu_mbox1_csr_mbox_cmd_status;
    let mbox1_dlen = &mci.registers.mcu_mbox1_csr_mbox_dlen;
    let mbox1_cmd = &mci.registers.mcu_mbox1_csr_mbox_cmd;
    let mbox1_sram = &mci.registers.mcu_mbox1_csr_mbox_sram;

    loop {
        // Poll both mailboxes until one has MBOX_EXECUTE asserted.
        let (active_mbox, is_mbox0) = loop {
            if mbox0_execute.read(mci::bits::MboxExecute::Execute) != 0 {
                break (
                    FuseMboxRegs {
                        execute: mbox0_execute,
                        status: mbox0_status,
                        dlen: mbox0_dlen,
                        cmd: mbox0_cmd,
                        sram: mbox0_sram,
                    },
                    true,
                );
            }
            if mbox1_execute.read(mci::bits::MboxExecute::Execute) != 0 {
                break (
                    FuseMboxRegs {
                        execute: mbox1_execute,
                        status: mbox1_status,
                        dlen: mbox1_dlen,
                        cmd: mbox1_cmd,
                        sram: mbox1_sram,
                    },
                    false,
                );
            }
        };

        let mbox_name = if is_mbox0 { "mbox0" } else { "mbox1" };
        crate::println!(
            "[mci-mbox] {} command received (MBOX_EXECUTE = 1)",
            mbox_name
        );

        // Clear notification sticky bit.
        if is_mbox0 {
            notif0.modify(mci::bits::Notif0IntrT::NotifMbox0CmdAvailSts::SET);
        } else {
            notif0.modify(mci::bits::Notif0IntrT::NotifMbox1CmdAvailSts::SET);
        }

        let cmd = active_mbox.cmd.get();
        let input_dlen = active_mbox.dlen.get();
        crate::println!(
            "[mci-mbox] Command: {}, dlen: {} bytes",
            HexWord(cmd),
            input_dlen
        );

        match cmd {
            MC_FUSE_READ_CMD => handle_fuse_read(cmd, input_dlen, &active_mbox, otp),
            MC_FUSE_WRITE_CMD => handle_fuse_write(cmd, input_dlen, &active_mbox, otp),
            MC_FUSE_LOCK_PARTITION_CMD => {
                handle_fuse_lock_partition(cmd, input_dlen, &active_mbox, otp)
            }
            _ => handle_unknown_cmd(cmd, &active_mbox),
        }

        // Wait for SoC to release the mailbox (MBOX_EXECUTE → 0).
        crate::println!(
            "[mci-mbox] Waiting for SoC to release {} (MBOX_EXECUTE → 0)",
            mbox_name
        );
        while active_mbox.execute.read(mci::bits::MboxExecute::Execute) != 0 {}
        crate::println!("[mci-mbox] {} released, ready for next command", mbox_name);
    }
}

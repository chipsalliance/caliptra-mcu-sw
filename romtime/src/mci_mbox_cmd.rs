// Licensed under the Apache-2.0 license
//
// MCI Mailbox Command Handler for Fuse Provisioning
//
// Receives fuse provisioning commands from MCI mailbox CSRs, dispatches to the
// DAI-backed handlers in otp_provision, and writes caliptra-compatible responses.
//
// Checksum verification and response formatting are centralized in the dispatch
// loop (process_fuse_mbox_commands), following the patterns established in
// caliptra-sw runtime and mcu-mbox-lib transport.

use crate::otp_provision::{fuse_lock_partition_dai, fuse_read_dai_params, fuse_write_dai};
use crate::{HexWord, Mci, Otp};
use caliptra_api::mailbox::populate_checksum;
use caliptra_mcu_error::McuError;
use caliptra_mcu_mbox_common::messages::{
    verify_checksum, CommandId, FuseLockPartitionReq, FuseReadReq, MailboxReqHeader,
    MailboxRespHeader, MAX_FUSE_DATA_WORDS,
};
use caliptra_mcu_registers_generated::mci;
use core::cmp::Ordering;
use core::mem::size_of;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Wire-format header for MC_FUSE_WRITE requests (without the variable-length data).
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable)]
struct FuseWriteReqHdr {
    pub hdr: MailboxReqHeader,
    pub partition: u32,
    pub entry: u32,
    pub start_bit: u32,
    pub length: u32,
}

/// Wire-format response for MC_FUSE_READ.
#[repr(C)]
#[derive(IntoBytes, FromBytes, KnownLayout, Immutable)]
struct FuseReadResp {
    pub hdr: MailboxRespHeader,
    pub valid_bits: u32,
    pub data: [u32; MAX_FUSE_DATA_WORDS],
}

const MAX_FUSE_REQ_BYTES: usize = size_of::<FuseWriteReqHdr>() + MAX_FUSE_DATA_WORDS * 4;
const RESP_HDR_BYTES: usize = size_of::<MailboxRespHeader>();

/// 4-byte–aligned buffer so zerocopy `ref_from_bytes` can produce references
/// to structs containing `u32` fields without alignment errors.
#[repr(C, align(4))]
struct AlignedBuf([u8; MAX_FUSE_REQ_BYTES]);

struct MciMboxRegs<'a> {
    execute: &'a tock_registers::registers::ReadWrite<u32, mci::bits::MboxExecute::Register>,
    status: &'a tock_registers::registers::ReadWrite<u32, mci::bits::MboxCmdStatus::Register>,
    dlen: &'a tock_registers::registers::ReadWrite<u32>,
    cmd: &'a tock_registers::registers::ReadWrite<u32>,
    sram: &'a [tock_registers::registers::ReadWrite<u32>],
}

// ---------------------------------------------------------------------------
// SRAM ↔ byte-buffer helpers
// ---------------------------------------------------------------------------

fn sram_to_buf(
    sram: &[tock_registers::registers::ReadWrite<u32>],
    buf: &mut [u8],
    byte_count: usize,
) {
    let words = (byte_count + 3) / 4;
    for i in 0..words.min(sram.len()).min(buf.len() / 4) {
        buf[i * 4..i * 4 + 4].copy_from_slice(&sram[i].get().to_le_bytes());
    }
}

fn buf_to_sram(buf: &[u8], sram: &[tock_registers::registers::ReadWrite<u32>], byte_count: usize) {
    let full_words = byte_count / 4;
    let tail = byte_count % 4;
    for i in 0..full_words.min(sram.len()) {
        sram[i].set(u32::from_le_bytes(
            buf[i * 4..i * 4 + 4].try_into().unwrap(),
        ));
    }
    if tail > 0 && full_words < sram.len() {
        let mut word_bytes = [0u8; 4];
        word_bytes[..tail].copy_from_slice(&buf[full_words * 4..full_words * 4 + tail]);
        sram[full_words].set(u32::from_le_bytes(word_bytes));
    }
}

/// Populate the response checksum, write the buffer to SRAM, and set
/// dlen / status in one shot.
fn send_response(mbox: &MciMboxRegs, buf: &mut [u8], resp_len: usize, success: bool) {
    let hdr = MailboxRespHeader::mut_from_bytes(&mut buf[..size_of::<MailboxRespHeader>()])
        .expect("buf is AlignedBuf and always large enough for MailboxRespHeader");
    if success {
        hdr.fips_status = MailboxRespHeader::FIPS_STATUS_APPROVED;
    }

    populate_checksum(&mut buf[..resp_len]);
    buf_to_sram(buf, mbox.sram, resp_len);
    mbox.dlen.set(resp_len as u32);
    if success {
        mbox.status
            .write(mci::bits::MboxCmdStatus::Status::DataReady);
    } else {
        mbox.status
            .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
    }
}

// ---------------------------------------------------------------------------
// Validation + dispatch
// ---------------------------------------------------------------------------

/// Validate the request envelope (size, checksum), then dispatch to the
/// appropriate handler.  Returns the response byte count on success with
/// the response body (excluding checksum) pre-filled in `buf`.
fn dispatch_fuse_command(
    cmd: u32,
    input_dlen: usize,
    sram: &[tock_registers::registers::ReadWrite<u32>],
    buf: &mut [u8],
    otp: &Otp,
) -> Result<usize, McuError> {
    if input_dlen < size_of::<u32>() || input_dlen > MAX_FUSE_REQ_BYTES {
        crate::println!(
            "[mci-mbox] Invalid dlen {} (must be {}..={})",
            input_dlen,
            size_of::<u32>(),
            MAX_FUSE_REQ_BYTES
        );
        return Err(McuError::ROM_OTP_FUSE_INVALID_LENGTH);
    }

    sram_to_buf(sram, buf, input_dlen);

    let chksum_bytes: [u8; 4] = buf
        .get(..size_of::<u32>())
        .ok_or(McuError::ROM_OTP_FUSE_INVALID_LENGTH)?
        .try_into()
        .unwrap();
    let chksum = u32::from_le_bytes(chksum_bytes);
    let payload = buf
        .get(size_of::<u32>()..input_dlen)
        .ok_or(McuError::ROM_OTP_FUSE_INVALID_LENGTH)?;
    if !verify_checksum(chksum, cmd, payload) {
        crate::println!("[mci-mbox] Checksum mismatch");
        return Err(McuError::ROM_OTP_FUSE_CHECKSUM_ERROR);
    }

    match CommandId(cmd) {
        CommandId::MC_FUSE_READ => handle_fuse_read(buf, input_dlen, otp),
        CommandId::MC_FUSE_WRITE => handle_fuse_write(buf, input_dlen, otp),
        CommandId::MC_FUSE_LOCK_PARTITION => handle_fuse_lock_partition(buf, input_dlen, otp),
        _ => {
            crate::println!("[mci-mbox] Unknown fuse command: {}", HexWord(cmd));
            Err(McuError::ROM_MCI_MBOX_UNKNOWN_COMMAND)
        }
    }
}

// ---------------------------------------------------------------------------
// Command handlers
//
// Each handler receives the request bytes in `buf` (checksum already verified)
// and builds the response body in the same buffer.  Returns the total response
// byte count on success; the caller populates the checksum and writes to SRAM.
// ---------------------------------------------------------------------------

fn handle_fuse_read(buf: &mut [u8], dlen: usize, otp: &Otp) -> Result<usize, McuError> {
    crate::println!("[mci-mbox] Processing MC_FUSE_READ (IFPR)");

    if dlen != size_of::<FuseReadReq>() {
        crate::println!(
            "[mci-mbox] IFPR: unexpected dlen {} (expected {})",
            dlen,
            size_of::<FuseReadReq>()
        );
        return Err(McuError::ROM_OTP_FUSE_INVALID_LENGTH);
    }

    let req = FuseReadReq::ref_from_bytes(&buf[..size_of::<FuseReadReq>()])
        .map_err(|_| McuError::ROM_OTP_FUSE_INVALID_LENGTH)?;
    let partition = req.partition;
    let entry = req.entry;
    crate::println!(
        "[mci-mbox] IFPR: partition={}, entry={}",
        HexWord(partition),
        entry
    );

    let params = fuse_read_dai_params(partition, entry, MAX_FUSE_DATA_WORDS)?;

    let resp = FuseReadResp::mut_from_bytes(&mut buf[..size_of::<FuseReadResp>()])
        .map_err(|_| McuError::ROM_OTP_FUSE_INVALID_LENGTH)?;
    resp.valid_bits = params.valid_bits;
    for i in 0..params.words_to_read {
        match otp.read_word(params.base_word_addr + i) {
            Ok(word) => resp.data[i] = word,
            Err(_) => {
                crate::println!(
                    "[mci-mbox] IFPR: DAI read error at word addr {}",
                    params.base_word_addr + i
                );
                return Err(McuError::ROM_OTP_FUSE_DAI_READ_ERROR);
            }
        }
    }

    let resp_bytes = RESP_HDR_BYTES + size_of::<u32>() + params.words_to_read * size_of::<u32>();
    crate::println!("[mci-mbox] IFPR: success, {} bits", params.valid_bits);
    Ok(resp_bytes)
}

fn handle_fuse_write(buf: &mut [u8], dlen: usize, otp: &Otp) -> Result<usize, McuError> {
    crate::println!("[mci-mbox] Processing MC_FUSE_WRITE (IFPW)");

    let hdr_size = size_of::<FuseWriteReqHdr>();
    if dlen < hdr_size {
        crate::println!(
            "[mci-mbox] IFPW: dlen too short {} (minimum {})",
            dlen,
            hdr_size
        );
        return Err(McuError::ROM_OTP_FUSE_INPUT_TOO_SHORT);
    }

    let req = FuseWriteReqHdr::ref_from_bytes(&buf[..hdr_size])
        .map_err(|_| McuError::ROM_OTP_FUSE_INVALID_LENGTH)?;
    let partition = req.partition;
    let entry = req.entry;
    let start_bit = req.start_bit;
    let length = req.length;

    crate::println!(
        "[mci-mbox] IFPW: partition={}, entry={}, start_bit={}, length={}",
        HexWord(partition),
        entry,
        start_bit,
        length
    );

    let data_bytes = length.div_ceil(8) as usize;
    let data_words = (data_bytes + 3) / 4;

    if data_words > MAX_FUSE_DATA_WORDS {
        crate::println!(
            "[mci-mbox] IFPW: data too large ({} words > max {})",
            data_words,
            MAX_FUSE_DATA_WORDS
        );
        return Err(McuError::ROM_OTP_FUSE_DATA_TOO_LARGE);
    }

    let expected_dlen = hdr_size.checked_add(data_bytes).ok_or_else(|| {
        crate::println!("[mci-mbox] IFPW: expected dlen overflow");
        McuError::ROM_OTP_FUSE_INVALID_LENGTH
    })?;

    match dlen.cmp(&expected_dlen) {
        Ordering::Less => {
            crate::println!(
                "[mci-mbox] IFPW: input too short for data ({} < {})",
                dlen,
                expected_dlen
            );
            return Err(McuError::ROM_OTP_FUSE_INPUT_TOO_SHORT);
        }
        Ordering::Greater => {
            crate::println!(
                "[mci-mbox] IFPW: input too long for data ({} > {})",
                dlen,
                expected_dlen
            );
            return Err(McuError::ROM_OTP_FUSE_INVALID_LENGTH);
        }
        Ordering::Equal => {}
    }

    fuse_write_dai(otp, partition, entry, start_bit, length, data_words, |i| {
        u32::from_le_bytes(
            buf[hdr_size + i * 4..hdr_size + i * 4 + 4]
                .try_into()
                .unwrap(),
        )
    })?;

    crate::println!("[mci-mbox] IFPW: success");
    Ok(RESP_HDR_BYTES)
}

fn handle_fuse_lock_partition(buf: &mut [u8], dlen: usize, otp: &Otp) -> Result<usize, McuError> {
    crate::println!("[mci-mbox] Processing MC_FUSE_LOCK_PARTITION (IFPK)");

    if dlen != size_of::<FuseLockPartitionReq>() {
        crate::println!(
            "[mci-mbox] IFPK: unexpected dlen {} (expected {})",
            dlen,
            size_of::<FuseLockPartitionReq>()
        );
        return Err(McuError::ROM_OTP_FUSE_INVALID_LENGTH);
    }

    let req = FuseLockPartitionReq::ref_from_bytes(&buf[..size_of::<FuseLockPartitionReq>()])
        .map_err(|_| McuError::ROM_OTP_FUSE_INVALID_LENGTH)?;
    let partition = req.partition;
    crate::println!("[mci-mbox] IFPK: partition={}", HexWord(partition));

    fuse_lock_partition_dai(otp, partition)?;

    crate::println!("[mci-mbox] IFPK: success");
    Ok(RESP_HDR_BYTES)
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

    let mbox0_execute = &mci.registers.mcu_mbox0_csr_mbox_execute;
    let mbox0_status = &mci.registers.mcu_mbox0_csr_mbox_cmd_status;
    let mbox0_dlen = &mci.registers.mcu_mbox0_csr_mbox_dlen;
    let mbox0_cmd = &mci.registers.mcu_mbox0_csr_mbox_cmd;
    let mbox0_sram = &mci.registers.mcu_mbox0_csr_mbox_sram;

    let mbox1_execute = &mci.registers.mcu_mbox1_csr_mbox_execute;
    let mbox1_status = &mci.registers.mcu_mbox1_csr_mbox_cmd_status;
    let mbox1_dlen = &mci.registers.mcu_mbox1_csr_mbox_dlen;
    let mbox1_cmd = &mci.registers.mcu_mbox1_csr_mbox_cmd;
    let mbox1_sram = &mci.registers.mcu_mbox1_csr_mbox_sram;

    loop {
        let (active_mbox, is_mbox0) = loop {
            if mbox0_execute.read(mci::bits::MboxExecute::Execute) != 0 {
                break (
                    MciMboxRegs {
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
                    MciMboxRegs {
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

        if is_mbox0 {
            notif0.modify(mci::bits::Notif0IntrT::NotifMbox0CmdAvailSts::SET);
        } else {
            notif0.modify(mci::bits::Notif0IntrT::NotifMbox1CmdAvailSts::SET);
        }

        let cmd = active_mbox.cmd.get();
        let input_dlen = active_mbox.dlen.get() as usize;
        crate::println!(
            "[mci-mbox] Command: {}, dlen: {} bytes",
            HexWord(cmd),
            input_dlen
        );

        let mut aligned_buf = AlignedBuf([0u8; MAX_FUSE_REQ_BYTES]);
        let buf = &mut aligned_buf.0[..];

        let result = dispatch_fuse_command(cmd, input_dlen, active_mbox.sram, buf, otp);

        match result {
            Ok(resp_len) => {
                send_response(&active_mbox, buf, resp_len, true);
            }
            Err(e) => {
                let err_code = u32::from(e);
                crate::println!("[mci-mbox] Command failed: {}", HexWord(err_code));
                let hdr =
                    MailboxRespHeader::mut_from_bytes(&mut buf[..size_of::<MailboxRespHeader>()])
                        .expect("buf is AlignedBuf and always large enough for MailboxRespHeader");
                hdr.fips_status = err_code;
                send_response(&active_mbox, buf, RESP_HDR_BYTES, false);
            }
        }

        crate::println!(
            "[mci-mbox] Waiting for SoC to release {} (MBOX_EXECUTE → 0)",
            mbox_name
        );
        while active_mbox.execute.read(mci::bits::MboxExecute::Execute) != 0 {}
        crate::println!("[mci-mbox] {} released, ready for next command", mbox_name);
    }
}

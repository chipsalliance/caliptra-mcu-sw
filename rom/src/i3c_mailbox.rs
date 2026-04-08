// Licensed under the Apache-2.0 license

use mcu_error::McuError;
use registers_generated::i3c;
use registers_generated::i3c::bits::{InterruptStatus, Status, TtiResetControl};
use romtime::StaticRef;
use tock_registers::interfaces::{Readable, Writeable};

/// I3C Mandatory Data Byte for service IBI notifications.
const MDB_SERVICES: u8 = 0x1F;

/// Built-in command IDs.
const CMD_PING: u8 = 0x00;

/// Status codes.
const STATUS_SUCCESS: u8 = 0x00;
const STATUS_INVALID_CMD: u8 = 0x01;
const STATUS_AWAITING: u8 = 0x80;

/// Maximum number of poll iterations before giving up.
/// At ~200 MHz AXI clock this gives roughly 5 seconds of polling.
const MAX_POLL_ITERATIONS: u32 = 200_000_000;

/// Maximum number of poll iterations waiting for an IBI to complete.
const MAX_IBI_POLL_ITERATIONS: u32 = 100_000_000;

/// Maximum number of poll iterations for the initial STATUS_AWAITING IBI.
/// Shorter than the normal IBI timeout since the controller may not be
/// ready yet. At ~200 MHz this gives roughly 50ms.
const AWAITING_IBI_POLL_ITERATIONS: u32 = 10_000_000;

/// Maximum RX data words (each word is 4 bytes).
const MAX_RX_WORDS: usize = 64;

/// "PONG" response payload (ASCII, little-endian u32).
const PONG_PAYLOAD: [u8; 4] = *b"PONG";

/// Result from dispatching a single command.
#[allow(dead_code)]
enum DispatchResult {
    /// Command handled; continue processing.
    Continue,
    /// Handler requests the mailbox loop to exit normally.
    Done,
}

/// Generic I3C mailbox handler.
///
/// The I3C peripheral must already be configured (via `I3c::configure()`)
/// before constructing this handler.
pub struct I3cMailboxHandler {
    registers: StaticRef<i3c::regs::I3c>,
    services: crate::I3cServicesModes,
}

impl I3cMailboxHandler {
    pub fn new(registers: StaticRef<i3c::regs::I3c>, services: crate::I3cServicesModes) -> Self {
        Self {
            registers,
            services,
        }
    }

    /// Run the mailbox processing loop until completion or timeout.
    pub fn run(&mut self) -> Result<(), McuError> {
        romtime::println!("[mcu-rom-i3c-svc] Entering I3C services mode");

        // Announce readiness via IBI. Use a short timeout since the I3C
        // controller may not be ready to acknowledge IBIs yet (e.g. on FPGA
        // it re-enumerates the bus after recovery). If the IBI doesn't
        // complete, reset the IBI queue to abort it — a pending IBI in the
        // queue causes the I3C target FSM to stay in DoIBI state and ignore
        // incoming private writes (i3c-core: i3c_target_fsm.sv line 565).
        self.send_ibi_with_abort(&[STATUS_AWAITING]);

        for _ in 0..MAX_POLL_ITERATIONS {
            if let Some((cmd, rx_buf, data_len)) = self.try_receive_command() {
                match self.dispatch(cmd, &rx_buf, data_len) {
                    DispatchResult::Continue => {}
                    DispatchResult::Done => return Ok(()),
                }
            }
        }

        romtime::println!("[mcu-rom-i3c-svc] I3C services timed out");
        Err(McuError::ROM_COLD_BOOT_DOT_ERROR)
    }

    /// Dispatch a received command to the appropriate handler.
    fn dispatch(&self, cmd: u8, _rx_buf: &[u32; MAX_RX_WORDS], _data_len: usize) -> DispatchResult {
        match cmd {
            CMD_PING => {
                romtime::println!("[mcu-rom-i3c-svc] PING received");
                self.send_response(STATUS_SUCCESS, &PONG_PAYLOAD);
                DispatchResult::Continue
            }
            _ => {
                romtime::println!("[mcu-rom-i3c-svc] Unknown command: {:#x}", cmd);
                self.send_status(STATUS_INVALID_CMD);
                DispatchResult::Continue
            }
        }
    }

    // ── I3C TTI low-level helpers ──────────────────────────────────────

    /// Send a status-only response (1 byte) via IBI.
    fn send_status(&self, status: u8) {
        self.send_ibi_with_payload(&[status]);
    }

    /// Send a response with status byte followed by data via IBI.
    fn send_response(&self, status: u8, data: &[u8]) {
        let mut buf = [0u8; 64];
        buf[0] = status;
        let copy_len = data.len().min(buf.len() - 1);
        let mut i = 0;
        while i < copy_len {
            buf[i + 1] = data[i];
            i += 1;
        }
        self.send_ibi_with_payload(&buf[..1 + copy_len]);
    }

    /// Send an IBI with MDB and inline payload data.
    fn send_ibi_with_payload(&self, data: &[u8]) {
        let regs = self.registers;

        let ibi_desc = ((MDB_SERVICES as u32) << 24) | (data.len() as u32);
        regs.tti_tti_ibi_port.set(ibi_desc);

        // Write payload 4 bytes at a time
        let words = data.len().div_ceil(4);
        let mut i = 0;
        while i < words {
            let base = i * 4;
            let mut word = 0u32;
            let mut j = 0;
            while j < 4 {
                if base + j < data.len() {
                    word |= (data[base + j] as u32) << (j * 8);
                }
                j += 1;
            }
            regs.tti_tti_ibi_port.set(word);
            i += 1;
        }

        for _ in 0..MAX_IBI_POLL_ITERATIONS {
            if regs
                .tti_interrupt_status
                .extract()
                .is_set(InterruptStatus::IbiDone)
            {
                // Read LastIbiStatus to clear the IbiDone interrupt.
                let _ = regs.tti_status.read(Status::LastIbiStatus);
                break;
            }
        }
    }

    /// Send an IBI with a short timeout; if the controller does not
    /// acknowledge it, reset the IBI queue to prevent the pending IBI
    /// from blocking the target FSM (which would prevent TTI RX).
    fn send_ibi_with_abort(&self, data: &[u8]) {
        let regs = self.registers;

        let ibi_desc = ((MDB_SERVICES as u32) << 24) | (data.len() as u32);
        regs.tti_tti_ibi_port.set(ibi_desc);

        let words = data.len().div_ceil(4);
        let mut i = 0;
        while i < words {
            let base = i * 4;
            let mut word = 0u32;
            let mut j = 0;
            while j < 4 {
                if base + j < data.len() {
                    word |= (data[base + j] as u32) << (j * 8);
                }
                j += 1;
            }
            regs.tti_tti_ibi_port.set(word);
            i += 1;
        }

        for _ in 0..AWAITING_IBI_POLL_ITERATIONS {
            if regs
                .tti_interrupt_status
                .extract()
                .is_set(InterruptStatus::IbiDone)
            {
                let _ = regs.tti_status.read(Status::LastIbiStatus);
                return;
            }
        }

        // IBI was not acknowledged — flush the IBI queue so the pending
        // entry does not keep the target FSM in DoIBI state.
        regs.tti_tti_reset_control
            .write(TtiResetControl::IbiQueueRst::SET);
    }

    /// Try to read a command from the I3C RX queue.
    /// Returns `Some((cmd_byte, word_buffer, data_len))` if a command arrived.
    fn try_receive_command(&self) -> Option<(u8, [u32; MAX_RX_WORDS], usize)> {
        let regs = self.registers;

        // Read RX descriptor to get data length. If the queue is empty the
        // descriptor reads as 0.
        let rx_desc = regs.tti_rx_desc_queue_port.get();
        let data_len = (rx_desc & 0xFFFF) as usize;

        if data_len == 0 {
            return None;
        }

        let mut buf = [0u32; MAX_RX_WORDS];
        let words = data_len.div_ceil(4);
        let mut i = 0;
        while i < words && i < MAX_RX_WORDS {
            buf[i] = regs.tti_rx_data_port.get();
            i += 1;
        }

        let cmd = (buf[0] & 0xFF) as u8;
        Some((cmd, buf, data_len))
    }

    /// Returns the enabled service modes.
    #[allow(dead_code)]
    pub fn services(&self) -> crate::I3cServicesModes {
        self.services
    }
}

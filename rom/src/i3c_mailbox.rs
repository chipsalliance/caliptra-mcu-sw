// Licensed under the Apache-2.0 license

use caliptra_mcu_error::McuError;
use caliptra_mcu_registers_generated::i3c;
use caliptra_mcu_registers_generated::i3c::bits::{InterruptStatus, Status, TtiResetControl};
use caliptra_mcu_romtime::StaticRef;
use tock_registers::interfaces::{Readable, Writeable};

/// I3C Mandatory Data Byte for service IBI notifications.
const MDB_SERVICES: u8 = 0x1F;

/// Built-in command IDs.
const CMD_PING: u8 = 0x00;
const CMD_DOT_STATUS: u8 = 0x01;
const CMD_DOT_RECOVERY: u8 = 0x02;
const CMD_DOT_UNLOCK_CHALLENGE: u8 = 0x03;
const CMD_DOT_OVERRIDE: u8 = 0x04;

/// Status codes.
const STATUS_SUCCESS: u8 = 0x00;
const STATUS_INVALID_CMD: u8 = 0x01;
const STATUS_INVALID_PAYLOAD: u8 = 0x02;
const STATUS_ERROR: u8 = 0x03;
const STATUS_AWAITING: u8 = 0x80;

/// Maximum number of poll iterations before giving up.
/// At ~200 MHz AXI clock this gives roughly 5 seconds of polling.
const MAX_POLL_ITERATIONS: u32 = 200_000_000;

/// Maximum number of poll iterations for the initial STATUS_AWAITING IBI.
/// Shorter than the normal IBI timeout since the controller may not be
/// ready yet. At ~200 MHz this gives roughly 50ms.
const AWAITING_IBI_POLL_ITERATIONS: u32 = 10_000_000;

/// Maximum RX data words for a single I3C private write (limited by TTI FIFO).
const MAX_RX_WORDS: usize = 64;

/// Packet header size: [cmd, payload_len, seq_num, total_seqs].
const PACKET_HEADER_SIZE: usize = 4;

// Maximum payload bytes per packet: 248. The TTI RX FIFO is 256 bytes
// (64 DWORDs). The on-wire size includes a 4-byte header, payload, and
// 1-byte PEC (CRC-8/SMBus). The chunk must be 4-byte aligned for u32
// word reassembly. 256 - 4 - 1 = 251, aligned → 248.

/// Maximum reassembled command payload (covers DOT_OVERRIDE at 7412 bytes).
pub const MAX_REASSEMBLY_BYTES: usize = 8192;

/// Maximum reassembly buffer size in u32 words.
pub const MAX_REASSEMBLY_WORDS: usize = MAX_REASSEMBLY_BYTES / 4;

/// "PONG" response payload (ASCII, little-endian u32).
const PONG_PAYLOAD: [u8; 4] = *b"PONG";

/// ECC P-384 public key size: two 48-byte coordinates.
const ECC_P384_PUB_KEY_SIZE: usize = 96;
/// ECC P-384 signature size: r (48 bytes) + s (48 bytes).
const ECC_P384_SIGNATURE_SIZE: usize = 96;

/// Result from dispatching a single command.
enum DispatchResult {
    /// Command handled; continue processing.
    Continue,
    /// Handler requests the mailbox loop to exit normally (e.g., after reset).
    Done,
}

/// DOT context passed to the I3C handler for DOT command processing.
///
/// Holds split borrows of individual ROM environment fields rather than
/// `&mut RomEnv`, so that `enter_i3c_services` can independently borrow
/// `&Mci` for boot-status checkpoints without creating a duplicate handle.
pub struct DotContext<'a> {
    pub soc_manager: &'a mut caliptra_mcu_romtime::CaliptraSoC,
    pub mci: &'a caliptra_mcu_romtime::Mci,
    pub otp: &'a crate::Otp,
    pub dot_fuses: &'a crate::DotFuses,
    pub dot_flash: &'a dyn crate::hil::FlashStorage,
    pub key_type: caliptra_api::mailbox::CmStableKeyType,
}

/// Tracks state for the multi-message DOT_OVERRIDE challenge/response flow.
enum OverrideState {
    /// No override in progress.
    Idle,
    /// Challenge has been sent; waiting for DOT_OVERRIDE response.
    /// Stores the 48-byte challenge so we can verify the signed response.
    ChallengeSent { challenge: [u8; 48] },
}

/// Generic I3C mailbox handler.
///
/// The I3C peripheral must already be configured (via `I3c::configure()`)
/// before constructing this handler.
pub struct I3cMailboxHandler<'a> {
    registers: StaticRef<i3c::regs::I3c>,
    services: crate::I3cServicesModes,
    /// I3C target address for PEC computation. Uses the dynamic address
    /// assigned by the controller (via ENTDAA/SETDASA), falling back to
    /// the static address if no dynamic address has been assigned.
    pec_addr: u8,
    dot_ctx: Option<DotContext<'a>>,
    override_state: OverrideState,
    /// Word-aligned reassembly buffer (backed by MCI mailbox SRAM).
    reassembly_buf: &'a mut [u32],
    /// Number of payload bytes accumulated so far.
    reassembly_len: usize,
    reassembly_cmd: u8,
    reassembly_total: u8,
    reassembly_next_seq: u8,
}

impl<'a> I3cMailboxHandler<'a> {
    pub fn new(
        registers: StaticRef<i3c::regs::I3c>,
        services: crate::I3cServicesModes,
        target_addr: u8,
        dot_ctx: Option<DotContext<'a>>,
        reassembly_buf: &'a mut [u32],
    ) -> Self {
        use caliptra_mcu_registers_generated::i3c::bits::StbyCrDeviceAddr;
        // Prefer the dynamic address assigned by the controller; fall back
        // to the caller-provided static address.
        let dev_addr = registers.stdby_ctrl_mode_stby_cr_device_addr.extract();
        let pec_addr = if dev_addr.is_set(StbyCrDeviceAddr::DynamicAddrValid) {
            dev_addr.read(StbyCrDeviceAddr::DynamicAddr) as u8
        } else {
            target_addr
        };
        Self {
            registers,
            services,
            pec_addr,
            dot_ctx,
            override_state: OverrideState::Idle,
            reassembly_buf,
            reassembly_len: 0,
            reassembly_cmd: 0,
            reassembly_total: 0,
            reassembly_next_seq: 0,
        }
    }

    /// Run the mailbox processing loop until completion or timeout.
    ///
    /// `on_ready` is invoked after the IBI announcement completes and the
    /// handler is ready to accept commands. Callers typically use it to set
    /// an MCI boot status checkpoint.
    pub fn run(&mut self, on_ready: impl FnOnce()) -> Result<(), McuError> {
        // Announce readiness via IBI. Use a short timeout since the I3C
        // controller may not be ready to acknowledge IBIs yet (e.g. on FPGA
        // it re-enumerates the bus after recovery). If the IBI doesn't
        // complete, reset the IBI queue to abort it — a pending IBI in the
        // queue causes the I3C target FSM to stay in DoIBI state and ignore
        // incoming private writes (i3c-core: i3c_target_fsm.sv line 565).
        self.send_ibi_with_abort(&[STATUS_AWAITING]);

        on_ready();

        caliptra_mcu_romtime::println!("[mcu-rom-i3c-svc] Ready for commands");

        for _ in 0..MAX_POLL_ITERATIONS {
            if let Some((cmd, payload_len)) = self.try_receive_reassembled_command() {
                match self.dispatch(cmd, payload_len) {
                    DispatchResult::Continue => {}
                    DispatchResult::Done => return Ok(()),
                }
            }
        }

        caliptra_mcu_romtime::println!("[mcu-rom-i3c-svc] I3C services timed out");
        Err(McuError::ROM_COLD_BOOT_DOT_ERROR)
    }

    /// Check whether DOT commands are available.
    fn dot_enabled(&self) -> bool {
        self.services
            .contains(crate::I3cServicesModes::DOT_RECOVERY)
            && self.dot_ctx.is_some()
    }

    /// Dispatch a reassembled command. `payload_len` is the number of valid
    /// bytes in the static reassembly buffer.
    fn dispatch(&mut self, cmd: u8, payload_len: usize) -> DispatchResult {
        match cmd {
            CMD_PING => {
                caliptra_mcu_romtime::println!("[mcu-rom-i3c-svc] PING received");
                self.send_response(STATUS_SUCCESS, &PONG_PAYLOAD);
                DispatchResult::Continue
            }
            CMD_DOT_STATUS if self.dot_enabled() => self.handle_dot_status(),
            CMD_DOT_RECOVERY if self.dot_enabled() => self.handle_dot_recovery(payload_len),
            CMD_DOT_UNLOCK_CHALLENGE if self.dot_enabled() => {
                self.handle_dot_unlock_challenge(payload_len)
            }
            CMD_DOT_OVERRIDE if self.dot_enabled() => self.handle_dot_override(payload_len),
            _ => {
                caliptra_mcu_romtime::println!("[mcu-rom-i3c-svc] Unknown command: {:#x}", cmd);
                self.send_status(STATUS_INVALID_CMD);
                DispatchResult::Continue
            }
        }
    }

    // ── DOT command handlers ──────────────────────────────────────────

    /// Handle DOT_STATUS: return current DOT fuse state.
    fn handle_dot_status(&mut self) -> DispatchResult {
        caliptra_mcu_romtime::println!("[mcu-rom-i3c-svc] DOT_STATUS received");
        let ctx = self.dot_ctx.as_ref().unwrap();
        // Response: [status, enabled, locked, burned_lo, burned_hi]
        let enabled = ctx.dot_fuses.enabled as u8;
        let locked = ctx.dot_fuses.is_locked() as u8;
        let burned_le = ctx.dot_fuses.burned.to_le_bytes();
        self.send_response(
            STATUS_SUCCESS,
            &[enabled, locked, burned_le[0], burned_le[1]],
        );
        DispatchResult::Continue
    }

    /// Handle DOT_RECOVERY: receive backup blob and run recovery flow.
    fn handle_dot_recovery(&mut self, payload_len: usize) -> DispatchResult {
        caliptra_mcu_romtime::println!("[mcu-rom-i3c-svc] DOT_RECOVERY received");

        let blob_size = crate::DOT_BLOB_SIZE;
        if payload_len < blob_size {
            caliptra_mcu_romtime::println!(
                "[mcu-rom-i3c-svc] DOT_RECOVERY payload too small: {} < {}",
                payload_len,
                blob_size
            );
            self.send_status(STATUS_INVALID_PAYLOAD);
            return DispatchResult::Continue;
        }

        let mut blob_bytes = [0u8; crate::DOT_BLOB_SIZE];
        read_bytes_from_words(self.reassembly_buf, 0, &mut blob_bytes);

        let result = {
            let ctx = self.dot_ctx.as_mut().unwrap();
            let key_type = ctx.key_type;
            crate::device_ownership_transfer::verify_and_write_recovery_blob(
                ctx.soc_manager,
                ctx.dot_fuses,
                &blob_bytes,
                ctx.dot_flash,
                key_type,
            )
        };

        match result {
            Ok(()) => {
                caliptra_mcu_romtime::println!(
                    "[mcu-rom-i3c-svc] DOT_RECOVERY succeeded, triggering reset"
                );
                self.send_status(STATUS_SUCCESS);
                let ctx = self.dot_ctx.as_ref().unwrap();
                ctx.mci.trigger_warm_reset();
                return DispatchResult::Done;
            }
            Err(err) => {
                caliptra_mcu_romtime::println!(
                    "[mcu-rom-i3c-svc] DOT_RECOVERY failed: {}",
                    caliptra_mcu_romtime::HexWord(err.into())
                );
                self.send_status(STATUS_ERROR);
            }
        }
        DispatchResult::Continue
    }

    /// Handle DOT_UNLOCK_CHALLENGE: start override by receiving vendor PK and
    /// generating a challenge.
    ///
    /// Payload: ECC P-384 PK (96 bytes) + MLDSA-87 PK (2592 bytes) = 2688 bytes
    fn handle_dot_unlock_challenge(&mut self, payload_len: usize) -> DispatchResult {
        caliptra_mcu_romtime::println!("[mcu-rom-i3c-svc] DOT_UNLOCK_CHALLENGE received");

        let expected_payload = 96 + crate::MLDSA87_PUB_KEY_SIZE_DWORDS * 4;
        if payload_len < expected_payload {
            caliptra_mcu_romtime::println!(
                "[mcu-rom-i3c-svc] DOT_UNLOCK_CHALLENGE payload too small: {} < {}",
                payload_len,
                expected_payload
            );
            self.send_status(STATUS_INVALID_PAYLOAD);
            return DispatchResult::Continue;
        }

        // ECC public key (all offsets are word-aligned)
        let mut ecc_x = [0u32; 12];
        let mut ecc_y = [0u32; 12];
        read_words(self.reassembly_buf, 0, &mut ecc_x);
        read_words(self.reassembly_buf, 12, &mut ecc_y);

        // MLDSA public key
        let mut mldsa_pub_key = [0u32; crate::MLDSA87_PUB_KEY_SIZE_DWORDS];
        read_words(self.reassembly_buf, 24, &mut mldsa_pub_key);

        let ctx = self.dot_ctx.as_mut().unwrap();

        // Verify device is in locked state
        if !ctx.dot_fuses.is_locked() {
            caliptra_mcu_romtime::println!(
                "[mcu-rom-i3c-svc] DOT_UNLOCK_CHALLENGE: device not locked"
            );
            self.send_status(STATUS_ERROR);
            return DispatchResult::Continue;
        }

        let recovery_pk_hash = match ctx.dot_fuses.recovery_pk_hash.as_ref() {
            Some(hash) => hash,
            None => {
                caliptra_mcu_romtime::println!(
                    "[mcu-rom-i3c-svc] No vendor recovery PK hash in OTP"
                );
                self.send_status(STATUS_ERROR);
                return DispatchResult::Continue;
            }
        };

        let ecc_key = crate::EccP384PublicKey { x: ecc_x, y: ecc_y };
        let ecc_key_u32 = crate::device_ownership_transfer::ecc_key_as_u32_slice(&ecc_key);

        let computed_hash = match crate::device_ownership_transfer::cm_sha384(
            ctx.soc_manager,
            &[ecc_key_u32, &mldsa_pub_key],
        ) {
            Ok(h) => h,
            Err(err) => {
                caliptra_mcu_romtime::println!(
                    "[mcu-rom-i3c-svc] PK hash computation failed: {}",
                    caliptra_mcu_romtime::HexWord(err.into())
                );
                self.send_status(STATUS_ERROR);
                return DispatchResult::Continue;
            }
        };

        let fuse_hash_bytes: [u8; 48] = zerocopy::transmute!(recovery_pk_hash.0);
        if !constant_time_eq::constant_time_eq(&computed_hash, &fuse_hash_bytes) {
            caliptra_mcu_romtime::println!("[mcu-rom-i3c-svc] Vendor recovery PK hash mismatch");
            self.send_status(STATUS_ERROR);
            return DispatchResult::Continue;
        }
        caliptra_mcu_romtime::println!("[mcu-rom-i3c-svc] Vendor PK hash verified");

        // Generate random challenge
        let challenge = match crate::device_ownership_transfer::cm_random_generate(ctx.soc_manager)
        {
            Ok(c) => c,
            Err(err) => {
                caliptra_mcu_romtime::println!(
                    "[mcu-rom-i3c-svc] Challenge generation failed: {}",
                    caliptra_mcu_romtime::HexWord(err.into())
                );
                self.send_status(STATUS_ERROR);
                return DispatchResult::Continue;
            }
        };

        // Release mutable borrow before calling self.send_response

        // Send challenge as response
        self.send_response(STATUS_SUCCESS, &challenge);
        self.override_state = OverrideState::ChallengeSent { challenge };
        caliptra_mcu_romtime::println!(
            "[mcu-rom-i3c-svc] Challenge sent, waiting for DOT_OVERRIDE: {}",
            caliptra_mcu_romtime::HexBytes(&challenge),
        );
        DispatchResult::Continue
    }

    /// Handle DOT_OVERRIDE: receive signed challenge response and complete override.
    ///
    /// Payload:
    ///   bytes 0..95:    ECC P-384 public key (x: 48, y: 48)
    ///   bytes 96..191:  ECC signature (r: 48, s: 48)
    ///   bytes 192..2783: MLDSA-87 public key (2592 bytes)
    ///   bytes 2784..7411: MLDSA-87 signature (4628 bytes)
    fn handle_dot_override(&mut self, payload_len: usize) -> DispatchResult {
        caliptra_mcu_romtime::println!("[mcu-rom-i3c-svc] DOT_OVERRIDE received");

        // Verify we're in the correct state
        let challenge = match &self.override_state {
            OverrideState::ChallengeSent { challenge } => *challenge,
            OverrideState::Idle => {
                caliptra_mcu_romtime::println!(
                    "[mcu-rom-i3c-svc] DOT_OVERRIDE without prior challenge"
                );
                self.send_status(STATUS_ERROR);
                return DispatchResult::Continue;
            }
        };

        // Reset override state
        self.override_state = OverrideState::Idle;

        let expected_payload = ECC_P384_PUB_KEY_SIZE
            + ECC_P384_SIGNATURE_SIZE
            + crate::MLDSA87_PUB_KEY_SIZE_DWORDS * 4
            + crate::MLDSA87_SIGNATURE_SIZE_DWORDS * 4;
        if payload_len < expected_payload {
            caliptra_mcu_romtime::println!(
                "[mcu-rom-i3c-svc] DOT_OVERRIDE payload too small: {} < {}",
                payload_len,
                expected_payload
            );
            self.send_status(STATUS_INVALID_PAYLOAD);
            return DispatchResult::Continue;
        }

        let payload = &self.reassembly_buf;
        let mut woff = 0usize; // word offset

        // ECC PK
        let mut ecc_x = [0u32; 12];
        let mut ecc_y = [0u32; 12];
        read_words(payload, woff, &mut ecc_x);
        woff += 12;
        read_words(payload, woff, &mut ecc_y);
        woff += 12;

        // ECC signature (read as bytes from word-aligned data)
        let mut ecc_sig_r = [0u8; 48];
        let mut ecc_sig_s = [0u8; 48];
        read_bytes_from_words(payload, woff * 4, &mut ecc_sig_r);
        woff += 12;
        read_bytes_from_words(payload, woff * 4, &mut ecc_sig_s);
        woff += 12;

        // MLDSA PK
        let mut mldsa_pub_key = [0u32; crate::MLDSA87_PUB_KEY_SIZE_DWORDS];
        read_words(payload, woff, &mut mldsa_pub_key);
        woff += crate::MLDSA87_PUB_KEY_SIZE_DWORDS;

        // MLDSA signature
        let mut mldsa_signature = [0u32; crate::MLDSA87_SIGNATURE_SIZE_DWORDS];
        read_words(payload, woff, &mut mldsa_signature);

        let ctx = self.dot_ctx.as_mut().unwrap();

        let recovery_pk_hash = match ctx.dot_fuses.recovery_pk_hash.as_ref() {
            Some(hash) => hash,
            None => {
                self.send_status(STATUS_ERROR);
                return DispatchResult::Continue;
            }
        };

        let ecc_key = crate::EccP384PublicKey { x: ecc_x, y: ecc_y };
        let auth = crate::device_ownership_transfer::OverrideAuth {
            ecc_key: &ecc_key,
            ecc_sig_r: &ecc_sig_r,
            ecc_sig_s: &ecc_sig_s,
            mldsa_pub_key: &mldsa_pub_key,
            mldsa_signature: &mldsa_signature,
            challenge: &challenge,
        };

        if crate::device_ownership_transfer::verify_override_response(
            ctx.soc_manager,
            recovery_pk_hash,
            &auth,
        )
        .is_err()
        {
            self.send_status(STATUS_ERROR);
            return DispatchResult::Continue;
        }

        caliptra_mcu_romtime::println!("[mcu-rom-i3c-svc] Both signatures verified");

        let key_type = ctx.key_type;
        if crate::device_ownership_transfer::apply_override(
            ctx.soc_manager,
            ctx.otp,
            ctx.dot_fuses,
            ctx.dot_flash,
            key_type,
        )
        .is_err()
        {
            caliptra_mcu_romtime::println!("[mcu-rom-i3c-svc] Failed to apply DOT override");
            self.send_status(STATUS_ERROR);
            return DispatchResult::Continue;
        }

        caliptra_mcu_romtime::println!("[mcu-rom-i3c-svc] DOT override complete, triggering reset");
        self.send_status(STATUS_SUCCESS);
        let ctx = self.dot_ctx.as_ref().unwrap();
        ctx.mci.trigger_warm_reset();
        DispatchResult::Done
    }

    // ── I3C TTI low-level helpers ──────────────────────────────────────

    /// Send a status-only response (1 byte) via TX (private read).
    fn send_status(&self, status: u8) {
        self.send_tx_response(&[status]);
    }

    /// Send a response with status byte followed by data via TX (private read).
    fn send_response(&self, status: u8, data: &[u8]) {
        let mut buf = [0u8; 64];
        buf[0] = status;
        let copy_len = data.len().min(buf.len() - 1);
        let mut i = 0;
        while i < copy_len {
            buf[i + 1] = data[i];
            i += 1;
        }
        self.send_tx_response(&buf[..1 + copy_len]);
    }

    /// Queue a response for the BMC to read via a private read transaction.
    /// Writes a TX descriptor (creating the buffer), then fills it with data
    /// words followed by a PEC (CRC-8/SMBus) byte. The I3C controller holds
    /// this data until the BMC issues a private read.
    fn send_tx_response(&self, data: &[u8]) {
        let regs = self.registers;

        // Compute PEC over the read address byte and payload, matching the
        // MCTP-over-I3C transport binding (transport_binding.rs).
        let addr_byte = (self.pec_addr << 1) | 1; // R/W bit = 1 for read
        let mut crc = 0u8;
        crc = caliptra_mcu_romtime::crc8(crc, addr_byte);
        let mut k = 0;
        while k < data.len() {
            crc = caliptra_mcu_romtime::crc8(crc, data[k]);
            k += 1;
        }

        let total_len = data.len() + 1; // data + PEC byte

        // Write TX descriptor first (creates the data buffer in the controller)
        regs.tti_tx_desc_queue_port.set(total_len as u32);

        // Write data + PEC as words
        let words = total_len.div_ceil(4);
        let mut i = 0;
        while i < words {
            let base = i * 4;
            let mut word = 0u32;
            let mut j = 0;
            // if-chain avoids match/cmp which prevents LLVM from eliding the bounds check
            #[allow(clippy::comparison_chain)]
            while j < 4 {
                let pos = base + j;
                let byte = if pos < data.len() {
                    data.get(pos).copied().unwrap_or(0)
                } else if pos == data.len() {
                    crc
                } else {
                    0
                };
                word |= (byte as u32) << (j * 8);
                j += 1;
            }
            regs.tti_tx_data_port.set(word);
            i += 1;
        }
    }

    /// Send an IBI with a short timeout; if the controller does not
    /// acknowledge it, reset the target core to force the FSM out of the
    /// DoIBI state (the RTL ties `ibi_abort_i` to 0, so only a soft
    /// reset can recover the FSM once an IBI gets stuck).
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

        // IBI was not acknowledged — hold the IBI queue in reset so
        // the pending entry is cleared and no retries are attempted.
        // These TTI reset bits are persistent ("hold-in-reset"), not
        // self-clearing, so the IBI queue stays disabled for the
        // remainder of the services loop.
        caliptra_mcu_romtime::println!(
            "[mcu-rom-i3c-svc] IBI not acknowledged, flushing IBI queue"
        );
        regs.tti_tti_reset_control
            .write(TtiResetControl::IbiQueueRst::SET + TtiResetControl::IbiRetryCtrRst::SET);
    }

    /// Try to receive and reassemble a complete command from packetized
    /// I3C private writes. Returns `Some((cmd, payload_len))` when all
    /// packets have arrived. The payload data is in the static `REASSEMBLY_BUF`.
    ///
    /// Packet format: `[cmd, payload_len, seq_num, total_seqs, payload...]`
    fn try_receive_reassembled_command(&mut self) -> Option<(u8, usize)> {
        let regs = self.registers;

        // Reading the descriptor queue port when empty returns 0 on real
        // hardware (I3C core read_queue.sv). We rely on the data_len check
        // below to discard empty reads rather than checking RxDescStat,
        // because RxDescStat is edge-triggered (set on write, cleared on
        // read) and would miss batched descriptors.
        let rx_desc = regs.tti_rx_desc_queue_port.get();
        let data_len = (rx_desc & 0xFFFF) as usize;
        if data_len < PACKET_HEADER_SIZE {
            return None;
        }

        // Read all words from the RX FIFO
        let total_words = data_len.div_ceil(4);
        let read_words = total_words.min(MAX_RX_WORDS);
        let mut buf = [0u32; MAX_RX_WORDS];
        let mut i = 0;
        while i < read_words {
            buf[i] = regs.tti_rx_data_port.get();
            i += 1;
        }

        // Parse the 4-byte packet header
        let first_word = buf[0].to_le_bytes();
        let cmd = first_word[0];
        let pkt_payload_len = first_word[1] as usize;
        let seq_num = first_word[2];
        let total_seqs = first_word[3];

        if total_seqs == 0 {
            return None;
        }

        caliptra_mcu_romtime::println!(
            "[mcu-rom-i3c-svc] Packet: cmd=0x{:02x} len={} seq={}/{} data_len={}",
            cmd,
            pkt_payload_len,
            seq_num,
            total_seqs,
            data_len,
        );
        // Validate the packet payload length against what arrived
        let actual_payload = data_len.saturating_sub(PACKET_HEADER_SIZE);
        let copy_bytes = actual_payload.min(pkt_payload_len);
        // Number of whole payload words to copy from buf[1..]
        let copy_words = copy_bytes.div_ceil(4);
        let buf_capacity = self.reassembly_buf.len() * 4; // in bytes

        if total_seqs == 1 {
            self.reassembly_len = copy_bytes.min(buf_capacity);
            copy_payload_words(&buf, 1, self.reassembly_buf, 0, copy_words);
            return Some((cmd, self.reassembly_len));
        }

        // Multi-packet: validate sequence
        if seq_num == 0 {
            self.reassembly_cmd = cmd;
            self.reassembly_total = total_seqs;
            self.reassembly_next_seq = 1;
            self.reassembly_len = copy_bytes.min(buf_capacity);
            copy_payload_words(&buf, 1, self.reassembly_buf, 0, copy_words);
        } else if seq_num == self.reassembly_next_seq
            && cmd == self.reassembly_cmd
            && total_seqs == self.reassembly_total
        {
            let space = buf_capacity.saturating_sub(self.reassembly_len);
            let n_bytes = copy_bytes.min(space);
            let n_words = n_bytes.div_ceil(4);
            let dst_word = self.reassembly_len / 4;
            copy_payload_words(&buf, 1, self.reassembly_buf, dst_word, n_words);
            self.reassembly_len += n_bytes;
            self.reassembly_next_seq += 1;
        } else {
            caliptra_mcu_romtime::println!(
                "[mcu-rom-i3c-svc] Packet seq mismatch: got {}/{}, expected {}/{}",
                seq_num,
                total_seqs,
                self.reassembly_next_seq,
                self.reassembly_total,
            );
            self.reassembly_len = 0;
            self.reassembly_next_seq = 0;
            self.reassembly_total = 0;
            return None;
        }

        if self.reassembly_next_seq == self.reassembly_total {
            let len = self.reassembly_len;
            let cmd = self.reassembly_cmd;
            self.reassembly_next_seq = 0;
            self.reassembly_total = 0;
            Some((cmd, len))
        } else {
            None
        }
    }

    /// Returns the enabled service modes.
    #[allow(dead_code)]
    pub fn services(&self) -> crate::I3cServicesModes {
        self.services
    }
}

/// Copy u32 words from the RX FIFO buffer into the reassembly buffer.
fn copy_payload_words(
    src: &[u32; MAX_RX_WORDS],
    src_word_start: usize,
    dst: &mut [u32],
    dst_word_start: usize,
    word_count: usize,
) {
    let mut i = 0;
    while i < word_count {
        let si = src_word_start + i;
        let di = dst_word_start + i;
        if si < MAX_RX_WORDS && di < dst.len() {
            dst[di] = src[si];
        }
        i += 1;
    }
}

/// Copy u32 words from the reassembly buffer into a destination u32 slice.
fn read_words(src: &[u32], src_word_offset: usize, dst: &mut [u32]) {
    let mut i = 0;
    while i < dst.len() {
        let si = src_word_offset + i;
        dst[i] = if si < src.len() { src[si] } else { 0 };
        i += 1;
    }
}

/// Read bytes from a u32-word buffer at a given byte offset.
fn read_bytes_from_words(src: &[u32], byte_offset: usize, dst: &mut [u8]) {
    let mut i = 0;
    while i < dst.len() {
        let pos = byte_offset + i;
        let word_idx = pos / 4;
        let byte_idx = pos % 4;
        let w = if word_idx < src.len() {
            src[word_idx]
        } else {
            0
        };
        dst[i] = ((w >> (byte_idx * 8)) & 0xFF) as u8;
        i += 1;
    }
}

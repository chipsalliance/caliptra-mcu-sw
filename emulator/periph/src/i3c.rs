/*++
Licensed under the Apache-2.0 license.
File Name:
    i3c.rs
Abstract:
    File contains I3C peripheral implementation.
--*/

use crate::i3c_protocol::I3cController;
use crate::{I3cIncomingCommandClient, I3cTarget};
use caliptra_emu_bus::{Clock, ReadWriteRegister, Timer};
use caliptra_emu_bus::{Device, Event, EventData};
use caliptra_emu_cpu::Irq;
use caliptra_emu_types::RvData;
use caliptra_mcu_emulator_registers_generated::i3c::{I3cGenerated, I3cPeripheral};
use caliptra_mcu_registers_generated::i3c::bits::{
    DeviceReset, DeviceStatus0, ExtcapHeader, IndirectFifoCtrl0, IndirectFifoStatus0,
    InterruptEnable, InterruptForce, InterruptStatus, RecIntfCfg, RecoveryCtrl, Status,
    StbyCrCapabilities, StbyCrDeviceAddr, TtiQueueSize,
};
use caliptra_mcu_testing_common::i3c::{
    DynamicI3cAddress, I3cTcriCommand, I3cTcriCommandXfer, I3cTcriResponseXfer, IbiDescriptor,
    ResponseDescriptor,
};
use semver::Version;
use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use zerocopy::FromBytes;

/// Recovery-path tracing, off by default to keep regression logs quiet. Set
/// `CALIPTRA_MCU_EMULATOR_I3C_LOG=1` to make a bring-up against an external
/// Recovery Initiator self-diagnosing; `0`, `false` and the empty string keep
/// it silent.
fn i3c_log_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("CALIPTRA_MCU_EMULATOR_I3C_LOG")
            .map(|value| !matches!(value.trim(), "" | "0" | "false"))
            .unwrap_or(false)
    })
}

macro_rules! i3c_log {
    ($($arg:tt)*) => {
        if crate::i3c::i3c_log_enabled() {
            println!("[I3C-Emulator] {}", format_args!($($arg)*));
        }
    };
}

/// First bytes of a transfer, for tracing.
fn head(data: &[u8]) -> String {
    let shown = data.len().min(8);
    let mut text = data[..shown]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    if data.len() > shown {
        text.push_str(" ..");
    }
    text
}

const I3C_REC_INT_BYPASS_I3C_CORE: u32 = 0x0;
const I3C_REC_INT_BYPASS_AXI_DIRECT: u32 = 0x1;

/// `DEVICE_STATUS_0.PROT_ERROR` codes from the OCP recovery specification.
const PROT_ERROR_UNSUPPORTED: u32 = 0x1;
const PROT_ERROR_LENGTH: u32 = 0x3;
const PROT_ERROR_CRC: u32 = 0x4;

/// Depth of the indirect FIFO in DWORDs, advertised through
/// `INDIRECT_FIFO_STATUS_3` and used to derive the FULL flag.
///
/// An initiator sizes its `INDIRECT_FIFO_DATA` writes from this and wraps each
/// chunk in the block-write framing (command code, two length bytes and a
/// trailing PEC), so a full-depth chunk occupies `depth * 4 + 4` bytes on the
/// wire. That is deliberately not clamped to any particular controller's
/// transfer limit: the FIFO depth is a property of this device, and a host
/// controller that cannot carry the resulting transfer needs fixing on its own
/// side rather than being papered over by understating the depth here.
const INDIRECT_FIFO_SIZE_DWORDS: u32 = 0x40;

/// Largest single transfer the initiator should attempt, in DWORDs
/// (`INDIRECT_FIFO_STATUS_4`). The whole FIFO can be filled in one transfer.
const INDIRECT_FIFO_MAX_TRANSFER_DWORDS: u32 = INDIRECT_FIFO_SIZE_DWORDS;

/// Saturating counters mirroring the recovery handler's `TARGET_ERR_CNT_RI_*`
/// registers, which this register map does not expose.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub struct RecoveryErrorCounters {
    pub pec: u32,
    pub length: u32,
    pub read_only: u32,
    pub unsupported: u32,
    pub indirect_fifo_overflow: u32,
}

/// CSRs the Recovery Initiator is allowed to write over I3C. Everything else is
/// device owned, and a write to it is reported as an unsupported command.
fn recovery_block_writeable(command_code: u8) -> bool {
    matches!(command_code, 37 | 38 | 45 | 47)
}

/// CRC-8 over C(x) = x^8 + x^2 + x + 1, the PEC polynomial from the MCTP I3C
/// binding that every recovery transfer carries.
fn crc8_pec(data: &[u8]) -> u8 {
    let mut crc = 0u8;
    for byte in data {
        crc ^= byte;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 {
                (crc << 1) ^ 0x07
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Address byte as it appears on the bus: the 7-bit target address shifted up
/// with the R/nW bit in bit 0.
fn wire_address_byte(address: u8, read: bool) -> u8 {
    (address << 1) | u8::from(read)
}

/// PEC for the command byte that opens a block read, covering the write address
/// phase and the command code.
fn recovery_command_pec(address: u8, command_code: u8) -> u8 {
    crc8_pec(&[wire_address_byte(address, false), command_code])
}

/// PEC for a block write: write address phase, CMD, 16-bit length, payload.
///
/// The CRC is seeded with the address byte because these transfers inherit
/// SMBus framing, where the PEC covers every byte the controller drives
/// including the address phase. Computing it over the payload alone yields a
/// value no real initiator will agree with.
fn recovery_write_pec(address: u8, command_code: u8, payload: &[u8]) -> u8 {
    let mut framed = Vec::with_capacity(payload.len() + 4);
    framed.push(wire_address_byte(address, false));
    framed.push(command_code);
    framed.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    framed.extend_from_slice(payload);
    crc8_pec(&framed)
}

/// PEC for the data phase of a block read. A block read is addressed twice: the
/// command is written, then a repeated start turns the bus around, so both
/// address bytes are covered along with the 16-bit length and the payload.
fn recovery_read_pec(address: u8, command_code: u8, payload: &[u8]) -> u8 {
    let mut framed = Vec::with_capacity(payload.len() + 5);
    framed.push(wire_address_byte(address, false));
    framed.push(command_code);
    framed.push(wire_address_byte(address, true));
    framed.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    framed.extend_from_slice(payload);
    crc8_pec(&framed)
}

/// Offset of INDIRECT_FIFO_DATA, which is a FIFO port rather than an array:
/// every word of a block transfer is written to (or read from) this one address.
const RECOVERY_INDIRECT_FIFO_DATA_OFFSET: u32 = 0x068;

/// Name of an OCP recovery command code, for tracing.
fn recovery_command_name(command_code: u8) -> &'static str {
    match command_code {
        34 => "PROT_CAP",
        35 => "DEVICE_ID",
        36 => "DEVICE_STATUS",
        37 => "DEVICE_RESET",
        38 => "RECOVERY_CTRL",
        39 => "RECOVERY_STATUS",
        40 => "HW_STATUS",
        45 => "INDIRECT_FIFO_CTRL",
        46 => "INDIRECT_FIFO_STATUS",
        47 => "INDIRECT_FIFO_DATA",
        _ => "unknown",
    }
}

/// Decodes the control registers whose fields explain a recovery flow, so the
/// log shows intent ("activate image") rather than only a raw word.
fn recovery_write_detail(addr: u32, val: u32) -> Option<String> {
    Some(match addr {
        // RECOVERY_CTRL: [7:0] CMS, [15:8] image selection, [23:16] activate.
        0x03c => format!(
            "cms={} image_sel={} activate={:#04x}",
            val & 0xff,
            (val >> 8) & 0xff,
            (val >> 16) & 0xff
        ),
        // INDIRECT_FIFO_CTRL: [7:0] CMS, [8] reset; image size is the next word.
        0x048 => format!("cms={} reset={}", val & 0xff, (val >> 8) & 0x1),
        0x04c => format!(
            "image size {} dwords ({} bytes)",
            val,
            val.saturating_mul(4)
        ),
        _ => return None,
    })
}

/// Name of a SecFwRecoveryIf register, for tracing. Only the registers a
/// recovery agent actually drives are named; anything else traces as its offset.
fn recovery_reg_name(addr: u32) -> Option<&'static str> {
    Some(match addr {
        0x004..=0x010 => "PROT_CAP",
        0x014..=0x02c => "DEVICE_ID",
        0x030..=0x034 => "DEVICE_STATUS",
        0x038 => "DEVICE_RESET",
        0x03c => "RECOVERY_CTRL",
        0x040 => "RECOVERY_STATUS",
        0x044 => "HW_STATUS",
        0x048..=0x04c => "INDIRECT_FIFO_CTRL",
        0x050..=0x064 => "INDIRECT_FIFO_STATUS",
        RECOVERY_INDIRECT_FIFO_DATA_OFFSET => "INDIRECT_FIFO_DATA",
        _ => return None,
    })
}

/// Renders a recovery register for tracing as `NAME+off` so the exact word is
/// still identifiable within a multi-register block.
fn recovery_reg_label(addr: u32) -> String {
    match recovery_reg_name(addr) {
        Some(name) => match addr {
            0x004 | 0x014 | 0x030 | 0x048 | 0x050 => name.to_string(),
            _ => format!("{name}+{:#x}", addr & 0xf),
        },
        None => format!("{addr:#05x}"),
    }
}

/// Maps an OCP Secure Firmware Recovery command code to the `(byte offset,
/// block length)` of the matching block in the SecFwRecoveryIf register space.
///
/// Command codes and block lengths are defined by the OCP recovery
/// specification; the offsets are those accepted by `read_recovery_interface`.
/// Codes without a backing block here (IndirectCtrl/Status/Data, Vendor) are
/// unsupported and fall through to the TTI path.
fn recovery_block(command_code: u8) -> Option<(u32, usize)> {
    Some(match command_code {
        34 => (0x004, 15), // PROT_CAP
        35 => (0x014, 24), // DEVICE_ID
        36 => (0x030, 7),  // DEVICE_STATUS
        37 => (0x038, 3),  // DEVICE_RESET
        38 => (0x03c, 3),  // RECOVERY_CTRL
        39 => (0x040, 2),  // RECOVERY_STATUS
        40 => (0x044, 4),  // HW_STATUS
        45 => (0x048, 6),  // INDIRECT_FIFO_CTRL
        46 => (0x050, 20), // INDIRECT_FIFO_STATUS
        // A firmware image is streamed through this block, so it carries as
        // much payload as the transfer holds rather than a fixed length.
        47 => (RECOVERY_INDIRECT_FIFO_DATA_OFFSET, usize::MAX),
        _ => return None,
    })
}

/// Byte layout of a recovery block across the 32-bit registers backing it, as
/// `(offset, bytes taken from this register)`.
///
/// Most blocks are a plain run of whole registers. INDIRECT_FIFO_CTRL is the
/// exception: it packs CMS and reset into the low two bytes of its first
/// register and continues with the image size in the whole of its second, so
/// the block is narrower on the wire (6 bytes) than the 8 bytes of register
/// space behind it. Taking the full first register there would pad the block
/// and shift the image size, so an initiator would decode it straddled across
/// a register boundary.
///
/// Returns `None` for the FIFO data port, which is not an array and is handled
/// separately.
fn recovery_block_segments(command_code: u8) -> Option<Vec<(u32, usize)>> {
    let (offset, len) = recovery_block(command_code)?;
    if offset == RECOVERY_INDIRECT_FIFO_DATA_OFFSET {
        return None;
    }
    if command_code == 45 {
        return Some(vec![(offset, 2), (offset + 4, 4)]);
    }
    let mut segments = Vec::new();
    let mut remaining = len;
    let mut addr = offset;
    while remaining > 0 {
        let take = remaining.min(4);
        segments.push((addr, take));
        addr += 4;
        remaining -= take;
    }
    Some(segments)
}
#[derive(Clone)]
struct PollScheduler {
    timer: Timer,
    // Held while scheduling to prevent the clock from advancing mid-operation.
    step_lock: Arc<Mutex<()>>,
}

impl I3cIncomingCommandClient for PollScheduler {
    fn incoming(&self) {
        let _guard = self.step_lock.lock().unwrap();
        // trigger interrupt check next tick
        self.timer.schedule_poll_in(1);
    }
}

pub struct I3c {
    /// Timer
    timer: Timer,
    /// I3C target abstraction
    i3c_target: I3cTarget,
    /// Virtual target the OCP recovery interface answers on, mirroring the
    /// separate recovery address real hardware exposes.
    recovery_target: I3cTarget,
    /// Command code from the private write that opens a recovery block read.
    pending_recovery_command: Option<u8>,
    /// Caps the "fell through to MCTP" trace so chatty MCTP tests stay readable.
    tti_fallthrough_logged: u32,
    /// Last traced value per recovery register, so polled status registers are
    /// only logged when they actually change.
    recovery_trace_last_read: std::collections::HashMap<u32, u32>,
    /// Pending INDIRECT_FIFO_DATA word counts, reported as a summary line.
    recovery_fifo_write_dwords: u64,
    recovery_fifo_read_dwords: u64,
    /// Last CP-framed transfer and how many times it has repeated since, so a
    /// poll loop collapses to a single line with a count.
    cp_trace_last: Option<(u8, bool)>,
    cp_trace_repeats: u64,
    /// RX Command in u32
    tti_rx_desc_queue_raw: VecDeque<u32>,
    /// RX DATA in u8
    tti_rx_data_raw: VecDeque<Vec<u8>>,
    /// RX DATA currently being read from driver
    tti_rx_current: VecDeque<u8>,
    /// TX Command in u32
    tti_tx_desc_queue_raw: VecDeque<u32>,
    /// TX DATA in u8
    tti_tx_data_raw: VecDeque<Vec<u8>>,
    /// IBI buffer
    tti_ibi_buffer: Vec<u8>,
    /// interrupt
    irq: Irq,
    hw_revision: Version,

    i3c_ec_sec_fw_recovery_if_prot_cap_2: ReadWriteRegister<u32>,
    i3c_ec_sec_fw_recovery_if_device_status_0: ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::i3c::bits::DeviceStatus0::Register,
    >,
    i3c_ec_sec_fw_recovery_if_recovery_status: ReadWriteRegister<u32>,
    i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0: ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::i3c::bits::IndirectFifoCtrl0::Register,
    >,
    i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1: ReadWriteRegister<u32>,
    i3c_ec_sec_fw_recovery_if_indirect_fifo_status_0: ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::i3c::bits::IndirectFifoStatus0::Register,
    >,
    i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1: ReadWriteRegister<u32>,
    i3c_ec_sec_fw_recovery_if_indirect_fifo_status_2: ReadWriteRegister<u32>,
    i3c_ec_sec_fw_recovery_if_recovery_ctrl:
        ReadWriteRegister<u32, caliptra_mcu_registers_generated::i3c::bits::RecoveryCtrl::Register>,
    i3c_ec_sec_fw_recovery_if_device_reset:
        ReadWriteRegister<u32, caliptra_mcu_registers_generated::i3c::bits::DeviceReset::Register>,
    /// I3CBase HC_CONTROL. A recovery agent parks the I3C PHY here while the
    /// AXI path owns the recovery interface, and restores it afterwards, so the
    /// register has to retain what was written rather than discard it.
    i3c_base_hc_control:
        ReadWriteRegister<u32, caliptra_mcu_registers_generated::i3c::bits::HcControl::Register>,
    i3c_ec_soc_mgmt_if_rec_intf_cfg:
        ReadWriteRegister<u32, caliptra_mcu_registers_generated::i3c::bits::RecIntfCfg::Register>,
    indirect_fifo_data: Vec<u8>,
    /// Mirrors `payload_available_o`: high while a complete or activated image
    /// is buffered, low once the device firmware has drained it. Firmware must
    /// see it fall before it may trust `IMAGE_SIZE` for the next stage.
    payload_available: bool,
    /// True once the recovery (virtual) device has been addressed. The socket
    /// transport exposes a single target address, so a recovery command code
    /// with CP set stands in for `virtual_device_sel`.
    recovery_mode_enabled: bool,
    recovery_errors: RecoveryErrorCounters,
    i3c_ec_soc_mgmt_if_rec_intf_reg_w1_c_access: ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::i3c::bits::RecIntfRegW1cAccess::Register,
    >,

    interrupt_status: ReadWriteRegister<u32, InterruptStatus::Register>,
    interrupt_enable: ReadWriteRegister<u32, InterruptEnable::Register>,
    /// Software-forced interrupt bits. INTERRUPT_FORCE shares bit positions with
    /// INTERRUPT_STATUS, and a forced bit stays set until cleared through the
    /// INTERRUPT_STATUS W1C path.
    interrupt_force: ReadWriteRegister<u32, InterruptForce::Register>,
    ibi_status: Option<ReadWriteRegister<u32, Status::Register>>,
    generated: I3cGenerated,

    events_to_caliptra: Option<mpsc::Sender<Event>>,
    events_from_caliptra: Option<mpsc::Receiver<Event>>,
    events_to_mcu: Option<mpsc::Sender<Event>>,
    events_from_mcu: Option<mpsc::Receiver<Event>>,
}

impl I3c {
    const HCI_VERSION: u32 = 0x120;
    /// Emulator poll interval for the I3C peripheral, in core clock ticks.
    /// Larger values mean fewer polling events per emulated second, which
    /// speeds up wall-clock execution of long-running tests at the cost of
    /// coarser I3C interrupt-check granularity. 5000 ticks is enough for
    /// MCTP / SPDM exchanges and roughly 5x faster than the previous value.
    const HCI_TICKS: u64 = 5000;

    pub fn new(
        clock: &Clock,
        controller: &mut I3cController,
        irq: Irq,
        hw_revision: Version,
        step_lock: Arc<Mutex<()>>,
    ) -> Self {
        let mut i3c_target = I3cTarget::default();
        let mut recovery_target = I3cTarget::default();

        controller.attach_target(i3c_target.clone()).unwrap();
        // Attached second so it takes the next dynamic address: the initiator
        // drives recovery on this one and MCTP on the first.
        controller.attach_target(recovery_target.clone()).unwrap();
        let timer = Timer::new(clock);
        timer.schedule_poll_in(Self::HCI_TICKS);
        let poll_scheduler = PollScheduler {
            timer: timer.clone(),
            step_lock,
        };
        i3c_target.set_incoming_command_client(Arc::new(poll_scheduler.clone()));
        recovery_target.set_incoming_command_client(Arc::new(poll_scheduler));

        i3c_log!(
            "targets attached: mctp={:?} recovery={:?}",
            i3c_target.get_address().map(u8::from),
            recovery_target.get_address().map(u8::from)
        );

        Self {
            i3c_target,
            recovery_target,
            pending_recovery_command: None,
            tti_fallthrough_logged: 0,
            recovery_trace_last_read: std::collections::HashMap::new(),
            recovery_fifo_write_dwords: 0,
            recovery_fifo_read_dwords: 0,
            cp_trace_last: None,
            cp_trace_repeats: 0,
            timer,
            tti_rx_desc_queue_raw: VecDeque::new(),
            tti_rx_data_raw: VecDeque::new(),
            tti_rx_current: VecDeque::new(),
            tti_tx_desc_queue_raw: VecDeque::new(),
            tti_tx_data_raw: VecDeque::new(),
            tti_ibi_buffer: vec![],
            irq,
            hw_revision,
            // PROT_CAP_2 resets to zero like the RDL; firmware owns the
            // version and agent-capability fields.
            i3c_ec_sec_fw_recovery_if_prot_cap_2: ReadWriteRegister::new(0),
            i3c_ec_sec_fw_recovery_if_device_status_0: ReadWriteRegister::new(0),
            i3c_ec_sec_fw_recovery_if_recovery_status: ReadWriteRegister::new(0),
            i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0: ReadWriteRegister::new(0),
            i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1: ReadWriteRegister::new(0),
            i3c_ec_sec_fw_recovery_if_indirect_fifo_status_0: ReadWriteRegister::new(
                1 << IndirectFifoStatus0::Empty.shift,
            ),
            i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1: ReadWriteRegister::new(0),
            i3c_ec_sec_fw_recovery_if_indirect_fifo_status_2: ReadWriteRegister::new(0),
            i3c_ec_sec_fw_recovery_if_recovery_ctrl: ReadWriteRegister::new(0),
            i3c_ec_sec_fw_recovery_if_device_reset: ReadWriteRegister::new(0),
            i3c_base_hc_control: ReadWriteRegister::new(0),
            i3c_ec_soc_mgmt_if_rec_intf_cfg: ReadWriteRegister::new(0),
            i3c_ec_soc_mgmt_if_rec_intf_reg_w1_c_access: ReadWriteRegister::new(0),
            indirect_fifo_data: Vec::new(),
            payload_available: false,
            recovery_mode_enabled: false,
            recovery_errors: RecoveryErrorCounters::default(),
            interrupt_status: ReadWriteRegister::new(0),
            interrupt_enable: ReadWriteRegister::new(0),
            interrupt_force: ReadWriteRegister::new(0),
            ibi_status: None,
            generated: I3cGenerated::default(),
            events_to_caliptra: None,
            events_from_caliptra: None,
            events_to_mcu: None,
            events_from_mcu: None,
        }
    }

    pub fn get_dynamic_address(&self) -> Option<DynamicI3cAddress> {
        self.i3c_target.get_address()
    }

    fn write_tx_data_into_target(&mut self) {
        if !self.tti_tx_desc_queue_raw.is_empty() {
            let resp_desc = ResponseDescriptor::read_from_bytes(
                &self.tti_tx_desc_queue_raw[0].to_le_bytes()[..],
            )
            .unwrap();
            let data_size = resp_desc.data_length().into();
            if let Some(_data) = self.tti_tx_data_raw.front() {
                if self.tti_tx_data_raw[0].len() >= data_size {
                    self.tti_tx_desc_queue_raw.pop_front();
                    let resp = I3cTcriResponseXfer {
                        resp: resp_desc,
                        data: self.tti_tx_data_raw.pop_front().unwrap(),
                    };
                    self.i3c_target.set_response(resp);
                }
            }
        }
    }

    fn read_rx_data_into_buffer(&mut self) {
        // Recovery blocks are drained back to back: streaming an image is
        // hundreds of transfers and one per poll tick would dominate run time.
        // A TTI transfer ends the loop so MCTP keeps its one-per-poll pacing.
        while let Some(xfer) = self.i3c_target.read_command() {
            if self.handle_recovery_block_transfer(&xfer) {
                continue;
            }
            // TODO: we don't request data using rnw
            let rnw = (u64::from(xfer.cmd.clone()) & (1 << 29)) as u32;
            self.tti_rx_desc_queue_raw
                .push_back(xfer.cmd.raw_data_len() as u32 | rnw);
            let data = match xfer.cmd.clone() {
                I3cTcriCommand::Immediate(imm) => vec![
                    imm.data_byte_1(),
                    imm.data_byte_2(),
                    imm.data_byte_3(),
                    imm.data_byte_4(),
                ],
                _ => xfer.data,
            };
            self.tti_rx_data_raw.push_back(data);
            if self.tti_fallthrough_logged < 32 {
                self.tti_fallthrough_logged += 1;
                i3c_log!(
                    "mctp transfer, {} bytes [{}] (not a recovery access)",
                    self.tti_rx_data_raw.back().map(Vec::len).unwrap_or(0),
                    head(
                        self.tti_rx_data_raw
                            .back()
                            .map(Vec::as_slice)
                            .unwrap_or(&[])
                    )
                );
            }
            return;
        }
    }

    /// Services transfers addressed to the recovery virtual target using the OCP
    /// wire framing, which is what a real Recovery Initiator (a BMC) emits.
    ///
    /// A block write is one private write carrying `CMD, LEN_LSB, LEN_MSB,
    /// DATA.., PEC`. A block read is a private write of just `CMD` (plus PEC)
    /// followed by a private read that must answer `LEN_LSB, LEN_MSB, DATA..`.
    fn drain_recovery_wire_commands(&mut self) {
        while let Some(xfer) = self.recovery_target.read_command() {
            let I3cTcriCommand::Regular(cmd) = &xfer.cmd else {
                i3c_log!("recovery: ignoring non-regular transfer");
                continue;
            };
            self.set_recovery_mode(true, "OCP wire transfer");

            if cmd.rnw() == 1 {
                let requested = cmd.data_length() as usize;
                let Some(command_code) = self.pending_recovery_command.take() else {
                    self.recovery_errors.unsupported =
                        self.recovery_errors.unsupported.saturating_add(1);
                    i3c_log!("recovery: read of {requested} bytes with no preceding command byte");
                    continue;
                };
                self.answer_recovery_wire_read(command_code, cmd.tid(), requested);
                continue;
            }

            self.accept_recovery_wire_write(&xfer.data);
        }
    }

    /// Handles the write half of the OCP framing: either the command byte that
    /// opens a read, or a complete block write.
    fn accept_recovery_wire_write(&mut self, data: &[u8]) {
        // A command byte on its own (optionally with PEC) opens a read; every
        // block write carries at least CMD + 2 length bytes + payload.
        if data.is_empty() {
            i3c_log!("recovery: empty write");
            return;
        }
        let command_code = data[0];

        if data.len() <= 2 {
            if data.len() == 2 {
                let address = self.recovery_wire_address();
                self.check_wire_pec(
                    command_code,
                    recovery_command_pec(address, command_code),
                    data[1],
                );
            }
            self.pending_recovery_command = Some(command_code);
            i3c_log!("recovery: read request for command {command_code}");
            return;
        }

        if data.len() < 3 {
            self.recovery_errors.length = self.recovery_errors.length.saturating_add(1);
            self.record_protocol_error(PROT_ERROR_LENGTH, "truncated block write", command_code);
            return;
        }
        let declared = u16::from_le_bytes([data[1], data[2]]) as usize;
        let body = &data[3..];
        if body.len() < declared {
            self.recovery_errors.length = self.recovery_errors.length.saturating_add(1);
            self.record_protocol_error(PROT_ERROR_LENGTH, "short block write", command_code);
            i3c_log!(
                "recovery: command {command_code} declared {declared} bytes but carries {}",
                body.len()
            );
            return;
        }
        let payload = &body[..declared];
        if body.len() > declared {
            let address = self.recovery_wire_address();
            self.check_wire_pec(
                command_code,
                recovery_write_pec(address, command_code, payload),
                body[declared],
            );
        }

        let Some((offset, block_len)) = recovery_block(command_code) else {
            self.recovery_errors.unsupported = self.recovery_errors.unsupported.saturating_add(1);
            self.record_protocol_error(PROT_ERROR_UNSUPPORTED, "unsupported command", command_code);
            return;
        };

        i3c_log!(
            "recovery: write command {command_code}, {declared} bytes [{}]",
            head(payload)
        );
        let payload = payload.to_vec();
        self.apply_recovery_block_write(command_code, offset, block_len, &payload);
    }

    /// Answers the private read that follows a command byte, prefixing the
    /// 16-bit block length the initiator reads back first.
    fn answer_recovery_wire_read(&mut self, command_code: u8, tid: u8, requested: usize) {
        let Some((offset, block_len)) = recovery_block(command_code) else {
            self.recovery_errors.unsupported = self.recovery_errors.unsupported.saturating_add(1);
            self.record_protocol_error(PROT_ERROR_UNSUPPORTED, "unsupported command", command_code);
            return;
        };

        // The initiator sizes its read as block length + the 2 length bytes.
        let len = if block_len == usize::MAX {
            requested.saturating_sub(2)
        } else {
            block_len
        };
        let payload = self.read_recovery_block(command_code, offset, len);

        let mut data = Vec::with_capacity(payload.len() + 2);
        data.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        data.extend_from_slice(&payload);
        if requested != 0 && data.len() > requested {
            data.truncate(requested);
        }

        i3c_log!(
            "recovery: read command {command_code} -> {} bytes [{}]",
            payload.len(),
            head(&payload)
        );

        let mut resp = ResponseDescriptor::default();
        resp.set_data_length(data.len() as u16);
        resp.set_tid(tid);
        self.recovery_target
            .set_response(I3cTcriResponseXfer { resp, data });
    }

    /// Address the recovery interface answers on when the initiator uses the OCP
    /// wire framing. PEC is seeded with it, so a target that has not been
    /// assigned an address yet contributes nothing rather than a wrong value.
    fn recovery_wire_address(&self) -> u8 {
        self.recovery_target
            .get_address()
            .map(u8::from)
            .unwrap_or(0)
    }

    /// Address the recovery interface answers on when the command is carried in
    /// the transfer descriptor rather than the payload.
    fn cp_wire_address(&self) -> u8 {
        self.i3c_target.get_address().map(u8::from).unwrap_or(0)
    }

    /// PEC is advisory on this path: the byte the controller appends also covers
    /// the address phase in some stacks, so a mismatch is reported rather than
    /// used to reject an otherwise well-formed transfer.
    fn check_wire_pec(&mut self, command_code: u8, expected: u8, received: u8) {
        if expected != received {
            self.recovery_errors.pec = self.recovery_errors.pec.saturating_add(1);
            i3c_log!(
                "recovery: command {command_code} PEC {received:#04x}, computed {expected:#04x}"
            );
        }
    }

    /// Services an OCP Secure Firmware Recovery block transfer received over the
    /// I3C bus, reusing the same register accessors as the Caliptra event path.
    ///
    /// Returns `false` only when the transfer is not addressed to the recovery
    /// interface, in which case the caller must fall through to the TTI (MCTP)
    /// receive path. A malformed recovery access is reported as a protocol error
    /// and dropped, never injected into the MCTP stream.
    fn handle_recovery_block_transfer(&mut self, xfer: &I3cTcriCommandXfer) -> bool {
        let I3cTcriCommand::Regular(cmd) = &xfer.cmd else {
            return false;
        };
        // A recovery access is a private transfer carrying a command code; plain
        // MCTP traffic leaves CP clear.
        if cmd.cp() == 0 {
            return false;
        }

        self.set_recovery_mode(true, "private CP transfer");

        let command_code = cmd.cmd();
        self.trace_cp_transfer(
            command_code,
            cmd.rnw() == 1,
            if cmd.rnw() == 1 {
                cmd.data_length() as usize
            } else {
                xfer.data.len()
            },
        );
        let Some((offset, block_len)) = recovery_block(command_code) else {
            self.recovery_errors.unsupported = self.recovery_errors.unsupported.saturating_add(1);
            self.record_protocol_error(PROT_ERROR_UNSUPPORTED, "unsupported command", command_code);
            return true;
        };

        if cmd.rnw() == 1 {
            self.handle_recovery_block_read(
                command_code,
                offset,
                block_len,
                cmd.tid(),
                cmd.data_length() as usize,
            );
        } else {
            self.handle_recovery_block_write(command_code, offset, block_len, &xfer.data);
        }
        true
    }

    /// Answers a recovery block read, appending the PEC byte when the initiator
    /// leaves room for it in the requested length.
    fn handle_recovery_block_read(
        &mut self,
        command_code: u8,
        offset: u32,
        block_len: usize,
        tid: u8,
        requested: usize,
    ) {
        let fixed_length = block_len != usize::MAX;
        let with_pec = fixed_length && requested == block_len + 1;
        if fixed_length && !with_pec && requested != block_len {
            self.recovery_errors.length = self.recovery_errors.length.saturating_add(1);
            self.record_protocol_error(PROT_ERROR_LENGTH, "read length mismatch", command_code);
        }
        let len = if with_pec {
            block_len
        } else {
            requested.min(block_len)
        };

        let mut data = self.read_recovery_block(command_code, offset, len);
        if with_pec {
            let address = self.cp_wire_address();
            let pec = recovery_read_pec(address, command_code, &data);
            data.push(pec);
        }

        let mut resp = ResponseDescriptor::default();
        resp.set_data_length(data.len() as u16);
        resp.set_tid(tid);
        self.i3c_target
            .set_response(I3cTcriResponseXfer { resp, data });
    }

    /// Applies a recovery block write after the checks the recovery handler
    /// performs: read-only CSR, PEC and payload length. A rejected transaction
    /// leaves the CSR untouched.
    fn handle_recovery_block_write(
        &mut self,
        command_code: u8,
        offset: u32,
        block_len: usize,
        payload: &[u8],
    ) {
        let fixed_length = block_len != usize::MAX;
        let expected = if fixed_length {
            block_len
        } else {
            payload.len()
        };

        let payload = if payload.len() == expected + 1 {
            let address = self.cp_wire_address();
            let pec = recovery_write_pec(address, command_code, &payload[..expected]);
            if pec != payload[expected] {
                self.recovery_errors.pec = self.recovery_errors.pec.saturating_add(1);
                self.record_protocol_error(PROT_ERROR_CRC, "PEC mismatch", command_code);
                return;
            }
            &payload[..expected]
        } else {
            payload
        };

        let payload = payload.to_vec();
        self.apply_recovery_block_write(command_code, offset, block_len, &payload);
    }

    /// Read-only and length checks every recovery block write goes through,
    /// independent of the framing it arrived in.
    fn apply_recovery_block_write(
        &mut self,
        command_code: u8,
        offset: u32,
        block_len: usize,
        payload: &[u8],
    ) {
        if !recovery_block_writeable(command_code) {
            self.recovery_errors.read_only = self.recovery_errors.read_only.saturating_add(1);
            self.record_protocol_error(PROT_ERROR_UNSUPPORTED, "write to read-only", command_code);
            return;
        }
        if block_len != usize::MAX && payload.len() != block_len {
            self.recovery_errors.length = self.recovery_errors.length.saturating_add(1);
            self.record_protocol_error(PROT_ERROR_LENGTH, "write length mismatch", command_code);
            return;
        }
        self.write_recovery_block(command_code, offset, block_len, payload);
    }

    /// Latches an OCP protocol error into `DEVICE_STATUS_0.PROT_ERROR`.
    fn record_protocol_error(&mut self, code: u32, reason: &str, command_code: u8) {
        self.i3c_ec_sec_fw_recovery_if_device_status_0
            .reg
            .modify(DeviceStatus0::ProtError.val(code));
        println!(
            "[I3C-Emulator] recovery protocol error {code:#x}: {reason} (command {command_code})"
        );
    }

    /// Traces a CP-framed recovery transfer, collapsing a run of identical
    /// transfers into one line with a repeat count. An agent polling
    /// RECOVERY_CTRL emits thousands of identical reads while it waits for an
    /// image, which would otherwise bury everything else.
    fn trace_cp_transfer(&mut self, command_code: u8, is_read: bool, len: usize) {
        if !i3c_log_enabled() {
            return;
        }
        if self.cp_trace_last == Some((command_code, is_read)) {
            self.cp_trace_repeats += 1;
            return;
        }
        self.flush_cp_trace();
        self.cp_trace_last = Some((command_code, is_read));
        i3c_log!(
            "cp transfer: {} command {command_code} ({}), {len} bytes",
            if is_read { "read" } else { "write" },
            recovery_command_name(command_code)
        );
    }

    /// Reports how many times the last CP transfer repeated, if more than once.
    fn flush_cp_trace(&mut self) {
        let repeats = std::mem::take(&mut self.cp_trace_repeats);
        if repeats != 0 {
            if let Some((command_code, is_read)) = self.cp_trace_last {
                i3c_log!(
                    "cp transfer: {} command {command_code} ({}) repeated {repeats}x",
                    if is_read { "read" } else { "write" },
                    recovery_command_name(command_code)
                );
            }
        }
        self.cp_trace_last = None;
    }

    /// Records recovery-mode entry/exit, tracing only the transition so a
    /// per-transfer assignment does not spam the log.
    fn set_recovery_mode(&mut self, enabled: bool, reason: &str) {
        if self.recovery_mode_enabled != enabled {
            self.flush_cp_trace();
            i3c_log!(
                "recovery mode {} ({reason})",
                if enabled { "entered" } else { "cleared" }
            );
        }
        self.recovery_mode_enabled = enabled;
    }

    /// Snapshot of the recovery handler error counters.
    pub fn recovery_error_counters(&self) -> RecoveryErrorCounters {
        self.recovery_errors
    }

    /// Reads up to `len` bytes of a recovery block as a little-endian byte
    /// stream.
    fn read_recovery_block(&mut self, command_code: u8, offset: u32, len: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(len.min(4096));
        match recovery_block_segments(command_code) {
            Some(segments) => {
                for (addr, take) in segments {
                    if data.len() >= len {
                        break;
                    }
                    let word = self.read_recovery_word(addr);
                    data.extend_from_slice(&word.to_le_bytes()[..take]);
                }
            }
            None => {
                // FIFO port: every word comes from the same address.
                while data.len() < len {
                    let word = self.read_recovery_word(offset);
                    data.extend_from_slice(&word.to_le_bytes());
                }
            }
        }
        data.truncate(len);
        data
    }

    fn read_recovery_word(&mut self, addr: u32) -> u32 {
        match self.read_recovery_interface(caliptra_emu_types::RvSize::Word, addr) {
            Ok(word) => word,
            Err(err) => {
                println!("[I3C-Emulator] recovery block read at {addr:#x} failed: {err:?}");
                0
            }
        }
    }

    /// Writes a recovery block from a little-endian byte stream. Bytes past the
    /// end of `payload` are zero-filled so a short write still lands a whole
    /// register, matching the RTL.
    fn write_recovery_block(
        &mut self,
        command_code: u8,
        offset: u32,
        block_len: usize,
        payload: &[u8],
    ) {
        let len = block_len.min(payload.len());
        match recovery_block_segments(command_code) {
            Some(segments) => {
                let mut consumed = 0;
                for (addr, take) in segments {
                    if consumed >= len {
                        break;
                    }
                    let mut bytes = [0u8; 4];
                    let available = (len - consumed).min(take);
                    bytes[..available].copy_from_slice(&payload[consumed..consumed + available]);
                    self.write_recovery_word(addr, u32::from_le_bytes(bytes));
                    consumed += take;
                }
            }
            None => {
                // FIFO port: push every word to the same address.
                for chunk in payload[..len].chunks(4) {
                    let mut bytes = [0u8; 4];
                    bytes[..chunk.len()].copy_from_slice(chunk);
                    self.write_recovery_word(offset, u32::from_le_bytes(bytes));
                }
            }
        }
    }

    fn write_recovery_word(&mut self, addr: u32, val: u32) {
        if let Err(err) = self.write_recovery_interface(caliptra_emu_types::RvSize::Word, addr, val)
        {
            println!("[I3C-Emulator] recovery block write at {addr:#x} failed: {err:?}");
        }
    }

    fn check_interrupts(&mut self) {
        // TODO: implement the timeout interrupts

        self.interrupt_status
            .reg
            .modify(if self.ibi_status.is_some() {
                InterruptStatus::IbiDone::SET
            } else {
                InterruptStatus::IbiDone::CLEAR
            });

        // Set RxDescStat interrupt if there is a pending write (i.e., data to read from rx registers)
        self.interrupt_status
            .reg
            .modify(if self.tti_rx_desc_queue_raw.is_empty() {
                InterruptStatus::RxDescStat::CLEAR
            } else {
                InterruptStatus::RxDescStat::SET
            });

        // Re-apply forced bits after the derived bits above, which would otherwise clear them.
        let forced = self.interrupt_force.reg.get();
        if forced != 0 {
            let status = self.interrupt_status.reg.get();
            self.interrupt_status.reg.set(status | forced);
        }

        let status: ReadWriteRegister<u32, InterruptStatus::Register> = ReadWriteRegister::new(
            self.interrupt_enable.reg.get() & self.interrupt_status.reg.get(),
        );

        self.irq.set_level(status.reg.any_matching_bits_set(
            InterruptStatus::RxDescStat::SET
                + InterruptStatus::TxDescStat::SET
                + InterruptStatus::RxDescTimeout::SET
                + InterruptStatus::TxDescTimeout::SET
                + InterruptStatus::IbiDone::SET,
        ));
    }

    // check if there area valid IBI descriptors and messages
    fn check_ibi_buffer(&mut self) {
        loop {
            if self.tti_ibi_buffer.len() < 4 {
                return;
            }

            let desc = IbiDescriptor::read_from_bytes(&self.tti_ibi_buffer[0..4]).unwrap();
            let len = desc.data_length() as usize;
            if self.tti_ibi_buffer.len() < len + 4 {
                // wait for more data
                return;
            }

            // TODO: support sending more bytes of IBI to target
            self.i3c_target.send_ibi((desc.0 >> 24) as u8);
            self.ibi_status = Some(ReadWriteRegister::new(0));
            self.tti_ibi_buffer.drain(0..(len + 4).next_multiple_of(4));
        }
    }

    pub fn incoming_caliptra_event(&mut self, event: Event) {
        match &event.event {
            EventData::MemoryRead { start_addr, len } => {
                let mut response = Vec::new();
                for _ in 0..(*len) / std::mem::size_of::<u32>() as u32 {
                    match self
                        .read_recovery_interface(caliptra_emu_types::RvSize::Word, *start_addr)
                    {
                        Ok(data) => {
                            response.extend_from_slice(&data.to_le_bytes());
                        }
                        Err(err) => {
                            println!("[I3C-Emulator] Error reading recovery interface: {:?}", err);
                            return;
                        }
                    }
                }

                self.events_to_caliptra
                    .as_ref()
                    .unwrap()
                    .send(Event::new(
                        Device::RecoveryIntf,
                        Device::CaliptraCore,
                        EventData::MemoryReadResponse {
                            start_addr: *start_addr,
                            data: response,
                        },
                    ))
                    .unwrap();
            }
            EventData::MemoryWrite { start_addr, data } => {
                self.write_recovery_interface(
                    caliptra_emu_types::RvSize::Word,
                    *start_addr,
                    caliptra_emu_types::RvData::from_le_bytes(data[0..4].try_into().unwrap()),
                )
                .unwrap();
            }
            EventData::RecoveryFifoStatusRequest => {
                // payload_available: a whole (or activated) image is buffered and
                // has not been drained yet.
                let status = u32::from(self.payload_available);

                self.events_to_caliptra
                    .as_ref()
                    .unwrap()
                    .send(Event::new(
                        Device::RecoveryIntf,
                        Device::CaliptraCore,
                        EventData::RecoveryFifoStatusResponse { status },
                    ))
                    .unwrap();
            }
            _ => {}
        }
    }

    pub fn incoming_mcu_event(&mut self, _event: Event) {
        // do nothing for now
    }

    /// Traces a recovery-interface read, then defers to the register decode.
    ///
    /// Every recovery path (OCP wire, the private CP framing, the Caliptra
    /// event channel and AXI-direct) funnels through here, so this is the one
    /// place that sees all recovery traffic. Reads are edge-logged - a polled
    /// status is only traced when its value changes - and the FIFO data port is
    /// counted rather than logged per word.
    fn read_recovery_interface(
        &mut self,
        size: caliptra_emu_types::RvSize,
        addr: caliptra_emu_types::RvAddr,
    ) -> Result<caliptra_emu_types::RvData, caliptra_emu_bus::BusError> {
        let result = self.read_recovery_interface_inner(size, addr);
        if i3c_log_enabled() {
            if addr == RECOVERY_INDIRECT_FIFO_DATA_OFFSET {
                self.recovery_fifo_read_dwords += 1;
            } else {
                self.flush_recovery_fifo_trace();
                if let Ok(value) = &result {
                    if self.recovery_trace_last_read.insert(addr, *value) != Some(*value) {
                        i3c_log!("read  {} = {value:#010x}", recovery_reg_label(addr));
                    }
                }
            }
        }
        result
    }

    fn read_recovery_interface_inner(
        &mut self,
        size: caliptra_emu_types::RvSize,
        addr: caliptra_emu_types::RvAddr,
    ) -> Result<caliptra_emu_types::RvData, caliptra_emu_bus::BusError> {
        if addr & 0x3 != 0 || size != caliptra_emu_types::RvSize::Word {
            return Err(caliptra_emu_bus::BusError::LoadAddrMisaligned);
        }
        match addr {
            0x000 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_extcap_header()
                    .reg
                    .get(),
            )),
            0x004 => Ok(self.read_i3c_ec_sec_fw_recovery_if_prot_cap_0()),
            0x008 => Ok(self.read_i3c_ec_sec_fw_recovery_if_prot_cap_1()),
            0x00c => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_prot_cap_2().reg.get(),
            )),
            0x010 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_prot_cap_3().reg.get(),
            )),
            0x014 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_device_id_0().reg.get(),
            )),
            0x018 => Ok(self.read_i3c_ec_sec_fw_recovery_if_device_id_1()),
            0x01c => Ok(self.read_i3c_ec_sec_fw_recovery_if_device_id_2()),
            0x020 => Ok(self.read_i3c_ec_sec_fw_recovery_if_device_id_3()),
            0x024 => Ok(self.read_i3c_ec_sec_fw_recovery_if_device_id_4()),
            0x028 => Ok(self.read_i3c_ec_sec_fw_recovery_if_device_id_5()),
            0x02c => Ok(self.read_i3c_ec_sec_fw_recovery_if_device_id_reserved()),
            0x030 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_device_status_0()
                    .reg
                    .get(),
            )),
            0x034 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_device_status_1()
                    .reg
                    .get(),
            )),
            0x038 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_device_reset().reg.get(),
            )),
            0x03c => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_recovery_ctrl()
                    .reg
                    .get(),
            )),
            0x040 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_recovery_status()
                    .reg
                    .get(),
            )),
            0x044 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_hw_status().reg.get(),
            )),
            0x048 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0()
                    .reg
                    .get(),
            )),
            0x04c => Ok(self.read_i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1()),
            0x050 => Ok(caliptra_emu_types::RvData::from(
                self.read_i3c_ec_sec_fw_recovery_if_indirect_fifo_status_0()
                    .reg
                    .get(),
            )),
            0x054 => Ok(self.read_i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1()),
            0x058 => Ok(self.read_i3c_ec_sec_fw_recovery_if_indirect_fifo_status_2()),
            0x05c => Ok(self.read_i3c_ec_sec_fw_recovery_if_indirect_fifo_status_3()),
            0x060 => Ok(self.read_i3c_ec_sec_fw_recovery_if_indirect_fifo_status_4()),
            0x064 => Ok(self.read_i3c_ec_sec_fw_recovery_if_indirect_fifo_reserved()),
            0x068 => Ok(self.read_i3c_ec_sec_fw_recovery_if_indirect_fifo_data()),
            0x210..0x214 => Ok(self
                .read_i3c_ec_soc_mgmt_if_rec_intf_reg_w1_c_access()
                .reg
                .get()),

            _ => Err(caliptra_emu_bus::BusError::LoadAccessFault),
        }
    }

    /// Traces a recovery-interface write, then defers to the register decode.
    /// Writes are events rather than polls, so each one is logged; the FIFO
    /// data port is counted and reported as a single summary line.
    fn write_recovery_interface(
        &mut self,
        size: caliptra_emu_types::RvSize,
        addr: caliptra_emu_types::RvAddr,
        val: caliptra_emu_types::RvData,
    ) -> Result<(), caliptra_emu_bus::BusError> {
        if i3c_log_enabled() {
            if addr == RECOVERY_INDIRECT_FIFO_DATA_OFFSET {
                self.recovery_fifo_write_dwords += 1;
            } else {
                self.flush_recovery_fifo_trace();
                match recovery_write_detail(addr, val) {
                    Some(detail) => {
                        i3c_log!(
                            "write {} = {val:#010x} ({detail})",
                            recovery_reg_label(addr)
                        )
                    }
                    None => i3c_log!("write {} = {val:#010x}", recovery_reg_label(addr)),
                }
                // A read-back of this register should reflect the new value.
                self.recovery_trace_last_read.remove(&addr);
            }
        }
        self.write_recovery_interface_inner(size, addr, val)
    }

    /// Emits the pending INDIRECT_FIFO_DATA totals once the image stream is
    /// interrupted by any other access, keeping a multi-megabyte transfer to
    /// one line instead of one line per 32-bit word.
    fn flush_recovery_fifo_trace(&mut self) {
        let (written, read) = (
            std::mem::take(&mut self.recovery_fifo_write_dwords),
            std::mem::take(&mut self.recovery_fifo_read_dwords),
        );
        if written != 0 {
            i3c_log!(
                "INDIRECT_FIFO_DATA: wrote {written} dwords ({} bytes)",
                written * 4
            );
        }
        if read != 0 {
            i3c_log!(
                "INDIRECT_FIFO_DATA: read {read} dwords ({} bytes)",
                read * 4
            );
        }
    }

    fn write_recovery_interface_inner(
        &mut self,
        size: caliptra_emu_types::RvSize,
        addr: caliptra_emu_types::RvAddr,
        val: caliptra_emu_types::RvData,
    ) -> Result<(), caliptra_emu_bus::BusError> {
        if addr & 0x3 != 0 || size != caliptra_emu_types::RvSize::Word {
            return Err(caliptra_emu_bus::BusError::StoreAddrMisaligned);
        }
        match addr {
            0x00c => {
                self.write_i3c_ec_sec_fw_recovery_if_prot_cap_2(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x010 => {
                self.write_i3c_ec_sec_fw_recovery_if_prot_cap_3(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x014 => {
                self.write_i3c_ec_sec_fw_recovery_if_device_id_0(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x018 => {
                self.write_i3c_ec_sec_fw_recovery_if_device_id_1(val);
                Ok(())
            }
            0x01c => {
                self.write_i3c_ec_sec_fw_recovery_if_device_id_2(val);
                Ok(())
            }
            0x020 => {
                self.write_i3c_ec_sec_fw_recovery_if_device_id_3(val);
                Ok(())
            }
            0x024 => {
                self.write_i3c_ec_sec_fw_recovery_if_device_id_4(val);
                Ok(())
            }
            0x028 => {
                self.write_i3c_ec_sec_fw_recovery_if_device_id_5(val);
                Ok(())
            }
            0x030 => {
                self.write_i3c_ec_sec_fw_recovery_if_device_status_0(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x034 => {
                self.write_i3c_ec_sec_fw_recovery_if_device_status_1(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x038 => {
                self.write_i3c_ec_sec_fw_recovery_if_device_reset(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x03c => {
                self.write_i3c_ec_sec_fw_recovery_if_recovery_ctrl(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x040 => {
                self.write_i3c_ec_sec_fw_recovery_if_recovery_status(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x044 => {
                self.write_i3c_ec_sec_fw_recovery_if_hw_status(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x048 => {
                self.write_i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x04c => {
                self.write_i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1(val);
                Ok(())
            }
            0x068 => {
                self.push_indirect_fifo_word(val);
                Ok(())
            }
            0x210 => {
                self.write_i3c_ec_soc_mgmt_if_rec_intf_reg_w1_c_access(
                    caliptra_emu_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            _ => Err(caliptra_emu_bus::BusError::StoreAccessFault),
        }
    }

    /// Appends one word to the indirect FIFO and advances the write index.
    ///
    /// This is how a recovery controller streams a firmware image in: the
    /// device side then drains it through INDIRECT_FIFO_DATA reads.
    fn push_indirect_fifo_word(&mut self, val: caliptra_emu_types::RvData) {
        let cms = self
            .i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0
            .reg
            .read(IndirectFifoCtrl0::Cms);
        if cms != 0 {
            println!("CMS {cms} not supported");
            return;
        }

        let write_index = self
            .i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1
            .reg
            .get();
        let read_index = self
            .i3c_ec_sec_fw_recovery_if_indirect_fifo_status_2
            .reg
            .get();
        // The socket transport cannot NACK, so an overflow past FIFO_SIZE is
        // counted rather than enforced and the backing store stays elastic.
        if write_index.saturating_sub(read_index) >= INDIRECT_FIFO_SIZE_DWORDS {
            self.recovery_errors.indirect_fifo_overflow = self
                .recovery_errors
                .indirect_fifo_overflow
                .saturating_add(1);
        }

        let address = (write_index * 4) as usize;
        self.indirect_fifo_data.resize(address + 4, 0);
        self.indirect_fifo_data[address..address + 4].copy_from_slice(&val.to_le_bytes());
        self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1
            .reg
            .set(write_index + 1);
        self.update_indirect_fifo_status();
    }

    /// Recomputes EMPTY/FULL and `payload_available` from the FIFO indices.
    ///
    /// `payload_available` rises once the image is ready and falls when the
    /// device firmware has drained it, which is the deassert firmware must
    /// observe between recovery stages. What "ready" means depends on who is
    /// filling the FIFO: over I3C the recovery handler decides, while an
    /// AXI-direct image provider signals its last chunk with REC_PAYLOAD_DONE.
    fn update_indirect_fifo_status(&mut self) {
        let write_index = self
            .i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1
            .reg
            .get();
        let read_index = self
            .i3c_ec_sec_fw_recovery_if_indirect_fifo_status_2
            .reg
            .get();
        let occupancy = write_index.saturating_sub(read_index);

        let bypass = self
            .i3c_ec_soc_mgmt_if_rec_intf_cfg
            .reg
            .read(RecIntfCfg::RecIntfBypass)
            == I3C_REC_INT_BYPASS_AXI_DIRECT;
        let payload_done = self
            .i3c_ec_soc_mgmt_if_rec_intf_cfg
            .reg
            .read(RecIntfCfg::RecPayloadDone)
            != 0;

        let image_dwords = self
            .i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1
            .reg
            .get();
        let image_complete = image_dwords != 0 && write_index >= image_dwords;

        // The model accumulates the whole image rather than draining a hardware
        // FIFO as it fills, so whoever is filling it is never back-pressured.
        // Reporting a real occupancy would deadlock them: an initiator polls
        // EMPTY between chunks, but only the device firmware drains this
        // buffer, and it does not start until the image is complete. Hide the
        // occupancy until the fill is finished, which each path signals
        // differently -- an AXI-direct provider sets REC_PAYLOAD_DONE, while an
        // initiator on the bus is done once it has written IMAGE_SIZE.
        let still_filling = if bypass {
            !payload_done
        } else {
            !image_complete
        };
        let visible_occupancy = if still_filling { 0 } else { occupancy };

        self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_0
            .reg
            .modify(
                IndirectFifoStatus0::Empty.val(u32::from(visible_occupancy == 0))
                    + IndirectFifoStatus0::Full
                        .val(u32::from(visible_occupancy >= INDIRECT_FIFO_SIZE_DWORDS)),
            );

        let activated = self
            .i3c_ec_sec_fw_recovery_if_recovery_ctrl
            .reg
            .read(RecoveryCtrl::ActivateRecImg)
            == 0xf;
        // Latched exactly like payload_available_q: raised by the trigger and
        // held until firmware drains the FIFO. It must not follow the trigger
        // down -- an AXI-direct provider clears REC_PAYLOAD_DONE as soon as it
        // activates the image, long before the DMA has read a word.
        let raise = if bypass {
            payload_done
        } else {
            image_complete || activated
        };
        if raise && occupancy != 0 {
            self.payload_available = true;
        } else if occupancy == 0 {
            self.payload_available = false;
        }
    }

    /// Drops FIFO contents and rewinds both indices, leaving IMAGE_SIZE alone.
    fn reset_indirect_fifo(&mut self) {
        self.indirect_fifo_data.clear();
        self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1
            .reg
            .set(0);
        self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_2
            .reg
            .set(0);
        self.update_indirect_fifo_status();
    }

    /// Clears the state the recovery handler holds in reset while the recovery
    /// interface is neither selected nor in AXI bypass.
    fn soft_reset_recovery(&mut self) {
        self.set_recovery_mode(false, "interface deselected");
        self.reset_indirect_fifo();
        self.i3c_ec_sec_fw_recovery_if_device_status_0
            .reg
            .modify(DeviceStatus0::ProtError.val(0));
    }
}

impl I3cPeripheral for I3c {
    fn generated(&mut self) -> Option<&mut I3cGenerated> {
        Some(&mut self.generated)
    }

    fn register_event_channels(
        &mut self,
        events_to_caliptra: mpsc::Sender<Event>,
        events_from_caliptra: mpsc::Receiver<Event>,
        events_to_mcu: mpsc::Sender<Event>,
        events_from_mcu: mpsc::Receiver<Event>,
    ) {
        self.events_to_caliptra = Some(events_to_caliptra);
        self.events_from_caliptra = Some(events_from_caliptra);
        self.events_to_mcu = Some(events_to_mcu);
        self.events_from_mcu = Some(events_from_mcu);
    }
    fn read_i3c_base_hci_version(&mut self) -> RvData {
        RvData::from(Self::HCI_VERSION)
    }

    fn read_i3c_ec_tti_status(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::i3c::bits::Status::Register,
    > {
        self.ibi_status
            .take()
            .unwrap_or_else(|| ReadWriteRegister::new(0))
    }

    fn read_i3c_ec_tti_interrupt_enable(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::i3c::bits::InterruptEnable::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.interrupt_enable.reg.get())
    }

    fn read_i3c_ec_tti_interrupt_status(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::i3c::bits::InterruptStatus::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.interrupt_status.reg.get())
    }

    fn write_i3c_ec_tti_interrupt_status(
        &mut self,

        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::i3c::bits::InterruptStatus::Register,
        >,
    ) {
        let current = self.interrupt_status.reg.get();
        let new = val.reg.get();
        // clear the interrupts that are set
        self.interrupt_status.reg.set(current & !new);
        // W1C on INTERRUPT_STATUS also releases the matching INTERRUPT_FORCE bits
        let forced = self.interrupt_force.reg.get();
        self.interrupt_force.reg.set(forced & !new);
        self.check_interrupts();
    }

    fn write_i3c_ec_tti_interrupt_enable(
        &mut self,

        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::i3c::bits::InterruptEnable::Register,
        >,
    ) {
        self.interrupt_enable.reg.set(val.reg.get());
    }

    fn read_i3c_ec_tti_interrupt_force(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::i3c::bits::InterruptForce::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.interrupt_force.reg.get())
    }

    fn write_i3c_ec_tti_interrupt_force(
        &mut self,

        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::i3c::bits::InterruptForce::Register,
        >,
    ) {
        let forced = self.interrupt_force.reg.get();
        self.interrupt_force.reg.set(forced | val.reg.get());
        self.check_interrupts();
    }

    fn write_i3c_ec_tti_tti_ibi_port(&mut self, val: RvData) {
        self.tti_ibi_buffer
            .extend_from_slice(val.to_le_bytes().as_ref());
        self.check_ibi_buffer();
        self.check_interrupts();
    }

    fn read_i3c_ec_stdby_ctrl_mode_stby_cr_capabilities(
        &mut self,
    ) -> ReadWriteRegister<u32, StbyCrCapabilities::Register> {
        ReadWriteRegister::new(StbyCrCapabilities::TargetXactSupport.val(1).value)
    }

    fn read_i3c_ec_stdby_ctrl_mode_stby_cr_device_addr(
        &mut self,
    ) -> ReadWriteRegister<u32, StbyCrDeviceAddr::Register> {
        let val = match self.i3c_target.get_address() {
            Some(addr) => {
                StbyCrDeviceAddr::DynamicAddr.val(addr.into())
                    + StbyCrDeviceAddr::DynamicAddrValid::SET
            }
            None => StbyCrDeviceAddr::StaticAddr.val(0x3d) + StbyCrDeviceAddr::StaticAddrValid::SET,
        };
        ReadWriteRegister::new(val.value)
    }

    fn read_i3c_ec_tti_extcap_header(&mut self) -> ReadWriteRegister<u32, ExtcapHeader::Register> {
        ReadWriteRegister::new(ExtcapHeader::CapId.val(0xc4).value)
    }

    fn read_i3c_ec_tti_rx_desc_queue_port(&mut self) -> u32 {
        self.tti_rx_current = self.tti_rx_data_raw.pop_front().unwrap_or_default().into();
        self.tti_rx_desc_queue_raw.pop_front().unwrap_or(0)
    }

    fn read_i3c_ec_tti_rx_data_port(&mut self) -> u32 {
        let mut data = self.tti_rx_current.pop_front().unwrap_or(0) as u32;
        data |= (self.tti_rx_current.pop_front().unwrap_or(0) as u32) << 8;
        data |= (self.tti_rx_current.pop_front().unwrap_or(0) as u32) << 16;
        data |= (self.tti_rx_current.pop_front().unwrap_or(0) as u32) << 24;
        data
    }

    fn write_i3c_ec_tti_tx_desc_queue_port(&mut self, val: u32) {
        self.tti_tx_desc_queue_raw.push_back(val);
        self.tti_tx_data_raw.push_back(vec![]);
        self.write_tx_data_into_target();
    }

    fn write_i3c_ec_tti_tx_data_port(&mut self, val: u32) {
        if self.hw_revision == Version::new(2, 0, 0) {
            // for HW revision 2.0.0, data is written to i3c core target
            self.tti_tx_data_raw
                .back_mut()
                .unwrap()
                .extend_from_slice(&val.to_le_bytes());
            self.write_tx_data_into_target();
        } else {
            // for HW revision 2.1.0 and later, data can be written to i3c core or recovery interface
            let bypass_cfg = self
                .i3c_ec_soc_mgmt_if_rec_intf_cfg
                .reg
                .read(RecIntfCfg::RecIntfBypass);
            if bypass_cfg == I3C_REC_INT_BYPASS_I3C_CORE {
                let to_append = val.to_le_bytes();
                let idx = self.tti_tx_data_raw.len() - 1;
                self.tti_tx_data_raw[idx].extend_from_slice(&to_append);
                self.write_tx_data_into_target();
            } else if bypass_cfg == I3C_REC_INT_BYPASS_AXI_DIRECT {
                let cms = self
                    .i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0
                    .reg
                    .read(IndirectFifoCtrl0::Cms);
                if cms != 0 {
                    println!("CMS {cms} not supported");
                    return;
                }

                let write_index = self
                    .i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1
                    .reg
                    .get();
                let address = (write_index * 4) as usize;
                self.indirect_fifo_data.resize(
                    address + std::mem::size_of::<caliptra_emu_types::RvData>(),
                    0,
                );
                self.indirect_fifo_data
                    [address..address + std::mem::size_of::<caliptra_emu_types::RvData>()]
                    .copy_from_slice(val.to_le_bytes().as_ref());
                // head pointer must be aligned to 4 bytes at the end
                self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1
                    .reg
                    .set(
                        ((address + std::mem::size_of::<caliptra_emu_types::RvData>())
                            .next_multiple_of(std::mem::size_of::<u32>())
                            / std::mem::size_of::<u32>()) as u32,
                    );
                self.update_indirect_fifo_status();
            } else {
                println!("[I3C-Emulator] Unknown bypass configuration: {bypass_cfg}");
            }
        }
    }

    fn read_i3c_ec_tti_tti_queue_size(&mut self) -> ReadWriteRegister<u32, TtiQueueSize::Register> {
        ReadWriteRegister::new(
            (TtiQueueSize::RxDataBufferSize.val(5)
                + TtiQueueSize::TxDataBufferSize.val(5)
                + TtiQueueSize::RxDescBufferSize.val(5)
                + TtiQueueSize::TxDescBufferSize.val(5))
            .value,
        )
    }

    fn write_i3c_ec_sec_fw_recovery_if_prot_cap_2(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::i3c::bits::ProtCap2::Register,
        >,
    ) {
        self.i3c_ec_sec_fw_recovery_if_prot_cap_2
            .reg
            .set(val.reg.get());
    }

    fn read_i3c_ec_sec_fw_recovery_if_prot_cap_2(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::i3c::bits::ProtCap2::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(
            self.i3c_ec_sec_fw_recovery_if_prot_cap_2.reg.get(),
        )
    }

    fn write_i3c_ec_sec_fw_recovery_if_device_status_0(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::i3c::bits::DeviceStatus0::Register,
        >,
    ) {
        let current_status = self
            .i3c_ec_sec_fw_recovery_if_device_status_0
            .reg
            .read(DeviceStatus0::DevStatus);
        // DevStatus is 0x3 when the device is ready for a new image
        if val.reg.read(DeviceStatus0::DevStatus) == 0x3 && current_status != 0x3 {
            // Reset the device status, when the device is ready for a new image.
            // IMAGE_SIZE and ACTIVATE_REC_IMG must go too: a stage that inherits
            // them makes firmware size the next DMA from the previous image and
            // treat it as already activated.
            self.i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0
                .reg
                .set(0);
            self.i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1
                .reg
                .set(0);
            self.i3c_ec_sec_fw_recovery_if_recovery_ctrl
                .reg
                .modify(RecoveryCtrl::ActivateRecImg.val(0));
            self.reset_indirect_fifo();
        }
        self.i3c_ec_sec_fw_recovery_if_device_status_0
            .reg
            .set(val.reg.get());
    }

    fn read_i3c_ec_sec_fw_recovery_if_device_status_0(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::i3c::bits::DeviceStatus0::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(
            self.i3c_ec_sec_fw_recovery_if_device_status_0.reg.get(),
        )
    }

    fn write_i3c_ec_sec_fw_recovery_if_recovery_status(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::i3c::bits::RecoveryStatus::Register,
        >,
    ) {
        self.i3c_ec_sec_fw_recovery_if_recovery_status
            .reg
            .set(val.reg.get());
    }

    fn read_i3c_ec_sec_fw_recovery_if_recovery_status(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::i3c::bits::RecoveryStatus::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(
            self.i3c_ec_sec_fw_recovery_if_recovery_status.reg.get(),
        )
    }

    fn write_i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::i3c::bits::IndirectFifoCtrl0::Register,
        >,
    ) {
        self.i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0
            .reg
            .set(val.reg.get());
        if val.reg.read(IndirectFifoCtrl0::Reset) != 0 {
            self.reset_indirect_fifo();
        } else {
            self.update_indirect_fifo_status();
        }
    }

    fn read_i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1(
        &mut self,
    ) -> caliptra_emu_types::RvData {
        caliptra_emu_types::RvData::from(
            self.i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1
                .reg
                .get(),
        )
    }

    fn write_i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1(
        &mut self,
        val: caliptra_emu_types::RvData,
    ) {
        self.i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1
            .reg
            .set(val);
        self.reset_indirect_fifo();
    }

    fn read_i3c_ec_sec_fw_recovery_if_indirect_fifo_data(&mut self) -> caliptra_emu_types::RvData {
        let cms = self
            .i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0
            .reg
            .read(IndirectFifoCtrl0::Cms);
        if cms != 0 {
            println!("CMS {cms} not supported");
            return 0xffff_ffff;
        }

        let read_index = self
            .i3c_ec_sec_fw_recovery_if_indirect_fifo_status_2
            .reg
            .get();
        let write_index = self
            .i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1
            .reg
            .get();
        let image_dwords = self
            .i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_1
            .reg
            .get();
        // Underflow: firmware may drain faster than the initiator streams, so
        // the read is bounded by what has actually been pushed, not by the
        // declared image size.
        let address = read_index as usize * std::mem::size_of::<u32>();
        if read_index >= write_index
            || (image_dwords != 0 && read_index >= image_dwords)
            || address + 4 > self.indirect_fifo_data.len()
        {
            return 0xffff_ffff;
        }

        let word = u32::from_le_bytes(
            self.indirect_fifo_data[address..address + 4]
                .try_into()
                .unwrap(),
        );
        self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_2
            .reg
            .set(read_index + 1);
        self.update_indirect_fifo_status();

        word
    }

    fn read_i3c_ec_sec_fw_recovery_if_indirect_fifo_status_0(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::i3c::bits::IndirectFifoStatus0::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(
            self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_0
                .reg
                .get(),
        )
    }

    fn read_i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1(
        &mut self,
    ) -> caliptra_emu_types::RvData {
        caliptra_emu_types::RvData::from(
            self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_1
                .reg
                .get(),
        )
    }

    fn read_i3c_ec_sec_fw_recovery_if_indirect_fifo_status_2(
        &mut self,
    ) -> caliptra_emu_types::RvData {
        caliptra_emu_types::RvData::from(
            self.i3c_ec_sec_fw_recovery_if_indirect_fifo_status_2
                .reg
                .get(),
        )
    }

    fn read_i3c_ec_sec_fw_recovery_if_indirect_fifo_status_3(
        &mut self,
    ) -> caliptra_emu_types::RvData {
        INDIRECT_FIFO_SIZE_DWORDS
    }

    fn read_i3c_ec_sec_fw_recovery_if_indirect_fifo_status_4(
        &mut self,
    ) -> caliptra_emu_types::RvData {
        INDIRECT_FIFO_MAX_TRANSFER_DWORDS
    }

    fn read_i3c_ec_sec_fw_recovery_if_device_reset(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::i3c::bits::DeviceReset::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(
            self.i3c_ec_sec_fw_recovery_if_device_reset.reg.get(),
        )
    }

    fn write_i3c_ec_sec_fw_recovery_if_device_reset(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::i3c::bits::DeviceReset::Register,
        >,
    ) {
        let previous = self
            .i3c_ec_sec_fw_recovery_if_device_reset
            .reg
            .read(DeviceReset::ResetCtrl);
        let requested = val.reg.read(DeviceReset::ResetCtrl);
        self.i3c_ec_sec_fw_recovery_if_device_reset
            .reg
            .set(val.reg.get());
        // Only the recovery interface is reset here; the rest of the device is
        // outside this model.
        if requested != 0 && previous == 0 {
            self.reset_indirect_fifo();
            self.i3c_ec_sec_fw_recovery_if_device_status_0
                .reg
                .modify(DeviceStatus0::ProtError.val(0));
        }
    }

    fn read_i3c_ec_sec_fw_recovery_if_recovery_ctrl(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::i3c::bits::RecoveryCtrl::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(
            self.i3c_ec_sec_fw_recovery_if_recovery_ctrl.reg.get(),
        )
    }

    fn read_i3c_ec_soc_mgmt_if_rec_intf_reg_w1_c_access(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::i3c::bits::RecIntfRegW1cAccess::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(
            self.i3c_ec_soc_mgmt_if_rec_intf_reg_w1_c_access.reg.get(),
        )
    }

    fn write_i3c_ec_sec_fw_recovery_if_recovery_ctrl(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::i3c::bits::RecoveryCtrl::Register,
        >,
    ) {
        self.i3c_ec_sec_fw_recovery_if_recovery_ctrl
            .reg
            .set(val.reg.get());
        self.update_indirect_fifo_status();
    }
    fn read_i3c_ec_soc_mgmt_if_rec_intf_cfg(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::i3c::bits::RecIntfCfg::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.i3c_ec_soc_mgmt_if_rec_intf_cfg.reg.get())
    }
    fn write_i3c_ec_soc_mgmt_if_rec_intf_cfg(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::i3c::bits::RecIntfCfg::Register,
        >,
    ) {
        let was_bypassed = self
            .i3c_ec_soc_mgmt_if_rec_intf_cfg
            .reg
            .read(RecIntfCfg::RecIntfBypass)
            == I3C_REC_INT_BYPASS_AXI_DIRECT;
        self.i3c_ec_soc_mgmt_if_rec_intf_cfg.reg.set(val.reg.get());
        // Handing the interface back from AXI bypass releases the recovery
        // handler state the RTL holds in reset.
        if was_bypassed
            && val.reg.read(RecIntfCfg::RecIntfBypass) == I3C_REC_INT_BYPASS_I3C_CORE
            && !self.recovery_mode_enabled
        {
            self.soft_reset_recovery();
        } else {
            self.update_indirect_fifo_status();
        }
    }

    fn write_i3c_base_hc_control(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::i3c::bits::HcControl::Register,
        >,
    ) {
        i3c_log!("write HC_CONTROL = {:#010x}", val.reg.get());
        self.i3c_base_hc_control.reg.set(val.reg.get());
    }

    fn read_i3c_base_hc_control(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::i3c::bits::HcControl::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.i3c_base_hc_control.reg.get())
    }

    fn write_i3c_ec_soc_mgmt_if_rec_intf_reg_w1_c_access(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::i3c::bits::RecIntfRegW1cAccess::Register,
        >,
    ) {
        self.i3c_ec_soc_mgmt_if_rec_intf_reg_w1_c_access
            .reg
            .set(val.reg.get());

        // Update recovery ctrl register
        let new_activate_rec_img = self
            .i3c_ec_soc_mgmt_if_rec_intf_reg_w1_c_access
            .reg
            .read(caliptra_mcu_registers_generated::i3c::bits::RecIntfRegW1cAccess::RecoveryCtrlActivateRecImg);

        let recovery_ctrl = self.read_i3c_ec_sec_fw_recovery_if_recovery_ctrl();
        recovery_ctrl
            .reg
            .modify(RecoveryCtrl::ActivateRecImg.val(new_activate_rec_img));
        self.write_i3c_ec_sec_fw_recovery_if_recovery_ctrl(recovery_ctrl);

        // Update indirect memory reset
        let new_indirect_fifo_reset = self.i3c_ec_soc_mgmt_if_rec_intf_reg_w1_c_access.reg.read(
            caliptra_mcu_registers_generated::i3c::bits::RecIntfRegW1cAccess::IndirectFifoCtrlReset,
        );
        let indirect_fifo_ctrl_0 = self.read_i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0();
        indirect_fifo_ctrl_0
            .reg
            .modify(IndirectFifoCtrl0::Reset.val(new_indirect_fifo_reset));
        self.write_i3c_ec_sec_fw_recovery_if_indirect_fifo_ctrl_0(indirect_fifo_ctrl_0);

        // Update device reset
        let new_device_reset = self.i3c_ec_soc_mgmt_if_rec_intf_reg_w1_c_access.reg.read(
            caliptra_mcu_registers_generated::i3c::bits::RecIntfRegW1cAccess::DeviceResetCtrl,
        );
        let device_reset = self.read_i3c_ec_sec_fw_recovery_if_device_reset();
        device_reset.reg.modify(
            caliptra_mcu_registers_generated::i3c::bits::DeviceReset::ResetCtrl
                .val(new_device_reset),
        );
        self.write_i3c_ec_sec_fw_recovery_if_device_reset(device_reset);

        self.update_indirect_fifo_status();
    }

    fn poll(&mut self) {
        self.check_interrupts();
        self.read_rx_data_into_buffer();
        self.drain_recovery_wire_commands();
        self.write_tx_data_into_target();
        self.timer.schedule_poll_in(Self::HCI_TICKS);

        if let Some(events_from_caliptra) = &self.events_from_caliptra {
            // Collect all events first to avoid borrowing issues
            let mut events = Vec::new();
            while let Ok(event) = events_from_caliptra.try_recv() {
                events.push(event);
            }
            // Now process events
            for event in events {
                match event.dest {
                    Device::RecoveryIntf => {
                        self.incoming_caliptra_event(event);
                    }
                    // route to the MCU
                    Device::MCU => {
                        self.events_to_mcu.as_mut().unwrap().send(event).unwrap();
                    }
                    Device::ExternalTestSram => {
                        self.events_to_mcu.as_mut().unwrap().send(event).unwrap();
                    }
                    Device::McuMbox0Sram => {
                        self.events_to_mcu.as_mut().unwrap().send(event).unwrap();
                    }
                    Device::McuMbox1Sram => {
                        self.events_to_mcu.as_mut().unwrap().send(event).unwrap();
                    }
                    _ => {}
                }
            }
        }
        if let Some(events_from_mcu) = &self.events_from_mcu {
            // Collect all events first to avoid borrowing issues
            let mut events = Vec::new();
            while let Ok(event) = events_from_mcu.try_recv() {
                events.push(event);
            }
            // Now process events
            for event in events {
                match event.dest {
                    Device::RecoveryIntf => {
                        self.incoming_mcu_event(event);
                    }
                    Device::CaliptraCore => {
                        self.events_to_caliptra
                            .as_mut()
                            .unwrap()
                            .send(event)
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_emu_bus::Bus;
    use caliptra_emu_cpu::Pic;
    use caliptra_emu_types::{RvAddr, RvSize};
    use caliptra_mcu_emulator_registers_generated::root_bus::AutoRootBus;
    use caliptra_mcu_testing_common::i3c::{
        DynamicI3cAddress, I3cTcriCommand, I3cTcriCommandXfer, ImmediateDataTransferCommand,
        ReguDataTransferCommand,
    };

    fn regular_recovery_cmd(
        command_code: u8,
        rnw: u8,
        data_length: u16,
    ) -> ReguDataTransferCommand {
        let mut cmd = ReguDataTransferCommand::read_from_bytes(&[0u8; 8][..]).unwrap();
        cmd.set_cmd(command_code);
        cmd.set_cp(1);
        cmd.set_rnw(rnw);
        cmd.set_data_length(data_length);
        cmd
    }

    const TTI_RX_DESC_QUEUE_PORT: RvAddr = 0x270;
    const TTI_INTERRUPT_STATUS: RvAddr = 0x220;
    const TTI_INTERRUPT_ENABLE: RvAddr = 0x224;
    const TTI_INTERRUPT_FORCE: RvAddr = 0x228;

    #[test]
    fn interrupt_force_sets_status_until_w1c() {
        let clock = Clock::new();
        let pic = Pic::new();
        let irq = pic.register_irq(2);
        let mut i3c_controller = I3cController::default();
        let step_lock = Arc::new(Mutex::new(()));
        let i3c = Box::new(I3c::new(
            &clock,
            &mut i3c_controller,
            irq,
            Version::new(2, 0, 0),
            step_lock,
        ));

        let mut bus = AutoRootBus::new(
            vec![],
            None,
            Some(i3c),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let base = caliptra_mcu_registers_generated::i3c::I3C_CSR_ADDR;
        let rx_desc_stat = 1u32 << InterruptStatus::RxDescStat.shift;

        bus.write(RvSize::Word, base + TTI_INTERRUPT_ENABLE, rx_desc_stat)
            .unwrap();
        bus.write(RvSize::Word, base + TTI_INTERRUPT_FORCE, rx_desc_stat)
            .unwrap();

        // The forced bit must survive polling, which recomputes RxDescStat from
        // the (empty) RX descriptor queue.
        for _ in 0..10000 {
            clock.increment_and_process_timer_actions(1, &mut bus);
        }
        assert_eq!(
            bus.read(RvSize::Word, base + TTI_INTERRUPT_STATUS).unwrap() & rx_desc_stat,
            rx_desc_stat
        );

        bus.write(RvSize::Word, base + TTI_INTERRUPT_STATUS, rx_desc_stat)
            .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, base + TTI_INTERRUPT_STATUS).unwrap() & rx_desc_stat,
            0
        );
        assert_eq!(
            bus.read(RvSize::Word, base + TTI_INTERRUPT_FORCE).unwrap(),
            0
        );
    }

    #[test]
    fn indirect_fifo_ctrl_block_packs_cms_and_size_separately() {
        // CMS and reset occupy only the low two bytes of INDIRECT_FIFO_CTRL_0;
        // the image size is a whole register. Chunking the 6-byte block into
        // 4-byte words instead would leave the size zero and stall recovery.
        let segments = recovery_block_segments(45).unwrap();
        assert_eq!(segments, vec![(0x048, 2), (0x04c, 4)]);
    }

    #[test]
    fn indirect_fifo_status_block_spans_whole_registers() {
        // Unlike INDIRECT_FIFO_CTRL, this block is not packed: the flags, write
        // index, read index, FIFO size and max transfer size each occupy a
        // whole register, so the block is 20 bytes and every 32-bit field stays
        // register-aligned on the wire.
        let (offset, len) = recovery_block(46).unwrap();
        assert_eq!((offset, len), (0x050, 20));
        assert_eq!(
            recovery_block_segments(46).unwrap(),
            vec![(0x050, 4), (0x054, 4), (0x058, 4), (0x05c, 4), (0x060, 4)]
        );
        // The declared length must match what the segments actually carry.
        let carried: usize = recovery_block_segments(46)
            .unwrap()
            .iter()
            .map(|(_, take)| take)
            .sum();
        assert_eq!(carried, len);
    }

    #[test]
    fn advertised_fifo_geometry_is_self_consistent() {
        // The initiator reads both fields and may fill the FIFO in one
        // transfer, so promising a larger transfer than the FIFO holds would
        // overrun the device.
        assert!(INDIRECT_FIFO_MAX_TRANSFER_DWORDS <= INDIRECT_FIFO_SIZE_DWORDS);
        // A full-depth chunk goes out wrapped in the block-write framing:
        // command code, two length bytes and a trailing PEC.
        const BLOCK_WRITE_FRAMING_BYTES: u32 = 1 + 2 + 1;
        assert_eq!(
            INDIRECT_FIFO_MAX_TRANSFER_DWORDS * 4 + BLOCK_WRITE_FRAMING_BYTES,
            260
        );
    }

    #[test]
    fn indirect_fifo_status_wire_read_places_sizes_at_the_documented_offsets() {
        let (clock, mut i3c_controller, mut bus) = recovery_test_bus();
        let recovery_addr = DynamicI3cAddress::new(9).unwrap();
        const INDIRECT_FIFO_STATUS: u8 = 46;

        i3c_controller
            .tcri_send(
                recovery_addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(wire_cmd(0, 1)),
                    data: vec![INDIRECT_FIFO_STATUS],
                },
            )
            .unwrap();
        i3c_controller
            .tcri_send(
                recovery_addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(wire_cmd(1, 22)),
                    data: Vec::new(),
                },
            )
            .unwrap();
        settle(&clock, &mut bus);

        let resp = i3c_controller.tcri_receive(recovery_addr).unwrap();
        assert_eq!(u16::from_le_bytes([resp.data[0], resp.data[1]]), 20);
        let payload = &resp.data[2..22];
        // Every field is a whole register, so each starts on a 4-byte boundary.
        let word = |at: usize| {
            u32::from_le_bytes([
                payload[at],
                payload[at + 1],
                payload[at + 2],
                payload[at + 3],
            ])
        };
        assert_eq!(word(4), 0, "write index");
        assert_eq!(word(8), 0, "read index");
        assert_eq!(word(12), INDIRECT_FIFO_SIZE_DWORDS, "FIFO size");
        assert_eq!(word(16), INDIRECT_FIFO_MAX_TRANSFER_DWORDS, "max transfer");
    }

    #[test]
    fn recovery_blocks_split_into_whole_registers() {
        assert_eq!(recovery_block_segments(38).unwrap(), vec![(0x03c, 3)]);
        assert_eq!(
            recovery_block_segments(36).unwrap(),
            vec![(0x030, 4), (0x034, 3)]
        );
        // The FIFO data port is not an array.
        assert!(recovery_block_segments(47).is_none());
    }

    /// Builds a bus + controller pair with the I3C peripheral attached.
    fn recovery_test_bus() -> (Clock, I3cController, AutoRootBus) {
        recovery_test_bus_rev(Version::new(2, 0, 0))
    }

    fn recovery_test_bus_rev(hw_revision: Version) -> (Clock, I3cController, AutoRootBus) {
        let clock = Clock::new();
        let pic = Pic::new();
        let irq = pic.register_irq(2);
        let mut i3c_controller = I3cController::default();
        let step_lock = Arc::new(Mutex::new(()));
        let i3c = Box::new(I3c::new(
            &clock,
            &mut i3c_controller,
            irq,
            hw_revision,
            step_lock,
        ));
        let bus = AutoRootBus::new(
            vec![],
            None,
            Some(i3c),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        (clock, i3c_controller, bus)
    }

    fn settle(clock: &Clock, bus: &mut AutoRootBus) {
        for _ in 0..10000 {
            clock.increment_and_process_timer_actions(1, bus);
        }
    }

    const INDIRECT_FIFO_CTRL_1_REG: RvAddr = 0x14c;
    const INDIRECT_FIFO_STATUS_0_REG: RvAddr = 0x150;
    const INDIRECT_FIFO_DATA_REG: RvAddr = 0x168;
    const DEVICE_STATUS_0_REG: RvAddr = 0x130;
    const RECOVERY_CTRL_REG_ADDR: RvAddr = 0x13c;

    #[test]
    fn fifo_read_past_the_write_pointer_does_not_panic() {
        // Firmware may drain faster than the initiator streams. Declaring a
        // four-word image and pushing only one must underflow, not index past
        // the backing store.
        let (clock, mut i3c_controller, mut bus) = recovery_test_bus();
        let base = caliptra_mcu_registers_generated::i3c::I3C_CSR_ADDR;
        let addr = DynamicI3cAddress::new(8).unwrap();

        i3c_controller
            .tcri_send(
                addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(regular_recovery_cmd(45, 0, 6)),
                    data: vec![0, 0, 4, 0, 0, 0],
                },
            )
            .unwrap();
        i3c_controller
            .tcri_send(
                addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(regular_recovery_cmd(47, 0, 4)),
                    data: vec![0xAA, 0xBB, 0xCC, 0xDD],
                },
            )
            .unwrap();
        settle(&clock, &mut bus);

        assert_eq!(
            bus.read(RvSize::Word, base + INDIRECT_FIFO_CTRL_1_REG)
                .unwrap(),
            4
        );
        assert_eq!(
            bus.read(RvSize::Word, base + INDIRECT_FIFO_DATA_REG)
                .unwrap(),
            0xDDCC_BBAA
        );
        // Only one of the four declared words was pushed.
        assert_eq!(
            bus.read(RvSize::Word, base + INDIRECT_FIFO_DATA_REG)
                .unwrap(),
            0xffff_ffff
        );
    }

    #[test]
    fn fifo_empty_is_reasserted_once_drained() {
        let (clock, mut i3c_controller, mut bus) = recovery_test_bus();
        let base = caliptra_mcu_registers_generated::i3c::I3C_CSR_ADDR;
        let addr = DynamicI3cAddress::new(8).unwrap();
        let empty = 1u32 << IndirectFifoStatus0::Empty.shift;

        i3c_controller
            .tcri_send(
                addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(regular_recovery_cmd(45, 0, 6)),
                    data: vec![0, 0, 1, 0, 0, 0],
                },
            )
            .unwrap();
        i3c_controller
            .tcri_send(
                addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(regular_recovery_cmd(47, 0, 4)),
                    data: vec![1, 2, 3, 4],
                },
            )
            .unwrap();
        settle(&clock, &mut bus);

        assert_eq!(
            bus.read(RvSize::Word, base + INDIRECT_FIFO_STATUS_0_REG)
                .unwrap()
                & empty,
            0
        );
        bus.read(RvSize::Word, base + INDIRECT_FIFO_DATA_REG)
            .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, base + INDIRECT_FIFO_STATUS_0_REG)
                .unwrap()
                & empty,
            empty
        );
    }

    #[test]
    fn entering_recovery_mode_clears_the_previous_stage() {
        // A stage that inherits IMAGE_SIZE or ACTIVATE_REC_IMG sizes its DMA
        // from the previous image and looks pre-activated.
        let (clock, mut i3c_controller, mut bus) = recovery_test_bus();
        let base = caliptra_mcu_registers_generated::i3c::I3C_CSR_ADDR;
        let addr = DynamicI3cAddress::new(8).unwrap();

        i3c_controller
            .tcri_send(
                addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(regular_recovery_cmd(45, 0, 6)),
                    data: vec![0, 0, 8, 0, 0, 0],
                },
            )
            .unwrap();
        i3c_controller
            .tcri_send(
                addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(regular_recovery_cmd(38, 0, 3)),
                    data: vec![0x00, 0x00, 0x0f],
                },
            )
            .unwrap();
        settle(&clock, &mut bus);
        assert_eq!(
            bus.read(RvSize::Word, base + INDIRECT_FIFO_CTRL_1_REG)
                .unwrap(),
            8
        );

        bus.write(RvSize::Word, base + DEVICE_STATUS_0_REG, 0x3)
            .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, base + INDIRECT_FIFO_CTRL_1_REG)
                .unwrap(),
            0
        );
        assert_eq!(
            bus.read(RvSize::Word, base + RECOVERY_CTRL_REG_ADDR)
                .unwrap()
                >> RecoveryCtrl::ActivateRecImg.shift,
            0
        );
    }

    #[test]
    fn unsupported_recovery_command_is_not_forwarded_to_mctp() {
        let (clock, mut i3c_controller, mut bus) = recovery_test_bus();
        let base = caliptra_mcu_registers_generated::i3c::I3C_CSR_ADDR;
        let addr = DynamicI3cAddress::new(8).unwrap();

        // Command 44 (Vendor) has no block mapping.
        i3c_controller
            .tcri_send(
                addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(regular_recovery_cmd(44, 0, 4)),
                    data: vec![1, 2, 3, 4],
                },
            )
            .unwrap();
        settle(&clock, &mut bus);

        assert_eq!(
            bus.read(RvSize::Word, base + TTI_RX_DESC_QUEUE_PORT)
                .unwrap(),
            0
        );
        assert_eq!(
            (bus.read(RvSize::Word, base + DEVICE_STATUS_0_REG).unwrap()
                >> DeviceStatus0::ProtError.shift)
                & 0xff,
            PROT_ERROR_UNSUPPORTED
        );
    }

    #[test]
    fn write_to_a_read_only_recovery_block_is_rejected() {
        let (clock, mut i3c_controller, mut bus) = recovery_test_bus();
        let base = caliptra_mcu_registers_generated::i3c::I3C_CSR_ADDR;
        let addr = DynamicI3cAddress::new(8).unwrap();

        // RECOVERY_STATUS (39) is device owned.
        i3c_controller
            .tcri_send(
                addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(regular_recovery_cmd(39, 0, 2)),
                    data: vec![0xAB, 0xCD],
                },
            )
            .unwrap();
        settle(&clock, &mut bus);

        assert_eq!(bus.read(RvSize::Word, base + 0x140).unwrap(), 0);
        assert_eq!(
            (bus.read(RvSize::Word, base + DEVICE_STATUS_0_REG).unwrap()
                >> DeviceStatus0::ProtError.shift)
                & 0xff,
            PROT_ERROR_UNSUPPORTED
        );
    }

    #[test]
    fn block_write_with_a_bad_pec_is_dropped() {
        let (clock, mut i3c_controller, mut bus) = recovery_test_bus();
        let base = caliptra_mcu_registers_generated::i3c::I3C_CSR_ADDR;
        let addr = DynamicI3cAddress::new(8).unwrap();

        let payload = [0xEF, 0xBE, 0x00];
        let good = recovery_write_pec(u8::from(addr), 38, &payload);
        i3c_controller
            .tcri_send(
                addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(regular_recovery_cmd(38, 0, 4)),
                    data: vec![payload[0], payload[1], payload[2], good ^ 0xff],
                },
            )
            .unwrap();
        settle(&clock, &mut bus);
        assert_eq!(
            bus.read(RvSize::Word, base + RECOVERY_CTRL_REG_ADDR)
                .unwrap()
                & 0xFFFF,
            0
        );

        i3c_controller
            .tcri_send(
                addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(regular_recovery_cmd(38, 0, 4)),
                    data: vec![payload[0], payload[1], payload[2], good],
                },
            )
            .unwrap();
        settle(&clock, &mut bus);
        assert_eq!(
            bus.read(RvSize::Word, base + RECOVERY_CTRL_REG_ADDR)
                .unwrap()
                & 0xFFFF,
            0xBEEF
        );
    }

    #[test]
    fn indirect_fifo_ctrl_reset_bit_empties_the_fifo() {
        let (clock, mut i3c_controller, mut bus) = recovery_test_bus();
        let base = caliptra_mcu_registers_generated::i3c::I3C_CSR_ADDR;
        let addr = DynamicI3cAddress::new(8).unwrap();
        let empty = 1u32 << IndirectFifoStatus0::Empty.shift;

        // A one-DWORD image, so the single write below completes it and the
        // occupancy becomes visible rather than being hidden mid-fill.
        i3c_controller
            .tcri_send(
                addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(regular_recovery_cmd(45, 0, 6)),
                    data: vec![0, 0, 1, 0, 0, 0],
                },
            )
            .unwrap();
        i3c_controller
            .tcri_send(
                addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(regular_recovery_cmd(47, 0, 4)),
                    data: vec![1, 2, 3, 4],
                },
            )
            .unwrap();
        settle(&clock, &mut bus);
        assert_eq!(
            bus.read(RvSize::Word, base + INDIRECT_FIFO_STATUS_0_REG)
                .unwrap()
                & empty,
            0
        );

        // RESET lives in the second byte of INDIRECT_FIFO_CTRL_0.
        bus.write(
            RvSize::Word,
            base + 0x148,
            1 << IndirectFifoCtrl0::Reset.shift,
        )
        .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, base + INDIRECT_FIFO_STATUS_0_REG)
                .unwrap()
                & empty,
            empty
        );
    }

    #[test]
    fn pec_matches_the_mctp_i3c_binding_polynomial() {
        assert_eq!(crc8_pec(&[]), 0x00);
        assert_eq!(crc8_pec(&[0x00]), 0x00);
        // CRC-8/SMBUS check value over "123456789".
        assert_eq!(crc8_pec(b"123456789"), 0xF4);
    }

    #[test]
    fn wire_address_byte_carries_the_direction_in_bit_0() {
        assert_eq!(wire_address_byte(0x09, false), 0x12);
        assert_eq!(wire_address_byte(0x09, true), 0x13);
        assert_eq!(wire_address_byte(0x08, false), 0x10);
    }

    /// The PEC accompanying a block read's command byte is seeded with the write
    /// address phase. Omitting it produces a value no controller will accept, so
    /// these vectors pin the address into the CRC.
    #[test]
    fn command_pec_covers_the_write_address_phase() {
        // Equivalent to CRC-8 over [addr << 1 | W, CMD].
        assert_eq!(recovery_command_pec(0x09, 34), crc8_pec(&[0x12, 34]));
        assert_eq!(recovery_command_pec(0x09, 36), crc8_pec(&[0x12, 36]));

        // The address must actually change the result, otherwise it is not
        // contributing to the CRC.
        assert_ne!(
            recovery_command_pec(0x09, 34),
            recovery_command_pec(0x08, 34)
        );
        assert_ne!(recovery_command_pec(0x09, 34), crc8_pec(&[34]));
    }

    /// A block write's PEC covers the address phase, the command, the 16-bit
    /// length and the payload, in that order.
    #[test]
    fn block_write_pec_covers_address_command_and_length() {
        let payload = [0xEF, 0xBE, 0x00];
        let mut expected = vec![0x12u8, 38];
        expected.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        expected.extend_from_slice(&payload);
        assert_eq!(recovery_write_pec(0x09, 38, &payload), crc8_pec(&expected));
        assert_ne!(
            recovery_write_pec(0x09, 38, &payload),
            recovery_write_pec(0x08, 38, &payload)
        );
    }

    /// A block read turns the bus around with a repeated start, so both the
    /// write and the read address phases are covered.
    #[test]
    fn block_read_pec_covers_both_address_phases() {
        let payload = [0x01, 0x02];
        let mut expected = vec![0x12u8, 34, 0x13];
        expected.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        expected.extend_from_slice(&payload);
        assert_eq!(recovery_read_pec(0x09, 34, &payload), crc8_pec(&expected));
        // The read phase byte distinguishes it from a write of the same payload.
        assert_ne!(
            recovery_read_pec(0x09, 34, &payload),
            recovery_write_pec(0x09, 34, &payload)
        );
    }

    /// A real Recovery Initiator drives the OCP framing on the recovery address:
    /// a one-byte command write opens a read, and the response leads with the
    /// 16-bit block length.
    #[test]
    fn ocp_wire_framing_on_the_recovery_address() {
        let (clock, mut i3c_controller, mut bus) = recovery_test_bus();
        let recovery_addr = DynamicI3cAddress::new(9).unwrap();
        const PROT_CAP: u8 = 34;
        const RECOVERY_CTRL: u8 = 38;

        // Read PROT_CAP: private write of the command byte, then a private read
        // sized block + 2.
        i3c_controller
            .tcri_send(
                recovery_addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(wire_cmd(0, 1)),
                    data: vec![PROT_CAP],
                },
            )
            .unwrap();
        i3c_controller
            .tcri_send(
                recovery_addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(wire_cmd(1, 17)),
                    data: Vec::new(),
                },
            )
            .unwrap();
        settle(&clock, &mut bus);

        let resp = i3c_controller.tcri_receive(recovery_addr).unwrap();
        assert_eq!(u16::from_le_bytes([resp.data[0], resp.data[1]]), 15);
        // "OCP " / "RECV" magic, which the initiator checks first.
        assert_eq!(&resp.data[2..10], b"OCP RECV");

        // Block write: CMD, LEN_LSB, LEN_MSB, payload.
        i3c_controller
            .tcri_send(
                recovery_addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(wire_cmd(0, 6)),
                    data: vec![RECOVERY_CTRL, 3, 0, 0xEF, 0xBE, 0x00],
                },
            )
            .unwrap();
        settle(&clock, &mut bus);
        let base = caliptra_mcu_registers_generated::i3c::I3C_CSR_ADDR;
        assert_eq!(
            bus.read(RvSize::Word, base + RECOVERY_CTRL_REG_ADDR)
                .unwrap()
                & 0xFFFF,
            0xBEEF
        );
    }

    /// TCRI descriptor for the OCP framing: no CP, no command code, just the
    /// direction and length that a private transfer carries.
    fn wire_cmd(rnw: u8, data_length: u16) -> ReguDataTransferCommand {
        let mut cmd = ReguDataTransferCommand::read_from_bytes(&[0u8; 8][..]).unwrap();
        cmd.set_rnw(rnw);
        cmd.set_data_length(data_length);
        cmd
    }

    const REC_INTF_CFG_REG: RvAddr = 0x30c;
    const TTI_TX_DATA_PORT: RvAddr = 0x27c;

    const RECOVERY_STATUS_REG: RvAddr = 0x140;
    const W1C_ACCESS_REG: RvAddr = 0x310;
    const HC_CONTROL_REG: RvAddr = 0x004;

    /// DEVICE_STATUS / RECOVERY_STATUS codes from the OCP recovery
    /// specification.
    const AWAITING_RECOVERY_IMAGE: u32 = 0x1;
    const BOOTING_RECOVERY_IMAGE: u32 = 0x2;
    const RECOVERY_SUCCESS: u32 = 0x3;
    const RECOVERY_FAILED: u32 = 0xC;
    const AUTHENTICATION_ERROR: u32 = 0xD;
    const ACTIVATE_REC_IMG_CMD: u32 = 0xF;

    /// DEV_REC_STATUS and REC_IMG_INDEX share one register, so both have to
    /// survive a round trip independently. The device owns these transitions;
    /// this model only has to store them and expose them to both sides.
    #[test]
    fn recovery_status_state_machine_round_trips_every_stage() {
        let (_clock, _i3c_controller, mut bus) = recovery_test_bus();
        let base = caliptra_mcu_registers_generated::i3c::I3C_CSR_ADDR;

        // Awaiting -> Booting -> Success is the nominal path; 0xC and 0xD are
        // the failure codes, which negative testing needs to be able to reach
        // rather than have the model synthesise.
        for status in [
            AWAITING_RECOVERY_IMAGE,
            BOOTING_RECOVERY_IMAGE,
            RECOVERY_SUCCESS,
            RECOVERY_FAILED,
            AUTHENTICATION_ERROR,
        ] {
            bus.write(RvSize::Word, base + RECOVERY_STATUS_REG, status)
                .unwrap();
            assert_eq!(
                bus.read(RvSize::Word, base + RECOVERY_STATUS_REG).unwrap() & 0xf,
                status,
                "DEV_REC_STATUS {status:#x} must be observable by the recovery agent"
            );
        }

        // REC_IMG_INDEX shares the register and advances per activated image,
        // so a status update must not clobber it.
        for index in 1..=3u32 {
            let value = AWAITING_RECOVERY_IMAGE | (index << 4);
            bus.write(RvSize::Word, base + RECOVERY_STATUS_REG, value)
                .unwrap();
            let read = bus.read(RvSize::Word, base + RECOVERY_STATUS_REG).unwrap();
            assert_eq!(read & 0xf, AWAITING_RECOVERY_IMAGE);
            assert_eq!((read >> 4) & 0xff, index, "REC_IMG_INDEX must increment");
        }
    }

    /// ACTIVATE_REC_IMG is write-1-to-clear, so it is driven through the
    /// REC_INTF_REG_W1C_ACCESS alias rather than written to RECOVERY_CTRL
    /// directly. The mirror into RECOVERY_CTRL is what arms the image.
    #[test]
    fn w1c_access_mirrors_the_activate_bit_into_recovery_ctrl() {
        let (_clock, _i3c_controller, mut bus) = recovery_test_bus();
        let base = caliptra_mcu_registers_generated::i3c::I3C_CSR_ADDR;

        bus.write(
            RvSize::Word,
            base + W1C_ACCESS_REG,
            ACTIVATE_REC_IMG_CMD
                << caliptra_mcu_registers_generated::i3c::bits::RecIntfRegW1cAccess::RecoveryCtrlActivateRecImg.shift,
        )
        .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, base + RECOVERY_CTRL_REG_ADDR)
                .unwrap()
                >> RecoveryCtrl::ActivateRecImg.shift
                & 0xff,
            ACTIVATE_REC_IMG_CMD,
            "W1C access must arm ACTIVATE_REC_IMG"
        );
    }

    /// HC_CONTROL parks the I3C PHY while the AXI path owns the recovery
    /// interface. It used to fall through to a non-functional stub, so a value
    /// written to it never read back.
    #[test]
    fn hc_control_retains_the_bus_enable_bit() {
        let (_clock, _i3c_controller, mut bus) = recovery_test_bus();
        let base = caliptra_mcu_registers_generated::i3c::I3C_CSR_ADDR;
        let bus_enable = 1u32 << 31;

        bus.write(RvSize::Word, base + HC_CONTROL_REG, bus_enable)
            .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, base + HC_CONTROL_REG).unwrap() & bus_enable,
            bus_enable
        );
        bus.write(RvSize::Word, base + HC_CONTROL_REG, 0).unwrap();
        assert_eq!(
            bus.read(RvSize::Word, base + HC_CONTROL_REG).unwrap() & bus_enable,
            0
        );
    }

    /// Walks one image through the AXI-direct recovery handshake in the order
    /// the registers are exercised: hand over the interface, wait for the
    /// device to be ready, size the image, stream it, activate it, then hand
    /// the interface back. A regression in any single register shows up here
    /// rather than as a boot that hangs with no indication of which step
    /// stalled.
    #[test]
    fn recovery_handshake_sequence_completes_an_image() {
        let (_clock, _i3c_controller, mut bus) = recovery_test_bus_rev(Version::new(2, 1, 0));
        let base = caliptra_mcu_registers_generated::i3c::I3C_CSR_ADDR;
        let empty = 1u32 << IndirectFifoStatus0::Empty.shift;
        const IMAGE_DWORDS: u32 = 128;

        // Park the PHY, then hand the recovery interface to the AXI path.
        bus.write(RvSize::Word, base + HC_CONTROL_REG, 0).unwrap();
        bus.write(
            RvSize::Word,
            base + REC_INTF_CFG_REG,
            I3C_REC_INT_BYPASS_AXI_DIRECT << RecIntfCfg::RecIntfBypass.shift,
        )
        .unwrap();

        // The device publishes readiness, then the image size is programmed
        // in dwords.
        bus.write(RvSize::Word, base + DEVICE_STATUS_0_REG, 0x3)
            .unwrap();
        bus.write(
            RvSize::Word,
            base + RECOVERY_STATUS_REG,
            AWAITING_RECOVERY_IMAGE,
        )
        .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, base + DEVICE_STATUS_0_REG).unwrap() & 0xf,
            0x3,
            "the agent waits here until the device accepts an image"
        );
        bus.write(RvSize::Word, base + INDIRECT_FIFO_CTRL_1_REG, IMAGE_DWORDS)
            .unwrap();

        // The image is streamed in fixed chunks, each gated on EMPTY. Progress
        // is only possible while EMPTY reads high, so this loop also proves the
        // agent cannot deadlock against a buffer nothing has drained yet.
        let mut written = 0;
        while written < IMAGE_DWORDS {
            assert_eq!(
                bus.read(RvSize::Word, base + INDIRECT_FIFO_STATUS_0_REG)
                    .unwrap()
                    & empty,
                empty,
                "EMPTY must stay set so streaming can continue"
            );
            for _ in 0..(AXI_RECOVERY_FIFO_DWORDS.min(IMAGE_DWORDS - written)) {
                bus.write(RvSize::Word, base + TTI_TX_DATA_PORT, 0xA5A5_5A5A)
                    .unwrap();
                written += 1;
            }
        }

        // Signal payload done, arm the image through the W1C alias, then drop
        // payload done again.
        bus.write(
            RvSize::Word,
            base + REC_INTF_CFG_REG,
            (I3C_REC_INT_BYPASS_AXI_DIRECT << RecIntfCfg::RecIntfBypass.shift)
                | (1 << RecIntfCfg::RecPayloadDone.shift),
        )
        .unwrap();
        bus.write(
            RvSize::Word,
            base + W1C_ACCESS_REG,
            ACTIVATE_REC_IMG_CMD
                << caliptra_mcu_registers_generated::i3c::bits::RecIntfRegW1cAccess::RecoveryCtrlActivateRecImg.shift,
        )
        .unwrap();
        bus.write(
            RvSize::Word,
            base + REC_INTF_CFG_REG,
            I3C_REC_INT_BYPASS_AXI_DIRECT << RecIntfCfg::RecIntfBypass.shift,
        )
        .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, base + RECOVERY_CTRL_REG_ADDR)
                .unwrap()
                >> RecoveryCtrl::ActivateRecImg.shift
                & 0xff,
            ACTIVATE_REC_IMG_CMD,
            "the image must stay armed after REC_PAYLOAD_DONE drops"
        );

        // The device reports the outcome and advances the image index, which is
        // what gates moving on to the next image.
        bus.write(
            RvSize::Word,
            base + RECOVERY_STATUS_REG,
            AWAITING_RECOVERY_IMAGE | (1 << 4),
        )
        .unwrap();

        // Give the bus back to the I3C PHY.
        bus.write(RvSize::Word, base + HC_CONTROL_REG, 1 << 31)
            .unwrap();
        bus.write(RvSize::Word, base + REC_INTF_CFG_REG, 0).unwrap();
        assert_eq!(
            bus.read(RvSize::Word, base + REC_INTF_CFG_REG).unwrap()
                >> RecIntfCfg::RecIntfBypass.shift
                & 0x1,
            0,
            "release must hand the interface back to the I3C core"
        );
    }

    /// Bytes streamed between EMPTY polls.
    const AXI_RECOVERY_FIFO_DWORDS: u32 = 256 / 4;

    #[test]
    #[test]
    fn recovery_initiator_is_never_back_pressured_by_full() {
        // An initiator on the bus streams the image through INDIRECT_FIFO_DATA
        // and polls EMPTY between chunks, exactly as an AXI-direct provider
        // does. The model has no background drain, so once a chunk the size of
        // the FIFO has landed, reporting real occupancy would latch FULL and
        // clear EMPTY forever -- only the device firmware drains this buffer,
        // and it does not start until the image is complete.
        let (clock, mut i3c_controller, mut bus) = recovery_test_bus();
        let base = caliptra_mcu_registers_generated::i3c::I3C_CSR_ADDR;
        let addr = DynamicI3cAddress::new(8).unwrap();
        let empty = 1u32 << IndirectFifoStatus0::Empty.shift;
        let full = 1u32 << IndirectFifoStatus0::Full.shift;

        // Two FIFO-depths' worth of image, so the first chunk alone fills it.
        let chunk_bytes = (INDIRECT_FIFO_SIZE_DWORDS * 4) as usize;
        let image_dwords = INDIRECT_FIFO_SIZE_DWORDS * 2;
        let size = image_dwords.to_le_bytes();
        i3c_controller
            .tcri_send(
                addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(regular_recovery_cmd(45, 0, 6)),
                    data: vec![0, 0, size[0], size[1], size[2], size[3]],
                },
            )
            .unwrap();

        let chunk = vec![0xA5u8; chunk_bytes];
        i3c_controller
            .tcri_send(
                addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(regular_recovery_cmd(47, 0, chunk_bytes as u16)),
                    data: chunk.clone(),
                },
            )
            .unwrap();
        settle(&clock, &mut bus);

        let status = bus
            .read(RvSize::Word, base + INDIRECT_FIFO_STATUS_0_REG)
            .unwrap();
        assert_eq!(
            status & full,
            0,
            "initiator must not be back-pressured mid-image"
        );
        assert_eq!(
            status & empty,
            empty,
            "initiator polls EMPTY between chunks and would otherwise deadlock"
        );

        // Completing the image hands the buffer to the device firmware, which
        // is when the occupancy becomes visible.
        i3c_controller
            .tcri_send(
                addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(regular_recovery_cmd(47, 0, chunk_bytes as u16)),
                    data: chunk,
                },
            )
            .unwrap();
        settle(&clock, &mut bus);
        assert_eq!(
            bus.read(RvSize::Word, base + INDIRECT_FIFO_STATUS_0_REG)
                .unwrap()
                & empty,
            0
        );
    }

    #[test]
    fn axi_direct_provider_is_never_back_pressured_by_empty() {
        // An image is streamed through TTI_TX_DATA_PORT in AXI bypass, polling
        // EMPTY between chunks. The model has no background drain, so reporting
        // the accumulated image as non-empty would stall the provider against a
        // buffer only the device drains.
        // AXI-direct streaming is a 2.1.0+ path.
        let (_clock, _i3c_controller, mut bus) = recovery_test_bus_rev(Version::new(2, 1, 0));
        let base = caliptra_mcu_registers_generated::i3c::I3C_CSR_ADDR;
        let empty = 1u32 << IndirectFifoStatus0::Empty.shift;

        bus.write(
            RvSize::Word,
            base + REC_INTF_CFG_REG,
            I3C_REC_INT_BYPASS_AXI_DIRECT << RecIntfCfg::RecIntfBypass.shift,
        )
        .unwrap();
        bus.write(RvSize::Word, base + INDIRECT_FIFO_CTRL_1_REG, 128)
            .unwrap();

        for _ in 0..64 {
            bus.write(RvSize::Word, base + TTI_TX_DATA_PORT, 0xAABB_CCDD)
                .unwrap();
        }
        assert_eq!(
            bus.read(RvSize::Word, base + INDIRECT_FIFO_STATUS_0_REG)
                .unwrap()
                & empty,
            empty,
            "provider must stay unblocked while it is still streaming"
        );

        // REC_PAYLOAD_DONE is how the provider signals its last chunk; only then
        // does the buffer become visible to the device firmware.
        bus.write(
            RvSize::Word,
            base + REC_INTF_CFG_REG,
            (I3C_REC_INT_BYPASS_AXI_DIRECT << RecIntfCfg::RecIntfBypass.shift)
                | (1 << RecIntfCfg::RecPayloadDone.shift),
        )
        .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, base + INDIRECT_FIFO_STATUS_0_REG)
                .unwrap()
                & empty,
            0
        );

        // Draining it deasserts again, which is what firmware waits on between
        // recovery stages.
        for _ in 0..64 {
            bus.read(RvSize::Word, base + INDIRECT_FIFO_DATA_REG)
                .unwrap();
        }
        assert_eq!(
            bus.read(RvSize::Word, base + INDIRECT_FIFO_STATUS_0_REG)
                .unwrap()
                & empty,
            empty
        );
    }

    #[test]
    fn payload_available_survives_the_provider_clearing_payload_done() {
        // A provider clears REC_PAYLOAD_DONE as soon as it activates the image,
        // well before the DMA has read a word. payload_available is latched, so
        // it must hold until the FIFO is actually drained.
        let (_clock, _i3c_controller, mut bus) = recovery_test_bus_rev(Version::new(2, 1, 0));
        let base = caliptra_mcu_registers_generated::i3c::I3C_CSR_ADDR;
        let bypass = I3C_REC_INT_BYPASS_AXI_DIRECT << RecIntfCfg::RecIntfBypass.shift;

        bus.write(RvSize::Word, base + REC_INTF_CFG_REG, bypass)
            .unwrap();
        bus.write(RvSize::Word, base + INDIRECT_FIFO_CTRL_1_REG, 4)
            .unwrap();
        for _ in 0..4 {
            bus.write(RvSize::Word, base + TTI_TX_DATA_PORT, 0x1234_5678)
                .unwrap();
        }

        bus.write(
            RvSize::Word,
            base + REC_INTF_CFG_REG,
            bypass | (1 << RecIntfCfg::RecPayloadDone.shift),
        )
        .unwrap();
        bus.write(RvSize::Word, base + REC_INTF_CFG_REG, bypass)
            .unwrap();

        // Still undrained, so the FIFO must still hand the image over.
        for expected in 0..4 {
            assert_eq!(
                bus.read(RvSize::Word, base + INDIRECT_FIFO_DATA_REG)
                    .unwrap(),
                0x1234_5678,
                "word {expected} was dropped after REC_PAYLOAD_DONE fell"
            );
        }
        assert_eq!(
            bus.read(RvSize::Word, base + INDIRECT_FIFO_DATA_REG)
                .unwrap(),
            0xffff_ffff
        );
    }

    #[test]
    fn recovery_ctrl_block_write_and_read_over_i3c() {
        let clock = Clock::new();
        let pic = Pic::new();
        let irq = pic.register_irq(2);
        let mut i3c_controller = I3cController::default();
        let step_lock = Arc::new(Mutex::new(()));
        let i3c = Box::new(I3c::new(
            &clock,
            &mut i3c_controller,
            irq,
            Version::new(2, 0, 0),
            step_lock,
        ));

        let mut bus = AutoRootBus::new(
            vec![],
            None,
            Some(i3c),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let addr = DynamicI3cAddress::new(8).unwrap();
        const RECOVERY_CTRL_CMD: u8 = 38;
        const RECOVERY_CTRL_REG: RvAddr = 0x13c;

        // Block write of 0xBEEF, little-endian over the wire.
        i3c_controller
            .tcri_send(
                addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(regular_recovery_cmd(RECOVERY_CTRL_CMD, 0, 3)),
                    data: vec![0xEF, 0xBE, 0x00],
                },
            )
            .unwrap();
        for _ in 0..10000 {
            clock.increment_and_process_timer_actions(1, &mut bus);
        }

        let base = caliptra_mcu_registers_generated::i3c::I3C_CSR_ADDR;
        assert_eq!(
            bus.read(RvSize::Word, base + RECOVERY_CTRL_REG).unwrap() & 0xFFFF,
            0xBEEF
        );

        // A recovery access must not land in the TTI receive queue.
        assert_eq!(
            bus.read(RvSize::Word, base + TTI_RX_DESC_QUEUE_PORT)
                .unwrap(),
            0
        );

        // Block read returns the same bytes.
        i3c_controller
            .tcri_send(
                addr,
                I3cTcriCommandXfer {
                    cmd: I3cTcriCommand::Regular(regular_recovery_cmd(RECOVERY_CTRL_CMD, 1, 3)),
                    data: Vec::new(),
                },
            )
            .unwrap();
        for _ in 0..10000 {
            clock.increment_and_process_timer_actions(1, &mut bus);
        }

        let resp = i3c_controller.tcri_receive(addr).unwrap();
        assert_eq!(resp.data, vec![0xEF, 0xBE, 0x00]);
    }

    #[test]
    fn receive_i3c_cmd() {
        let clock = Clock::new();
        let pic = Pic::new();
        let irq = pic.register_irq(2);
        let mut i3c_controller = I3cController::default();
        let step_lock = Arc::new(Mutex::new(()));
        let mut i3c = Box::new(I3c::new(
            &clock,
            &mut i3c_controller,
            irq,
            Version::new(2, 0, 0),
            step_lock,
        ));

        assert_eq!(i3c.read_i3c_base_hci_version(), I3c::HCI_VERSION);

        let cmd_bytes: [u8; 8] = [0x01, 0, 0, 0, 0, 0, 0, 0];
        let cmd = I3cTcriCommandXfer {
            cmd: I3cTcriCommand::Immediate(
                ImmediateDataTransferCommand::read_from_bytes(&cmd_bytes[..]).unwrap(),
            ),
            data: Vec::new(),
        };
        i3c_controller
            .tcri_send(DynamicI3cAddress::new(8).unwrap(), cmd)
            .unwrap();

        let mut bus = AutoRootBus::new(
            vec![],
            None,
            Some(i3c),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        for _ in 0..10000 {
            clock.increment_and_process_timer_actions(1, &mut bus);
        }

        assert_eq!(
            bus.read(
                RvSize::Word,
                caliptra_mcu_registers_generated::i3c::I3C_CSR_ADDR + TTI_RX_DESC_QUEUE_PORT
            )
            .unwrap(),
            4
        );
    }
}

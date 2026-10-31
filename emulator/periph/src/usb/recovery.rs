// Licensed under the Apache-2.0 license

//! Device 0's hardware-owned OCP Recovery v1.1 EP0 path.
//!
//! Matches the selected USB RTL's package, control decoder and CMS FIFO: IN
//! SETUP requests specify 64 bytes, responses have command-specific lengths,
//! and FIFO_CTRL carries CMS/reset followed by a little-endian DWORD count.
//! CPU FIFO_CTRL instead exposes IMAGE_SIZE in its own aligned register.
//! The 64-DWORD FIFO reports modulo-64 indices, not total image progress.
//! Payload becomes available to Caliptra on FIFO-full or the final image word.
//!
//! Transactions are packet-atomic, not cycle/ULPI accurate. A replacement SETUP
//! before FIFO DATA is received flushes the unconsumed FIFO and marks the batch
//! aborted. Firmware owns device/recovery status and activation handling; the
//! peripheral does not authenticate images or implement ROM boot policy.

use super::LpcipUsbError;
use caliptra_emu_bus::{Device, Event, EventData};
use std::collections::VecDeque;
use std::sync::mpsc::{Receiver, Sender};

const FIFO_DEPTH: usize = 64;
const MAX_DMA_BYTES: u32 = 1024 * 1024;
const FIFO_DATA: u8 = 0x2f;

/// Opt-in observations of the existing hardware recovery path, not injected data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LpcipUsbRecoveryEvent {
    Requested { image: u8, words: u32 },
    Consumed { image: u8, data: Vec<u8> },
    Activated { image: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LpcipUsbRecoverySnapshot {
    pub claimed: bool,
    pub stalled: bool,
    pub fifo_words: usize,
    pub accepted_words: u32,
    pub image_words: u32,
    pub payload_available: bool,
    pub image_activated: bool,
    pub protocol_error: u8,
    /// Diagnostic only: the RTL has no underflow status bit.
    pub underflow_reads: u64,
    /// DMA reads invalidated by FIFO reset/abort; no fabricated data is returned.
    pub aborted_dma_reads: u64,
}

enum Transfer {
    Firmware,
    Read { command: u8, data: Vec<u8> },
    Write { command: u8, length: usize },
    StatusOut { clear_error: bool },
    StatusIn,
    Complete,
    Stall,
}

pub(super) struct Recovery {
    registers: [u32; 130],
    transfer: Transfer,
    fifo: VecDeque<u32>,
    accepted: u32,
    write_index: u32,
    payload_available: bool,
    sticky: u32,
    protocol_error: u8,
    generation: u64,
    underflow_reads: u64,
    aborted_dma_reads: u64,
    status_snapshot: [u32; 5],
    status_next: Option<u32>,
    observer: Option<Box<dyn FnMut(LpcipUsbRecoveryEvent) + Send>>,
}

impl Default for Recovery {
    fn default() -> Self {
        let mut registers = [0; 130];
        registers[1] = 0x2050_434f;
        registers[2] = 0x5643_4552;
        registers[3] = 0x1a9a_0101;
        registers[4] = 1;
        Self {
            registers,
            transfer: Transfer::Firmware,
            fifo: VecDeque::with_capacity(FIFO_DEPTH),
            accepted: 0,
            write_index: 0,
            payload_available: false,
            sticky: 0,
            protocol_error: 0,
            generation: 0,
            underflow_reads: 0,
            aborted_dma_reads: 0,
            status_snapshot: [0; 5],
            status_next: None,
            observer: None,
        }
    }
}

impl Recovery {
    pub(super) fn reset(&mut self) {
        let generation = self.generation.wrapping_add(1);
        let observer = self.observer.take();
        *self = Self {
            generation,
            observer,
            ..Self::default()
        };
    }

    pub(super) fn observe(&mut self, observer: impl FnMut(LpcipUsbRecoveryEvent) + Send + 'static) {
        self.observer = Some(Box::new(observer));
    }

    fn image_index(&self) -> u8 {
        ((self.registers[0x40 / 4] >> 4) & 0xf) as u8
    }

    fn notify(&mut self, event: LpcipUsbRecoveryEvent) {
        if let Some(observer) = &mut self.observer {
            observer(event);
        }
    }

    fn consumed(&mut self, data: &[u8]) {
        if self.observer.is_some() {
            self.notify(LpcipUsbRecoveryEvent::Consumed {
                image: self.image_index(),
                data: data.to_vec(),
            });
        }
    }

    pub(super) fn snapshot(&self) -> LpcipUsbRecoverySnapshot {
        LpcipUsbRecoverySnapshot {
            claimed: !matches!(self.transfer, Transfer::Firmware),
            stalled: matches!(self.transfer, Transfer::Stall),
            fifo_words: self.fifo.len(),
            accepted_words: self.accepted,
            image_words: self.registers[0x4c / 4],
            payload_available: self.payload_available,
            image_activated: self.registers[0x3c / 4] >> 16 == 0x0f,
            protocol_error: self.protocol_error,
            underflow_reads: self.underflow_reads,
            aborted_dma_reads: self.aborted_dma_reads,
        }
    }

    fn fifo_status(&self) -> [u32; 5] {
        [
            u32::from(self.fifo.is_empty()) | (u32::from(self.fifo.len() == FIFO_DEPTH) << 1),
            self.write_index,
            (self.write_index + FIFO_DEPTH as u32 - self.fifo.len() as u32) % FIFO_DEPTH as u32,
            FIFO_DEPTH as u32,
            FIFO_DEPTH as u32,
        ]
    }

    pub(super) fn read(&mut self, offset: u32) -> u32 {
        match offset {
            0x30 => (self.registers[0x30 / 4] & !0xff00) | u32::from(self.protocol_error) << 8,
            0x50..=0x60 => {
                let index = (offset - 0x50) / 4;
                if index == 0 {
                    self.status_snapshot = self.fifo_status();
                    self.status_next = Some(1);
                    self.status_snapshot[0]
                } else if self.status_next == Some(index) {
                    self.status_next = (index < 4).then_some(index + 1);
                    self.status_snapshot[index as usize]
                } else {
                    self.status_next = None;
                    self.fifo_status()[index as usize]
                }
            }
            0x68 => self.pop().unwrap_or_else(|| {
                self.underflow_reads += 1;
                eprintln!("[EMU] USB recovery FIFO read while empty");
                0
            }),
            0x204 => self.sticky,
            0x7fc => 0,
            _ => self.registers[offset as usize / 4],
        }
    }

    pub(super) fn write(&mut self, offset: u32, value: u32) {
        let mask = match offset {
            0x0c => 0x1fff_0000,
            0x10 | 0x38 | 0x3c => 0x00ff_ffff,
            0x44 => 0x00ff_ff07,
            0x14..=0x28 | 0x4c => u32::MAX,
            0x30 => 0xffff_00ff,
            0x40 => 0xffff,
            0x48 => 0xff,
            0x100 => 0xff,
            0x200 => 1,
            _ => panic!("Unsupported USB recovery register write: {offset:#x}"),
        };
        let register = &mut self.registers[offset as usize / 4];
        *register = (*register & !mask) | (value & mask);
        if offset == 0x48 && value & 0x100 != 0 {
            self.flush();
            self.sticky = 1;
        }
        if offset == 0x200 {
            if value & 2 != 0 {
                self.abort();
            }
            if value & 4 != 0 && self.sticky & 8 != 0 {
                if self.protocol_error == 0 {
                    self.protocol_error = 0xff;
                }
                if !matches!(self.transfer, Transfer::Firmware) {
                    self.transfer = Transfer::Stall;
                }
            }
        }
    }

    fn flush(&mut self) {
        self.fifo.clear();
        self.accepted = 0;
        self.write_index = 0;
        self.payload_available = false;
        self.status_next = None;
        self.generation = self.generation.wrapping_add(1);
    }

    pub(super) fn abort(&mut self) {
        if matches!(
            self.transfer,
            Transfer::Write {
                command: FIFO_DATA,
                ..
            }
        ) {
            self.flush();
            self.sticky = (self.sticky & 1) | 8;
        }
        self.transfer = Transfer::Firmware;
    }

    fn error(&mut self, code: u8) {
        if self.protocol_error == 0 {
            self.protocol_error = code;
        }
        self.transfer = Transfer::Stall;
    }

    pub(super) fn setup(&mut self, setup: &[u8]) -> bool {
        self.abort();
        if self.registers[0x200 / 4] & 1 != 0
            || !matches!(setup[0], 0x21 | 0xa1)
            || setup[1] != 0
            || setup[4..6] != [0, 0]
        {
            return false;
        }
        let command = setup[2];
        let read = setup[0] == 0xa1;
        let length = usize::from(u16::from_le_bytes([setup[6], setup[7]]));
        if setup[3] != 0 {
            self.error(0xff);
            return true;
        }
        let capabilities = self.registers[3] >> 16;
        let supported = match command {
            0x22 | 0x24 | 0x26..=0x28 | 0x2d..=0x2f => true,
            0x23 => capabilities & 1 != 0,
            0x25 => capabilities & (1 << 3) != 0,
            0x2c => capabilities & (1 << 10) != 0,
            _ => false,
        };
        if !supported
            || (command == FIFO_DATA && read)
            || (!read && !matches!(command, 0x25 | 0x26 | 0x2c | 0x2d | FIFO_DATA))
        {
            self.error(1);
        } else if read {
            if length != 64 {
                self.error(0xff);
            } else {
                self.transfer = Transfer::Read {
                    command,
                    data: self.response(command),
                };
            }
        } else if match command {
            0x25 | 0x26 => length != 3,
            0x2c => length != 1,
            0x2d => length != 6,
            FIFO_DATA => !(1..=64).contains(&length),
            _ => unreachable!(),
        } {
            self.error(3);
        } else {
            self.transfer = Transfer::Write { command, length };
        }
        true
    }

    fn response(&mut self, command: u8) -> Vec<u8> {
        if command == 0x2d {
            let mut data = vec![self.registers[0x48 / 4] as u8, 0];
            data.extend(self.registers[0x4c / 4].to_le_bytes());
            return data;
        }
        if command == 0x2e {
            return self
                .fifo_status()
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
        }
        let (offset, length): (u32, u32) = match command {
            0x22 => (4, 15),
            0x23 => (0x14, 24),
            0x24 => (0x30, 7),
            0x25 => (0x38, 3),
            0x26 => (0x3c, 3),
            0x27 => (0x40, 2),
            0x28 => (0x44, 4),
            0x2c => (0x100, 1),
            _ => unreachable!(),
        };
        let mut data: Vec<_> = (0..length.div_ceil(4))
            .flat_map(|index| self.read(offset + index * 4).to_le_bytes())
            .collect();
        data.truncate(length as usize);
        data
    }

    pub(super) fn host_in(&mut self) -> Option<Result<Vec<u8>, LpcipUsbError>> {
        Some(match &self.transfer {
            Transfer::Firmware => return None,
            Transfer::Stall => Err(LpcipUsbError::Stall),
            Transfer::Read { command, data } => {
                let data = data.clone();
                self.transfer = Transfer::StatusOut {
                    clear_error: *command == 0x24,
                };
                Ok(data)
            }
            Transfer::StatusIn => {
                self.transfer = Transfer::Complete;
                Ok(Vec::new())
            }
            _ => Err(LpcipUsbError::Nak),
        })
    }

    pub(super) fn host_out(&mut self, data: &[u8]) -> Option<Result<(), LpcipUsbError>> {
        let (command, length) = match self.transfer {
            Transfer::Firmware => return None,
            Transfer::Stall => return Some(Err(LpcipUsbError::Stall)),
            Transfer::StatusOut { clear_error } if data.is_empty() => {
                if clear_error {
                    self.protocol_error = 0;
                }
                self.transfer = Transfer::Complete;
                return Some(Ok(()));
            }
            Transfer::Write { command, length } => (command, length),
            Transfer::StatusOut { .. } => {
                self.error(3);
                return Some(Err(LpcipUsbError::Stall));
            }
            _ => return Some(Err(LpcipUsbError::Nak)),
        };
        if data.len() != length {
            self.error(3);
            return Some(Err(LpcipUsbError::Stall));
        }
        if command == FIFO_DATA {
            let words = data.len().div_ceil(4);
            let image_size = self.registers[0x4c / 4];
            let remaining = if image_size == 0 {
                u32::MAX
            } else {
                image_size.saturating_sub(self.accepted)
            };
            if words > FIFO_DEPTH - self.fifo.len() || words as u32 > remaining {
                return Some(Err(LpcipUsbError::Nak));
            }
            for bytes in data.chunks(4) {
                let mut word = [0; 4];
                word[..bytes.len()].copy_from_slice(bytes);
                self.fifo.push_back(u32::from_le_bytes(word));
                self.accepted = self.accepted.wrapping_add(1);
                self.write_index = (self.write_index + 1) % FIFO_DEPTH as u32;
            }
            if image_size != 0 && self.accepted >= image_size {
                self.sticky |= 4;
            }
            self.payload_available |= self.fifo.len() == FIFO_DEPTH || self.sticky & 4 != 0;
        } else if command == 0x2d {
            self.write(0x48, u32::from(data[0]) | u32::from(data[1]) << 8);
            self.write(0x4c, u32::from_le_bytes(data[2..6].try_into().unwrap()));
            let words = self.registers[0x4c / 4];
            if words != 0 {
                self.notify(LpcipUsbRecoveryEvent::Requested {
                    image: self.image_index(),
                    words,
                });
            }
        } else {
            let offset = match command {
                0x25 => 0x38,
                0x26 => 0x3c,
                0x2c => 0x100,
                _ => unreachable!(),
            };
            let mut word = [0; 4];
            word[..data.len()].copy_from_slice(data);
            self.write(offset, u32::from_le_bytes(word));
            if command == 0x26 && self.registers[offset as usize / 4] >> 16 == 0x0f {
                self.notify(LpcipUsbRecoveryEvent::Activated {
                    image: self.image_index(),
                });
            }
        }
        self.transfer = Transfer::StatusIn;
        Some(Ok(()))
    }

    fn pop(&mut self) -> Option<u32> {
        let word = self.fifo.pop_front()?;
        if self.fifo.is_empty() {
            self.payload_available = false;
        }
        Some(word)
    }
}

struct PendingRead {
    address: u32,
    length: usize,
    generation: u64,
    data: Vec<u8>,
}

pub(super) struct RecoveryEvents {
    to_caliptra: Sender<Event>,
    from_caliptra: Receiver<Event>,
    to_mcu: Sender<Event>,
    from_mcu: Receiver<Event>,
    pending: Option<PendingRead>,
}

impl RecoveryEvents {
    pub(super) fn new(
        to_caliptra: Sender<Event>,
        from_caliptra: Receiver<Event>,
        to_mcu: Sender<Event>,
        from_mcu: Receiver<Event>,
    ) -> Self {
        Self {
            to_caliptra,
            from_caliptra,
            to_mcu,
            from_mcu,
            pending: None,
        }
    }

    fn reply(&self, event: EventData) {
        self.to_caliptra
            .send(Event::new(
                Device::RecoveryIntf,
                Device::CaliptraCore,
                event,
            ))
            .expect("Caliptra USB recovery event receiver disconnected");
    }

    pub(super) fn poll(&mut self, recovery: &mut Recovery) {
        while let Ok(event) = self.from_caliptra.try_recv() {
            if event.dest == Device::RecoveryIntf {
                self.handle(event.event, recovery);
            } else if matches!(
                event.dest,
                Device::MCU
                    | Device::ExternalTestSram
                    | Device::McuMbox0Sram
                    | Device::McuMbox1Sram
            ) {
                self.to_mcu
                    .send(event)
                    .expect("MCU USB recovery event receiver disconnected");
            }
        }
        while let Ok(event) = self.from_mcu.try_recv() {
            if event.dest == Device::CaliptraCore {
                self.to_caliptra
                    .send(event)
                    .expect("Caliptra USB recovery event receiver disconnected");
            }
        }
        if let Some(pending) = &mut self.pending {
            if pending.generation != recovery.generation {
                recovery.aborted_dma_reads += 1;
                eprintln!("[EMU] USB FIFO reset/abort invalidated a pending Caliptra DMA read");
                self.pending = None;
                return;
            }
            if recovery.payload_available {
                while pending.data.len() < pending.length {
                    let Some(word) = recovery.pop() else { break };
                    pending.data.extend(word.to_le_bytes());
                }
            }
            if pending.data.len() == pending.length {
                let pending = self.pending.take().unwrap();
                recovery.consumed(&pending.data);
                self.reply(EventData::MemoryReadResponse {
                    start_addr: pending.address,
                    data: pending.data,
                });
            }
        }
    }

    fn handle(&mut self, event: EventData, recovery: &mut Recovery) {
        match event {
            EventData::MemoryRead { start_addr, len } => {
                assert!(
                    len != 0 && len <= MAX_DMA_BYTES && len % 4 == 0,
                    "Invalid Caliptra USB recovery read length: {len}"
                );
                if start_addr == 0x68 {
                    assert!(
                        self.pending.is_none(),
                        "Overlapping Caliptra USB FIFO DMA reads"
                    );
                    self.pending = Some(PendingRead {
                        address: start_addr,
                        length: len as usize,
                        generation: recovery.generation,
                        data: Vec::with_capacity(len as usize),
                    });
                } else {
                    let mut data = Vec::with_capacity(len as usize);
                    for index in (0..len).step_by(4) {
                        let offset = start_addr
                            .checked_add(index)
                            .expect("USB recovery DMA address overflow");
                        assert!(
                            matches!(offset, 4..=0x28 | 0x30..=0x60) && offset % 4 == 0,
                            "Invalid Caliptra USB recovery read offset: {offset:#x}"
                        );
                        data.extend(recovery.read(offset).to_le_bytes());
                    }
                    self.reply(EventData::MemoryReadResponse { start_addr, data });
                }
            }
            EventData::MemoryWrite { start_addr, data } => {
                assert!(
                    !data.is_empty() && data.len() % 4 == 0,
                    "Invalid Caliptra USB recovery write length"
                );
                for (index, word) in data.chunks_exact(4).enumerate() {
                    let offset = start_addr
                        .checked_add(index as u32 * 4)
                        .expect("USB recovery DMA address overflow");
                    assert!(
                        matches!(offset, 0x0c..=0x28 | 0x30 | 0x38..=0x4c) && offset % 4 == 0,
                        "Invalid Caliptra USB recovery write offset: {offset:#x}"
                    );
                    recovery.write(offset, u32::from_le_bytes(word.try_into().unwrap()));
                }
            }
            EventData::RecoveryFifoStatusRequest => {
                self.reply(EventData::RecoveryFifoStatusResponse {
                    status: u32::from(recovery.payload_available),
                })
            }
            _ => {}
        }
    }
}

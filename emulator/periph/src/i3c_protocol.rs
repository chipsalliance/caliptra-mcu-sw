/*++

Licensed under the Apache-2.0 license.

File Name:

    i3c.rs

Abstract:

    File contains I3C driver for the Caliptra Emulator Library.

--*/

use bitfield::bitfield;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use zerocopy::{FromBytes, IntoBytes};

#[derive(Default)]
pub struct I3cController {
    targets: Arc<Mutex<Vec<I3cTarget>>>,
    rx: Option<Receiver<I3cBusCommand>>,
    tx: Option<Sender<I3cBusResponse>>,
    running: Arc<AtomicBool>,
    // used for testing
    incoming_counter: Arc<AtomicUsize>,
}

#[derive(Debug)]
pub enum I3cError {
    NoMoreAddresses,
    DeviceAttachedWithoutAddress,
    InvalidAddress,
    TargetNotFound,
    TargetNoResponseReady,
    InvalidTcriCommand,
}

impl Drop for I3cController {
    fn drop(&mut self) {
        self.stop();
    }
}

impl I3cController {
    pub fn new(rx: Receiver<I3cBusCommand>, tx: Sender<I3cBusResponse>) -> I3cController {
        I3cController {
            targets: Arc::new(Mutex::new(Vec::new())),
            rx: Some(rx),
            tx: Some(tx),
            running: Arc::new(AtomicBool::new(false)),
            incoming_counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Stops the thread that processes incoming commands and sends responses.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Spawns a thread that processes incoming commands and sends outgoing responses as
    /// long as this I3cController is in scope.
    pub fn start(&mut self) -> JoinHandle<()> {
        let rx = self.rx.take().unwrap();
        let tx = self.tx.take().unwrap();
        self.running.store(true, Ordering::Relaxed);
        let running = self.running.clone();
        let targets = self.targets.clone();
        let counter = self.incoming_counter.clone();
        thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                I3cController::tcri_receive_all(targets.clone())
                    .iter()
                    .for_each(|resp| {
                        tx.send(resp.clone()).unwrap();
                    });
                if let Ok(cmd) = rx.recv_timeout(Duration::from_millis(5)) {
                    I3cController::incoming(targets.clone(), counter.clone(), cmd);
                }
            }
        })
    }

    /// Run the one round of the incoming loop (without blocking or sleeping).
    /// This is useful for testing or running in a polling loop, rather than spawning a thread.
    pub fn run_once(&mut self) {
        if let Some(rx) = self.rx.as_ref() {
            if let Ok(cmd) = rx.try_recv() {
                I3cController::incoming(self.targets.clone(), self.incoming_counter.clone(), cmd);
            }
        }
        I3cController::tcri_receive_all(self.targets.clone())
            .iter()
            .for_each(|resp| {
                if let Some(tx) = self.tx.as_ref() {
                    tx.send(resp.clone()).unwrap();
                }
            });
    }

    /// Processes a single incoming command and relays it to the appropriate target device.
    fn incoming(
        targets: Arc<Mutex<Vec<I3cTarget>>>,
        counter: Arc<AtomicUsize>,
        cmd: I3cBusCommand,
    ) {
        counter.fetch_add(1, Ordering::Relaxed);
        let addr = cmd.addr;
        targets.lock().unwrap().iter_mut().for_each(|target| {
            if let Some(target_address) = target.get_address() {
                if target_address == addr {
                    target.send_command(cmd.cmd.clone());
                }
            }
        });
    }

    // Abstract the I3C address
    pub fn attach_target(&mut self, mut target: I3cTarget) -> Result<(), I3cError> {
        let mut targets = self.targets.lock().unwrap();
        let new_dyn_addr = if let Some(last_target) = targets.last() {
            let mut highest_address = last_target
                .target
                .lock()
                .unwrap()
                .dynamic_address
                .ok_or(I3cError::DeviceAttachedWithoutAddress)?;
            highest_address.next().ok_or(I3cError::NoMoreAddresses)?
        } else {
            DynamicI3cAddress::new(8)?
        };
        target.set_address(new_dyn_addr);
        targets.push(target);
        Ok(())
    }

    pub fn tcri_send(
        &mut self,
        addr: DynamicI3cAddress,
        cmd: I3cTcriCommandXfer,
    ) -> Result<(), I3cError> {
        self.targets
            .lock()
            .unwrap()
            .iter_mut()
            .find(|s| {
                if let Some(target_address) = s.get_address() {
                    target_address == addr
                } else {
                    false
                }
            })
            .map(|target| target.send_command(cmd))
            .ok_or(I3cError::TargetNotFound)
    }

    pub fn tcri_receive(
        &mut self,
        addr: DynamicI3cAddress,
    ) -> Result<I3cTcriResponseXfer, I3cError> {
        match self
            .targets
            .lock()
            .unwrap()
            .iter_mut()
            .find(|s| {
                if let Some(target_address) = s.get_address() {
                    target_address == addr
                } else {
                    false
                }
            })
            .ok_or(I3cError::TargetNotFound)
            .map(|target| target.get_response())
        {
            Ok(Some(resp)) => Ok(resp),
            Ok(None) => Err(I3cError::TargetNoResponseReady),
            Err(e) => Err(e),
        }
    }

    fn tcri_receive_all(targets: Arc<Mutex<Vec<I3cTarget>>>) -> Vec<I3cBusResponse> {
        targets
            .lock()
            .unwrap()
            .iter_mut()
            .flat_map(|target| {
                let mut v = vec![];
                v.extend(target.get_response().map(|resp| I3cBusResponse {
                    ibi: None,
                    addr: target.get_address().unwrap(),
                    resp,
                }));
                v.extend(target.get_ibis().iter().map(|mdb| {
                    I3cBusResponse {
                        ibi: Some(*mdb),
                        addr: target.get_address().unwrap(),
                        resp: I3cTcriResponseXfer::default(), // empty descriptor for the IBI
                    }
                }));
                v
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DynamicI3cAddress {
    address: u8,
}

impl DynamicI3cAddress {
    pub fn new(value: u8) -> Result<Self, I3cError> {
        // Assume I2C might be there
        match value {
            0x08..=0x3d | 0x3f..=0x6d | 0x6f..=0x75 => Ok(Self { address: value }),
            _ => Err(I3cError::InvalidAddress),
        }
    }
}

impl From<DynamicI3cAddress> for u32 {
    fn from(value: DynamicI3cAddress) -> Self {
        value.address as u32
    }
}

impl From<DynamicI3cAddress> for u8 {
    fn from(value: DynamicI3cAddress) -> Self {
        value.address
    }
}

impl TryFrom<u32> for DynamicI3cAddress {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value <= 256 {
            Ok(Self {
                address: value as u8,
            })
        } else {
            Err(format!("Address must be less than 256: {}", value))
        }
    }
}

impl From<u8> for DynamicI3cAddress {
    fn from(value: u8) -> Self {
        DynamicI3cAddress { address: value }
    }
}

impl Iterator for DynamicI3cAddress {
    type Item = DynamicI3cAddress;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.address;
        let next = match current {
            0x3d => Some(0x3f),
            0x6d => Some(0x6f),
            0x75 => None,
            _ => Some(current + 1),
        };
        next.map(|address| Self { address })
    }
}

pub trait I3cIncomingCommandClient {
    // Callback to be notified when a command is received.
    fn incoming(&self);
}

#[derive(Clone, Default)]
pub struct I3cTarget {
    target: Arc<Mutex<I3cTargetDevice>>,
    // double Arc is necessary to allow for the client to be shared with the command thread
    incoming_command_client: Arc<Mutex<Option<Arc<dyn I3cIncomingCommandClient + Send + Sync>>>>,
}

impl I3cTarget {
    pub fn set_incoming_command_client(
        &mut self,
        client: Arc<dyn I3cIncomingCommandClient + Send + Sync>,
    ) {
        *self.incoming_command_client.lock().unwrap() = Some(client);
    }

    pub fn set_address(&mut self, address: DynamicI3cAddress) {
        self.target.lock().unwrap().dynamic_address = Some(address)
    }

    pub fn get_address(&self) -> Option<DynamicI3cAddress> {
        self.target.lock().unwrap().dynamic_address
    }

    pub fn send_command(&mut self, cmd: I3cTcriCommandXfer) {
        let mut target = self.target.lock().unwrap();
        target.rx_buffer.push_back(cmd);
        if let Some(client) = self.incoming_command_client.lock().unwrap().clone() {
            client.incoming();
        }
    }

    pub fn get_response(&mut self) -> Option<I3cTcriResponseXfer> {
        self.target.lock().unwrap().tx_buffer.pop_front()
    }

    pub fn read_command(&mut self) -> Option<I3cTcriCommandXfer> {
        self.target.lock().unwrap().rx_buffer.pop_front()
    }

    pub fn peek_command(&mut self) -> Option<I3cTcriCommandXfer> {
        self.target.lock().unwrap().rx_buffer.front().cloned()
    }

    pub fn set_response(&mut self, resp: I3cTcriResponseXfer) {
        self.target.lock().unwrap().tx_buffer.push_back(resp)
    }

    pub fn get_ibis(&mut self) -> Vec<u8> {
        self.target.lock().unwrap().ibi_buffer.drain(..).collect()
    }

    pub fn send_ibi(&mut self, mdb: u8) {
        self.target.lock().unwrap().ibi_buffer.push_back(mdb)
    }
}

#[derive(Clone, Default)]
pub struct I3cTargetDevice {
    dynamic_address: Option<DynamicI3cAddress>,
    rx_buffer: VecDeque<I3cTcriCommandXfer>,
    tx_buffer: VecDeque<I3cTcriResponseXfer>,
    ibi_buffer: VecDeque<u8>,
}

bitfield! {
    #[derive(Clone, FromBytes, IntoBytes)]
    pub struct IbiDescriptor(u32);
    impl Debug;
    pub u8, received_status, set_received_status: 31, 31;
    pub u8, error, set_error: 30, 30;
    // Regular = 0
    // CreditAck = 1
    // ScheduledCmd = 2
    // AutocmdRead = 4
    // StbyCrBcastCcc = 7
    pub u8, status_type, set_status_type: 29, 27;
    pub u8, timestamp_preset, set_timestamp_preset: 25, 25;
    pub u8, last_status, set_last_status: 24, 24;
    pub u8, chunks, set_chunks: 23, 16;
    pub u8, id, set_id: 15, 8;
    pub u8, data_length, set_data_length: 7, 0;
}

bitfield! {
    #[derive(Clone, FromBytes, IntoBytes)]
    pub struct ImmediateDataTransferCommand(u64);
    impl Debug;
    u8, cmd_attr, set_cmd_attr: 2, 0;
    u8, tid, set_tid: 6, 3;
    u8, cmd, set_cmd: 14, 7;
    u8, cp, set_cp: 15, 15;
    u8, dev_index, set_dev_index: 20, 16;
    u8, ddt, set_ddt: 25, 23;
    u8, mode, set_mode: 28, 26;
    u8, rnw, set_rnw: 29, 29;
    u8, wroc, set_wroc: 30, 30;
    u8, toc, set_toc: 31, 31;
    pub u8, data_byte_1, set_data_byte_1: 39, 32;
    pub u8, data_byte_2, set_data_byte_2: 47, 40;
    pub u8, data_byte_3, set_data_byte_3: 55, 48;
    pub u8, data_byte_4, set_data_byte_4: 63, 56;
}

bitfield! {
    #[derive(Clone, FromBytes, IntoBytes)]
    pub struct ReguDataTransferCommand(u64);
    impl Debug;
    u8, cmd_attr, set_cmd_attr: 2, 0;
    u8, tid, set_tid: 6, 3;
    u8, cmd, set_cmd: 14, 7;
    u8, cp, set_cp: 15, 15;
    u8, dev_index, set_dev_index: 20, 16;
    u8, short_read_err, set_short_read_err: 24, 24;
    u8, dbp, set_dbp: 25, 25;
    u8, mode, set_mode: 28, 26;
    pub u8, rnw, set_rnw: 29, 29;
    u8, wroc, set_wroc: 30, 30;
    u8, toc, set_toc: 31, 31;
    u8, def_byte, set_def_byte: 39, 32;
    pub u16, data_length, set_data_length: 63, 48;
}

bitfield! {
    #[derive(Clone, FromBytes, IntoBytes)]
    pub struct ComboTransferCommand(u64);
    impl Debug;
    u8, cmd_attr, set_cmd_attr: 2, 0;
    u8, tid, set_tid: 6, 3;
    u8, cmd, set_cmd: 14, 7;
    u8, cp, set_cp: 15, 15;
    u8, dev_index, set_dev_index: 20, 16;
    u8, data_length_position, set_data_length_position: 23, 22;
    u8, first_phase_mode, set_first_phase_mode: 24, 24;
    u8, suboffset_16bit, set_suboffset_16bit: 25, 25;
    u8, mode, set_mode: 28, 26;
    u8, rnw, set_rnw: 29, 29;
    u8, wroc, set_wroc: 30, 30;
    u8, toc, set_toc: 31, 31;
    u8, offset, set_offset: 47, 32;
    u16, data_length, set_data_length: 63, 48;
}

bitfield! {
    #[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
    pub struct ResponseDescriptor(u32);
    impl Debug;

    pub u16, data_length, set_data_length: 15, 0;
    u8, tid, set_tid: 27, 24;
    u8, err_status, set_err_status: 31, 28;
}

#[derive(Clone, Debug)]
pub enum I3cTcriCommand {
    Immediate(ImmediateDataTransferCommand),
    Regular(ReguDataTransferCommand),
    Combo(ComboTransferCommand),
}

impl TryFrom<[u32; 2]> for I3cTcriCommand {
    type Error = I3cError;

    fn try_from(data: [u32; 2]) -> Result<Self, Self::Error> {
        let combined_data = data[0] as u64 | ((data[1] as u64) << 32);

        match combined_data & 7 {
            1 => Ok(Self::Immediate(
                ImmediateDataTransferCommand::read_from_bytes(&combined_data.to_ne_bytes()[..])
                    .map_err(|_| I3cError::InvalidTcriCommand)?,
            )),
            0 => Ok(Self::Regular(
                ReguDataTransferCommand::read_from_bytes(&combined_data.to_ne_bytes()[..])
                    .map_err(|_| I3cError::InvalidTcriCommand)?,
            )),
            3 => Ok(Self::Combo(
                ComboTransferCommand::read_from_bytes(&combined_data.to_ne_bytes()[..])
                    .map_err(|_| I3cError::InvalidTcriCommand)?,
            )),
            _ => Err(I3cError::InvalidTcriCommand),
        }
    }
}

impl From<I3cTcriCommand> for u64 {
    fn from(item: I3cTcriCommand) -> u64 {
        match item {
            I3cTcriCommand::Regular(reg) => reg.0,
            I3cTcriCommand::Combo(combo) => combo.0,
            I3cTcriCommand::Immediate(imm) => imm.0,
        }
    }
}

impl I3cTcriCommand {
    pub fn raw_data_len(&self) -> usize {
        match self {
            Self::Immediate(_) => 4,
            Self::Regular(regular) => regular.data_length().into(),
            Self::Combo(combo) => combo.data_length().into(),
        }
    }
    pub fn data_len(&self) -> usize {
        match self {
            Self::Immediate(_) => 0,
            Self::Regular(regular) => regular.data_length().into(),
            Self::Combo(combo) => combo.data_length().into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct I3cBusCommand {
    pub addr: DynamicI3cAddress,
    pub cmd: I3cTcriCommandXfer,
}

#[derive(Clone, Debug)]
pub struct I3cBusResponse {
    pub ibi: Option<u8>,
    pub addr: DynamicI3cAddress,
    pub resp: I3cTcriResponseXfer,
}

#[derive(Clone, Debug)]
pub struct I3cTcriCommandXfer {
    pub cmd: I3cTcriCommand,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct I3cTcriResponseXfer {
    pub resp: ResponseDescriptor,
    pub data: Vec<u8>,
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::mpsc::channel;

    #[test]
    fn i3c_comms_test() {
        let to_target = channel();
        let from_target = channel();
        let mut controller = I3cController::new(to_target.1, from_target.0);
        // don't start the controller, but run it manually to avoid race conditions

        let cmd_bytes: [u8; 8] = [0x01, 0, 0, 0, 0, 0, 0, 0];
        let xfer = I3cTcriCommandXfer {
            cmd: I3cTcriCommand::Immediate(
                ImmediateDataTransferCommand::read_from_bytes(&cmd_bytes[..]).unwrap(),
            ),
            data: Vec::new(),
        };
        let cmd = I3cBusCommand {
            addr: DynamicI3cAddress::new(8).unwrap(),
            cmd: xfer,
        };
        to_target.0.send(cmd).unwrap();

        controller.run_once();
        assert_eq!(1, controller.incoming_counter.load(Ordering::Relaxed));
    }
}

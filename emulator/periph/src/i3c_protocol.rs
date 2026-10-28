/*++

Licensed under the Apache-2.0 license.

File Name:

    i3c.rs

Abstract:

    File contains I3C driver for the Caliptra Emulator Library.

--*/

use caliptra_mcu_testing_common::i3c::{
    DynamicI3cAddress, I3cBusCommand, I3cBusResponse, I3cError, I3cTcriCommandXfer,
    I3cTcriResponseXfer,
};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Firmware-visible LAST_IBI_STATUS values from i3c-core's `ibi_status_e`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum I3cIbiStatus {
    #[default]
    Success = 0,
    Nack = 1,
    PartialData = 2,
    Retry = 3,
    AddressArbitration = 4,
}

/// One deterministic IBI attempt. No electrical bus behavior is simulated.
#[derive(Clone, Copy, Debug)]
pub enum I3cIbiOutcome {
    /// Complete after this many peripheral polls (at least one).
    Complete {
        status: I3cIbiStatus,
        after_polls: u32,
    },
    /// Never complete: no IbiDone and no controller notification.
    Missing,
}

impl Default for I3cIbiOutcome {
    fn default() -> Self {
        Self::Complete {
            status: I3cIbiStatus::Success,
            after_polls: 1,
        }
    }
}

#[derive(Default)]
pub struct I3cController {
    targets: Arc<Mutex<Vec<I3cTarget>>>,
    rx: Option<Receiver<I3cBusCommand>>,
    tx: Option<Sender<I3cBusResponse>>,
    running: Arc<AtomicBool>,
    // used for testing
    incoming_counter: Arc<AtomicUsize>,
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

    /// A shared target handle for emulator-only fault scripting and inspection.
    pub fn target(&self, addr: DynamicI3cAddress) -> Result<I3cTarget, I3cError> {
        self.targets
            .lock()
            .unwrap()
            .iter()
            .find(|target| target.get_address() == Some(addr))
            .cloned()
            .ok_or(I3cError::TargetNotFound)
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
                v.extend(target.get_ibis().into_iter().map(|(mdb, data)| {
                    let mut resp = I3cTcriResponseXfer::default();
                    resp.resp.set_data_length(data.len() as u16);
                    resp.data = data;
                    I3cBusResponse {
                        ibi: Some(mdb),
                        addr: target.get_address().unwrap(),
                        resp,
                    }
                }));
                v
            })
            .collect()
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
        // Release the target lock before calling incoming() to avoid a
        // lock-ordering inversion with the emulator step lock.
        {
            let mut target = self.target.lock().unwrap();
            if cmd.cmd.is_read() {
                // A read belongs to the TX path, never to the RX descriptor
                // FIFO. Retain early requests until a TX packet is available.
                let tid = ((u64::from(cmd.cmd.clone()) >> 3) & 0xf) as u8;
                target
                    .read_requests
                    .push_back((cmd.cmd.raw_data_len(), tid));
            } else {
                target.rx_buffer.push_back(cmd);
            }
        }
        let client = self.incoming_command_client.lock().unwrap().clone();
        if let Some(client) = client {
            client.incoming();
        }
    }

    pub fn get_response(&mut self) -> Option<I3cTcriResponseXfer> {
        let mut target = self.target.lock().unwrap();
        let (requested, tid) = *target.read_requests.front()?;
        let mut resp = target.tx_buffer.pop_front()?;
        target.read_requests.pop_front();
        // A zero length means read the whole queued packet, matching existing
        // socket clients. A short read consumes this packet, not the next one.
        let len = if requested == 0 {
            resp.data.len()
        } else {
            requested.min(resp.data.len())
        };
        resp.data.truncate(len);
        resp.resp.set_data_length(len as u16);
        resp.resp.0 = (resp.resp.0 & !(0xf << 24)) | ((tid as u32) << 24);
        Some(resp)
    }

    pub fn has_pending_response(&self) -> bool {
        !self.target.lock().unwrap().tx_buffer.is_empty()
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

    pub fn get_ibis(&mut self) -> Vec<(u8, Vec<u8>)> {
        self.target.lock().unwrap().ibi_buffer.drain(..).collect()
    }

    pub fn send_ibi(&mut self, mdb: u8, data: Vec<u8>) {
        self.target
            .lock()
            .unwrap()
            .ibi_buffer
            .push_back((mdb, data))
    }

    /// Queue next-N outcomes before triggering firmware transmissions. Once
    /// exhausted, subsequent attempts succeed after one peripheral poll.
    pub fn queue_ibi_outcome(&self, outcome: I3cIbiOutcome) {
        self.target.lock().unwrap().ibi_outcomes.push_back(outcome);
    }

    pub fn ibi_attempts(&self) -> usize {
        self.target.lock().unwrap().ibi_attempts
    }

    pub(crate) fn next_ibi_outcome(&self) -> I3cIbiOutcome {
        let mut target = self.target.lock().unwrap();
        target.ibi_attempts += 1;
        target.ibi_outcomes.pop_front().unwrap_or_default()
    }

    /// Override the next private write's RX descriptor Error field. Queue zero
    /// to leave an intervening packet valid. Oversized writes need no special
    /// control: send their actual data and length through the normal interface.
    pub fn queue_rx_error(&self, error: u8) {
        assert!(error <= 0xf);
        self.target.lock().unwrap().rx_errors.push_back(error);
    }

    pub(crate) fn next_rx_error(&self) -> u8 {
        self.target
            .lock()
            .unwrap()
            .rx_errors
            .pop_front()
            .unwrap_or(0)
    }
}

#[derive(Clone, Default)]
pub struct I3cTargetDevice {
    dynamic_address: Option<DynamicI3cAddress>,
    rx_buffer: VecDeque<I3cTcriCommandXfer>,
    tx_buffer: VecDeque<I3cTcriResponseXfer>,
    read_requests: VecDeque<(usize, u8)>,
    ibi_buffer: VecDeque<(u8, Vec<u8>)>,
    ibi_outcomes: VecDeque<I3cIbiOutcome>,
    ibi_attempts: usize,
    rx_errors: VecDeque<u8>,
}

#[cfg(test)]
mod test {
    use super::*;
    use caliptra_mcu_testing_common::i3c::{I3cTcriCommand, ImmediateDataTransferCommand};
    use std::sync::mpsc::channel;
    use zerocopy::FromBytes;

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

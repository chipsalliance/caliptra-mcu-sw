// Licensed under the Apache-2.0 license

//! Loopback USB/IP transport for the transaction-level Device0 model.
//!
//! Call [`UsbIpServer::poll`] on the model thread, interleaved with firmware
//! execution. No worker thread executes USB transactions. Only EP0 control URBs
//! are supported. Standard requests run through firmware; recovery requests use
//! the model's existing hardware-owned path. This is not a USB
//! bus/address/electrical simulation.
//! The discovery record describes the test recovery device (VID/PID ffff:ffff,
//! interface ef/08/01). Firmware, not this transport, supplies USB descriptors,
//! including the recovery functional descriptor.

use super::{LpcipUsbError, LpcipUsbHostController, LpcipUsbSpeed};
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

const VERSION: u16 = 0x0111;
const DEVLIST: u16 = 0x8005;
const IMPORT: u16 = 0x8003;
const DEVID: u32 = 0x0001_0001;
/// USB/IP bus ID of the sole exported Device0.
pub const BUS_ID: &str = "1-1";
const MAX_TRANSFER: usize = 64 * 1024;
const MAX_URBS: usize = 32;
const MAX_BUFFER: usize = 2 * MAX_TRANSFER + 4096;
const IO_BUDGET: usize = 16 * 1024;
const FRAME_BUDGET: usize = 32;
const TIMEOUT: Duration = Duration::from_secs(5);
const EPIPE: i32 = -32;
const EPROTO: i32 = -71;
const ECONNRESET: i32 = -104;
const ETIMEDOUT: i32 = -110;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn put_word(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Setup,
    Data,
    Status,
}

struct Urb {
    seq: u32,
    direction: u32,
    flags: u32,
    length: usize,
    setup: [u8; 8],
    data: Vec<u8>,
    actual: usize,
    stage: Stage,
    deadline: Instant,
}

impl Urb {
    fn abort(&self, host: &LpcipUsbHostController) {
        if self.stage != Stage::Setup {
            // Cancel hardware recovery staging without resetting the firmware's
            // address. Firmware-owned EP0 is superseded by the next real SETUP.
            if let Some(recovery) = &mut host.state.lock().unwrap().recovery {
                recovery.abort();
            }
        }
    }

    /// Performs at most one USB transaction, leaving firmware time between stages.
    fn advance(&mut self, host: &LpcipUsbHostController, setup_address: Option<u8>) -> Option<i32> {
        let address = host.device_address();
        let result = match self.stage {
            Stage::Setup => host
                .host_setup(setup_address.unwrap_or(address), &self.setup)
                .map(|()| {
                    self.stage = if self.length == 0 {
                        Stage::Status
                    } else {
                        Stage::Data
                    };
                    false
                }),
            Stage::Data if self.direction == 1 => host.host_in(address, 0).and_then(|packet| {
                if packet.len() > self.length - self.actual {
                    return Err(LpcipUsbError::DataTooLong);
                }
                self.actual += packet.len();
                let done = packet.len() < 64 || self.actual == self.length;
                self.data.extend_from_slice(&packet);
                if done {
                    self.stage = Stage::Status;
                }
                Ok(false)
            }),
            Stage::Data => {
                let end = (self.actual + 64).min(self.length);
                host.host_out(address, 0, &self.data[self.actual..end])
                    .map(|()| {
                        self.actual = end;
                        if end == self.length {
                            self.stage = Stage::Status;
                        }
                        false
                    })
            }
            Stage::Status if self.setup[0] & 0x80 != 0 && self.length != 0 => {
                host.host_out(address, 0, &[]).map(|()| true)
            }
            Stage::Status => host.host_in(address, 0).and_then(|packet| {
                if packet.is_empty() {
                    Ok(true)
                } else {
                    Err(LpcipUsbError::DataTooLong)
                }
            }),
        };
        match result {
            Ok(true) if self.direction == 1 && self.actual < self.length && self.flags & 1 != 0 => {
                Some(-121) // EREMOTEIO / URB_SHORT_NOT_OK
            }
            Ok(true) => Some(0),
            Ok(false) | Err(LpcipUsbError::Nak) => None,
            // After SET_ADDRESS's status ACK the CPU still needs to program the
            // pending address, which the model latches on the next SETUP token.
            Err(LpcipUsbError::AddressMismatch) if setup_address.is_some() => None,
            Err(LpcipUsbError::Stall | LpcipUsbError::EndpointDisabled) => Some(EPIPE),
            Err(LpcipUsbError::Disconnected) => Some(-19),
            Err(_) => Some(EPROTO),
        }
    }

    fn response(&self, status: i32) -> Vec<u8> {
        let mut reply = vec![0; 48];
        put_word(&mut reply, 0, 3); // RET_SUBMIT
        put_word(&mut reply, 4, self.seq);
        // Linux requires the unused basic-header fields in replies to be zero.
        put_word(&mut reply, 20, status as u32);
        put_word(&mut reply, 24, self.actual as u32);
        if self.direction == 1 {
            reply.extend_from_slice(&self.data);
        }
        reply
    }
}

struct Connection {
    stream: TcpStream,
    imported: bool,
    closing: bool,
    peer_closed: bool,
    input: Vec<u8>,
    output: VecDeque<u8>,
    urbs: VecDeque<Urb>,
    addressing: Option<Urb>,
    next_setup_address: Option<u8>,
    input_since: Option<Instant>,
    output_progress: Instant,
    connected_at: Instant,
}

impl Connection {
    fn new(stream: TcpStream, now: Instant) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            imported: false,
            closing: false,
            peer_closed: false,
            input: Vec::new(),
            output: VecDeque::new(),
            urbs: VecDeque::new(),
            addressing: None,
            next_setup_address: None,
            input_since: None,
            output_progress: now,
            connected_at: now,
        })
    }

    fn queue(&mut self, bytes: &[u8], now: Instant) -> io::Result<()> {
        if self.output.len() + bytes.len() > MAX_BUFFER {
            return Err(invalid("USB/IP output limit exceeded"));
        }
        if self.output.is_empty() {
            self.output_progress = now;
        }
        self.output.extend(bytes);
        Ok(())
    }

    fn read(&mut self, now: Instant) -> io::Result<()> {
        let mut buffer = [0; 4096];
        let mut budget = IO_BUDGET;
        while budget != 0 && !self.closing {
            let size = buffer.len().min(budget);
            match self.stream.read(&mut buffer[..size]) {
                Ok(0) => {
                    self.peer_closed = true;
                    break;
                }
                Ok(n) => {
                    if self.input.len() + n > MAX_BUFFER {
                        return Err(invalid("USB/IP input limit exceeded"));
                    }
                    self.input_since.get_or_insert(now);
                    self.input.extend_from_slice(&buffer[..n]);
                    budget -= n;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn write(&mut self, now: Instant) -> io::Result<()> {
        let mut budget = IO_BUDGET;
        while budget != 0 && !self.output.is_empty() {
            let (bytes, _) = self.output.as_slices();
            match self.stream.write(&bytes[..bytes.len().min(budget)]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    self.output.drain(..n);
                    self.output_progress = now;
                    budget -= n;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn parse(&mut self, host: &LpcipUsbHostController, now: Instant) -> io::Result<bool> {
        for _ in 0..FRAME_BUDGET {
            if self.closing {
                return Ok(false);
            }
            let consumed = if self.imported {
                self.parse_urb(host, now)?
            } else {
                self.parse_operation(host, now)?
            };
            if consumed == 0 {
                return Ok(false);
            }
            self.input.drain(..consumed);
            self.input_since = if self.input.is_empty() {
                None
            } else {
                Some(now)
            };
        }
        Ok(true)
    }

    fn parse_operation(
        &mut self,
        host: &LpcipUsbHostController,
        now: Instant,
    ) -> io::Result<usize> {
        if self.input.len() < 8 {
            return Ok(0);
        }
        let version = u16::from_be_bytes(self.input[..2].try_into().unwrap());
        let operation = u16::from_be_bytes(self.input[2..4].try_into().unwrap());
        if version != VERSION || word(&self.input, 4) != 0 {
            return Err(invalid("invalid USB/IP operation header"));
        }
        match operation {
            DEVLIST => {
                let present = host.connected();
                let mut reply = operation_reply(DEVLIST, 0);
                reply.extend_from_slice(&u32::from(present).to_be_bytes());
                if present {
                    reply.extend_from_slice(&device_record(host));
                    reply.extend_from_slice(&[0xef, 0x08, 0x01, 0]);
                }
                self.queue(&reply, now)?;
                self.closing = true;
                Ok(8)
            }
            IMPORT => {
                if self.input.len() < 40 {
                    return Ok(0);
                }
                let mut expected = [0; 32];
                expected[..BUS_ID.len()].copy_from_slice(BUS_ID.as_bytes());
                let success =
                    self.input[8..40] == expected && host.bus_reset(LpcipUsbSpeed::High).is_ok();
                let mut reply = operation_reply(IMPORT, u32::from(!success));
                if success {
                    reply.extend_from_slice(&device_record(host));
                    self.imported = true;
                    // vhci handles the client's SET_ADDRESS without sending it
                    // over USB/IP. Give the physical model its exported device
                    // number through firmware, rather than fabricating address
                    // state or relaxing firmware's standard request validation.
                    self.addressing = Some(Urb {
                        seq: 0,
                        direction: 0,
                        flags: 0,
                        length: 0,
                        setup: [0, 5, 1, 0, 0, 0, 0, 0],
                        data: Vec::new(),
                        actual: 0,
                        stage: Stage::Setup,
                        deadline: now + TIMEOUT,
                    });
                } else {
                    self.closing = true;
                }
                self.queue(&reply, now)?;
                Ok(40)
            }
            _ => Err(invalid("unsupported USB/IP operation")),
        }
    }

    fn parse_urb(&mut self, host: &LpcipUsbHostController, now: Instant) -> io::Result<usize> {
        if self.input.len() < 48 {
            return Ok(0);
        }
        let bytes = &self.input;
        let command = word(bytes, 0);
        let seq = word(bytes, 4);
        let direction = word(bytes, 12);
        let endpoint = word(bytes, 16);
        if word(bytes, 8) != DEVID || direction > 1 || endpoint > 15 {
            return Err(invalid("invalid USB/IP URB header"));
        }
        match command {
            1 => {
                let length = word(bytes, 24) as usize;
                // Signed negative lengths, ISO descriptors, and huge frames are
                // rejected before allocating or waiting for their payload.
                if length > MAX_TRANSFER || word(bytes, 32) != 0 {
                    return Err(invalid("unsupported USB/IP transfer length or ISO URB"));
                }
                let frame_length = 48 + if direction == 0 { length } else { 0 };
                if bytes.len() < frame_length {
                    return Ok(0);
                }
                if self.urbs.len() == MAX_URBS || self.urbs.iter().any(|u| u.seq == seq) {
                    return Err(invalid("USB/IP URB limit or duplicate sequence"));
                }
                let setup: [u8; 8] = bytes[40..48].try_into().unwrap();
                let setup_length = usize::from(u16::from_le_bytes([setup[6], setup[7]]));
                let urb = Urb {
                    seq,
                    direction,
                    flags: word(bytes, 20),
                    length,
                    setup,
                    data: if direction == 0 {
                        bytes[48..frame_length].to_vec()
                    } else {
                        Vec::new()
                    },
                    actual: 0,
                    stage: Stage::Setup,
                    deadline: now + TIMEOUT,
                };
                if endpoint != 0 {
                    self.queue(&urb.response(EPIPE), now)?;
                } else if setup_length != length
                    || (length != 0 && u32::from(setup[0] >> 7) != direction)
                {
                    self.queue(&urb.response(EPROTO), now)?;
                } else {
                    self.urbs.push_back(urb);
                }
                Ok(frame_length)
            }
            2 => {
                let target = word(bytes, 20);
                let status = if let Some(index) = self.urbs.iter().position(|u| u.seq == target) {
                    self.urbs.remove(index).unwrap().abort(host);
                    ECONNRESET
                } else {
                    // Like Linux stub_rx: an already completed URB has its own
                    // RET_SUBMIT; a live cancellation gets only RET_UNLINK.
                    0
                };
                let mut reply = [0; 48];
                put_word(&mut reply, 0, 4); // RET_UNLINK
                put_word(&mut reply, 4, seq);
                put_word(&mut reply, 20, status as u32);
                self.queue(&reply, now)?;
                Ok(48)
            }
            _ => Err(invalid("unsupported USB/IP URB command")),
        }
    }

    fn poll(&mut self, host: &LpcipUsbHostController, now: Instant) -> io::Result<bool> {
        self.read(now)?;
        let parse_budget_exhausted = self.parse(host, now)?;
        if self.peer_closed {
            if !self.input.is_empty() {
                if parse_budget_exhausted {
                    return Ok(false);
                }
                return Err(invalid("USB/IP peer closed with a truncated frame"));
            }
            return Ok(true);
        }
        if self.imported && !host.connected() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "USB/IP Device0 disconnected",
            ));
        }
        // Expire queued as well as active URBs, even if an earlier URB NAKs.
        let mut index = 0;
        while index < self.urbs.len() {
            if now >= self.urbs[index].deadline {
                let urb = self.urbs.remove(index).unwrap();
                urb.abort(host);
                self.queue(&urb.response(ETIMEDOUT), now)?;
            } else {
                index += 1;
            }
        }
        if let Some(urb) = &mut self.addressing {
            if now >= urb.deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "USB/IP firmware address initialization timed out",
                ));
            }
            // A reset handler may discard SETUP, so wait for firmware to
            // acknowledge the import reset before beginning initialization.
            if host.state.lock().unwrap().command & super::RESET_CHANGE == 0 {
                if let Some(status) = urb.advance(host, None) {
                    if status != 0 {
                        return Err(io::Error::other(
                            "USB/IP firmware rejected address initialization",
                        ));
                    }
                    self.addressing = None;
                    self.next_setup_address = Some(1);
                }
            }
        } else if let Some(urb) = self.urbs.front_mut() {
            let stage = urb.stage;
            let status = urb.advance(host, self.next_setup_address);
            if stage == Stage::Setup && urb.stage != Stage::Setup {
                self.next_setup_address = None;
            }
            if let Some(status) = status {
                let urb = self.urbs.pop_front().unwrap();
                if status != 0 {
                    urb.abort(host);
                }
                self.queue(&urb.response(status), now)?;
            }
        }
        self.write(now)?;
        if (!self.imported && now.duration_since(self.connected_at) >= TIMEOUT)
            || self
                .input_since
                .is_some_and(|start| now.duration_since(start) >= TIMEOUT)
            || (!self.output.is_empty() && now.duration_since(self.output_progress) >= TIMEOUT)
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "USB/IP peer stalled",
            ));
        }
        Ok(self.closing && self.output.is_empty())
    }
}

fn operation_reply(operation: u16, status: u32) -> Vec<u8> {
    let mut reply = Vec::with_capacity(8);
    reply.extend_from_slice(&VERSION.to_be_bytes());
    reply.extend_from_slice(&(operation & 0x7fff).to_be_bytes());
    reply.extend_from_slice(&status.to_be_bytes());
    reply
}

fn device_record(host: &LpcipUsbHostController) -> [u8; 312] {
    let mut record = [0; 312];
    let path = b"/sys/devices/virtual/lpcip/device0";
    record[..path.len()].copy_from_slice(path);
    record[256..256 + BUS_ID.len()].copy_from_slice(BUS_ID.as_bytes());
    put_word(&mut record, 288, 1);
    put_word(&mut record, 292, 1);
    let state = host.state.lock().unwrap();
    put_word(
        &mut record,
        296,
        if state.command & (1 << 21) != 0 { 2 } else { 3 },
    );
    record[300..304].fill(0xff); // Test ROM VID/PID.
    record[309] = 1; // Configuration value.
    record[310] = 1; // One configuration.
    record[311] = 1; // One interface, listed separately by DEVLIST.
    record
}

/// A bounded, nonblocking, single-client USB/IP server exporting Device0 as `1-1`.
///
/// Binding supplies VBUS. IMPORT resets and addresses the model via firmware's
/// EP0 (vhci consumes SET_ADDRESS locally); Linux requests the remaining standard
/// enumeration transfers. Call `poll` on the same thread as `model.step`.
/// Protocol/socket errors close the client, cancel queued work, reset the device,
/// and are returned to the caller; the listener remains usable for a new client.
/// Clean EOF detaches normally; EOF inside a frame returns `InvalidData`.
pub struct UsbIpServer {
    listener: TcpListener,
    host: LpcipUsbHostController,
    connection: Option<Connection>,
}

impl UsbIpServer {
    pub const BUS_ID: &'static str = BUS_ID;

    pub fn bind(address: SocketAddr, host: LpcipUsbHostController) -> io::Result<Self> {
        if !address.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "USB/IP is restricted to loopback",
            ));
        }
        let listener = TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        host.set_vbus(true);
        Ok(Self {
            listener,
            host,
            connection: None,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    pub fn is_imported(&self) -> bool {
        self.connection.as_ref().is_some_and(|c| c.imported)
    }

    /// Close the current client and discard all URBs. The listener and VBUS stay
    /// available for reimport. A new IMPORT resets the bus again.
    pub fn detach(&mut self) {
        if let Some(connection) = self.connection.take() {
            let _ = connection.stream.shutdown(Shutdown::Both);
            if connection.imported {
                if let Some(urb) = connection.urbs.front() {
                    urb.abort(&self.host);
                }
                // bus_reset aborts the hardware recovery engine as well.
                let _ = self.host.bus_reset(LpcipUsbSpeed::High);
            }
        }
    }

    pub fn poll(&mut self) -> io::Result<()> {
        self.poll_at(Instant::now())
    }

    fn poll_at(&mut self, now: Instant) -> io::Result<()> {
        // Accept at most one connection each poll; reject extra clients without
        // disturbing the imported device or allowing an unbounded accept loop.
        match self.listener.accept() {
            Ok((stream, _)) if self.connection.is_none() => {
                self.connection = Some(Connection::new(stream, now)?);
            }
            Ok((stream, _)) => {
                stream.shutdown(Shutdown::Both)?;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
        let result = match &mut self.connection {
            Some(connection) => connection.poll(&self.host, now),
            None => return Ok(()),
        };
        match result {
            Ok(false) => Ok(()),
            Ok(true) => {
                self.detach();
                Ok(())
            }
            Err(e) => {
                self.detach();
                Err(e)
            }
        }
    }
}

impl Drop for UsbIpServer {
    fn drop(&mut self) {
        self.detach();
        self.host.set_vbus(false);
    }
}

#[cfg(test)]
mod tests {
    use super::super::{UsbCombo, ACTIVE, CONNECT, DEV_EN, LENGTH_MASK, SETUP, STALL};
    use super::*;

    struct Fixture {
        server: UsbIpServer,
        host: LpcipUsbHostController,
        peer: TcpStream,
    }

    impl Fixture {
        fn new() -> Self {
            let host = UsbCombo::new().host_controller();
            {
                let mut state = host.state.lock().unwrap();
                state.command = DEV_EN | CONNECT;
                state.epliststart = state.memory_base;
                state.databufstart = state.memory_base;
                state.memory[4..8].copy_from_slice(&4u32.to_le_bytes());
            }
            let mut server =
                UsbIpServer::bind("127.0.0.1:0".parse().unwrap(), host.clone()).unwrap();
            let peer = TcpStream::connect(server.local_addr().unwrap()).unwrap();
            peer.set_nodelay(true).unwrap();
            peer.set_nonblocking(true).unwrap();
            server.poll().unwrap();
            Self { server, host, peer }
        }

        fn send(&mut self, data: &[u8]) {
            // Test messages are small enough to fit in the local socket buffer.
            self.peer.write_all(data).unwrap();
        }

        fn receive(&mut self, length: usize) -> Vec<u8> {
            let mut result = Vec::new();
            for _ in 0..2000 {
                self.server.poll().unwrap();
                let mut bytes = [0; 4096];
                match self.peer.read(&mut bytes) {
                    Ok(0) if result.len() == length => return result,
                    Ok(0) => panic!("early EOF: {} of {length}", result.len()),
                    Ok(n) => result.extend_from_slice(&bytes[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(e) => panic!("{e}"),
                }
                if result.len() >= length {
                    assert_eq!(result.len(), length);
                    return result;
                }
                std::thread::yield_now();
            }
            panic!("response did not arrive: {} of {length}", result.len());
        }

        fn import(&mut self) {
            self.send(&import_request(BUS_ID.as_bytes()));
            let response = self.receive(320);
            assert_eq!(word(&response, 4), 0);
            assert!(self.server.is_imported());
            // Emulate firmware servicing import reset, SET_ADDRESS and its
            // status ACK. Individual tests service subsequent real URBs.
            self.host.state.lock().unwrap().command &= !super::super::RESET_CHANGE;
            self.server.poll().unwrap();
            self.firmware();
            self.arm(1, 0, ACTIVE);
            self.server.poll().unwrap();
            assert!(self
                .server
                .connection
                .as_ref()
                .unwrap()
                .addressing
                .is_none());
            self.host.state.lock().unwrap().pending_address = 1;
        }

        fn firmware(&self) {
            self.host.state.lock().unwrap().command &= !SETUP;
        }

        fn arm(&self, physical: usize, length: usize, flags: u32) {
            let mut state = self.host.state.lock().unwrap();
            let word = flags | ((length as u32) << 11) | 8;
            state.memory[physical * 8..physical * 8 + 4].copy_from_slice(&word.to_le_bytes());
        }

        fn poll_error(&mut self) -> io::Error {
            for _ in 0..2000 {
                if let Err(error) = self.server.poll() {
                    assert!(!self.server.is_connected());
                    return error;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            panic!("expected client error");
        }
    }

    fn operation(op: u16) -> Vec<u8> {
        let mut bytes = operation_reply(op, 0);
        bytes[2..4].copy_from_slice(&op.to_be_bytes());
        bytes
    }

    fn import_request(bus: &[u8]) -> Vec<u8> {
        let mut bytes = operation(IMPORT);
        bytes.resize(40, 0);
        bytes[8..8 + bus.len()].copy_from_slice(bus);
        bytes
    }

    fn submit(seq: u32, direction: u32, setup: [u8; 8], payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 48];
        put_word(&mut bytes, 0, 1);
        put_word(&mut bytes, 4, seq);
        put_word(&mut bytes, 8, DEVID);
        put_word(&mut bytes, 12, direction);
        put_word(
            &mut bytes,
            24,
            u32::from(u16::from_le_bytes([setup[6], setup[7]])),
        );
        bytes[40..48].copy_from_slice(&setup);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn unlink(seq: u32, target: u32) -> Vec<u8> {
        let mut bytes = vec![0; 48];
        put_word(&mut bytes, 0, 2);
        put_word(&mut bytes, 4, seq);
        put_word(&mut bytes, 8, DEVID);
        put_word(&mut bytes, 20, target);
        bytes
    }

    const GET_DESCRIPTOR: [u8; 8] = [0x80, 6, 0, 1, 0, 0, 18, 0];

    #[test]
    fn loopback_only_and_drop_removes_vbus() {
        let host = UsbCombo::new().host_controller();
        assert!(UsbIpServer::bind("0.0.0.0:0".parse().unwrap(), host.clone()).is_err());
        {
            let server = UsbIpServer::bind("127.0.0.1:0".parse().unwrap(), host.clone()).unwrap();
            assert!(server.local_addr().unwrap().ip().is_loopback());
            assert!(host.state.lock().unwrap().vbus);
        }
        assert!(!host.state.lock().unwrap().vbus);
    }

    #[test]
    fn devlist_reports_exactly_device0_and_closes() {
        let mut f = Fixture::new();
        f.send(&operation(DEVLIST));
        let response = f.receive(328);
        assert_eq!(&response[..4], &[1, 0x11, 0, 5]);
        assert_eq!(word(&response, 8), 1);
        assert_eq!(&response[12 + 256..12 + 259], BUS_ID.as_bytes());
        assert_eq!(word(&response, 12 + 288), 1);
        assert_eq!(&response[12 + 300..12 + 304], &[0xff; 4]);
        assert_eq!(&response[324..], &[0xef, 0x08, 0x01, 0]);
        assert!(!f.server.is_connected());
    }

    #[test]
    fn devlist_hides_disconnected_device_and_invalid_import_fails() {
        let mut f = Fixture::new();
        f.host.state.lock().unwrap().command &= !CONNECT;
        f.send(&operation(DEVLIST));
        assert_eq!(word(&f.receive(12), 8), 0);
        let mut f = Fixture::new();
        f.send(&import_request(b"1-2"));
        let response = f.receive(8);
        assert_eq!(word(&response, 4), 1);
        assert!(!f.server.is_imported());
    }

    #[test]
    fn fragmented_import_resets_and_detach_allows_reimport() {
        let mut f = Fixture::new();
        {
            let mut state = f.host.state.lock().unwrap();
            state.address = 7;
            state.pending_address = 7;
        }
        let bytes = import_request(BUS_ID.as_bytes());
        for byte in &bytes[..39] {
            f.send(&[*byte]);
            f.server.poll().unwrap();
            assert!(!f.server.is_imported());
        }
        f.send(&bytes[39..]);
        f.receive(320);
        assert_eq!(f.host.device_address(), 0);
        f.server.detach();
        f.peer = TcpStream::connect(f.server.local_addr().unwrap()).unwrap();
        f.peer.set_nonblocking(true).unwrap();
        f.import();
    }

    #[test]
    fn control_in_uses_model_setup_data_and_out_status_with_nak_retries() {
        let mut f = Fixture::new();
        f.import();
        let request = submit(42, 1, GET_DESCRIPTOR, &[]);
        for chunk in request.chunks(7) {
            f.send(chunk);
            f.server.poll().unwrap();
        }
        for _ in 0..10 {
            f.server.poll().unwrap();
        }
        {
            let state = f.host.state.lock().unwrap();
            assert_eq!(&state.memory[0x100..0x108], &GET_DESCRIPTOR);
            assert_ne!(state.command & SETUP, 0);
        }
        f.firmware();
        let descriptor = [18, 1, 0, 2, 0, 0, 0, 64, 0x14, 0x14, 1, 0, 0, 1, 0, 0, 0, 1];
        f.host.state.lock().unwrap().memory[0x200..0x212].copy_from_slice(&descriptor);
        f.arm(1, 18, ACTIVE);
        f.server.poll().unwrap();
        assert_eq!(f.server.connection.as_ref().unwrap().urbs[0].actual, 18);
        f.server.poll().unwrap(); // Status OUT NAK until firmware arms it.
        assert_eq!(f.server.connection.as_ref().unwrap().urbs.len(), 1);
        f.arm(0, 0, ACTIVE);
        let response = f.receive(66);
        assert_eq!(word(&response, 0), 3);
        assert_eq!(word(&response, 4), 42);
        assert_eq!(word(&response, 20), 0);
        assert_eq!(word(&response, 24), 18);
        assert_eq!(&response[48..], &descriptor);
        let state = f.host.state.lock().unwrap();
        assert_eq!(
            u32::from_le_bytes(state.memory[..4].try_into().unwrap()) & ACTIVE,
            0
        );
    }

    #[test]
    fn multipacket_control_out_and_in_status() {
        let mut f = Fixture::new();
        f.import();
        let payload: Vec<u8> = (0..100).collect();
        let request = submit(7, 0, [0x40, 1, 0, 0, 0, 0, 100, 0], &payload);
        // A partial OUT frame must not execute SETUP.
        f.send(&request[..60]);
        f.server.poll().unwrap();
        assert_eq!(f.host.state.lock().unwrap().command & SETUP, 0);
        f.send(&request[60..]);
        f.server.poll().unwrap();
        f.firmware();
        f.arm(0, 100, ACTIVE);
        f.server.poll().unwrap();
        f.server.poll().unwrap();
        {
            let state = f.host.state.lock().unwrap();
            assert_eq!(&state.memory[0x200..0x264], &payload);
            let word = u32::from_le_bytes(state.memory[..4].try_into().unwrap());
            assert_eq!(word & (ACTIVE | LENGTH_MASK), 0);
        }
        f.arm(1, 0, ACTIVE);
        let response = f.receive(48);
        assert_eq!(word(&response, 20), 0);
        assert_eq!(word(&response, 24), 100);
    }

    #[test]
    fn no_data_status_and_current_model_address() {
        let mut f = Fixture::new();
        f.import();
        f.send(&submit(1, 0, [0, 5, 7, 0, 0, 0, 0, 0], &[]));
        f.server.poll().unwrap();
        f.firmware();
        f.arm(1, 0, ACTIVE);
        assert_eq!(word(&f.receive(48), 20), 0);
        // vhci handles virtual SET_ADDRESS itself. Transport tokens always use
        // the actual model address, not the USB/IP logical device number.
        {
            let mut state = f.host.state.lock().unwrap();
            state.address = 7;
            state.pending_address = 7;
        }
        f.send(&submit(2, 0, [0, 9, 1, 0, 0, 0, 0, 0], &[]));
        f.server.poll().unwrap();
        assert_eq!(f.host.device_address(), 7);
        f.firmware();
        f.arm(1, 0, ACTIVE);
        assert_eq!(word(&f.receive(48), 20), 0);
    }

    #[test]
    fn stall_and_unsupported_endpoint_return_errors() {
        let mut f = Fixture::new();
        f.import();
        f.send(&submit(1, 1, GET_DESCRIPTOR, &[]));
        f.server.poll().unwrap();
        f.firmware();
        f.arm(1, 0, STALL);
        assert_eq!(word(&f.receive(48), 20) as i32, EPIPE);
        let mut request = submit(2, 1, GET_DESCRIPTOR, &[]);
        put_word(&mut request, 16, 1);
        f.send(&request);
        assert_eq!(word(&f.receive(48), 20) as i32, EPIPE);
        assert!(f.server.connection.as_ref().unwrap().urbs.is_empty());
    }

    #[test]
    fn unlink_live_queued_and_unknown_are_linux_compatible() {
        let mut f = Fixture::new();
        f.import();
        let mut bytes = submit(1, 1, GET_DESCRIPTOR, &[]);
        bytes.extend(submit(2, 1, GET_DESCRIPTOR, &[]));
        f.send(&bytes);
        f.server.poll().unwrap();
        let mut bytes = unlink(3, 1);
        bytes.extend(unlink(4, 2));
        bytes.extend(unlink(5, 999));
        f.send(&bytes);
        let response = f.receive(144);
        for (index, status) in [ECONNRESET, ECONNRESET, 0].into_iter().enumerate() {
            let frame = &response[index * 48..(index + 1) * 48];
            assert_eq!(word(frame, 0), 4);
            assert_eq!(word(frame, 4), index as u32 + 3);
            assert_eq!(word(frame, 20) as i32, status);
        }
        assert!(f.server.connection.as_ref().unwrap().urbs.is_empty());
        assert!(f.server.is_imported());
    }

    #[test]
    fn malformed_urb_headers_drop_connection_without_allocation() {
        for (offset, value) in [
            (0, 99),
            (8, DEVID + 1),
            (12, 2),
            (16, 16),
            (24, MAX_TRANSFER as u32 + 1),
            (24, u32::MAX),
            (32, 1),
        ] {
            let mut f = Fixture::new();
            f.import();
            let mut request = submit(1, 1, GET_DESCRIPTOR, &[]);
            put_word(&mut request, offset, value);
            f.send(&request);
            assert_eq!(f.poll_error().kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn malformed_setup_returns_protocol_error() {
        let mut f = Fixture::new();
        f.import();
        let mut request = submit(1, 1, GET_DESCRIPTOR, &[]);
        put_word(&mut request, 24, 17);
        f.send(&request);
        assert_eq!(word(&f.receive(48), 20) as i32, EPROTO);
        assert_eq!(f.host.state.lock().unwrap().command & SETUP, 0);
    }

    #[test]
    fn invalid_operation_header_is_rejected() {
        for bytes in [
            vec![0, 0, 0x80, 5, 0, 0, 0, 0],
            vec![1, 0x11, 0x80, 5, 0, 0, 0, 1],
            vec![1, 0x11, 0x80, 99, 0, 0, 0, 0],
        ] {
            let mut f = Fixture::new();
            f.send(&bytes);
            assert_eq!(f.poll_error().kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn duplicate_sequence_and_urb_limit_are_bounded() {
        for count in [2, MAX_URBS + 1] {
            let mut f = Fixture::new();
            f.import();
            let mut requests = Vec::new();
            for index in 0..count {
                requests.extend(submit(
                    if count == 2 { 1 } else { index as u32 },
                    1,
                    GET_DESCRIPTOR,
                    &[],
                ));
            }
            f.send(&requests);
            assert_eq!(f.poll_error().kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn nak_deadlines_expire_active_and_queued_urbs() {
        let mut f = Fixture::new();
        f.import();
        let mut request = submit(1, 1, GET_DESCRIPTOR, &[]);
        request.extend(submit(2, 1, GET_DESCRIPTOR, &[]));
        f.send(&request);
        f.server.poll().unwrap();
        let deadline = f.server.connection.as_ref().unwrap().urbs[0].deadline;
        f.server
            .poll_at(deadline + Duration::from_millis(1))
            .unwrap();
        let response = f.receive(96);
        assert_eq!(word(&response, 20) as i32, ETIMEDOUT);
        assert_eq!(word(&response[48..], 20) as i32, ETIMEDOUT);
        assert!(f.server.connection.as_ref().unwrap().urbs.is_empty());
    }

    #[test]
    fn stalled_handshake_partial_frame_and_output_have_deadlines() {
        for mode in 0..3 {
            let mut f = Fixture::new();
            if mode != 0 {
                f.import();
            }
            let now = Instant::now();
            let connection = f.server.connection.as_mut().unwrap();
            match mode {
                0 => connection.connected_at = now - TIMEOUT,
                1 => {
                    connection.input.push(0);
                    connection.input_since = Some(now - TIMEOUT);
                }
                _ => {
                    // Deterministically saturate the send socket without sleeps.
                    let buffer = [0; 4096];
                    let mut blocked = false;
                    for _ in 0..16384 {
                        match connection.stream.write(&buffer) {
                            Ok(_) => {}
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                blocked = true;
                                break;
                            }
                            Err(e) => panic!("{e}"),
                        }
                    }
                    assert!(blocked);
                    connection.queue(&[0; 48], now - TIMEOUT).unwrap();
                }
            }
            let error = f
                .server
                .poll_at(now + Duration::from_millis(1))
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(!f.server.is_connected());
        }
    }

    #[test]
    fn disconnect_and_model_unplug_discard_all_work() {
        for unplug in [false, true] {
            let mut f = Fixture::new();
            f.import();
            f.send(&submit(1, 1, GET_DESCRIPTOR, &[]));
            f.server.poll().unwrap();
            if unplug {
                f.host.state.lock().unwrap().command &= !CONNECT;
                assert_eq!(f.poll_error().kind(), io::ErrorKind::NotConnected);
            } else {
                f.peer.shutdown(Shutdown::Both).unwrap();
                for _ in 0..2000 {
                    f.server.poll().unwrap();
                    if !f.server.is_connected() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            assert!(!f.server.is_connected());
            assert!(!f.server.is_imported());
        }
    }

    #[test]
    fn output_bound_and_short_writes_preserve_framing() {
        let mut f = Fixture::new();
        f.import();
        let now = Instant::now();
        let connection = f.server.connection.as_mut().unwrap();
        let data: Vec<u8> = (0..MAX_BUFFER).map(|i| i as u8).collect();
        connection.queue(&data, now).unwrap();
        assert!(connection.queue(&[1], now).is_err());
        connection.write(now).unwrap();
        assert!(connection.output.len() >= MAX_BUFFER - IO_BUDGET);
        assert_eq!(f.receive(MAX_BUFFER), data);
    }

    #[test]
    fn control_in_short_packets_flags_and_overflow() {
        for (requested, supplied, flags, expected) in
            [(100, 18, 0, 0), (100, 18, 1, -121), (18, 64, 0, EPROTO)]
        {
            let mut f = Fixture::new();
            f.import();
            let mut setup = GET_DESCRIPTOR;
            setup[6] = requested;
            let mut request = submit(1, 1, setup, &[]);
            put_word(&mut request, 20, flags);
            f.send(&request);
            f.server.poll().unwrap();
            f.firmware();
            f.arm(1, supplied, ACTIVE);
            f.server.poll().unwrap();
            if expected != EPROTO {
                f.arm(0, 0, ACTIVE);
            }
            let actual = if expected == EPROTO { 0 } else { supplied };
            let response = f.receive(48 + actual);
            assert_eq!(word(&response, 20) as i32, expected);
            assert_eq!(word(&response, 24) as usize, actual);
        }
    }

    #[test]
    fn multipacket_control_in_waits_for_status() {
        let mut f = Fixture::new();
        f.import();
        let mut setup = GET_DESCRIPTOR;
        setup[6] = 130;
        f.send(&submit(1, 1, setup, &[]));
        f.server.poll().unwrap();
        f.firmware();
        let payload: Vec<u8> = (0..130).collect();
        f.host.state.lock().unwrap().memory[0x200..0x282].copy_from_slice(&payload);
        f.arm(1, 130, ACTIVE);
        for actual in [64, 128, 130] {
            f.server.poll().unwrap();
            assert_eq!(f.server.connection.as_ref().unwrap().urbs[0].actual, actual);
        }
        f.arm(0, 0, ACTIVE);
        assert_eq!(&f.receive(178)[48..], &payload);
    }

    #[test]
    fn cancelling_or_expiring_active_recovery_aborts_staging() {
        for expire in [false, true] {
            let mut f = Fixture::new();
            f.import();
            f.send(&submit(1, 1, [0xa1, 0, 0x22, 0, 0, 0, 64, 0], &[]));
            f.server.poll().unwrap();
            assert!(f.host.recovery_snapshot().unwrap().claimed);
            if expire {
                let deadline = f.server.connection.as_ref().unwrap().urbs[0].deadline;
                f.server.poll_at(deadline).unwrap();
            } else {
                f.send(&unlink(2, 1));
            }
            f.receive(48);
            assert!(!f.host.recovery_snapshot().unwrap().claimed);
            assert!(f.server.connection.as_ref().unwrap().urbs.is_empty());
        }
    }

    #[test]
    fn unplug_and_detach_abort_active_recovery_without_further_transactions() {
        for unplug in [false, true] {
            let mut f = Fixture::new();
            f.import();
            f.send(&submit(1, 1, [0xa1, 0, 0x22, 0, 0, 0, 64, 0], &[]));
            f.server.poll().unwrap();
            assert!(f.host.recovery_snapshot().unwrap().claimed);
            if unplug {
                f.host.state.lock().unwrap().command &= !CONNECT;
                assert_eq!(f.poll_error().kind(), io::ErrorKind::NotConnected);
            } else {
                f.server.detach();
            }
            assert!(!f.host.recovery_snapshot().unwrap().claimed);
            assert!(!f.server.is_connected());
        }
    }

    #[test]
    fn input_limit_is_enforced_and_partial_out_frame_expires() {
        let mut f = Fixture::new();
        f.import();
        f.server
            .connection
            .as_mut()
            .unwrap()
            .input
            .resize(MAX_BUFFER, 0);
        f.send(&[0]);
        assert_eq!(f.poll_error().kind(), io::ErrorKind::InvalidData);

        let mut f = Fixture::new();
        f.import();
        let request = submit(1, 0, [0x40, 0, 0, 0, 0, 0, 64, 0], &[]);
        f.send(&request);
        f.server.poll().unwrap();
        assert!(f.server.connection.as_ref().unwrap().urbs.is_empty());
        let start = f.server.connection.as_ref().unwrap().input_since.unwrap();
        assert_eq!(
            f.server.poll_at(start + TIMEOUT).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(!f.server.is_connected());
    }

    #[test]
    fn extra_clients_do_not_disrupt_import() {
        let mut f = Fixture::new();
        f.import();
        let extra = TcpStream::connect(f.server.local_addr().unwrap()).unwrap();
        extra
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        f.server.poll().unwrap();
        let mut extra = extra;
        assert_eq!(extra.read(&mut [0]).unwrap(), 0);
        assert!(f.server.is_imported());
    }

    #[test]
    fn import_addresses_firmware_after_reset_and_waits_for_address_commit() {
        let mut f = Fixture::new();
        f.send(&import_request(BUS_ID.as_bytes()));
        f.receive(320);
        assert_eq!(f.host.state.lock().unwrap().command & SETUP, 0);
        f.server.poll().unwrap();
        assert_eq!(f.host.state.lock().unwrap().command & SETUP, 0);
        f.host.state.lock().unwrap().command &= !super::super::RESET_CHANGE;
        f.server.poll().unwrap();
        assert_eq!(
            &f.host.state.lock().unwrap().memory[0x100..0x108],
            &[0, 5, 1, 0, 0, 0, 0, 0]
        );
        f.firmware();
        f.arm(1, 0, ACTIVE);
        f.server.poll().unwrap();
        assert!(f.server.connection.as_ref().unwrap().addressing.is_none());
        f.send(&submit(1, 1, GET_DESCRIPTOR, &[]));
        f.server.poll().unwrap();
        assert_eq!(f.host.device_address(), 0);
        assert!(f.server.connection.as_ref().unwrap().urbs[0].stage == Stage::Setup);
        f.host.state.lock().unwrap().pending_address = 1;
        f.server.poll().unwrap();
        assert_eq!(f.host.device_address(), 1);
        assert_eq!(
            &f.host.state.lock().unwrap().memory[0x100..0x108],
            &GET_DESCRIPTOR
        );
    }

    #[test]
    fn unresponsive_or_stalling_address_initialization_is_bounded() {
        for stall in [false, true] {
            let mut f = Fixture::new();
            f.send(&import_request(BUS_ID.as_bytes()));
            f.receive(320);
            let expected = if stall {
                f.host.state.lock().unwrap().command &= !super::super::RESET_CHANGE;
                f.server.poll().unwrap();
                f.firmware();
                f.arm(1, 0, STALL);
                f.poll_error().kind()
            } else {
                let deadline = f
                    .server
                    .connection
                    .as_ref()
                    .unwrap()
                    .addressing
                    .as_ref()
                    .unwrap()
                    .deadline;
                f.server.poll_at(deadline).unwrap_err().kind()
            };
            assert_eq!(
                expected,
                if stall {
                    io::ErrorKind::Other
                } else {
                    io::ErrorKind::TimedOut
                }
            );
            assert!(!f.server.is_connected());
        }
    }

    #[test]
    fn eof_is_benign_only_at_a_complete_frame_boundary() {
        for imported in [false, true] {
            for truncated in [false, true] {
                let mut f = Fixture::new();
                if imported {
                    f.import();
                    let request = submit(1, 1, GET_DESCRIPTOR, &[]);
                    f.send(if truncated { &request[..47] } else { &request });
                } else if truncated {
                    f.send(&operation(IMPORT)[..7]);
                }
                f.peer.shutdown(Shutdown::Write).unwrap();
                if truncated {
                    assert_eq!(f.poll_error().kind(), io::ErrorKind::InvalidData);
                } else {
                    for _ in 0..2000 {
                        f.server.poll().unwrap();
                        if !f.server.is_connected() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    assert!(!f.server.is_connected());
                }
            }
        }
    }

    #[test]
    fn eof_after_more_than_one_parse_budget_is_not_a_truncated_frame() {
        let mut f = Fixture::new();
        f.import();
        let mut bytes = Vec::new();
        for seq in 0..FRAME_BUDGET + 1 {
            let mut request = submit(seq as u32, 1, GET_DESCRIPTOR, &[]);
            put_word(&mut request, 16, 1);
            bytes.extend_from_slice(&request);
        }
        f.send(&bytes);
        f.peer.shutdown(Shutdown::Write).unwrap();
        for _ in 0..2000 {
            f.server.poll().unwrap();
            if !f.server.is_connected() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(!f.server.is_connected());
    }
}

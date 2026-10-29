// Licensed under the Apache-2.0 license

use super::{LpcipUsbError, LpcipUsbHostController, LpcipUsbSpeed, CONNECT, FORCE_VBUS, VBUS};
use std::sync::{Arc, Mutex};

const TABLE_WORDS: usize = 196;
const CONTROL_WORD: usize = 12;
const ENABLE: u32 = 1;
const SELF_POWERED: u32 = 1 << 18;
const CONNECTION_CHANGE: u16 = 1;
const SUSPEND_CHANGE: u16 = 1 << 2;
const RESET_CHANGE: u16 = 1 << 4;

#[derive(Default)]
struct Port {
    connected: bool,
    enabled: bool,
    suspended: bool,
    change: u16,
}

enum Transfer {
    Idle,
    Stall,
    DataIn {
        data: Vec<u8>,
        offset: usize,
        zlp: bool,
    },
    StatusIn,
    StatusOut,
}

pub(super) struct Hub {
    table: [u32; TABLE_WORDS],
    vbus: bool,
    speed: LpcipUsbSpeed,
    address: u8,
    pending_address: u8,
    configuration: u8,
    remote_wakeup: bool,
    interrupt_halted: bool,
    ports: [Port; 2],
    transfer: Transfer,
}

impl Default for Hub {
    fn default() -> Self {
        Self {
            table: reset_table(),
            vbus: false,
            speed: LpcipUsbSpeed::Full,
            address: 0,
            pending_address: 0,
            configuration: 0,
            remote_wakeup: false,
            interrupt_halted: false,
            ports: Default::default(),
            transfer: Transfer::Idle,
        }
    }
}

impl Hub {
    pub(super) fn reset(&mut self) {
        let vbus = self.vbus;
        *self = Self {
            vbus,
            ..Self::default()
        };
    }

    fn connected(&self) -> bool {
        self.table[CONTROL_WORD] & (ENABLE | CONNECT) == ENABLE | CONNECT
            && (self.vbus || self.table[CONTROL_WORD] & FORCE_VBUS != 0)
    }

    pub(super) fn read_word(&self, index: usize) -> u32 {
        if index != CONTROL_WORD {
            return self.table[index];
        }
        let speed = match self.speed {
            LpcipUsbSpeed::Full => 1,
            LpcipUsbSpeed::High => 2,
        };
        (self.table[index] & !((3 << 22) | VBUS)) | (speed << 22) | if self.vbus { VBUS } else { 0 }
    }

    pub(super) fn write_word(&mut self, index: usize, value: u32) {
        if index == CONTROL_WORD {
            let old = self.table[index];
            self.table[index] = value & !((3 << 22) | VBUS);
            if (old ^ value) & SELF_POWERED != 0 {
                let attributes = if value & SELF_POWERED != 0 {
                    0xc0
                } else {
                    0x80
                };
                for word in [17, 65] {
                    self.table[word] = (self.table[word] & 0x00ff_ffff) | (attributes << 24);
                }
            }
            if !self.connected() {
                self.transfer = Transfer::Idle;
            }
        } else if self.table[CONTROL_WORD] & (ENABLE | CONNECT) != ENABLE | CONNECT {
            self.table[index] = value;
        }
    }

    fn check_token(&self, address: u8) -> Result<(), LpcipUsbError> {
        if !self.connected() {
            return Err(LpcipUsbError::Disconnected);
        }
        if address != self.address && address != self.pending_address {
            return Err(LpcipUsbError::AddressMismatch);
        }
        Ok(())
    }

    fn sync_ports(&mut self, devices: &[LpcipUsbHostController; 2]) {
        for (port, device) in self.ports.iter_mut().zip(devices) {
            let connected = device.state.lock().unwrap().link_connected();
            if connected != port.connected {
                port.connected = connected;
                port.change |= CONNECTION_CHANGE;
            }
            if !connected {
                port.enabled = false;
                port.suspended = false;
                port.change &= CONNECTION_CHANGE;
            } else if !port.enabled {
                port.suspended = false;
                port.change &= CONNECTION_CHANGE;
            }
        }
    }

    fn port_index(port: u16) -> Result<usize, LpcipUsbError> {
        match port {
            1 | 2 => Ok(usize::from(port - 1)),
            _ => Err(LpcipUsbError::InvalidPort),
        }
    }

    fn check_port(&self, port: u8) -> Result<usize, LpcipUsbError> {
        if !self.connected() {
            return Err(LpcipUsbError::Disconnected);
        }
        let index = Self::port_index(u16::from(port))?;
        if !self.ports[index].connected {
            return Err(LpcipUsbError::Disconnected);
        }
        if self.configuration == 0 || !self.ports[index].enabled {
            return Err(LpcipUsbError::EndpointDisabled);
        }
        if self.ports[index].suspended {
            return Err(LpcipUsbError::Nak);
        }
        Ok(index)
    }

    fn port_status(&self, index: usize) -> u32 {
        let port = &self.ports[index];
        u32::from(port.connected)
            | (u32::from(port.enabled) << 1)
            | (u32::from(port.suspended) << 2)
            | (1 << 8) // Embedded ports are always powered in the RTL.
            | if self.speed == LpcipUsbSpeed::High { 1 << 10 } else { 0 }
            | (u32::from(port.change) << 16)
    }

    fn change_bitmap(&self) -> u8 {
        self.ports
            .iter()
            .enumerate()
            .fold(0, |bitmap, (index, port)| {
                bitmap
                    | if port.change != 0 {
                        1 << (index + 1)
                    } else {
                        0
                    }
            })
    }

    fn lookup(&self, setup: &[u8; 8]) -> Result<Option<(u32, usize)>, LpcipUsbError> {
        let command = u16::from_le_bytes([setup[0], setup[1]]);
        let value = u16::from_le_bytes([setup[2], setup[3]]);
        let index = u16::from_le_bytes([setup[4], setup[5]]);
        let length = usize::from(u16::from_le_bytes([setup[6], setup[7]]));
        let start = (self.table[14] & 0xfff) as usize;
        let entries = self
            .table
            .get(start..)
            .ok_or(LpcipUsbError::InvalidMemory)?;
        for words in entries.chunks_exact(4) {
            if words[0] as u16 == command
                && value & (words[1] >> 16) as u16 == (words[0] >> 16) as u16
                && index & words[3] as u16 == words[2] as u16
            {
                return Ok(Some((words[1], length.min((words[2] >> 16) as usize))));
            }
            if words[1] & 0x80 != 0 {
                return Ok(None);
            }
        }
        Err(LpcipUsbError::InvalidMemory)
    }

    fn descriptor(&self, selector: u32, length: usize) -> Result<Vec<u8>, LpcipUsbError> {
        let start = ((selector >> 8) & 0x3f) as usize * 16;
        let words = self
            .table
            .get(start..start + length.div_ceil(4))
            .ok_or(LpcipUsbError::InvalidMemory)?;
        Ok(words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .take(length)
            .collect())
    }

    fn standard_request(&mut self, request: u8, setup: &[u8; 8]) -> Result<Vec<u8>, LpcipUsbError> {
        let value = u16::from_le_bytes([setup[2], setup[3]]);
        let index = u16::from_le_bytes([setup[4], setup[5]]);
        let mut data = setup.to_vec();
        match request {
            0 => {}
            1 => self.pending_address = (value & 0x7f) as u8,
            2 => {
                self.configuration = (value & 1) as u8;
                self.interrupt_halted = false;
            }
            3 | 10 => match value {
                0 => {}
                1 => self.remote_wakeup = request == 3,
                2 if request == 3 => return Err(LpcipUsbError::UnsupportedTransfer),
                _ => return Err(LpcipUsbError::Stall),
            },
            4 | 11 => match index {
                0 | 0x80 => {}
                0x81 => self.interrupt_halted = request == 4,
                _ => return Err(LpcipUsbError::Stall),
            },
            5 => data[0] = self.configuration,
            6 => data[0] = 0,
            7 => {
                data[0] = u8::from(self.table[CONTROL_WORD] & SELF_POWERED != 0)
                    | (u8::from(self.remote_wakeup) << 1);
                data[1] = 0;
            }
            8 => data[..2].fill(0),
            9 => {
                data[0] = match index {
                    0 | 0x80 => 0,
                    0x81 => u8::from(self.interrupt_halted),
                    _ => return Err(LpcipUsbError::Stall),
                };
                data[1] = 0;
            }
            _ => return Err(LpcipUsbError::UnsupportedTransfer),
        }
        Ok(data)
    }

    fn class_request(
        &mut self,
        request: u8,
        setup: &[u8; 8],
        devices: &[LpcipUsbHostController; 2],
    ) -> Result<Vec<u8>, LpcipUsbError> {
        let value = u16::from_le_bytes([setup[2], setup[3]]);
        let index = u16::from_le_bytes([setup[4], setup[5]]);
        if request == 0x43 {
            return Err(LpcipUsbError::UnsupportedTransfer);
        }
        if index == 0 {
            return match request {
                0x42 => Ok(vec![0; 4]),
                0x40 | 0x41 if value <= 1 => Ok(Vec::new()),
                _ => Err(LpcipUsbError::Stall),
            };
        }
        let port_index = Self::port_index(index).map_err(|_| LpcipUsbError::Stall)?;
        if request == 0x42 {
            return Ok(self.port_status(port_index).to_le_bytes().to_vec());
        }
        let port = &mut self.ports[port_index];
        match (request, value) {
            (0x40, 1) => {
                port.enabled = false;
                port.suspended = false;
                port.change &= CONNECTION_CHANGE;
            }
            (0x40, 2) => {
                port.suspended = false;
                if port.enabled {
                    port.change |= SUSPEND_CHANGE;
                }
            }
            (0x40, 16) => port.change &= !CONNECTION_CHANGE,
            (0x40, 18) => port.change &= !SUSPEND_CHANGE,
            (0x40, 20) => port.change &= !RESET_CHANGE,
            (0x41, 1) => port.enabled = port.connected,
            (0x41, 2) => port.suspended = port.connected && port.enabled,
            (0x41, 4) => {
                if port.connected {
                    let mut state = devices[port_index].state.lock().unwrap();
                    state.reset_bus(self.speed);
                    port.enabled = true;
                    port.suspended = false;
                    port.change = (port.change & !SUSPEND_CHANGE) | RESET_CHANGE;
                }
            }
            // These selectors are accepted but have no effect in the selected
            // embedded-port RTL (power is always on, no overcurrent or LEDs).
            (0x40 | 0x41, 0 | 3 | 8 | 9 | 17 | 19 | 21 | 22) | (0x40, 4) | (0x41, 16 | 18 | 20) => {
            }
            _ => return Err(LpcipUsbError::Stall),
        }
        Ok(Vec::new())
    }

    fn setup(
        &mut self,
        address: u8,
        setup: &[u8; 8],
        devices: &[LpcipUsbHostController; 2],
    ) -> Result<(), LpcipUsbError> {
        self.check_token(address)?;
        self.address = address;
        self.pending_address = address;
        self.transfer = Transfer::Stall;
        let Some((selector, length)) = self.lookup(setup)? else {
            return Ok(());
        };
        let response = match selector & 0xc000 {
            0 => self.standard_request((selector & 0x7f) as u8, setup),
            0x4000 => self.class_request((selector & 0x7f) as u8, setup, devices),
            0x8000 => self.descriptor(selector, length),
            _ => Err(LpcipUsbError::UnsupportedTransfer),
        };
        let mut data = match response {
            Ok(data) => data,
            Err(LpcipUsbError::Stall) => return Ok(()),
            Err(error) => return Err(error),
        };
        let requested = usize::from(u16::from_le_bytes([setup[6], setup[7]]));
        if setup[0] & 0x80 != 0 && requested != 0 {
            data.truncate(length);
            let zlp = data.len() < requested && data.len().is_multiple_of(64);
            self.transfer = Transfer::DataIn {
                data,
                offset: 0,
                zlp,
            };
        } else {
            self.transfer = Transfer::StatusIn;
        }
        Ok(())
    }

    fn host_in(&mut self, endpoint: u8) -> Result<Vec<u8>, LpcipUsbError> {
        if endpoint == 1 {
            if self.configuration == 0 {
                return Err(LpcipUsbError::EndpointDisabled);
            }
            if self.interrupt_halted {
                return Err(LpcipUsbError::Stall);
            }
            let bitmap = self.change_bitmap();
            return if bitmap == 0 {
                Err(LpcipUsbError::Nak)
            } else {
                Ok(vec![bitmap])
            };
        }
        if endpoint != 0 {
            return Err(LpcipUsbError::InvalidEndpoint);
        }
        match &mut self.transfer {
            Transfer::Stall => Err(LpcipUsbError::Stall),
            Transfer::StatusIn => {
                self.transfer = Transfer::Idle;
                Ok(Vec::new())
            }
            Transfer::DataIn { data, offset, zlp } => {
                let end = (*offset + 64).min(data.len());
                let packet = data[*offset..end].to_vec();
                *offset = end;
                if end == data.len() && (packet.len() < 64 || !*zlp) {
                    self.transfer = Transfer::StatusOut;
                }
                Ok(packet)
            }
            _ => Err(LpcipUsbError::Nak),
        }
    }

    fn host_out(&mut self, endpoint: u8, data: &[u8]) -> Result<(), LpcipUsbError> {
        if endpoint != 0 {
            return Err(LpcipUsbError::InvalidEndpoint);
        }
        match self.transfer {
            Transfer::Stall => Err(LpcipUsbError::Stall),
            Transfer::StatusOut if data.is_empty() => {
                self.transfer = Transfer::Idle;
                Ok(())
            }
            Transfer::StatusOut => Err(LpcipUsbError::DataTooLong),
            _ => Err(LpcipUsbError::Nak),
        }
    }
}

/// Transaction-level host for the upstream hub and its two embedded ports.
/// Hub requests are hardware-managed; downstream requests still require each
/// device's firmware-owned descriptors and never synthesize firmware replies.
#[derive(Clone)]
pub struct LpcipUsbHubHostController {
    hub: Arc<Mutex<Hub>>,
    devices: [LpcipUsbHostController; 2],
}

impl LpcipUsbHubHostController {
    pub(super) fn new(hub: Arc<Mutex<Hub>>, devices: [LpcipUsbHostController; 2]) -> Self {
        Self { hub, devices }
    }

    pub(super) fn poll(&self) {
        self.hub.lock().unwrap().sync_ports(&self.devices);
    }

    pub fn connected(&self) -> bool {
        self.hub.lock().unwrap().connected()
    }

    pub fn device_address(&self) -> u8 {
        self.hub.lock().unwrap().address
    }

    pub fn set_vbus(&self, present: bool) {
        for device in &self.devices {
            device.set_vbus(present);
        }
        let mut hub = self.hub.lock().unwrap();
        hub.vbus = present;
        if !hub.connected() {
            hub.transfer = Transfer::Idle;
        }
        hub.sync_ports(&self.devices);
    }

    pub fn bus_reset(&self, speed: LpcipUsbSpeed) -> Result<(), LpcipUsbError> {
        let mut hub = self.hub.lock().unwrap();
        if !hub.connected() {
            return Err(LpcipUsbError::Disconnected);
        }
        hub.speed = if hub.table[CONTROL_WORD] & (1 << 21) != 0 {
            LpcipUsbSpeed::Full
        } else {
            speed
        };
        hub.address = 0;
        hub.pending_address = 0;
        hub.configuration = 0;
        hub.remote_wakeup = false;
        hub.interrupt_halted = false;
        hub.ports = Default::default();
        hub.transfer = Transfer::Idle;
        for device in &self.devices {
            let mut state = device.state.lock().unwrap();
            if state.link_connected() {
                state.reset_bus(hub.speed);
            }
        }
        hub.sync_ports(&self.devices);
        Ok(())
    }

    pub fn host_setup(&self, address: u8, setup: &[u8]) -> Result<(), LpcipUsbError> {
        let setup = setup.try_into().map_err(|_| LpcipUsbError::InvalidSetup)?;
        let mut hub = self.hub.lock().unwrap();
        hub.sync_ports(&self.devices);
        hub.setup(address, setup, &self.devices)
    }

    pub fn host_in(&self, address: u8, endpoint: u8) -> Result<Vec<u8>, LpcipUsbError> {
        let mut hub = self.hub.lock().unwrap();
        hub.check_token(address)?;
        hub.sync_ports(&self.devices);
        hub.host_in(endpoint)
    }

    pub fn host_out(&self, address: u8, endpoint: u8, data: &[u8]) -> Result<(), LpcipUsbError> {
        let mut hub = self.hub.lock().unwrap();
        hub.check_token(address)?;
        hub.host_out(endpoint, data)
    }

    pub fn port_setup(&self, port: u8, address: u8, setup: &[u8]) -> Result<(), LpcipUsbError> {
        let mut hub = self.hub.lock().unwrap();
        hub.sync_ports(&self.devices);
        let index = hub.check_port(port)?;
        self.devices[index].host_setup(address, setup)
    }

    pub fn port_in(&self, port: u8, address: u8, endpoint: u8) -> Result<Vec<u8>, LpcipUsbError> {
        let mut hub = self.hub.lock().unwrap();
        hub.sync_ports(&self.devices);
        let index = hub.check_port(port)?;
        self.devices[index].host_in(address, endpoint)
    }

    pub fn port_out(
        &self,
        port: u8,
        address: u8,
        endpoint: u8,
        data: &[u8],
    ) -> Result<(), LpcipUsbError> {
        let mut hub = self.hub.lock().unwrap();
        hub.sync_ports(&self.devices);
        let index = hub.check_port(port)?;
        self.devices[index].host_out(address, endpoint, data)
    }
}

fn reset_table() -> [u32; TABLE_WORDS] {
    let mut table = [0; TABLE_WORDS];
    // Reset descriptors from usb_ep0_hub_descr.m.vhdl, not a production VID/PID
    // allocation. Firmware may replace descriptors before enabling/connecting.
    let descriptors: &[(usize, &[u8])] = &[
        (
            0,
            &[
                18, 1, 0x10, 2, 9, 0, 0, 64, 0xc9, 0x1f, 0, 0xbe, 0, 1, 0, 0, 0, 1,
            ],
        ),
        (
            16,
            &[
                9, 2, 25, 0, 1, 1, 0, 0x80, 250, 9, 4, 0, 0, 1, 9, 0, 0, 0, 7, 5, 0x81, 3, 1, 0, 12,
            ],
        ),
        (32, &[9, 0x29, 2, 0x14, 0, 0, 0, 6, 0xff]),
        (48, &[10, 6, 0, 2, 0, 0, 0, 64, 1, 0]),
        (
            64,
            &[
                9, 7, 25, 0, 1, 1, 0, 0x80, 250, 9, 4, 0, 0, 1, 9, 0, 0, 0, 7, 5, 0x81, 3, 1, 0, 12,
            ],
        ),
        (80, &[5, 15, 12, 0, 1, 7, 16, 2, 2, 0, 0, 0]),
    ];
    for &(start, bytes) in descriptors {
        for (offset, chunk) in bytes.chunks(4).enumerate() {
            let mut word = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            table[start + offset] = u32::from_le_bytes(word);
        }
    }
    table[12] = 1 << 11;
    table[14] = 96;
    // Four DWORDs per request: expected request/value, value mask and action,
    // expected index/maximum length, index mask. Bit 7 marks the last entry.
    let requests = [
        [0x0100_0680, 0xffff_8000, 0x0012_0000, 0x0000_ffff],
        [0x0200_0680, 0xffff_8100, 0x0019_0000, 0x0000_ffff],
        [0x0000_0500, 0xf800_0001, 0, 0x0000_ffff],
        [0x0000_0900, 0xfffe_0002, 0, 0x0000_ffff],
        [0x0000_0300, 0xfffc_0003, 0, 0x0000_00ff],
        [0x0000_0302, 0xffff_0004, 0, 0x0000_ff7e],
        [0x0000_0b01, 0xffff_0000, 0, 0x0000_ffff],
        [0x0000_0880, 0xffff_0005, 0x0001_0000, 0x0000_ffff],
        [0x0000_0a81, 0xffff_0006, 0x0001_0000, 0x0000_ffff],
        [0x0000_0080, 0xffff_0007, 0x0002_0000, 0x0000_ffff],
        [0x0000_0081, 0xffff_0008, 0x0002_0000, 0x0000_ffff],
        [0x0000_0082, 0xffff_0009, 0x0002_0000, 0x0000_ff7e],
        [0x0000_0100, 0xfffe_000a, 0, 0x0000_ffff],
        [0x0000_0102, 0xffff_000b, 0, 0x0000_ff7e],
        [0x2900_06a0, 0xffff_8200, 0x0009_0000, 0x0000_ffff],
        [0x0000_00a0, 0xffff_4042, 0x0004_0000, 0x0000_ffff],
        [0x0000_00a3, 0xffff_4042, 0x0004_0000, 0x0000_fffc],
        [0x0000_0120, 0xfffe_4040, 0, 0x0000_ffff],
        [0x0000_0123, 0xffe0_4040, 0, 0x0000_fffc],
        [0x0000_0320, 0xfffe_4041, 0, 0x0000_ffff],
        [0x0000_0323, 0xffe0_4041, 0, 0x0000_fffc],
        [0x0600_0680, 0xffff_8300, 0x000a_0000, 0x0000_ffff],
        [0x0700_0680, 0xffff_8400, 0x0019_0000, 0x0000_ffff],
        [0x0f00_0680, 0xffff_8500, 0x000c_0000, 0x0000_ffff],
        [0x0000_0ca3, 0xffe0_40c3, 0x0001_0000, 0],
    ];
    for (index, request) in requests.iter().enumerate() {
        table[96 + index * 4..100 + index * 4].copy_from_slice(request);
    }
    table
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    ethernet.rs

Abstract:

    File contains Ethernet peripheral implementation for the Network Coprocessor.
--*/

use caliptra_emu_bus::{Clock, ReadWriteRegister, Timer};
use caliptra_emu_cpu::Irq;
use caliptra_emu_types::RvData;
use emulator_registers_generated::ethernet::{EthernetGenerated, EthernetPeripheral};
use registers_generated::ethernet::bits::{EthRxLen, EthStatus};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tock_registers::interfaces::{ReadWriteable, Readable};

pub const ETH_MAX_FRAME_SIZE: usize = 1514;
const RX_QUEUE_DEPTH: usize = 16;

pub trait TapDevice: Send {
    // Send an Ethernet frame to the TAP device
    fn send(&mut self, frame: &[u8]) -> std::io::Result<usize>;
    // Receive an Ethernet frame from the TAP device (non-blocking)
    fn recv(&mut self, buffer: &mut [u8]) -> std::io::Result<usize>;
    // Check if there are frames available to read
    fn poll_readable(&self) -> bool;
}

// A TAP device backend using a Unix TAP interface
#[cfg(target_os = "linux")]
pub struct LinuxTapDevice {
    fd: std::os::unix::io::RawFd,
}

#[cfg(target_os = "linux")]
impl LinuxTapDevice {
    // Open or create a TAP device with the given name
    pub fn open(name: &str) -> std::io::Result<Self> {
        use std::ffi::CString;

        // Open /dev/net/tun
        let fd = unsafe {
            let path = CString::new("/dev/net/tun").unwrap();
            libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK)
        };

        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Configure as TAP device
        #[repr(C)]
        struct IfReq {
            ifr_name: [u8; 16],
            ifr_flags: i16,
            _pad: [u8; 22],
        }

        let mut ifr = IfReq {
            ifr_name: [0; 16],
            ifr_flags: (libc::IFF_TAP | libc::IFF_NO_PI) as i16,
            _pad: [0; 22],
        };

        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(15);
        ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let ret = unsafe {
            libc::ioctl(fd, 0x400454ca /* TUNSETIFF */, &ifr as *const _)
        };

        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self { fd })
    }
}

#[cfg(target_os = "linux")]
impl TapDevice for LinuxTapDevice {
    fn send(&mut self, frame: &[u8]) -> std::io::Result<usize> {
        let ret = unsafe { libc::write(self.fd, frame.as_ptr() as *const _, frame.len()) };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    fn recv(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let ret = unsafe { libc::read(self.fd, buffer.as_mut_ptr() as *mut _, buffer.len()) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            Err(err)
        } else {
            Ok(ret as usize)
        }
    }

    fn poll_readable(&self) -> bool {
        let mut pollfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pollfd, 1, 0) };
        ret > 0 && (pollfd.revents & libc::POLLIN) != 0
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxTapDevice {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

// A dummy TAP device that discards all frames (for testing without a real TAP)
pub struct DummyTapDevice {
    rx_frames: VecDeque<Vec<u8>>,
}

impl DummyTapDevice {
    pub fn new() -> Self {
        Self {
            rx_frames: VecDeque::new(),
        }
    }

    // Inject a frame into the dummy device for testing
    pub fn inject_frame(&mut self, frame: Vec<u8>) {
        self.rx_frames.push_back(frame);
    }
}

impl Default for DummyTapDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl TapDevice for DummyTapDevice {
    fn send(&mut self, frame: &[u8]) -> std::io::Result<usize> {
        // Just discard the frame
        Ok(frame.len())
    }

    fn recv(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if let Some(frame) = self.rx_frames.pop_front() {
            let len = frame.len().min(buffer.len());
            buffer[..len].copy_from_slice(&frame[..len]);
            Ok(len)
        } else {
            Ok(0)
        }
    }

    fn poll_readable(&self) -> bool {
        !self.rx_frames.is_empty()
    }
}

// Control register bits
const CTRL_TX_START: u32 = 1 << 0;
const CTRL_RX_POP: u32 = 1 << 1;
const CTRL_IRQ_ACK: u32 = 1 << 2;

// Ethernet peripheral for the Network Coprocessor
pub struct Ethernet {
    generated: EthernetGenerated,
    tap: Option<Arc<Mutex<Box<dyn TapDevice>>>>,
    tx_buffer: Vec<u8>,
    tx_busy: bool,
    rx_queue: VecDeque<Vec<u8>>,
    irq: Irq,
    irq_pending: bool,
    timer: Timer,
}

impl Ethernet {
    // Create a new Ethernet peripheral
    //
    // # Arguments
    // * `tap` - Optional TAP device backend. If None, the peripheral operates in loopback/dummy mode.
    // * `irq` - Interrupt line for RX frame notifications
    // * `clock` - Clock reference for timing
    pub fn new(tap: Option<Arc<Mutex<Box<dyn TapDevice>>>>, irq: Irq, clock: &Clock) -> Self {
        let timer = Timer::new(clock);
        // Schedule initial poll
        timer.schedule_poll_in(1);
        Self {
            generated: EthernetGenerated::new(),
            tap,
            tx_buffer: vec![0u8; ETH_MAX_FRAME_SIZE],
            tx_busy: false,
            rx_queue: VecDeque::with_capacity(RX_QUEUE_DEPTH),
            irq,
            irq_pending: false,
            timer,
        }
    }

    pub fn set_mac_addr(&mut self, mac: [u8; 6]) {
        let mac_low = u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]);
        let mac_high = u32::from_le_bytes([mac[4], mac[5], 0, 0]);
        self.generated.write_eth_mac_low(mac_low);
        self.generated
            .write_eth_mac_high(ReadWriteRegister::new(mac_high));
    }

    pub fn mac_addr(&mut self) -> [u8; 6] {
        let mac_low = self.read_eth_mac_low().to_le_bytes();
        let mac_high = self.read_eth_mac_high().reg.get().to_le_bytes();
        [
            mac_low[0],
            mac_low[1],
            mac_low[2],
            mac_low[3],
            mac_high[0],
            mac_high[1],
        ]
    }

    fn transmit(&mut self) {
        let tx_len = self.read_eth_tx_len().reg.get() as u16;
        if tx_len == 0 || self.tx_busy {
            return;
        }

        let frame_len = tx_len as usize;
        if frame_len > ETH_MAX_FRAME_SIZE {
            // Invalid frame length
            return;
        }

        self.tx_busy = true;

        if let Some(tap) = &self.tap {
            if let Ok(mut tap) = tap.lock() {
                match tap.send(&self.tx_buffer[..frame_len]) {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("[ETH TX] Failed to send via TAP: {}", e);
                    }
                }
            }
        } else {
            eprintln!(
                "[ETH TX] No TAP device configured, frame size: {}",
                frame_len
            );
        }

        // Reset TX state
        self.tx_busy = false;
        self.write_eth_tx_len(ReadWriteRegister::new(0));
        self.write_eth_tx_ptr(ReadWriteRegister::new(0));
    }

    fn poll_rx(&mut self) {
        if self.rx_queue.len() >= RX_QUEUE_DEPTH {
            // Queue is full, drop incoming frames
            return;
        }

        if let Some(tap) = &self.tap {
            if let Ok(mut tap) = tap.lock() {
                let mut buffer = vec![0u8; ETH_MAX_FRAME_SIZE];
                match tap.recv(&mut buffer) {
                    Ok(len) if len > 0 => {
                        buffer.truncate(len);
                        self.rx_queue.push_back(buffer);
                        // Trigger interrupt
                        if !self.irq_pending {
                            self.irq_pending = true;
                            self.irq.set_level(true);
                        }
                    }
                    Ok(_) => {
                        // No data available (non-blocking)
                    }
                    Err(e) => {
                        eprintln!("[ETH RX] Error receiving from TAP: {}", e);
                    }
                }
            }
        }
    }

    fn current_rx_frame(&self) -> Option<&Vec<u8>> {
        self.rx_queue.front()
    }

    fn pop_rx_frame(&mut self) {
        self.rx_queue.front();
        self.rx_queue.pop_front();
        self.write_eth_rx_ptr(ReadWriteRegister::new(0));

        // Clear interrupt if no more frames
        if self.rx_queue.is_empty() && self.irq_pending {
            self.irq_pending = false;
            self.irq.set_level(false);
        }
    }

    fn ack_irq(&mut self) {
        if self.irq_pending && self.rx_queue.is_empty() {
            self.irq_pending = false;
            self.irq.set_level(false);
        }
    }
}

impl EthernetPeripheral for Ethernet {
    fn generated(&mut self) -> Option<&mut EthernetGenerated> {
        Some(&mut self.generated)
    }

    fn poll(&mut self) {
        // Poll for incoming frames
        self.poll_rx();

        // Schedule next poll
        self.timer.schedule_poll_in(1000); // Poll every 1000 cycles
    }

    fn warm_reset(&mut self) {
        self.generated.warm_reset();
        self.tx_buffer.fill(0);
        self.tx_busy = false;
        self.rx_queue.clear();
        self.irq_pending = false;
        self.irq.set_level(false);
    }

    fn update_reset(&mut self) {
        self.warm_reset();
    }

    fn read_eth_status(
        &mut self,
    ) -> ReadWriteRegister<u32, registers_generated::ethernet::bits::EthStatus::Register> {
        let status = ReadWriteRegister::<u32, EthStatus::Register>::new(0);

        // TX_READY: TX buffer is not busy
        if !self.tx_busy {
            status.reg.modify(EthStatus::TxReady::SET);
        }

        // RX_AVAIL: At least one frame in RX queue
        if !self.rx_queue.is_empty() {
            status.reg.modify(EthStatus::RxAvail::SET);
        }

        // TX_BUSY
        if self.tx_busy {
            status.reg.modify(EthStatus::TxBusy::SET);
        }

        // RX queue count in bits 15:8
        let queue_count = self.rx_queue.len().min(255) as u32;
        status.reg.modify(EthStatus::RxQueueCount.val(queue_count));

        status
    }

    fn write_eth_ctrl(
        &mut self,
        val: ReadWriteRegister<u32, registers_generated::ethernet::bits::EthCtrl::Register>,
    ) {
        let ctrl_val = val.reg.get();
        if ctrl_val & CTRL_TX_START != 0 {
            self.transmit();
        }
        if ctrl_val & CTRL_RX_POP != 0 {
            self.pop_rx_frame();
        }
        if ctrl_val & CTRL_IRQ_ACK != 0 {
            self.ack_irq();
        }
        self.generated.write_eth_ctrl(val);
    }

    fn read_eth_rx_len(
        &mut self,
    ) -> ReadWriteRegister<u32, registers_generated::ethernet::bits::EthRxLen::Register> {
        let len = self.current_rx_frame().map(|f| f.len()).unwrap_or(0) as u32;
        let reg = ReadWriteRegister::<u32, EthRxLen::Register>::new(0);
        reg.reg.modify(EthRxLen::Len.val(len));
        reg
    }

    fn read_eth_rx_data(&mut self, index: usize) -> RvData {
        if let Some(frame) = self.current_rx_frame() {
            let offset = index * 4;
            if offset + 4 <= frame.len() {
                u32::from_le_bytes([
                    frame[offset],
                    frame[offset + 1],
                    frame[offset + 2],
                    frame[offset + 3],
                ])
            } else if offset < frame.len() {
                // Partial read at end of frame
                let mut bytes = [0u8; 4];
                for (i, byte) in bytes.iter_mut().enumerate() {
                    if offset + i < frame.len() {
                        *byte = frame[offset + i];
                    }
                }
                u32::from_le_bytes(bytes)
            } else {
                0
            }
        } else {
            0
        }
    }

    fn write_eth_tx_data(&mut self, val: RvData, index: usize) {
        let offset = index * 4;
        if offset + 4 <= ETH_MAX_FRAME_SIZE {
            let bytes = val.to_le_bytes();
            self.tx_buffer[offset..offset + 4].copy_from_slice(&bytes);
        }
        self.generated.write_eth_tx_data(val, index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_emu_bus::{Bus, Clock};
    use caliptra_emu_cpu::Pic;
    use caliptra_emu_types::RvSize;
    use emulator_registers_generated::ethernet::EthernetBus;
    use std::rc::Rc;

    // Register offsets from the generated code
    const REG_CTRL: u32 = 0x00;
    const REG_STATUS: u32 = 0x04;
    const REG_TX_LEN: u32 = 0x08;
    const REG_RX_LEN: u32 = 0x0C;
    const REG_MAC_LOW: u32 = 0x18;
    const REG_MAC_HIGH: u32 = 0x1C;
    const REG_TX_DATA_BASE: u32 = 0x100;
    const REG_RX_DATA_BASE: u32 = 0x800;

    fn create_test_ethernet_bus() -> EthernetBus {
        let clock = Rc::new(Clock::new());
        let pic = Rc::new(Pic::new());
        let irq = pic.register_irq(1);
        let dummy_tap: Box<dyn TapDevice> = Box::new(DummyTapDevice::new());
        let eth = Ethernet::new(Some(Arc::new(Mutex::new(dummy_tap))), irq, &clock);
        EthernetBus {
            periph: Box::new(eth),
        }
    }

    #[test]
    fn test_status_register() {
        let mut eth_bus = create_test_ethernet_bus();
        let status = eth_bus.read(RvSize::Word, REG_STATUS).unwrap();
        // TX should be ready, no RX available
        assert_eq!(status & 0x1, 0x1); // TX_READY
        assert_eq!(status & 0x2, 0); // RX_AVAIL
    }

    #[test]
    fn test_mac_address() {
        let mut eth_bus = create_test_ethernet_bus();

        // Write MAC address
        eth_bus
            .write(RvSize::Word, REG_MAC_LOW, 0x04030201)
            .unwrap();
        eth_bus.write(RvSize::Word, REG_MAC_HIGH, 0x0605).unwrap();

        // Read back
        let mac_low = eth_bus.read(RvSize::Word, REG_MAC_LOW).unwrap();
        let mac_high = eth_bus.read(RvSize::Word, REG_MAC_HIGH).unwrap();

        assert_eq!(mac_low, 0x04030201);
        assert_eq!(mac_high, 0x0605);
    }

    #[test]
    fn test_tx_buffer_write() {
        let mut eth_bus = create_test_ethernet_bus();

        // Write some data to TX buffer
        eth_bus
            .write(RvSize::Word, REG_TX_DATA_BASE, 0xDEADBEEF)
            .unwrap();
        eth_bus
            .write(RvSize::Word, REG_TX_DATA_BASE + 4, 0xCAFEBABE)
            .unwrap();

        // Set TX length and transmit
        eth_bus.write(RvSize::Word, REG_TX_LEN, 8).unwrap();
        eth_bus
            .write(RvSize::Word, REG_CTRL, CTRL_TX_START)
            .unwrap();

        // TX should complete immediately with dummy device
        let status = eth_bus.read(RvSize::Word, REG_STATUS).unwrap();
        assert_eq!(status & 0x1, 0x1); // TX_READY
    }

    #[test]
    fn test_rx_frame() {
        let clock = Rc::new(Clock::new());
        let pic = Rc::new(Pic::new());
        let irq = pic.register_irq(1);

        let mut dummy_tap = DummyTapDevice::new();
        // Inject a test frame
        dummy_tap.inject_frame(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);

        let tap: Box<dyn TapDevice> = Box::new(dummy_tap);
        let eth = Ethernet::new(Some(Arc::new(Mutex::new(tap))), irq, &clock);
        let mut eth_bus = EthernetBus {
            periph: Box::new(eth),
        };

        // Poll to receive the frame
        eth_bus.poll();

        // Check status
        let status = eth_bus.read(RvSize::Word, REG_STATUS).unwrap();
        assert_eq!(status & 0x2, 0x2); // RX_AVAIL

        // Check RX length
        let rx_len = eth_bus.read(RvSize::Word, REG_RX_LEN).unwrap();
        assert_eq!(rx_len, 6);

        // Read RX data
        let data = eth_bus.read(RvSize::Word, REG_RX_DATA_BASE).unwrap();
        assert_eq!(data, 0x04030201);

        // Pop the frame
        eth_bus.write(RvSize::Word, REG_CTRL, CTRL_RX_POP).unwrap();

        // Check status - no more frames
        let status = eth_bus.read(RvSize::Word, REG_STATUS).unwrap();
        assert_eq!(status & 0x2, 0); // RX_AVAIL
    }
}

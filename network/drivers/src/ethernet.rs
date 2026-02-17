/*++

Licensed under the Apache-2.0 license.

File Name:

    ethernet.rs

Abstract:

    Ethernet driver for the Network Coprocessor.

--*/

use network_hil::ethernet::{
    Ethernet, EthernetError, MacAddress, Result, ETH_MAX_FRAME_SIZE, ETH_MIN_FRAME_SIZE,
};
use registers_generated::ethernet::{
    bits::{EthCtrl, EthStatus},
    regs::Ethernet as EthernetRegs,
    ETHERNET_ADDR,
};
use romtime::StaticRef;
use tock_registers::interfaces::{Readable, Writeable};

// Ethernet driver for the Network Coprocessor
pub struct EthernetDriver {
    regs: StaticRef<EthernetRegs>,
}

// Default StaticRef to the Ethernet peripheral registers
pub const ETHERNET_REGS: StaticRef<EthernetRegs> =
    unsafe { StaticRef::new(ETHERNET_ADDR as *const EthernetRegs) };

impl EthernetDriver {
    // Create a new Ethernet driver using the default peripheral address
    pub fn new() -> Self {
        Self::from(ETHERNET_REGS)
    }

    // Create a new Ethernet driver from a StaticRef to the registers
    pub fn from(regs: StaticRef<EthernetRegs>) -> Self {
        Self { regs }
    }
}

impl Default for EthernetDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl EthernetDriver {
    #[allow(dead_code)]
    fn read_tx_data(&self, index: usize) -> u32 {
        self.regs.eth_tx_data[index].get()
    }

    fn write_tx_data(&mut self, index: usize, value: u32) {
        self.regs.eth_tx_data[index].set(value);
    }

    fn read_rx_data(&self, index: usize) -> u32 {
        self.regs.eth_rx_data[index].get()
    }
}

impl Ethernet for EthernetDriver {
    fn mac_address(&self) -> MacAddress {
        let mac_low = self.regs.eth_mac_low.get();
        let mac_high = self.regs.eth_mac_high.get();
        let low_bytes = mac_low.to_le_bytes();
        let high_bytes = mac_high.to_le_bytes();
        [
            low_bytes[0],
            low_bytes[1],
            low_bytes[2],
            low_bytes[3],
            high_bytes[0],
            high_bytes[1],
        ]
    }

    fn set_mac_address(&mut self, mac: MacAddress) {
        let mac_low = u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]);
        let mac_high = u32::from_le_bytes([mac[4], mac[5], 0, 0]);
        self.regs.eth_mac_low.set(mac_low);
        self.regs.eth_mac_high.set(mac_high);
    }

    fn tx_ready(&self) -> bool {
        self.regs.eth_status.is_set(EthStatus::TxReady)
    }

    fn rx_available(&self) -> bool {
        self.regs.eth_status.is_set(EthStatus::RxAvail)
    }

    fn rx_queue_count(&self) -> u8 {
        self.regs.eth_status.read(EthStatus::RxQueueCount) as u8
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<()> {
        // Check frame size constraints
        if frame.len() > ETH_MAX_FRAME_SIZE {
            return Err(EthernetError::FrameTooLarge);
        }
        if frame.len() < ETH_MIN_FRAME_SIZE {
            return Err(EthernetError::FrameTooSmall);
        }

        // Check if TX is ready
        if !self.tx_ready() {
            return Err(EthernetError::TxNotReady);
        }

        // Reset TX pointer
        self.regs.eth_tx_ptr.set(0);

        // Copy frame data to TX buffer (word at a time)
        let mut word_idx = 0;
        let mut byte_idx = 0;

        while byte_idx < frame.len() {
            let mut word_bytes = [0u8; 4];
            for (i, byte) in word_bytes.iter_mut().enumerate() {
                if byte_idx + i < frame.len() {
                    *byte = frame[byte_idx + i];
                }
            }
            self.write_tx_data(word_idx, u32::from_le_bytes(word_bytes));
            word_idx += 1;
            byte_idx += 4;
        }

        // Set frame length
        self.regs.eth_tx_len.set(frame.len() as u32);

        // Trigger transmission
        self.regs.eth_ctrl.write(EthCtrl::TxStart::SET);

        Ok(())
    }

    fn rx_frame_len(&self) -> Option<usize> {
        if self.rx_available() {
            Some(self.regs.eth_rx_len.get() as usize)
        } else {
            None
        }
    }

    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize> {
        // Check if a frame is available
        let frame_len = self.rx_frame_len().ok_or(EthernetError::NoFrameAvailable)?;

        // Check buffer size
        if buffer.len() < frame_len {
            return Err(EthernetError::BufferTooSmall);
        }

        // Reset RX pointer
        self.regs.eth_rx_ptr.set(0);

        // Copy frame data from RX buffer (word at a time)
        let mut byte_idx = 0;
        let mut word_idx = 0;

        while byte_idx < frame_len {
            let word = self.read_rx_data(word_idx);
            let word_bytes = word.to_le_bytes();
            for byte in word_bytes.iter() {
                if byte_idx < frame_len {
                    buffer[byte_idx] = *byte;
                    byte_idx += 1;
                }
            }
            word_idx += 1;
        }

        // Pop the frame from the queue
        self.pop_rx_frame();

        Ok(frame_len)
    }

    fn pop_rx_frame(&mut self) {
        self.regs.eth_ctrl.write(EthCtrl::RxPop::SET);
    }

    fn ack_interrupt(&mut self) {
        self.regs.eth_ctrl.write(EthCtrl::IrqAck::SET);
    }
}

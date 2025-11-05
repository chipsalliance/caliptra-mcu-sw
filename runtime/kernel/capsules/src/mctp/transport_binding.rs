// Licensed under the Apache-2.0 license

use crate::mctp::base_protocol::{MCTP_BASELINE_TRANSMISSION_UNIT, MCTP_HDR_SIZE};
use core::cell::Cell;
use core::fmt::Write;
use i3c_driver::hil::{I3CTarget, RxClient, TxClient};
use kernel::utilities::cells::OptionalCell;
use kernel::utilities::cells::TakeCell;
use kernel::ErrorCode;
use romtime::println;

// TODO: Set the correct value for MCTP_I3C_MAXBUF.
pub const MCTP_I3C_MAXBUF: usize = MCTP_HDR_SIZE + MCTP_BASELINE_TRANSMISSION_UNIT + 1; // 4 MCTP header + 64 baseline payload + 1 (PEC)

pub const MCTP_I3C_MAXMTU: usize = MCTP_I3C_MAXBUF - 1; // 68 bytes
pub const MCTP_I3C_MINMTU: usize = MCTP_HDR_SIZE + MCTP_BASELINE_TRANSMISSION_UNIT;

/// This trait contains the interface definition
/// for sending the MCTP packet through MCTP transport binding layer.
pub trait MCTPTransportBinding<'a> {
    /// Set the client that will be called when the packet is transmitted.
    fn set_tx_client(&self, client: &'a dyn TransportTxClient);

    /// Set the client that will be called when the packet is received.
    fn set_rx_client(&self, client: &'a dyn TransportRxClient);

    /// Set the buffer that will be used for receiving packets.
    fn set_rx_buffer(&self, rx_buf: &'static mut [u8]);

    fn transmit(
        &self,
        tx_buffer: &'static mut [u8],
        len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])>;

    /// Enable/Disable the I3C target device
    fn enable(&self);
    fn disable(&self);

    /// Get the maximum transmission unit (MTU) size.
    fn get_mtu_size(&self) -> usize;

    /// Get hdr size of transport binding layer
    fn get_hdr_size(&self) -> usize;
}

pub trait TransportTxClient {
    /// Called when the packet has been transmitted.
    fn send_done(&self, tx_buffer: &'static mut [u8], result: Result<(), ErrorCode>);
}

pub trait TransportRxClient {
    /// Called when a complete MCTP packet is received and ready to be processed by the client.
    fn receive(&self, rx_buffer: &'static mut [u8], len: usize);

    /// Called when the I3C Controller has requested a private Write by addressing the target
    /// and the driver needs buffer to receive the data.
    fn write_expected(&self);
}

pub struct MCTPI3CBinding<'a> {
    /// Reference to the I3C Target device driver.
    i3c_target: &'a dyn I3CTarget<'a>,
    rx_client: OptionalCell<&'a dyn TransportRxClient>,
    tx_client: OptionalCell<&'a dyn TransportTxClient>,
    /// I3C Target device address needed for PEC calculation.
    device_address: Cell<u8>,
    /// Max Read length supported by the I3C target device.
    max_read_len: Cell<usize>,
    /// Max Write length supported by the I3C target device.
    max_write_len: Cell<usize>,
    /// Buffer to store the transmitted packet.
    tx_buffer: TakeCell<'static, [u8]>,
}

impl<'a> MCTPI3CBinding<'a> {
    pub fn new(i3c_target: &'a dyn I3CTarget<'a>) -> MCTPI3CBinding<'a> {
        MCTPI3CBinding {
            i3c_target,
            rx_client: OptionalCell::empty(),
            tx_client: OptionalCell::empty(),
            device_address: Cell::new(0),
            max_read_len: Cell::new(0),
            max_write_len: Cell::new(0),
            tx_buffer: TakeCell::empty(),
        }
    }

    pub fn setup_mctp_i3c(&self) {
        let device_info = self.i3c_target.get_device_info();
        self.max_read_len.set(device_info.max_read_len);
        self.max_write_len.set(device_info.max_write_len);
        self.device_address.set(
            device_info
                .dynamic_addr
                .unwrap_or(device_info.static_addr.unwrap_or(0)),
        );
    }

    /// SMBus CRC8 calculation.
    fn compute_pec(addr: u8, buf: &[u8], len: usize) -> u8 {
        let mut crc = 0u8;

        crc = romtime::crc8(crc, addr);

        for byte in buf.iter().take(len) {
            crc = romtime::crc8(crc, *byte);
        }
        crc
    }
}

impl<'a> MCTPTransportBinding<'a> for MCTPI3CBinding<'a> {
    fn set_tx_client(&self, tx_client: &'a dyn TransportTxClient) {
        self.tx_client.set(tx_client);
    }

    fn set_rx_client(&self, rx_client: &'a dyn TransportRxClient) {
        self.rx_client.set(rx_client);
    }

    fn set_rx_buffer(&self, rx_buf: &'static mut [u8]) {
        self.i3c_target.set_rx_buffer(rx_buf);
    }

    fn transmit(
        &self,
        tx_buffer: &'static mut [u8],
        len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        self.tx_buffer.replace(tx_buffer);

        // Make sure there's enough space for the PEC byte
        if len == 0 || len > self.max_write_len.get() - 1 {
            println!(
                "MCTPI3CBinding: Invalid length. Expected: {}",
                self.max_write_len.get() - 1
            );
            Err((ErrorCode::SIZE, self.tx_buffer.take().unwrap()))?;
        }

        // Tx is a read operation from the I3C controller. Set the R/W bit at LSB to 1.
        let addr = (self.device_address.get() << 1) | 0x01;
        match self.tx_buffer.take() {
            Some(tx_buffer) => {
                if tx_buffer.len() > len + 1 {
                    let pec = MCTPI3CBinding::compute_pec(addr, tx_buffer, len);
                    tx_buffer[len] = pec;

                    match self.i3c_target.transmit_read(tx_buffer, len + 1) {
                        Ok(_) => {}
                        Err((e, tx_buffer)) => {
                            Err((e, tx_buffer))?;
                        }
                    }
                } else {
                    println!("MCTPI3CBinding: Invalid length. Expected: {}", len + 1);
                    Err((ErrorCode::SIZE, tx_buffer))?;
                }
            }
            None => {
                Err((ErrorCode::FAIL, self.tx_buffer.take().unwrap()))?;
            }
        }
        Ok(())
    }

    fn enable(&self) {
        self.i3c_target.enable();
    }

    fn disable(&self) {
        self.i3c_target.disable();
    }

    fn get_mtu_size(&self) -> usize {
        MCTP_I3C_MAXMTU
    }

    fn get_hdr_size(&self) -> usize {
        0
    }
}

impl TxClient for MCTPI3CBinding<'_> {
    fn send_done(&self, tx_buffer: &'static mut [u8], result: Result<(), ErrorCode>) {
        self.tx_client.map(|client| {
            client.send_done(tx_buffer, result);
        });
    }
}

impl RxClient for MCTPI3CBinding<'_> {
    fn receive_write(&self, rx_buffer: &'static mut [u8], len: usize) {
        // check if len is > 0 and <= max_write_len
        // if yes, compute PEC and check if it matches with the last byte of the buffer
        // if yes, call the client's receive_write function
        // if no, drop the packet and set_rx_buffer on i3c_target to receive the next packet
        if len == 0 || len > self.max_write_len.get() {
            self.i3c_target.set_rx_buffer(rx_buffer);
            return;
        }
        // Rx is a write operation from the I3C controller. Set the R/W bit at LSB to 0.
        let addr = self.device_address.get() << 1;
        let pec = MCTPI3CBinding::compute_pec(addr, rx_buffer, len - 1);
        if pec == rx_buffer[len - 1] {
            self.rx_client.map(|client| {
                client.receive(rx_buffer, len - 1);
            });
        } else {
            println!(
                "MCTPI3CBinding: Invalid PEC {:02x} (expected {:02x}) for address {:02x}. Dropping packet.",
                rx_buffer[len - 1],
                pec,
                addr >> 1,
            );
            self.i3c_target.set_rx_buffer(rx_buffer);
        }
    }

    fn write_expected(&self) {
        self.rx_client.map(|client| {
            client.write_expected();
        });
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn calculate_crc8(data: &[u8]) -> u8 {
        let polynomial = 0x07;
        let mut crc = 0u8;

        for &byte in data {
            crc ^= byte;
            for _ in 0..8 {
                if crc & 0x80 != 0 {
                    crc = (crc << 1) ^ polynomial;
                } else {
                    crc <<= 1;
                }
            }
        }
        crc
    }

    #[test]
    fn test_crc8() {
        assert_eq!(0xf4, calculate_crc8(b"123456789"));
    }

    #[test]
    fn test_pec_for_req() {
        // Write to device address 0x10
        let dev_addr = 0x10 << 1;
        // header version 0x01, src EID 0x00, dest EID 0x08, som = 1, eom = 1, pkt_seq = 0, tag_owner = 1, msg_tag = 1
        let mctp_hdr = [0x01, 0x00, 0x08, 0xC9];
        // (IC, control message type) = 0x00, Request packet (0x80), set EID command = 0x01
        let msg_hdr = [0x00, 0x80, 0x1];
        // msg payload: op = 0x00, EID = 0x0A
        let msg = [0x00, 0x0A];

        let pkt_buf_len = 1 + mctp_hdr.len() + msg_hdr.len() + msg.len();

        let pkt: &mut [u8] = &mut [0; MCTP_I3C_MAXBUF];
        pkt[0] = dev_addr;
        pkt[1..1 + mctp_hdr.len()].copy_from_slice(&mctp_hdr);
        pkt[1 + mctp_hdr.len()..1 + mctp_hdr.len() + msg_hdr.len()].copy_from_slice(&msg_hdr);
        pkt[1 + mctp_hdr.len() + msg_hdr.len()..pkt_buf_len].copy_from_slice(&msg);

        let computed_pec =
            MCTPI3CBinding::compute_pec(dev_addr, &pkt[1..pkt_buf_len], pkt_buf_len - 1);
        let exp_pec = calculate_crc8(&pkt[..pkt_buf_len]);
        assert_eq!(exp_pec, computed_pec);
    }

    #[test]
    fn test_pec_for_resp() {
        let dev_addr = (0x10 << 1) | 0x01;
        // header version 0x01, src EID 0x00, dest EID 0x08, som = 1, eom = 1, pkt_seq = 0, tag_owner = 0, msg_tag = 1
        let mctp_hdr = [0x01, 0x00, 0x08, 0xC1];
        // (IC, control message type) = 0x00, Response packet (0x00), set EID command = 0x01
        let msg_hdr = [0x00, 0x00, 0x01];
        // msg payload: completion code = 0x00, byte 2 : (0x00), EID = 0x0A, byte 4: (0x00)
        let msg = [0x00, 0x00, 0x0A, 0x00];

        let pkt_buf_len = 1 + mctp_hdr.len() + msg_hdr.len() + msg.len();
        let pkt: &mut [u8] = &mut [0; MCTP_I3C_MAXBUF];
        pkt[0] = dev_addr;
        pkt[1..1 + mctp_hdr.len()].copy_from_slice(&mctp_hdr);
        pkt[1 + mctp_hdr.len()..1 + mctp_hdr.len() + msg_hdr.len()].copy_from_slice(&msg_hdr);
        pkt[1 + mctp_hdr.len() + msg_hdr.len()..pkt_buf_len].copy_from_slice(&msg);

        let computed_pec =
            MCTPI3CBinding::compute_pec(dev_addr, &pkt[1..pkt_buf_len], pkt_buf_len - 1);
        let exp_pec = calculate_crc8(&pkt[..pkt_buf_len]);
        assert_eq!(exp_pec, computed_pec);
    }
}

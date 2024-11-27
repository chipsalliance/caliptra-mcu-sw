// Licensed under the Apache-2.0 license

use i3c_driver::hil::{I3CTarget, RxClient, TxClient};

use core::cell::Cell;

use kernel::debug;
use kernel::utilities::cells::OptionalCell;
use kernel::utilities::cells::TakeCell;
use kernel::ErrorCode;

pub const MCTP_I3C_MAXBUF: usize = 69; // 4 MCTP header + 64 baseline payload + 1 (PEC)

pub const MCTP_I3C_MAXMTU: usize = MCTP_I3C_MAXBUF - 1; // 64 bytes
pub const MCTP_I3C_MINMTU: usize = 4 + 64; // 4 MCPT header + 64 baseline payload

/// This trait contains the interface definition
/// for sending the MCTP packet through MCTP transport binding layer.
pub trait MCTPTransportBinding<'a> {
    /// Set the client that will be called when the packet is transmitted.
    fn set_tx_client(&self, client: &'a dyn TxClient);

    /// Set the client that will be called when the packet is received.
    fn set_rx_client(&self, client: &'a dyn RxClient);

    /// Set the buffer that will be used for receiving packets.
    fn set_rx_buffer(&self, rx_buf: &'static mut [u8]);

    fn transmit(&self, tx_buffer: &'static mut [u8]) -> Result<(), (ErrorCode, &'static mut [u8])>;

    /// Enable/Disable the I3C target device
    fn enable(&self);
    fn disable(&self);

    /// Get the maximum transmission unit (MTU) size.
    fn get_mtu_size(&self) -> usize;

    /// Get hdr size of transport binding layer
    fn get_hdr_size(&self) -> usize;
}

pub struct MCTPI3CBinding<'a> {
    /// Reference to the I3C Target device driver.
    i3c_target: &'a dyn I3CTarget<'a>,
    rx_client: OptionalCell<&'a dyn RxClient>,
    tx_client: OptionalCell<&'a dyn TxClient>,
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

    pub fn mctp_i3c_setup(&self) {
        let device_info = self.i3c_target.get_device_info();
        self.max_read_len.set(device_info.max_read_len);
        self.max_write_len.set(device_info.max_write_len);
        self.device_address.set(
            device_info
                .dynamic_addr
                .unwrap_or(device_info.static_addr.unwrap_or(0)),
        );
        self.i3c_target.enable();
    }

    /// SMBus CRC8 calculation.
    fn compute_pec(addr: u8, buf: &[u8], len: usize) -> u8 {
        let mut crc = 0u8;

        crc = MCTPI3CBinding::crc8(crc, addr);

        for byte in buf.iter().take(len) {
            crc = MCTPI3CBinding::crc8(crc, *byte);
        }
        crc
    }

    fn crc8(crc: u8, data: u8) -> u8 {
        let mut crc = crc;
        crc ^= data;
        for _ in 0..8 {
            if crc & 0x80 != 0 {
                crc = (crc << 1) ^ 0x07;
            } else {
                crc <<= 1;
            }
        }
        crc
    }
}

impl<'a> MCTPTransportBinding<'a> for MCTPI3CBinding<'a> {
    fn set_tx_client(&self, tx_client: &'a dyn TxClient) {
        self.tx_client.set(tx_client);
    }

    fn set_rx_client(&self, rx_client: &'a dyn RxClient) {
        self.rx_client.set(rx_client);
    }

    fn set_rx_buffer(&self, rx_buf: &'static mut [u8]) {
        self.i3c_target.set_rx_buffer(rx_buf);
    }

    fn transmit(&self, tx_buffer: &'static mut [u8]) -> Result<(), (ErrorCode, &'static mut [u8])> {
        let len = tx_buffer.len();

        self.tx_buffer.replace(tx_buffer);

        // Make sure there's enough space for the PEC byte
        if len == 0 || len > self.max_write_len.get() - 1 as usize {
            Err((ErrorCode::SIZE, self.tx_buffer.take().unwrap()))?;
        }

        let addr = self.device_address.get() << 1;
        match self.tx_buffer.take() {
            Some(tx_buffer) => {
                let pec = MCTPI3CBinding::compute_pec(addr, tx_buffer, len);
                tx_buffer[len] = pec;
                match self.i3c_target.transmit_read(tx_buffer, len + 1) {
                    Ok(_) => {}
                    Err((e, tx_buffer)) => {
                        Err((e, tx_buffer))?;
                    }
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

impl<'a> TxClient for MCTPI3CBinding<'a> {
    fn send_done(&self, tx_buffer: &'static mut [u8], result: Result<(), ErrorCode>) {
        self.tx_client.map(|client| {
            client.send_done(tx_buffer, result);
        });
    }
}

impl<'a> RxClient for MCTPI3CBinding<'a> {
    fn receive_write(&self, rx_buffer: &'static mut [u8], len: usize) {
        // check if len is > 0 and <= max_write_len
        // if yes, compute PEC and check if it matches with the last byte of the buffer
        // if yes, call the client's receive_write function
        // if no, drop the packet and set_rx_buffer on i3c_target to receive the next packet
        if len == 0 || len > self.max_write_len.get() as usize {
            debug!("MCTPI3CBinding: Invalid packet length. Dropping packet.");
            self.i3c_target.set_rx_buffer(rx_buffer);
            return;
        }
        let addr = self.device_address.get() << 1 | 0x01;
        let pec = MCTPI3CBinding::compute_pec(addr, rx_buffer, len - 1);
        if pec == rx_buffer[len - 1] {
            self.rx_client.map(|client| {
                client.receive_write(rx_buffer, len - 1);
            });
        } else {
            debug!("MCTPI3CBinding: Invalid PEC. Dropping packet.");
            self.i3c_target.set_rx_buffer(rx_buffer);
        }
    }

    fn write_expected(&self) {
        self.rx_client.map(|client| {
            client.write_expected();
        });
    }
}

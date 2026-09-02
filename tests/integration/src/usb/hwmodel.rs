// Licensed under the Apache-2.0 license

//! Adapter between USB/IP control URBs and the emulated USB peripheral.

use super::usbip::{UsbControlRequest, UsbIpDevice};
use caliptra_mcu_emulator_periph::{UsbHostController, UsbTransactionError};
use std::io;
use std::thread;
use std::time::{Duration, Instant};

const EP0: u8 = 0;
const EP0_MAX_PACKET_SIZE: usize = 64;
const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(10);

pub struct HwModelUsbDevice {
    host: UsbHostController,
}

impl HwModelUsbDevice {
    pub fn new(host: UsbHostController) -> Self {
        Self { host }
    }

    fn setup(&self, setup: &[u8; 8]) -> io::Result<()> {
        let deadline = Instant::now() + TRANSACTION_TIMEOUT;
        loop {
            match self.host.host_setup(EP0, setup) {
                Ok(()) => return Ok(()),
                Err(UsbTransactionError::NoBuffer | UsbTransactionError::FifoFull)
                    if Instant::now() < deadline =>
                {
                    thread::yield_now();
                }
                Err(error) => return Err(transaction_error("SETUP", error)),
            }
        }
    }

    fn input(&self) -> io::Result<Vec<u8>> {
        let deadline = Instant::now() + TRANSACTION_TIMEOUT;
        loop {
            match self.host.host_in(EP0) {
                Ok(data) => return Ok(data),
                Err(UsbTransactionError::Nak) if Instant::now() < deadline => {
                    thread::yield_now();
                }
                Err(error) => return Err(transaction_error("IN", error)),
            }
        }
    }

    fn output(&self, data: &[u8]) -> io::Result<()> {
        let deadline = Instant::now() + TRANSACTION_TIMEOUT;
        loop {
            match self.host.host_out(EP0, data) {
                Ok(()) => return Ok(()),
                Err(UsbTransactionError::Nak) if Instant::now() < deadline => {
                    thread::yield_now();
                }
                Err(error) => return Err(transaction_error("OUT", error)),
            }
        }
    }
}

impl UsbIpDevice for HwModelUsbDevice {
    fn control(&mut self, request: UsbControlRequest<'_>) -> io::Result<Vec<u8>> {
        let device_to_host = request.setup[0] & 0x80 != 0;
        let requested_length = u16::from_le_bytes([request.setup[6], request.setup[7]]) as usize;

        self.setup(&request.setup)?;

        if device_to_host {
            let mut response = Vec::with_capacity(requested_length);
            while response.len() < requested_length {
                let packet = self.input()?;
                let short_packet = packet.len() < EP0_MAX_PACKET_SIZE;
                response.extend_from_slice(&packet);
                if short_packet {
                    break;
                }
            }
            response.truncate(requested_length);
            self.output(&[])?;
            Ok(response)
        } else {
            for packet in request.data.chunks(EP0_MAX_PACKET_SIZE) {
                self.output(packet)?;
            }
            let status = self.input()?;
            if !status.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "control OUT status stage was not a zero-length packet",
                ));
            }
            Ok(Vec::new())
        }
    }
}

fn transaction_error(stage: &str, error: UsbTransactionError) -> io::Error {
    let kind = match error {
        UsbTransactionError::Stall => io::ErrorKind::Unsupported,
        UsbTransactionError::Nak
        | UsbTransactionError::NoBuffer
        | UsbTransactionError::FifoFull => io::ErrorKind::TimedOut,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("EP0 {stage} failed: {error:?}"))
}

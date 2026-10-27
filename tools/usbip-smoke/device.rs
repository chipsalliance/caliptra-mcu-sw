// Licensed under the Apache-2.0 license

#[allow(dead_code)]
#[path = "../../tests/integration/src/usb/usbip.rs"]
mod usbip;

use std::io;
use std::net::TcpListener;
use usbip::{UsbControlRequest, UsbIpDevice, UsbIpServer, UsbIpServerConfig};

const DEVICE: [u8; 18] = [18, 1, 0, 2, 0, 0, 0, 64, 0x5e, 0xca, 1, 0, 0, 1, 0, 0, 0, 1];
const CONFIG: [u8; 18] = [
    9, 2, 18, 0, 1, 1, 0, 0x80, 50, // Configuration
    9, 4, 0, 0, 0, 0xff, 0, 0, 0, // Vendor-specific interface, EP0 only
];

#[derive(Default)]
struct Device {
    configured: u8,
    payload: Vec<u8>,
}

impl UsbIpDevice for Device {
    fn control(&mut self, request: UsbControlRequest<'_>) -> io::Result<Vec<u8>> {
        let length = u16::from_le_bytes([request.setup[6], request.setup[7]]) as usize;
        let mut response = match (request.setup[0], request.setup[1]) {
            (0x80, 6) => match request.setup[3] {
                1 => DEVICE.to_vec(),
                2 => CONFIG.to_vec(),
                _ => return Err(io::ErrorKind::Unsupported.into()),
            },
            (0x00, 5) => Vec::new(),
            (0x00, 9) if request.setup[2] <= 1 => {
                self.configured = request.setup[2];
                Vec::new()
            }
            (0x80, 8) => vec![self.configured],
            (0x80, 0) | (0x81, 0) => vec![0, 0],
            (0x40, 0x5a) if request.data.len() == length && length <= 64 => {
                self.payload = request.data.to_vec();
                println!("Device received {} bytes: {:?}", length, self.payload);
                Vec::new()
            }
            (0xc0, 0x5b) => self.payload.clone(),
            _ => return Err(io::ErrorKind::Unsupported.into()),
        };
        response.truncate(length);
        Ok(response)
    }
}

fn main() -> io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 3240))?;
    println!("USB/IP device listening on 127.0.0.1:3240, bus ID 1-2, VID:PID ca5e:0001");
    UsbIpServer::new(
        listener,
        UsbIpServerConfig::new("1-2", 1, 2, 0xca5e, 1),
        Device::default(),
    )
    .serve_until_disconnect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_round_trip_and_short_read() {
        let mut device = Device::default();
        let payload = b"hello over USB/IP";
        assert!(device
            .control(UsbControlRequest {
                setup: [0x40, 0x5a, 0, 0, 0, 0, payload.len() as u8, 0],
                data: payload,
            })
            .unwrap()
            .is_empty());
        assert_eq!(
            device
                .control(UsbControlRequest {
                    setup: [0xc0, 0x5b, 0, 0, 0, 0, 64, 0],
                    data: &[],
                })
                .unwrap(),
            payload
        );
        assert_eq!(
            device
                .control(UsbControlRequest {
                    setup: [0xc0, 0x5b, 0, 0, 0, 0, 5, 0],
                    data: &[],
                })
                .unwrap(),
            b"hello"
        );
    }
}

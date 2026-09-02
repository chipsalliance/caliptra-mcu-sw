// Licensed under the Apache-2.0 license

//! Minimal USB/IP device-side transport for control-transfer testing.
//!
//! USB/IP integer fields are big-endian, while the eight-byte USB SETUP
//! packet carried inside a submit request retains USB's little-endian fields.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};

const USBIP_VERSION: u16 = 0x0111;
const OP_REQ_IMPORT: u16 = 0x8003;
const OP_REP_IMPORT: u16 = 0x0003;
const USBIP_CMD_SUBMIT: u32 = 0x0000_0001;
const USBIP_CMD_UNLINK: u32 = 0x0000_0002;
const USBIP_RET_SUBMIT: u32 = 0x0000_0003;
const USBIP_RET_UNLINK: u32 = 0x0000_0004;
const USBIP_DIR_OUT: u32 = 0;
const USBIP_DIR_IN: u32 = 1;

pub struct UsbControlRequest<'a> {
    pub setup: [u8; 8],
    pub data: &'a [u8],
}

pub trait UsbIpDevice: Send + 'static {
    fn control(&mut self, request: UsbControlRequest<'_>) -> io::Result<Vec<u8>>;
}

pub struct UsbIpServerConfig {
    busid: String,
    busnum: u32,
    devnum: u32,
    vendor_id: u16,
    product_id: u16,
}

impl UsbIpServerConfig {
    pub fn new(busid: &str, busnum: u32, devnum: u32, vendor_id: u16, product_id: u16) -> Self {
        Self {
            busid: busid.to_owned(),
            busnum,
            devnum,
            vendor_id,
            product_id,
        }
    }
}

pub struct UsbIpServer<D> {
    listener: TcpListener,
    config: UsbIpServerConfig,
    device: D,
}

impl<D: UsbIpDevice> UsbIpServer<D> {
    pub fn new(listener: TcpListener, config: UsbIpServerConfig, device: D) -> Self {
        Self {
            listener,
            config,
            device,
        }
    }

    pub fn serve_one_connection(mut self, urb_count: usize) -> io::Result<()> {
        let (mut stream, _) = self.listener.accept()?;
        stream.set_nodelay(true)?;
        self.handle_import(&mut stream)?;
        for _ in 0..urb_count {
            self.handle_command(&mut stream)?;
        }
        Ok(())
    }

    pub fn serve_until_disconnect(mut self) -> io::Result<()> {
        let (mut stream, _) = self.listener.accept()?;
        stream.set_nodelay(true)?;
        self.handle_import(&mut stream)?;
        loop {
            match self.handle_command(&mut stream) {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::BrokenPipe
                    ) =>
                {
                    return Ok(())
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn handle_import(&self, stream: &mut TcpStream) -> io::Result<()> {
        let mut request = [0_u8; 40];
        stream.read_exact(&mut request)?;
        require(
            read_u16(&request, 0) == USBIP_VERSION,
            "unsupported USB/IP version",
        )?;
        require(
            read_u16(&request, 2) == OP_REQ_IMPORT,
            "expected import request",
        )?;
        require(read_u32(&request, 4) == 0, "nonzero import status")?;
        let requested_busid = c_string(&request[8..40]);
        require(requested_busid == self.config.busid, "unknown USB bus ID")?;

        let mut reply = Vec::with_capacity(320);
        push_u16(&mut reply, USBIP_VERSION);
        push_u16(&mut reply, OP_REP_IMPORT);
        push_u32(&mut reply, 0);
        self.append_device_description(&mut reply);
        debug_assert_eq!(reply.len(), 320);
        stream.write_all(&reply)
    }

    fn handle_command(&mut self, stream: &mut TcpStream) -> io::Result<()> {
        let mut command = [0_u8; 48];
        stream.read_exact(&mut command)?;
        match read_u32(&command, 0) {
            USBIP_CMD_SUBMIT => self.handle_submit(stream, &command),
            USBIP_CMD_UNLINK => self.handle_unlink(stream, &command),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown USB/IP command",
            )),
        }
    }

    fn handle_submit(&mut self, stream: &mut TcpStream, command: &[u8; 48]) -> io::Result<()> {
        let seqnum = read_u32(command, 4);
        let devid = read_u32(command, 8);
        let direction = read_u32(command, 12);
        let endpoint = read_u32(command, 16);
        let transfer_length = read_u32(command, 24) as usize;
        require(
            devid == (self.config.busnum << 16) | self.config.devnum,
            "wrong device ID",
        )?;
        require(endpoint == 0, "only endpoint zero is supported")?;
        require(
            direction == USBIP_DIR_OUT || direction == USBIP_DIR_IN,
            "invalid transfer direction",
        )?;

        let mut out_data = if direction == USBIP_DIR_OUT {
            vec![0; transfer_length]
        } else {
            Vec::new()
        };
        stream.read_exact(&mut out_data)?;
        let setup: [u8; 8] = command[40..48].try_into().unwrap();

        let result = self.device.control(UsbControlRequest {
            setup,
            data: &out_data,
        });
        let (status, mut response) = match result {
            Ok(data) => (0_i32, data),
            Err(error) if error.kind() == io::ErrorKind::Unsupported => (-32_i32, Vec::new()),
            Err(error) => return Err(error),
        };
        if direction == USBIP_DIR_OUT {
            response.clear();
        } else {
            response.truncate(transfer_length);
        }

        let mut reply = Vec::with_capacity(48 + response.len());
        for value in [USBIP_RET_SUBMIT, seqnum, devid, direction, endpoint] {
            push_u32(&mut reply, value);
        }
        reply.extend_from_slice(&status.to_be_bytes());
        push_u32(&mut reply, response.len() as u32);
        push_u32(&mut reply, 0); // start frame
        push_u32(&mut reply, 0); // packet count
        push_u32(&mut reply, 0); // error count
        reply.extend_from_slice(&setup);
        reply.extend_from_slice(&response);
        stream.write_all(&reply)
    }

    fn handle_unlink(&self, stream: &mut TcpStream, command: &[u8; 48]) -> io::Result<()> {
        let mut reply = Vec::with_capacity(48);
        push_u32(&mut reply, USBIP_RET_UNLINK);
        reply.extend_from_slice(&command[4..20]);
        reply.extend_from_slice(&(-104_i32).to_be_bytes()); // ECONNRESET
        reply.resize(48, 0);
        stream.write_all(&reply)
    }

    fn append_device_description(&self, output: &mut Vec<u8>) {
        push_fixed_string(output, "/sys/devices/platform/caliptra-usb/usb1/1-2", 256);
        push_fixed_string(output, &self.config.busid, 32);
        push_u32(output, self.config.busnum);
        push_u32(output, self.config.devnum);
        push_u32(output, 2); // USB_SPEED_FULL
        push_u16(output, self.config.vendor_id);
        push_u16(output, self.config.product_id);
        push_u16(output, 0x0100);
        output.extend_from_slice(&[
            0, // device class
            0, // device subclass
            0, // device protocol
            1, // active configuration
            1, // number of configurations
            1, // number of interfaces
        ]);
    }
}

fn require(condition: bool, message: &'static str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, message))
    }
}

fn c_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_fixed_string(output: &mut Vec<u8>, value: &str, length: usize) {
    let mut field = vec![0; length];
    let bytes = value.as_bytes();
    field[..bytes.len().min(length)].copy_from_slice(&bytes[..bytes.len().min(length)]);
    output.extend_from_slice(&field);
}

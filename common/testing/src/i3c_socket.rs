/*++

Licensed under the Apache-2.0 license.

File Name:

    i3c_socket.rs

Abstract:

    I3C over TCP socket implementation.

    The protocol is byte-based and is relatively simple.

    The server is running and will forward all responses from targets in the emulator to the client.
    Data written to the server is interpreted as a command.

     and sends commands, and the client is one (or more)
    more targets who can only respond or send IBIs.

    The server will read (and the client will write) packets of the form:
    to_addr: u8
    command_descriptor: [u8; 8]
    data: [u8; N] // length is in the descriptor

    The server will write (and the client will read) packets of the form:
    ibi: u8,
    from_addr: u8
    response_descriptor: [u8; 4]
    data: [u8; N] // length is in the descriptor

    If the ibi field is non-zero, then it should be interpreted as the MDB for the IBI.

--*/

use crate::i3c::{DynamicI3cAddress, ReguDataTransferCommand};
use crate::i3c_socket_server::{IncomingHeader, OutgoingHeader, CRC8_SMBUS};
use crate::{wait_for_runtime_start, MCU_RUNNING};
use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::exit;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::vec;
use zerocopy::{transmute, FromBytes};

pub trait MctpTransportTest {
    fn run_test(&mut self, stream: &mut BufferedStream, target_addr: u8);
    fn is_passed(&self) -> bool;
}

pub fn run_tests(
    port: u16,
    target_addr: DynamicI3cAddress,
    tests: Vec<Box<dyn MctpTransportTest + Send>>,
    test_timeout_seconds: Option<Duration>,
) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let stream = TcpStream::connect(addr).unwrap();
    // cancel the test after 120 seconds
    std::thread::spawn(move || {
        let timeout = test_timeout_seconds.unwrap_or(Duration::from_secs(120));
        std::thread::sleep(timeout);
        println!(
            "INTEGRATION TEST ON MCTP-I3C TIMED OUT AFTER {:?} SECONDS",
            timeout
        );
        exit(-1);
    });
    std::thread::spawn(move || {
        wait_for_runtime_start();
        if !MCU_RUNNING.load(Ordering::Relaxed) {
            exit(-1);
        }
        let mut test_runner =
            MctpTestRunner::new(BufferedStream::new(stream), target_addr.into(), tests);
        test_runner.run_tests();
    });
}

#[derive(Debug, Clone)]
pub enum MctpTestState {
    Start,
    SendReq,
    ReceiveResp,
    ReceiveReq,
    SendResp,
    Finish,
}

struct MctpTestRunner {
    stream: BufferedStream,
    target_addr: u8,
    passed: usize,
    tests: Vec<Box<dyn MctpTransportTest + Send>>,
}

impl MctpTestRunner {
    pub fn new(
        stream: BufferedStream,
        target_addr: u8,
        tests: Vec<Box<dyn MctpTransportTest + Send>>,
    ) -> Self {
        Self {
            stream,
            target_addr,
            passed: 0,
            tests,
        }
    }

    pub fn run_tests(&mut self) {
        for test in self.tests.iter_mut() {
            test.run_test(&mut self.stream, self.target_addr);
            if test.is_passed() {
                self.passed += 1;
            }
        }
        println!(
            "Test Result: {}/{} tests passed",
            self.passed,
            self.tests.len()
        );
        MCU_RUNNING.store(false, Ordering::Relaxed);
        if self.passed == self.tests.len() {
            exit(0);
        } else {
            exit(-1);
        }
    }
}

struct Packet {
    header: OutgoingHeader,
    data: Vec<u8>,
}

pub struct BufferedStream {
    stream: TcpStream,
    read_buffer: VecDeque<Packet>,
}

impl BufferedStream {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            read_buffer: VecDeque::new(),
        }
    }

    pub fn try_clone(&self) -> std::io::Result<Self> {
        self.stream.try_clone().map(|stream| Self {
            stream,
            read_buffer: VecDeque::new(),
        })
    }

    fn read_packet(&mut self, target_addr: u8) -> Option<Packet> {
        let mut out_header_bytes: [u8; 6] = [0u8; 6];
        match self.stream.read_exact(&mut out_header_bytes) {
            Ok(()) => {
                let header: OutgoingHeader = transmute!(out_header_bytes);
                let desc = header.response_descriptor;
                let data_len = desc.data_length() as usize;
                let mut data = vec![0u8; data_len];
                self.stream.set_nonblocking(false).unwrap();
                self.stream
                    .read_exact(&mut data)
                    .expect("Failed to read message from socket");
                self.stream.set_nonblocking(true).unwrap();
                if header.from_addr == target_addr {
                    Some(Packet { header, data })
                } else {
                    None
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => None,
            Err(e) => panic!("Error reading message from socket: {}", e),
        }
    }

    pub fn send_private_write(&mut self, target_addr: u8, data: Vec<u8>) -> bool {
        let addr: u8 = target_addr;

        let pec = calculate_crc8(addr << 1, data.as_slice());

        let mut pkt = Vec::new();
        pkt.extend_from_slice(data.as_slice());
        pkt.push(pec);

        let pvt_write_cmd = prepare_private_write_cmd(addr, pkt.len() as u16);
        self.stream.set_nonblocking(false).unwrap();
        self.stream.write_all(&pvt_write_cmd).unwrap();
        self.stream.set_nonblocking(true).unwrap();
        self.stream.write_all(&pkt).unwrap();
        true
    }

    pub fn receive_ibi(&mut self, target_addr: u8) -> bool {
        loop {
            match self.read_packet(target_addr) {
                Some(packet) => {
                    if packet.header.ibi != 0 {
                        let pvt_read_cmd = prepare_private_read_cmd(target_addr);
                        self.stream.set_nonblocking(false).unwrap();
                        self.stream.write_all(&pvt_read_cmd).unwrap();
                        self.stream.set_nonblocking(true).unwrap();
                        return true;
                    } else {
                        self.read_buffer.push_back(packet);
                    }
                }
                _ => {
                    return false;
                }
            }
        }
    }

    pub fn receive_private_read(&mut self, target_addr: u8) -> Option<Vec<u8>> {
        let mut packet = None;
        while !self.read_buffer.is_empty() {
            let read = self.read_buffer.pop_front().unwrap();
            if read.header.from_addr == target_addr {
                packet = Some(read);
                break;
            }
        }

        match packet.or_else(|| self.read_packet(target_addr)) {
            Some(Packet { data, .. }) => {
                if data.is_empty() {
                    println!("Received empty data packet");
                    return None;
                }
                let pec = calculate_crc8((target_addr << 1) | 1, &data[..data.len() - 1]);
                if pec != data[data.len() - 1] {
                    println!(
                        "Received data with invalid CRC8: calclulated {:X} != received {:X}",
                        pec,
                        data[data.len() - 1]
                    );
                    return None;
                }
                Some(data[..data.len() - 1].to_vec())
            }
            _ => None,
        }
    }

    pub fn set_nonblocking(&self, blocking: bool) -> std::io::Result<()> {
        self.stream.set_nonblocking(blocking)
    }
}

fn prepare_private_write_cmd(to_addr: u8, data_len: u16) -> [u8; 9] {
    let mut write_cmd = ReguDataTransferCommand::read_from_bytes(&[0; 8]).unwrap();
    write_cmd.set_rnw(0);
    write_cmd.set_data_length(data_len);

    let cmd_words: [u32; 2] = transmute!(write_cmd);
    let cmd_hdr = IncomingHeader {
        to_addr,
        command: cmd_words,
    };
    transmute!(cmd_hdr)
}

fn prepare_private_read_cmd(to_addr: u8) -> [u8; 9] {
    let mut read_cmd = ReguDataTransferCommand::read_from_bytes(&[0; 8]).unwrap();
    read_cmd.set_rnw(1);
    read_cmd.set_data_length(0);
    let cmd_words: [u32; 2] = transmute!(read_cmd);
    let cmd_hdr = IncomingHeader {
        to_addr,
        command: cmd_words,
    };
    transmute!(cmd_hdr)
}

fn calculate_crc8(addr: u8, data: &[u8]) -> u8 {
    let mut pec_data = Vec::new();
    pec_data.push(addr);
    pec_data.extend(data.iter());

    CRC8_SMBUS.checksum(pec_data.as_slice())
}

#[cfg(test)]
mod tests {
    use crate::{i3c::ResponseDescriptor, i3c_socket::*};
    use zerocopy::transmute;

    #[test]
    fn test_into_bytes() {
        let idata = IncomingHeader {
            to_addr: 10,
            command: [0x01020304, 0x05060708],
        };
        let serialized: [u8; 9] = transmute!(idata);
        assert_eq!("0a0403020108070605", hex::encode(serialized));
        let odata = OutgoingHeader {
            ibi: 0,
            from_addr: 10,
            response_descriptor: ResponseDescriptor(0x01020304),
        };
        let serialized: [u8; 6] = transmute!(odata);
        assert_eq!("000a04030201", hex::encode(serialized));
    }

    #[test]
    fn test_prepare_private_write_cmd() {
        // to_addr = 0x10, cmd_desc = [0x00000000, 0x00200000]
        let cmd = prepare_private_write_cmd(0x10, 0x20);
        assert_eq!("100000000000002000", hex::encode(cmd));
    }

    #[test]
    fn test_prepare_private_read_cmd() {
        // to_addr = 0x10, cmd_desc = [0x20000000, 0x00000000]
        let cmd = prepare_private_read_cmd(0x10);
        assert_eq!("100000002000000000", hex::encode(cmd));
    }
}

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
use crate::{is_emulator_running, stop_emulator, wait_emulator_ticks, wait_for_runtime_start};
use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::exit;
use std::vec;
use zerocopy::{transmute, FromBytes};

pub trait MctpTransportTest {
    fn run_test(&mut self, stream: &mut BufferedStream, target_addr: u8);
    fn is_passed(&self) -> bool;
}

/// Default timeout in emulator ticks
pub const DEFAULT_TEST_TIMEOUT_TICKS: u64 = 120_000_000;

pub fn run_tests(
    port: u16,
    target_addr: DynamicI3cAddress,
    tests: Vec<Box<dyn MctpTransportTest + Send>>,
    test_timeout_ticks: Option<u64>,
) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let stream = TcpStream::connect(addr).unwrap();
    // cancel the test after timeout ticks
    let timeout_ticks = test_timeout_ticks.unwrap_or(DEFAULT_TEST_TIMEOUT_TICKS);
    crate::spawn_with_emulator_state(move || {
        if !wait_emulator_ticks(timeout_ticks) {
            // Emulator stopped before timeout - this is normal completion
            return;
        }
        println!(
            "INTEGRATION TEST ON MCTP-I3C TIMED OUT AFTER {} TICKS",
            timeout_ticks
        );
        exit(-1);
    });
    crate::spawn_with_emulator_state(move || {
        wait_for_runtime_start();
        if !is_emulator_running() {
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
        stop_emulator();
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
        // Pin the socket to nonblocking mode for its lifetime. set_nonblocking()
        // modifies the open file description, which is shared across every dup'd FD —
        // toggling it from one clone parks any concurrent read on a sibling clone in the
        // kernel until both the flag is restored AND data arrives. Keep the flag stable.
        stream.set_nonblocking(true).unwrap();
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

    fn read_all(stream: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
        let mut off = 0;
        while off < buf.len() {
            match stream.read(&mut buf[off..]) {
                Ok(0) => return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "peer closed")),
                Ok(n) => off += n,
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn write_all_nb(stream: &mut TcpStream, buf: &[u8]) -> std::io::Result<()> {
        let mut off = 0;
        while off < buf.len() {
            match stream.write(&buf[off..]) {
                Ok(0) => return Err(std::io::Error::new(ErrorKind::WriteZero, "no progress")),
                Ok(n) => off += n,
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn read_packet(&mut self) -> Option<Packet> {
        let mut out_header_bytes: [u8; 6] = [0u8; 6];
        match self.stream.read(&mut out_header_bytes[..1]) {
            Ok(0) => panic!("peer closed mid-header"),
            Ok(n) => {
                if n < out_header_bytes.len() {
                    Self::read_all(&mut self.stream, &mut out_header_bytes[n..])
                        .expect("Failed to read header from socket");
                }
                let header: OutgoingHeader = transmute!(out_header_bytes);
                let desc = header.response_descriptor;
                let data_len = desc.data_length() as usize;
                let mut data = vec![0u8; data_len];
                if data_len > 0 {
                    Self::read_all(&mut self.stream, &mut data)
                        .expect("Failed to read message from socket");
                }
                Some(Packet { header, data })
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => None,
            Err(e) => panic!("Error reading message from socket: {}", e),
        }
    }

    fn fill_buffer(&mut self) {
        while let Some(packet) = self.read_packet() {
            self.read_buffer.push_back(packet);
        }
    }

    pub fn send_private_write(&mut self, target_addr: u8, data: Vec<u8>) -> bool {
        let addr: u8 = target_addr;

        let pec = calculate_crc8(addr << 1, data.as_slice());

        let mut pkt = Vec::new();
        pkt.extend_from_slice(data.as_slice());
        pkt.push(pec);

        let pvt_write_cmd = prepare_private_write_cmd(addr, pkt.len() as u16);
        Self::write_all_nb(&mut self.stream, &pvt_write_cmd).unwrap();
        Self::write_all_nb(&mut self.stream, &pkt).unwrap();
        true
    }

    /// Send a command with payload using the packetized protocol.
    ///
    /// Each packet has a 4-byte header `[cmd, payload_len, seq_num, total_seqs]`
    /// followed by up to 252 bytes of payload, fitting within the 256-byte
    /// I3C TTI FIFO. Large payloads are split across multiple private writes.
    /// A delay is inserted between packets to allow the target to drain its
    /// FIFO before the next packet arrives.
    pub fn send_packetized_write(&mut self, target_addr: u8, cmd: u8, payload: &[u8]) {
        // Each packet must fit in the 256-byte TTI RX FIFO including the
        // 4-byte header and 1-byte PEC appended by send_private_write.
        // The chunk size must also be 4-byte aligned so the ROM's u32-word
        // reassembly buffer doesn't lose partial-word boundaries between
        // packets.  256 - 4 - 1 = 251, rounded down to 248.
        const MAX_CHUNK: usize = 248;
        let total_seqs = if payload.is_empty() {
            1u8
        } else {
            payload.len().div_ceil(MAX_CHUNK) as u8
        };

        let mut offset = 0usize;
        for seq in 0..total_seqs {
            let end = (offset + MAX_CHUNK).min(payload.len());
            let chunk = &payload[offset..end];
            let chunk_len = chunk.len() as u8;

            let mut pkt = Vec::with_capacity(4 + chunk.len());
            pkt.push(cmd);
            pkt.push(chunk_len);
            pkt.push(seq);
            pkt.push(total_seqs);
            pkt.extend_from_slice(chunk);

            self.send_private_write(target_addr, pkt);

            offset = end;

            // Give the target time to drain its 256-byte RX data FIFO
            // before the next packet. The FPGA controller adds ~5ms of its
            // own delay, so total inter-packet gap is ~30ms.
            if seq + 1 < total_seqs {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        }
    }

    /// Issue a private read request to the target. The response can then be
    /// retrieved with [`receive_private_read`].
    pub fn request_private_read(&mut self, target_addr: u8) {
        let pvt_read_cmd = prepare_private_read_cmd(target_addr);
        self.stream.set_nonblocking(false).unwrap();
        self.stream.write_all(&pvt_read_cmd).unwrap();
        self.stream.set_nonblocking(true).unwrap();
    }

    pub fn receive_ibi(&mut self, target_addr: u8) -> bool {
        self.fill_buffer();
        let mut i = 0;
        while i < self.read_buffer.len() {
            if self.read_buffer[i].header.from_addr == target_addr
                && self.read_buffer[i].header.ibi != 0
            {
                self.read_buffer.remove(i);
                let pvt_read_cmd = prepare_private_read_cmd(target_addr);
                Self::write_all_nb(&mut self.stream, &pvt_read_cmd).unwrap();
                return true;
            }
            i += 1;
        }
        false
    }

    pub fn receive_private_read(&mut self, target_addr: u8) -> Option<Vec<u8>> {
        self.fill_buffer();
        let mut i = 0;
        while i < self.read_buffer.len() {
            if self.read_buffer[i].header.from_addr == target_addr
                && self.read_buffer[i].header.ibi == 0
            {
                let packet = self.read_buffer.remove(i).unwrap();
                let data = packet.data;
                if data.is_empty() {
                    return None;
                }
                let pec = calculate_crc8((target_addr << 1) | 1, &data[..data.len() - 1]);
                if pec != data[data.len() - 1] {
                    return None;
                }
                return Some(data[..data.len() - 1].to_vec());
            }
            i += 1;
        }
        None
    }

    /// Send a private read request to the model without waiting for an IBI.
    /// Used when the target has TX data queued but did not send an IBI
    /// (e.g. ROM services response after a command).
    pub fn send_private_read_request(&mut self, target_addr: u8) {
        self.send_private_read_request_with_len(target_addr, 0);
    }

    /// Send a private read request with a specific data_length field.
    /// If len is 0, the model uses DEFAULT_PRIVATE_READ_LEN.
    pub fn send_private_read_request_with_len(&mut self, target_addr: u8, len: u16) {
        let pvt_read_cmd = prepare_private_read_cmd_with_len(target_addr, len);
        self.stream.set_nonblocking(false).unwrap();
        self.stream.write_all(&pvt_read_cmd).unwrap();
        self.stream.set_nonblocking(true).unwrap();
    }

    /// Drain any pending IBI packets from the buffer without triggering reads.
    pub fn drain_ibis(&mut self, target_addr: u8) {
        self.fill_buffer();
        self.read_buffer
            .retain(|pkt| !(pkt.header.from_addr == target_addr && pkt.header.ibi != 0));
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
    prepare_private_read_cmd_with_len(to_addr, 0)
}

fn prepare_private_read_cmd_with_len(to_addr: u8, len: u16) -> [u8; 9] {
    let mut read_cmd = ReguDataTransferCommand::read_from_bytes(&[0; 8]).unwrap();
    read_cmd.set_rnw(1);
    read_cmd.set_data_length(len);
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

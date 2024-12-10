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

use emulator_periph::{
    DynamicI3cAddress, I3cBusCommand, I3cBusResponse, I3cTcriCommand, I3cTcriCommandXfer,
    ReguDataTransferCommand, ResponseDescriptor,
};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{mpsc, Arc};
use std::time::Duration;
use std::vec;
use zerocopy::{transmute, FromBytes, IntoBytes};

const CRC8_SMBUS: crc::Crc<u8> = crc::Crc::<u8>::new(&crc::CRC_8_SMBUS);

pub(crate) fn start_i3c_socket(
    running: Arc<AtomicBool>,
    port: u16,
) -> (Receiver<I3cBusCommand>, Sender<I3cBusResponse>) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .expect("Failed to bind TCP socket for port");

    let (bus_command_tx, bus_command_rx) = mpsc::channel::<I3cBusCommand>();
    let (bus_response_tx, bus_response_rx) = mpsc::channel::<I3cBusResponse>();
    let running_clone = running.clone();
    std::thread::spawn(move || {
        handle_i3c_socket_loop(running_clone, listener, bus_response_rx, bus_command_tx)
    });

    (bus_command_rx, bus_response_tx)
}

fn handle_i3c_socket_loop(
    running: Arc<AtomicBool>,
    listener: TcpListener,
    mut bus_response_rx: Receiver<I3cBusResponse>,
    mut bus_command_tx: Sender<I3cBusCommand>,
) {
    listener
        .set_nonblocking(true)
        .expect("Could not set non-blocking");
    while running.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, addr)) => {
                handle_i3c_socket_connection(
                    running.clone(),
                    stream,
                    addr,
                    &mut bus_response_rx,
                    &mut bus_command_tx,
                );
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => panic!("Error accepting connection: {}", e),
        }
    }
}

#[derive(FromBytes, IntoBytes)]
#[repr(C, packed)]
struct IncomingHeader {
    to_addr: u8,
    command: [u32; 2],
}

#[derive(FromBytes, IntoBytes)]
#[repr(C, packed)]
struct OutgoingHeader {
    ibi: u8,
    from_addr: u8,
    response_descriptor: ResponseDescriptor,
}

fn handle_i3c_socket_connection(
    running: Arc<AtomicBool>,
    mut stream: TcpStream,
    _addr: SocketAddr,
    bus_response_rx: &mut Receiver<I3cBusResponse>,
    bus_command_tx: &mut Sender<I3cBusCommand>,
) {
    let stream = &mut stream;
    stream.set_nonblocking(true).unwrap();

    while running.load(Ordering::Relaxed) {
        // try reading
        let mut incoming_header_bytes = [0u8; 9];
        match stream.read_exact(&mut incoming_header_bytes) {
            Ok(()) => {
                let incoming_header: IncomingHeader = transmute!(incoming_header_bytes);
                let cmd: I3cTcriCommand = incoming_header.command.try_into().unwrap();

                let mut data = vec![0u8; cmd.data_len()];
                stream.set_nonblocking(false).unwrap();
                stream
                    .read_exact(&mut data)
                    .expect("Failed to read message from socket");
                stream.set_nonblocking(true).unwrap();
                let bus_command = I3cBusCommand {
                    addr: incoming_header.to_addr.into(),
                    cmd: I3cTcriCommandXfer { cmd, data },
                };
                bus_command_tx.send(bus_command).unwrap();
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(ref e) if e.kind() == ErrorKind::ConnectionReset => {
                println!("handle_i3c_socket_connection: Connection reset by client");
                break;
            }
            Err(e) => panic!("Error reading message from socket: {}", e),
        }
        if let Ok(response) = bus_response_rx.recv_timeout(Duration::from_millis(10)) {
            let data_len = response.resp.data.len();
            if data_len > 255 {
                panic!("Cannot write more than 255 bytes to socket");
            }
            let outgoing_header = OutgoingHeader {
                ibi: response.ibi.unwrap_or_default(),
                from_addr: response.addr.into(),
                response_descriptor: response.resp.resp,
            };
            let header_bytes: [u8; 6] = transmute!(outgoing_header);
            stream.write_all(&header_bytes).unwrap();
            stream.write_all(&response.resp.data).unwrap();
        }
    }
}

pub(crate) fn run_tests(
    running: Arc<AtomicBool>,
    port: u16,
    target_addr: DynamicI3cAddress,
    tests: Vec<Test>,
) {
    let running_clone = running.clone();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let stream = TcpStream::connect(addr).unwrap();
    std::thread::spawn(move || {
        let mut test_runner = TestRunner::new(stream, target_addr.into(), running_clone, tests);
        test_runner.run_tests();
    });
}

#[derive(Debug, Clone)]
enum TestState {
    Start,
    SendPrivateWrite,
    WaitForIbi,
    ReceivePrivateRead,
    Finish,
}

#[derive(Debug, Clone)]
pub(crate) struct Test {
    name: String,
    state: TestState,
    pvt_write_data: Vec<u8>,
    pvt_read_data: Vec<u8>,
    passed: bool,
}

impl Test {
    pub(crate) fn new(name: &str, pvt_write_data: Vec<u8>, pvt_read_data: Vec<u8>) -> Self {
        Self {
            name: name.to_string(),
            state: TestState::Start,
            pvt_write_data,
            pvt_read_data,
            passed: false,
        }
    }

    fn is_passed(&self) -> bool {
        self.passed
    }

    fn check_response(&mut self, data: &[u8]) {
        if data.len() == self.pvt_read_data.len() && data == self.pvt_read_data {
            self.passed = true;
        }
    }

    fn run_test(&mut self, running: Arc<AtomicBool>, stream: &mut TcpStream, target_addr: u8) {
        stream.set_nonblocking(true).unwrap();
        while running.load(Ordering::Relaxed) {
            match self.state {
                TestState::Start => {
                    println!("Starting test: {}", self.name);
                    self.state = TestState::SendPrivateWrite;
                }
                TestState::SendPrivateWrite => self.send_private_write(stream, target_addr),
                TestState::WaitForIbi => self.receive_ibi(stream, target_addr),
                TestState::ReceivePrivateRead => self.receive_private_read(stream, target_addr),
                TestState::Finish => {
                    println!(
                        "Test {} : {}",
                        self.name,
                        if self.passed { "PASSED" } else { "FAILED" }
                    );
                    break;
                }
            }
        }
    }

    fn send_private_write(&mut self, stream: &mut TcpStream, target_addr: u8) {
        let addr: u8 = target_addr;
        let pvt_write_data = self.pvt_write_data.as_slice();

        let pec = calculate_crc8(addr << 1, pvt_write_data);

        let mut pkt = Vec::new();
        pkt.extend_from_slice(pvt_write_data);
        pkt.push(pec);

        let pvt_write_cmd = prepare_private_write_cmd(addr, pkt.len() as u16);
        stream.set_nonblocking(false).unwrap();
        stream.write_all(&pvt_write_cmd).unwrap();
        stream.set_nonblocking(true).unwrap();
        stream.write_all(&pkt).unwrap();
        self.state = TestState::WaitForIbi;
    }

    fn receive_ibi(&mut self, stream: &mut TcpStream, target_addr: u8) {
        let mut out_header_bytes: [u8; 6] = [0u8; 6];
        match stream.read_exact(&mut out_header_bytes) {
            Ok(()) => {
                let outdata: OutgoingHeader = transmute!(out_header_bytes);
                if outdata.ibi != 0 && outdata.from_addr == target_addr {
                    let pvt_read_cmd = prepare_private_read_cmd(target_addr);
                    stream.set_nonblocking(false).unwrap();
                    stream.write_all(&pvt_read_cmd).unwrap();
                    stream.set_nonblocking(true).unwrap();
                    self.state = TestState::ReceivePrivateRead;
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => panic!("Error reading message from socket: {}", e),
        }
    }

    fn receive_private_read(&mut self, stream: &mut TcpStream, target_addr: u8) {
        let mut out_header_bytes = [0u8; 6];
        match stream.read_exact(&mut out_header_bytes) {
            Ok(()) => {
                let outdata: OutgoingHeader = transmute!(out_header_bytes);
                if target_addr != outdata.from_addr {
                    return;
                }
                let resp_desc = outdata.response_descriptor;
                let data_len = resp_desc.data_length() as usize;
                let mut data = vec![0u8; data_len];

                stream.set_nonblocking(false).unwrap();
                stream
                    .read_exact(&mut data)
                    .expect("Failed to read message from socket");
                stream.set_nonblocking(true).unwrap();

                let pec = calculate_crc8((target_addr << 1) | 1, &data[..data.len() - 1]);
                if pec == data[data.len() - 1] {
                    self.check_response(&data[..data.len() - 1]);
                } else {
                    println!(
                        "Received data with invalid CRC8: calclulated {:X} != received {:X}",
                        pec,
                        data[data.len() - 1]
                    );
                }

                self.state = TestState::Finish;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => panic!("Error reading message from socket: {}", e),
        }
    }
}

struct TestRunner {
    stream: TcpStream,
    target_addr: u8,
    passed: usize,
    running: Arc<AtomicBool>,
    tests: Vec<Test>,
}

impl TestRunner {
    pub fn new(
        stream: TcpStream,
        target_addr: u8,
        running: Arc<AtomicBool>,
        tests: Vec<Test>,
    ) -> Self {
        Self {
            stream,
            target_addr,
            passed: 0,
            running,
            tests,
        }
    }

    pub fn run_tests(&mut self) {
        for test in self.tests.iter_mut() {
            test.run_test(self.running.clone(), &mut self.stream, self.target_addr);
            if test.is_passed() {
                self.passed += 1;
            }
        }
        println!(
            "Test Result: {} tests/{} total tests passed ",
            self.passed,
            self.tests.len()
        );
        self.running.store(false, Ordering::Relaxed);
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
    use crate::i3c_socket::*;
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
}

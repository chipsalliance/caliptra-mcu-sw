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
    stream.set_nonblocking(true).unwrap(); //non-blocking

    while running.load(Ordering::Relaxed) {
        // try reading
        let mut incoming_header_bytes = [0u8; 9];
        match stream.read_exact(&mut incoming_header_bytes) {
            Ok(()) => {
                let incoming_header: IncomingHeader = transmute!(incoming_header_bytes);
                let cmd: I3cTcriCommand = incoming_header.command.try_into().unwrap();

                let mut data = vec![0u8; cmd.data_len()];
                stream.set_nonblocking(false).unwrap(); //blocking
                stream
                    .read_exact(&mut data)
                    .expect("Failed to read message from socket");
                stream.set_nonblocking(true).unwrap(); //non-blocking
                let bus_command = I3cBusCommand {
                    addr: incoming_header.to_addr.into(),
                    cmd: I3cTcriCommandXfer { cmd, data },
                };
                bus_command_tx.send(bus_command).unwrap();
            }
            Err(ref e)
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::UnexpectedEof => {}
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

#[derive(Debug, Clone)]
enum TestI3cControllerState {
    Start,
    SendPrivateWrite,
    WaitForIbi,
    ReceivePrivateRead,
    Finish,
}
struct Test {
    name: String,
    state: TestI3cControllerState,
    pvt_write_data: Vec<u8>,
    pvt_read_data: Vec<u8>,
    passed: bool,
}

impl Test {
    pub fn new(name: &str, pvt_write_data: Vec<u8>, pvt_read_data: Vec<u8>) -> Self {
        Self {
            name: name.to_string(),
            state: TestI3cControllerState::Start,
            pvt_write_data,
            pvt_read_data,
            passed: false,
        }
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn set_passed(&mut self) {
        self.passed = true;
    }

    pub fn is_passed(&self) -> bool {
        self.passed
    }

    pub fn set_state(&mut self, state: TestI3cControllerState) {
        self.state = state;
    }

    pub fn get_state(&self) -> TestI3cControllerState {
        self.state.clone()
    }

    pub fn get_pvt_write_data(&self) -> &[u8] {
        &self.pvt_write_data
    }

    pub fn check_response(&mut self, data: &[u8]) {
        // println!(
        //     "Checking response: {:X?} expected {:X?}",
        //     data, self.pvt_read_data
        // );

        if data.len() == self.pvt_read_data.len() && data == self.pvt_read_data {
            // for i in 0..data.len() {
            //     if data[i] != self.pvt_read_data[i] {
            //         return;
            //     }
            // }
            self.set_passed();
        }
    }
}

fn send_private_write(stream: &mut TcpStream, target_addr: u8, test: &mut Test) {
    let addr: u8 = target_addr;
    let pvt_write_data = test.get_pvt_write_data();
    // TODO: Temporary workaround until target address assign issue is resolved
    let pec = calculate_crc8(0, &[0x00 << 1]);
    let pec = calculate_crc8(pec, pvt_write_data);

    let mut pkt = Vec::new();
    pkt.extend_from_slice(pvt_write_data);
    pkt.push(pec);

    let pvt_write_cmd = prepare_private_write_cmd(addr, pkt.len() as u16);
    stream.set_nonblocking(false).unwrap();
    stream.write_all(&pvt_write_cmd).unwrap();
    stream.set_nonblocking(true).unwrap();
    stream.write_all(&pkt).unwrap();
    test.set_state(TestI3cControllerState::WaitForIbi);
}

fn receive_ibi(stream: &mut TcpStream, target_addr: u8, test: &mut Test) {
    let mut out_header_bytes = [0u8; 6];
    match stream.read_exact(&mut out_header_bytes) {
        Ok(()) => {
            let outdata: OutgoingHeader = transmute!(out_header_bytes);
            if outdata.ibi != 0 && outdata.from_addr == target_addr {
                let pvt_read_cmd = prepare_private_read_cmd(target_addr);
                stream.set_nonblocking(false).unwrap();
                stream.write_all(&pvt_read_cmd).unwrap();
                stream.set_nonblocking(true).unwrap();
                test.set_state(TestI3cControllerState::ReceivePrivateRead);
            }
        }
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
        Err(e) => panic!("Error reading message from socket: {}", e),
    }
}

fn receive_private_read(stream: &mut TcpStream, target_addr: u8, test: &mut Test) {
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

            // TODO: Temporary workaround until target address assign issue is resolved
            let mut pec = calculate_crc8(0, &[1]);
            pec = calculate_crc8(pec, &data[..data.len() - 1]);
            if pec == data[data.len() - 1] {
                test.check_response(&data[..data.len() - 1]);
            } else {
                println!(
                    "Received data with invalid CRC8 {:X} != {:X}",
                    pec,
                    data[data.len() - 1]
                );
            }

            test.set_state(TestI3cControllerState::Finish);
        }
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
        Err(e) => panic!("Error reading message from socket: {}", e),
    }
}

fn run_test(stream: &mut TcpStream, target_addr: u8, running: Arc<AtomicBool>, test: &mut Test) {
    while running.load(Ordering::Relaxed) {
        match test.get_state() {
            TestI3cControllerState::Start => {
                println!("Starting test: {}", test.get_name());
                test.set_state(TestI3cControllerState::SendPrivateWrite);
            }
            TestI3cControllerState::SendPrivateWrite => {
                send_private_write(stream, target_addr, test)
            }
            TestI3cControllerState::WaitForIbi => receive_ibi(stream, target_addr, test),
            TestI3cControllerState::ReceivePrivateRead => {
                receive_private_read(stream, target_addr, test)
            }
            TestI3cControllerState::Finish => {
                println!(
                    "Test {} : {}",
                    test.get_name(),
                    if test.is_passed() { "PASSED" } else { "FAILED" }
                );
                break;
            }
        }
    }
}

pub fn run_tests(running: Arc<AtomicBool>, port: u16, target_addr: DynamicI3cAddress) {
    let running_clone = running.clone();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let stream = TcpStream::connect(addr).unwrap();
    std::thread::spawn(move || {
        run_mctp_ctrl_cmd_tests(stream, running_clone, target_addr);
    });
}

fn run_mctp_ctrl_cmd_tests(
    mut stream: TcpStream,
    running: Arc<AtomicBool>,
    target_addr: DynamicI3cAddress,
) {
    let req_data = vec![0x01, 0x00, 0x08, 0xC9, 0x00, 0x80, 0x1, 0x00, 0x0A];
    let resp_data = vec![
        0x01, 0x08, 0x00, 0xC1, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0A, 0x00,
    ];
    let test = Test::new("Set EID Test", req_data, resp_data);

    let mut passed = 0;

    let mut tests = [test];
    for test in tests.iter_mut() {
        run_test(&mut stream, target_addr.into(), running.clone(), test);
        if test.is_passed() {
            passed += 1;
        }
    }

    println!(
        "Test Result: {} tests/{} total tests passed ",
        passed,
        tests.len()
    );
}

fn prepare_private_write_cmd(to_addr: u8, data_len: u16) -> [u8; 9] {
    let mut write_cmd = ReguDataTransferCommand::read_from_bytes(&[0; 8]).unwrap();
    write_cmd.set_rnw(0);
    write_cmd.set_data_length(data_len);

    let cmd_words: [u32; 2] = transmute!(write_cmd);
    println!("prepare_private_write_cmd: {:x?}", cmd_words);
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

fn calculate_crc8(crc: u8, data: &[u8]) -> u8 {
    let polynomial = 0x07;
    let mut crc = crc;

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

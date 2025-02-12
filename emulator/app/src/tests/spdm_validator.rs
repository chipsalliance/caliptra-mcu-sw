// Licensed under the Apache-2.0 license

use crate::i3c_socket::{
    receive_ibi, receive_private_read, send_private_write, MctpTestState, TestTrait,
};
use crate::tests::mctp_util::base_protocol::{MCTPHdr, MCTP_HDR_SIZE};
use crate::tests::mctp_util::common::MctpUtil;
use std::collections::VecDeque;
use std::env;
use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::vec;
use zerocopy::{transmute, FromBytes, Immutable, IntoBytes};

const RECEIVER_BUFFER_SIZE: usize = 4160;
pub const SOCKET_SPDM_COMMAND_NORMAL: u32 = 0x0001;
pub const SOCKET_SPDM_COMMAND_STOP: u32 = 0xFFFE;
pub const SOCKET_SPDM_COMMAND_UNKOWN: u32 = 0xFFFF;
pub const SOCKET_SPDM_COMMAND_TEST: u32 = 0xDEAD;
pub const SOCKET_HEADER_LEN: usize = 12;

pub fn generate_tests() -> Vec<Box<dyn TestTrait + Send>> {
    vec![Box::new(Test::new("SpdmValidatorTests")) as Box<dyn TestTrait + Send>]
}

#[derive(Debug, Clone)]
pub enum SpdmServerState {
    Start,
    ReceiveRequest,
    SendResponse,
    SendRequest,
    ReceiveResponse,
    Finish,
}

struct Test {
    test_name: String,
    spdm_server_state: SpdmServerState,
    mctp_test_state: MctpTestState,
    cur_req_msg: Vec<u8>,
    // incoming_req_pkts: VecDeque<Vec<u8>>,
    cur_resp_msg: Vec<u8>,
    // outgoing_resp_pkts: VecDeque<Vec<u8>>,
    cur_msg_tag: u8,
    mctp_util: MctpUtil,
    passed: bool,
}

#[derive(Debug, Copy, Clone, Default, FromBytes, IntoBytes, Immutable)]

pub struct SpdmSocketHeader {
    pub command: u32,
    pub transport_type: u32,
    pub payload_size: u32,
}

impl Test {
    fn new(test_name: &str) -> Self {
        Test {
            test_name: test_name.to_string(),
            spdm_server_state: SpdmServerState::Start,
            mctp_test_state: MctpTestState::Start,
            cur_req_msg: Vec::new(),
            cur_resp_msg: Vec::new(),
            cur_msg_tag: 0,
            mctp_util: MctpUtil::new(),
            passed: false,
        }
    }

    fn receive_socket_message(
        &self,
        running: Arc<AtomicBool>,
        stream: &mut TcpStream,
    ) -> Option<(u32, u32, Vec<u8>)> {
        let mut buffer = [0u8; RECEIVER_BUFFER_SIZE];
        let mut buffer_size = 0;
        let mut expected_size = 0;

        let mut command: u32 = 0;
        let mut transport_type: u32 = 0;
        while running.load(Ordering::Relaxed) {
            let s = stream
                .read(&mut buffer[buffer_size..])
                .expect("socket read error!");
            buffer_size += s;
            if (expected_size == 0) && (buffer_size >= SOCKET_HEADER_LEN) {
                let socket_header_bytes: [u8; SOCKET_HEADER_LEN] =
                    buffer[..SOCKET_HEADER_LEN].try_into().unwrap();

                let socket_header: SpdmSocketHeader = transmute!(socket_header_bytes);
                command = socket_header.command.to_be();
                transport_type = socket_header.transport_type.to_be();

                expected_size = socket_header.payload_size.to_be() as usize + SOCKET_HEADER_LEN;
            }
            if (expected_size != 0) && (buffer_size >= expected_size) {
                break;
            }
        }

        if buffer_size < SOCKET_HEADER_LEN {
            return None;
        }

        println!(
            "read: {:02X?}{:02X?}",
            &buffer[..SOCKET_HEADER_LEN],
            &buffer[SOCKET_HEADER_LEN..buffer_size]
        );

        let buffer_vec = buffer[SOCKET_HEADER_LEN..buffer_size].to_vec();

        Some((transport_type, command, buffer_vec))
    }

    fn send_socket_message(
        &self,
        spdm_client_stream: &mut TcpStream,
        transport_type: u32,
        command: u32,
        payload: &[u8],
    ) {
        let mut buffer = [0u8; SOCKET_HEADER_LEN];
        let payload_len = payload.len() as u32;
        let header = SpdmSocketHeader {
            command: command.to_be(),
            transport_type: transport_type.to_be(),
            payload_size: payload_len.to_be(),
        };
        buffer[..SOCKET_HEADER_LEN].copy_from_slice(header.as_bytes());
        spdm_client_stream
            .write_all(&buffer[..SOCKET_HEADER_LEN])
            .unwrap();
        spdm_client_stream.write_all(payload).unwrap();
        spdm_client_stream.flush().unwrap();
        println!(
            "write: {:02X?}{:02X?}",
            &buffer[..SOCKET_HEADER_LEN],
            payload
        );
    }

    // fn send_hello(&self, stream: &mut TcpStream, transport_encap: u32, session_id: u32) {
    //     let mut hello_msg = vec![0u8; 12];
    //     let mut hello_msg_bytes = [0u8; 12];
    //     let hello_header = SpdmSocketHeader {
    //         command: 0,
    //         transport_type: transport_encap,
    //         payload_size: 0,
    //     };
    //     hello_msg_bytes.copy_from_slice(&transmute!(hello_header));
    //     stream.write_all(&hello_msg_bytes).unwrap();
    // }

    fn send_req_receive_resp(
        &mut self,
        running: Arc<AtomicBool>,
        i3c_stream: &mut TcpStream,
        target_addr: u8,
    ) {
        i3c_stream.set_nonblocking(true).unwrap();
        println!("Sending message to target {:X?}", self.cur_req_msg);
        self.mctp_test_state = MctpTestState::Start;

        while running.load(Ordering::Relaxed) {
            match self.mctp_test_state {
                MctpTestState::Start => {
                    self.mctp_test_state = MctpTestState::SendReq;
                }
                MctpTestState::SendReq => {
                    self.mctp_util.send_request(
                        self.cur_msg_tag,
                        self.cur_req_msg.as_slice(),
                        running.clone(),
                        i3c_stream,
                        target_addr,
                    );
                    self.mctp_test_state = MctpTestState::ReceiveResp;
                }

                MctpTestState::ReceiveResp => {
                    let resp_msg = self.mctp_util.receive_response(
                        running.clone(),
                        i3c_stream,
                        self.cur_msg_tag,
                    );
                    if !resp_msg.is_empty() {
                        self.cur_resp_msg = resp_msg;
                        self.mctp_test_state = MctpTestState::Finish;
                    }
                }

                MctpTestState::Finish => {
                    break;
                }
                _ => {}
            }
        }
    }

    fn send_hello(&self, stream: &mut TcpStream, tranport_type: u32) {
        println!("get hello");
        let server_hello = b"Server Hello!\0";
        let hello_bytes = server_hello.as_bytes();

        self.send_socket_message(stream, tranport_type, SOCKET_SPDM_COMMAND_TEST, hello_bytes);
    }

    fn send_stop(&self, stream: &mut TcpStream, tranport_type: u32) {
        println!("get stop");
        self.send_socket_message(stream, tranport_type, SOCKET_SPDM_COMMAND_STOP, &[]);
    }

    fn process_socket_message(
        &mut self,
        running: Arc<AtomicBool>,
        spdm_client_stream: &mut TcpStream,
        i3c_server_stream: &mut TcpStream,
        target_addr: u8,
        transport_type: u32,
        socket_command: u32,
        buffer: Vec<u8>,
    ) -> bool {
        if transport_type != 1 {
            println!("SPDM_SERVER: Invalid transport type. Only MCTP (1) is supported");
            return false;
        }
        match socket_command {
            SOCKET_SPDM_COMMAND_TEST => {
                println!("SPDM_SERVER: Received test command. Send Server Hello");
                self.send_hello(spdm_client_stream, transport_type);
                self.spdm_server_state = SpdmServerState::ReceiveRequest;
                true
            }
            SOCKET_SPDM_COMMAND_STOP => {
                println!("SPDM_SERVER: Received stop command. Stop the responder plugin");
                self.send_stop(spdm_client_stream, transport_type);
                self.passed = true;
                false
            }
            SOCKET_SPDM_COMMAND_NORMAL => {
                println!("SPDM_SERVER: Received normal SPDM command. Send it to the target");
                self.cur_req_msg = buffer;
                self.send_req_receive_resp(running, i3c_server_stream, target_addr);
                self.spdm_server_state = SpdmServerState::SendResponse;
                self.cur_msg_tag = (self.cur_msg_tag + 1) % 4 as u8;
                true
            }
            _ => {
                // send_unknown(stream, transport_encap.clone(), res.0).await;
                false
            }
        }
    }

    fn run_test_internal(
        &mut self,
        running: Arc<AtomicBool>,
        spdm_client_stream: &mut TcpStream,
        i3c_server_stream: &mut TcpStream,
        target_addr: u8,
    ) {
        while running.load(Ordering::Relaxed) {
            match self.spdm_server_state {
                SpdmServerState::Start => {
                    self.spdm_server_state = SpdmServerState::ReceiveRequest;
                }
                SpdmServerState::ReceiveRequest => {
                    let result = self.receive_socket_message(running.clone(), spdm_client_stream);
                    if let Some((transport_type, command, buffer)) = result {
                        println!("SPDM_SERVER: Received message from SPDM client transport type {} command {} Buffer {:x?}", transport_type, command, buffer);
                        let result = self.process_socket_message(
                            running.clone(),
                            spdm_client_stream,
                            i3c_server_stream,
                            target_addr,
                            transport_type,
                            command,
                            buffer,
                        );
                        if result == false {
                            self.spdm_server_state = SpdmServerState::Finish;
                        }
                    }
                }
                SpdmServerState::SendResponse => {
                    println!("SPDM_SERVER: Sending response to SPDM client");
                    self.send_socket_message(
                        spdm_client_stream,
                        1,
                        SOCKET_SPDM_COMMAND_NORMAL,
                        self.cur_resp_msg.as_slice(),
                    );
                    self.spdm_server_state = SpdmServerState::ReceiveRequest;
                }
                SpdmServerState::Finish => {
                    // self.passed = true;
                    break;
                }
                _ => {
                    println!("SPDM_SERVER: Invalid state");
                    break;
                }
            }
        }

        println!(
            "SPDM_SERVER: Test {} : {}",
            self.test_name,
            if self.passed { "PASSED" } else { "FAILED" }
        );
    }
}

impl TestTrait for Test {
    fn is_passed(&self) -> bool {
        self.passed
    }

    fn run_test(&mut self, running: Arc<AtomicBool>, stream: &mut TcpStream, target_addr: u8) {
        let listener =
            TcpListener::bind("127.0.0.1:2323").expect("Could not bind to the SPDM listerner port");
        println!("SPDM_SERVER: Emulator Listening on port 2323");

        if let Some(spdm_stream) = listener.incoming().next() {
            let mut client_stream = spdm_stream.expect("Failed to accept connection");

            println!("SPDM_SERVER: Emulator Accepted connection from SPDM client");
            self.run_test_internal(running, &mut client_stream, stream, target_addr);
        }
    }
}

pub fn start_spdm_device_validator(_running: Arc<AtomicBool>) -> io::Result<()> {
    let spdm_validator_dir = env::var("SPDM_VALIDATOR_DIR");
    let dir_path = match spdm_validator_dir {
        Ok(dir) => {
            println!("SPDM_VALIDATOR_DIR: {}", dir);
            Path::new(&dir).to_path_buf()
        }
        Err(_e) => {
            println!(
                "SPDM_VALIDATOR_DIR is not set. The spdm_device_validator_sample can't be found"
            );
            return Err(ErrorKind::NotFound.into());
        }
    };

    let utility_path = dir_path.join("spdm_device_validator_sample");
    if !utility_path.exists() {
        println!("spdm_device_validator_sample not found in the path");
        return Err(ErrorKind::NotFound.into());
    }

    let log_file_path = dir_path.join("spdm_device_validator_output.txt");

    let output_file = File::create(log_file_path)?;
    let output_file_clone = output_file.try_clone()?;

    println!("Starting spdm_device_validator_sample process");

    let child = Command::new(utility_path)
        .stdout(Stdio::from(output_file))
        .stderr(Stdio::from(output_file_clone))
        .spawn()
        .expect("failed to execute spdm validator");

    let output = child
        .wait_with_output()
        .expect("failed to wait on child process");
    println!(
        "spdm_device_validator_sample process Status {}",
        output.status
    );
    println!(
        "spdm_device_validator_sample process stdout {}",
        String::from_utf8_lossy(&output.stdout)
    );
    println!(
        "spdm_device_validator_sample process stderr {}",
        String::from_utf8_lossy(&output.stderr)
    );
    io::stdout().flush().unwrap();
    io::stderr().flush().unwrap();
    Ok(())
}

// Licensed under the Apache-2.0 license

use crate::tests::spdm_responder_validator::transport::Transport;
use mcu_testing_common::MCU_RUNNING;
use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use zerocopy::{transmute, FromBytes, Immutable, IntoBytes};

const RECEIVER_BUFFER_SIZE: usize = 4160;
pub const SOCKET_SPDM_COMMAND_NORMAL: u32 = 0x0001;
pub const SOCKET_SPDM_COMMAND_STOP: u32 = 0xFFFE;
pub const SOCKET_SPDM_COMMAND_TEST: u32 = 0xDEAD;
pub const SOCKET_HEADER_LEN: usize = 12;

pub(crate) static SERVER_LISTENING: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Copy, Clone, Default, FromBytes, IntoBytes, Immutable)]
pub struct SpdmSocketHeader {
    pub command: u32,
    pub transport_type: u32,
    pub payload_size: u32,
}

#[derive(Debug, Clone)]
pub enum SpdmServerState {
    Start,
    ReceiveRequest,
    SendResponse,
    Finish,
}

pub struct SpdmValidatorRunner {
    test_name: &'static str,
    transport: Box<dyn Transport>,
    passed: bool,
    responder_ready: bool,
    cur_req_msg: Vec<u8>,
    cur_rsp_msg: Vec<u8>,
    state: SpdmServerState,
}

impl SpdmValidatorRunner {
    pub fn new(transport: Box<dyn Transport>, test_name: &'static str) -> Self {
        Self {
            test_name,
            transport,
            passed: false,
            responder_ready: false,
            cur_req_msg: Vec::new(),
            cur_rsp_msg: Vec::new(),
            state: SpdmServerState::Start,
        }
    }

    pub fn run_test(&mut self, stream: &mut TcpStream) {
        while MCU_RUNNING.load(Ordering::Relaxed) {
            match self.state {
                SpdmServerState::Start => {
                    self.state = SpdmServerState::ReceiveRequest;
                }
                SpdmServerState::ReceiveRequest => {
                    let result = self.receive_socket_message(stream);
                    if let Some((transport_type, command, buffer)) = result {
                        let result =
                            self.process_socket_message(stream, transport_type, command, buffer);
                        if !result {
                            self.state = SpdmServerState::Finish;
                        }
                    }
                }
                SpdmServerState::SendResponse => {
                    println!("[{}]: Sending response to SPDM client", self.test_name);
                    self.send_socket_message(
                        stream,
                        self.transport.transport_type(),
                        SOCKET_SPDM_COMMAND_NORMAL,
                        self.cur_rsp_msg.as_slice(),
                    );
                    self.state = SpdmServerState::ReceiveRequest;
                }
                SpdmServerState::Finish => {
                    break;
                }
            }
        }

        println!(
            "[{}]: Test : {}",
            self.test_name,
            if self.passed { "PASSED" } else { "FAILED" }
        );
    }

    pub fn is_passed(&self) -> bool {
        self.passed
    }

    fn receive_socket_message(&self, spdm_stream: &mut TcpStream) -> Option<(u32, u32, Vec<u8>)> {
        let mut buffer = [0u8; RECEIVER_BUFFER_SIZE];
        let mut buffer_size = 0;
        let mut expected_size = 0;

        let mut command: u32 = 0;
        let mut transport_type: u32 = 0;
        while MCU_RUNNING.load(Ordering::Relaxed) {
            let s = spdm_stream
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
            "read from SPDM client: {:02X?}{:02X?}",
            &buffer[..SOCKET_HEADER_LEN],
            &buffer[SOCKET_HEADER_LEN..buffer_size]
        );

        let buffer_vec = buffer[SOCKET_HEADER_LEN..buffer_size].to_vec();

        Some((transport_type, command, buffer_vec))
    }

    fn send_socket_message(
        &self,
        spdm_stream: &mut TcpStream,
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
        spdm_stream.write_all(&buffer[..SOCKET_HEADER_LEN]).unwrap();
        spdm_stream.write_all(payload).unwrap();
        spdm_stream.flush().unwrap();
        println!(
            "write to SPDM client: {:02X?}{:02X?}",
            &buffer[..SOCKET_HEADER_LEN],
            payload
        );
    }

    fn send_hello(&self, stream: &mut TcpStream, transport_type: u32) {
        println!("[{}]: Got Client Hello. Send Server Hello", self.test_name);
        let server_hello = b"Server Hello!\0";
        let hello_bytes = server_hello.as_bytes();

        self.send_socket_message(
            stream,
            transport_type,
            SOCKET_SPDM_COMMAND_TEST,
            hello_bytes,
        );
    }

    fn send_stop(&self, stream: &mut TcpStream, transport_type: u32) {
        println!("[{}]: Got Stop", self.test_name);
        self.send_socket_message(stream, transport_type, SOCKET_SPDM_COMMAND_STOP, &[]);
    }

    fn process_socket_message(
        &mut self,
        spdm_stream: &mut TcpStream,
        transport_type: u32,
        socket_command: u32,
        buffer: Vec<u8>,
    ) -> bool {
        if transport_type != self.transport.transport_type() {
            println!(
                "[{}]: Invalid transport type {} expected {}",
                self.test_name,
                transport_type,
                self.transport.transport_type()
            );
            return false;
        }

        match socket_command {
            SOCKET_SPDM_COMMAND_TEST => {
                println!("[{}]: Received test command", self.test_name);
                self.send_hello(spdm_stream, transport_type);
                self.state = SpdmServerState::ReceiveRequest;
                true
            }
            SOCKET_SPDM_COMMAND_STOP => {
                println!(
                    "[{}]: Received stop command. Stop the responder plugin",
                    self.test_name
                );
                self.send_stop(spdm_stream, transport_type);
                self.passed = true;
                false
            }
            SOCKET_SPDM_COMMAND_NORMAL => {
                println!(
                    "[{}]: Received normal SPDM command. Send it to the target",
                    self.test_name
                );
                self.cur_req_msg = buffer;
                self.cur_rsp_msg = match self
                    .transport
                    .target_send_and_receive(&self.cur_req_msg, !self.responder_ready)
                {
                    Some(resp) => {
                        self.responder_ready = true;
                        resp
                    }
                    None => {
                        println!("[{}]: Error sending SPDM request", self.test_name);
                        return false;
                    }
                };

                self.state = SpdmServerState::SendResponse;
                true
            }
            _ => false,
        }
    }
}

pub fn execute_spdm_tee_io_validator(transport: &'static str) {
    std::thread::spawn(move || {
        println!("Starting spdm_tee_io_validator process. Waiting for SPDM listener to start...");
        while !SERVER_LISTENING.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        match start_spdm_tee_io_validator(transport, None, true) {
            Ok(mut child) => {
                while MCU_RUNNING.load(Ordering::Relaxed) {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            println!("spdm_tee_io_validator exited with status: {:?}", status);
                            break;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            println!("Error: {:?}", e);
                            break;
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                let _ = child.kill();
            }
            Err(e) => {
                println!("Error: {:?} Failed to spawn spdm_tee_io_validator!!", e);
            }
        }
    });
}

pub fn execute_spdm_responder_validator(transport: &'static str) {
    std::thread::spawn(move || {
        println!(
            "Starting spdm_device_validator_sample process. Waiting for SPDM listener to start..."
        );
        while !SERVER_LISTENING.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        match start_spdm_responder_validator(transport) {
            Ok(mut child) => {
                while MCU_RUNNING.load(Ordering::Relaxed) {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            println!(
                                "spdm_device_validator_sample exited with status: {:?}",
                                status
                            );
                            break;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            println!("Error: {:?}", e);
                            break;
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                let _ = child.kill();
            }
            Err(e) => {
                println!(
                    "Error: {:?} Failed to spawn spdm_device_validator_sample!!",
                    e
                );
            }
        }
    });
}

pub fn start_spdm_responder_validator(transport: &'static str) -> io::Result<Child> {
    spawn_validator_binary(
        "spdm_device_validator_sample",
        "spdm_device_validator_output.txt",
        |cmd| {
            println!(
                "Starting spdm_device_validator_sample process with transport: {}",
                transport
            );
            cmd.arg("--trans")
                .arg(transport)
                .arg("--pcap")
                .arg("caliptra_spdm_validator.pcap");
        },
    )
}

pub fn start_spdm_tee_io_validator(
    _transport: &'static str,
    features: Option<&[&str]>,
    no_default_features: bool,
) -> io::Result<Child> {
    // Default features if none provided
    let default_features = ["spdm-ring", "hashed-transcript-data", "async-executor"];
    let features_to_use = features.unwrap_or(&default_features);
    let features_str = features_to_use.join(",");
    spawn_validator_binary(
        "spdm-requester-emu",
        "tdisp_ide_validator_output.txt",
        |cmd| {
            if no_default_features {
                cmd.arg("--no-default-features");
            }
            cmd.arg("--features").arg(&features_str);
            println!(
                "Starting spdm-requester-emu process with{} default features, features: {}",
                if no_default_features { "out" } else { "" },
                features_str
            );
        },
    )
}

fn validator_dir() -> io::Result<PathBuf> {
    match std::env::var("SPDM_VALIDATOR_DIR") {
        Ok(dir) => {
            println!("SPDM_VALIDATOR_DIR: {}", dir);
            Ok(PathBuf::from(dir))
        }
        Err(_) => Err(ErrorKind::NotFound.into()),
    }
}

fn spawn_validator_binary<F>(binary: &str, log_file: &str, configure: F) -> io::Result<Child>
where
    F: FnOnce(&mut Command),
{
    let dir_path = match validator_dir() {
        Ok(p) => p,
        Err(e) => {
            println!(
                "SPDM_VALIDATOR_DIR is not set. The {} can't be found (env missing)",
                binary
            );
            return Err(e);
        }
    };

    let utility_path = dir_path.join(binary);
    if !utility_path.exists() {
        println!("{} not found in the path", binary);
        return Err(ErrorKind::NotFound.into());
    }

    let log_file_path = dir_path.join(log_file);
    let output_file = File::create(log_file_path)?;
    let output_file_clone = output_file.try_clone()?;

    let mut cmd = Command::new(utility_path);
    configure(&mut cmd);
    cmd.stdout(Stdio::from(output_file))
        .stderr(Stdio::from(output_file_clone))
        .current_dir(&dir_path)
        .spawn()
}

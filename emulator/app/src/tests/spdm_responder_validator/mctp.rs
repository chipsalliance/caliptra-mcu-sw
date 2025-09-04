// Licensed under the Apache-2.0 license

use crate::i3c_socket::BufferedStream;
use crate::tests::mctp_util::common::MctpUtil;
use crate::tests::spdm_responder_validator::common::{
    execute_spdm_validator, SpdmValidatorRunner, SERVER_LISTENING,
};
use crate::tests::spdm_responder_validator::transport::{
    Transport, MAX_CMD_TIMEOUT_SECONDS, SOCKET_TRANSPORT_TYPE_MCTP,
};
use crate::{wait_for_runtime_start, EMULATOR_RUNNING};
use emulator_periph::DynamicI3cAddress;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::exit;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

const TEST_NAME: &str = "MCTP-SPDM-RESPONDER-VALIDATOR";

#[derive(Debug, Clone)]
enum TxRxState {
    Start,
    SendReq,
    ReceiveResp,
    Finish,
}

pub struct MctpTransport {
    stream: BufferedStream,
    mctp_util: MctpUtil,
    target_addr: u8,
    msg_tag: u8,
    tx_rx_state: TxRxState,
    retry_count: usize,
}

impl MctpTransport {
    pub fn new(stream: BufferedStream, target_addr: u8, retry_count: usize) -> Self {
        Self {
            stream,
            mctp_util: MctpUtil::new(),
            target_addr,
            msg_tag: 0,
            tx_rx_state: TxRxState::Start,
            retry_count,
        }
    }

    fn send_req_receive_resp(&mut self, req: &[u8]) -> Option<Vec<u8>> {
        self.stream.set_nonblocking(true).unwrap();
        println!("[{}]: Sending message to target ", TEST_NAME);
        self.tx_rx_state = TxRxState::Start;
        let mut resp = None;
        let mut cur_retry_count = 0;

        while EMULATOR_RUNNING.load(Ordering::Relaxed) {
            match self.tx_rx_state {
                TxRxState::Start => {
                    // This is to give some time for send_done upcall to be invoked by the kernel to the app.
                    // Just a hack and may not be perfect solution.
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    self.tx_rx_state = TxRxState::SendReq;
                }
                TxRxState::SendReq => {
                    self.mctp_util.send_request(
                        self.msg_tag,
                        req,
                        &mut self.stream,
                        self.target_addr,
                    );
                    self.tx_rx_state = TxRxState::ReceiveResp;
                }

                TxRxState::ReceiveResp => {
                    println!("[{}]: receiving response from target", TEST_NAME);
                    let resp_msg = self.mctp_util.receive_response(
                        &mut self.stream,
                        self.target_addr,
                        Some(MAX_CMD_TIMEOUT_SECONDS), // timeout in seconds
                    );
                    if !resp_msg.is_empty() {
                        resp = Some(resp_msg);
                        println!("[{}]: response received, marking finished", TEST_NAME);
                        self.tx_rx_state = TxRxState::Finish;
                    } else if cur_retry_count == self.retry_count {
                        println!(
                            "[{}]: No response received after {} retries, marking finished",
                            TEST_NAME, self.retry_count
                        );
                        self.tx_rx_state = TxRxState::Finish;
                    } else {
                        cur_retry_count += 1;
                        println!(
                            "[{}]: No response received, retrying ({})",
                            TEST_NAME, cur_retry_count
                        );
                        self.tx_rx_state = TxRxState::SendReq;
                    }
                }

                TxRxState::Finish => {
                    break;
                }
            }
        }
        resp
    }

    fn wait_for_responder(&mut self, req: &[u8]) -> Option<Vec<u8>> {
        let resp = self.mctp_util.wait_for_responder(
            self.msg_tag,
            req,
            &mut self.stream,
            self.target_addr,
        );
        if let Some(ref resp_msg) = resp {
            println!(
                "[{}]: Received response from target {:X?}",
                TEST_NAME, resp_msg
            );
            assert_eq!(resp_msg[0], req[0]);
        } else {
            println!("[{}]: No response from target", TEST_NAME);
            return None;
        }
        resp
    }
}

impl Transport for MctpTransport {
    fn target_send_and_receive(&mut self, req: &[u8], wait_for_responder: bool) -> Option<Vec<u8>> {
        let resp = if wait_for_responder {
            self.wait_for_responder(req)
        } else {
            self.send_req_receive_resp(req)
        };
        if resp.is_some() {
            self.msg_tag = (self.msg_tag + 1) % 4;
        }
        resp
    }

    fn transport_type(&self) -> u32 {
        SOCKET_TRANSPORT_TYPE_MCTP
    }
}

pub fn run_mctp_spdm_conformance_test(
    port: u16,
    target_addr: DynamicI3cAddress,
    test_timeout_seconds: Duration,
) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let stream = TcpStream::connect(addr).unwrap();
    let transport = MctpTransport::new(BufferedStream::new(stream), target_addr.into(), 1);

    thread::spawn(move || {
        thread::sleep(test_timeout_seconds);
        println!(
            "[{}] TIMED OUT AFTER {:?} SECONDS",
            TEST_NAME,
            test_timeout_seconds.as_secs()
        );
        exit(-1);
    });

    thread::spawn(move || {
        wait_for_runtime_start();

        if !EMULATOR_RUNNING.load(Ordering::Relaxed) {
            exit(-1);
        }
        let listener =
            TcpListener::bind("127.0.0.1:2323").expect("Could not bind to the SPDM listerner port");
        println!("[{}]: Spdm Server Listening on port 2323", TEST_NAME);
        SERVER_LISTENING.store(true, Ordering::Relaxed);

        if let Some(spdm_stream) = listener.incoming().next() {
            let mut spdm_stream = spdm_stream.expect("Failed to accept connection");

            let mut test = SpdmValidatorRunner::new(Box::new(transport), TEST_NAME);
            test.run_test(&mut spdm_stream);
            if !test.is_passed() {
                println!("[{}]: Spdm Responder Conformance Test Failed", TEST_NAME);
                exit(-1);
            } else {
                println!("[{}]: Spdm Responder Conformance Test Passed", TEST_NAME);
                exit(0);
            }
        }
    });

    execute_spdm_validator("MCTP");
}

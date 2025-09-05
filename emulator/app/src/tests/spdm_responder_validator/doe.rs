// Licensed under the Apache-2.0 license

use crate::tests::doe_util::common::DoeUtil;
use crate::tests::spdm_responder_validator::common::{
    execute_spdm_validator, SpdmValidatorRunner, SERVER_LISTENING,
};
use crate::tests::spdm_responder_validator::transport::{Transport, SOCKET_TRANSPORT_TYPE_PCI_DOE};
use mcu_testing_common::{sleep_emulator_ticks, wait_for_runtime_start, MCU_RUNNING};
use std::net::TcpListener;
use std::process::exit;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::Duration;

const TEST_NAME: &str = "DOE-SPDM-RESPONDER-VALIDATOR";

enum TxRxState {
    Start,
    SendReq,
    ReceiveResp,
    Finish,
}

pub struct DoeTransport {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    tx_rx_state: TxRxState,
    retry_count: usize,
}

impl DoeTransport {
    pub fn new(tx: Sender<Vec<u8>>, rx: Receiver<Vec<u8>>, retry_count: usize) -> Self {
        Self {
            tx,
            rx,
            tx_rx_state: TxRxState::Start,
            retry_count,
        }
    }
}

impl Transport for DoeTransport {
    fn target_send_and_receive(&mut self, req: &[u8], wait_for_responder: bool) -> Option<Vec<u8>> {
        self.tx_rx_state = TxRxState::Start;
        let mut resp = None;
        let mut retry_count = 0;

        while MCU_RUNNING.load(Ordering::Relaxed) {
            match self.tx_rx_state {
                TxRxState::Start => {
                    if wait_for_responder {
                        sleep_emulator_ticks(5_000_000);
                    } else {
                        // This is to give some time for send_done upcall to be invoked by the kernel to the app.
                        // Just a hack and may not be perfect solution.
                        sleep_emulator_ticks(100_000);
                    }
                    self.tx_rx_state = TxRxState::SendReq;
                }
                TxRxState::SendReq => {
                    if DoeUtil::send_raw_data_object(req, &mut self.tx).is_ok() {
                        self.tx_rx_state = TxRxState::ReceiveResp;
                    } else {
                        println!("[{}]: Failed to send request", TEST_NAME);
                        self.tx_rx_state = TxRxState::Finish;
                    }
                }
                TxRxState::ReceiveResp => match DoeUtil::receive_raw_data_object(&self.rx) {
                    Ok(response) if !response.is_empty() => {
                        resp = Some(response.clone());
                        self.tx_rx_state = TxRxState::Finish;
                    }
                    Ok(_) => {
                        if retry_count < self.retry_count {
                            retry_count += 1;
                            println!(
                                "[{}]: No response received, retrying... ({})",
                                TEST_NAME, retry_count
                            );
                            self.tx_rx_state = TxRxState::SendReq;
                        } else {
                            println!(
                                "[{}]: No response received after {} retries, failing test",
                                TEST_NAME, self.retry_count
                            );
                            self.tx_rx_state = TxRxState::Finish;
                        }
                    }
                    Err(e) => {
                        println!("[{}]: Failed to receive response: {:?}", TEST_NAME, e);
                        self.tx_rx_state = TxRxState::Finish;
                    }
                },
                TxRxState::Finish => {
                    break;
                }
            }
        }
        resp
    }

    fn transport_type(&self) -> u32 {
        SOCKET_TRANSPORT_TYPE_PCI_DOE
    }
}

pub fn run_doe_spdm_conformance_test(
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    test_timeout_seconds: Duration,
) {
    let transport = DoeTransport::new(tx, rx, 1);
    // Spawn a thread to handle the timeout for the test
    thread::spawn(move || {
        thread::sleep(test_timeout_seconds);
        println!(
            "[{}] TIMED OUT AFTER {:?} SECONDS",
            TEST_NAME,
            test_timeout_seconds.as_secs()
        );
        exit(-1);
    });

    // Spawn a thread to run the tests
    thread::spawn(move || {
        wait_for_runtime_start();
        // give time for the app to be loaded and ready
        sleep_emulator_ticks(1_000_000);

        if !MCU_RUNNING.load(Ordering::Relaxed) {
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

    execute_spdm_validator("PCI_DOE");
}

// Licensed under the Apache-2.0 license

/// This module tests the PLDM request/response interaction between the emulator and the device.
/// The emulator sends out different PLDM requests and expects a corresponding response for those requests.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::mctp_transport::MctpPldmSocket;
use pldm_common::codec::PldmCodec;
use pldm_common::message::control::*;
use pldm_common::protocol::base::PldmMsgType;
use pldm_ua::transport::{PldmSocket, PldmTransportError};

pub struct PldmRequestResponseTest {
    test_messages: Vec<PldmExpectedMessagePair>,
    socket: MctpPldmSocket,
    running: Arc<AtomicBool>,
}

pub struct PldmExpectedMessagePair {
    // PLDM Message Sent
    pub request: Vec<u8>,
    // Expected PLDM Message Response to receive
    pub response: Vec<u8>,
}

impl PldmRequestResponseTest {
    fn new(socket: MctpPldmSocket, running: Arc<AtomicBool>) -> Self {
        let mut test_messages: Vec<PldmExpectedMessagePair> = Vec::new();

        // Add the PLDM requests to send, and the expected responses
        Self::add_test_message(
            &mut test_messages,
            GetTidRequest::new(1u8, PldmMsgType::Request),
            GetTidResponse::new(1u8, 1u8, 0u8),
        );

        Self::add_test_message(
            &mut test_messages,
            SetTidRequest::new(2u8, PldmMsgType::Request, 2u8),
            SetTidResponse::new(2u8, 0u8),
        );

        Self {
            test_messages,
            socket,
            running,
        }
    }

    fn add_test_message<Req: PldmCodec, Resp: PldmCodec>(
        test_messages: &mut Vec<PldmExpectedMessagePair>,
        request: Req,
        response: Resp,
    ) {
        let mut buffer = [0u8; 1024];
        let sz = request.encode(&mut buffer).unwrap();
        let request = buffer[0..sz].to_vec();
        let sz = response.encode(&mut buffer).unwrap();
        let response = buffer[0..sz].to_vec();
        test_messages.push(PldmExpectedMessagePair { request, response });
    }

    pub fn test_send_receive(&mut self) -> Result<(), PldmTransportError> {
        self.socket.connect()?;

        for message_pair in &self.test_messages {
            self.socket.send(&message_pair.request)?;
            let rx_pkt = self.socket.receive(None)?;
            assert_eq!(
                rx_pkt.payload.data[..rx_pkt.payload.len],
                message_pair.response
            );
        }
        Ok(())
    }

    pub fn run(socket: MctpPldmSocket, running: Arc<AtomicBool>) {
        std::thread::spawn(move || {
            print!("Emulator: Running PLDM Loopback Test: ",);
            let mut test = PldmRequestResponseTest::new(socket, running);
            if test.test_send_receive().is_err() {
                println!("Failed");
            } else {
                println!("Passed");
            }
            test.running.store(false, Ordering::Relaxed);
        });
    }
}

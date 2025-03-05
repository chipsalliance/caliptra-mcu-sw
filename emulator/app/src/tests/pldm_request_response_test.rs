// Licensed under the Apache-2.0 license

/// This module tests the PLDM request/response interaction between the emulator and the device.
/// The emulator sends out different PLDM requests and expects a corresponding response for those requests.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::mctp_transport::MctpPldmSocket;
use pldm_common::codec::PldmCodec;
use pldm_common::message::control::*;
use pldm_common::protocol::base::*;
use pldm_common::protocol::firmware_update::*;
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

        if cfg!(feature = "test-pldm-request-response") {
            println!("Emulator: Running PLDM Request Response Test");
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
        } else if cfg!(feature = "test-pldm-discovery") {
            println!("Emulator: Running PLDM discovery Test");
            Self::add_pldm_discovery_test_message(&mut test_messages);
        }

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

    fn add_pldm_discovery_test_message(test_messages: &mut Vec<PldmExpectedMessagePair>) {
        Self::add_test_message(
            test_messages,
            GetTidRequest::new(1u8, PldmMsgType::Request),
            GetTidResponse::new(1u8, 0u8, 0u8), //unassigned TID is 0
        );

        Self::add_test_message(
            test_messages,
            SetTidRequest::new(2u8, PldmMsgType::Request, 2u8),
            SetTidResponse::new(2u8, 0u8),
        );

        Self::add_test_message(
            test_messages,
            GetTidRequest::new(3u8, PldmMsgType::Request),
            GetTidResponse::new(3u8, 2u8, 0u8),
        );

        Self::add_test_message(
            test_messages,
            GetPldmTypeRequest::new(4u8, PldmMsgType::Request),
            // PLDM types supported by the device are 0x0 and 0x5
            GetPldmTypeResponse::new(
                4u8,
                0u8,
                &[
                    PldmSupportedType::Base as u8,
                    PldmSupportedType::FwUpdate as u8,
                ],
            ),
        );

        Self::add_test_message(
            test_messages,
            GetPldmVersionRequest::new(
                5u8,
                PldmMsgType::Request,
                0,
                TransferOperationFlag::GetFirstPart,
                PldmSupportedType::Base,
            ),
            GetPldmVersionResponse::new(5u8, 0u8, 0, TransferRespFlag::StartAndEnd, "1.1.0")
                .unwrap(),
        );

        Self::add_test_message(
            test_messages,
            GetPldmCommandsRequest::new(
                6u8,
                PldmMsgType::Request,
                PldmSupportedType::Base as u8,
                "1.1.0",
            ),
            GetPldmCommandsResponse::new(
                6u8,
                0u8,
                &[
                    PldmControlCmd::SetTid as u8,
                    PldmControlCmd::GetTid as u8,
                    PldmControlCmd::GetPldmCommands as u8,
                    PldmControlCmd::GetPldmVersion as u8,
                    PldmControlCmd::GetPldmTypes as u8,
                ],
            ),
        );

        Self::add_test_message(
            test_messages,
            GetPldmVersionRequest::new(
                7u8,
                PldmMsgType::Request,
                0,
                TransferOperationFlag::GetFirstPart,
                PldmSupportedType::FwUpdate,
            ),
            // PLDM version supported by the device is 0x1
            GetPldmVersionResponse::new(7u8, 0u8, 0, TransferRespFlag::StartAndEnd, "1.3.0")
                .unwrap(),
        );

        Self::add_test_message(
            test_messages,
            GetPldmCommandsRequest::new(
                8u8,
                PldmMsgType::Request,
                PldmSupportedType::FwUpdate as u8,
                "1.3.0",
            ),
            GetPldmCommandsResponse::new(
                8u8,
                0u8,
                &[
                    FwUpdateCmd::QueryDeviceIdentifiers as u8,
                    FwUpdateCmd::GetFirmwareParameters as u8,
                    FwUpdateCmd::RequestUpdate as u8,
                    FwUpdateCmd::PassComponentTable as u8,
                    FwUpdateCmd::UpdateComponent as u8,
                    FwUpdateCmd::RequestFirmwareData as u8,
                    FwUpdateCmd::TransferComplete as u8,
                    FwUpdateCmd::VerifyComplete as u8,
                    FwUpdateCmd::ApplyComplete as u8,
                    FwUpdateCmd::ActivateFirmware as u8,
                    FwUpdateCmd::GetStatus as u8,
                    FwUpdateCmd::CancelUpdate as u8,
                ],
            ),
        );
    }
}

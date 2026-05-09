//! Licensed under the Apache-2.0 license
//! This module tests the PLDM request/response interaction between the emulator and the device.
//! The emulator sends out different PLDM requests and expects a corresponding response for those requests.

use mcu_testing_common::mctp_transport::MctpPldmSocket;
use mcu_testing_common::{wait_for_runtime_start, MCU_RUNNING};
use pldm_common::codec::PldmCodec;
use pldm_common::message::control::*;
use pldm_common::message::firmware_update::get_fw_params::{
    FirmwareParameters, GetFirmwareParametersRequest, GetFirmwareParametersResponse,
};
use pldm_common::message::firmware_update::query_devid::{
    QueryDeviceIdentifiersRequest, QueryDeviceIdentifiersResponse,
};
use pldm_common::protocol::base::*;
use pldm_common::protocol::firmware_update::*;
use pldm_ua::transport::PldmSocket;
use std::process::exit;
use std::sync::atomic::Ordering;

pub struct PldmRequestResponseTest {
    test_messages: Vec<PldmExpectedMessagePair>,
    socket: MctpPldmSocket,
}

pub struct PldmExpectedMessagePair {
    // PLDM Message Sent
    pub request: Vec<u8>,
    // Expected PLDM Message Response to receive
    pub response: Vec<u8>,
}

impl PldmRequestResponseTest {
    fn new(socket: MctpPldmSocket) -> Self {
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
        } else if cfg!(feature = "test-pldm-fw-update") {
            println!("Emulator: Running PLDM Firmware Update Test");
            Self::add_pldm_fw_update_test_message(&mut test_messages);
        }

        Self {
            test_messages,
            socket,
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

    #[allow(clippy::result_unit_err)]
    pub fn test_send_receive(&mut self) -> Result<(), ()> {
        self.socket.connect().map_err(|_| ())?;

        for message_pair in &self.test_messages {
            self.socket.send(&message_pair.request).map_err(|_| ())?;
            let rx_pkt = self.socket.receive(None).map_err(|_| ())?;
            if rx_pkt.payload.data[..rx_pkt.payload.len] != message_pair.response {
                return Err(());
            }
        }
        Ok(())
    }

    pub fn run(socket: MctpPldmSocket) {
        std::thread::spawn(move || {
            wait_for_runtime_start();
            if !MCU_RUNNING.load(Ordering::Relaxed) {
                exit(-1);
            }
            print!("Emulator: Running PLDM Loopback Test: ",);
            let mut test = PldmRequestResponseTest::new(socket);
            if test.test_send_receive().is_err() {
                println!("Failed");
                exit(-1);
            } else {
                println!("Passed");
            }
            MCU_RUNNING.store(false, Ordering::Relaxed);
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
                    FwUpdateCmd::CancelUpdateComponent as u8,
                    FwUpdateCmd::CancelUpdate as u8,
                ],
            ),
        );
    }

    fn add_pldm_fw_update_test_message(test_messages: &mut Vec<PldmExpectedMessagePair>) {
        // Construct test message for QueryDeviceIdentifiers
        let query_device_identifiers_req =
            QueryDeviceIdentifiersRequest::new(1, PldmMsgType::Request);
        let test_uuid: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let query_device_identifiers_resp = QueryDeviceIdentifiersResponse::new(
            1,
            0,
            &Descriptor::new(DescriptorType::Uuid, &test_uuid).unwrap(),
            None,
        )
        .unwrap();

        Self::add_test_message(
            test_messages,
            query_device_identifiers_req,
            query_device_identifiers_resp,
        );

        // Construct test message for GetFirmwareParameters
        let active_firmware_string = PldmFirmwareString::new("UTF-8", "soc-fw-1.0").unwrap();
        let active_firmware_version =
            PldmFirmwareVersion::new(0x12345678, &active_firmware_string, Some("20250210"));
        let pending_firmware_string = PldmFirmwareString::new("UTF-8", "soc-fw-1.1").unwrap();
        let pending_firmware_version =
            PldmFirmwareVersion::new(0x87654321, &pending_firmware_string, Some("20250213"));
        let comp_activation_methods = ComponentActivationMethods(0x0001);
        let capabilities_during_update = FirmwareDeviceCapability(0x0010);
        let component_parameter_entry = ComponentParameterEntry::new(
            ComponentClassification::Firmware,
            0x0001,
            0,
            &active_firmware_version,
            &pending_firmware_version,
            comp_activation_methods,
            capabilities_during_update,
        );
        let test_fw_param = FirmwareParameters::new(
            capabilities_during_update,
            1,
            &active_firmware_string,
            &pending_firmware_string,
            &[component_parameter_entry],
        );
        let get_fw_params_req = GetFirmwareParametersRequest::new(1, PldmMsgType::Request);
        let get_fw_params_resp = GetFirmwareParametersResponse::new(1, 0, &test_fw_param);

        Self::add_test_message(test_messages, get_fw_params_req, get_fw_params_resp);
    }
}

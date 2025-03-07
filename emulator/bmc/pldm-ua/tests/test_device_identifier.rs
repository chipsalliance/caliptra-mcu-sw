// Licensed under the Apache-2.0 license

#[cfg(test)]
mod mock_transport;
use std::time::Duration;

use log::{error, LevelFilter};
use mock_transport::{MockPldmSocket, MockTransport};
use pldm_common::message::firmware_update::get_fw_params::FirmwareParameters;
use pldm_common::message::firmware_update::query_devid::{
    QueryDeviceIdentifiersRequest, QueryDeviceIdentifiersResponse,
};
use pldm_common::protocol::base::{PldmBaseCompletionCode, PldmMsgHeader};
use pldm_common::protocol::firmware_update::FwUpdateCmd;
use pldm_fw_pkg::manifest::{Descriptor, DescriptorType, FirmwareDeviceIdRecord};
use pldm_fw_pkg::FirmwareManifest;
use pldm_ua::events::PldmEvents;
use simple_logger::SimpleLogger;

use pldm_common::codec::PldmCodec;
use pldm_ua::daemon::{Options, PldmDaemon};
use pldm_ua::transport::{PldmSocket, PldmTransport};
use pldm_ua::{discovery_sm, update_sm};

struct TestSetup<
    D: discovery_sm::StateMachineActions + Send + 'static,
    U: update_sm::StateMachineActions + Send + 'static,
> {
    pub fd_sock: MockPldmSocket,
    pub daemon: PldmDaemon<MockPldmSocket, D, U>,
}

// Test UUID
const TEST_UUID: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
];

const TEST_UUID2: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xFF,
];

const TEST_UUID3: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0x00,
];

fn setup<
    D: discovery_sm::StateMachineActions + Send + 'static,
    U: update_sm::StateMachineActions + Send + 'static,
>(
    daemon_options: Options<D, U>,
) -> TestSetup<D, U> {
    // Initialize log level to info (only once)
    let _ = SimpleLogger::new().with_level(LevelFilter::Info).init();

    // Setup the PLDM transport
    let transport = MockTransport::new();

    // Define the update agent endpoint id
    let ua_sid = pldm_ua::transport::EndpointId(0x01);

    // Define the device endpoint id
    let fd_sid = pldm_ua::transport::EndpointId(0x02);

    // Create socket used by the PLDM daemon (update agent)
    let ua_sock = transport.create_socket(ua_sid, fd_sid).unwrap();

    // Create socket to be used by the device (FD)
    let fd_sock = transport.create_socket(fd_sid, ua_sid).unwrap();

    // Run the PLDM daemon
    let daemon = PldmDaemon::run(ua_sock.clone(), daemon_options).unwrap();

    TestSetup { fd_sock, daemon }
}

impl<
        D: discovery_sm::StateMachineActions + Send + 'static,
        U: update_sm::StateMachineActions + Send + 'static,
    > TestSetup<D, U>
{
    fn wait_for_state_transition(&self, expected_state: update_sm::States) -> Result<(), ()> {
        let timeout = Duration::from_secs(5);
        let start_time = std::time::Instant::now();

        while start_time.elapsed() < timeout {
            if self.daemon.get_update_sm_state() == expected_state {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(())
    }
}

/* Override the Discovery SM. Skip the discovery process by starting firmware update immediately when discovery is kicked-off */
struct CustomDiscoverySm {}
impl discovery_sm::StateMachineActions for CustomDiscoverySm {
    fn on_start_discovery(
        &self,
        ctx: &discovery_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        ctx.event_queue
            .send(PldmEvents::Update(update_sm::Events::StartUpdate))
            .map_err(|_| ())?;
        Ok(())
    }
}

fn send_response<P: PldmCodec>(socket: &MockPldmSocket, response: &P) {
    let mut buffer = [0u8; 512];
    let sz = response.encode(&mut buffer).unwrap();
    socket.send(&buffer[..sz]).unwrap();
}

fn receive_request<P: PldmCodec>(socket: &MockPldmSocket, cmd_code: u8) -> Result<P, ()> {
    let request = socket.receive(None).unwrap();

    let header = PldmMsgHeader::decode(&request.payload.data[..request.payload.len])
        .map_err(|_| (error!("Error decoding packet!")))?;
    if !header.is_hdr_ver_valid() {
        error!("Invalid header version!");
        return Err(());
    }
    if header.cmd_code() != cmd_code {
        error!("Invalid command code!");
        return Err(());
    }

    P::decode(&request.payload.data[..request.payload.len])
        .map_err(|_| (error!("Error decoding packet!")))
}

fn encode_descriptor(
    pkg_descriptor: &pldm_fw_pkg::manifest::Descriptor,
) -> Result<pldm_common::protocol::firmware_update::Descriptor, ()> {
    let descriptor = pldm_common::protocol::firmware_update::Descriptor {
        descriptor_type: pkg_descriptor.descriptor_type as u16,
        descriptor_length: pkg_descriptor.descriptor_data.len() as u16,
        descriptor_data: {
            let mut array = [0u8; 64];
            let data_slice = pkg_descriptor.descriptor_data.as_slice();
            let len = data_slice.len().min(64);
            array[..len].copy_from_slice(&data_slice[..len]);
            array
        },
    };
    Ok(descriptor)
}

#[test]
fn test_valid_device_identifier_one_descriptor() {
    let pldm_fw_pkg = FirmwareManifest {
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            initial_descriptor: Descriptor {
                descriptor_type: DescriptorType::Uuid,
                descriptor_data: TEST_UUID.to_vec(),
            },
            ..Default::default()
        }],
        ..Default::default()
    };

    // Setup the test environment
    let mut setup = setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: update_sm::DefaultActions {},
        fd_tid: 0x02,
    });

    // Receive QueryDeviceIdentifiers request
    let request: QueryDeviceIdentifiersRequest =
        receive_request(&setup.fd_sock, FwUpdateCmd::QueryDeviceIdentifiers as u8).unwrap();

    let initial_descriptor =
        encode_descriptor(&pldm_fw_pkg.firmware_device_id_records[0].initial_descriptor).unwrap();

    let response = QueryDeviceIdentifiersResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        std::mem::size_of::<pldm_common::protocol::firmware_update::Descriptor>() as u32,
        1,
        &initial_descriptor,
        None,
    )
    .unwrap();

    // Send the response
    send_response(&setup.fd_sock, &response);

    assert!(setup
        .wait_for_state_transition(update_sm::States::GetFirmwareParametersSent,)
        .is_ok());

    assert!(setup.daemon.get_device_id().is_some());

    setup.daemon.stop();
}

#[test]
fn test_valid_device_identifier_not_matched() {
    let pldm_fw_pkg = FirmwareManifest {
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            initial_descriptor: Descriptor {
                descriptor_type: DescriptorType::Uuid,
                descriptor_data: TEST_UUID.to_vec(),
            },
            ..Default::default()
        }],
        ..Default::default()
    };

    // Setup the test environment
    let mut setup = setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: update_sm::DefaultActions {},
        fd_tid: 0x02,
    });

    // Receive QueryDeviceIdentifiers request
    let request: QueryDeviceIdentifiersRequest =
        receive_request(&setup.fd_sock, FwUpdateCmd::QueryDeviceIdentifiers as u8).unwrap();

    let response_id_record = FirmwareDeviceIdRecord {
        initial_descriptor: Descriptor {
            descriptor_type: DescriptorType::Uuid,
            descriptor_data: TEST_UUID2.to_vec(),
        },
        ..Default::default()
    };
    let initial_descriptor = encode_descriptor(&response_id_record.initial_descriptor).unwrap();

    let response = QueryDeviceIdentifiersResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        std::mem::size_of::<pldm_common::protocol::firmware_update::Descriptor>() as u32,
        1,
        &initial_descriptor,
        None,
    )
    .unwrap();

    // Send the response
    send_response(&setup.fd_sock, &response);

    setup
        .wait_for_state_transition(update_sm::States::Done)
        .unwrap();

    assert!(setup.daemon.get_device_id().is_none());

    setup.daemon.stop();
}

#[test]
fn test_multiple_device_identifiers() {
    let pldm_fw_pkg = FirmwareManifest {
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            initial_descriptor: Descriptor {
                descriptor_type: DescriptorType::Uuid,
                descriptor_data: TEST_UUID.to_vec(),
            },
            additional_descriptors: Some(vec![
                Descriptor {
                    descriptor_type: DescriptorType::Uuid,
                    descriptor_data: TEST_UUID2.to_vec(),
                },
                Descriptor {
                    descriptor_type: DescriptorType::Uuid,
                    descriptor_data: TEST_UUID3.to_vec(),
                },
            ]),
            ..Default::default()
        }],
        ..Default::default()
    };

    // Setup the test environment
    let mut setup = setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: update_sm::DefaultActions {},
        fd_tid: 0x02,
    });

    // Receive QueryDeviceIdentifiers request
    let request: QueryDeviceIdentifiersRequest =
        receive_request(&setup.fd_sock, FwUpdateCmd::QueryDeviceIdentifiers as u8).unwrap();

    let initial_descriptor_response = encode_descriptor(&Descriptor {
        descriptor_type: DescriptorType::Uuid,
        descriptor_data: TEST_UUID.to_vec(),
    })
    .unwrap();
    let additional_descriptor_response1 = encode_descriptor(&Descriptor {
        descriptor_type: DescriptorType::Uuid,
        descriptor_data: TEST_UUID2.to_vec(),
    })
    .unwrap();
    let additional_descriptor_response2 = encode_descriptor(&Descriptor {
        descriptor_type: DescriptorType::Uuid,
        descriptor_data: TEST_UUID3.to_vec(),
    })
    .unwrap();

    let response = QueryDeviceIdentifiersResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        std::mem::size_of::<pldm_common::protocol::firmware_update::Descriptor>() as u32,
        3,
        &initial_descriptor_response,
        Some(&[
            additional_descriptor_response1,
            additional_descriptor_response2,
        ]),
    )
    .unwrap();

    // Send the response
    send_response(&setup.fd_sock, &response);

    assert!(setup
        .wait_for_state_transition(update_sm::States::GetFirmwareParametersSent,)
        .is_ok());

    assert!(setup.daemon.get_device_id().is_some());

    setup.daemon.stop();
}

#[test]
fn test_send_get_fw_parameter_after_response() {
    let pldm_fw_pkg = FirmwareManifest {
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            initial_descriptor: Descriptor {
                descriptor_type: DescriptorType::Uuid,
                descriptor_data: TEST_UUID.to_vec(),
            },
            ..Default::default()
        }],
        ..Default::default()
    };

    struct UpdateSmIgnoreFirmwareParamsResponse {}
    impl update_sm::StateMachineActions for UpdateSmIgnoreFirmwareParamsResponse {
        fn on_get_firmware_parameters_response(
            &mut self,
            _ctx: &mut update_sm::InnerContext<impl PldmSocket>,
            _response : pldm_common::message::firmware_update::get_fw_params::GetFirmwareParametersResponse,
        ) -> Result<(), ()> {
            Ok(())
        }
    }

    let mut setup = setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmIgnoreFirmwareParamsResponse {},
        fd_tid: 0x02,
    });

    // Receive QueryDeviceIdentifiers request
    let request: QueryDeviceIdentifiersRequest =
        receive_request(&setup.fd_sock, FwUpdateCmd::QueryDeviceIdentifiers as u8).unwrap();

    let initial_descriptor =
        encode_descriptor(&pldm_fw_pkg.firmware_device_id_records[0].initial_descriptor).unwrap();

    let response = QueryDeviceIdentifiersResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        std::mem::size_of::<pldm_common::protocol::firmware_update::Descriptor>() as u32,
        1,
        &initial_descriptor,
        None,
    )
    .unwrap();

    // Send the QueryDeviceIdentifiers response
    send_response(&setup.fd_sock, &response);

    // Receive the GetFwParameters request
    let request: pldm_common::message::firmware_update::get_fw_params::GetFirmwareParametersRequest =
        receive_request(&setup.fd_sock, FwUpdateCmd::GetFirmwareParameters as u8).unwrap();

    // Send the GetFwParameters response
    let response =
        pldm_common::message::firmware_update::get_fw_params::GetFirmwareParametersResponse::new(
            request.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            &FirmwareParameters {
                ..Default::default()
            },
        );
    send_response(&setup.fd_sock, &response);

    assert!(setup
        .wait_for_state_transition(update_sm::States::ReceivedFirmwareParameters,)
        .is_ok());

    setup.daemon.stop();
}

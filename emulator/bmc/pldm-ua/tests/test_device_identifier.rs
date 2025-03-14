// Licensed under the Apache-2.0 license

#[cfg(test)]
mod common;

use pldm_common::message::firmware_update::get_fw_params::FirmwareParameters;
use pldm_common::message::firmware_update::query_devid::{
    QueryDeviceIdentifiersRequest, QueryDeviceIdentifiersResponse,
};
use pldm_common::protocol::base::PldmBaseCompletionCode;
use pldm_common::protocol::firmware_update::FwUpdateCmd;
use pldm_fw_pkg::manifest::{Descriptor, DescriptorType, FirmwareDeviceIdRecord};
use pldm_fw_pkg::FirmwareManifest;

use pldm_ua::daemon::Options;
use pldm_ua::transport::PldmSocket;
use pldm_ua::update_sm;

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
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: common::CustomDiscoverySm {},
        update_sm_actions: update_sm::DefaultActions {},
        fd_tid: 0x02,
    });

    // Receive QueryDeviceIdentifiers request
    let request: QueryDeviceIdentifiersRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::QueryDeviceIdentifiers as u8)
        .unwrap();

    let initial_descriptor =
        encode_descriptor(&pldm_fw_pkg.firmware_device_id_records[0].initial_descriptor).unwrap();

    let response = QueryDeviceIdentifiersResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        &initial_descriptor,
        None,
    )
    .unwrap();

    // Send the response
    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::GetFirmwareParametersSent);

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
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: common::CustomDiscoverySm {},
        update_sm_actions: update_sm::DefaultActions {},
        fd_tid: 0x02,
    });

    // Receive QueryDeviceIdentifiers request
    let request: QueryDeviceIdentifiersRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::QueryDeviceIdentifiers as u8)
        .unwrap();

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
        &initial_descriptor,
        None,
    )
    .unwrap();

    // Send the response
    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::Done);

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
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: common::CustomDiscoverySm {},
        update_sm_actions: update_sm::DefaultActions {},
        fd_tid: 0x02,
    });

    // Receive QueryDeviceIdentifiers request
    let request: QueryDeviceIdentifiersRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::QueryDeviceIdentifiers as u8)
        .unwrap();

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
        &initial_descriptor_response,
        Some(&[
            additional_descriptor_response1,
            additional_descriptor_response2,
        ]),
    )
    .unwrap();

    // Send the response
    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::GetFirmwareParametersSent);

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

    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: common::CustomDiscoverySm {},
        update_sm_actions: UpdateSmIgnoreFirmwareParamsResponse {},
        fd_tid: 0x02,
    });

    // Receive QueryDeviceIdentifiers request
    let request: QueryDeviceIdentifiersRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::QueryDeviceIdentifiers as u8)
        .unwrap();

    let initial_descriptor =
        encode_descriptor(&pldm_fw_pkg.firmware_device_id_records[0].initial_descriptor).unwrap();

    let response = QueryDeviceIdentifiersResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        &initial_descriptor,
        None,
    )
    .unwrap();

    // Send the QueryDeviceIdentifiers response
    setup.send_response(&setup.fd_sock, &response);

    // Receive the GetFwParameters request
    let request: pldm_common::message::firmware_update::get_fw_params::GetFirmwareParametersRequest =
        setup.receive_request(&setup.fd_sock, FwUpdateCmd::GetFirmwareParameters as u8).unwrap();

    // Send the GetFwParameters response
    let response =
        pldm_common::message::firmware_update::get_fw_params::GetFirmwareParametersResponse::new(
            request.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            &FirmwareParameters {
                ..Default::default()
            },
        );
    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::ReceivedFirmwareParameters);

    setup.daemon.stop();
}

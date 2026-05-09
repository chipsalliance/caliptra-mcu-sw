// Licensed under the Apache-2.0 license

#[cfg(test)]
mod common;

use common::CustomDiscoverySm;
use pldm_common::message::firmware_update::{
    get_fw_params::GetFirmwareParametersResponse,
    pass_component::{PassComponentTableRequest, PassComponentTableResponse},
    query_devid::QueryDeviceIdentifiersResponse,
    request_update::RequestUpdateResponse,
};
use pldm_common::protocol::{
    base::{PldmBaseCompletionCode, TransferRespFlag},
    firmware_update::{
        ComponentClassification, ComponentResponse, ComponentResponseCode, FwUpdateCmd,
    },
};
use pldm_fw_pkg::manifest::{
    ComponentImageInformation, Descriptor, DescriptorType, FirmwareDeviceIdRecord,
};
use pldm_fw_pkg::FirmwareManifest;
use pldm_ua::{daemon::Options, events::PldmEvents, transport::PldmSocket, update_sm};

// Test UUID
pub const TEST_UUID: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
];

/* Override the Update SM, go directly to PassComponents */
struct UpdateSmBypassed {}
impl update_sm::StateMachineActions for UpdateSmBypassed {
    fn on_start_update(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        ctx.device_id = Some(ctx.pldm_fw_pkg.firmware_device_id_records[0].clone());
        ctx.components = ctx.pldm_fw_pkg.component_image_information.clone();
        ctx.event_queue
            .send(PldmEvents::Update(
                update_sm::Events::QueryDeviceIdentifiersResponse(QueryDeviceIdentifiersResponse {
                    ..Default::default()
                }),
            ))
            .map_err(|_| ())?;
        Ok(())
    }
    fn on_query_device_identifiers_response(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
        _response: QueryDeviceIdentifiersResponse,
    ) -> Result<(), ()> {
        ctx.event_queue
            .send(PldmEvents::Update(
                update_sm::Events::SendGetFirmwareParameters,
            ))
            .map_err(|_| ())?;
        Ok(())
    }
    fn on_send_get_firmware_parameters(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        ctx.event_queue
            .send(PldmEvents::Update(
                update_sm::Events::GetFirmwareParametersResponse(GetFirmwareParametersResponse {
                    ..Default::default()
                }),
            ))
            .map_err(|_| ())
    }
    fn on_get_firmware_parameters_response(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
        _response: pldm_common::message::firmware_update::get_fw_params::GetFirmwareParametersResponse,
    ) -> Result<(), ()> {
        ctx.event_queue
            .send(PldmEvents::Update(update_sm::Events::SendRequestUpdate))
            .map_err(|_| ())
    }
    fn on_send_request_update(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        ctx.event_queue
            .send(PldmEvents::Update(
                update_sm::Events::RequestUpdateResponse(RequestUpdateResponse {
                    ..Default::default()
                }),
            ))
            .map_err(|_| ())
    }
    fn on_request_update_response(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
        _response: RequestUpdateResponse,
    ) -> Result<(), ()> {
        ctx.event_queue
            .send(PldmEvents::Update(
                update_sm::Events::SendPassComponentRequest,
            ))
            .map_err(|_| ())
    }
    fn on_send_update_component(
        &mut self,
        _ctx: &mut update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        // Do nothing
        Ok(())
    }
}

#[test]
fn test_pass_one_component() {
    let pldm_fw_pkg = FirmwareManifest {
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            initial_descriptor: Descriptor {
                descriptor_type: DescriptorType::Uuid,
                descriptor_data: TEST_UUID.to_vec(),
            },
            component_image_set_version_string_type: pldm_fw_pkg::manifest::StringType::Utf8,
            component_image_set_version_string: Some("1.1.0".to_string()),
            applicable_components: Some(vec![0]),
            ..Default::default()
        }],
        component_image_information: vec![ComponentImageInformation {
            classification: ComponentClassification::Firmware as u16,
            identifier: 0x0001,
            comparison_stamp: Some(0x00010101),
            ..Default::default()
        }],
        ..Default::default()
    };

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassed {},
        fd_tid: 0x01,
    });

    // Receive PassComponent request
    let request: PassComponentTableRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::PassComponentTable as u8)
        .unwrap();

    assert_eq!(
        request.fixed.transfer_flag,
        TransferRespFlag::StartAndEnd as u8
    );

    // Send PassComponent response
    let response = PassComponentTableResponse::new(
        request.fixed.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        ComponentResponse::CompCanBeUpdated,
        ComponentResponseCode::CompCanBeUpdated,
    );

    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::ReadyXfer);

    setup.daemon.stop();
}

#[test]
fn test_pass_two_components() {
    let pldm_fw_pkg = FirmwareManifest {
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            initial_descriptor: Descriptor {
                descriptor_type: DescriptorType::Uuid,
                descriptor_data: TEST_UUID.to_vec(),
            },
            component_image_set_version_string_type: pldm_fw_pkg::manifest::StringType::Utf8,
            component_image_set_version_string: Some("1.1.0".to_string()),
            applicable_components: Some(vec![0]),
            ..Default::default()
        }],
        component_image_information: vec![
            ComponentImageInformation {
                classification: ComponentClassification::Firmware as u16,
                identifier: 0x0001,
                comparison_stamp: Some(0x00010101),
                ..Default::default()
            },
            ComponentImageInformation {
                classification: ComponentClassification::Firmware as u16,
                identifier: 0x0002,
                comparison_stamp: Some(0x00010101),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassed {},
        fd_tid: 0x01,
    });

    // Receive PassComponent request
    let request: PassComponentTableRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::PassComponentTable as u8)
        .unwrap();

    assert_eq!(request.fixed.transfer_flag, TransferRespFlag::Start as u8);

    // Send PassComponent response
    let response = PassComponentTableResponse::new(
        request.fixed.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        ComponentResponse::CompCanBeUpdated,
        ComponentResponseCode::CompCanBeUpdated,
    );

    setup.send_response(&setup.fd_sock, &response);

    let request: PassComponentTableRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::PassComponentTable as u8)
        .unwrap();
    assert_eq!(request.fixed.transfer_flag, TransferRespFlag::End as u8);

    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::ReadyXfer);

    setup.daemon.stop();
}

#[test]
fn test_pass_three_components() {
    let pldm_fw_pkg = FirmwareManifest {
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            initial_descriptor: Descriptor {
                descriptor_type: DescriptorType::Uuid,
                descriptor_data: TEST_UUID.to_vec(),
            },
            component_image_set_version_string_type: pldm_fw_pkg::manifest::StringType::Utf8,
            component_image_set_version_string: Some("1.1.0".to_string()),
            applicable_components: Some(vec![0]),
            ..Default::default()
        }],
        component_image_information: vec![
            ComponentImageInformation {
                classification: ComponentClassification::Firmware as u16,
                identifier: 0x0001,
                comparison_stamp: Some(0x00010101),
                ..Default::default()
            },
            ComponentImageInformation {
                classification: ComponentClassification::Firmware as u16,
                identifier: 0x0002,
                comparison_stamp: Some(0x00010101),
                ..Default::default()
            },
            ComponentImageInformation {
                classification: ComponentClassification::Firmware as u16,
                identifier: 0x0003,
                comparison_stamp: Some(0x00010101),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassed {},
        fd_tid: 0x01,
    });

    // Receive PassComponent request
    let request: PassComponentTableRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::PassComponentTable as u8)
        .unwrap();

    assert_eq!(request.fixed.transfer_flag, TransferRespFlag::Start as u8);

    // Send PassComponent response
    let response = PassComponentTableResponse::new(
        request.fixed.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        ComponentResponse::CompCanBeUpdated,
        ComponentResponseCode::CompCanBeUpdated,
    );

    setup.send_response(&setup.fd_sock, &response);

    let request: PassComponentTableRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::PassComponentTable as u8)
        .unwrap();
    assert_eq!(request.fixed.transfer_flag, TransferRespFlag::Middle as u8);

    setup.send_response(&setup.fd_sock, &response);

    let request: PassComponentTableRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::PassComponentTable as u8)
        .unwrap();
    assert_eq!(request.fixed.transfer_flag, TransferRespFlag::End as u8);

    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::ReadyXfer);

    setup.daemon.stop();
}

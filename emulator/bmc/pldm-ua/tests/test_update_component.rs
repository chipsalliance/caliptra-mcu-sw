// Licensed under the Apache-2.0 license

#[cfg(test)]
mod common;

use common::CustomDiscoverySm;
use pldm_common::message::firmware_update::{
    get_fw_params::GetFirmwareParametersResponse,
    pass_component::PassComponentTableResponse,
    query_devid::QueryDeviceIdentifiersResponse,
    request_update::RequestUpdateResponse,
    update_component::{UpdateComponentRequest, UpdateComponentResponse},
};
use pldm_common::protocol::base::PldmBaseCompletionCode;
use pldm_common::protocol::firmware_update::{
    ComponentClassification, ComponentCompatibilityResponse, ComponentCompatibilityResponseCode,
    ComponentResponseCode, FwUpdateCmd, UpdateOptionFlags,
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

/* Override the Update SM, go directly to UpdateComponent */
struct UpdateSmBypassed {}
impl update_sm::StateMachineActions for UpdateSmBypassed {
    fn on_start_update(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        ctx.device_id = Some(ctx.pldm_fw_pkg.firmware_device_id_records[0].clone());
        ctx.components = ctx.pldm_fw_pkg.component_image_information.clone();
        for _ in &ctx.components {
            ctx.component_response_codes
                .push(ComponentResponseCode::CompCanBeUpdated);
        }
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
    fn on_send_pass_component_request(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        ctx.event_queue
            .send(PldmEvents::Update(
                update_sm::Events::PassComponentResponse(PassComponentTableResponse {
                    ..Default::default()
                }),
            ))
            .map_err(|_| ())
    }
    fn are_all_components_passed(
        &self,
        _ctx: &update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<bool, ()> {
        Ok(true)
    }
    fn on_start_download(
        &mut self,
        _ctx: &mut update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        // Bypass the download step
        Ok(())
    }
}

#[test]
fn test_update_one_component() {
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

    // Receive UpdateComponent request
    let request: UpdateComponentRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::UpdateComponent as u8)
        .unwrap();

    let comp_identifier = request.fixed.comp_identifier;
    assert_eq!(comp_identifier, 0x0001);

    // Send UpdateComponent response
    let response = UpdateComponentResponse::new(
        request.fixed.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        ComponentCompatibilityResponse::CompCanBeUpdated,
        ComponentCompatibilityResponseCode::NoResponseCode,
        UpdateOptionFlags(0),
        0,
        None,
    );

    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::Download);

    setup.daemon.stop();
}

#[test]
fn test_update_two_components() {
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

    // Receive UpdateComponent request
    let request: UpdateComponentRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::UpdateComponent as u8)
        .unwrap();

    let comp_identifier = request.fixed.comp_identifier;
    assert_eq!(comp_identifier, 0x0001);

    // Send UpdateComponent response with can not be updated response code
    let response = UpdateComponentResponse::new(
        request.fixed.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        ComponentCompatibilityResponse::CompCannotBeUpdated,
        ComponentCompatibilityResponseCode::CompComparisonStampLower,
        UpdateOptionFlags(0),
        0,
        None,
    );
    setup.send_response(&setup.fd_sock, &response);

    // Should receive the next UpdateComponent request
    let request: UpdateComponentRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::UpdateComponent as u8)
        .unwrap();

    let comp_identifier = request.fixed.comp_identifier;
    assert_eq!(comp_identifier, 0x0002);

    let response = UpdateComponentResponse::new(
        request.fixed.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        ComponentCompatibilityResponse::CompCanBeUpdated,
        ComponentCompatibilityResponseCode::NoResponseCode,
        UpdateOptionFlags(0),
        0,
        None,
    );

    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::Download);

    setup.daemon.stop();
}

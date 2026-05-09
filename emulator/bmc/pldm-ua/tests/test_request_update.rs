// Licensed under the Apache-2.0 license

#[cfg(test)]
mod common;

use common::CustomDiscoverySm;
use pldm_common::message::firmware_update::get_fw_params::GetFirmwareParametersResponse;
use pldm_common::message::firmware_update::query_devid::QueryDeviceIdentifiersResponse;
use pldm_common::message::firmware_update::request_update::{
    RequestUpdateRequest, RequestUpdateResponse,
};
use pldm_common::protocol::base::PldmBaseCompletionCode;
use pldm_common::protocol::firmware_update::{ComponentClassification, FwUpdateCmd};
use pldm_fw_pkg::manifest::{
    ComponentImageInformation, Descriptor, DescriptorType, FirmwareDeviceIdRecord,
};
use pldm_fw_pkg::FirmwareManifest;
use pldm_ua::events::PldmEvents;

use pldm_ua::daemon::Options;
use pldm_ua::transport::PldmSocket;
use pldm_ua::update_sm;

// Test UUID
pub const TEST_UUID: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
];

/* Override the Update SM, bypass QueryDeviceIdentifiers and GetFirmwareParameters */
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
}

const COMPONENT_ACTIVE_VER_STR: &str = "1.1.0";
const CALIPTRA_FW_COMP_IDENTIFIER: u16 = 0x0001;
const CALIPTRA_FW_ACTIVE_COMP_STAMP: u32 = 0x00010105;
const SOC_MANIFEST_COMP_IDENTIFIER: u16 = 0x0003;
const SOC_MANIFEST_ACTIVE_COMP_STAMP: u32 = 0x00010101;

fn get_pldm_fw_pkg_caliptra_and_manifest(
    caliptra_comp_stamp: Option<u32>,
    manifest_comp_stamp: Option<u32>,
) -> FirmwareManifest {
    FirmwareManifest {
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            initial_descriptor: Descriptor {
                descriptor_type: DescriptorType::Uuid,
                descriptor_data: TEST_UUID.to_vec(),
            },
            component_image_set_version_string_type: pldm_fw_pkg::manifest::StringType::Utf8,
            component_image_set_version_string: Some(COMPONENT_ACTIVE_VER_STR.to_string()),
            applicable_components: Some(vec![0, 1]),
            ..Default::default()
        }],
        component_image_information: vec![
            ComponentImageInformation {
                classification: ComponentClassification::Firmware as u16,
                identifier: CALIPTRA_FW_COMP_IDENTIFIER,
                comparison_stamp: caliptra_comp_stamp,
                ..Default::default()
            },
            ComponentImageInformation {
                classification: ComponentClassification::Other as u16,
                identifier: SOC_MANIFEST_COMP_IDENTIFIER,
                comparison_stamp: manifest_comp_stamp,
                ..Default::default()
            },
        ],
        ..Default::default()
    }
}

#[test]
fn test_request_update_receive_ok() {
    // PLDM firmware package contains Caliptra Firmware with current active version + 1
    let pldm_fw_pkg = get_pldm_fw_pkg_caliptra_and_manifest(
        Some(CALIPTRA_FW_ACTIVE_COMP_STAMP + 1),
        Some(SOC_MANIFEST_ACTIVE_COMP_STAMP + 1),
    );

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassed {},
        fd_tid: 0x01,
    });

    // Receive RequestUpdate request
    let request: RequestUpdateRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::RequestUpdate as u8)
        .unwrap();

    // Send RequestUpdate response
    let response = RequestUpdateResponse::new(
        request.fixed.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        0,
        0,
        None,
    );

    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::LearnComponents);

    setup.daemon.stop();
}

#[test]
fn test_request_update_receive_fail() {
    // PLDM firmware package contains Caliptra Firmware with current active version + 1
    let pldm_fw_pkg = get_pldm_fw_pkg_caliptra_and_manifest(
        Some(CALIPTRA_FW_ACTIVE_COMP_STAMP + 1),
        Some(SOC_MANIFEST_ACTIVE_COMP_STAMP + 1),
    );

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassed {},
        fd_tid: 0x01,
    });

    // Receive RequestUpdate request
    let request: RequestUpdateRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::RequestUpdate as u8)
        .unwrap();

    // Send RequestUpdate response
    let response = RequestUpdateResponse::new(
        request.fixed.hdr.instance_id(),
        PldmBaseCompletionCode::Error as u8,
        0,
        0,
        None,
    );

    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::Done);

    setup.daemon.stop();
}

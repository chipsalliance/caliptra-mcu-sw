// Licensed under the Apache-2.0 license

#[cfg(test)]
mod common;

use std::thread::sleep;
use std::time::Duration;

use common::CustomDiscoverySm;
use pldm_common::message::firmware_update::get_fw_params::{
    FirmwareParameters, GetFirmwareParametersRequest, GetFirmwareParametersResponse,
};
use pldm_common::message::firmware_update::query_devid::QueryDeviceIdentifiersResponse;
use pldm_common::protocol::base::PldmBaseCompletionCode;
use pldm_common::protocol::firmware_update::{
    ComponentActivationMethods, ComponentClassification, ComponentParameterEntry,
    ComponentParameterEntryFixed, FirmwareDeviceCapability, FwUpdateCmd, PldmFirmwareString,
    VersionStringType, PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN,
};
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

/* Override the Update SM, and bypass the QueryDeviceIdentifier exchange and go straight to GetFirmwareParameters */
struct UpdateSmBypassQueryDevId {
    expected_num_components_to_update: usize,
}
impl update_sm::StateMachineActions for UpdateSmBypassQueryDevId {
    fn on_start_update(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        ctx.device_id = Some(FirmwareDeviceIdRecord {
            applicable_components: Some(vec![0, 1, 2]),
            ..Default::default()
        });
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
    fn on_stop_update(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        // When the state machine is stopped, verify the number of components to update
        assert_eq!(self.expected_num_components_to_update, ctx.components.len());
        Ok(())
    }
}

const COMPONENT_ACTIVE_VER_STR: &str = "1.1.0";

const CALIPTRA_FW_COMP_IDENTIFIER: u16 = 0x0001;
const CALIPTRA_FW_ACTIVE_COMP_STAMP: u32 = 0x00010105;
const CALIPTRA_FW_ACTIVE_VER_STR: &str = "caliptra-fmc-1.1.0";
const CALIPTRA_FW_RELEASE_DATE: [u8; 8] = *b"20250210";
const EMPTY_RELEASE_DATE: [u8; 8] = *b"\0\0\0\0\0\0\0\0";

fn get_caliptra_component_fw_params() -> ComponentParameterEntry {
    ComponentParameterEntry {
        comp_param_entry_fixed: ComponentParameterEntryFixed {
            comp_classification: ComponentClassification::Firmware as u16,
            comp_identifier: CALIPTRA_FW_COMP_IDENTIFIER,
            comp_classification_index: 0u8,
            active_comp_comparison_stamp: CALIPTRA_FW_ACTIVE_COMP_STAMP,
            active_comp_ver_str_type: VersionStringType::Utf8 as u8,
            active_comp_ver_str_len: CALIPTRA_FW_ACTIVE_VER_STR.len() as u8,
            active_comp_release_date: CALIPTRA_FW_RELEASE_DATE,
            pending_comp_comparison_stamp: 0u32,
            pending_comp_ver_str_type: VersionStringType::Unspecified as u8,
            pending_comp_ver_str_len: 0,
            pending_comp_release_date: EMPTY_RELEASE_DATE,
            comp_activation_methods: ComponentActivationMethods(0),
            capabilities_during_update: FirmwareDeviceCapability(0),
        },
        active_comp_ver_str: {
            let mut active_comp_ver_str = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
            active_comp_ver_str[..CALIPTRA_FW_ACTIVE_VER_STR.len()]
                .copy_from_slice(CALIPTRA_FW_ACTIVE_VER_STR.as_bytes());
            active_comp_ver_str
        },
        pending_comp_ver_str: None,
    }
}

const SOC_MANIFEST_COMP_IDENTIFIER: u16 = 0x0003;
const SOC_MANIFEST_ACTIVE_COMP_STAMP: u32 = 0x00010101;
const SOC_MANIFEST_ACTIVE_VER_STR: &str = "caliptra-fmc-1.1.0";
const SOC_MANIFEST_RELEASE_DATE: [u8; 8] = *b"20250210";

fn get_soc_manifest_component_fw_params() -> ComponentParameterEntry {
    ComponentParameterEntry {
        comp_param_entry_fixed: ComponentParameterEntryFixed {
            comp_classification: ComponentClassification::Other as u16,
            comp_identifier: SOC_MANIFEST_COMP_IDENTIFIER,
            comp_classification_index: 0u8,
            active_comp_comparison_stamp: SOC_MANIFEST_ACTIVE_COMP_STAMP,
            active_comp_ver_str_type: VersionStringType::Utf8 as u8,
            active_comp_ver_str_len: SOC_MANIFEST_ACTIVE_VER_STR.len() as u8,
            active_comp_release_date: SOC_MANIFEST_RELEASE_DATE,
            pending_comp_comparison_stamp: 0u32,
            pending_comp_ver_str_type: VersionStringType::Unspecified as u8,
            pending_comp_ver_str_len: 0,
            pending_comp_release_date: EMPTY_RELEASE_DATE,
            comp_activation_methods: ComponentActivationMethods(0),
            capabilities_during_update: FirmwareDeviceCapability(0),
        },
        active_comp_ver_str: {
            let mut active_comp_ver_str = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
            active_comp_ver_str[..SOC_MANIFEST_ACTIVE_VER_STR.len()]
                .copy_from_slice(SOC_MANIFEST_ACTIVE_VER_STR.as_bytes());
            active_comp_ver_str
        },
        pending_comp_ver_str: None,
    }
}

fn get_pldm_fw_pkg_caliptra_only(comp_stamp: Option<u32>) -> FirmwareManifest {
    FirmwareManifest {
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            initial_descriptor: Descriptor {
                descriptor_type: DescriptorType::Uuid,
                descriptor_data: TEST_UUID.to_vec(),
            },
            component_image_set_version_string_type: pldm_fw_pkg::manifest::StringType::Utf8,
            component_image_set_version_string: Some(COMPONENT_ACTIVE_VER_STR.to_string()),
            applicable_components: Some(vec![0]),
            ..Default::default()
        }],
        component_image_information: vec![ComponentImageInformation {
            classification: ComponentClassification::Firmware as u16,
            identifier: CALIPTRA_FW_COMP_IDENTIFIER,
            comparison_stamp: comp_stamp,
            ..Default::default()
        }],
        ..Default::default()
    }
}

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
fn test_caliptra_fw_update() {
    // PLDM firmware package contains Caliptra Firmware with current active version + 1
    let pldm_fw_pkg = get_pldm_fw_pkg_caliptra_only(Some(CALIPTRA_FW_ACTIVE_COMP_STAMP + 1));

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassQueryDevId {
            expected_num_components_to_update: 1,
        },
        fd_tid: 0x01,
    });

    // Receive QueryDeviceIdentifiers request
    let request: GetFirmwareParametersRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::GetFirmwareParameters as u8)
        .unwrap();

    let caliptra_comp_fw_params = get_caliptra_component_fw_params();
    let params = FirmwareParameters::new(
        FirmwareDeviceCapability(0x0010),
        1,
        &PldmFirmwareString::new("UTF-8", COMPONENT_ACTIVE_VER_STR).unwrap(),
        &PldmFirmwareString::new("UTF-8", "").unwrap(),
        &[caliptra_comp_fw_params],
    );

    let response = GetFirmwareParametersResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        &params,
    );

    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::RequestUpdateSent);

    setup.daemon.stop();
}

#[test]
fn test_caliptra_fw_update_with_timeout() {
    // PLDM firmware package contains Caliptra Firmware with current active version + 1
    let pldm_fw_pkg = get_pldm_fw_pkg_caliptra_only(Some(CALIPTRA_FW_ACTIVE_COMP_STAMP + 1));

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassQueryDevId {
            expected_num_components_to_update: 1,
        },
        fd_tid: 0x01,
    });

    // Receive QueryDeviceIdentifiers request
    let _: GetFirmwareParametersRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::GetFirmwareParameters as u8)
        .unwrap();

    sleep(Duration::from_secs(5)); // Simulate a delay before sending response

    // Should receive another GetFirmwareParameters request
    let request: GetFirmwareParametersRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::GetFirmwareParameters as u8)
        .unwrap();

    let caliptra_comp_fw_params = get_caliptra_component_fw_params();
    let params = FirmwareParameters::new(
        FirmwareDeviceCapability(0x0010),
        1,
        &PldmFirmwareString::new("UTF-8", COMPONENT_ACTIVE_VER_STR).unwrap(),
        &PldmFirmwareString::new("UTF-8", "").unwrap(),
        &[caliptra_comp_fw_params],
    );

    let response = GetFirmwareParametersResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        &params,
    );

    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::RequestUpdateSent);

    setup.daemon.stop();
}

#[test]
fn test_caliptra_fw_incorrect_id() {
    let pldm_fw_pkg = get_pldm_fw_pkg_caliptra_only(Some(CALIPTRA_FW_ACTIVE_COMP_STAMP + 1));

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassQueryDevId {
            expected_num_components_to_update: 0,
        },
        fd_tid: 0x01,
    });

    // Receive QueryDeviceIdentifiers request
    let request: GetFirmwareParametersRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::GetFirmwareParameters as u8)
        .unwrap();

    let mut caliptra_comp_fw_params = get_caliptra_component_fw_params();
    caliptra_comp_fw_params
        .comp_param_entry_fixed
        .comp_identifier = 0x0002;
    let params = FirmwareParameters::new(
        FirmwareDeviceCapability(0x0010),
        1,
        &PldmFirmwareString::new("UTF-8", COMPONENT_ACTIVE_VER_STR).unwrap(),
        &PldmFirmwareString::new("UTF-8", "").unwrap(),
        &[caliptra_comp_fw_params],
    );

    let response = GetFirmwareParametersResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        &params,
    );

    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::Done);

    setup.daemon.stop();
}

#[test]
fn test_caliptra_fw_update_same_version() {
    let pldm_fw_pkg = get_pldm_fw_pkg_caliptra_only(Some(CALIPTRA_FW_ACTIVE_COMP_STAMP));

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassQueryDevId {
            expected_num_components_to_update: 0,
        },
        fd_tid: 0x01,
    });

    // Receive QueryDeviceIdentifiers request
    let request: GetFirmwareParametersRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::GetFirmwareParameters as u8)
        .unwrap();

    let caliptra_comp_fw_params = get_caliptra_component_fw_params();
    let params = FirmwareParameters::new(
        FirmwareDeviceCapability(0x0010),
        1,
        &PldmFirmwareString::new("UTF-8", COMPONENT_ACTIVE_VER_STR).unwrap(),
        &PldmFirmwareString::new("UTF-8", "").unwrap(),
        &[caliptra_comp_fw_params],
    );

    let response = GetFirmwareParametersResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        &params,
    );

    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::Done);

    setup.daemon.stop();
}

#[test]
fn test_caliptra_fw_caliptra_and_manifest() {
    let pldm_fw_pkg = get_pldm_fw_pkg_caliptra_and_manifest(
        Some(CALIPTRA_FW_ACTIVE_COMP_STAMP + 1),
        Some(SOC_MANIFEST_ACTIVE_COMP_STAMP + 1),
    );

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassQueryDevId {
            expected_num_components_to_update: 2,
        },
        fd_tid: 0x01,
    });

    // Receive QueryDeviceIdentifiers request
    let request: GetFirmwareParametersRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::GetFirmwareParameters as u8)
        .unwrap();

    let caliptra_fw_params = get_caliptra_component_fw_params();
    let manifest_fw_params = get_soc_manifest_component_fw_params();
    let params = FirmwareParameters::new(
        FirmwareDeviceCapability(0x0010),
        2,
        &PldmFirmwareString::new("UTF-8", COMPONENT_ACTIVE_VER_STR).unwrap(),
        &PldmFirmwareString::new("UTF-8", "").unwrap(),
        &[caliptra_fw_params, manifest_fw_params],
    );

    let response = GetFirmwareParametersResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        &params,
    );

    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::RequestUpdateSent);

    setup.daemon.stop();
}

#[test]
fn test_caliptra_fw_caliptra_same_version_and_manifest_diff_version() {
    let pldm_fw_pkg = get_pldm_fw_pkg_caliptra_and_manifest(
        Some(CALIPTRA_FW_ACTIVE_COMP_STAMP),
        Some(SOC_MANIFEST_ACTIVE_COMP_STAMP + 1),
    );

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassQueryDevId {
            expected_num_components_to_update: 1,
        },
        fd_tid: 0x01,
    });

    // Receive QueryDeviceIdentifiers request
    let request: GetFirmwareParametersRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::GetFirmwareParameters as u8)
        .unwrap();

    let caliptra_fw_params = get_caliptra_component_fw_params();
    let manifest_fw_params = get_soc_manifest_component_fw_params();
    let params = FirmwareParameters::new(
        FirmwareDeviceCapability(0x0010),
        2,
        &PldmFirmwareString::new("UTF-8", COMPONENT_ACTIVE_VER_STR).unwrap(),
        &PldmFirmwareString::new("UTF-8", "").unwrap(),
        &[caliptra_fw_params, manifest_fw_params],
    );

    let response = GetFirmwareParametersResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        &params,
    );

    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::RequestUpdateSent);

    setup.daemon.cancel_update();

    setup.wait_for_state_transition(update_sm::States::Done);

    setup.daemon.stop();
}

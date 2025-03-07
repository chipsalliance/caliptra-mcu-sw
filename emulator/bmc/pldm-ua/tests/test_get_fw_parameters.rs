// Licensed under the Apache-2.0 license

#[cfg(test)]
mod tests {}
mod mock_transport;
use std::time::Duration;

use log::{error, LevelFilter};
use mock_transport::{MockPldmSocket, MockTransport};
use pldm_common::message::firmware_update::get_fw_params::{
    FirmwareParameters, GetFirmwareParametersRequest, GetFirmwareParametersResponse,
};
use pldm_common::message::firmware_update::query_devid::QueryDeviceIdentifiersResponse;
use pldm_common::protocol::base::{PldmBaseCompletionCode, PldmMsgHeader};
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
    fn wait_for_state_transition(&self, expected_state: update_sm::States) {
        let timeout = Duration::from_secs(5);
        let start_time = std::time::Instant::now();

        while start_time.elapsed() < timeout {
            if self.daemon.get_update_sm_state() == expected_state {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(
            self.daemon.get_update_sm_state(),
            expected_state,
            "Timed out waiting for state transition"
        );
    }
}

/* Override the Discovery SM, when started, discovery will immediately start firmware update and skip the
discovery process. */
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
    let mut setup = setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassQueryDevId {
            expected_num_components_to_update: 1,
        },
        fd_tid: 0x01,
    });

    // Receive QueryDeviceIdentifiers request
    let request: GetFirmwareParametersRequest =
        receive_request(&setup.fd_sock, FwUpdateCmd::GetFirmwareParameters as u8).unwrap();

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

    send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::RequestUpdateSent);

    setup.daemon.stop();
}

#[test]
fn test_caliptra_fw_incorrect_id() {
    let pldm_fw_pkg = get_pldm_fw_pkg_caliptra_only(Some(CALIPTRA_FW_ACTIVE_COMP_STAMP + 1));

    // Setup the test environment
    let mut setup = setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassQueryDevId {
            expected_num_components_to_update: 0,
        },
        fd_tid: 0x01,
    });

    // Receive QueryDeviceIdentifiers request
    let request: GetFirmwareParametersRequest =
        receive_request(&setup.fd_sock, FwUpdateCmd::GetFirmwareParameters as u8).unwrap();

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

    send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::Done);

    setup.daemon.stop();
}

#[test]
fn test_caliptra_fw_update_same_version() {
    let pldm_fw_pkg = get_pldm_fw_pkg_caliptra_only(Some(CALIPTRA_FW_ACTIVE_COMP_STAMP));

    // Setup the test environment
    let mut setup = setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassQueryDevId {
            expected_num_components_to_update: 0,
        },
        fd_tid: 0x01,
    });

    // Receive QueryDeviceIdentifiers request
    let request: GetFirmwareParametersRequest =
        receive_request(&setup.fd_sock, FwUpdateCmd::GetFirmwareParameters as u8).unwrap();

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

    send_response(&setup.fd_sock, &response);

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
    let mut setup = setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassQueryDevId {
            expected_num_components_to_update: 2,
        },
        fd_tid: 0x01,
    });

    // Receive QueryDeviceIdentifiers request
    let request: GetFirmwareParametersRequest =
        receive_request(&setup.fd_sock, FwUpdateCmd::GetFirmwareParameters as u8).unwrap();

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

    send_response(&setup.fd_sock, &response);

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
    let mut setup = setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassQueryDevId {
            expected_num_components_to_update: 1,
        },
        fd_tid: 0x01,
    });

    // Receive QueryDeviceIdentifiers request
    let request: GetFirmwareParametersRequest =
        receive_request(&setup.fd_sock, FwUpdateCmd::GetFirmwareParameters as u8).unwrap();

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

    send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::RequestUpdateSent);

    setup.daemon.cancel_update();

    setup.wait_for_state_transition(update_sm::States::Done);

    setup.daemon.stop();
}

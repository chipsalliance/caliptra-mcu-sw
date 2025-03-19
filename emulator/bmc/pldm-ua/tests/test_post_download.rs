// Licensed under the Apache-2.0 license

#[cfg(test)]
mod common;
use common::CustomDiscoverySm;
use pldm_common::{
    message::firmware_update::{
        activate_fw::{ActivateFirmwareRequest, ActivateFirmwareResponse},
        apply_complete::{ApplyCompleteRequest, ApplyCompleteResponse, ApplyResult},
        get_fw_params::GetFirmwareParametersResponse,
        get_status::{
            AuxState, AuxStateStatus, GetStatusRequest, GetStatusResponse, ProgressPercent,
            ReasonCode, UpdateOptionResp,
        },
        pass_component::PassComponentTableResponse,
        query_devid::QueryDeviceIdentifiersResponse,
        request_cancel::{CancelUpdateComponentRequest, CancelUpdateComponentResponse},
        request_update::RequestUpdateResponse,
        update_component::{UpdateComponentRequest, UpdateComponentResponse},
        verify_complete::{VerifyCompleteRequest, VerifyCompleteResponse, VerifyResult},
    },
    protocol::{
        base::{PldmBaseCompletionCode, PldmMsgType},
        firmware_update::{
            ComponentActivationMethods, ComponentCompatibilityResponse,
            ComponentCompatibilityResponseCode, ComponentResponseCode, FirmwareDeviceState,
            FwUpdateCmd, UpdateOptionFlags,
        },
    },
};
use pldm_fw_pkg::{
    manifest::{ComponentImageInformation, FirmwareDeviceIdRecord, PackageHeaderInformation},
    FirmwareManifest,
};
use pldm_ua::{daemon::Options, events::PldmEvents, transport::PldmSocket, update_sm};

// Test UUID
pub const TEST_UUID: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
];

const SELF_ACTIVATION_FIELD_BIT: u16 = 0x0001;
const SELF_ACTIVATION_FIELD_MASK: u16 = 0x0001;

/* Override the Update SM, go directly to TransferComplete */
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
        ctx.current_component_index = Some(0);
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
    fn on_all_components_passed(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        ctx.event_queue
            .send(PldmEvents::Update(update_sm::Events::StartDownload))
            .map_err(|_| ())
    }
    fn on_start_download(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        ctx.event_queue
            .send(PldmEvents::Update(update_sm::Events::TransferCompletePass))
            .map_err(|_| ())
    }
}

#[test]
fn test_one_component_activate() {
    let activation_option: u16 = SELF_ACTIVATION_FIELD_MASK << SELF_ACTIVATION_FIELD_BIT;
    let pldm_fw_pkg = FirmwareManifest {
        package_header_information: PackageHeaderInformation {
            ..Default::default()
        },
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            ..Default::default()
        }],
        downstream_device_id_records: None,
        component_image_information: vec![ComponentImageInformation {
            identifier: 0x0002,
            options: 0x0000,
            requested_activation_method: activation_option,
            ..Default::default()
        }],
    };

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassed {},
        fd_tid: 0x01,
    });

    setup.wait_for_state_transition(update_sm::States::Verify);

    let mut instance_id = 0u8;
    let request = VerifyCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        VerifyResult::VerifySuccess,
    );
    setup.send_response(&setup.fd_sock, &request);

    let _: VerifyCompleteResponse = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::VerifyComplete as u8)
        .unwrap();
    setup.wait_for_state_transition(update_sm::States::Apply);

    instance_id += 1;

    let request = ApplyCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        ApplyResult::ApplySuccess,
        ComponentActivationMethods(0),
    );
    setup.send_response(&setup.fd_sock, &request);

    let _: ApplyCompleteResponse = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::ApplyComplete as u8)
        .unwrap();

    setup.wait_for_state_transition(update_sm::States::Activate);

    let request: ActivateFirmwareRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::ActivateFirmware as u8)
        .unwrap();

    let response = ActivateFirmwareResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        5,
    );

    setup.send_response(&setup.fd_sock, &response);

    // Don't respond for 2 seconds
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Expect a GetStatusRequest
    let request: GetStatusRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::GetStatus as u8)
        .unwrap();

    // Send a GetStatusResponse with a progress of 80%
    let response = GetStatusResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        FirmwareDeviceState::Activate,
        FirmwareDeviceState::Apply,
        AuxState::OperationInProgress,
        AuxStateStatus::AuxStateInProgressOrSuccess,
        ProgressPercent::new(80).unwrap(),
        ReasonCode::ActivateFw,
        UpdateOptionResp::NoForceUpdate,
    );

    setup.send_response(&setup.fd_sock, &response);

    // Check that the state machine is still in the Activate state
    setup.wait_for_state_transition(update_sm::States::Activate);

    // Expect another GetStatusRequest
    let request: GetStatusRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::GetStatus as u8)
        .unwrap();

    // Send a GetStatusResponse with a progress of 100%
    let response = GetStatusResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        FirmwareDeviceState::Idle,
        FirmwareDeviceState::Activate,
        AuxState::OperationSuccessful,
        AuxStateStatus::AuxStateInProgressOrSuccess,
        ProgressPercent::new(100).unwrap(),
        ReasonCode::ActivateFw,
        UpdateOptionResp::NoForceUpdate,
    );

    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::Done);

    setup.daemon.stop();
}

#[test]
fn test_one_component_verify_failed() {
    let activation_option: u16 = SELF_ACTIVATION_FIELD_MASK << SELF_ACTIVATION_FIELD_BIT;
    let pldm_fw_pkg = FirmwareManifest {
        package_header_information: PackageHeaderInformation {
            ..Default::default()
        },
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            ..Default::default()
        }],
        downstream_device_id_records: None,
        component_image_information: vec![ComponentImageInformation {
            identifier: 0x0002,
            options: 0x0000,
            requested_activation_method: activation_option,
            ..Default::default()
        }],
    };

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassed {},
        fd_tid: 0x01,
    });

    setup.wait_for_state_transition(update_sm::States::Verify);

    let instance_id = 0u8;
    let request = VerifyCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        VerifyResult::VerifyErrorVerificationFailure,
    );
    setup.send_response(&setup.fd_sock, &request);

    let _: VerifyCompleteResponse = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::VerifyComplete as u8)
        .unwrap();

    // Expect a CancelUpdateComponentRequest
    let request: CancelUpdateComponentRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::CancelUpdateComponent as u8)
        .unwrap();

    let response = CancelUpdateComponentResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
    );
    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::Idle);

    setup.daemon.stop();
}

#[test]
fn test_one_component_apply_failed() {
    let activation_option: u16 = SELF_ACTIVATION_FIELD_MASK << SELF_ACTIVATION_FIELD_BIT;
    let pldm_fw_pkg = FirmwareManifest {
        package_header_information: PackageHeaderInformation {
            ..Default::default()
        },
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            ..Default::default()
        }],
        downstream_device_id_records: None,
        component_image_information: vec![ComponentImageInformation {
            identifier: 0x0002,
            options: 0x0000,
            requested_activation_method: activation_option,
            ..Default::default()
        }],
    };

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassed {},
        fd_tid: 0x01,
    });

    setup.wait_for_state_transition(update_sm::States::Verify);

    let instance_id = 0u8;
    let request = VerifyCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        VerifyResult::VerifySuccess,
    );
    setup.send_response(&setup.fd_sock, &request);

    let _: VerifyCompleteResponse = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::VerifyComplete as u8)
        .unwrap();

    setup.wait_for_state_transition(update_sm::States::Apply);

    let instance_id = 1u8;
    let request = ApplyCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        ApplyResult::ApplyFailureMemoryIssue,
        ComponentActivationMethods(0),
    );
    setup.send_response(&setup.fd_sock, &request);

    let _: ApplyCompleteResponse = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::ApplyComplete as u8)
        .unwrap();

    // Expect a CancelUpdateComponentRequest
    let request: CancelUpdateComponentRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::CancelUpdateComponent as u8)
        .unwrap();

    let response = CancelUpdateComponentResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
    );
    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::Idle);

    setup.daemon.stop();
}

#[test]
fn test_apply_complete_with_activation_modification() {
    let activation_option: u16 = SELF_ACTIVATION_FIELD_MASK << SELF_ACTIVATION_FIELD_BIT;
    let pldm_fw_pkg = FirmwareManifest {
        package_header_information: PackageHeaderInformation {
            ..Default::default()
        },
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            ..Default::default()
        }],
        downstream_device_id_records: None,
        component_image_information: vec![ComponentImageInformation {
            identifier: 0x0002,
            options: 0x0000,
            requested_activation_method: activation_option,
            ..Default::default()
        }],
    };

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassed {},
        fd_tid: 0x01,
    });

    setup.wait_for_state_transition(update_sm::States::Verify);

    let instance_id = 0u8;
    let request = VerifyCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        VerifyResult::VerifySuccess,
    );
    setup.send_response(&setup.fd_sock, &request);

    let _: VerifyCompleteResponse = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::VerifyComplete as u8)
        .unwrap();

    setup.wait_for_state_transition(update_sm::States::Apply);

    let instance_id = 1u8;
    let mut new_activation_method = ComponentActivationMethods(0);
    new_activation_method.set_automatic(true);

    let request = ApplyCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        ApplyResult::ApplySuccessWithActivationMethod,
        new_activation_method,
    );
    setup.send_response(&setup.fd_sock, &request);

    let _: ApplyCompleteResponse = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::ApplyComplete as u8)
        .unwrap();

    let request: ActivateFirmwareRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::ActivateFirmware as u8)
        .unwrap();

    // ActivateRequest should indicate that self-activation is not requested
    assert_eq!(request.self_contained_activation_req, 0x00);

    let response = ActivateFirmwareResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        0,
    );
    setup.send_response(&setup.fd_sock, &response);

    // Since there's nothing to activate, we should be done
    setup.wait_for_state_transition(update_sm::States::Done);
    setup.daemon.stop();
}

#[test]
fn test_two_components_activate() {
    let activation_option: u16 = SELF_ACTIVATION_FIELD_MASK << SELF_ACTIVATION_FIELD_BIT;
    let pldm_fw_pkg = FirmwareManifest {
        package_header_information: PackageHeaderInformation {
            ..Default::default()
        },
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            ..Default::default()
        }],
        downstream_device_id_records: None,
        component_image_information: vec![
            ComponentImageInformation {
                identifier: 0x0002,
                options: 0x0000,
                requested_activation_method: activation_option,
                ..Default::default()
            },
            ComponentImageInformation {
                identifier: 0x0003,
                options: 0x0000,
                requested_activation_method: activation_option,
                ..Default::default()
            },
        ],
    };

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassed {},
        fd_tid: 0x01,
    });

    setup.wait_for_state_transition(update_sm::States::Verify);

    let mut instance_id = 0u8;
    let request = VerifyCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        VerifyResult::VerifySuccess,
    );
    setup.send_response(&setup.fd_sock, &request);

    let _: VerifyCompleteResponse = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::VerifyComplete as u8)
        .unwrap();

    setup.wait_for_state_transition(update_sm::States::Apply);

    instance_id += 1;
    let request = ApplyCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        ApplyResult::ApplySuccess,
        ComponentActivationMethods(0),
    );
    setup.send_response(&setup.fd_sock, &request);

    let _: ApplyCompleteResponse = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::ApplyComplete as u8)
        .unwrap();

    // UA should send UpdateComponent for the next component
    let request: UpdateComponentRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::UpdateComponent as u8)
        .unwrap();
    let request_comp_identifier = request.fixed.comp_identifier;
    assert_eq!(request_comp_identifier, 0x0003);

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

    // Download starts here, and will go straight to Verify since we bypassed the download
    setup.wait_for_state_transition(update_sm::States::Verify);

    instance_id += request.fixed.hdr.instance_id() + 1;
    let request = VerifyCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        VerifyResult::VerifySuccess,
    );
    setup.send_response(&setup.fd_sock, &request);

    let _: VerifyCompleteResponse = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::VerifyComplete as u8)
        .unwrap();

    setup.wait_for_state_transition(update_sm::States::Apply);

    instance_id += 1;
    let request = ApplyCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        ApplyResult::ApplySuccess,
        ComponentActivationMethods(0),
    );
    setup.send_response(&setup.fd_sock, &request);

    let _: ApplyCompleteResponse = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::ApplyComplete as u8)
        .unwrap();

    // Since all components are applied, SM should now be in the Activate state
    setup.wait_for_state_transition(update_sm::States::Activate);

    let request: ActivateFirmwareRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::ActivateFirmware as u8)
        .unwrap();
    assert_ne!(request.self_contained_activation_req, 0x00);

    let response = ActivateFirmwareResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        5,
    );

    setup.send_response(&setup.fd_sock, &response);

    // Don't respond for 2 seconds
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Expect a GetStatusRequest
    let request: GetStatusRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::GetStatus as u8)
        .unwrap();

    // Send a GetStatusResponse with a progress of 80%
    let response = GetStatusResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        FirmwareDeviceState::Activate,
        FirmwareDeviceState::Apply,
        AuxState::OperationInProgress,
        AuxStateStatus::AuxStateInProgressOrSuccess,
        ProgressPercent::new(80).unwrap(),
        ReasonCode::ActivateFw,
        UpdateOptionResp::NoForceUpdate,
    );

    setup.send_response(&setup.fd_sock, &response);

    // Check that the state machine is still in the Activate state
    setup.wait_for_state_transition(update_sm::States::Activate);

    // Expect another GetStatusRequest
    let request: GetStatusRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::GetStatus as u8)
        .unwrap();

    // Send a GetStatusResponse with a progress of 100%
    let response = GetStatusResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        FirmwareDeviceState::Idle,
        FirmwareDeviceState::Activate,
        AuxState::OperationSuccessful,
        AuxStateStatus::AuxStateInProgressOrSuccess,
        ProgressPercent::new(100).unwrap(),
        ReasonCode::ActivateFw,
        UpdateOptionResp::NoForceUpdate,
    );

    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::Done);

    setup.daemon.stop();
}

#[test]
fn test_two_components_no_self_activation() {
    let activation_option: u16 = 0x0000;
    let pldm_fw_pkg = FirmwareManifest {
        package_header_information: PackageHeaderInformation {
            ..Default::default()
        },
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            ..Default::default()
        }],
        downstream_device_id_records: None,
        component_image_information: vec![
            ComponentImageInformation {
                identifier: 0x0002,
                options: 0x0000,
                requested_activation_method: activation_option,
                ..Default::default()
            },
            ComponentImageInformation {
                identifier: 0x0003,
                options: 0x0000,
                requested_activation_method: activation_option,
                ..Default::default()
            },
        ],
    };

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassed {},
        fd_tid: 0x01,
    });

    setup.wait_for_state_transition(update_sm::States::Verify);

    let mut instance_id = 0u8;
    let request = VerifyCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        VerifyResult::VerifySuccess,
    );
    setup.send_response(&setup.fd_sock, &request);

    let _: VerifyCompleteResponse = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::VerifyComplete as u8)
        .unwrap();

    setup.wait_for_state_transition(update_sm::States::Apply);

    instance_id += 1;
    let request = ApplyCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        ApplyResult::ApplySuccess,
        ComponentActivationMethods(0),
    );
    setup.send_response(&setup.fd_sock, &request);

    let _: ApplyCompleteResponse = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::ApplyComplete as u8)
        .unwrap();

    // UA should send UpdateComponent for the next component
    let request: UpdateComponentRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::UpdateComponent as u8)
        .unwrap();
    let request_comp_identifier = request.fixed.comp_identifier;
    assert_eq!(request_comp_identifier, 0x0003);

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
    // Download starts here, and will go straight to Verify since we bypassed the download
    setup.wait_for_state_transition(update_sm::States::Verify);
    instance_id += request.fixed.hdr.instance_id() + 1;
    let request = VerifyCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        VerifyResult::VerifySuccess,
    );
    setup.send_response(&setup.fd_sock, &request);
    let _: VerifyCompleteResponse = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::VerifyComplete as u8)
        .unwrap();
    setup.wait_for_state_transition(update_sm::States::Apply);
    instance_id += 1;
    let request = ApplyCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        ApplyResult::ApplySuccess,
        ComponentActivationMethods(0),
    );
    setup.send_response(&setup.fd_sock, &request);
    let _: ApplyCompleteResponse = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::ApplyComplete as u8)
        .unwrap();
    // Since all components are applied, SM should now be in the Activate state
    let request: ActivateFirmwareRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::ActivateFirmware as u8)
        .unwrap();

    assert_eq!(request.self_contained_activation_req, 0x00);
    let response = ActivateFirmwareResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        0,
    );
    setup.send_response(&setup.fd_sock, &response);
    setup.wait_for_state_transition(update_sm::States::Done);
    setup.daemon.stop();
}

#[test]
fn test_two_components_one_activate() {
    let activation_option: u16 = SELF_ACTIVATION_FIELD_MASK << SELF_ACTIVATION_FIELD_BIT;
    let pldm_fw_pkg = FirmwareManifest {
        package_header_information: PackageHeaderInformation {
            ..Default::default()
        },
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            ..Default::default()
        }],
        downstream_device_id_records: None,
        component_image_information: vec![
            ComponentImageInformation {
                identifier: 0x0002,
                options: 0x0000,
                requested_activation_method: activation_option,
                ..Default::default()
            },
            ComponentImageInformation {
                identifier: 0x0003,
                options: 0x0000,
                requested_activation_method: 0x0000,
                ..Default::default()
            },
        ],
    };

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassed {},
        fd_tid: 0x01,
    });

    setup.wait_for_state_transition(update_sm::States::Verify);

    let mut instance_id = 0u8;
    let request = VerifyCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        VerifyResult::VerifySuccess,
    );
    setup.send_response(&setup.fd_sock, &request);

    let _: VerifyCompleteResponse = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::VerifyComplete as u8)
        .unwrap();

    setup.wait_for_state_transition(update_sm::States::Apply);

    instance_id += 1;
    let request = ApplyCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        ApplyResult::ApplySuccess,
        ComponentActivationMethods(0),
    );
    setup.send_response(&setup.fd_sock, &request);

    let _: ApplyCompleteResponse = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::ApplyComplete as u8)
        .unwrap();

    // UA should send UpdateComponent for the next component
    let request: UpdateComponentRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::UpdateComponent as u8)
        .unwrap();
    let request_comp_identifier = request.fixed.comp_identifier;
    assert_eq!(request_comp_identifier, 0x0003);

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
    // Download starts here, and will go straight to Verify since we bypassed the download
    setup.wait_for_state_transition(update_sm::States::Verify);
    instance_id += request.fixed.hdr.instance_id() + 1;
    let request = VerifyCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        VerifyResult::VerifySuccess,
    );
    setup.send_response(&setup.fd_sock, &request);
    let _: VerifyCompleteResponse = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::VerifyComplete as u8)
        .unwrap();
    setup.wait_for_state_transition(update_sm::States::Apply);
    instance_id += 1;
    let request = ApplyCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        ApplyResult::ApplySuccess,
        ComponentActivationMethods(0),
    );
    setup.send_response(&setup.fd_sock, &request);
    let _: ApplyCompleteResponse = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::ApplyComplete as u8)
        .unwrap();
    // Since all components are applied, SM should now be in the Activate state
    let request: ActivateFirmwareRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::ActivateFirmware as u8)
        .unwrap();
    assert_ne!(request.self_contained_activation_req, 0x00);

    let response = ActivateFirmwareResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        5,
    );

    setup.send_response(&setup.fd_sock, &response);

    // Don't respond for 2 seconds
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Expect a GetStatusRequest
    let request: GetStatusRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::GetStatus as u8)
        .unwrap();

    // Send a GetStatusResponse with a progress of 80%
    let response = GetStatusResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        FirmwareDeviceState::Activate,
        FirmwareDeviceState::Apply,
        AuxState::OperationInProgress,
        AuxStateStatus::AuxStateInProgressOrSuccess,
        ProgressPercent::new(80).unwrap(),
        ReasonCode::ActivateFw,
        UpdateOptionResp::NoForceUpdate,
    );

    setup.send_response(&setup.fd_sock, &response);

    // Check that the state machine is still in the Activate state
    setup.wait_for_state_transition(update_sm::States::Activate);

    // Expect another GetStatusRequest
    let request: GetStatusRequest = setup
        .receive_request(&setup.fd_sock, FwUpdateCmd::GetStatus as u8)
        .unwrap();

    // Send a GetStatusResponse with a progress of 100%
    let response = GetStatusResponse::new(
        request.hdr.instance_id(),
        PldmBaseCompletionCode::Success as u8,
        FirmwareDeviceState::Idle,
        FirmwareDeviceState::Activate,
        AuxState::OperationSuccessful,
        AuxStateStatus::AuxStateInProgressOrSuccess,
        ProgressPercent::new(100).unwrap(),
        ReasonCode::ActivateFw,
        UpdateOptionResp::NoForceUpdate,
    );

    setup.send_response(&setup.fd_sock, &response);

    setup.wait_for_state_transition(update_sm::States::Done);

    setup.daemon.stop();
}

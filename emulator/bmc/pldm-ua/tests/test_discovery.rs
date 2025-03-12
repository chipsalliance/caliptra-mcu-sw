// Licensed under the Apache-2.0 license

#[cfg(test)]
mod common;
use pldm_common::protocol::base::{PldmControlCmd, PldmSupportedType, TransferRespFlag};
use pldm_common::protocol::firmware_update::FwUpdateCmd;
use pldm_common::protocol::version::{PLDM_BASE_PROTOCOL_VERSION, PLDM_FW_UPDATE_PROTOCOL_VERSION};
use pldm_ua::events::PldmEvents;
use pldm_ua::{discovery_sm, update_sm};

use pldm_common::message::control::*;
use pldm_fw_pkg::FirmwareManifest;
use pldm_ua::daemon::Options;
use pldm_ua::transport::PldmSocket;

const COMPLETION_CODE_SUCCESSFUL: u8 = 0x00;

/* Override the Firmware Update State Machine.
 * When discovery is finished, verify that the Discovery State machine will kick-off the Firmware Update State machine.
 * This can be verified by checking if the on_start_update() of the Firmware Update SM is called.
 * To do this, we need to override the on_start_update() and on_stop_update() methods of the Firmware Update SM.
 * The on_start_update() method will set a flag to true to indicate that the Firmware Update SM has started.
 * When the Daemon is stopped the on_stop_update() method will be called and verify the flag is true.
 */
struct UpdateSmStopAfterRequest {
    is_fw_update_started: bool,
}
impl update_sm::StateMachineActions for UpdateSmStopAfterRequest {
    fn on_start_update(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        ctx.event_queue
            .send(PldmEvents::Update(update_sm::Events::StopUpdate))
            .map_err(|_| ())?;
        self.is_fw_update_started = true;
        Ok(())
    }
    fn on_stop_update(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        assert!(self.is_fw_update_started);
        ctx.event_queue.send(PldmEvents::Stop).map_err(|_| ())?;
        Ok(())
    }
}

#[test]
fn test_discovery() {
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(FirmwareManifest::default()),
        discovery_sm_actions: discovery_sm::DefaultActions {},
        update_sm_actions: UpdateSmStopAfterRequest {
            is_fw_update_started: false,
        },
        fd_tid: DEVICE_TID,
    });

    // TID to be assigned to the device
    const DEVICE_TID: u8 = 0x01;

    let request: SetTidRequest = setup
        .receive_request(&setup.fd_sock, PldmControlCmd::SetTid as u8)
        .unwrap();
    assert_eq!(request.tid, DEVICE_TID);

    // Send SetTid response
    setup.send_response(
        &setup.fd_sock,
        &SetTidResponse::new(request.hdr.instance_id(), COMPLETION_CODE_SUCCESSFUL),
    );

    // Receive GetTid request
    let request: GetTidRequest = setup
        .receive_request(&setup.fd_sock, PldmControlCmd::GetTid as u8)
        .unwrap();

    // Send GetTid response
    setup.send_response(
        &setup.fd_sock,
        &GetTidResponse::new(
            request.hdr.instance_id(),
            DEVICE_TID,
            COMPLETION_CODE_SUCCESSFUL,
        ),
    );

    // Receive GetPldmTypes
    let request: GetPldmTypeRequest = setup
        .receive_request(&setup.fd_sock, PldmControlCmd::GetPldmTypes as u8)
        .unwrap();

    // Send GetPldmTypes response
    setup.send_response(
        &setup.fd_sock,
        &GetPldmTypeResponse::new(
            request.hdr.instance_id(),
            COMPLETION_CODE_SUCCESSFUL,
            &[
                PldmSupportedType::Base as u8,
                PldmSupportedType::FwUpdate as u8,
            ],
        ),
    );

    // Receive GetPldmVersion for Type 0
    let request: GetPldmVersionRequest = setup
        .receive_request(&setup.fd_sock, PldmControlCmd::GetPldmVersion as u8)
        .unwrap();
    assert_eq!(request.pldm_type, PldmSupportedType::Base as u8);

    // Send GetPldmVersion response
    setup.send_response(
        &setup.fd_sock,
        &GetPldmVersionResponse::new(
            request.hdr.instance_id(),
            COMPLETION_CODE_SUCCESSFUL,
            request.data_transfer_handle,
            TransferRespFlag::StartAndEnd,
            PLDM_BASE_PROTOCOL_VERSION,
        )
        .unwrap(),
    );

    // Receive GetPldmCommands for Type 0
    let request: GetPldmCommandsRequest = setup
        .receive_request(&setup.fd_sock, PldmControlCmd::GetPldmCommands as u8)
        .unwrap();
    assert_eq!(request.pldm_type, PldmSupportedType::Base as u8);

    // Send GetPldmCommands response
    setup.send_response(
        &setup.fd_sock,
        &GetPldmCommandsResponse::new(
            request.hdr.instance_id(),
            COMPLETION_CODE_SUCCESSFUL,
            &[
                PldmControlCmd::GetTid as u8,
                PldmControlCmd::SetTid as u8,
                PldmControlCmd::GetPldmTypes as u8,
                PldmControlCmd::GetPldmVersion as u8,
                PldmControlCmd::GetPldmCommands as u8,
            ],
        ),
    );

    // Receive GetPldmVersion for Type 5
    let request: GetPldmVersionRequest = setup
        .receive_request(&setup.fd_sock, PldmControlCmd::GetPldmVersion as u8)
        .unwrap();
    assert_eq!(request.pldm_type, PldmSupportedType::FwUpdate as u8);

    // Send GetPldmVersion response
    setup.send_response(
        &setup.fd_sock,
        &GetPldmVersionResponse::new(
            request.hdr.instance_id(),
            COMPLETION_CODE_SUCCESSFUL,
            request.data_transfer_handle,
            TransferRespFlag::StartAndEnd,
            PLDM_FW_UPDATE_PROTOCOL_VERSION,
        )
        .unwrap(),
    );

    // Receive GetPldmCommands for Type 5
    let request: GetPldmCommandsRequest = setup
        .receive_request(&setup.fd_sock, PldmControlCmd::GetPldmCommands as u8)
        .unwrap();
    assert_eq!(request.pldm_type, PldmSupportedType::FwUpdate as u8);

    // Send GetPldmCommands response
    setup.send_response(
        &setup.fd_sock,
        &GetPldmCommandsResponse::new(
            request.hdr.instance_id(),
            COMPLETION_CODE_SUCCESSFUL,
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

    setup.daemon.stop();
}

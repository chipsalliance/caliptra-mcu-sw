// Licensed under the Apache-2.0 license

#[cfg(test)]
mod mock_transport;
use log::{error, LevelFilter};
use mock_transport::{MockPldmSocket, MockTransport};
use pldm_common::protocol::base::{
    PldmControlCmd, PldmMsgHeader, PldmSupportedType, TransferRespFlag,
};
use pldm_common::protocol::firmware_update::FwUpdateCmd;
use pldm_common::protocol::version::{PLDM_BASE_PROTOCOL_VERSION, PLDM_FW_UPDATE_PROTOCOL_VERSION};
use pldm_ua::discovery_sm;
use simple_logger::SimpleLogger;

use pldm_common::codec::PldmCodec;
use pldm_common::message::control::*;
use pldm_ua::daemon::{Options, PldmDaemon};
use pldm_ua::transport::{PldmSocket, PldmTransport};

const COMPLETION_CODE_SUCCESSFUL: u8 = 0x00;

fn send_response<P: PldmCodec>(socket: &MockPldmSocket, response: &P) {
    let mut buffer = [0u8; 512];
    let sz = response.encode(&mut buffer).unwrap();
    socket.send(&buffer[..sz]).unwrap();
}

fn receive_request<P: PldmCodec>(
    socket: &MockPldmSocket,
    cmd_code: PldmControlCmd,
) -> Result<P, ()> {
    let request = socket.receive(None).unwrap();

    let header = PldmMsgHeader::decode(&request.payload.data[..request.payload.len])
        .map_err(|_| (error!("Error decoding packet!")))?;
    if !header.is_hdr_ver_valid() {
        error!("Invalid header version!");
        return Err(());
    }
    if header.cmd_code() != cmd_code as u8 {
        error!("Invalid command code!");
        return Err(());
    }

    P::decode(&request.payload.data[..request.payload.len])
        .map_err(|_| (error!("Error decoding packet!")))
}

#[test]
fn test_discovery() {
    // Initialize log level to info
    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .init()
        .unwrap();

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
    let mut daemon = PldmDaemon::run(
        ua_sock,
        Options {
            discovery_sm_actions: discovery_sm::DefaultActions {},
            fd_tid: DEVICE_TID,
        },
    );

    // TID to be assigned to the device
    const DEVICE_TID: u8 = 0x01;

    let request: SetTidRequest = receive_request(&fd_sock, PldmControlCmd::SetTid).unwrap();
    assert_eq!(request.tid, DEVICE_TID);

    // Send SetTid response
    send_response(
        &fd_sock,
        &SetTidResponse::new(request.hdr.instance_id(), COMPLETION_CODE_SUCCESSFUL),
    );

    // Receive GetTid request
    let request: GetTidRequest = receive_request(&fd_sock, PldmControlCmd::GetTid).unwrap();

    // Send GetTid response
    send_response(
        &fd_sock,
        &GetTidResponse::new(
            request.hdr.instance_id(),
            DEVICE_TID,
            COMPLETION_CODE_SUCCESSFUL,
        ),
    );

    // Receive GetPldmTypes
    let request: GetPldmTypeRequest =
        receive_request(&fd_sock, PldmControlCmd::GetPldmTypes).unwrap();

    // Send GetPldmTypes response
    send_response(
        &fd_sock,
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
    let request: GetPldmVersionRequest =
        receive_request(&fd_sock, PldmControlCmd::GetPldmVersion).unwrap();
    assert_eq!(request.pldm_type, PldmSupportedType::Base as u8);

    // Send GetPldmVersion response
    send_response(
        &fd_sock,
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
    let request: GetPldmCommandsRequest =
        receive_request(&fd_sock, PldmControlCmd::GetPldmCommands).unwrap();
    assert_eq!(request.pldm_type, PldmSupportedType::Base as u8);

    // Send GetPldmCommands response
    send_response(
        &fd_sock,
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
    let request: GetPldmVersionRequest =
        receive_request(&fd_sock, PldmControlCmd::GetPldmVersion).unwrap();
    assert_eq!(request.pldm_type, PldmSupportedType::FwUpdate as u8);

    // Send GetPldmVersion response
    send_response(
        &fd_sock,
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
    let request: GetPldmCommandsRequest =
        receive_request(&fd_sock, PldmControlCmd::GetPldmCommands).unwrap();
    assert_eq!(request.pldm_type, PldmSupportedType::FwUpdate as u8);

    // Send GetPldmCommands response
    send_response(
        &fd_sock,
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

    daemon.stop();
}

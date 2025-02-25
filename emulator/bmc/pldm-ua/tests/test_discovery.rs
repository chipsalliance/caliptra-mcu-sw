#[cfg(test)]
mod mock_transport;
use mock_transport::{MockPldmSocket, MockTransport};
use pldm_common::protocol::base::{PldmControlCmd, PldmMsgHeader, PldmSupportedType, TransferRespFlag};
use pldm_common::protocol::firmware_update::FwUpdateCmd;
use pldm_common::protocol::version::{PLDM_BASE_PROTOCOL_VERSION, PLDM_FW_UPDATE_PROTOCOL_VERSION};
use simple_logger::SimpleLogger;
use log::error;


use pldm_common::codec::PldmCodec;
use pldm_common::message::control::*;
use pldm_ua::daemon::{Daemon,Options};
use pldm_ua::transport::{PldmSocket, PldmTransport};

const COMPLETION_CODE_SUCCESSFUL: u8 = 0x00;

fn send_response<P: PldmCodec>(socket: &MockPldmSocket, response: &P) {
    let mut buffer = [0u8; 512];
    let sz = response.encode(&mut buffer).unwrap();
    socket.send(&buffer[..sz]).unwrap();
}

fn receive_request<P: PldmCodec>(socket: &MockPldmSocket, cmd_code : PldmControlCmd) -> Result<P,()> {
    let request = socket.receive(None).unwrap();


    let header = PldmMsgHeader::decode(&request.payload.data[..request.payload.len])
        .map_err(|_| (error!("Error decoding packet!")))?;
    if !header.is_hdr_ver_valid() {
        error!("Invalid header version!");
        return Err(());
    }
    if header.cmd_code() != cmd_code as u8{
        error!("Invalid command code!");
        return Err(());
    }

    P::decode(&request.payload.data[..request.payload.len])
        .map_err(|_| (error!("Error decoding packet!")))
    
}

#[test]
fn test_discovery() {
    SimpleLogger::new().init().unwrap();

    let transport = MockTransport::new();

    let ua_sid = pldm_ua::transport::EndpointId(0x01);
    let fd_sid = pldm_ua::transport::EndpointId(0x02);
    let ua_sock = transport.create_socket(ua_sid, fd_sid).unwrap();
    let fd_sock = transport.create_socket(fd_sid, ua_sid).unwrap();
    let daemon = Daemon::run(ua_sock, Options::default());
    
    const DEVICE_TID: u8 = 0x01;

    // Receive GetTid request
    let request : GetTidRequest = receive_request(&fd_sock, PldmControlCmd::GetTid).unwrap();

    // Send GetTid response
    send_response(&fd_sock, &GetTidResponse::new(request.hdr.instance_id(), DEVICE_TID, COMPLETION_CODE_SUCCESSFUL));

    // Receive GetPldmTypes
    let request : GetPldmTypeRequest = receive_request(&fd_sock,PldmControlCmd::GetPldmTypes).unwrap();

    // Send GetPldmTypes response
    send_response(&fd_sock, &GetPldmTypeResponse::new(
        request.hdr.instance_id(), 
        COMPLETION_CODE_SUCCESSFUL,
        &[PldmSupportedType::Base as u8, PldmSupportedType::FwUpdate as u8]
    ));

    // Receive GetPldmVersion for Type 0
    let request : GetPldmVersionRequest = receive_request(&fd_sock,PldmControlCmd::GetPldmVersion).unwrap();
    assert_eq!(request.pldm_type, PldmSupportedType::Base as u8);

    // Send GetPldmVersion response
    send_response(&fd_sock, &GetPldmVersionResponse::new(
        request.hdr.instance_id(), 
        COMPLETION_CODE_SUCCESSFUL,
        request.data_transfer_handle,
        TransferRespFlag::StartAndEnd,
        PLDM_BASE_PROTOCOL_VERSION
    ).unwrap());

    // Receive GetPldmCommands for Type 0
    let request : GetPldmCommandsRequest = receive_request(&fd_sock,PldmControlCmd::GetPldmCommands).unwrap();
    assert_eq!(request.pldm_type, PldmSupportedType::Base as u8);

    // Send GetPldmCommands response
    send_response(&fd_sock, &GetPldmCommandsResponse::new(
        request.hdr.instance_id(), 
        COMPLETION_CODE_SUCCESSFUL,
        &[PldmControlCmd::GetTid as u8, 
        PldmControlCmd::SetTid as u8,
        PldmControlCmd::GetPldmTypes as u8, 
        PldmControlCmd::GetPldmVersion as u8, 
        PldmControlCmd::GetPldmCommands as u8]
    ));

    // Receive GetPldmVersion for Type 5
    let request : GetPldmVersionRequest = receive_request(&fd_sock,PldmControlCmd::GetPldmVersion).unwrap();
    assert_eq!(request.pldm_type, PldmSupportedType::FwUpdate as u8);

    // Send GetPldmVersion response
    send_response(&fd_sock, &GetPldmVersionResponse::new(
        request.hdr.instance_id(), 
        COMPLETION_CODE_SUCCESSFUL,
        request.data_transfer_handle,
        TransferRespFlag::StartAndEnd,
        PLDM_FW_UPDATE_PROTOCOL_VERSION
    ).unwrap());

    // Receive GetPldmCommands for Type 5
    let request : GetPldmCommandsRequest = receive_request(&fd_sock,PldmControlCmd::GetPldmCommands).unwrap();
    assert_eq!(request.pldm_type, PldmSupportedType::FwUpdate as u8);

    // Send GetPldmCommands response
    send_response(&fd_sock, &GetPldmCommandsResponse::new(
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
        ]
    ));


    // Wait for daemon to finish
    daemon.join().unwrap();


}

#[test]
fn test2() {
    let mut buffer = [0u8; 512];
    let response = GetTidResponse::new(5, 6, COMPLETION_CODE_SUCCESSFUL);
    let sz = response.encode(&mut buffer).unwrap();

    println!("Response: {:02x?}", &buffer[..sz]);
    println!("Rq: {:?}", response.hdr.rq());
    println!("Datagram: {:?}", response.hdr.datagram());
}
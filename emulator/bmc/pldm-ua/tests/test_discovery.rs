#[cfg(test)]
mod mock_transport;
use futures::future;
use mock_transport::{MockPldmSocket, MockTransport};
use simple_logger::SimpleLogger;
use log::logger;


use pldm_common::codec::PldmCodec;
use pldm_common::message::control::*;
use pldm_ua::daemon::{Daemon,Options};
use pldm_ua::future_executor::FutureExecutor;
use pldm_ua::transport::{FilterType, PldmSocket, PldmTransport};
use pldm_ua::update_sm::DefaultActions;

const COMPLETION_CODE_SUCCESSFUL: u8 = 0x00;

#[test]
fn test_discovery() {
    SimpleLogger::new().init().unwrap();
    let transport = MockTransport::new();

    let ua_sid = pldm_ua::transport::EndpointId(0x01);
    let fd_sid = pldm_ua::transport::EndpointId(0x02);
    let ua_sock = transport.create_socket(ua_sid, fd_sid).unwrap();
    let fd_sock = transport.create_socket(fd_sid, ua_sid).unwrap();
    let x = Daemon::run(ua_sock, Options::default());
    let y = FutureExecutor::spawn(x);

    let mut buffer = [0u8; 512];
    const DEVICE_TID: u8 = 0x01;

    let request = fd_sock.receive(None, FilterType::Request).unwrap();
    let request = GetTidRequest::decode(&request.payload.data[..request.payload.len]).unwrap();
    logger().flush();
    let response = GetTidResponse::new(request.hdr.instance_id(), DEVICE_TID, COMPLETION_CODE_SUCCESSFUL);
    let sz = response.encode(&mut buffer).unwrap();
    fd_sock.send(&buffer[..sz]).unwrap();

    let request = fd_sock.receive(None, FilterType::Request).unwrap();

    fd_sock.disconnect();

    let _z = y.get_output().unwrap();
}

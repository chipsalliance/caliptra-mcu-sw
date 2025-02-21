#[cfg(test)]
mod mock_transport;
use futures::future;
use mock_transport::{MockPldmSocket, MockTransport};

use pldm_ua::daemon::Daemon;
use pldm_ua::future_executor::FutureExecutor;
use pldm_ua::transport::{PldmSocket, PldmTransport};
use pldm_ua::update_sm::DefaultActions;

// create a unit test for update_agent

#[test]
fn test_daemon() {
    let transport = MockTransport::new();

    let ua_sid = pldm_ua::transport::SockId(0x01);
    let fd_sid = pldm_ua::transport::SockId(0x02);
    let ua_sock = transport.create_socket(ua_sid, fd_sid).unwrap();
    let fd_sock = transport.create_socket(fd_sid, ua_sid).unwrap();

    let x = Daemon::run(ua_sock);

    let y = FutureExecutor::spawn(x);

    fd_sock.disconnect();

    let _z = y.get_output().unwrap();
}

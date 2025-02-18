#[cfg(test)]
mod mock_transport;
use futures::future;
use mock_transport::{MockTransport,MockPldmSocket};


use pldm::update_sm::DefaultActions;
use pldm::transport::{PldmTransport,PldmSocket};
use pldm::daemon::Daemon;
use pldm::future_executor::FutureExecutor;

// create a unit test for update_agent

#[test]
fn test_daemon() {
    let transport = MockTransport::new();

    let ua_sid = pldm::transport::SockId(0x01);
    let fd_sid = pldm::transport::SockId(0x02);
    let ua_sock = transport.create_socket(ua_sid).unwrap();
    let fd_sock = transport.create_socket(fd_sid).unwrap();

    let x = Daemon::run(ua_sock);

    let y = FutureExecutor::spawn(x);

    fd_sock.disconnect();

    let _z = y.get_output().unwrap();

    
    
}

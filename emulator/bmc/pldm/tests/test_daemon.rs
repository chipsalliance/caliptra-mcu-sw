#[cfg(test)]
mod mock_transport;
use mock_transport::{MockTransport,MockPldmSocket};


use pldm::update_sm::DefaultActions;
use pldm::transport::{PldmTransport,PldmSocket};
use pldm::daemon::Daemon;
mod future_thread;
use future_thread::FutureThread;

// create a unit test for update_agent

#[test]
fn test_daemon() {
    let transport = MockTransport::new();

    let ua_sid = pldm::transport::SockId(0x01);

    let ua_sock = transport.create_socket(ua_sid).unwrap();

    let _x = Daemon::run(ua_sock);

    
    
}

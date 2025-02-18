#[cfg(test)]
mod mock_transport;
use mock_transport::MockTransport;

use pldm::update_agent::UpdateAgent;
use pldm::update_sm::DefaultActions;
use pldm::transport::{PldmTransport,PldmSocket};
use std::sync::Arc;

// create a unit test for update_agent

#[test]
fn test_update_agent() {
    let transport = MockTransport::new();

    let ua_sid = pldm::transport::SockId(0x01);
    let fd_sid = pldm::transport::SockId(0x02);

    let ua_sock = transport.create_socket(ua_sid).unwrap();
    let fd_sock = transport.create_socket(fd_sid).unwrap();

    // create an std thread that runs the update agent
    let ua_thread = std::thread::spawn(move || {
        let mut update_agent = UpdateAgent::new(DefaultActions {}, ua_sock);
        update_agent.start_update().unwrap();
    });
    

    fd_sock.send(ua_sid,&[1,2,3]).unwrap();

    println!("Received in FD: {}", fd_sock.receive(None).unwrap());

    fd_sock.send(ua_sid, &[4,5,6,7,8]).unwrap();

    println!("Received in FD: {}", fd_sock.receive(None).unwrap());    


    fd_sock.disconnect();
    
    let _x = ua_thread.join();
    
}

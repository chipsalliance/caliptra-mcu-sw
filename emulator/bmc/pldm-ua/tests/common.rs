// Licensed under the Apache-2.0 license
#![allow(clippy::result_unit_err)]
use core::time::Duration;
use log::{error, LevelFilter};
use pldm_common::message::firmware_update::query_devid::{
    QueryDeviceIdentifiersRequest, QueryDeviceIdentifiersResponse,
};
use pldm_common::protocol::base::PldmMsgHeader;
use pldm_fw_pkg::FirmwareManifest;
use pldm_ua::events::PldmEvents;
use pldm_ua::transport::{
    EndpointId, Payload, PldmSocket, PldmTransport, PldmTransportError, RxPacket, TxPacket,
    MAX_PLDM_PAYLOAD_SIZE,
};
use simple_logger::SimpleLogger;
use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use pldm_common::codec::PldmCodec;
use pldm_ua::daemon::{Options, PldmDaemon};
use pldm_ua::{discovery_sm, update_sm};

pub struct MockPldmSocket {
    source: EndpointId,
    dest: EndpointId,
    senders: Arc<Mutex<HashMap<EndpointId, Sender<TxPacket>>>>,
    receiver: Arc<Mutex<Option<Receiver<TxPacket>>>>,
}

impl PldmSocket for MockPldmSocket {
    fn send(&self, payload: &[u8]) -> Result<(), PldmTransportError> {
        let mut tx_payload = [0u8; MAX_PLDM_PAYLOAD_SIZE];
        tx_payload[..payload.len()].copy_from_slice(payload);

        let pkt = TxPacket {
            src: self.source,
            dest: self.dest,
            payload: Payload {
                data: tx_payload,
                len: payload.len(),
            },
        };
        if let Some(tx) = self.senders.lock().unwrap().get(&pkt.dest) {
            let _ = tx.send(pkt.clone());
        }
        Ok(())
    }

    fn receive(&self, _timeout: Option<Duration>) -> Result<RxPacket, PldmTransportError> {
        if let Some(receiver) = self.receiver.lock().unwrap().as_ref() {
            if let Ok(pkt) = receiver.recv() {
                if pkt.payload.len == 0 {
                    Err(PldmTransportError::Underflow)
                } else {
                    let src = pkt.src;
                    let mut data = [0u8; MAX_PLDM_PAYLOAD_SIZE];
                    data[..pkt.payload.len].copy_from_slice(&pkt.payload.data[..pkt.payload.len]);
                    Ok(RxPacket {
                        src,
                        payload: Payload {
                            data,
                            len: pkt.payload.len,
                        },
                    })
                }
            } else {
                Err(PldmTransportError::Timeout)
            }
        } else {
            Err(PldmTransportError::NotInitialized)
        }
    }

    fn disconnect(&self) {
        // Send an empty packet to indicate disconnection
        // for all senders send a null packet
        for (id, sender) in self.senders.lock().unwrap().iter() {
            let pkt = TxPacket {
                src: self.source,
                dest: *id,
                payload: Payload {
                    data: [0; MAX_PLDM_PAYLOAD_SIZE],
                    len: 0,
                },
            };
            let _ = sender.send(pkt);
        }
    }

    fn connect(&self) -> Result<(), PldmTransportError> {
        Ok(())
    }

    fn clone(&self) -> Self {
        MockPldmSocket {
            source: self.source,
            dest: self.dest,
            senders: Arc::clone(&self.senders),
            receiver: Arc::clone(&self.receiver),
        }
    }
}

#[derive(Clone)]
pub struct MockTransport {
    senders: Arc<Mutex<HashMap<EndpointId, Sender<TxPacket>>>>,
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MockTransport {
    pub fn new() -> Self {
        Self {
            senders: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl PldmTransport<MockPldmSocket> for MockTransport {
    fn create_socket(
        &self,
        source: EndpointId,
        dest: EndpointId,
    ) -> Result<MockPldmSocket, PldmTransportError> {
        let (tx, rx) = mpsc::channel();
        self.senders.lock().unwrap().insert(source, tx);
        Ok(MockPldmSocket {
            source,
            dest,
            senders: Arc::clone(&self.senders),
            receiver: Arc::new(Mutex::new(Some(rx))),
        })
    }
}

#[cfg(test)]
#[test]
fn test_send_receive() {
    let transport = MockTransport::new();

    let sid1 = EndpointId(1);
    let sid2 = EndpointId(2);

    let sock1 = Arc::new(transport.create_socket(sid1, sid2).unwrap());
    let sock2 = Arc::new(transport.create_socket(sid2, sid1).unwrap());

    let sock1_clone = Arc::clone(&sock1);
    let h1 = thread::spawn(move || {
        if let Ok(packet) = sock1_clone.receive(None) {
            println!("EndpointId 1 received: {}", packet);
        }
    });

    let sock2_clone = Arc::clone(&sock2);
    let h2 = thread::spawn(move || {
        if let Ok(packet) = sock2_clone.receive(None) {
            println!("EndpointId 2 received: {}", packet);
        }
    });

    sock1.send(&[1, 2, 3]).unwrap();
    sock2.send(&[4, 5, 6]).unwrap();

    // wait for h1 and h2 to finish
    h1.join().unwrap();
    h2.join().unwrap();
}

// create a unit test where there are 2 tasks using the same socket to send a packet
#[cfg(test)]
#[test]
fn test_send_receive_same_socket() {
    let transport = MockTransport::new();

    let sid1 = EndpointId(1);
    let sid2 = EndpointId(2);

    let sock1 = Arc::new(transport.create_socket(sid1, sid2).unwrap());
    let sock2 = Arc::new(transport.create_socket(sid2, sid1).unwrap());

    let sock1_clone = Arc::clone(&sock1);
    let h1 = thread::spawn(move || {
        sock1_clone.send(&[7, 8, 9]).unwrap();
    });

    let sock2_clone = Arc::clone(&sock2);
    let h2 = thread::spawn(move || {
        for _ in 0..2 {
            if let Ok(packet) = sock2_clone.receive(None) {
                println!("EndpointId 2 received: {}", packet);
            }
        }
    });

    sock1.send(&[1, 2, 3]).unwrap();

    // wait for h1 and h2 to finish
    h1.join().unwrap();
    h2.join().unwrap();
}

pub struct TestSetup<
    D: discovery_sm::StateMachineActions + Send + 'static,
    U: update_sm::StateMachineActions + Send + 'static,
> {
    pub fd_sock: MockPldmSocket,
    pub daemon: PldmDaemon<MockPldmSocket, D, U>,
}

pub fn setup<
    D: discovery_sm::StateMachineActions + Send + 'static,
    U: update_sm::StateMachineActions + Send + 'static,
>(
    daemon_options: Options<D, U>,
) -> TestSetup<D, U> {
    // Initialize log level to info (only once)
    let _ = SimpleLogger::new().with_level(LevelFilter::Debug).init();

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
    pub fn wait_for_state_transition(&self, expected_state: update_sm::States) {
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

    pub fn send_response<P: PldmCodec>(&self, socket: &MockPldmSocket, response: &P) {
        let mut buffer = [0u8; 512];
        let sz = response.encode(&mut buffer).unwrap();
        socket.send(&buffer[..sz]).unwrap();
    }

    pub fn receive_request<P: PldmCodec>(
        &self,
        socket: &MockPldmSocket,
        cmd_code: u8,
    ) -> Result<P, ()> {
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
}

/* Override the Discovery SM. Skip the discovery process by starting firmware update immediately when discovery is kicked-off */
pub struct CustomDiscoverySm {}
impl discovery_sm::StateMachineActions for CustomDiscoverySm {
    fn on_start_discovery(
        &self,
        ctx: &mut pldm_ua::discovery_sm::InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        ctx.event_queue
            .send(PldmEvents::Update(update_sm::Events::StartUpdate))
            .map_err(|_| ())?;
        Ok(())
    }
    fn on_cancel_discovery(
        &self,
        _ctx: &mut discovery_sm::InnerContext<impl PldmSocket + Send + 'static>,
    ) -> Result<(), ()> {
        Ok(())
    }
}

#[test]
fn test_pldm_daemon_setup() {
    let setup = setup(Options {
        pldm_fw_pkg: Some(FirmwareManifest::default()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: update_sm::DefaultActions {},
        fd_tid: 0x02,
    });

    let _: QueryDeviceIdentifiersRequest = setup.receive_request(&setup.fd_sock, 1u8).unwrap();

    let response = QueryDeviceIdentifiersResponse {
        ..Default::default()
    };

    setup.wait_for_state_transition(update_sm::States::QueryDeviceIdentifiersSent);

    setup.send_response(&setup.fd_sock, &response);
}

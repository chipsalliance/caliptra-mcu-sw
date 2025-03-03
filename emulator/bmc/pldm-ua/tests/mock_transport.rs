// Licensed under the Apache-2.0 license

use core::time::Duration;
use pldm_ua::transport::{
    EndpointId, Payload, PldmSocket, PldmTransport, PldmTransportError, RxPacket, TxPacket,
    MAX_PLDM_PAYLOAD_SIZE,
};
use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

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

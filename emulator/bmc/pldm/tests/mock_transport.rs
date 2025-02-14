
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Sender, Receiver};
use std::thread;
use pldm::transport::{Payload, PldmSocket, PldmTransport, RxPacket, SockId, TxPacket, MAX_PLDM_PAYLOAD_SIZE};
use core::time::Duration;


pub struct MockPldmSocket {
    sid: SockId,
    senders: Arc<Mutex<HashMap<SockId, Sender<TxPacket>>>>,
    receiver: Arc<Mutex<Receiver<TxPacket>>>,
}


impl PldmSocket for MockPldmSocket {
    fn send(&self, dst: SockId, payload: &[u8]) -> Result<(), ()> {
        let mut tx_payload = [0u8; MAX_PLDM_PAYLOAD_SIZE];
        tx_payload[..payload.len()].copy_from_slice(payload);
        
        let pkt = TxPacket { 
            src: self.sid, 
            dest: dst, 
            payload: Payload {
                data: tx_payload,
                len: payload.len(),
            }
        };
        if let Some(tx) = self.senders.lock().unwrap().get(&pkt.dest) {
            let _ = tx.send(pkt.clone());
        }
        Ok(())
    }

    fn receive(&self, timeout: Option<Duration>) -> Result<RxPacket, ()> {
        let pkt = self.receiver.lock().unwrap().recv().map_err(|_| ())?;
        if pkt.payload.len == 0 {
            Err(())
        }
        else {
            let src = pkt.src;
            let mut data = [0u8; MAX_PLDM_PAYLOAD_SIZE];
            data[..pkt.payload.len].copy_from_slice(&pkt.payload.data[..pkt.payload.len]);
            Ok(
                RxPacket { src, payload: Payload { data, len: pkt.payload.len } }

            )
        }
    }

    fn disconnect(&self) {
        // Send an empty packet to indicate disconnection
        // for all senders send a null packet
        for (id, sender) in self.senders.lock().unwrap().iter() {
            let pkt = TxPacket { src: self.sid, dest: *id, payload: Payload { data: [0; MAX_PLDM_PAYLOAD_SIZE], len: 0 } };
            let _ = sender.send(pkt);
        }
    }

}

#[derive(Clone)]
pub struct MockTransport {
    senders: Arc<Mutex<HashMap<SockId, Sender<TxPacket>>>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self {
            senders: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl PldmTransport<MockPldmSocket> for MockTransport {
    fn create_socket(&self, sid: SockId) -> Result<MockPldmSocket, ()> {
        let (tx, rx) = mpsc::channel();
        self.senders.lock().unwrap().insert(sid, tx);
        Ok(MockPldmSocket { sid, senders: Arc::clone(&self.senders), receiver: Arc::new(Mutex::new(rx)) })
    }
}

#[cfg(test)]
#[test]
fn test_send_receive() {
    let transport = MockTransport::new();

    let sid1 = SockId(1);
    let sid2 = SockId(2);
    
    let sock1 = Arc::new(transport.create_socket(sid1).unwrap());
    let sock2 = Arc::new(transport.create_socket(sid2).unwrap());
    
    let sock1_clone = Arc::clone(&sock1);
    let h1 = thread::spawn(move || {
        if let Ok(packet) = sock1_clone.receive(None) {
            println!("SockId 1 received: {}", packet);
        }
    });
    
    let sock2_clone = Arc::clone(&sock2);
    let h2 = thread::spawn(move || {
        if let Ok(packet) = sock2_clone.receive(None) {
            println!("SockId 2 received: {}", packet);
        }
    });
    
    sock1.send(sid2, &[1,2,3]).unwrap();
    sock2.send(sid1, &[4,5,6]).unwrap();
    
    // wait for h1 and h2 to finish
    h1.join().unwrap();
    h2.join().unwrap();
}

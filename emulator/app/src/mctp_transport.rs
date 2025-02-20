
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Sender, Receiver};
use std::thread;
use pldm_common::protocol::base::PldmMsgType;
use pldm_ua::transport::{Payload, PldmSocket, PldmTransport, RxPacket, SockId, TxPacket, MAX_PLDM_PAYLOAD_SIZE};
use core::time::Duration;
use emulator_periph::DynamicI3cAddress;
use std::net::{SocketAddr, TcpStream};
use crate::tests::mctp_util::common::MctpUtil;
use pldm_common::message::control::GetTidRequest;
use pldm_common::codec::PldmCodec;

pub struct MctpPldmSocket {
    source: SockId,
    dest: SockId,
    target_addr : u8,
    stream : Arc<Mutex<TcpStream>>,
    msg_tag : u8,
    running : Arc<AtomicBool>


}

impl PldmSocket for MctpPldmSocket {
    fn send(&self, payload: &[u8]) -> Result<(), ()> {

        let mut mctp_util = MctpUtil::new();
        mctp_util.set_dest_eid(self.dest.0);
        mctp_util.set_src_eid(self.source.0);
        mctp_util.set_msg_tag(self.msg_tag);
        mctp_util.set_tag_owner(0x1);
        mctp_util.new_req(0x1);

        if payload[0] & 0x80 == 0x80 {
            mctp_util.send_request(self.msg_tag, payload, self.running.clone(), self.stream.lock().as_mut().unwrap(), self.target_addr);
        }
        else {
            mctp_util.send_response(payload, self.running.clone(), self.stream.lock().as_mut().unwrap(), self.target_addr);
        }

        Ok(())
    }

    fn receive(&self, timeout: Option<Duration>, filter: FilterType) -> Result<RxPacket, ()> {
        let mut mctp_util = MctpUtil::new();
        let raw_pkt :Vec<u8> = Vec::new();
        match filter {
            FilterType::Any | FilterType::Request => {
                raw_pkt = mctp_util.receive_request(self.running.clone(), self.stream.lock().as_mut().unwrap(), self.target_addr);
            }
            FilterType::Response => {
                raw_pkt = mctp_util.receive_response(self.running.clone(), self.stream.lock().as_mut().unwrap(), self.target_addrtarget_addr);
            }
        }
        if raw_pkt.len() == 0 {
            return Err(());
        }
        Ok(RxPacket {
            src: self.dest,
            payload: Payload {
                data: raw_pkt.try_into().unwrap(),
                len: raw_pkt.len()
            }
        })



    }
    fn connect(&self) -> Result<(), ()> 
    {
        // Send a packet to the target address and wait for a response
        // Prepare the MCTP Header
        let mut mctp_util = MctpUtil::new();
        mctp_util.set_dest_eid(self.dest.0);
        mctp_util.set_src_eid(self.source.0);
        mctp_util.set_msg_tag(self.msg_tag);
        mctp_util.set_tag_owner(0x1);
        mctp_util.new_req(0x1);

        // Create the PLDM message
        let instance_id = 1u8;
        let get_tid_request = GetTidRequest::new(instance_id, PldmMsgType::Request);
        let mut pldm_pkt_buffer = [0u8; 4096];
        let pldm_pkt_sz = get_tid_request.encode(&mut pldm_pkt_buffer).map_err(|_| ())?;

        // Combine the MCTP common header and the PLDM Message
        let mut mctp_payload: Vec<u8> = Vec::new();
        mctp_payload.extend_from_slice(&pldm_pkt_buffer[..pldm_pkt_sz]);

        let response = mctp_util.wait_for_responder(self.msg_tag, mctp_payload.as_mut_slice(), self.running.clone(), self.stream.lock().as_mut().unwrap(), self.target_addr);
        if response.is_none() {
            return Err(());
        }

        Ok(())
    }

    fn disconnect(&self) {
    }

    fn clone(&self) -> Self {
        MctpPldmSocket {
            source: self.source,
            dest: self.dest,
            target_addr : self.target_addr,
            stream : self.stream.clone(),
            msg_tag : self.msg_tag,
            running : self.running.clone()

         }
    }

}

#[derive(Clone)]
pub struct MctpTransport {
    port : u16,
    target_addr : DynamicI3cAddress,
}

impl MctpTransport {
    pub fn new(port: u16, target_addr: DynamicI3cAddress) -> Self {
        Self {
            port,
            target_addr
        }
    }
}

impl PldmTransport<MctpPldmSocket> for MctpTransport {
    fn create_socket(&self, source : SockId, dest : SockId) -> Result<MctpPldmSocket, ()> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let stream = Arc::new(Mutex::new(TcpStream::connect(addr).map_err(|_| ())?));
        let running = Arc::new(AtomicBool::new(true));

        Ok(MctpPldmSocket {
            source,
            dest,
            target_addr : self.target_addr.into(),
            stream,
            msg_tag : 0,
            running
        })




    }
}

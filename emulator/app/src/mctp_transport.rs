// Licensed under the Apache-2.0 license

// This module provides an abstraction over the MCTP (Management Component Transport Protocol) transport layer for PLDM (Platform Level Data Model).
// It implements the `PldmSocket` and `PldmTransport` traits, which define generic transport entities used by PLDM for communication.
// The `MctpPldmSocket` struct represents a socket for sending and receiving PLDM messages over MCTP.
// The `MctpTransport` struct is responsible for creating and managing `MctpPldmSocket` instances.

use crate::tests::mctp_util::common::MctpUtil;
use core::time::Duration;
use emulator_periph::DynamicI3cAddress;
use pldm_common::util::mctp_transport::{MctpCommonHeader, MCTP_PLDM_MSG_TYPE};
use pldm_ua::transport::{
    EndpointId, Payload, PldmSocket, PldmTransport, PldmTransportError, RxPacket,
    MAX_PLDM_PAYLOAD_SIZE,
};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

pub struct MctpPldmSocket {
    source: EndpointId,
    dest: EndpointId,
    target_addr: u8,
    stream: Arc<Mutex<TcpStream>>,
    msg_tag: u8,
    running: Arc<AtomicBool>,
    first_response: Arc<Mutex<Option<Vec<u8>>>>,
    wait_for_responder: Arc<Mutex<bool>>,
    mctp_util: Arc<Mutex<MctpUtil>>,
}

impl PldmSocket for MctpPldmSocket {
    fn send(&self, payload: &[u8]) -> Result<(), PldmTransportError> {
        let mctp_util = &mut *self.mctp_util.lock().unwrap();

        let mut mctp_common_headeer = MctpCommonHeader(0);
        mctp_common_headeer.set_ic(0);
        mctp_common_headeer.set_msg_type(MCTP_PLDM_MSG_TYPE);

        let mut mctp_payload: Vec<u8> = Vec::new();
        mctp_payload.push(mctp_common_headeer.0);
        mctp_payload.extend_from_slice(payload);

        if *self.wait_for_responder.lock().unwrap() {
            /* If this is the first time we are sending a request,
             * we need to make sure that the responder is ready
             * so we wait for a response for the first message
             */
            mctp_util.new_req(self.msg_tag);
            let response = mctp_util.wait_for_responder(
                self.msg_tag,
                mctp_payload.as_mut_slice(),
                self.running.clone(),
                self.stream.lock().as_mut().unwrap(),
                self.target_addr,
            );

            self.first_response
                .lock()
                .unwrap()
                .replace(response.unwrap());

            *self.wait_for_responder.lock().unwrap() = false;
        } else if payload[0] & 0x80 == 0x80 {
            mctp_util.send_request(
                self.msg_tag,
                mctp_payload.as_mut_slice(),
                self.running.clone(),
                self.stream.lock().as_mut().unwrap(),
                self.target_addr,
            );
        } else {
            mctp_util.send_response(
                mctp_payload.as_mut_slice(),
                self.running.clone(),
                self.stream.lock().as_mut().unwrap(),
                self.target_addr,
            );
        }

        Ok(())
    }

    fn receive(
        &self,
        _timeout: Option<Duration>
    ) -> Result<RxPacket, PldmTransportError> {
        let mut first_response = self.first_response.lock().unwrap();
        if let Some(response) = first_response.as_mut() {
            let mut data = [0u8; MAX_PLDM_PAYLOAD_SIZE];
            // Skip the first byte containing the MCTP common header
            // and only return the PLDM payload
            data[..response.len() - 1].copy_from_slice(&response[1..]);
            let ret = RxPacket {
                src: self.dest,
                payload: Payload {
                    data,
                    len: response.len() - 1,
                },
            };
            *first_response = None;
            return Ok(ret);
        }

        let mctp_util = &mut *self.mctp_util.lock().unwrap();
        let raw_pkt: Vec<u8> = mctp_util.receive(
            self.running.clone(),
            self.stream.lock().as_mut().unwrap(),
            self.target_addr,
        );
        let len = raw_pkt.len() - 1;
        if raw_pkt.is_empty() {
            return Err(PldmTransportError::Underflow);
        }
        let mut data = [0u8; MAX_PLDM_PAYLOAD_SIZE];
        // Skip the first byte containing the MCTP common header
        // and only return the PLDM payload
        data[..len].copy_from_slice(&raw_pkt[1..]);
        Ok(RxPacket {
            src: self.dest,
            payload: Payload { data, len },
        })
    }

    fn connect(&self) -> Result<(), PldmTransportError> {
        // Not supported
        Ok(())
    }

    fn disconnect(&self) {
        // Not supported
    }

    fn clone(&self) -> Self {
        MctpPldmSocket {
            source: self.source,
            dest: self.dest,
            target_addr: self.target_addr,
            stream: self.stream.clone(),
            msg_tag: self.msg_tag,
            running: self.running.clone(),
            first_response: self.first_response.clone(),
            wait_for_responder: self.wait_for_responder.clone(),
            mctp_util: self.mctp_util.clone(),
        }
    }
}

#[derive(Clone)]
pub struct MctpTransport {
    port: u16,
    target_addr: DynamicI3cAddress,
}

impl MctpTransport {
    pub fn new(port: u16, target_addr: DynamicI3cAddress) -> Self {
        Self { port, target_addr }
    }
}

impl PldmTransport<MctpPldmSocket> for MctpTransport {
    fn create_socket(
        &self,
        source: EndpointId,
        dest: EndpointId,
    ) -> Result<MctpPldmSocket, PldmTransportError> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let stream = Arc::new(Mutex::new(
            TcpStream::connect(addr).map_err(|_| PldmTransportError::Disconnected)?,
        ));
        let running = Arc::new(AtomicBool::new(true));
        let mctp_util = MctpUtil::new();
        let msg_tag = 0u8;
        Ok(MctpPldmSocket {
            source,
            dest,
            target_addr: self.target_addr.into(),
            stream,
            msg_tag,
            running,
            first_response: Arc::new(Mutex::new(None)),
            wait_for_responder: Arc::new(Mutex::new(true)),
            mctp_util: Arc::new(Mutex::new(mctp_util)),
        })
    }
}

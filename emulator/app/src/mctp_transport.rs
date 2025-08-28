// Licensed under the Apache-2.0 license

// This module provides an abstraction over the MCTP (Management Component Transport Protocol) transport layer for PLDM (Platform Level Data Model).
// It implements the `PldmSocket` and `PldmTransport` traits, which define generic transport entities used by PLDM for communication.
// The `MctpPldmSocket` struct represents a socket for sending and receiving PLDM messages over MCTP.
// The `MctpTransport` struct is responsible for creating and managing `MctpPldmSocket` instances.

use crate::i3c_socket::BufferedStream;
use crate::tests::mctp_util::common::MctpUtil;
use core::time::Duration;
use emulator_periph::DynamicI3cAddress;
use pldm_common::util::mctp_transport::{MctpCommonHeader, MCTP_PLDM_MSG_TYPE};
use pldm_ua::transport::{
    EndpointId, Payload, PldmSocket, PldmTransport, PldmTransportError, RxPacket,
    MAX_PLDM_PAYLOAD_SIZE,
};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Condvar, Mutex};

pub const MCTP_TAG_MASK: u8 = 0x07;

#[derive(Debug, PartialEq, Clone)]
enum MctpPldmSocketState {
    Idle,
    FirstResponse,
    DuplexReady,
}

pub struct MctpPldmSocket {
    source: EndpointId,
    dest: EndpointId,
    target_addr: u8,
    msg_tag: u8,
    context: Arc<(Mutex<MctpPldmSocketData>, Condvar)>,
    stream: BufferedStream,
    response_msg_tag: Arc<Mutex<u8>>,
}

struct MctpPldmSocketData {
    state: MctpPldmSocketState,
    first_response: Option<Vec<u8>>,
}

impl PldmSocket for MctpPldmSocket {
    fn send(&self, payload: &[u8]) -> Result<(), PldmTransportError> {
        let mut mctp_util = MctpUtil::new();
        mctp_util.set_pkt_payload_size(MAX_PLDM_PAYLOAD_SIZE);
        let mut mctp_common_header = MctpCommonHeader(0);
        mctp_common_header.set_ic(0);
        mctp_common_header.set_msg_type(MCTP_PLDM_MSG_TYPE);

        let mut mctp_payload: Vec<u8> = Vec::new();
        mctp_payload.push(mctp_common_header.0);
        mctp_payload.extend_from_slice(payload);

        let mut stream = self
            .stream
            .try_clone()
            .map_err(|_| PldmTransportError::Disconnected)?;
        let (context_lock, cvar) = &*self.context;
        let context = &mut *context_lock.lock().unwrap();
        if context.state == MctpPldmSocketState::Idle {
            /* If this is the first time we are sending a request,
             * we need to make sure that the responder is ready
             * so we wait for a response for the first message
             */
            mctp_util.new_req(self.msg_tag);
            let response = mctp_util.wait_for_responder(
                self.msg_tag,
                mctp_payload.as_mut_slice(),
                &mut stream,
                self.target_addr,
            );
            context.first_response.replace(response.unwrap());
            context.state = MctpPldmSocketState::FirstResponse;
            cvar.notify_all();
        } else if payload[0] & 0x80 == 0x80 {
            mctp_util.send_request(
                self.msg_tag,
                mctp_payload.as_mut_slice(),
                &mut stream,
                self.target_addr,
            );
        } else {
            let msg_tag = *self.response_msg_tag.lock().unwrap();
            mctp_util.set_src_eid(self.dest.0);
            mctp_util.set_dest_eid(self.source.0);
            mctp_util.set_msg_tag(msg_tag & MCTP_TAG_MASK);
            mctp_util.send_response(mctp_payload.as_mut_slice(), &mut stream, self.target_addr);
        }

        Ok(())
    }

    fn receive(&self, _timeout: Option<Duration>) -> Result<RxPacket, PldmTransportError> {
        {
            let (context_lock, cvar) = &*self.context;
            let mut context = context_lock.lock().unwrap();
            if context.state == MctpPldmSocketState::FirstResponse
                || context.state == MctpPldmSocketState::Idle
            {
                while context.first_response.is_none() {
                    // Wait for the first response from the responder in the sending thread
                    context = cvar.wait(context).unwrap();
                }
                // Wait for the first response
                if let Some(response) = context.first_response.as_mut() {
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
                    context.first_response = None;
                    context.state = MctpPldmSocketState::DuplexReady;
                    return Ok(ret);
                } else {
                    return Err(PldmTransportError::Disconnected);
                }
            }
        }

        // We are in duplex mode, so we can receive packets
        // without waiting for the first response
        let mut mctp_util = MctpUtil::new();
        mctp_util.set_pkt_payload_size(MAX_PLDM_PAYLOAD_SIZE);
        let mut stream = self
            .stream
            .try_clone()
            .map_err(|_| PldmTransportError::Disconnected)?;
        let raw_pkt: Vec<u8> = mctp_util.receive(&mut stream, self.target_addr, None);
        if raw_pkt.is_empty() {
            return Err(PldmTransportError::Underflow);
        }
        let len = raw_pkt.len() - 1;
        let mut data = [0u8; MAX_PLDM_PAYLOAD_SIZE];
        // Skip the first byte containing the MCTP common header
        // and only return the PLDM payload
        data[..len].copy_from_slice(&raw_pkt[1..]);
        *self.response_msg_tag.lock().unwrap() = mctp_util.get_msg_tag();
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
            msg_tag: self.msg_tag,
            context: self.context.clone(),
            stream: self.stream.try_clone().unwrap(),
            response_msg_tag: self.response_msg_tag.clone(),
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
        let stream = TcpStream::connect(addr).map_err(|_| PldmTransportError::Disconnected)?;
        let stream = BufferedStream::new(stream);
        let msg_tag = 0u8;
        Ok(MctpPldmSocket {
            source,
            dest,
            target_addr: self.target_addr.into(),
            msg_tag,
            stream,
            context: Arc::new((
                Mutex::new(MctpPldmSocketData {
                    state: MctpPldmSocketState::Idle,
                    first_response: None,
                }),
                Condvar::new(),
            )),
            response_msg_tag: Arc::new(Mutex::new(msg_tag)),
        })
    }
}

// Licensed under the Apache-2.0 license

use crate::i3c_socket::{receive_ibi, receive_private_read, send_private_write};
use crate::tests::mctp_util::base_protocol::{MCTPHdr, LOCAL_TEST_ENDPOINT_EID, MCTP_HDR_SIZE};

use std::collections::VecDeque;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use zerocopy::{FromBytes, IntoBytes};

// Default message tag generated by the initiator
const DEFAULT_MSG_TAG: u8 = 0x08;

#[derive(Debug, Clone)]
pub struct MctpUtil {
    dest_eid: u8,
    src_eid: u8,
    msg_tag: u8,
    tag_owner: u8,
    pkt_payload_size: usize,
}

#[derive(Debug, Clone)]
enum I3cControllerState {
    Start,
    SendPrivateWrite,
    WaitForIbi,
    ReceivePrivateRead,
    Finish,
}

#[derive(Debug, Clone, Default)]
// This struct is used to identify the message the MCTP packet belongs to.
// Packets with the same `MessageIdentifier` are considered to be part of the same message.
pub struct MessageIdentifier {
    pub dest_eid: u8,
    pub src_eid: u8,
    pub msg_tag: u8,
    pub tag_owner: u8,
}

impl MctpUtil {
    pub fn new() -> MctpUtil {
        MctpUtil {
            dest_eid: 0,
            src_eid: LOCAL_TEST_ENDPOINT_EID,
            msg_tag: DEFAULT_MSG_TAG,
            tag_owner: 1,
            pkt_payload_size: 64,
        }
    }

    pub fn new_req(&mut self, msg_tag: u8) {
        self.dest_eid = 0;
        self.src_eid = LOCAL_TEST_ENDPOINT_EID;
        self.msg_tag = msg_tag;
        self.tag_owner = 1;
    }

    pub fn new_resp(&mut self) {
        std::mem::swap(&mut self.src_eid, &mut self.dest_eid);
        self.tag_owner = 0;
    }

    #[allow(dead_code)]
    pub fn set_tag_owner(&mut self, owner: u8) {
        self.tag_owner = owner;
    }

    #[allow(dead_code)]
    pub fn get_tag_owner(&self) -> u8 {
        self.tag_owner
    }

    #[allow(dead_code)]
    pub fn set_dest_eid(&mut self, eid: u8) {
        self.dest_eid = eid;
    }

    #[allow(dead_code)]
    pub fn get_dest_eid(&self) -> u8 {
        self.dest_eid
    }

    #[allow(dead_code)]
    pub fn set_src_eid(&mut self, eid: u8) {
        self.src_eid = eid;
    }

    #[allow(dead_code)]
    pub fn set_pkt_payload_size(&mut self, size: usize) {
        self.pkt_payload_size = size;
    }

    #[allow(dead_code)]
    pub fn get_pkt_payload_size(&self) -> usize {
        self.pkt_payload_size
    }

    #[allow(dead_code)]
    pub fn set_msg_tag(&mut self, tag: u8) {
        self.msg_tag = tag;
    }

    #[allow(dead_code)]
    pub fn get_msg_tag(&self) -> u8 {
        self.msg_tag
    }

    /// Sends a single packet message to the target address and waits for a response.
    /// Retries up to 10 times if no response is received.
    /// This function will block until a response is received or the retry limit is reached.
    ///
    /// # Arguments
    /// * `msg_tag` - The message tag to be used for the request
    /// * `msg` - The message to be sent
    /// * `running` - A flag to indicate if the emulator running status
    /// * `stream` - The TCP stream to I3C socket
    /// * `target_addr` - The target address of the I3C device
    ///
    /// # Returns
    /// * `Option<Vec<u8>>` - The response message if received, otherwise None
    pub fn wait_for_responder(
        &mut self,
        msg_tag: u8,
        msg: &[u8],
        running: Arc<AtomicBool>,
        stream: &mut TcpStream,
        target_addr: u8,
    ) -> Option<Vec<u8>> {
        self.new_req(msg_tag);
        let pkts = self.packetize(msg);
        assert!(pkts.len() == 1, "Only one packet is expected in message");
        let mut i3c_state = I3cControllerState::Start;
        let msg_type = msg[0];

        let mut retry = 10;

        while running.load(Ordering::Relaxed) && retry > 0 {
            match i3c_state {
                I3cControllerState::Start => {
                    i3c_state = I3cControllerState::SendPrivateWrite;
                }

                I3cControllerState::SendPrivateWrite => {
                    let write_pkt = pkts.front().unwrap().clone();
                    if send_private_write(stream, target_addr, write_pkt) {
                        i3c_state = I3cControllerState::WaitForIbi;
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                }
                I3cControllerState::WaitForIbi => {
                    if receive_ibi(stream, target_addr) {
                        i3c_state = I3cControllerState::ReceivePrivateRead;
                    } else {
                        retry -= 1;
                        println!("MCTP_UTIL: IBI not received. Retrying...");
                        i3c_state = I3cControllerState::SendPrivateWrite;
                    }
                }
                I3cControllerState::ReceivePrivateRead => {
                    if let Some(data) = receive_private_read(stream, target_addr) {
                        if data[4] == msg_type {
                            let mut resp_pkts = VecDeque::new();
                            let message_identifier = MessageIdentifier {
                                dest_eid: self.src_eid, // Destination is the requester
                                src_eid: self.dest_eid, // Source is the responder
                                msg_tag,                // The message tag sent in the request
                                tag_owner: 0,           // Not tag owner for response
                            };
                            resp_pkts.push_back(data);
                            self.new_resp();
                            let resp = self.assemble(resp_pkts, &message_identifier);
                            return Some(resp);
                        }

                        i3c_state = I3cControllerState::Finish;
                    }
                }
                I3cControllerState::Finish => {
                    break;
                }
            }
        }

        None
    }

    /// Send a request to the target address
    /// This function will block until the request message is sent
    ///
    /// # Arguments
    /// * `msg_tag` - The message tag to be used for the request
    /// * `msg` - The message to be sent
    /// * `running` - A flag to indicate if the emulator running status
    /// * `stream` - The TCP stream to I3C socket
    /// * `target_addr` - The target address of the I3C device
    pub fn send_request(
        &mut self,
        msg_tag: u8,
        msg: &[u8],
        running: Arc<AtomicBool>,
        stream: &mut TcpStream,
        target_addr: u8,
    ) {
        self.new_req(msg_tag);
        let pkts = self.packetize(msg);
        self.send_packets(pkts, running, stream, target_addr);
    }

    /// Send a response to the target address
    /// This function will block until the response message is sent
    ///
    /// # Arguments
    /// * `msg` - The message to be sent
    /// * `running` - A flag to indicate if the emulator running status
    /// * `stream` - The TCP stream to I3C socket
    /// * `target_addr` - The target address of the I3C device
    pub fn send_response(
        &mut self,
        msg: &[u8],
        running: Arc<AtomicBool>,
        stream: &mut TcpStream,
        target_addr: u8,
    ) {
        self.new_resp();
        let pkts = self.packetize(msg);
        self.send_packets(pkts, running, stream, target_addr);
    }

    /// Receive a response from target address and return the assembled message
    /// Blocks until a response is received or the specified timeout is reached.
    /// If no timeout is provided, it will wait indefinitely for a response.
    ///
    /// # Arguments
    /// * `running` - A flag to indicate if the emulator running status
    /// * `stream` - The TCP stream to I3C socket
    /// * `target_addr` - The target address of the I3C device
    /// * `timeout` - An optional timeout value in seconds
    ///
    /// # Returns
    /// * `Vec<u8>` - The assembled response message
    ///
    pub fn receive_response(
        &mut self,
        running: Arc<AtomicBool>,
        stream: &mut TcpStream,
        target_addr: u8,
        timeout: Option<u32>,
    ) -> Vec<u8> {
        let retry_count = timeout.unwrap_or(0) * 5;
        self.new_resp();
        let mut message_identifier = MessageIdentifier::default();
        let pkts = self.receive_packets(
            running,
            stream,
            target_addr,
            &mut message_identifier,
            retry_count,
        );
        assert_eq!(message_identifier.tag_owner, 0);
        self.assemble(pkts, &message_identifier)
    }

    /// Receive a request and return the assembled message
    /// This function will block until the request is received or the specified timeout is reached.
    /// If no timeout is provided, it will wait indefinitely for a request.
    ///
    /// # Arguments
    /// * `running` - A flag to indicate if the emulator running status
    /// * `stream` - The TCP stream to I3C socket
    /// * `target_addr` - The target address of the I3C device
    /// * `timeout` - An optional timeout value in seconds
    ///
    /// # Returns
    /// * `Vec<u8>` - The assembled request message
    pub fn receive_request(
        &mut self,
        running: Arc<AtomicBool>,
        stream: &mut TcpStream,
        target_addr: u8,
        timeout: Option<u32>,
    ) -> Vec<u8> {
        let retry_count = timeout.unwrap_or(0) * 5;
        // Msg tag will be assigned by the sender (device in this case)
        self.new_req(8);
        let mut message_identifier = MessageIdentifier::default();
        let pkts = self.receive_packets(
            running,
            stream,
            target_addr,
            &mut message_identifier,
            retry_count,
        );
        assert_eq!(message_identifier.tag_owner, 1);
        self.assemble(pkts, &message_identifier)
    }

    /// Receive a generic MCTP Message and return the assembled message
    /// This function will block until the request is received or the specified timeout is reached.
    /// If no timeout is provided, it will wait indefinitely for a request.
    ///
    /// # Arguments
    /// * `running` - A flag to indicate if the emulator running status
    /// * `stream` - The TCP stream to I3C socket
    /// * `target_addr` - The target address of the I3C device
    /// * `timeout` - An optional timeout value in seconds
    ///
    /// # Returns
    /// * `Vec<u8>` - The assembled request message
    pub fn receive(
        &mut self,
        running: Arc<AtomicBool>,
        stream: &mut TcpStream,
        target_addr: u8,
        timeout: Option<u32>,
    ) -> Vec<u8> {
        let retry_count = timeout.unwrap_or(0) * 5;
        let mut message_identifier = MessageIdentifier::default();
        let pkts = self.receive_packets(
            running,
            stream,
            target_addr,
            &mut message_identifier,
            retry_count,
        );
        self.assemble(pkts, &message_identifier)
    }

    fn receive_packets(
        &mut self,
        running: Arc<AtomicBool>,
        stream: &mut TcpStream,
        target_addr: u8,
        message_identifier: &mut MessageIdentifier,
        retry_count: u32,
    ) -> VecDeque<Vec<u8>> {
        let mut i3c_state = I3cControllerState::WaitForIbi;
        let mut pkts: VecDeque<Vec<u8>> = VecDeque::new();
        stream.set_nonblocking(true).unwrap();

        let mut retry = retry_count;

        while running.load(Ordering::Relaxed) {
            match i3c_state {
                I3cControllerState::WaitForIbi => {
                    if receive_ibi(stream, target_addr) {
                        i3c_state = I3cControllerState::ReceivePrivateRead;
                    } else if retry > 0 {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                        retry -= 1;
                        if retry == 0 {
                            println!("MCTP_UTIL: IBI not received. Exiting...");
                            pkts.clear();
                            break;
                        }
                    }
                }
                I3cControllerState::ReceivePrivateRead => {
                    if let Some(data) = receive_private_read(stream, target_addr) {
                        if self.receive_packet(&mut pkts, data, message_identifier) {
                            break;
                        } else {
                            i3c_state = I3cControllerState::WaitForIbi;
                        }
                    }
                }
                _ => {
                    panic!("Unknown state {:?}", i3c_state);
                }
            }
        }

        pkts
    }

    fn receive_packet(
        &mut self,
        pkts: &mut VecDeque<Vec<u8>>,
        data: Vec<u8>,
        message_identifier: &mut MessageIdentifier,
    ) -> bool {
        let mut last_pkt = false;
        let mut pkt = data.clone();
        let mctp_hdr: &mut MCTPHdr<[u8; MCTP_HDR_SIZE]> =
            MCTPHdr::mut_from_bytes(&mut pkt[0..MCTP_HDR_SIZE]).unwrap();

        if mctp_hdr.som() == 1 {
            pkts.clear();
            if mctp_hdr.tag_owner() == 1 {
                // This is a request
                self.msg_tag = mctp_hdr.msg_tag();
                self.src_eid = mctp_hdr.src_eid();
                self.dest_eid = mctp_hdr.dest_eid();
            }
            // This is the start of a new message
            // Reset the message identifier
            message_identifier.dest_eid = mctp_hdr.dest_eid();
            message_identifier.src_eid = mctp_hdr.src_eid();
            message_identifier.msg_tag = mctp_hdr.msg_tag();
            message_identifier.tag_owner = mctp_hdr.tag_owner();
        }

        assert!(message_identifier.msg_tag == mctp_hdr.msg_tag());
        assert!(message_identifier.tag_owner == mctp_hdr.tag_owner());

        if mctp_hdr.eom() == 1 {
            last_pkt = true;
        }
        pkts.push_back(pkt);
        last_pkt
    }

    fn generate_mctp_packet(&self, index: usize, payload: Vec<u8>, last: bool) -> Vec<u8> {
        let mut pkt: Vec<u8> = vec![0; MCTP_HDR_SIZE + payload.len()];
        let pkt_seq: u8 = (index % 4) as u8;
        let som = if index == 0 { 1 } else { 0 };
        let eom = if last { 1 } else { 0 };
        let mut mctp_hdr = MCTPHdr::new();
        mctp_hdr.prepare_header(
            self.dest_eid,
            self.src_eid,
            som,
            eom,
            pkt_seq,
            self.tag_owner,
            self.msg_tag,
        );
        mctp_hdr
            .write_to(&mut pkt[0..MCTP_HDR_SIZE])
            .expect("mctp header write failed");
        pkt[MCTP_HDR_SIZE..].copy_from_slice(&payload[..]);
        pkt
    }

    fn packetize(&self, message: &[u8]) -> VecDeque<Vec<u8>> {
        assert!(self.msg_tag <= 7, "A valid msg tag is required");
        let pkt_payloads: Vec<Vec<u8>> = message
            .chunks(self.pkt_payload_size)
            .map(|chunk| chunk.to_vec())
            .collect();

        let n = pkt_payloads.len() - 1;

        let processed_payloads: Vec<Vec<u8>> = pkt_payloads
            .into_iter()
            .enumerate()
            .map(|(i, payload)| self.generate_mctp_packet(i, payload, n == i))
            .collect();

        let mctp_pkts: VecDeque<Vec<u8>> = processed_payloads.into_iter().collect();
        mctp_pkts
    }

    fn assemble(
        &self,
        packets: VecDeque<Vec<u8>>,
        message_identifier: &MessageIdentifier,
    ) -> Vec<u8> {
        let mut msg: Vec<u8> = Vec::new();
        for (i, pkt) in packets.iter().enumerate() {
            let mctp_hdr: MCTPHdr<[u8; MCTP_HDR_SIZE]> =
                MCTPHdr::read_from_bytes(&pkt[0..MCTP_HDR_SIZE]).unwrap();
            if i == 0 {
                assert_eq!(mctp_hdr.som(), 1);
            }
            if i == packets.len() - 1 {
                assert_eq!(mctp_hdr.eom(), 1);
            }
            let seq_num = (i % 4) as u8;
            assert_eq!(mctp_hdr.dest_eid(), message_identifier.dest_eid);
            assert_eq!(mctp_hdr.tag_owner(), message_identifier.tag_owner);
            assert_eq!(mctp_hdr.msg_tag(), message_identifier.msg_tag);
            assert_eq!(mctp_hdr.pkt_seq(), seq_num);

            msg.extend_from_slice(&pkt[MCTP_HDR_SIZE..]);
        }
        msg
    }

    fn send_packets(
        &mut self,
        pkts: VecDeque<Vec<u8>>,
        running: Arc<AtomicBool>,
        stream: &mut TcpStream,
        target_addr: u8,
    ) {
        let mut pkts = pkts;
        stream.set_nonblocking(true).unwrap();
        while running.load(Ordering::Relaxed) {
            if let Some(write_pkt) = pkts.pop_front() {
                if !send_private_write(stream, target_addr, write_pkt) {
                    break;
                }
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mctp_packetize_assembly() {
        assert!(verify_packetize_assembly(4096, 0, 64));
        assert!(verify_packetize_assembly(1000, 1, 64));
        assert!(verify_packetize_assembly(64, 2, 64));
        assert!(verify_packetize_assembly(63, 3, 64));
        assert!(verify_packetize_assembly(1, 4, 64));
        assert!(verify_packetize_assembly(4096, 5, 256));
        assert!(verify_packetize_assembly(4095, 6, 256));
    }

    fn verify_packetize_assembly(msg_size: usize, tag: u8, pkt_payload_size: usize) -> bool {
        let msg_buf: Vec<u8> = (0..msg_size).map(|_| rand::random::<u8>()).collect();

        let mut mctp = MctpUtil::new();
        mctp.set_pkt_payload_size(pkt_payload_size);
        mctp.set_msg_tag(tag);

        let expected_packets = msg_size.div_ceil(pkt_payload_size);

        let packets = mctp.packetize(&msg_buf);
        if packets.len() != expected_packets {
            println!(
                "MCTP_UTIL: Expected {} packets, but got {}",
                expected_packets,
                packets.len()
            );
            return false;
        }
        let message_identifier = MessageIdentifier {
            dest_eid: mctp.get_dest_eid(),
            src_eid: mctp.src_eid,
            msg_tag: mctp.msg_tag,
            tag_owner: mctp.get_tag_owner(),
        };
        let assembled_msg = mctp.assemble(packets, &message_identifier);
        if assembled_msg != msg_buf {
            println!("MCTP_UTIL: Assembled message does not match original message");
            return false;
        }
        true
    }
}

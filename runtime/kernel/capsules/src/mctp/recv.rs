// Licensed under the Apache-2.0 license

use crate::mctp::base_protocol::{MCTPHeader, MessageType, MCTP_TAG_MASK, MCTP_TAG_OWNER};
use kernel::collections::list::{ListLink, ListNode};
use kernel::utilities::cells::{MapCell, OptionalCell, TakeCell};

/// This trait is implemented to get notified of the messages received
/// on corresponding msg_type.
pub trait MCTPRxClient {
    fn receive(
        &self,
        dst_eid: u8,
        msg_type: u8,
        msg_tag: u8,
        msg_payload: &[u8],
        msg_len: usize,
        recv_time: u32,
    );
}

/// Receive state
pub struct MCTPRxState<'a> {
    /// Message assembly context
    msg_terminus: MapCell<MsgTerminus>,
    /// Expected message types
    msg_type: MessageType,
    /// Client (implements the MCTPRxClient trait)
    client: OptionalCell<&'a dyn MCTPRxClient>,
    /// Message buffer
    msg_payload: TakeCell<'static, [u8]>,
    /// next MCTPRxState node
    next: ListLink<'a, MCTPRxState<'a>>,
}

impl<'a> ListNode<'a, MCTPRxState<'a>> for MCTPRxState<'a> {
    fn next(&'a self) -> &'a ListLink<'a, MCTPRxState<'a>> {
        &self.next
    }
}

struct MsgTerminus {
    msg_type: u8,
    msg_tag: u8,
    source_eid: u8,
    tag_owner: u8,
    start_payload_len: usize,
    pkt_seq: u8,
    msg_size: usize,
}

impl<'a> MCTPRxState<'a> {
    pub fn new(rx_msg_buf: &'static mut [u8], msg_type: MessageType) -> MCTPRxState<'static> {
        MCTPRxState {
            msg_terminus: MapCell::empty(),
            msg_type,
            client: OptionalCell::empty(),
            msg_payload: TakeCell::new(rx_msg_buf),
            next: ListLink::empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::mctp::base_protocol::MCTP_BASELINE_TRANSMISSION_UNIT;
    use crate::mctp::driver::MCTP_MAX_MESSAGE_SIZE;
    use std::boxed::Box;
    use std::cell::RefCell;
    use std::vec;
    use std::vec::Vec;

    #[derive(Debug, PartialEq, Eq)]
    struct ReceivedMessage {
        source_eid: u8,
        msg_type: u8,
        msg_tag: u8,
        payload: Vec<u8>,
        recv_time: u32,
    }

    #[derive(Default)]
    struct RecordingClient {
        messages: RefCell<Vec<ReceivedMessage>>,
    }

    impl MCTPRxClient for RecordingClient {
        fn receive(
            &self,
            source_eid: u8,
            msg_type: u8,
            msg_tag: u8,
            msg_payload: &[u8],
            msg_len: usize,
            recv_time: u32,
        ) {
            self.messages.borrow_mut().push(ReceivedMessage {
                source_eid,
                msg_type,
                msg_tag,
                payload: msg_payload[..msg_len].to_vec(),
                recv_time,
            });
        }
    }

    fn new_state(capacity: usize) -> (&'static MCTPRxState<'static>, &'static RecordingClient) {
        let buffer = Box::leak(vec![0; capacity].into_boxed_slice());
        let state = Box::leak(Box::new(MCTPRxState::new(buffer, MessageType::Spdm)));
        let client = Box::leak(Box::new(RecordingClient::default()));
        state.set_client(client);
        (state, client)
    }

    fn receive_fragmented_message(state: &MCTPRxState<'_>, payload: &[u8]) {
        const PACKET_PAYLOAD_SIZE: usize = MCTP_BASELINE_TRANSMISSION_UNIT;

        let first_len = payload.len().min(PACKET_PAYLOAD_SIZE);
        state.start_receive(
            MCTPHeader::new(0x08, 0x20, 1, u8::from(first_len == payload.len()), 0, 1, 3),
            MessageType::Spdm,
            &payload[..first_len],
            0,
        );

        let mut offset = first_len;
        let mut pkt_seq = 1;
        while offset < payload.len() {
            let end = (offset + PACKET_PAYLOAD_SIZE).min(payload.len());
            let header =
                MCTPHeader::new(0x08, 0x20, 0, u8::from(end == payload.len()), pkt_seq, 1, 3);
            assert!(state.is_next_packet(header, end - offset));
            state.receive_next(header, &payload[offset..end], pkt_seq as u32);
            offset = end;
            pkt_seq = header.next_pkt_seq();
        }
    }

    fn chunk_send_message(handle: u8, sequence: u16, last: bool, chunk: &[u8]) -> Vec<u8> {
        let mut message = vec![MessageType::Spdm as u8, 0x14, 0x85, u8::from(last), handle];
        message.extend_from_slice(&sequence.to_le_bytes());
        message.extend_from_slice(&0u16.to_le_bytes());
        message.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
        message.extend_from_slice(chunk);
        message
    }

    #[test]
    fn single_packet_delivers_payload_and_response_context() {
        let (state, client) = new_state(16);
        let header = MCTPHeader::new(0x08, 0x20, 1, 1, 0, 1, 3);

        state.start_receive(header, MessageType::Spdm, &[5, 0x12, 0x84], 42);

        assert_eq!(
            client.messages.borrow().as_slice(),
            &[ReceivedMessage {
                source_eid: 0x20,
                msg_type: MessageType::Spdm as u8,
                msg_tag: MCTP_TAG_OWNER | 3,
                payload: vec![5, 0x12, 0x84],
                recv_time: 42,
            }]
        );
        assert!(!state.is_next_packet(MCTPHeader::new(0x08, 0x20, 0, 1, 1, 1, 3), 1));
    }

    #[test]
    fn invalid_start_packets_do_not_assemble_or_deliver_and_allow_fresh_message() {
        let cases: [(u8, &[u8]); 3] = [(0, &[5, 1]), (1, &[]), (1, &[5, 1, 2, 3, 4])];

        for (som, payload) in cases {
            for eom in [0, 1] {
                let (state, client) = new_state(4);
                state.start_receive(
                    MCTPHeader::new(0x08, 0x20, som, eom, 0, 1, 3),
                    MessageType::Spdm,
                    payload,
                    0,
                );

                assert!(state.msg_terminus.map(|_| ()).is_none());
                assert!(!state.is_next_packet(MCTPHeader::new(0x08, 0x20, 0, 1, 1, 1, 3), 1));
                assert!(client.messages.borrow().is_empty());

                state.start_receive(
                    MCTPHeader::new(0x08, 0x20, 1, 1, 0, 1, 3),
                    MessageType::Spdm,
                    &[5, 0x84],
                    42,
                );

                assert_eq!(
                    client.messages.borrow().as_slice(),
                    &[ReceivedMessage {
                        source_eid: 0x20,
                        msg_type: MessageType::Spdm as u8,
                        msg_tag: MCTP_TAG_OWNER | 3,
                        payload: vec![5, 0x84],
                        recv_time: 42,
                    }]
                );
                assert!(state.msg_terminus.map(|_| ()).is_none());
            }
        }
    }

    #[test]
    fn multi_packet_reassembly_handles_sequence_wrap() {
        let (state, client) = new_state(16);
        let first = MCTPHeader::new(0x08, 0x20, 1, 0, 3, 0, 2);
        let middle = MCTPHeader::new(0x08, 0x20, 0, 0, 0, 0, 2);
        let last = MCTPHeader::new(0x08, 0x20, 0, 1, 1, 0, 2);

        state.start_receive(first, MessageType::Spdm, &[5, 1, 2, 3], 1);
        assert!(state.is_next_packet(middle, 4));
        state.receive_next(middle, &[4, 5, 6, 7], 2);
        assert!(state.is_next_packet(last, 2));
        state.receive_next(last, &[8, 9], 3);

        assert_eq!(client.messages.borrow().len(), 1);
        assert_eq!(
            client.messages.borrow()[0].payload,
            [5, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        );
        assert_eq!(client.messages.borrow()[0].recv_time, 3);
    }

    #[test]
    fn continuation_requires_matching_fields_without_disrupting_reassembly() {
        let (state, client) = new_state(16);
        state.start_receive(
            MCTPHeader::new(0x08, 0x20, 1, 0, 0, 1, 3),
            MessageType::Spdm,
            &[5, 1, 2, 3],
            0,
        );

        assert!(!state.is_next_packet(MCTPHeader::new(0x08, 0x20, 0, 0, 2, 1, 3), 4));
        assert!(!state.is_next_packet(MCTPHeader::new(0x08, 0x21, 0, 0, 1, 1, 3), 4));
        assert!(!state.is_next_packet(MCTPHeader::new(0x08, 0x20, 0, 0, 1, 1, 4), 4));
        assert!(!state.is_next_packet(MCTPHeader::new(0x08, 0x20, 0, 0, 1, 0, 3), 4));
        assert!(!state.is_next_packet(MCTPHeader::new(0x08, 0x20, 0, 0, 1, 1, 3), 3));
        assert!(client.messages.borrow().is_empty());

        let valid_last = MCTPHeader::new(0x08, 0x20, 0, 1, 1, 1, 3);
        assert!(state.is_next_packet(valid_last, 2));
        state.receive_next(valid_last, &[4, 5], 1);

        assert_eq!(client.messages.borrow()[0].payload, [5, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn duplicate_and_reordered_fragments_do_not_advance_reassembly() {
        let (state, client) = new_state(16);
        state.start_receive(
            MCTPHeader::new(0x08, 0x20, 1, 0, 0, 0, 1),
            MessageType::Spdm,
            &[5, 1, 2, 3],
            0,
        );

        let duplicate = MCTPHeader::new(0x08, 0x20, 0, 0, 0, 0, 1);
        let reordered = MCTPHeader::new(0x08, 0x20, 0, 1, 2, 0, 1);
        assert!(!state.is_next_packet(duplicate, 4));
        assert!(!state.is_next_packet(reordered, 2));
        assert!(client.messages.borrow().is_empty());

        let middle = MCTPHeader::new(0x08, 0x20, 0, 0, 1, 0, 1);
        assert!(state.is_next_packet(middle, 4));
        state.receive_next(middle, &[4, 5, 6, 7], 1);

        let last = MCTPHeader::new(0x08, 0x20, 0, 1, 2, 0, 1);
        assert!(state.is_next_packet(last, 2));
        state.receive_next(last, &[8, 9], 2);

        assert_eq!(
            client.messages.borrow()[0].payload,
            [5, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        );
    }

    #[test]
    fn maximum_boundary_messages_deliver_and_oversize_aborts() {
        for size in [MCTP_MAX_MESSAGE_SIZE - 1, MCTP_MAX_MESSAGE_SIZE] {
            let (state, client) = new_state(MCTP_MAX_MESSAGE_SIZE);
            let payload: Vec<u8> = (0..size).map(|index| index as u8).collect();

            receive_fragmented_message(state, &payload);

            assert_eq!(client.messages.borrow().len(), 1);
            assert_eq!(client.messages.borrow()[0].payload, payload);
        }

        let (state, client) = new_state(MCTP_MAX_MESSAGE_SIZE);
        let oversize: Vec<u8> = (0..=MCTP_MAX_MESSAGE_SIZE)
            .map(|index| index as u8)
            .collect();
        receive_fragmented_message(state, &oversize);

        assert!(client.messages.borrow().is_empty());
        assert!(!state.is_next_packet(MCTPHeader::new(0x08, 0x20, 0, 1, 0, 1, 3), 1));

        state.start_receive(
            MCTPHeader::new(0x08, 0x20, 1, 1, 0, 1, 4),
            MessageType::Spdm,
            &[5, 0x84],
            20,
        );
        assert_eq!(client.messages.borrow()[0].payload, [5, 0x84]);
    }

    #[test]
    fn fragmented_spdm_chunk_recovers_after_transport_fragment_fault() {
        let (state, client) = new_state(MCTP_MAX_MESSAGE_SIZE);
        let interrupted = chunk_send_message(7, 0, false, &[0xa5; 96]);
        assert!(interrupted.len() > MCTP_BASELINE_TRANSMISSION_UNIT);

        state.start_receive(
            MCTPHeader::new(0x08, 0x20, 1, 0, 0, 1, 3),
            MessageType::Spdm,
            &interrupted[..MCTP_BASELINE_TRANSMISSION_UNIT],
            0,
        );
        let reordered_last = MCTPHeader::new(0x08, 0x20, 0, 1, 2, 1, 3);
        assert!(!state.is_next_packet(
            reordered_last,
            interrupted.len() - MCTP_BASELINE_TRANSMISSION_UNIT
        ));
        assert!(client.messages.borrow().is_empty());

        let replacement = chunk_send_message(8, 0, true, &[0x5a; 80]);
        receive_fragmented_message(state, &replacement);

        assert_eq!(client.messages.borrow().len(), 1);
        assert_eq!(client.messages.borrow()[0].payload, replacement);
    }

    #[test]
    fn overflow_aborts_reassembly_and_allows_fresh_message() {
        let (state, client) = new_state(5);
        state.start_receive(
            MCTPHeader::new(0x08, 0x20, 1, 0, 0, 0, 1),
            MessageType::Spdm,
            &[5, 1, 2, 3],
            0,
        );
        state.receive_next(MCTPHeader::new(0x08, 0x20, 0, 1, 1, 0, 1), &[4, 5], 1);

        assert!(client.messages.borrow().is_empty());
        assert!(!state.is_next_packet(MCTPHeader::new(0x08, 0x20, 0, 1, 1, 0, 1), 1));

        state.start_receive(
            MCTPHeader::new(0x08, 0x20, 1, 1, 0, 0, 2),
            MessageType::Spdm,
            &[5, 0x84],
            2,
        );
        assert_eq!(client.messages.borrow()[0].payload, [5, 0x84]);
    }

    #[test]
    fn new_start_replaces_interrupted_message_without_cross_delivery() {
        let (state, client) = new_state(16);
        state.start_receive(
            MCTPHeader::new(0x08, 0x20, 1, 0, 0, 0, 1),
            MessageType::Spdm,
            &[5, 1, 1, 1],
            0,
        );
        state.start_receive(
            MCTPHeader::new(0x08, 0x21, 1, 0, 2, 1, 3),
            MessageType::Spdm,
            &[5, 2, 2, 2],
            1,
        );

        assert!(!state.is_next_packet(MCTPHeader::new(0x08, 0x20, 0, 1, 1, 0, 1), 1));

        let replacement_last = MCTPHeader::new(0x08, 0x21, 0, 1, 3, 1, 3);
        assert!(state.is_next_packet(replacement_last, 2));
        state.receive_next(replacement_last, &[3, 3], 2);

        assert_eq!(client.messages.borrow().len(), 1);
        assert_eq!(client.messages.borrow()[0].source_eid, 0x21);
        assert_eq!(client.messages.borrow()[0].payload, [5, 2, 2, 2, 3, 3]);
    }
}

impl<'a> MCTPRxState<'a> {
    pub fn set_client(&self, client: &'a dyn MCTPRxClient) {
        self.client.set(client);
    }

    pub fn msg_type(&self) -> MessageType {
        self.msg_type
    }

    /// Checks if a message of the given type is expected to be received.
    ///
    /// # Arguments
    /// 'msg_type' - The message type to check if it is expected.
    ///
    /// # Returns
    /// True if the message type is expected, false otherwise.
    pub fn is_receive_expected(&self, msg_type: MessageType) -> bool {
        self.msg_type == msg_type
    }

    /// Checks from the received MCTP header if the next packet belongs to
    /// the current message being assembled.
    ///
    /// # Arguments
    /// 'mctp_hdr' - The MCTP header of the received packet.
    /// 'pkt_payload_len' - The length of the payload of the received packet.
    ///
    /// # Returns
    /// True if the next packet belongs to the current message, false otherwise.
    pub fn is_next_packet(&self, mctp_hdr: MCTPHeader, pkt_payload_len: usize) -> bool {
        self.msg_terminus
            .map(|msg_terminus| {
                // Check if the received packet belongs to the current message
                let next_pkt = msg_terminus.tag_owner == mctp_hdr.tag_owner()
                    && msg_terminus.msg_tag == mctp_hdr.msg_tag()
                    && msg_terminus.source_eid == mctp_hdr.src_eid()
                    && msg_terminus.pkt_seq == mctp_hdr.pkt_seq();

                // Check if the payload length of the middle packet is the same as the first packet
                if mctp_hdr.middle_pkt() {
                    next_pkt && msg_terminus.start_payload_len == pkt_payload_len
                } else {
                    next_pkt
                }
            })
            .unwrap_or(false)
    }

    /// Receives the next packet of the message being assembled.
    /// If the packet is the last one, the message is delivered to the client
    /// by calling the `receive` method of the client.
    ///
    /// # Arguments
    /// 'mctp_hdr' - The MCTP header of the received packet.
    /// 'pkt_payload' - The payload of the received packet.
    pub fn receive_next(&self, mctp_hdr: MCTPHeader, pkt_payload: &[u8], recv_time: u32) {
        if let Some(mut msg_terminus) = self.msg_terminus.take() {
            let offset = msg_terminus.msg_size;
            let end_offset = offset + pkt_payload.len();
            if end_offset > self.msg_payload.map_or(0, |msg_payload| msg_payload.len()) {
                capsule_debug!(
                    "MCTP",
                    "Received packet with payload length greater than buffer size. Reset assembly."
                );
                return;
            }

            self.msg_payload
                .map(|msg_payload| {
                    msg_payload[offset..end_offset].copy_from_slice(pkt_payload);
                    msg_terminus.msg_size = end_offset;
                    msg_terminus.pkt_seq = mctp_hdr.next_pkt_seq();
                    self.msg_terminus.replace(msg_terminus);
                })
                .unwrap_or_else(|| {
                    // This should never happen
                    panic!(
                        "MuxMCTPDriver - No msg buffer in receive next. This should never happen."
                    );
                });

            if mctp_hdr.eom() == 1 {
                self.end_receive(recv_time);
            }
        }
    }

    /// Called at the end of the message assembly to deliver the message to the client.
    /// The message terminus state is set to None after the message is delivered.
    pub fn end_receive(&self, recv_time: u32) {
        if let Some(msg_terminus) = self.msg_terminus.take() {
            let msg_tag = if msg_terminus.tag_owner == 1 {
                (msg_terminus.msg_tag & MCTP_TAG_MASK) | MCTP_TAG_OWNER
            } else {
                msg_terminus.msg_tag & MCTP_TAG_MASK
            };
            self.client
                .map(|client| {
                    self.msg_payload.map(|msg_payload| {
                        client.receive(
                            msg_terminus.source_eid,
                            msg_terminus.msg_type,
                            msg_tag,
                            msg_payload,
                            msg_terminus.msg_size,
                            recv_time,
                        );
                    });
                })
                .unwrap_or_else(|| {
                    // This should never happen
                    panic!(
                        "MuxMCTPDriver - No msg buffer in end receive. This should never happen."
                    );
                });
        }
    }

    /// Called when the first packet of a message is received.
    /// The message terminus state is initialized with the current context.
    /// The previous message assembly state will be lost and a new message assembly
    /// will be started.
    ///
    /// # Arguments
    /// 'mctp_hdr' - The MCTP header of the received packet.
    /// 'msg_type' - The message type of the received packet.
    /// 'pkt_payload' - The payload of the received packet.
    pub fn start_receive(
        &self,
        mctp_hdr: MCTPHeader,
        msg_type: MessageType,
        pkt_payload: &[u8],
        recv_time: u32,
    ) {
        if mctp_hdr.som() != 1 {
            capsule_debug!(
                "MCTP",
                "Received first packet without SOM. Dropping packet."
            );
            return;
        }

        let pkt_payload_len = pkt_payload.len();

        if pkt_payload_len == 0
            || pkt_payload_len > self.msg_payload.map_or(0, |msg_payload| msg_payload.len())
        {
            capsule_debug!("MCTP-RX", "Received bad packet length. Dropping packet.");
            return;
        }

        self.msg_payload
            .map(|msg_payload| {
                msg_payload[..pkt_payload.len()].copy_from_slice(pkt_payload);

                let msg_terminus = MsgTerminus {
                    msg_type: msg_type as u8,
                    msg_tag: mctp_hdr.msg_tag(),
                    source_eid: mctp_hdr.src_eid(),
                    tag_owner: mctp_hdr.tag_owner(),
                    start_payload_len: pkt_payload_len,
                    pkt_seq: mctp_hdr.next_pkt_seq(),
                    msg_size: pkt_payload_len,
                };
                self.msg_terminus.replace(msg_terminus);
            })
            .unwrap_or_else(|| {
                // This should never happen
                panic!("MuxMCTPDriver - Received first packet without buffer. This should never happen.");
            });

        // Single packet message
        if mctp_hdr.eom() == 1 {
            self.end_receive(recv_time);
        }
    }
}

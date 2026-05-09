// Licensed under the Apache-2.0 license

use crate::mctp::base_protocol::{MCTPHeader, MessageType, MCTP_TAG_MASK, MCTP_TAG_OWNER};
use core::fmt::Write;
use kernel::collections::list::{ListLink, ListNode};
use kernel::utilities::cells::{MapCell, OptionalCell, TakeCell};
use romtime::println;

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

#[derive(Debug)]
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

    pub fn set_client(&self, client: &'a dyn MCTPRxClient) {
        self.client.set(client);
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
                println!("MuxMCTPDriver - Received packet with payload length greater than buffer size. Reset assembly.");
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
            println!("MuxMCTPDriver - Received first packet without SOM. Dropping packet.");
            return;
        }

        let pkt_payload_len = pkt_payload.len();

        if pkt_payload_len == 0
            || pkt_payload_len > self.msg_payload.map_or(0, |msg_payload| msg_payload.len())
        {
            println!("MuxMCTPDriver - Received bad packet length. Dropping packet.");
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

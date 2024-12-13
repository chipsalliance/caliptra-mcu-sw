use crate::mctp::base_protocol::MCTPHeader;

use core::fmt::Write;
use romtime::println;

use core::cell::Cell;

use kernel::collections::list::{ListLink, ListNode};
use kernel::utilities::cells::{MapCell, OptionalCell, TakeCell};

use super::base_protocol::{MessageType, MCTP_HDR_SIZE};
use super::common::{MCTP_TAG_MASK, MCTP_TAG_OWNER};
use super::driver::MAX_MESSAGE_TYPES;

/// This trait is implemented to get notified of the messages received
/// on corresponding message_type.
pub trait MCTPRxClient {
    fn receive(&self, dst_eid: u8, msg_type: u8, msg_tag: u8, msg_payload: &[u8], msg_len: usize);
}

/// Receive state
#[allow(dead_code)]
pub struct MCTPRxState<'a> {
    /// Message assembly context
    msg_terminus: MapCell<MsgTerminus>,
    msg_types: Cell<[u8; MAX_MESSAGE_TYPES]>,
    // // /// Source EID
    // // source_eid: Cell<u8>,
    // /// message type
    // msg_type: Cell<u8>,
    // /// msg_tag for the message being assembled
    // msg_tag: Cell<u8>,
    /// Current packet sequence
    // pkt_seq: Cell<u8>,
    /// msg_size in the message buffer
    msg_size: Cell<usize>,
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
}

impl<'a> MCTPRxState<'a> {
    pub fn new(
        rx_msg_buf: &'static mut [u8],
        message_types: [u8; MAX_MESSAGE_TYPES],
    ) -> MCTPRxState<'static> {
        MCTPRxState {
            msg_terminus: MapCell::empty(),
            msg_types: Cell::new(message_types),
            msg_size: Cell::new(0),
            client: OptionalCell::empty(),
            msg_payload: TakeCell::new(rx_msg_buf),
            next: ListLink::empty(),
        }
    }

    pub fn set_client(&self, client: &'a dyn MCTPRxClient) {
        self.client.set(client);
    }

    pub fn is_receive_expected(&self, msg_type: MessageType) -> bool {
        let msg_types = self.msg_types.get();
        for i in 0..MAX_MESSAGE_TYPES {
            if msg_type as u8 == msg_types[i] {
                return true;
            }
        }
        false
    }

    pub fn is_next_packet(
        &self,
        mctp_hdr: &MCTPHeader<[u8; MCTP_HDR_SIZE]>,
        pkt_payload_len: usize,
    ) -> bool {
        self.msg_terminus
            .map(|msg_terminus| {
                msg_terminus.tag_owner == mctp_hdr.tag_owner()
                    && msg_terminus.msg_tag == mctp_hdr.msg_tag()
                    && msg_terminus.source_eid == mctp_hdr.src_eid()
                    && msg_terminus.pkt_seq == mctp_hdr.pkt_seq()
                    && (mctp_hdr.som() == 0
                        && mctp_hdr.eom() == 0
                        && msg_terminus.start_payload_len == pkt_payload_len) // middle packet
            })
            .unwrap_or(false)
    }

    pub fn receive_next(&self, mctp_hdr: MCTPHeader<[u8; MCTP_HDR_SIZE]>, pkt_payload: &[u8]) {
        if let Some(mut msg_terminus) = self.msg_terminus.take() {
            let offset = self.msg_size.get();
            let end_offset = offset + pkt_payload.len();
            if end_offset > self.msg_payload.map_or(0, |msg_payload| msg_payload.len()) {
                println!("MCTPMuxDriver - Received packet with payload length greater than buffer size. Dropping packet.");
                self.msg_size.set(0);
                return;
            }

            self.msg_payload.map(|msg_payload| {
                msg_payload[offset..end_offset].copy_from_slice(pkt_payload);
                self.msg_size.set(end_offset);
            });
            msg_terminus.pkt_seq = mctp_hdr.next_pkt_seq();
            self.msg_terminus.replace(msg_terminus);
        }

        if mctp_hdr.eom() == 1 {
            self.end_receive();
        }
    }

    pub fn end_receive(&self) {
        if let Some(msg_terminus) = self.msg_terminus.take() {
            let msg_tag = if msg_terminus.tag_owner == 1 {
                msg_terminus.msg_tag & MCTP_TAG_MASK | MCTP_TAG_OWNER
            } else {
                msg_terminus.msg_tag
            };
            self.client.map(|client| {
                self.msg_payload.map(|msg_payload| {
                    client.receive(
                        msg_terminus.source_eid,
                        msg_terminus.msg_type,
                        msg_tag,
                        msg_payload,
                        self.msg_size.get(),
                    );
                });
            });
        }
    }

    pub fn start_receive(
        &self,
        mctp_hdr: MCTPHeader<[u8; MCTP_HDR_SIZE]>,
        msg_type: MessageType,
        pkt_payload: &[u8],
    ) {
        if mctp_hdr.som() != 1 {
            println!("MCTPMuxDriver - Received first packet without SOM. Dropping packet.");
            return;
        }

        if pkt_payload.len() == 0 {
            println!("MCTPMuxDriver - Received packet with no payload. Dropping packet.");
            return;
        }

        let pkt_payload_len = pkt_payload.len();

        let msg_terminus = MsgTerminus {
            msg_type: msg_type as u8,
            msg_tag: mctp_hdr.msg_tag(),
            source_eid: mctp_hdr.src_eid(),
            tag_owner: mctp_hdr.tag_owner(),
            start_payload_len: pkt_payload_len,
            pkt_seq: mctp_hdr.next_pkt_seq(),
        };

        self.msg_terminus.replace(msg_terminus);

        self.msg_payload.take().map(|msg_payload| {
            msg_payload[..pkt_payload.len()].copy_from_slice(pkt_payload);
            self.msg_payload.replace(msg_payload);
        });
        self.msg_size.set(pkt_payload_len);

        if mctp_hdr.eom() == 1 {
            self.end_receive();
        }
    }
}

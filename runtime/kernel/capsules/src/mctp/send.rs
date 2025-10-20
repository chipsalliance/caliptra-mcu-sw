// Licensed under the Apache-2.0 license

use crate::mctp::base_protocol::{MCTPHeader, MCTP_HDR_SIZE, MCTP_TAG_MASK, MCTP_TAG_OWNER};
use crate::mctp::mux::MuxMCTPDriver;
use crate::mctp::transport_binding::MCTPTransportBinding;
use core::cell::Cell;
use core::fmt::Write;
use kernel::collections::list::{ListLink, ListNode};
use kernel::hil::time::Alarm;
use kernel::utilities::cells::{MapCell, OptionalCell};
use kernel::utilities::leasable_buffer::SubSliceMut;
use kernel::ErrorCode;
use romtime::println;

/// The trait that provides an interface to send the MCTP messages to MCTP kernel stack.
pub trait MCTPSender<'a> {
    /// Sets the client for the `MCTPSender` instance.
    fn set_client(&self, client: &'a dyn MCTPTxClient);

    /// Sends the message to the MCTP kernel stack.
    fn send_msg(
        &'a self,
        msg_type: u8,
        dest_eid: u8,
        msg_tag: u8,
        msg_payload: SubSliceMut<'static, u8>,
    ) -> Result<(), SubSliceMut<'static, u8>>;
}

/// This trait is implemented by client to get notified after message is sent.
pub trait MCTPTxClient {
    fn send_done(
        &self,
        dest_eid: u8,
        msg_type: u8,
        msg_tag: u8,
        result: Result<(), ErrorCode>,
        msg_payload: SubSliceMut<'static, u8>,
    );
}

/// Send state for MCTP
pub struct MCTPTxState<'a, A: Alarm<'a>, M: MCTPTransportBinding<'a>> {
    mctp_mux_sender: &'a MuxMCTPDriver<'a, A, M>,
    /// Destination EID
    dest_eid: Cell<u8>,
    /// Message type
    msg_type: Cell<u8>,
    /// msg_tag for the message being packetized
    msg_tag: Cell<u8>,
    tag_owner: Cell<bool>,
    /// Current packet sequence
    pkt_seq: Cell<u8>,
    /// Offset into the message buffer
    offset: Cell<usize>,
    /// Client to invoke when send done. This is set to the corresponding Virtual MCTP driver
    client: OptionalCell<&'a dyn MCTPTxClient>,
    /// next node in the list
    next: ListLink<'a, MCTPTxState<'a, A, M>>,
    /// The message buffer is set by the virtual MCTP driver when it issues the Tx request.
    msg_payload: MapCell<SubSliceMut<'static, u8>>,
}

impl<'a, A: Alarm<'a>, M: MCTPTransportBinding<'a>> ListNode<'a, MCTPTxState<'a, A, M>>
    for MCTPTxState<'a, A, M>
{
    fn next(&'a self) -> &'a ListLink<'a, MCTPTxState<'a, A, M>> {
        &self.next
    }
}

impl<'a, A: Alarm<'a>, M: MCTPTransportBinding<'a>> MCTPSender<'a> for MCTPTxState<'a, A, M> {
    fn set_client(&self, client: &'a dyn MCTPTxClient) {
        self.client.set(client);
    }

    fn send_msg(
        &'a self,
        msg_type: u8,
        dest_eid: u8,
        msg_tag: u8,
        msg_payload: SubSliceMut<'static, u8>,
    ) -> Result<(), SubSliceMut<'static, u8>> {
        self.dest_eid.set(dest_eid);
        // Response message should not have the owner bit set
        if msg_tag & MCTP_TAG_OWNER == 0 {
            self.msg_tag.set(msg_tag & MCTP_TAG_MASK);
            self.tag_owner.set(false);
        } else {
            let msg_tag = self.mctp_mux_sender.get_next_msg_tag();
            self.msg_tag.set(msg_tag | MCTP_TAG_OWNER);
            self.tag_owner.set(true);
        }
        self.msg_type.set(msg_type);
        self.msg_payload.replace(msg_payload);
        self.pkt_seq.set(0);
        self.offset.set(0);

        self.mctp_mux_sender.add_sender(self);

        Ok(())
    }
}

impl<'a, A: Alarm<'a>, M: MCTPTransportBinding<'a>> MCTPTxState<'a, A, M> {
    pub fn new(mctp_mux_sender: &'a MuxMCTPDriver<'a, A, M>) -> MCTPTxState<'a, A, M> {
        MCTPTxState {
            mctp_mux_sender,
            dest_eid: Cell::new(0),
            tag_owner: Cell::new(false),
            msg_tag: Cell::new(0),
            msg_type: Cell::new(0),
            pkt_seq: Cell::new(0),
            offset: Cell::new(0),
            client: OptionalCell::empty(),
            next: ListLink::empty(),
            msg_payload: MapCell::empty(),
        }
    }

    pub fn is_eom(&self) -> bool {
        self.offset.get() >= self.msg_payload.map_or(0, |msg_payload| msg_payload.len())
    }

    /// Fills the next packet in the packet buffer.
    /// The packet buffer should be large enough to hold the MCTP header and the payload.
    ///
    /// # Arguments
    /// `pkt_buf` - The buffer to fill the next packet.
    /// `src_eid` - The source EID to be used in the MCTP header.
    ///
    /// # Returns
    /// The number of bytes filled in the packet buffer on success, error code otherwise.
    pub fn fill_next_packet(
        &self,
        pkt_buf: &mut SubSliceMut<'static, u8>,
        src_eid: u8,
    ) -> Result<usize, ErrorCode> {
        if self.is_eom() {
            println!("MCTPTxState - Error!! fill_next_packet: EOM reached");
            Err(ErrorCode::FAIL)?;
        }

        self.msg_payload
            .map_or(Err(ErrorCode::FAIL), |msg_payload| {
                let max_payload_len = pkt_buf.len() - MCTP_HDR_SIZE;
                let total_msg_len = msg_payload.len();
                let offset = self.offset.get();
                let pkt_seq = self.pkt_seq.get();
                let remaining_len = total_msg_len - offset;
                let som = if offset == 0 { 1 } else { 0 };
                let eom = if remaining_len <= max_payload_len {
                    1
                } else {
                    0
                };
                let copy_len = max_payload_len.min(remaining_len);

                let mut mctp_hdr = MCTPHeader::new();
                mctp_hdr.prepare_header(
                    self.dest_eid.get(),
                    src_eid,
                    som,
                    eom,
                    self.pkt_seq.get(),
                    self.tag_owner.get() as u8,
                    self.msg_tag.get(),
                );
                pkt_buf[0..MCTP_HDR_SIZE].copy_from_slice(&mctp_hdr.0.to_le_bytes());
                pkt_buf[MCTP_HDR_SIZE..MCTP_HDR_SIZE + copy_len]
                    .copy_from_slice(&msg_payload[offset..offset + copy_len]);
                self.offset.set(offset + copy_len);
                self.pkt_seq.set((pkt_seq + 1) % 4);
                Ok(copy_len + MCTP_HDR_SIZE)
            })
    }

    /// Informs the client that the message has been sent.
    ///
    /// # Arguments
    /// `result` - The result of the send operation.
    pub fn send_done(&self, result: Result<(), ErrorCode>) {
        self.client.map(|client| {
            if let Some(msg_payload) = self.msg_payload.take() {
                let msg_tag = self.msg_tag.get()
                    | if self.tag_owner.get() {
                        MCTP_TAG_OWNER
                    } else {
                        0
                    };
                client.send_done(
                    self.dest_eid.get(),
                    self.msg_type.get(),
                    msg_tag,
                    result,
                    msg_payload,
                );
            } else {
                println!("MCTPTxState - Error!! send_done: msg_payload is None");
            }
        });
    }
}

// Licensed under the Apache-2.0 license

use crate::mctp::base_protocol::{MCTPHeader, MessageType, MCTP_HDR_SIZE};
use crate::mctp::control_msg::{MCTPCtrlCmd, MCTPCtrlMsgHdr, MCTP_CTRL_MSG_HEADER_LEN};
use crate::mctp::transport_binding::MCTPTransportBinding;

use core::cell::Cell;

use i3c_driver::hil::{RxClient, TxClient};
use kernel::collections::list::{List, ListLink, ListNode};
use kernel::utilities::cells::{MapCell, OptionalCell, TakeCell};
use kernel::utilities::leasable_buffer::SubSliceMut;
use kernel::{debug, ErrorCode};

use zerocopy::{FromBytes, IntoBytes};

/// The trait that provides an interface to send the MCTP messages to MCTP kernel stack.
pub trait MCTPSender {
    /// Sets the client for the `MCTPSender` instance.
    fn set_client(&self, client: &dyn MCTPTxClient);

    /// Sends the message to the MCTP kernel stack.
    fn send_msg(&self, dest_eid: u8, msg_tag: u8, msg_payload: SubSliceMut<'static, u8>);
}

/// This trait is implemented by client to get notified after message is sent.
pub trait MCTPTxClient {
    fn send_done(
        &self,
        msg_tag: Option<u8>,
        result: Result<(), ErrorCode>,
        msg_payload: SubSliceMut<'static, u8>,
    );
}

/// This trait is implemented to get notified of the messages received
/// on corresponding message_type.
pub trait MCTPRxClient {
    fn receive(&self, dst_eid: u8, msg_type: u8, msg_tag: u8, msg_payload: &[u8]);
}

/// Send state for MCTP
#[allow(dead_code)]
pub struct MCTPTxState<'a, M: MCTPTransportBinding<'a>> {
    mctp_mux_sender: &'a MuxMCTPDriver<'a, M>,
    /// Destination EID
    dest_eid: Cell<u8>,
    /// Message type
    msg_type: Cell<u8>,
    /// msg_tag for the message being packetized
    msg_tag: Cell<u8>,
    /// Current packet sequence
    pkt_seq: Cell<u8>,
    /// Offset into the message buffer
    offset: Cell<usize>,
    /// Client to invoke when send done. This is set to the corresponding Virtual MCTP driver
    client: OptionalCell<&'a dyn MCTPTxClient>,
    /// next node in the list
    next: ListLink<'a, MCTPTxState<'a, M>>,
    /// The message buffer is set by the virtual MCTP driver when it issues the Tx request.
    msg_payload: MapCell<SubSliceMut<'static, u8>>,
}

impl<'a, M: MCTPTransportBinding<'a>> ListNode<'a, MCTPTxState<'a, M>> for MCTPTxState<'a, M> {
    fn next(&'a self) -> &'a ListLink<'a, MCTPTxState<'a, M>> {
        &self.next
    }
}

/// Receive state
#[allow(dead_code)]
pub struct MCTPRxState<'a> {
    /// Source EID
    source_eid: Cell<u8>,
    /// message type
    msg_type: Cell<u8>,
    /// msg_tag for the message being assembled
    msg_tag: Cell<u8>,
    /// Current packet sequence
    pkt_seq: Cell<u8>,
    /// Offset into the message buffer
    offset: Cell<usize>,
    /// Start packet len
    start_pkt_len: Cell<usize>,
    /// Client (implements the MCTPRxClient trait)
    client: OptionalCell<&'a dyn MCTPRxClient>,
    /// Message buffer
    msg_payload: MapCell<SubSliceMut<'static, u8>>,
    /// next MCTPRxState node
    next: ListLink<'a, MCTPRxState<'a>>,
}

impl<'a> ListNode<'a, MCTPRxState<'a>> for MCTPRxState<'a> {
    fn next(&'a self) -> &'a ListLink<'a, MCTPRxState<'a>> {
        &self.next
    }
}

/// MUX struct that manages multiple MCTP driver users (clients).
///
/// This struct implements a FIFO queue for the
/// transmitted and received request states.
/// The virtualized upper layer ensures that only
/// one message is transmitted per driver instance at a time.
/// Receive is event based. The received packet in the rx buffer is
/// matched against the pending receive requests.
pub struct MuxMCTPDriver<'a, M: MCTPTransportBinding<'a>> {
    mctp_device: &'a dyn MCTPTransportBinding<'a>,
    next_msg_tag: Cell<u8>, //global msg tag. increment by 1 for next tag upto 7 and wrap around.
    local_eid: Cell<u8>,
    mtu: Cell<usize>,
    // List of outstanding send requests
    sender_list: List<'a, MCTPTxState<'a, M>>,
    receiver_list: List<'a, MCTPRxState<'a>>,
    tx_pkt_buffer: TakeCell<'static, [u8]>, // Static buffer for tx packet. (may not be needed)
    rx_pkt_buffer: TakeCell<'static, [u8]>, //Static buffer for rx packet
}

impl<'a, M: MCTPTransportBinding<'a>> MuxMCTPDriver<'a, M> {
    pub fn new(
        mctp_device: &'a dyn MCTPTransportBinding<'a>,
        local_eid: u8,
        mtu: usize,
        tx_pkt_buf: &'static mut [u8],
        rx_pkt_buf: &'static mut [u8],
    ) -> MuxMCTPDriver<'a, M> {
        MuxMCTPDriver {
            mctp_device,
            next_msg_tag: Cell::new(0),
            local_eid: Cell::new(local_eid),
            mtu: Cell::new(mtu),
            sender_list: List::new(),
            receiver_list: List::new(),
            tx_pkt_buffer: TakeCell::new(tx_pkt_buf),
            rx_pkt_buffer: TakeCell::new(rx_pkt_buf),
        }
    }

    pub fn add_sender(&self, sender: &'a MCTPTxState<'a, M>) {
        self.sender_list.push_tail(sender);
    }

    pub fn add_receiver(&self, receiver: &'a MCTPRxState<'a>) {
        self.receiver_list.push_tail(receiver);
    }

    pub fn set_local_eid(&self, local_eid: u8) {
        self.local_eid.set(local_eid);
    }

    pub fn set_mtu(&self, mtu: usize) {
        self.mtu.set(mtu);
    }

    pub fn get_local_eid(&self) -> u8 {
        self.local_eid.get()
    }

    pub fn get_mtu(&self) -> usize {
        self.mtu.get()
    }

    pub fn get_next_msg_tag(&self) -> u8 {
        let msg_tag = self.next_msg_tag.get();
        self.next_msg_tag.set((msg_tag + 1) % 8);
        msg_tag
    }

    fn interpret_packet(
        &self,
        packet: &[u8],
    ) -> (MCTPHeader<[u8; MCTP_HDR_SIZE]>, Option<MessageType>, usize) {
        let mut msg_type = None;
        let mut mctp_header = MCTPHeader::new();
        let mut payload_offset = 0;

        if packet.len() < MCTP_HDR_SIZE {
            return (mctp_header, msg_type, payload_offset);
        }

        mctp_header = MCTPHeader::read_from_bytes(&packet[0..MCTP_HDR_SIZE]).unwrap();

        if mctp_header.hdr_version() != 1 {
            return (mctp_header, msg_type, payload_offset);
        }

        if mctp_header.som() == 1 {
            if packet.len() < MCTP_HDR_SIZE + 1 {
                return (mctp_header, msg_type, payload_offset);
            }
            msg_type = Some((packet[MCTP_HDR_SIZE] & 0x7F).into());
        }
        payload_offset = MCTP_HDR_SIZE;
        (mctp_header, msg_type, payload_offset)
    }

    fn fill_mctp_ctrl_hdr_resp(
        &self,
        mctp_ctrl_msg_hdr_resp: MCTPCtrlMsgHdr<[u8; MCTP_CTRL_MSG_HEADER_LEN]>,
        resp_buf: &mut [u8],
    ) -> Result<(), ErrorCode> {
        if resp_buf.len() < MCTP_CTRL_MSG_HEADER_LEN {
            return Err(ErrorCode::INVAL);
        }

        mctp_ctrl_msg_hdr_resp.write_to(&mut resp_buf[0..MCTP_CTRL_MSG_HEADER_LEN]).map_err(|_| {
            debug!("MuxMCTPDriver: Failed to write MCTP Control message header. Dropping tx packet.");
            ErrorCode::FAIL
        })
    }

    fn fill_mctp_hdr_resp(
        &self,
        mctp_hdr_resp: MCTPHeader<[u8; MCTP_HDR_SIZE]>,
        resp_buf: &mut [u8],
    ) -> Result<(), ErrorCode> {
        if resp_buf.len() < MCTP_HDR_SIZE {
            return Err(ErrorCode::INVAL);
        }

        mctp_hdr_resp
            .write_to(&mut resp_buf[0..MCTP_HDR_SIZE])
            .map_err(|_| {
                debug!("MuxMCTPDriver: Failed to write MCTP header. Dropping tx packet.");
                ErrorCode::FAIL
            })
    }

    fn process_mctp_control_msg(
        &self,
        mctp_hdr: MCTPHeader<[u8; MCTP_HDR_SIZE]>,
        msg_buf: &[u8],
    ) -> Result<(), ErrorCode> {
        if msg_buf.len() < MCTP_CTRL_MSG_HEADER_LEN {
            return Err(ErrorCode::INVAL);
        }

        let mctp_ctrl_msg_hdr: MCTPCtrlMsgHdr<[u8; MCTP_CTRL_MSG_HEADER_LEN]> =
            MCTPCtrlMsgHdr::read_from_bytes(&msg_buf[0..MCTP_CTRL_MSG_HEADER_LEN]).unwrap();
        if mctp_ctrl_msg_hdr.rq() != 0 || mctp_ctrl_msg_hdr.datagram() != 0 {
            // Only Command/Request messages are handled
            return Err(ErrorCode::INVAL);
        }

        let mut mctp_hdr_resp = MCTPHeader::new();
        mctp_hdr_resp.prepare_header(
            mctp_hdr.src_eid(),
            mctp_hdr.dest_eid(),
            1,
            1,
            0,
            0,
            mctp_hdr.msg_tag(),
        );

        let mut mctp_ctrl_msg_hdr_resp = MCTPCtrlMsgHdr::new();
        mctp_ctrl_msg_hdr_resp.prepare_header(
            0,
            mctp_ctrl_msg_hdr.datagram(),
            mctp_ctrl_msg_hdr.instance_id(),
            mctp_ctrl_msg_hdr.cmd(),
        );

        let mctp_hdr_offset = self.get_total_hdr_size() - MCTP_HDR_SIZE;
        let mctp_ctrl_msg_hdr_offset = mctp_hdr_offset + MCTP_HDR_SIZE;
        let msg_payload_offset = mctp_ctrl_msg_hdr_offset + MCTP_CTRL_MSG_HEADER_LEN;

        let req_buf = &msg_buf[MCTP_CTRL_MSG_HEADER_LEN..];
        let mctp_ctrl_cmd: MCTPCtrlCmd = mctp_ctrl_msg_hdr.cmd().into();
        if req_buf.len() < mctp_ctrl_cmd.req_data_len() {
            Err(ErrorCode::INVAL)?;
        }

        self.tx_pkt_buffer
            .take()
            .map_or(Err(ErrorCode::NOMEM), |resp_buf| {
                let result = match mctp_ctrl_cmd {
                    MCTPCtrlCmd::SetEID => mctp_ctrl_cmd
                        .process_set_endpoint_id(req_buf, &mut resp_buf[msg_payload_offset..])
                        .map(|eid| {
                            self.set_local_eid(eid);
                        }),

                    MCTPCtrlCmd::GetEID => mctp_ctrl_cmd.process_get_endpoint_id(
                        self.get_local_eid(),
                        &mut resp_buf[msg_payload_offset..],
                    ),

                    MCTPCtrlCmd::GetMsgTypeSupport => return Err(ErrorCode::NOSUPPORT),
                    _ => return Err(ErrorCode::NOSUPPORT),
                };
                match result {
                    Ok(_) => {
                        let res = self
                            .fill_mctp_ctrl_hdr_resp(
                                mctp_ctrl_msg_hdr_resp,
                                &mut resp_buf[mctp_ctrl_msg_hdr_offset..],
                            )
                            .and_then(|_| {
                                self.fill_mctp_hdr_resp(
                                    mctp_hdr_resp,
                                    &mut resp_buf[mctp_hdr_offset..],
                                )
                            });

                        match res {
                            Ok(_) => match self.mctp_device.transmit(resp_buf) {
                                Ok(_) => Ok(()),
                                Err((err, tx_buf)) => {
                                    self.tx_pkt_buffer.replace(tx_buf);
                                    Err(err)
                                }
                            },
                            Err(e) => {
                                self.tx_pkt_buffer.replace(resp_buf);
                                Err(e)
                            }
                        }
                    }
                    Err(e) => {
                        self.tx_pkt_buffer.replace(resp_buf);
                        Err(e)
                    }
                }
            })
    }

    fn get_total_hdr_size(&self) -> usize {
        MCTP_HDR_SIZE + self.mctp_device.get_hdr_size()
    }
}

impl<'a, M: MCTPTransportBinding<'a>> TxClient for MuxMCTPDriver<'a, M> {
    fn send_done(&self, tx_buffer: &'static mut [u8], _result: Result<(), ErrorCode>) {
        self.tx_pkt_buffer.replace(tx_buffer);
    }
}

impl<'a, M: MCTPTransportBinding<'a>> RxClient for MuxMCTPDriver<'a, M> {
    fn receive_write(&self, rx_buffer: &'static mut [u8], len: usize) {
        if len == 0 || len > rx_buffer.len() {
            debug!("MuxMCTPDriver: Invalid packet length. Dropping packet.");
            return;
        }

        let (mctp_header, msg_type, payload_offset) = self.interpret_packet(&rx_buffer[0..len]);
        if let Some(msg_type) = msg_type {
            match msg_type {
                MessageType::MCTPControl => {
                    if mctp_header.tag_owner() == 1
                        && mctp_header.som() == 1
                        && mctp_header.eom() == 1
                    {
                        let _ = self.process_mctp_control_msg(
                            mctp_header,
                            &rx_buffer[payload_offset + 1..len],
                        );
                    } else {
                        debug!("MuxMCTPDriver: Invalid MCTP Control message. Dropping packet.");
                    }
                }
                _ => unimplemented!(),
            }
        }
    }

    fn write_expected(&self) {
        if let Some(rx_buf) = self.rx_pkt_buffer.take() {
            self.mctp_device.set_rx_buffer(rx_buf);
        };
    }
}

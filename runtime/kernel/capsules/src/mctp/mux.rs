// Licensed under the Apache-2.0 license

use crate::mctp::base_protocol::{
    MCTPHeader, MessageType, MCTP_BASELINE_TRANSMISSION_UNIT, MCTP_HDR_SIZE,
};
use crate::mctp::control_msg::{MCTPCtrlCmd, MCTPCtrlMsgHdr, MCTP_CTRL_MSG_HEADER_LEN};
use crate::mctp::recv::MCTPRxState;
use crate::mctp::send::MCTPTxState;
use crate::mctp::transport_binding::{MCTPTransportBinding, TransportRxClient, TransportTxClient};
use core::cell::Cell;
use core::fmt::Write;
use kernel::collections::list::List;
use kernel::deferred_call::{DeferredCall, DeferredCallClient};
use kernel::hil::time::{Alarm, Ticks};
use kernel::utilities::cells::TakeCell;
use kernel::utilities::leasable_buffer::SubSliceMut;
use kernel::ErrorCode;
use romtime::println;
use zerocopy::{FromBytes, IntoBytes};

/// MUX struct that manages multiple MCTP driver users (clients).
///
/// This struct implements a FIFO queue for the
/// transmitted and received request states.
/// The virtualized upper layer ensures that only
/// one message is transmitted per driver instance at a time.
/// Receive is event based. The received packet in the rx buffer is
/// matched against the pending receive requests.
pub struct MuxMCTPDriver<'a, A: Alarm<'a>, M: MCTPTransportBinding<'a>> {
    mctp_device: &'a dyn MCTPTransportBinding<'a>,
    next_msg_tag: Cell<u8>, //global msg tag. increment by 1 for next tag upto 7 and wrap around.
    local_eid: Cell<u8>,
    mtu: Cell<usize>,
    // List of outstanding send requests
    sender_list: List<'a, MCTPTxState<'a, A, M>>,
    receiver_list: List<'a, MCTPRxState<'a>>,
    tx_pkt_buffer: TakeCell<'static, [u8]>, // Static buffer for tx packet.
    rx_pkt_buffer: TakeCell<'static, [u8]>, //Static buffer for rx packet
    clock: &'a A,
    deferred_call: DeferredCall,
}

impl<'a, A: Alarm<'a>, M: MCTPTransportBinding<'a>> MuxMCTPDriver<'a, A, M> {
    pub fn new(
        mctp_device: &'a dyn MCTPTransportBinding<'a>,
        local_eid: u8,
        mtu: usize,
        tx_pkt_buf: &'static mut [u8],
        rx_pkt_buf: &'static mut [u8],
        clock: &'a A,
    ) -> MuxMCTPDriver<'a, A, M> {
        MuxMCTPDriver {
            mctp_device,
            next_msg_tag: Cell::new(0),
            local_eid: Cell::new(local_eid),
            mtu: Cell::new(mtu),
            sender_list: List::new(),
            receiver_list: List::new(),
            tx_pkt_buffer: TakeCell::new(tx_pkt_buf),
            rx_pkt_buffer: TakeCell::new(rx_pkt_buf),
            clock,
            deferred_call: DeferredCall::new(),
        }
    }

    pub fn enable(&self) {
        self.mctp_device.enable();
    }

    pub fn add_sender(&self, sender: &'a MCTPTxState<'a, A, M>) {
        let list_empty = self.sender_list.head().is_none();

        self.sender_list.push_tail(sender);

        if list_empty {
            self.deferred_call.set();
        }
    }

    fn deferred_send(&self) {
        if let Some(sender) = self.sender_list.head() {
            self.send_next_packet(sender);
        }
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

        mctp_header = match MCTPHeader::read_from_bytes(&packet[0..MCTP_HDR_SIZE]) {
            Ok(header) => header,
            Err(_) => {
                return (mctp_header, msg_type, payload_offset);
            }
        };

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
            println!("MuxMCTPDriver: Failed to write MCTP Control message header. Dropping tx packet.");
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
                println!("MuxMCTPDriver: Failed to write MCTP header. Dropping tx packet.");
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
            MCTPCtrlMsgHdr::read_from_bytes(&msg_buf[0..MCTP_CTRL_MSG_HEADER_LEN])
                .map_err(|_| ErrorCode::FAIL)?;

        if mctp_ctrl_msg_hdr.rq() != 1 || mctp_ctrl_msg_hdr.datagram() != 0 {
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

        let mctp_hdr_start = self.mctp_hdr_offset();
        let mctp_ctrl_hdr_start = mctp_hdr_start + MCTP_HDR_SIZE;
        let msg_payload_start = mctp_ctrl_hdr_start + MCTP_CTRL_MSG_HEADER_LEN;

        let req_buf = &msg_buf[MCTP_CTRL_MSG_HEADER_LEN..];
        let mctp_ctrl_cmd: MCTPCtrlCmd = mctp_ctrl_msg_hdr.cmd().into();
        let resp_len = MCTP_CTRL_MSG_HEADER_LEN + MCTP_HDR_SIZE + mctp_ctrl_cmd.resp_data_len();

        if req_buf.len() < mctp_ctrl_cmd.req_data_len() {
            println!(
                "MuxMCTPDriver: Invalid buffer len Dropping packet. {:?} ctrl_cmd_len {:?}",
                req_buf.len(),
                mctp_ctrl_cmd.req_data_len()
            );
            Err(ErrorCode::INVAL)?;
        }

        self.tx_pkt_buffer
            .take()
            .map_or(Err(ErrorCode::NOMEM), |resp_buf| {
                let result = match mctp_ctrl_cmd {
                    MCTPCtrlCmd::SetEID => mctp_ctrl_cmd
                        .process_set_endpoint_id(req_buf, &mut resp_buf[msg_payload_start..])
                        .map(|eid| {
                            if let Some(eid) = eid {
                                self.set_local_eid(eid);
                            }
                        }),

                    MCTPCtrlCmd::GetEID => mctp_ctrl_cmd.process_get_endpoint_id(
                        self.get_local_eid(),
                        &mut resp_buf[msg_payload_start..],
                    ),

                    MCTPCtrlCmd::GetVersionSupport => mctp_ctrl_cmd
                        .process_get_version_support(req_buf, &mut resp_buf[msg_payload_start..]),

                    MCTPCtrlCmd::GetMsgTypeSupport => return Err(ErrorCode::NOSUPPORT),
                    _ => return Err(ErrorCode::NOSUPPORT),
                };

                match result {
                    Ok(_) => {
                        let res = self
                            .fill_mctp_ctrl_hdr_resp(
                                mctp_ctrl_msg_hdr_resp,
                                &mut resp_buf[mctp_ctrl_hdr_start
                                    ..mctp_ctrl_hdr_start + MCTP_CTRL_MSG_HEADER_LEN],
                            )
                            .and_then(|_| {
                                self.fill_mctp_hdr_resp(
                                    mctp_hdr_resp,
                                    &mut resp_buf[mctp_hdr_start..mctp_hdr_start + MCTP_HDR_SIZE],
                                )
                            });

                        match res {
                            Ok(_) => match self.mctp_device.transmit(resp_buf, resp_len) {
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

    fn send_next_packet(&self, cur_sender: &'a MCTPTxState<'a, A, M>) {
        let mut tx_pkt = SubSliceMut::new(self.tx_pkt_buffer.take().unwrap());
        let mctp_hdr_offset = self.mctp_hdr_offset();
        let pkt_end_offset = self.get_mtu();

        // set the window of the subslice for MCTP header and the payload
        tx_pkt.slice(mctp_hdr_offset..pkt_end_offset);

        match cur_sender.fill_next_packet(&mut tx_pkt, self.local_eid.get()) {
            Ok(len) => {
                tx_pkt.reset();
                match self
                    .mctp_device
                    .transmit(tx_pkt.take(), len + mctp_hdr_offset)
                {
                    Ok(_) => (),
                    Err((err, buf)) => {
                        println!("MuxMCTPDriver: Failed to transmit {:?}", err);
                        self.tx_pkt_buffer.replace(buf);
                    }
                }
            }
            Err(err) => {
                println!("MuxMCTPDriver: Failed to start transmit {:?}", err);
                self.tx_pkt_buffer.replace(tx_pkt.take());
            }
        }
    }

    fn process_first_packet(
        &self,
        mctp_hdr: MCTPHeader<[u8; MCTP_HDR_SIZE]>,
        msg_type: MessageType,
        pkt_payload: &[u8],
    ) {
        // Check if the first packet of a multi-packet message has at least length of
        // MCTP_BASELINE_TRANSMISSION_UNIT bytes.
        if mctp_hdr.eom() == 0 && pkt_payload.len() < MCTP_BASELINE_TRANSMISSION_UNIT {
            println!(
                "MuxMCTPDriver: Received first packet with less than 64 bytes. Dropping packet."
            );
            return;
        }

        let rx_state = self
            .receiver_list
            .iter()
            .find(|rx_state| rx_state.is_receive_expected(msg_type));

        if let Some(rx_state) = rx_state {
            let recv_time = self.clock.now().into_u32();
            rx_state.start_receive(mctp_hdr, msg_type, pkt_payload, recv_time);
        } else {
            println!("MuxMCTPDriver: No matching receive request found. Dropping packet.");
        }
    }

    fn process_packet(&self, mctp_hdr: MCTPHeader<[u8; MCTP_HDR_SIZE]>, pkt_payload: &[u8]) {
        if self.local_eid != mctp_hdr.dest_eid().into() {
            println!("MuxMCTPDriver: Packet not for this Endpoint. Dropping packet.");
            return;
        }

        if mctp_hdr.eom() != 1 && pkt_payload.len() < MCTP_BASELINE_TRANSMISSION_UNIT {
            println!("MuxMCTPDriver: Received first or middle packet with less than 64 bytes. Dropping packet.");
            return;
        }

        let rx_state = self
            .receiver_list
            .iter()
            .find(|rx_state| rx_state.is_next_packet(&mctp_hdr, pkt_payload.len()));

        match rx_state {
            Some(rx_state) => {
                let recv_time = self.clock.now().into_u32();
                rx_state.receive_next(mctp_hdr, pkt_payload, recv_time);
            }
            None => {
                println!("MuxMCTPDriver: No matching receive request found. Dropping packet.");
            }
        }
    }

    fn mctp_hdr_offset(&self) -> usize {
        self.mctp_device.get_hdr_size()
    }
}

impl<'a, A: Alarm<'a>, M: MCTPTransportBinding<'a>> TransportTxClient for MuxMCTPDriver<'a, A, M> {
    fn send_done(&self, tx_buffer: &'static mut [u8], result: Result<(), ErrorCode>) {
        self.tx_pkt_buffer.replace(tx_buffer);

        let mut cur_sender = self.sender_list.head();
        if let Some(sender) = cur_sender {
            if sender.is_eom() || result.is_err() {
                sender.send_done(result);
                self.sender_list.pop_head();
                cur_sender = self.sender_list.head();
            }
        }

        if let Some(cur_sender) = cur_sender {
            self.send_next_packet(cur_sender);
        };
    }
}

impl<'a, A: Alarm<'a>, M: MCTPTransportBinding<'a>> TransportRxClient for MuxMCTPDriver<'a, A, M> {
    fn receive(&self, rx_buffer: &'static mut [u8], len: usize) {
        if len == 0 || len > rx_buffer.len() {
            println!("MuxMCTPDriver: Invalid packet length. Dropping packet.");
            self.rx_pkt_buffer.replace(rx_buffer);
            return;
        }

        let (mctp_header, msg_type, payload_offset) = self.interpret_packet(&rx_buffer[0..len]);
        if let Some(msg_type) = msg_type {
            match msg_type {
                MessageType::MctpControl => {
                    if mctp_header.tag_owner() == 1
                        && mctp_header.som() == 1
                        && mctp_header.eom() == 1
                    {
                        let _ = self
                            .process_mctp_control_msg(mctp_header, &rx_buffer[payload_offset..len]);
                    } else {
                        println!("MuxMCTPDriver: Invalid MCTP Control message. Dropping packet.");
                    }
                }
                MessageType::Pldm
                | MessageType::Spdm
                | MessageType::SecureSpdm
                | MessageType::Caliptra
                | MessageType::TestMsgType => {
                    self.process_first_packet(
                        mctp_header,
                        msg_type,
                        &rx_buffer[payload_offset..len],
                    );
                }
                _ => {
                    println!("MuxMCTPDriver: Unsupported message type. Dropping packet.");
                }
            }
        } else {
            self.process_packet(mctp_header, &rx_buffer[payload_offset..len]);
        }
        self.rx_pkt_buffer.replace(rx_buffer);
    }

    fn write_expected(&self) {
        if let Some(rx_buf) = self.rx_pkt_buffer.take() {
            self.mctp_device.set_rx_buffer(rx_buf);
        };
    }
}

impl<'a, A: Alarm<'a>, M: MCTPTransportBinding<'a>> DeferredCallClient for MuxMCTPDriver<'a, A, M> {
    fn handle_deferred_call(&self) {
        self.deferred_send();
    }

    fn register(&'static self) {
        self.deferred_call.register(self);
    }
}

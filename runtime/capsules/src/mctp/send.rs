use crate::mctp::mux::MuxMCTPDriver;
use crate::mctp::transport_binding::MCTPTransportBinding;

use core::cell::Cell;

use kernel::collections::list::{ListLink, ListNode};
use kernel::utilities::cells::{MapCell, OptionalCell};
use kernel::utilities::leasable_buffer::SubSliceMut;
use kernel::ErrorCode;

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

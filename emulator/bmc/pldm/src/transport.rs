use core::fmt::{Display, Formatter};
use core::time::Duration;


pub trait PldmTransport<T : PldmSocket> {
    fn create_socket(&self, eid: SockId) -> Result<T, ()>;
}

pub const MAX_PLDM_PAYLOAD_SIZE: usize = 1024;
/// A trait representing a PLDM (Platform Level Data Model) socket for sending and receiving MCTP (Management Component Transport Protocol) packets.
pub trait PldmSocket {
    /// Sends an MCTP packet.
    ///
    /// # Arguments
    ///
    /// * `pkt` - A reference to the `TransportPacket` to be sent.
    ///
    /// # Returns
    ///
    /// * `Result<(), ()>` - Returns `Ok(())` if the packet was sent successfully, otherwise returns `Err(())`.
    fn send(&self, dst : SockId, payload: &[u8]) -> Result<(), ()>;

    /// Receives an MCTP packet.
    ///
    /// # Returns
    ///
    /// * `Result<TransportPacket, ()>` - Returns `Ok(TransportPacket)` if a packet was received successfully, otherwise returns `Err(())`.
    fn receive(&self, timeout: Option<Duration>) -> Result<RxPacket, ()>;

    fn disconnect(&self);

    fn clone(&self) -> Self;
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SockId(pub u8);
#[derive(Debug, Clone)]
pub struct Payload {
    pub data: [u8;MAX_PLDM_PAYLOAD_SIZE],
    pub len: usize,
}

impl Default for Payload {
    fn default() -> Self {
        Self {
            data: [0; MAX_PLDM_PAYLOAD_SIZE],
            len: 0,
        }
    }
}

impl Display for Payload {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Payload {{ data: {:?}, len: {} }}", &self.data[..self.len], self.len)
    }
}

#[derive(Debug, Clone, Default)]
pub struct TxPacket {
    pub src: SockId,
    pub dest: SockId,
    pub payload: Payload
}

#[derive(Debug, Clone, Default)]
pub struct RxPacket {
    pub src: SockId,
    pub payload: Payload
}

impl Display for RxPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "RxPacket {{ src: {:?}, payload: {} }}", self.src, self.payload)
    }
}
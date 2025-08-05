// Licensed under the Apache-2.0 license

pub const SOCKET_TRANSPORT_TYPE_MCTP: u32 = 0x01;
pub const SOCKET_TRANSPORT_TYPE_PCI_DOE: u32 = 0x02;

pub const MAX_CMD_TIMEOUT_SECONDS: u32 = 120;

pub trait Transport {
    fn target_send_and_receive(&mut self, req: &[u8], wait_for_responder: bool) -> Option<Vec<u8>>;
    fn transport_type(&self) -> u32;
}

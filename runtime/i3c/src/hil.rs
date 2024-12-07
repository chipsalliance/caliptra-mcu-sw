// Licensed under the Apache-2.0 license

use core::result::Result;
use kernel::ErrorCode;

/// Provides information about an I3C target device.
#[derive(Debug)]
pub struct I3CTargetInfo {
    /// Could be assigned by the hardware or absent.
    pub static_addr: Option<u8>,
    /// Could be assigned by the controller or absent if
    /// static address is used, or device has not received the address yet.
    pub dynamic_addr: Option<u8>,
    /// Maximum length of data that will be received in a Write command.
    pub max_read_len: usize,
    /// Maximum length of data that can be sent in response to a Read command.
    pub max_write_len: usize,
}

pub trait TxClient {
    /// Called when the packet has been transmitted.
    fn send_done(&self, tx_buffer: &'static mut [u8], result: Result<(), ErrorCode>);
}

pub trait RxClient {
    /// Called when a complete MCTP packet is received and ready to be processed.
    fn receive_write(&self, rx_buffer: &'static mut [u8], len: usize);

    /// Called when the I3C Controller has requested a private Write by addressing the target
    /// and the driver needs buffer to receive the data.
    /// The client should call set_rx_buffer() to set the buffer.
    fn write_expected(&self);
}

pub trait I3CTarget<'a> {
    /// Set the client that will be called when the packet is transmitted.
    fn set_tx_client(&self, client: &'a dyn TxClient);

    /// Set the client that will be called when the packet is received.
    fn set_rx_client(&self, client: &'a dyn RxClient);

    /// Set the buffer that will be used for receiving Write packets.
    fn set_rx_buffer(&self, rx_buf: &'static mut [u8]);

    /// Queue a packet in response to a private Read.
    fn transmit_read(
        &self,
        tx_buf: &'static mut [u8],
        len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])>;

    /// Enable the I3C target device
    fn enable(&self);

    /// Disable the I3C target device
    fn disable(&self);

    /// Returns information about this I3C Target Device.
    fn get_device_info(&self) -> I3CTargetInfo;
}

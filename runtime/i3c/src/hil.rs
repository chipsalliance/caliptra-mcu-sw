// Licensed under the Apache-2.0 license

use core::result::Result;
use kernel::ErrorCode;

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
    fn transmit_read(&self, tx_buf: &'static mut [u8], len: usize) -> Result<(), ErrorCode>;

    /// Enable the I3C target device
    fn enable(&self);

    /// Disable the I3C target device
    fn disable(&self);

    /// Get the maximum transmission unit (MTU) size.
    fn get_mtu_size(&self) -> usize;

    /// Get the address of the I3C target device. Needed for PEC calculation.
    fn get_address(&self) -> u8;
}

// Licensed under the Apache-2.0 license

use core::result::Result;
use kernel::ErrorCode;

pub trait DoeTransportTxClient {
    /// Called by driver to notify that the DOE data object transmission is done.
    ///
    /// # Arguments
    /// * `tx_buf` - buffer containing the DOE data object that was transmitted
    /// * `result` - Result indicating success or failure of the transmission
    fn send_done(&self, tx_buf: &'static mut [u32], result: Result<(), ErrorCode>);
}

pub trait DoeTransportRxClient {
    /// Called to receive a DOE data object.
    ///
    /// # Arguments
    /// * `rx_buf` - buffer containing the received DOE data object
    /// * `len_dwords` - The length of the data received in dwords
    fn receive(&self, rx_buf: &'static mut [u32], len_dwords: usize);
    /// receive expected callback. This is called when a DOE data object is received,
    /// but buffer is not available with the driver to copy the data into.
    /// The client must call `set_rx_buffer()` to set the buffer
    fn receive_expected(&self);
}

pub trait DoeTransport {
    /// Sets the transmit and receive clients for the DOE transport instance
    fn set_tx_client(&self, client: &'static dyn DoeTransportTxClient);
    fn set_rx_client(&self, client: &'static dyn DoeTransportRxClient);

    /// Sets the buffer used for receiving incoming DOE Objects.
    fn set_rx_buffer(&self, rx_buf: &'static mut [u32]);

    /// Gets the maximum size of the data object that can be sent or received over DOE Transport.
    fn max_data_object_size(&self) -> usize;

    /// Enable the DOE transport driver instance.
    fn enable(&self) -> Result<(), ErrorCode>;

    /// Disable the DOE transport driver instance.
    fn disable(&self) -> Result<(), ErrorCode>;

    /// Send DOE Object to be transmitted over SoC specific DOE transport.
    ///
    /// # Arguments
    /// * `tx_buf` - A reference to the DOE data object to be transmitted.
    /// * `len` - The length of the message in bytes
    fn transmit(
        &self,
        tx_buf: &'static mut [u32],
        len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u32])>;
}

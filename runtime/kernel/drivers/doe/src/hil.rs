// Licensed under the Apache-2.0 license

use core::result::Result;
use kernel::ErrorCode;

pub trait DoeTransportTxClient {
    /// Called when the DOE data object transmission is done.
    fn send_done(&self, tx_buf: &'static mut [u8], result: Result<(), ErrorCode>);
}

pub trait DoeTransportRxClient {
    /// Called when a DOE data object is received.
    ///
    /// # Arguments
    /// * `rx_buf` - A mutable reference to the buffer containing the received DOE data object.
    /// * `len_dwords` - The length of the received message in dwords (32-bit words).
    fn receive(&self, rx_buf: &'static mut [u32], len_dwords: usize);
}

pub trait DoeTransport {
    /// Sets the transmit and receive clients for the DOE transport instance
    fn set_tx_client(&self, client: &'static dyn DoeTransportTxClient);
    fn set_rx_client(&self, client: &'static dyn DoeTransportRxClient);

    /// Sets the buffer used for receiving incoming DOE Objects.
    /// This function should be called by the Rx client upon receiving the `receive()` callback.
    fn set_rx_buffer(&self, rx_buf: &'static mut [u32]);

    /// Gets the maximum size of the data object that can be sent or received over DOE Transport.
    fn max_data_size_dwords(&self) -> usize;

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
        tx_buf: &'static mut [u8],
        len_bytes: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])>;
}

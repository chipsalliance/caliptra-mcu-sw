// Licensed under the Apache-2.0 license

use core::result::Result;
use kernel::ErrorCode;

pub const DOE_HDR_SIZE_DWORDS: usize = 2; // Size of the DOE header in DWORDs (8 bytes)

pub trait DoeTransportTxClient {
    /// Called when the DOE data object transmission is done.
    fn send_done(&self, tx_buf: &'static mut [u32], result: Result<(), ErrorCode>);
}

pub trait DoeTransportRxClient {
    /// Called when a DOE data object is received.
    fn receive(&self, rx_buf: &'static mut [u32], len: usize);
}

pub trait DoeTransport {
    /// Sets the transmit and receive clients for the DOE transport instance
    fn set_tx_client(&self, client: &'static dyn DoeTransportTxClient);
    fn set_rx_client(&self, client: &'static dyn DoeTransportRxClient);

    /// Sets the buffer used for receiving incoming DOE Objects.
    /// This function should be called by the Rx client upon receiving the `receive()` callback.
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
    /// * `doe_hdr` - DOE header bytes
    /// * `doe_payload` - A reference to the DOE payload
    /// * `payload_len` - The length of the payload in bytes
    fn transmit(
        &self,
        doe_hdr: Option<[u32; DOE_HDR_SIZE_DWORDS]>,
        doe_payload: &'static mut [u32],
        payload_len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u32])>;
}

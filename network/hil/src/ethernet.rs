/*++

Licensed under the Apache-2.0 license.

File Name:

    ethernet.rs

Abstract:

    Hardware Interface Layer trait for Ethernet peripherals.
--*/

pub const ETH_MAX_FRAME_SIZE: usize = 1514;
pub const ETH_MIN_FRAME_SIZE: usize = 60;
pub const ETH_HEADER_SIZE: usize = 14;
pub type MacAddress = [u8; 6];
pub const BROADCAST_MAC: MacAddress = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthernetError {
    TxNotReady,
    FrameTooLarge,
    FrameTooSmall,
    NoFrameAvailable,
    BufferTooSmall,
    HardwareError,
}

pub type Result<T> = core::result::Result<T, EthernetError>;

// Hardware Interface Layer trait for Ethernet peripherals
pub trait Ethernet {
    // Get the MAC address of this Ethernet interface
    fn mac_address(&self) -> MacAddress;

    // Set the MAC address of this Ethernet interface
    fn set_mac_address(&mut self, mac: MacAddress);

    // Check if the transmitter is ready to accept a new frame
    fn tx_ready(&self) -> bool;

    // Check if there is at least one received frame available
    fn rx_available(&self) -> bool;

    // Get the number of frames in the receive queue
    fn rx_queue_count(&self) -> u8;

    // Transmit an Ethernet frame
    //
    // The frame should include the complete Ethernet header (destination MAC,
    // source MAC, and EtherType) followed by the payload. The FCS is typically
    // computed by hardware.
    //
    // # Arguments
    // * `frame` - The complete Ethernet frame to transmit
    //
    // # Returns
    // * `Ok(())` - Frame was successfully queued for transmission
    // * `Err(EthernetError)` - Transmission failed
    fn transmit(&mut self, frame: &[u8]) -> Result<()>;

    // Get the length of the next received frame
    //
    // # Returns
    // * `Some(len)` - Length of the next frame in bytes
    // * `None` - No frame available
    fn rx_frame_len(&self) -> Option<usize>;

    // Receive an Ethernet frame
    //
    // Copies the next received frame into the provided buffer.
    //
    // # Arguments
    // * `buffer` - Buffer to receive the frame data
    //
    // # Returns
    // * `Ok(len)` - Number of bytes written to the buffer
    // * `Err(EthernetError)` - Reception failed
    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize>;

    // Pop the current RX frame from the queue without reading it
    //
    // Use this to discard a frame that cannot be processed.
    fn pop_rx_frame(&mut self);

    // Acknowledge and clear the RX interrupt
    fn ack_interrupt(&mut self);

    // Poll the Ethernet peripheral
    //
    // This should be called periodically to handle any pending operations.
    // For interrupt-driven implementations, this may be a no-op.
    fn poll(&mut self) {}
}

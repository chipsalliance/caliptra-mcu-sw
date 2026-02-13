/*++

Licensed under the Apache-2.0 license.

File Name:

    ethernet.rs

Abstract:

    Hardware Interface Layer trait for Ethernet peripherals.
    
    This trait provides an abstraction over Ethernet hardware, allowing
    network protocol implementations (DHCP, TFTP, etc.) to work with
    any Ethernet implementation that satisfies this interface.

--*/

/// Maximum Ethernet frame size (excluding FCS, including headers)
pub const ETH_MAX_FRAME_SIZE: usize = 1514;

/// Minimum Ethernet frame size (including headers)
pub const ETH_MIN_FRAME_SIZE: usize = 60;

/// Ethernet header size (dest MAC + src MAC + ethertype)
pub const ETH_HEADER_SIZE: usize = 14;

/// MAC address type (6 bytes)
pub type MacAddress = [u8; 6];

/// Broadcast MAC address
pub const BROADCAST_MAC: MacAddress = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

/// Error types for Ethernet operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthernetError {
    /// TX buffer is busy or not ready
    TxNotReady,
    /// Frame size exceeds maximum allowed
    FrameTooLarge,
    /// Frame size is below minimum required
    FrameTooSmall,
    /// No RX frame available
    NoFrameAvailable,
    /// Buffer provided is too small for the frame
    BufferTooSmall,
    /// Hardware error occurred
    HardwareError,
}

/// Result type for Ethernet operations
pub type Result<T> = core::result::Result<T, EthernetError>;

/// Hardware Interface Layer trait for Ethernet peripherals
///
/// This trait abstracts the hardware-specific details of an Ethernet
/// peripheral, providing a clean interface for network protocol
/// implementations.
pub trait Ethernet {
    /// Get the MAC address of this Ethernet interface
    fn mac_address(&self) -> MacAddress;

    /// Set the MAC address of this Ethernet interface
    fn set_mac_address(&mut self, mac: MacAddress);

    /// Check if the transmitter is ready to accept a new frame
    fn tx_ready(&self) -> bool;

    /// Check if there is at least one received frame available
    fn rx_available(&self) -> bool;

    /// Get the number of frames in the receive queue
    fn rx_queue_count(&self) -> u8;

    /// Transmit an Ethernet frame
    ///
    /// The frame should include the complete Ethernet header (destination MAC,
    /// source MAC, and EtherType) followed by the payload. The FCS is typically
    /// computed by hardware.
    ///
    /// # Arguments
    /// * `frame` - The complete Ethernet frame to transmit
    ///
    /// # Returns
    /// * `Ok(())` - Frame was successfully queued for transmission
    /// * `Err(EthernetError)` - Transmission failed
    fn transmit(&mut self, frame: &[u8]) -> Result<()>;

    /// Get the length of the next received frame
    ///
    /// # Returns
    /// * `Some(len)` - Length of the next frame in bytes
    /// * `None` - No frame available
    fn rx_frame_len(&self) -> Option<usize>;

    /// Receive an Ethernet frame
    ///
    /// Copies the next received frame into the provided buffer.
    ///
    /// # Arguments
    /// * `buffer` - Buffer to receive the frame data
    ///
    /// # Returns
    /// * `Ok(len)` - Number of bytes written to the buffer
    /// * `Err(EthernetError)` - Reception failed
    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize>;

    /// Pop the current RX frame from the queue without reading it
    ///
    /// Use this to discard a frame that cannot be processed.
    fn pop_rx_frame(&mut self);

    /// Acknowledge and clear the RX interrupt
    fn ack_interrupt(&mut self);

    /// Poll the Ethernet peripheral
    ///
    /// This should be called periodically to handle any pending operations.
    /// For interrupt-driven implementations, this may be a no-op.
    fn poll(&mut self) {}
}

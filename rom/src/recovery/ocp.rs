// Licensed under the Apache-2.0 license

//! OCP Recovery [`ImageProvider`](super::ImageProvider) implementation.
//!
//! Wraps the OCP [`RecoveryStateMachine`] and implements the ROM's `ImageProvider`
//! trait so that the host can push recovery images over USB via the OCP Secure
//! Firmware Recovery v1.1 protocol.

use super::ImageProvider;
use ocp::error::OcpError;
use ocp::interface::{RecoveryAction, RecoveryCmsRegion, RecoveryStateMachine};
use ocp::protocol::device_status::RecoveryReasonCode;
use ocp::usb::driver::UsbDeviceDriver;
use ocp::vendor::VendorHandler;

/// Tracks which type of CMS region is being used for the current transfer.
enum ActiveRegion {
    /// The full image is buffered in an indirect (memory-window) region.
    Indirect,
    /// Data is streamed through a FIFO region.
    Fifo,
}

/// An [`ImageProvider`] backed by the OCP Recovery state machine.
///
/// The host pushes recovery image data over USB using the OCP protocol. The
/// provider drives `process_command()` internally and exposes the received
/// image through the `ImageProvider` interface.
///
/// Behavior depends on the CMS region type selected by the host via
/// `RECOVERY_CTRL`:
///
/// - **Indirect region**: `image_ready()` blocks until `ActivateRecoveryImage`
///   is returned (the full image is in the buffer). `next_bytes()` reads
///   directly from the region.
///
/// - **FIFO region**: `image_ready()` blocks until the image size is known
///   (via `INDIRECT_FIFO_CTRL`). `next_bytes()` continues to drive
///   `process_command()` and drains the FIFO incrementally.
pub struct OcpImageProvider<'a, U: UsbDeviceDriver, V: VendorHandler> {
    state_machine: RecoveryStateMachine<'a, U, V>,
    image_size: usize,
    bytes_read: usize,
    active_cms: u8,
    active_region: Option<ActiveRegion>,
    transport_initialized: bool,
}

impl<'a, U: UsbDeviceDriver, V: VendorHandler> OcpImageProvider<'a, U, V> {
    /// Create a new OCP image provider wrapping the given state machine.
    pub fn new(state_machine: RecoveryStateMachine<'a, U, V>) -> Self {
        Self {
            state_machine,
            image_size: 0,
            bytes_read: 0,
            active_cms: 0,
            active_region: None,
            transport_initialized: false,
        }
    }

    /// Process one OCP command, retrying on transport errors.
    ///
    /// Returns the resulting [`RecoveryAction`] or an error if the
    /// transport fails with a non-transient error.
    fn next_action(&mut self) -> Result<RecoveryAction, ()> {
        // Iterate through the process command, until either a valid command took place, or an
        // unrecoverable error occurred.  If the transport errored, repeat the command, hoping
        // for an intermittent failure.
        //
        // Start with a transport error to jump start the loop.
        let mut action = Err(OcpError::TransportError(0));
        while matches!(action, Err(OcpError::TransportError(_))) {
            action = self.state_machine.process_command();
        }

        action.map_err(|_| ())
    }

    /// Returns true if the CMS index selected by the host has changed since
    /// `image_ready()` recorded `active_cms`.
    fn cms_changed(&self) -> bool {
        match self.active_region {
            Some(ActiveRegion::Fifo) => self.state_machine.fifo_ctrl_cms() != self.active_cms,
            _ => self.state_machine.recovery_ctrl_cms() != self.active_cms,
        }
    }
}

impl<U: UsbDeviceDriver, V: VendorHandler> ImageProvider for OcpImageProvider<'_, U, V> {
    fn image_ready(&mut self, _image_index: u32) -> Result<usize, ()> {
        self.bytes_read = 0;
        self.image_size = 0;
        self.active_region = None;

        if !self.transport_initialized {
            self.state_machine.init_transport().map_err(|_| ())?;
            self.state_machine
                .enter_recovery(RecoveryReasonCode::CorruptedMissingCriticalData);
            self.transport_initialized = true;
        }

        // Drive the command loop until we can determine the region type and image size.
        loop {
            match self.next_action()? {
                RecoveryAction::ActivateRecoveryImage => {
                    // Host wrote the full image into an indirect region and activated.
                    self.active_cms = self.state_machine.recovery_ctrl_cms();
                    let region = self.state_machine.recovery_cms_region().ok_or(())?;
                    match region {
                        RecoveryCmsRegion::Indirect(r) => {
                            self.image_size = r.imo() as usize;
                            self.active_region = Some(ActiveRegion::Indirect);
                            return Ok(self.image_size);
                        }
                        RecoveryCmsRegion::Fifo(_) => {
                            // Activation before we started streaming — treat as error.
                            return Err(());
                        }
                    }
                }
                RecoveryAction::IndirectFifoCtrlChanged => {
                    let image_size = self.state_machine.fifo_image_size();
                    if image_size > 0 {
                        self.image_size = image_size as usize;
                        self.active_cms = self.state_machine.fifo_ctrl_cms();
                        self.active_region = Some(ActiveRegion::Fifo);
                        return Ok(self.image_size);
                    }
                }
                _ => continue,
            }
        }
    }

    fn next_bytes(&mut self, data: &mut [u8]) -> Result<(), ()> {
        match self.active_region.as_ref().ok_or(())? {
            ActiveRegion::Indirect => {
                let region = self.state_machine.recovery_cms_region().ok_or(())?;
                match region {
                    RecoveryCmsRegion::Indirect(r) => {
                        let n = r.device_read(self.bytes_read as u32, data);
                        self.bytes_read += n;
                        Ok(())
                    }
                    RecoveryCmsRegion::Fifo(_) => Err(()),
                }
            }
            ActiveRegion::Fifo => {
                let mut filled = 0;
                let mut activation_received = false;
                // The loop continues while either:
                // 1. The buffer needs more data and there is data remaining
                //    in the image (normal streaming path), OR
                // 2. All data was drained but the activation command hasn't
                //    arrived yet — the pending SETUP must be consumed so its
                //    ZLP is sent and the host's control transfer completes.
                while (filled < data.len() && self.bytes_read < self.image_size)
                    || (!activation_received && self.bytes_read >= self.image_size)
                {
                    // Try to drain data from the FIFO. Uses device_drain
                    // rather than pop because pop enforces host-side access
                    // control (e.g. CodeSpace is write-only from the host's
                    // perspective) while the device must always be able to
                    // consume the data.
                    let fifo = self.state_machine.fifo_cms_region().ok_or(())?;
                    match fifo.device_drain(&mut data[filled..]) {
                        Ok(n) if n > 0 => {
                            filled += n;
                            self.bytes_read += n;
                        }
                        _ => {
                            // FIFO empty — process one command from the host,
                            // then retry the drain so the FIFO can empty between
                            // host writes instead of overflowing.
                            match self.next_action()? {
                                RecoveryAction::ActivateRecoveryImage => {
                                    self.bytes_read = self.image_size;
                                    activation_received = true;
                                }
                                _ => {
                                    if self.cms_changed() {
                                        return Err(());
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(())
            }
        }
    }

    fn bytes_loaded(&self) -> usize {
        self.bytes_read
    }
}

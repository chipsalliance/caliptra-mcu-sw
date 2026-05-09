// Licensed under the Apache-2.0 license

//! Shared test infrastructure for OCP integration tests.

extern crate alloc;

use alloc::vec::Vec;
use core::cell::RefCell;

use ocp::error::OcpError;
use ocp::interface::RecoveryDeviceConfig;
use ocp::protocol::device_id::{DeviceDescriptor, DeviceId, PciVendorDescriptor};
use ocp::protocol::RecoveryCommand;
use ocp::usb::driver::{RecoveryRequest, UsbDeviceDriver, UsbDriverError};

enum MockRequest {
    Read { len: u16 },
    Write { data: Vec<u8> },
}

/// Mock USB device driver that stores sent responses in a shared `RefCell`
/// so the test can inspect them even though the state machine owns the driver.
pub struct MockUsbDeviceDriver<'a> {
    recv_queue: Vec<(RecoveryCommand, MockRequest)>,
    recv_idx: usize,
    send_buf: [u8; 256],
    sent: &'a RefCell<Vec<Vec<u8>>>,
}

impl<'a> MockUsbDeviceDriver<'a> {
    pub fn new(sent: &'a RefCell<Vec<Vec<u8>>>) -> Self {
        Self {
            recv_queue: Vec::new(),
            recv_idx: 0,
            send_buf: [0u8; 256],
            sent,
        }
    }

    pub fn enqueue_read(&mut self, cmd: RecoveryCommand) {
        self.recv_queue.push((cmd, MockRequest::Read { len: 255 }));
    }

    pub fn enqueue_write(&mut self, cmd: RecoveryCommand, data: &[u8]) {
        self.recv_queue.push((
            cmd,
            MockRequest::Write {
                data: data.to_vec(),
            },
        ));
    }
}

impl UsbDeviceDriver for MockUsbDeviceDriver<'_> {
    fn init(&mut self) -> Result<(), UsbDriverError> {
        Ok(())
    }

    fn recv(&mut self) -> Result<(RecoveryCommand, RecoveryRequest<'_>), UsbDriverError> {
        if self.recv_idx >= self.recv_queue.len() {
            return Err(UsbDriverError::NoPendingCommand);
        }
        let idx = self.recv_idx;
        self.recv_idx += 1;
        let (cmd, ref req) = self.recv_queue[idx];
        match req {
            MockRequest::Read { len } => Ok((cmd, RecoveryRequest::Read { len: *len })),
            MockRequest::Write { data } => Ok((cmd, RecoveryRequest::Write { data })),
        }
    }

    fn send(
        &mut self,
        populate_buffer: &mut dyn FnMut(&mut [u8]) -> Result<usize, OcpError>,
    ) -> Result<(), UsbDriverError> {
        let n = populate_buffer(&mut self.send_buf).map_err(UsbDriverError::OcpError)?;
        self.sent.borrow_mut().push(self.send_buf[..n].to_vec());
        Ok(())
    }

    fn stall_endpoint(&mut self) -> Result<(), UsbDriverError> {
        Ok(())
    }
}

pub fn test_config() -> RecoveryDeviceConfig<'static> {
    let desc = DeviceDescriptor::PciVendor(PciVendorDescriptor::new(0x1234, 0x5678, 0, 0, 0));
    RecoveryDeviceConfig {
        device_id: DeviceId::new(desc, &[]).unwrap(),
        major_version: 1,
        minor_version: 1,
        max_response_time: 17,
        heartbeat_period: 0,
        local_c_image_support: false,
    }
}

pub fn test_config_with_local_c_image() -> RecoveryDeviceConfig<'static> {
    RecoveryDeviceConfig {
        local_c_image_support: true,
        ..test_config()
    }
}

pub fn take_last_response(sent: &RefCell<Vec<Vec<u8>>>) -> Vec<u8> {
    sent.borrow_mut()
        .pop()
        .expect("expected a response but none was sent")
}

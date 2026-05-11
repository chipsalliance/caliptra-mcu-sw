// Licensed under the Apache-2.0 license

//! Test firmware exercising [`ExamplarUsbDriver`] for OCP Recovery over USB.
//!
//! Enumerates as a USB device, then responds to OCP recovery commands:
//!   - PROT_CAP read  → returns a fixed 15-byte response
//!   - DEVICE_STATUS read → returns a fixed 3-byte response
//!   - Any other read → STALLs EP0
//!   - Any write      → already ACKed by the driver

#![no_main]
#![no_std]

use mcu_usb_emulator::ExamplarUsbDriver;
use ocp::protocol::device_status::{
    DeviceStatus, DeviceStatusValue, ProtocolError, RecoveryReasonCode,
};
use ocp::protocol::prot_cap::{ProtCap, RecoveryProtocolCapabilities};
use ocp::protocol::RecoveryCommand;
use ocp::usb::driver::{RecoveryRequest, UsbDeviceDriver, UsbDriverError};
use registers_generated::usbdev;
use romtime::StaticRef;
use zerocopy::IntoBytes;

extern crate mcu_rom_common;

fn prot_cap_response() -> ProtCap {
    let mut caps = RecoveryProtocolCapabilities(0);
    caps.set_identification(true);
    caps.set_device_status(true);
    caps.set_push_c_image_support(true);
    caps.set_recovery_memory_access(true);
    ProtCap::new(1, 0, caps, 1, 0, 0)
}

fn run() -> ! {
    let regs = unsafe { StaticRef::new(usbdev::USBDEV_ADDR as *const _) };
    let mut driver = ExamplarUsbDriver::new(regs);

    driver.init().unwrap();

    loop {
        match driver.recv() {
            Ok((cmd, req)) => match (cmd, req) {
                (RecoveryCommand::ProtCap, RecoveryRequest::Read { .. }) => {
                    let resp = prot_cap_response();
                    let _ = driver.send(&mut |buf| {
                        let bytes = resp.as_bytes();
                        buf[..bytes.len()].copy_from_slice(bytes);
                        Ok(bytes.len())
                    });
                }
                (RecoveryCommand::DeviceStatus, RecoveryRequest::Read { .. }) => {
                    let ds = DeviceStatus::new(
                        DeviceStatusValue::StatusPending,
                        ProtocolError::NoError,
                        RecoveryReasonCode::NoBootFailure,
                        0,
                        &[],
                    )
                    .unwrap();
                    let _ = driver.send(&mut |buf| Ok(ds.to_message(buf).unwrap()));
                }
                (_, RecoveryRequest::Read { .. }) => {
                    let _ = driver.stall_endpoint();
                }
                (_, RecoveryRequest::Write { .. }) => {}
            },
            Err(UsbDriverError::NoPendingCommand) => {}
            Err(_) => {}
        }
    }
}

#[no_mangle]
pub extern "C" fn main() {
    mcu_test_harness::set_printer();
    run();
}

// Licensed under the Apache-2.0 license

//! Host-side USB control transfer helpers for hardware-model tests.
//!
//! Each function steps the model in a polling loop until the emulated
//! USB device responds, panicking on timeout or unexpected errors.

use crate::McuHwModel;
use emulator_periph::{UsbHostController, UsbTransactionError};
use ocp::usb::setup::{BmRequestType, SetupPacket, StandardRequest};
use zerocopy::IntoBytes;

/// Perform an IN transaction on EP0, retrying on NAK.
///
/// Returns the received data payload.
///
/// # Panics
///
/// Panics if the device does not respond within `iterations`
/// steps or returns an unexpected error.
pub fn poll_in(
    model: &mut impl McuHwModel,
    host: &UsbHostController,
    iterations: usize,
) -> Vec<u8> {
    for _ in 0..iterations {
        model.step();
        match host.host_in(0) {
            Ok(data) => return data,
            Err(UsbTransactionError::Nak) => continue,
            Err(e) => panic!("unexpected host_in error: {:?}", e),
        }
    }
    panic!("timed out waiting for IN data");
}

/// Perform an IN transaction on EP0, expecting a STALL response.
///
/// # Panics
///
/// Panics if the device does not STALL within `iterations`
/// steps or returns an unexpected response.
pub fn poll_in_stall(model: &mut impl McuHwModel, host: &UsbHostController, iterations: usize) {
    for _ in 0..iterations {
        model.step();
        match host.host_in(0) {
            Err(UsbTransactionError::Stall) => return,
            Err(UsbTransactionError::Nak) => continue,
            other => panic!("expected STALL, got {:?}", other),
        }
    }
    panic!("timed out waiting for STALL");
}

/// Send a SETUP packet on EP0, retrying while the device has no
/// available setup buffer.
///
/// # Panics
///
/// Panics if the device does not accept the SETUP within
/// `iterations` steps or returns an unexpected error.
pub fn poll_setup(
    model: &mut impl McuHwModel,
    host: &UsbHostController,
    setup: &SetupPacket,
    iterations: usize,
) {
    let data = setup.as_bytes();
    for _ in 0..iterations {
        model.step();
        match host.host_setup(0, data) {
            Ok(()) => return,
            Err(UsbTransactionError::NoBuffer) => continue,
            Err(e) => panic!("unexpected host_setup error: {:?}", e),
        }
    }
    panic!("timed out waiting for setup buffer");
}

/// Send an OUT data packet on EP0, retrying on NAK.
///
/// # Panics
///
/// Panics if the device does not accept the OUT within
/// `iterations` steps or returns an unexpected error.
pub fn poll_out(
    model: &mut impl McuHwModel,
    host: &UsbHostController,
    data: &[u8],
    iterations: usize,
) {
    for _ in 0..iterations {
        model.step();
        match host.host_out(0, data) {
            Ok(()) => return,
            Err(UsbTransactionError::Nak) => continue,
            Err(e) => panic!("unexpected host_out error: {:?}", e),
        }
    }
    panic!("timed out waiting for host_out");
}

/// Build a standard USB SETUP packet (Device-to-Host).
pub fn std_request_in(request: StandardRequest, w_value: u16, w_length: u16) -> SetupPacket {
    SetupPacket {
        bm_request_type: BmRequestType(0x80),
        b_request: request as u8,
        w_value: w_value.to_le_bytes(),
        w_index: [0x00, 0x00],
        w_length,
    }
}

/// Build a standard USB SETUP packet (Host-to-Device).
pub fn std_request_out(request: StandardRequest, w_value: u16) -> SetupPacket {
    SetupPacket {
        bm_request_type: BmRequestType(0x00),
        b_request: request as u8,
        w_value: w_value.to_le_bytes(),
        w_index: [0x00, 0x00],
        w_length: 0,
    }
}

/// Build an OCP Recovery read SETUP packet (Device-to-Host, Class, Interface).
pub fn ocp_read(command: ocp::protocol::RecoveryCommand, w_length: u16) -> SetupPacket {
    SetupPacket {
        bm_request_type: BmRequestType(0xA1),
        b_request: 0x00,
        w_value: [command as u8, 0x00],
        w_index: [0x00, 0x00],
        w_length,
    }
}

/// Build an OCP Recovery write SETUP packet (Host-to-Device, Class, Interface).
pub fn ocp_write(command: ocp::protocol::RecoveryCommand, w_length: u16) -> SetupPacket {
    SetupPacket {
        bm_request_type: BmRequestType(0x21),
        b_request: 0x00,
        w_value: [command as u8, 0x00],
        w_index: [0x00, 0x00],
        w_length,
    }
}

fn desc_value(dt: ocp::usb::descriptors::DescriptorType, idx: u8) -> u16 {
    ((dt as u16) << 8) | idx as u16
}

/// Drive a minimal USB enumeration sequence through the emulated host.
///
/// Sends GET_DESCRIPTOR(Device), SET_ADDRESS(1),
/// GET_DESCRIPTOR(Configuration), and SET_CONFIGURATION(1), asserting
/// that the device responds correctly at each step.
///
/// Call [`UsbHostController::bus_reset`] before this function so the
/// firmware can proceed past its link-reset wait.
pub fn enumerate(model: &mut impl McuHwModel, host: &UsbHostController, iterations: usize) {
    use ocp::usb::descriptors::DescriptorType;

    // GET_DESCRIPTOR(Device), wLength=18
    let setup = std_request_in(
        StandardRequest::GetDescriptor,
        desc_value(DescriptorType::Device, 0),
        18,
    );
    poll_setup(model, host, &setup, iterations);
    let desc = poll_in(model, host, iterations);
    assert_eq!(desc.len(), 18, "device descriptor length");
    assert_eq!(desc[1], DescriptorType::Device as u8);
    poll_out(model, host, &[], iterations);

    // SET_ADDRESS(1)
    let setup = std_request_out(StandardRequest::SetAddress, 1);
    poll_setup(model, host, &setup, iterations);
    let zlp = poll_in(model, host, iterations);
    assert!(zlp.is_empty(), "SET_ADDRESS status should be ZLP");

    // GET_DESCRIPTOR(Configuration), wLength=64
    let setup = std_request_in(
        StandardRequest::GetDescriptor,
        desc_value(DescriptorType::Configuration, 0),
        64,
    );
    poll_setup(model, host, &setup, iterations);
    let config = poll_in(model, host, iterations);
    assert_eq!(config[1], DescriptorType::Configuration as u8);
    poll_out(model, host, &[], iterations);

    // SET_CONFIGURATION(1)
    let setup = std_request_out(StandardRequest::SetConfiguration, 1);
    poll_setup(model, host, &setup, iterations);
    let zlp = poll_in(model, host, iterations);
    assert!(zlp.is_empty(), "SET_CONFIGURATION status should be ZLP");
}

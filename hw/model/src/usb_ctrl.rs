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

/// Perform a complete OCP Recovery read command: SETUP + IN data + OUT ZLP status.
///
/// Returns the response data payload.
pub fn ocp_read_data(
    model: &mut impl McuHwModel,
    host: &UsbHostController,
    command: ocp::protocol::RecoveryCommand,
    len: u16,
    iterations: usize,
) -> Vec<u8> {
    let setup = ocp_read(command, len);
    poll_setup(model, host, &setup, iterations);
    let data = poll_in(model, host, iterations);
    poll_out(model, host, &[], iterations);
    data
}

/// Perform a complete OCP Recovery write command: SETUP + OUT data + IN ZLP status.
pub fn ocp_write_data(
    model: &mut impl McuHwModel,
    host: &UsbHostController,
    command: ocp::protocol::RecoveryCommand,
    data: &[u8],
    iterations: usize,
) {
    let setup = ocp_write(command, data.len() as u16);
    poll_setup(model, host, &setup, iterations);
    poll_out(model, host, data, iterations);
    let _zlp = poll_in(model, host, iterations);
}

/// Write INDIRECT_CTRL to select an indirect CMS region and set the IMO.
pub fn ocp_select_indirect_cms(
    model: &mut impl McuHwModel,
    host: &UsbHostController,
    cms: u8,
    imo: u32,
    iterations: usize,
) {
    let imo_bytes = imo.to_le_bytes();
    let data = [
        cms,
        0x00,
        imo_bytes[0],
        imo_bytes[1],
        imo_bytes[2],
        imo_bytes[3],
    ];
    ocp_write_data(
        model,
        host,
        ocp::protocol::RecoveryCommand::IndirectCtrl,
        &data,
        iterations,
    );
}

/// Write INDIRECT_DATA payload at the current IMO (auto-increments).
pub fn ocp_write_indirect_data(
    model: &mut impl McuHwModel,
    host: &UsbHostController,
    data: &[u8],
    iterations: usize,
) {
    ocp_write_data(
        model,
        host,
        ocp::protocol::RecoveryCommand::IndirectData,
        data,
        iterations,
    );
}

/// Write INDIRECT_FIFO_CTRL to select a FIFO CMS region and set the image size.
///
/// `image_size_4b` is the image size in 4-byte units.
pub fn ocp_select_fifo_cms(
    model: &mut impl McuHwModel,
    host: &UsbHostController,
    cms: u8,
    image_size_4b: u32,
    iterations: usize,
) {
    let size_bytes = image_size_4b.to_le_bytes();
    let data = [
        cms,
        0x00,
        size_bytes[0],
        size_bytes[1],
        size_bytes[2],
        size_bytes[3],
    ];
    ocp_write_data(
        model,
        host,
        ocp::protocol::RecoveryCommand::IndirectFifoCtrl,
        &data,
        iterations,
    );
}

/// Write INDIRECT_FIFO_DATA payload (streamed into FIFO).
pub fn ocp_write_fifo_data(
    model: &mut impl McuHwModel,
    host: &UsbHostController,
    data: &[u8],
    iterations: usize,
) {
    ocp_write_data(
        model,
        host,
        ocp::protocol::RecoveryCommand::IndirectFifoData,
        data,
        iterations,
    );
}

/// Write RECOVERY_CTRL to activate a recovery image from a memory-window CMS.
///
/// Sends CMS index, ImageSelection::MemoryWindow (0x01), and Activate (0x0F).
pub fn ocp_activate_recovery(
    model: &mut impl McuHwModel,
    host: &UsbHostController,
    cms: u8,
    iterations: usize,
) {
    let data = [cms, 0x01, 0x0F];
    ocp_write_data(
        model,
        host,
        ocp::protocol::RecoveryCommand::RecoveryCtrl,
        &data,
        iterations,
    );
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

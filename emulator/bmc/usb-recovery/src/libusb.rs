// Licensed under the Apache-2.0 license

//! Linux performs enumeration; this adapter claims only an already configured
//! OCP recovery interface. It never detaches a kernel driver or resets a device.

use crate::{RecoveryTransport, CONTROL_MAX_BYTES};
use anyhow::{bail, ensure, Context, Result};
use caliptra_mcu_ocp::protocol::RecoveryCommand;
use rusb::{DeviceHandle, GlobalContext, UsbContext};
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub struct DeviceSelector {
    pub vendor_id: u16,
    pub product_id: u16,
    pub bus: Option<u8>,
    pub address: Option<u8>,
}

pub struct LibusbTransport {
    handle: DeviceHandle<GlobalContext>,
    interface: u8,
}

impl LibusbTransport {
    pub fn open(selector: DeviceSelector) -> Result<Self> {
        let devices = rusb::GlobalContext::default()
            .devices()
            .context("enumerate USB devices")?;
        let mut selected = None;
        for device in devices.iter() {
            let descriptor = device
                .device_descriptor()
                .context("read USB device descriptor")?;
            if descriptor.vendor_id() != selector.vendor_id
                || descriptor.product_id() != selector.product_id
                || selector.bus.is_some_and(|bus| device.bus_number() != bus)
                || selector
                    .address
                    .is_some_and(|address| device.address() != address)
            {
                continue;
            }
            ensure!(
                selected.is_none(),
                "multiple matching USB devices; specify --bus and --address"
            );
            selected = Some(device);
        }
        let device = selected.context(format!(
            "USB device {:04x}:{:04x} not found; check Linux enumeration and device selection",
            selector.vendor_id, selector.product_id
        ))?;
        let descriptor = device
            .device_descriptor()
            .context("read selected device descriptor")?;
        ensure!(
            descriptor.max_packet_size() == 64,
            "unsupported EP0 packet size"
        );
        let handle = device
            .open()
            .context("open USB device; check /dev/bus/usb permissions")?;
        let configuration = handle
            .active_configuration()
            .context("read active Linux USB configuration")?;
        ensure!(
            configuration != 0,
            "Linux has not configured the USB device"
        );
        let mut interface = None;
        for index in 0..descriptor.num_configurations() {
            let config = device
                .config_descriptor(index)
                .context("read configuration descriptor")?;
            if config.number() != configuration {
                continue;
            }
            for candidate in config.interfaces().flat_map(|group| group.descriptors()) {
                if candidate.class_code() == 0xef
                    && candidate.sub_class_code() == 8
                    && candidate.protocol_code() == 1
                    && candidate.setting_number() == 0
                {
                    validate_functional_descriptor(candidate.extra())?;
                    ensure!(interface.is_none(), "multiple OCP recovery interfaces");
                    interface = Some(candidate.interface_number());
                }
            }
        }
        let interface =
            interface.context("configured device has no supported OCP recovery interface")?;
        handle.claim_interface(interface).with_context(|| {
            format!(
                "claim OCP recovery interface {interface}; check permissions and competing users"
            )
        })?;
        Ok(Self { handle, interface })
    }

    /// Explicitly report release errors; rusb also releases claims when dropped.
    pub fn close(self) -> Result<()> {
        self.handle
            .release_interface(self.interface)
            .context("release OCP recovery interface")
    }
}

fn validate_functional_descriptor(mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        let length = usize::from(bytes[0]);
        ensure!(
            length >= 2 && length <= bytes.len(),
            "malformed interface extra descriptor"
        );
        if bytes[1] == 0x24 {
            ensure!(
                length == 10 && bytes[2] == 1 && bytes[3] == 0,
                "unsupported OCP functional descriptor"
            );
            let input = u16::from_le_bytes([bytes[4], bytes[5]]);
            let output = u16::from_le_bytes([bytes[6], bytes[7]]);
            ensure!(
                input >= 64 && output >= 64 && bytes[8..10] == [1, 1],
                "unsupported OCP transfer limits/version"
            );
            return Ok(());
        }
        bytes = &bytes[length..];
    }
    bail!("missing OCP functional descriptor")
}

fn bounded_timeout(timeout: Duration) -> Result<Duration> {
    // rusb casts milliseconds to u32; zero means an unlimited libusb timeout.
    let milliseconds = u32::try_from(timeout.as_millis())
        .context("libusb timeout exceeds the 32-bit millisecond limit")?;
    ensure!(
        milliseconds != 0,
        "libusb transfer timeout: less than one millisecond remains"
    );
    Ok(Duration::from_millis(u64::from(milliseconds)))
}

impl RecoveryTransport for LibusbTransport {
    fn read(
        &mut self,
        command: RecoveryCommand,
        response: &mut [u8; CONTROL_MAX_BYTES],
        timeout: Duration,
    ) -> Result<usize> {
        let timeout = bounded_timeout(timeout)?;
        self.handle
            .read_control(
                0xa1,
                0,
                command as u16,
                u16::from(self.interface),
                response,
                timeout,
            )
            .with_context(|| format!("{command:?} libusb IN (including data/status stages)"))
    }

    fn write(&mut self, command: RecoveryCommand, data: &[u8], timeout: Duration) -> Result<()> {
        let timeout = bounded_timeout(timeout)?;
        ensure!(
            !data.is_empty() && data.len() <= CONTROL_MAX_BYTES,
            "invalid control OUT length"
        );
        let written = self
            .handle
            .write_control(
                0x21,
                0,
                command as u16,
                u16::from(self.interface),
                data,
                timeout,
            )
            .with_context(|| format!("{command:?} libusb OUT; transfer is not replayed"))?;
        ensure!(
            written == data.len(),
            "{command:?} short write: {written}/{}",
            data.len()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_functional_descriptor_and_limits() {
        let valid = [10, 0x24, 1, 0, 64, 0, 64, 0, 1, 1];
        validate_functional_descriptor(&valid).unwrap();
        for index in [0, 1, 2, 3, 4, 6, 8, 9] {
            let mut invalid = valid;
            invalid[index] = if valid[index] == 0 { 1 } else { 0 };
            assert!(
                validate_functional_descriptor(&invalid).is_err(),
                "byte {index}"
            );
        }
        assert!(validate_functional_descriptor(&valid[..9]).is_err());
        assert!(validate_functional_descriptor(&[]).is_err());
    }

    #[test]
    fn timeout_conversion_cannot_disable_or_wrap_a_deadline() {
        assert!(bounded_timeout(Duration::ZERO)
            .unwrap_err()
            .to_string()
            .contains("timeout"));
        assert!(bounded_timeout(Duration::from_nanos(999_999)).is_err());
        assert!(bounded_timeout(Duration::from_millis(u64::from(u32::MAX) + 1)).is_err());
        assert_eq!(
            bounded_timeout(Duration::from_nanos(1_999_999)).unwrap(),
            Duration::from_millis(1)
        );
    }
}

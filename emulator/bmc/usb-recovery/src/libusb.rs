// Licensed under the Apache-2.0 license

//! `libusb`-backed [`RecoveryTransport`] implementation.

use crate::{RecoveryTransport, CONTROL_MAX_BYTES};
use anyhow::{bail, ensure, Context, Result};
use caliptra_mcu_ocp::protocol::RecoveryCommand;
use rusb::{DeviceHandle, GlobalContext, UsbContext};
use std::time::Duration;

/// USB device filter used by [`LibusbTransport::open`].
#[derive(Clone, Copy, Debug)]
pub struct DeviceSelector {
    pub vendor_id: u16,
    pub product_id: u16,
    pub bus: Option<u8>,
    pub address: Option<u8>,
}

impl DeviceSelector {
    fn matches<T: UsbContext>(
        &self,
        device: &rusb::Device<T>,
        desc: &rusb::DeviceDescriptor,
    ) -> bool {
        desc.vendor_id() == self.vendor_id
            && desc.product_id() == self.product_id
            && self.bus.is_none_or(|bus| device.bus_number() == bus)
            && self.address.is_none_or(|addr| device.address() == addr)
    }
}

/// [`RecoveryTransport`] backed by `rusb` (`libusb`) control transfers.
pub struct LibusbTransport {
    handle: DeviceHandle<GlobalContext>,
    interface: u8,
    timeout: Duration,
}

impl LibusbTransport {
    fn is_ocp_recovery_interface(desc: &rusb::InterfaceDescriptor<'_>) -> bool {
        (
            desc.class_code(),
            desc.sub_class_code(),
            desc.protocol_code(),
            desc.setting_number(),
        ) == (0xef, 0x08, 0x01, 0)
    }

    /// Open the configured USB device matching `selector`, validate its OCP
    /// Recovery v1.1 interface and functional descriptor, claim the interface,
    /// and apply `timeout` to each control transfer.
    pub fn open(selector: DeviceSelector, timeout: Duration) -> Result<Self> {
        // `rusb` passes `timeout.as_millis() as c_uint` to `libusb`, where `0` blocks forever.
        ensure!(
            (1..=u128::from(u32::MAX)).contains(&timeout.as_millis()),
            "libusb transfer timeout must be between 1 ms and {} ms",
            u32::MAX
        );
        let devices = GlobalContext::default()
            .devices()
            .context("enumerate USB devices")?;
        let matches = devices
            .iter()
            .filter_map(|device| match device.device_descriptor() {
                Ok(desc) => selector
                    .matches(&device, &desc)
                    .then_some(Ok((device, desc))),
                Err(err) => Some(Err(err).context("read USB device descriptor")),
            })
            .collect::<Result<Vec<_>>>()?;
        let (device, descriptor) = match matches.as_slice() {
            [] => bail!(
                "USB device {:04x}:{:04x} not found; check Linux enumeration and device selection",
                selector.vendor_id,
                selector.product_id
            ),
            [(device, descriptor)] => (device, descriptor),
            _ => bail!("multiple matching USB devices; specify bus and address"),
        };
        ensure!(
            descriptor.max_packet_size() == 64,
            "unsupported EP0 packet size"
        );

        let config = device.active_config_descriptor().map_err(|err| match err {
            rusb::Error::NotFound => anyhow::anyhow!("Linux has not configured the USB device"),
            other => anyhow::Error::new(other).context("read active Linux USB configuration"),
        })?;
        let interfaces = config
            .interfaces()
            .flat_map(|group| group.descriptors())
            .filter(Self::is_ocp_recovery_interface)
            .map(|desc| {
                Self::validate_functional_descriptor(desc.extra())?;
                Ok(desc.interface_number())
            })
            .collect::<Result<Vec<_>>>()?;
        let interface = match interfaces.as_slice() {
            [] => bail!("configured device has no supported OCP recovery interface"),
            &[interface] => interface,
            _ => bail!("multiple OCP recovery interfaces"),
        };

        let handle = device
            .open()
            .context("open USB device; check /dev/bus/usb permissions")?;
        handle.claim_interface(interface).with_context(|| {
            format!(
                "claim OCP recovery interface {interface}; check permissions and competing users"
            )
        })?;
        Ok(Self {
            handle,
            interface,
            timeout,
        })
    }

    /// Release the claimed OCP recovery interface.
    pub fn close(self) -> Result<()> {
        self.handle
            .release_interface(self.interface)
            .context("release OCP recovery interface")
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
}

impl RecoveryTransport for LibusbTransport {
    fn read(
        &mut self,
        command: RecoveryCommand,
        response: &mut [u8; CONTROL_MAX_BYTES],
    ) -> Result<usize> {
        self.handle
            .read_control(
                0xa1,
                0,
                command as u16,
                u16::from(self.interface),
                response,
                self.timeout,
            )
            .with_context(|| format!("{command:?} libusb IN"))
    }

    fn write(&mut self, command: RecoveryCommand, data: &[u8]) -> Result<()> {
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
                self.timeout,
            )
            .with_context(|| format!("{command:?} libusb OUT"))?;
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
        LibusbTransport::validate_functional_descriptor(&valid).unwrap();
        for index in [0, 1, 2, 3, 4, 6, 8, 9] {
            let mut invalid = valid;
            invalid[index] = if valid[index] == 0 { 1 } else { 0 };
            assert!(
                LibusbTransport::validate_functional_descriptor(&invalid).is_err(),
                "byte {index}"
            );
        }
        assert!(LibusbTransport::validate_functional_descriptor(&valid[..9]).is_err());
        assert!(LibusbTransport::validate_functional_descriptor(&[]).is_err());
    }

    #[test]
    fn open_rejects_invalid_transfer_timeouts() {
        let selector = DeviceSelector {
            vendor_id: 0xffff,
            product_id: 0xffff,
            bus: None,
            address: None,
        };
        for invalid in [
            Duration::ZERO,
            Duration::from_nanos(999_999),
            Duration::from_millis(u64::from(u32::MAX) + 1),
        ] {
            let err = LibusbTransport::open(selector, invalid)
                .err()
                .expect("invalid timeout should fail");
            assert!(err.to_string().contains("timeout"));
        }
    }
}

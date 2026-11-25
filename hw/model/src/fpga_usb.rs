// Licensed under the Apache-2.0 license

//! Linux `usbcore` enumeration helpers for [`crate::ModelFpgaRealtime`].

use anyhow::{bail, ensure, Result};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::{McuHwModel, ModelFpgaRealtime};

const SYSFS_USB_DEVICES: &str = "/sys/bus/usb/devices";

/// Metadata reported by Linux `usbcore` in `/sys/bus/usb/devices/` once a
/// Caliptra USB device has been enumerated and configured (`bConfigurationValue == 1`).
#[derive(Clone, Debug)]
pub struct EnumeratedLinuxUsbDevice {
    pub sysfs_path: PathBuf,
    pub bus_num: u8,
    pub dev_num: u8,
    pub speed_mbps: u32,
    pub vendor_id: u16,
    pub product_id: u16,
    pub bcd_device: u16,
    pub num_interfaces: u8,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub raw_descriptors: Vec<u8>,
}

impl TryFrom<PathBuf> for EnumeratedLinuxUsbDevice {
    type Error = anyhow::Error;

    fn try_from(sysfs_path: PathBuf) -> Result<Self> {
        let read = |attr: &str| -> Result<String> {
            Ok(std::fs::read_to_string(sysfs_path.join(attr))?
                .trim()
                .to_string())
        };
        ensure!(read("bConfigurationValue")? == "1", "device not configured");

        Ok(Self {
            vendor_id: u16::from_str_radix(&read("idVendor")?, 16)?,
            product_id: u16::from_str_radix(&read("idProduct")?, 16)?,
            bcd_device: u16::from_str_radix(&read("bcdDevice")?, 16)?,
            bus_num: read("busnum")?.parse()?,
            dev_num: read("devnum")?.parse()?,
            speed_mbps: read("speed")?.parse()?,
            num_interfaces: read("bNumInterfaces")?.parse()?,
            manufacturer: read("manufacturer").ok(),
            product: read("product").ok(),
            raw_descriptors: std::fs::read(sysfs_path.join("descriptors"))?,
            sysfs_path,
        })
    }
}

fn find_configured_usb_device(
    vendor_id: u16,
    product_id: u16,
) -> Result<Option<EnumeratedLinuxUsbDevice>> {
    for entry in std::fs::read_dir(SYSFS_USB_DEVICES)? {
        if let Ok(dev) = EnumeratedLinuxUsbDevice::try_from(entry?.path()) {
            if dev.vendor_id == vendor_id && dev.product_id == product_id {
                return Ok(Some(dev));
            }
        }
    }
    Ok(None)
}

impl ModelFpgaRealtime {
    /// Step the hardware model until Linux `usbcore` has enumerated and
    /// configured (`bConfigurationValue == 1`) the target USB `vendor_id:product_id`.
    pub fn wait_for_usb_enumeration(
        &mut self,
        vendor_id: u16,
        product_id: u16,
        timeout: Duration,
    ) -> Result<EnumeratedLinuxUsbDevice> {
        let deadline = Instant::now() + timeout;

        loop {
            if let Some(device) = find_configured_usb_device(vendor_id, product_id)? {
                return Ok(device);
            }

            if Instant::now() >= deadline {
                bail!(
                    "Linux usbcore did not enumerate+configure {vendor_id:04x}:{product_id:04x} \
                     within {timeout:?}"
                );
            }

            for _ in 0..50 {
                self.step();
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

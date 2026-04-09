// Licensed under the Apache-2.0 license

//! Caliptra MCTP VDM Client Library
//!
//! Provides a high-level `VdmClient` for issuing MCTP VDM commands through the
//! `MctpVdmTransport` layer. The underlying I3C/MCTP transport is provided by
//! `MctpVdmSocketDriver`, which wraps the existing `MctpVdmSocket` from
//! `mcu-testing-common`.

mod network_driver;
pub mod validator;

pub use network_driver::MctpVdmSocketDriver;
pub use validator::{ValidationResult, Validator};

// Re-export shared config.
pub use caliptra_mcu_core_util_host_mctp_vdm_test_config::*;

// Re-export the I3C address type so callers don't need a direct dep.
pub use caliptra_mcu_testing_common::i3c::DynamicI3cAddress;

use anyhow::Result;
use caliptra_mcu_core_util_host_command_types::*;
use caliptra_mcu_core_util_host_transport::{MctpVdmTransport, Transport};

/// High-level MCTP VDM client.
pub struct VdmClient<'a> {
    transport: MctpVdmTransport<'a>,
}

impl<'a> VdmClient<'a> {
    /// Create a new `VdmClient` over any `MctpVdmDriver` implementation.
    pub fn new(driver: &'a mut dyn caliptra_mcu_core_util_host_transport::MctpVdmDriver) -> Self {
        let transport = MctpVdmTransport::new(driver);
        Self { transport }
    }

    /// Create a `VdmClient` backed by the common/testing MCTP VDM socket driver.
    pub fn with_socket_driver(driver: &'a mut MctpVdmSocketDriver) -> Self {
        let transport = MctpVdmTransport::new(
            driver as &mut dyn caliptra_mcu_core_util_host_transport::MctpVdmDriver,
        );
        Self { transport }
    }

    /// Connect the underlying transport.
    pub fn connect(&mut self) -> Result<()> {
        self.transport
            .connect()
            .map_err(|e| anyhow::anyhow!("VDM connect failed: {e:?}"))
    }

    /// Disconnect the underlying transport.
    pub fn disconnect(&mut self) -> Result<()> {
        self.transport
            .disconnect()
            .map_err(|e| anyhow::anyhow!("VDM disconnect failed: {e:?}"))
    }

    // ------------------------------------------------------------------
    // Device Information commands
    // ------------------------------------------------------------------

    /// Retrieve the device ID (VDM command 0x03).
    pub fn get_device_id(&mut self) -> Result<GetDeviceIdResponse> {
        let req = GetDeviceIdRequest {};
        self.send_command(CaliptraCommandId::GetDeviceId as u32, &req)
    }

    /// Retrieve device capabilities (VDM command 0x02).
    pub fn get_device_capabilities(&mut self) -> Result<GetDeviceCapabilitiesResponse> {
        let req = GetDeviceCapabilitiesRequest {};
        self.send_command(CaliptraCommandId::GetDeviceCapabilities as u32, &req)
    }

    /// Retrieve the firmware version for the given index (VDM command 0x01).
    pub fn get_firmware_version(&mut self, fw_id: u32) -> Result<GetFirmwareVersionResponse> {
        let req = GetFirmwareVersionRequest { index: fw_id };
        self.send_command(CaliptraCommandId::GetFirmwareVersion as u32, &req)
    }

    /// Retrieve device info for the given index (VDM command 0x04).
    pub fn get_device_info(&mut self) -> Result<GetDeviceInfoResponse> {
        let req = GetDeviceInfoRequest { info_type: 0 };
        self.send_command(CaliptraCommandId::GetDeviceInfo as u32, &req)
    }

    // ------------------------------------------------------------------
    // Generic send helper
    // ------------------------------------------------------------------

    fn send_command<Req, Resp>(&mut self, command_id: u32, req: &Req) -> Result<Resp>
    where
        Req: zerocopy::IntoBytes + zerocopy::Immutable,
        Resp: zerocopy::FromBytes,
    {
        let payload = req.as_bytes();
        self.transport
            .send(command_id, payload)
            .map_err(|e| anyhow::anyhow!("VDM send failed: {e:?}"))?;

        let mut buf = vec![0u8; 2048];
        let n = self
            .transport
            .receive(&mut buf)
            .map_err(|e| anyhow::anyhow!("VDM receive failed: {e:?}"))?;
        if n == 0 {
            anyhow::bail!("Empty response from device");
        }

        Resp::read_from_bytes(&buf[..n])
            .map_err(|_| anyhow::anyhow!("Failed to parse response ({n} bytes)"))
    }
}

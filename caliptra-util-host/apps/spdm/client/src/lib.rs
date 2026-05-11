// Licensed under the Apache-2.0 license

//! Caliptra SPDM VDM Client Library
//!
//! Provides a high-level typed API for Caliptra VDM commands over SPDM transport.
//! The `SpdmVdmClient` wraps an `SpdmVdmDriver` and uses `CaliptraSession` and
//! command APIs for typed request/response handling.
//!
//! Also provides validation tooling for integration testing.
//!
//! # Usage
//!
//! ```ignore
//! let mut client = SpdmVdmClient::new(&mut vdm_driver);
//! client.connect()?;
//! let response = client.export_attested_csr(0x0001, 0x0001, &nonce)?;
//! println!("CSR: {} bytes", response.data_len);
//! ```

pub mod config;
pub mod validator;

pub use config::TestConfig;
pub use validator::{all_passed, print_summary, run_all, ValidationResult, ValidationStatus};

use anyhow::Result;
use caliptra_mcu_core_util_host_command_types::certificate::{
    ExportAttestedCsrResponse, ExportIdevidCsrResponse,
};
use caliptra_mcu_core_util_host_command_types::{
    GetDeviceCapabilitiesResponse, GetDeviceIdResponse, GetDeviceInfoResponse,
    GetFirmwareVersionResponse,
};
use caliptra_mcu_core_util_host_transport::transports::spdm_vdm::transport::{
    SpdmVdmDriver, SpdmVdmTransport,
};
use caliptra_mcu_core_util_host_transport::Transport;
use caliptra_util_host_commands::api::certificate::{
    caliptra_cmd_export_attested_csr, caliptra_cmd_export_idevid_csr,
};
use caliptra_util_host_commands::api::device_info::{
    caliptra_cmd_get_device_capabilities, caliptra_cmd_get_device_id, caliptra_cmd_get_device_info,
    caliptra_cmd_get_firmware_version,
};
use caliptra_util_host_session::CaliptraSession;

/// High-level SPDM VDM Client for communicating with Caliptra devices.
///
/// Wraps an `SpdmVdmDriver` and provides typed command methods using
/// `CaliptraSession` dispatch (same pattern as `MailboxClient`).
pub struct SpdmVdmClient<'a> {
    transport: SpdmVdmTransport<'a>,
}

impl<'a> SpdmVdmClient<'a> {
    /// Create a new SpdmVdmClient with the provided VDM driver.
    pub fn new(driver: &'a mut dyn SpdmVdmDriver) -> Self {
        let transport = SpdmVdmTransport::new(driver);
        Self { transport }
    }

    /// Connect the SPDM VDM transport.
    pub fn connect(&mut self) -> Result<()> {
        self.transport
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect SPDM VDM transport: {:?}", e))
    }

    /// Disconnect the SPDM VDM transport.
    pub fn disconnect(&mut self) -> Result<()> {
        self.transport
            .disconnect()
            .map_err(|e| anyhow::anyhow!("Failed to disconnect SPDM VDM transport: {:?}", e))
    }

    /// Execute the GetDeviceId command.
    pub fn get_device_id(&mut self) -> Result<GetDeviceIdResponse> {
        let mut session = self.create_session()?;
        caliptra_cmd_get_device_id(&mut session)
            .map_err(|e| anyhow::anyhow!("GetDeviceId failed: {:?}", e))
    }

    /// Execute the GetFirmwareVersion command.
    pub fn get_firmware_version(&mut self, fw_id: u32) -> Result<GetFirmwareVersionResponse> {
        let mut session = self.create_session()?;
        caliptra_cmd_get_firmware_version(&mut session, fw_id)
            .map_err(|e| anyhow::anyhow!("GetFirmwareVersion failed: {:?}", e))
    }

    /// Execute the GetDeviceCapabilities command.
    pub fn get_device_capabilities(&mut self) -> Result<GetDeviceCapabilitiesResponse> {
        let mut session = self.create_session()?;
        caliptra_cmd_get_device_capabilities(&mut session)
            .map_err(|e| anyhow::anyhow!("GetDeviceCapabilities failed: {:?}", e))
    }

    /// Execute the GetDeviceInfo command.
    pub fn get_device_info(&mut self, info_index: u32) -> Result<GetDeviceInfoResponse> {
        let mut session = self.create_session()?;
        caliptra_cmd_get_device_info(&mut session, info_index)
            .map_err(|e| anyhow::anyhow!("GetDeviceInfo failed: {:?}", e))
    }

    /// Execute the ExportAttestedCsr command.
    ///
    /// # Parameters
    /// - `device_key_id`: Device key identifier (0x0001=LDevID, 0x0002=FMC Alias, 0x0003=RT Alias)
    /// - `algorithm`: Asymmetric algorithm (0x0001=ECC384, 0x0002=MLDSA87)
    /// - `nonce`: 32-byte nonce for freshness
    pub fn export_attested_csr(
        &mut self,
        device_key_id: u32,
        algorithm: u32,
        nonce: &[u8; 32],
    ) -> Result<ExportAttestedCsrResponse> {
        let mut session = self.create_session()?;
        caliptra_cmd_export_attested_csr(&mut session, device_key_id, algorithm, nonce)
            .map_err(|e| anyhow::anyhow!("ExportAttestedCsr failed: {:?}", e))
    }

    /// Execute the ExportIdevidCsr command (manufacturing mode only).
    ///
    /// # Parameters
    /// - `algorithm`: Asymmetric algorithm (0x0001=ECC384, 0x0002=MLDSA87)
    pub fn export_idevid_csr(&mut self, algorithm: u32) -> Result<ExportIdevidCsrResponse> {
        let mut session = self.create_session()?;
        caliptra_cmd_export_idevid_csr(&mut session, algorithm)
            .map_err(|e| anyhow::anyhow!("ExportIdevidCsr failed: {:?}", e))
    }

    fn create_session(&mut self) -> Result<CaliptraSession> {
        let mut session = CaliptraSession::new(1, &mut self.transport as &mut dyn Transport)
            .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;
        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect session: {:?}", e))?;
        Ok(session)
    }
}

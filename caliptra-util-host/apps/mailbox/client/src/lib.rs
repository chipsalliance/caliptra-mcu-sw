// Licensed under the Apache-2.0 license

//! Caliptra Mailbox Client Library
//!
//! This library provides communication with Caliptra devices using the Mailbox transport
//! abstraction. The UdpTransportDriver implements MailboxDriver to provide UDP-based
//! communication, which is then used through the Mailbox transport layer.

mod network_driver;
pub mod validator;

pub use network_driver::UdpTransportDriver;
pub use validator::{run_basic_validation, run_verbose_validation, ValidationResult, Validator};

// Re-export config from the shared library
pub use caliptra_util_host_mailbox_test_config::*;

use anyhow::Result;
use caliptra_util_host_command_types::{
    GetDeviceIdResponse, GetDeviceInfoResponse, GetDeviceCapabilitiesResponse,
    GetFirmwareVersionResponse,
};
use caliptra_util_host_commands::api::device_info::{
    caliptra_cmd_get_device_id, caliptra_cmd_get_device_info,
    caliptra_cmd_get_device_capabilities, caliptra_cmd_get_firmware_version,
};
use caliptra_util_host_session::CaliptraSession;
use caliptra_util_host_transport::Mailbox;

/// High-level Mailbox Client for communicating with Caliptra devices
pub struct MailboxClient<'a> {
    transport: Mailbox<'a>,
}

impl<'a> MailboxClient<'a> {
    /// Create a new MailboxClient with the provided mailbox driver
    pub fn new(mailbox_driver: &'a mut dyn caliptra_util_host_transport::MailboxDriver) -> Self {
        let transport = Mailbox::new(mailbox_driver);
        Self { transport }
    }

    /// Create a new MailboxClient with UDP transport
    pub fn with_udp_driver(udp_driver: &'a mut UdpTransportDriver) -> Self {
        let transport =
            Mailbox::new(udp_driver as &mut dyn caliptra_util_host_transport::MailboxDriver);
        Self { transport }
    }

    /// Execute the GetDeviceId command and return the response
    pub fn get_device_id(&mut self) -> Result<GetDeviceIdResponse> {
        println!("Executing GetDeviceId command...");

        // Create session with Mailbox transport
        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        // Connect to the device
        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_get_device_id(&mut session) {
            Ok(response) => {
                println!("✓ GetDeviceId succeeded!");
                println!("  Device ID: 0x{:04X}", response.device_id);
                println!("  Vendor ID: 0x{:04X}", response.vendor_id);
                println!(
                    "  Subsystem Vendor ID: 0x{:04X}",
                    response.subsystem_vendor_id
                );
                println!("  Subsystem ID: 0x{:04X}", response.subsystem_id);
                Ok(response)
            }
            Err(e) => {
                eprintln!("✗ GetDeviceId failed: {:?}", e);
                Err(anyhow::anyhow!("GetDeviceId command failed: {:?}", e))
            }
        }
    }

    /// Validate that the device response matches expected values
    pub fn validate_device_id(
        &mut self,
        expected_device_id: Option<u16>,
        expected_vendor_id: Option<u16>,
    ) -> Result<()> {
        let response = self.get_device_id()?;
        if let Some(expected_id) = expected_device_id {
            if response.device_id != expected_id {
                return Err(anyhow::anyhow!(
                    "Device ID mismatch: got 0x{:04X}, expected 0x{:04X}",
                    response.device_id,
                    expected_id
                ));
            }
            println!("✓ Device ID matches expected value: 0x{:04X}", expected_id);
        }

        if let Some(expected_vendor) = expected_vendor_id {
            if response.vendor_id != expected_vendor {
                return Err(anyhow::anyhow!(
                    "Vendor ID mismatch: got 0x{:04X}, expected 0x{:04X}",
                    response.vendor_id,
                    expected_vendor
                ));
            }
            println!(
                "✓ Vendor ID matches expected value: 0x{:04X}",
                expected_vendor
            );
        }

        Ok(())
    }

    /// Execute the GetDeviceInfo command and return the response
    pub fn get_device_info(&mut self) -> Result<GetDeviceInfoResponse> {
        println!("Executing GetDeviceInfo command...");

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_get_device_info(&mut session, 0) {
            Ok(response) => {
                println!("✓ GetDeviceInfo succeeded!");
                println!("  Info length: {} bytes", response.info_length);
                println!("  FIPS status: {}", response.common.fips_status);
                if response.info_length > 0 {
                    let info_str = std::str::from_utf8(&response.info_data[..response.info_length as usize])
                        .unwrap_or("<binary data>");
                    println!("  Info data: {}", info_str);
                }
                Ok(response)
            }
            Err(e) => {
                eprintln!("✗ GetDeviceInfo failed: {:?}", e);
                Err(anyhow::anyhow!("GetDeviceInfo command failed: {:?}", e))
            }
        }
    }

    /// Execute the GetDeviceCapabilities command and return the response
    pub fn get_device_capabilities(&mut self) -> Result<GetDeviceCapabilitiesResponse> {
        println!("Executing GetDeviceCapabilities command...");

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_get_device_capabilities(&mut session) {
            Ok(response) => {
                println!("✓ GetDeviceCapabilities succeeded!");
                println!("  Capabilities: 0x{:08X}", response.capabilities);
                println!("  Max certificate size: {} bytes", response.max_cert_size);
                println!("  Max CSR size: {} bytes", response.max_csr_size);
                println!("  Device lifecycle: {}", response.device_lifecycle);
                println!("  FIPS status: {}", response.common.fips_status);
                Ok(response)
            }
            Err(e) => {
                eprintln!("✗ GetDeviceCapabilities failed: {:?}", e);
                Err(anyhow::anyhow!("GetDeviceCapabilities command failed: {:?}", e))
            }
        }
    }

    /// Execute the GetFirmwareVersion command and return the response
    pub fn get_firmware_version(&mut self, fw_id: u32) -> Result<GetFirmwareVersionResponse> {
        println!("Executing GetFirmwareVersion command (fw_id={})...", fw_id);

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_get_firmware_version(&mut session, fw_id) {
            Ok(response) => {
                println!("✓ GetFirmwareVersion succeeded!");
                println!("  Version: {}.{}.{}.{}", response.version[0], response.version[1], response.version[2], response.version[3]);
                println!("  Git commit hash: {:02X?}", &response.commit_id[..8]);
                println!("  FIPS status: {}", response.common.fips_status);
                Ok(response)
            }
            Err(e) => {
                eprintln!("✗ GetFirmwareVersion failed: {:?}", e);
                Err(anyhow::anyhow!("GetFirmwareVersion command failed: {:?}", e))
            }
        }
    }
}

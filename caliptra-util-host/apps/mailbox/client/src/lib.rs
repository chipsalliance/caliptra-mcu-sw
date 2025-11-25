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

use anyhow::Result;
use caliptra_util_host_command_types::GetDeviceIdResponse;
use caliptra_util_host_commands::api::device_info::caliptra_cmd_get_device_id;
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
}

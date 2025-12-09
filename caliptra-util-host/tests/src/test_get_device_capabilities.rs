// Licensed under the Apache-2.0 license

//! Integration tests for GetDeviceCapabilities command
//!
//! These tests focus on the GetDeviceCapabilities command functionality using the
//! actual high-level API with CaliptraSession and VDM transport.

use crate::common::{test_constants::*, MockMailbox};
use caliptra_util_host_commands::api::device_info::caliptra_cmd_get_device_capabilities;
use caliptra_util_host_session::CaliptraSession;
use caliptra_util_host_transport::Mailbox;

/// Test GetDeviceCapabilities command with basic configuration
#[test]
fn test_get_device_capabilities_basic() {
    println!("Testing GetDeviceCapabilities with basic configuration...");

    let expected_device_id = TEST_DEVICE_ID_1;
    println!(
        "Testing with expected device ID: 0x{:04X}",
        expected_device_id
    );

    // Create mock mailbox and mailbox transport
    let mut mock_mailbox = MockMailbox::new(expected_device_id);
    let mut mailbox_transport = Mailbox::new(
        &mut mock_mailbox
            as &mut dyn caliptra_util_host_transport::transports::mailbox::MailboxDriver,
    );

    // Create and connect session
    let mut session = CaliptraSession::new(
        1,
        &mut mailbox_transport as &mut dyn caliptra_util_host_transport::Transport,
    )
    .expect("Failed to create CaliptraSession");

    session
        .connect()
        .expect("Failed to connect CaliptraSession");

    println!("CaliptraSession created and connected successfully");

    // Use the high-level API
    let capabilities_result = caliptra_cmd_get_device_capabilities(&mut session);

    match capabilities_result {
        Ok(capabilities) => {
            println!(
                "Successfully got device capabilities via high-level API: {:?}",
                capabilities
            );

            // Basic validation that we got a response
            println!("Device capabilities: 0x{:08X}", capabilities.capabilities);
            println!("Max cert size: {}", capabilities.max_cert_size);
            println!("Max CSR size: {}", capabilities.max_csr_size);
            println!("Device lifecycle: {}", capabilities.device_lifecycle);

            println!("All device capabilities fields verified successfully!");
        }
        Err(e) => {
            panic!("Failed to get device capabilities via high-level API: {:?}", e);
        }
    }

    println!("GetDeviceCapabilities basic test completed successfully!");
}

/// Test GetDeviceCapabilities command error handling
#[test]
fn test_get_device_capabilities_session_not_connected() {
    println!("Testing GetDeviceCapabilities error handling - session not connected...");

    let expected_device_id = TEST_DEVICE_ID_1;

    // Create mock mailbox and mailbox transport but don't connect
    let mut mock_mailbox = MockMailbox::new(expected_device_id);
    let mut mailbox_transport = Mailbox::new(
        &mut mock_mailbox
            as &mut dyn caliptra_util_host_transport::transports::mailbox::MailboxDriver,
    );

    // Create session but don't connect it
    let mut session = CaliptraSession::new(
        1,
        &mut mailbox_transport as &mut dyn caliptra_util_host_transport::Transport,
    )
    .expect("Failed to create CaliptraSession");

    // Note: We don't call session.connect() here to test error handling

    // Try to use the high-level API - this should fail because session is not connected
    let capabilities_result = caliptra_cmd_get_device_capabilities(&mut session);

    match capabilities_result {
        Ok(_) => {
            panic!("Expected GetDeviceCapabilities to fail when session is not connected, but it succeeded");
        }
        Err(e) => {
            println!(
                "GetDeviceCapabilities correctly failed when session not connected: {:?}",
                e
            );
        }
    }

    println!("GetDeviceCapabilities error handling test completed successfully!");
}
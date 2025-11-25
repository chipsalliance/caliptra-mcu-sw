// Licensed under the Apache-2.0 license

//! Integration tests for GetDeviceId command
//!
//! These tests focus on the GetDeviceId command functionality using the
//! actual high-level API with CaliptraSession and VDM transport.

use crate::common::{test_constants::*, MockMailbox};
use caliptra_util_host_commands::api::device_info::caliptra_cmd_get_device_id;
use caliptra_util_host_session::CaliptraSession;
use caliptra_util_host_transport::Mailbox;

/// Test GetDeviceId command with default configuration
#[test]
fn test_get_device_id_basic() {
    println!("Testing GetDeviceId with basic configuration...");

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
    let device_id_result = caliptra_cmd_get_device_id(&mut session);

    match device_id_result {
        Ok(device_id) => {
            println!(
                "Successfully got device ID via high-level API: {:?}",
                device_id
            );

            // Verify the device ID matches our expected value
            assert_eq!(
                device_id.device_id, expected_device_id,
                "Device ID should match the configured mock value"
            );
            println!(
                "Device ID verified: 0x{:04X} matches expected: 0x{:04X}",
                device_id.device_id, expected_device_id
            );

            // Also verify other fields are set correctly
            assert_eq!(
                device_id.vendor_id, DEFAULT_VENDOR_ID,
                "Vendor ID should match mock value"
            );
            assert_eq!(
                device_id.subsystem_vendor_id, DEFAULT_SUBSYSTEM_VENDOR_ID,
                "Subsystem vendor ID should match mock value"
            );
            assert_eq!(
                device_id.subsystem_id, DEFAULT_SUBSYSTEM_ID,
                "Subsystem ID should match mock value"
            );

            println!("All device ID fields verified successfully!");
        }
        Err(e) => {
            panic!("Failed to get device ID via high-level API: {:?}", e);
        }
    }

    println!("GetDeviceId basic test completed successfully!");
}

/// Test GetDeviceId command with different device ID
#[test]
fn test_get_device_id_different_device() {
    println!("Testing GetDeviceId with different device ID...");

    let expected_device_id = TEST_DEVICE_ID_2;
    println!(
        "Testing with expected device ID: 0x{:04X}",
        expected_device_id
    );

    // Create mock mailbox with different device ID and mailbox transport
    let mut mock_mailbox = MockMailbox::new(expected_device_id);
    let mut mailbox_transport = Mailbox::new(
        &mut mock_mailbox
            as &mut dyn caliptra_util_host_transport::transports::mailbox::MailboxDriver,
    );

    // Create and connect session
    let mut session = CaliptraSession::new(
        2,
        &mut mailbox_transport as &mut dyn caliptra_util_host_transport::Transport,
    )
    .expect("Failed to create CaliptraSession with different device ID");

    session
        .connect()
        .expect("Failed to connect CaliptraSession");

    // Use the high-level API
    let device_id_result = caliptra_cmd_get_device_id(&mut session);

    match device_id_result {
        Ok(device_id) => {
            // Verify it returns the configured device ID
            assert_eq!(device_id.device_id, expected_device_id);
            println!(
                "Successfully verified different device ID via high-level API: 0x{:04X}",
                device_id.device_id
            );

            // Verify all fields
            assert_eq!(
                device_id.vendor_id, DEFAULT_VENDOR_ID,
                "Vendor ID should match mock value"
            );
            assert_eq!(
                device_id.subsystem_vendor_id, DEFAULT_SUBSYSTEM_VENDOR_ID,
                "Subsystem vendor ID should match mock value"
            );
            assert_eq!(
                device_id.subsystem_id, DEFAULT_SUBSYSTEM_ID,
                "Subsystem ID should match mock value"
            );

            println!("All device ID fields verified for different device ID test!");
        }
        Err(e) => {
            panic!("Failed to get device ID via high-level API: {:?}", e);
        }
    }

    println!("GetDeviceId different device test completed successfully!");
}

/// Test GetDeviceId command error handling
#[test]
fn test_get_device_id_session_not_connected() {
    println!("Testing GetDeviceId error handling with disconnected session...");

    let mut mock_mailbox = MockMailbox::new(TEST_DEVICE_ID_1);
    let mut mailbox_transport = Mailbox::new(
        &mut mock_mailbox
            as &mut dyn caliptra_util_host_transport::transports::mailbox::MailboxDriver,
    );

    // Create session but don't connect
    let mut session = CaliptraSession::new(
        3,
        &mut mailbox_transport as &mut dyn caliptra_util_host_transport::Transport,
    )
    .expect("Failed to create CaliptraSession");

    // Note: We intentionally don't call session.connect() to test error handling

    // Try to use the high-level API with disconnected session
    let device_id_result = caliptra_cmd_get_device_id(&mut session);

    // Should fail because session is not connected
    match device_id_result {
        Ok(_) => {
            panic!("Expected GetDeviceId to fail with disconnected session, but it succeeded");
        }
        Err(e) => {
            println!(
                "GetDeviceId correctly failed with disconnected session: {:?}",
                e
            );
        }
    }

    println!("GetDeviceId error handling test completed successfully!");
}

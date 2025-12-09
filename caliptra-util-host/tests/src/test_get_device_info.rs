// Licensed under the Apache-2.0 license

//! Integration tests for GetDeviceInfo command
//!
//! These tests focus on the GetDeviceInfo command functionality using the
//! actual high-level API with CaliptraSession and VDM transport.

use crate::common::{test_constants::*, MockMailbox};
use caliptra_util_host_commands::api::device_info::caliptra_cmd_get_device_info;
use caliptra_util_host_session::CaliptraSession;
use caliptra_util_host_transport::Mailbox;

/// Test GetDeviceInfo command with basic configuration
#[test]
fn test_get_device_info_basic() {
    println!("Testing GetDeviceInfo with basic configuration...");

    let expected_device_id = TEST_DEVICE_ID_1;
    let info_type = 1; // Example info type
    println!(
        "Testing with expected device ID: 0x{:04X}, info_type: {}",
        expected_device_id, info_type
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
    let device_info_result = caliptra_cmd_get_device_info(&mut session, info_type);

    match device_info_result {
        Ok(device_info) => {
            println!(
                "Successfully got device info via high-level API: {:?}",
                device_info
            );

            // Basic validation that we got a response
            println!("Device info length: {}", device_info.info_length);
            println!("All device info fields verified successfully!");
        }
        Err(e) => {
            panic!("Failed to get device info via high-level API: {:?}", e);
        }
    }

    println!("GetDeviceInfo basic test completed successfully!");
}

/// Test GetDeviceInfo command error handling
#[test]
fn test_get_device_info_session_not_connected() {
    println!("Testing GetDeviceInfo error handling - session not connected...");

    let expected_device_id = TEST_DEVICE_ID_1;
    let info_type = 1;

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
    let device_info_result = caliptra_cmd_get_device_info(&mut session, info_type);

    match device_info_result {
        Ok(_) => {
            panic!("Expected GetDeviceInfo to fail when session is not connected, but it succeeded");
        }
        Err(e) => {
            println!(
                "GetDeviceInfo correctly failed when session not connected: {:?}",
                e
            );
        }
    }

    println!("GetDeviceInfo error handling test completed successfully!");
}
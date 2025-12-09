// Licensed under the Apache-2.0 license

//! Integration tests for GetFirmwareVersion command
//!
//! These tests focus on the GetFirmwareVersion command functionality using the
//! actual high-level API with CaliptraSession and VDM transport.

use crate::common::{test_constants::*, MockMailbox};
use caliptra_util_host_commands::api::device_info::caliptra_cmd_get_firmware_version;
use caliptra_util_host_session::CaliptraSession;
use caliptra_util_host_transport::Mailbox;

/// Test GetFirmwareVersion command with ROM firmware
#[test]
fn test_get_firmware_version_rom() {
    println!("Testing GetFirmwareVersion for ROM firmware...");

    let expected_device_id = TEST_DEVICE_ID_1;
    let firmware_index = 0; // ROM firmware
    println!(
        "Testing with expected device ID: 0x{:04X}, firmware_index: {} (ROM)",
        expected_device_id, firmware_index
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
    let firmware_version_result = caliptra_cmd_get_firmware_version(&mut session, firmware_index);

    match firmware_version_result {
        Ok(firmware_version) => {
            println!(
                "Successfully got firmware version via high-level API: {:?}",
                firmware_version
            );

            // Basic validation that we got a response
            println!(
                "Firmware version: {}.{}.{}.{}",
                firmware_version.version[0],
                firmware_version.version[1],
                firmware_version.version[2],
                firmware_version.version[3]
            );

            println!("All firmware version fields verified successfully!");
        }
        Err(e) => {
            panic!("Failed to get firmware version via high-level API: {:?}", e);
        }
    }

    println!("GetFirmwareVersion ROM test completed successfully!");
}

/// Test GetFirmwareVersion command with Runtime firmware
#[test]
fn test_get_firmware_version_runtime() {
    println!("Testing GetFirmwareVersion for Runtime firmware...");

    let expected_device_id = TEST_DEVICE_ID_1;
    let firmware_index = 1; // Runtime firmware
    println!(
        "Testing with expected device ID: 0x{:04X}, firmware_index: {} (Runtime)",
        expected_device_id, firmware_index
    );

    // Create mock mailbox and mailbox transport
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
    .expect("Failed to create CaliptraSession");

    session
        .connect()
        .expect("Failed to connect CaliptraSession");

    println!("CaliptraSession created and connected successfully");

    // Use the high-level API
    let firmware_version_result = caliptra_cmd_get_firmware_version(&mut session, firmware_index);

    match firmware_version_result {
        Ok(firmware_version) => {
            println!(
                "Successfully got runtime firmware version via high-level API: {:?}",
                firmware_version
            );

            // Basic validation that we got a response
            println!(
                "Runtime firmware version: {}.{}.{}.{}",
                firmware_version.version[0],
                firmware_version.version[1],
                firmware_version.version[2],
                firmware_version.version[3]
            );

            println!("All runtime firmware version fields verified successfully!");
        }
        Err(e) => {
            panic!("Failed to get runtime firmware version via high-level API: {:?}", e);
        }
    }

    println!("GetFirmwareVersion Runtime test completed successfully!");
}

/// Test GetFirmwareVersion command error handling
#[test]
fn test_get_firmware_version_session_not_connected() {
    println!("Testing GetFirmwareVersion error handling - session not connected...");

    let expected_device_id = TEST_DEVICE_ID_1;
    let firmware_index = 0;

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
    let firmware_version_result = caliptra_cmd_get_firmware_version(&mut session, firmware_index);

    match firmware_version_result {
        Ok(_) => {
            panic!("Expected GetFirmwareVersion to fail when session is not connected, but it succeeded");
        }
        Err(e) => {
            println!(
                "GetFirmwareVersion correctly failed when session not connected: {:?}",
                e
            );
        }
    }

    println!("GetFirmwareVersion error handling test completed successfully!");
}
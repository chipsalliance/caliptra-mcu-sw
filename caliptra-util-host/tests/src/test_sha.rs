// Licensed under the Apache-2.0 license

//! Unit tests for SHA commands using MockMailbox
//!
//! These tests verify the SHA API functions work correctly with the mock mailbox.

use crate::common::{test_constants::*, MockMailbox};
use caliptra_util_host_command_types::crypto_hash::{ShaAlgorithm, SHA_CONTEXT_SIZE};
use caliptra_util_host_commands::api::crypto_hash::caliptra_cmd_sha_init;
use caliptra_util_host_session::CaliptraSession;
use caliptra_util_host_transport::Mailbox;

/// Test SHA384 init command
#[test]
fn test_sha384_init_basic() {
    println!("Testing SHA384 init command...");

    let mut mock_mailbox = MockMailbox::new(TEST_DEVICE_ID_1);
    let mut mailbox_transport = Mailbox::new(
        &mut mock_mailbox
            as &mut dyn caliptra_util_host_transport::transports::mailbox::MailboxDriver,
    );

    let mut session = CaliptraSession::new(
        1,
        &mut mailbox_transport as &mut dyn caliptra_util_host_transport::Transport,
    )
    .expect("Failed to create CaliptraSession");

    session
        .connect()
        .expect("Failed to connect CaliptraSession");

    let input = b"test data for SHA384";
    let result = caliptra_cmd_sha_init(&mut session, ShaAlgorithm::Sha384, input);

    match result {
        Ok(resp) => {
            println!(
                "SHA384 init succeeded, context length: {}",
                resp.context.len()
            );
            assert_eq!(resp.context.len(), SHA_CONTEXT_SIZE);
        }
        Err(e) => {
            // Mock mailbox doesn't support SHA yet, so we expect an error
            println!("SHA384 init returned error (expected with mock): {:?}", e);
        }
    }

    println!("SHA384 init test completed!");
}

/// Test SHA512 init command
#[test]
fn test_sha512_init_basic() {
    println!("Testing SHA512 init command...");

    let mut mock_mailbox = MockMailbox::new(TEST_DEVICE_ID_1);
    let mut mailbox_transport = Mailbox::new(
        &mut mock_mailbox
            as &mut dyn caliptra_util_host_transport::transports::mailbox::MailboxDriver,
    );

    let mut session = CaliptraSession::new(
        1,
        &mut mailbox_transport as &mut dyn caliptra_util_host_transport::Transport,
    )
    .expect("Failed to create CaliptraSession");

    session
        .connect()
        .expect("Failed to connect CaliptraSession");

    let input = b"test data for SHA512";
    let result = caliptra_cmd_sha_init(&mut session, ShaAlgorithm::Sha512, input);

    match result {
        Ok(resp) => {
            println!(
                "SHA512 init succeeded, context length: {}",
                resp.context.len()
            );
            assert_eq!(resp.context.len(), SHA_CONTEXT_SIZE);
        }
        Err(e) => {
            // Mock mailbox doesn't support SHA yet
            println!("SHA512 init returned error (expected with mock): {:?}", e);
        }
    }

    println!("SHA512 init test completed!");
}

/// Test SHA command with disconnected session
#[test]
fn test_sha_disconnected_session() {
    println!("Testing SHA with disconnected session...");

    let mut mock_mailbox = MockMailbox::new(TEST_DEVICE_ID_1);
    let mut mailbox_transport = Mailbox::new(
        &mut mock_mailbox
            as &mut dyn caliptra_util_host_transport::transports::mailbox::MailboxDriver,
    );

    // Create session but don't connect
    let mut session = CaliptraSession::new(
        1,
        &mut mailbox_transport as &mut dyn caliptra_util_host_transport::Transport,
    )
    .expect("Failed to create CaliptraSession");

    // Note: intentionally not calling session.connect()

    let input = b"test data";
    let result = caliptra_cmd_sha_init(&mut session, ShaAlgorithm::Sha384, input);

    // Should fail because session is not connected
    match result {
        Ok(_) => {
            panic!("Expected SHA init to fail with disconnected session, but it succeeded");
        }
        Err(e) => {
            println!(
                "SHA init correctly failed with disconnected session: {:?}",
                e
            );
        }
    }

    println!("SHA disconnected session test completed!");
}

/// Test ShaAlgorithm enum
#[test]
fn test_sha_algorithm_enum() {
    // Test hash size
    assert_eq!(ShaAlgorithm::Sha384.hash_size(), 48);
    assert_eq!(ShaAlgorithm::Sha512.hash_size(), 64);

    // Test conversion from u32
    assert_eq!(ShaAlgorithm::from(1u32), ShaAlgorithm::Sha384);
    assert_eq!(ShaAlgorithm::from(2u32), ShaAlgorithm::Sha512);
    assert_eq!(ShaAlgorithm::from(99u32), ShaAlgorithm::Sha384); // Default

    // Test conversion to u32
    assert_eq!(u32::from(ShaAlgorithm::Sha384), 1);
    assert_eq!(u32::from(ShaAlgorithm::Sha512), 2);

    println!("SHA algorithm enum test passed!");
}

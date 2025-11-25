// Licensed under the Apache-2.0 license

//! Integration tests for Caliptra Utility Host Library
//!
//! These tests focus on general integration scenarios using the modular architecture.
//! For command-specific tests, see the dedicated test files (e.g., test_get_device_id.rs)
//!
//! ## Architecture Overview
//!
//! The tests use the new no_std modular architecture:
//! - `caliptra-transport`: Transport trait definitions (no_std)
//! - `caliptra-session`: Session management with transport integration (no_std)  
//! - `caliptra-command-types`: Command structures with zerocopy serialization (no_std)
//! - `caliptra-commands`: High-level API functions (no_std)
//! - `caliptra-core`: Core execution logic (no_std)
//! - `caliptra-osal`: OS abstraction layer (only module with std access)

use crate::common::{test_constants::*, MockMailbox};
use caliptra_util_host_session::CaliptraSession;
use caliptra_util_host_transport::Mailbox;

/// Integration test demonstrating session lifecycle management
///
/// This test verifies proper session creation, connection, and cleanup
#[test]
fn test_session_lifecycle() {
    println!("Testing session lifecycle management...");

    // Create mock mailbox and mailbox transport
    let mut mock_mailbox = MockMailbox::new(TEST_DEVICE_ID_1);
    let mut mailbox_transport = Mailbox::new(
        &mut mock_mailbox
            as &mut dyn caliptra_util_host_transport::transports::mailbox::MailboxDriver,
    );

    // Create a session with the mailbox transport
    let mut session = CaliptraSession::new(
        1,
        &mut mailbox_transport as &mut dyn caliptra_util_host_transport::Transport,
    )
    .expect("Failed to create CaliptraSession");

    // Verify initial state
    assert!(
        !session.is_ready(),
        "Session should not be ready before connection"
    );

    // Connect the session
    session
        .connect()
        .expect("Failed to connect CaliptraSession");

    // Verify connected state
    assert!(
        session.is_ready(),
        "Session should be ready after connection"
    );

    println!("Session lifecycle test completed successfully!");
}

/// Integration test for error handling across layers
#[test]
fn test_error_propagation() {
    println!("Testing error propagation through layers...");

    // Create mock mailbox but don't make it ready
    let mut mock_mailbox = MockMailbox::new(TEST_DEVICE_ID_2);
    mock_mailbox.set_ready(false); // This should cause connection to fail

    let mut mailbox_transport = Mailbox::new(
        &mut mock_mailbox
            as &mut dyn caliptra_util_host_transport::transports::mailbox::MailboxDriver,
    );

    // Create a session with the mailbox transport
    let mut session = CaliptraSession::new(
        2,
        &mut mailbox_transport as &mut dyn caliptra_util_host_transport::Transport,
    )
    .expect("Failed to create CaliptraSession");

    // Try to connect - this should fail
    let connection_result = session.connect();

    match connection_result {
        Ok(_) => {
            panic!("Expected connection to fail with unready mock mailbox, but it succeeded");
        }
        Err(_) => {
            println!("Connection correctly failed with unready mock mailbox");
        }
    }

    println!("Error propagation test completed successfully!");
}

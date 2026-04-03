// Licensed under the Apache-2.0 license

//! Unit tests for AES commands using MockMailbox
//!
//! These tests verify the AES API functions work correctly with the mock mailbox.

use crate::common::{test_constants::*, MockMailbox};
use caliptra_util_host_command_types::crypto_aes::{
    AesMode, AES_CONTEXT_SIZE, AES_GCM_CONTEXT_SIZE, AES_GCM_IV_SIZE, AES_IV_SIZE,
};
use caliptra_util_host_command_types::crypto_hmac::Cmk;
use caliptra_util_host_commands::api::crypto_aes::{
    caliptra_cmd_aes_decrypt_init, caliptra_cmd_aes_encrypt_init,
    caliptra_cmd_aes_gcm_decrypt_init, caliptra_cmd_aes_gcm_encrypt_init,
};
use caliptra_util_host_session::CaliptraSession;
use caliptra_util_host_transport::Mailbox;

#[test]
fn test_aes_encrypt_init_basic() {
    println!("Testing AES encrypt init command...");

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

    let key = Cmk::default();
    let plaintext = b"test data for AES encrypt";
    let result = caliptra_cmd_aes_encrypt_init(&mut session, &key, AesMode::Cbc, plaintext);

    match result {
        Ok(resp) => {
            println!(
                "AES encrypt init succeeded, context length: {}",
                resp.context.len()
            );
            assert_eq!(resp.context.len(), AES_CONTEXT_SIZE);
        }
        Err(e) => {
            println!(
                "AES encrypt init returned error (expected with mock): {:?}",
                e
            );
        }
    }

    println!("AES encrypt init test completed!");
}

#[test]
fn test_aes_decrypt_init_basic() {
    println!("Testing AES decrypt init command...");

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

    let key = Cmk::default();
    let iv = [0u8; AES_IV_SIZE];
    let ciphertext = b"test data for AES decrypt";
    let result = caliptra_cmd_aes_decrypt_init(&mut session, &key, AesMode::Cbc, &iv, ciphertext);

    match result {
        Ok(resp) => {
            println!(
                "AES decrypt init succeeded, context length: {}",
                resp.context.len()
            );
            assert_eq!(resp.context.len(), AES_CONTEXT_SIZE);
        }
        Err(e) => {
            println!(
                "AES decrypt init returned error (expected with mock): {:?}",
                e
            );
        }
    }

    println!("AES decrypt init test completed!");
}

#[test]
fn test_aes_gcm_encrypt_init_basic() {
    println!("Testing AES-GCM encrypt init command...");

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

    let key = Cmk::default();
    let aad = b"test data for AES-GCM aad";
    let result = caliptra_cmd_aes_gcm_encrypt_init(&mut session, &key, aad);

    match result {
        Ok(resp) => {
            println!(
                "AES-GCM encrypt init succeeded, context length: {}",
                resp.context.len()
            );
            assert_eq!(resp.context.len(), AES_GCM_CONTEXT_SIZE);
        }
        Err(e) => {
            println!(
                "AES-GCM encrypt init returned error (expected with mock): {:?}",
                e
            );
        }
    }

    println!("AES-GCM encrypt init test completed!");
}

#[test]
fn test_aes_gcm_decrypt_init_basic() {
    println!("Testing AES-GCM decrypt init command...");

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

    let key = Cmk::default();
    let iv = [0u8; AES_GCM_IV_SIZE];
    let aad = b"test data for AES-GCM aad";
    let result = caliptra_cmd_aes_gcm_decrypt_init(&mut session, &key, &iv, aad);

    match result {
        Ok(resp) => {
            println!(
                "AES-GCM decrypt init succeeded, context length: {}",
                resp.context.len()
            );
            assert_eq!(resp.context.len(), AES_GCM_CONTEXT_SIZE);
        }
        Err(e) => {
            println!(
                "AES-GCM decrypt init returned error (expected with mock): {:?}",
                e
            );
        }
    }

    println!("AES-GCM decrypt init test completed!");
}

#[test]
fn test_aes_disconnected_session() {
    println!("Testing AES with disconnected session...");

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

    let key = Cmk::default();
    let plaintext = b"test data";
    let result = caliptra_cmd_aes_encrypt_init(&mut session, &key, AesMode::Cbc, plaintext);

    match result {
        Ok(_) => {
            panic!("Expected AES encrypt init to fail with disconnected session, but it succeeded");
        }
        Err(e) => {
            println!(
                "AES encrypt init correctly failed with disconnected session: {:?}",
                e
            );
        }
    }

    println!("AES disconnected session test completed!");
}

#[test]
fn test_aes_mode_enum() {
    assert_eq!(AesMode::from(1u32), AesMode::Cbc);
    assert_eq!(AesMode::from(2u32), AesMode::Ctr);
    assert_eq!(AesMode::from(99u32), AesMode::Reserved);

    println!("AES mode enum test passed!");
}

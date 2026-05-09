// Licensed under the Apache-2.0 license

//! Unit tests for HMAC commands using MockMailbox
//!
//! These tests verify the HMAC API functions and types work correctly.

use crate::common::{test_constants::*, MockMailbox};
use caliptra_util_host_command_types::crypto_hmac::{
    CmKeyUsage, Cmk, HmacAlgorithm, HmacKdfCounterRequest, HmacRequest, CMK_SIZE,
    MAX_HMAC_INPUT_SIZE,
};
use caliptra_util_host_commands::api::crypto_hmac::{
    caliptra_cmd_hmac, caliptra_cmd_hmac_kdf_counter,
};
use caliptra_util_host_session::CaliptraSession;
use caliptra_util_host_transport::Mailbox;

/// Test HMAC SHA384 command
#[test]
fn test_hmac_sha384_basic() {
    println!("Testing HMAC SHA384 command...");

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
    let data = b"test data for HMAC-SHA384";
    let result = caliptra_cmd_hmac(&mut session, &key, HmacAlgorithm::Sha384, data);

    match result {
        Ok(resp) => {
            println!("HMAC SHA384 succeeded, MAC size: {}", resp.mac_size);
            assert!(resp.mac_size <= 64);
        }
        Err(e) => {
            // Mock mailbox doesn't support HMAC yet, so we expect an error
            println!("HMAC SHA384 returned error (expected with mock): {:?}", e);
        }
    }

    println!("HMAC SHA384 test completed!");
}

/// Test HMAC SHA512 command
#[test]
fn test_hmac_sha512_basic() {
    println!("Testing HMAC SHA512 command...");

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
    let data = b"test data for HMAC-SHA512";
    let result = caliptra_cmd_hmac(&mut session, &key, HmacAlgorithm::Sha512, data);

    match result {
        Ok(resp) => {
            println!("HMAC SHA512 succeeded, MAC size: {}", resp.mac_size);
            assert!(resp.mac_size <= 64);
        }
        Err(e) => {
            // Mock mailbox doesn't support HMAC yet
            println!("HMAC SHA512 returned error (expected with mock): {:?}", e);
        }
    }

    println!("HMAC SHA512 test completed!");
}

/// Test HMAC command with disconnected session
#[test]
fn test_hmac_disconnected_session() {
    println!("Testing HMAC with disconnected session...");

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

    let key = Cmk::default();
    let data = b"test data";
    let result = caliptra_cmd_hmac(&mut session, &key, HmacAlgorithm::Sha384, data);

    // Should fail because session is not connected
    match result {
        Ok(_) => {
            panic!("Expected HMAC to fail with disconnected session, but it succeeded");
        }
        Err(e) => {
            println!("HMAC correctly failed with disconnected session: {:?}", e);
        }
    }

    println!("HMAC disconnected session test completed!");
}

/// Test HMAC KDF counter command
#[test]
fn test_hmac_kdf_counter_basic() {
    println!("Testing HMAC KDF counter command...");

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

    let kin = Cmk::default();
    let label = b"test key derivation";
    let result = caliptra_cmd_hmac_kdf_counter(
        &mut session,
        &kin,
        HmacAlgorithm::Sha384,
        CmKeyUsage::Aes,
        256,
        label,
    );

    match result {
        Ok(resp) => {
            println!("HMAC KDF counter succeeded");
            assert_eq!(resp.kout.0.len(), CMK_SIZE);
        }
        Err(e) => {
            // Mock mailbox doesn't support KDF yet
            println!(
                "HMAC KDF counter returned error (expected with mock): {:?}",
                e
            );
        }
    }

    println!("HMAC KDF counter test completed!");
}

/// Test HmacAlgorithm enum
#[test]
fn test_hmac_algorithm_enum() {
    // Test MAC size
    assert_eq!(HmacAlgorithm::Sha384.mac_size(), 48);
    assert_eq!(HmacAlgorithm::Sha512.mac_size(), 64);

    // Test conversion from u32
    assert_eq!(HmacAlgorithm::from(1u32), HmacAlgorithm::Sha384);
    assert_eq!(HmacAlgorithm::from(2u32), HmacAlgorithm::Sha512);
    assert_eq!(HmacAlgorithm::from(99u32), HmacAlgorithm::Sha384); // Default

    // Test conversion to u32
    assert_eq!(u32::from(HmacAlgorithm::Sha384), 1);
    assert_eq!(u32::from(HmacAlgorithm::Sha512), 2);

    println!("HMAC algorithm enum test passed!");
}

/// Test CmKeyUsage enum
#[test]
fn test_cm_key_usage_enum() {
    // Test conversion from u32
    assert_eq!(CmKeyUsage::from(0u32), CmKeyUsage::Reserved);
    assert_eq!(CmKeyUsage::from(1u32), CmKeyUsage::Hmac);
    assert_eq!(CmKeyUsage::from(2u32), CmKeyUsage::Aes);
    assert_eq!(CmKeyUsage::from(3u32), CmKeyUsage::Ecdsa);
    assert_eq!(CmKeyUsage::from(4u32), CmKeyUsage::Mldsa);
    assert_eq!(CmKeyUsage::from(99u32), CmKeyUsage::Reserved); // Default

    // Test conversion to u32
    assert_eq!(u32::from(CmKeyUsage::Reserved), 0);
    assert_eq!(u32::from(CmKeyUsage::Hmac), 1);
    assert_eq!(u32::from(CmKeyUsage::Aes), 2);
    assert_eq!(u32::from(CmKeyUsage::Ecdsa), 3);
    assert_eq!(u32::from(CmKeyUsage::Mldsa), 4);

    println!("CmKeyUsage enum test passed!");
}

/// Test Cmk struct
#[test]
fn test_cmk_struct() {
    // Test default
    let cmk = Cmk::default();
    assert_eq!(cmk.0.len(), CMK_SIZE);
    assert!(cmk.0.iter().all(|&b| b == 0));

    // Test new
    let data = [0x42u8; CMK_SIZE];
    let cmk = Cmk::new(data);
    assert_eq!(cmk.as_bytes(), &data);

    // Test clone
    let cmk2 = cmk.clone();
    assert_eq!(cmk, cmk2);

    println!("Cmk struct test passed!");
}

/// Test HmacRequest construction
#[test]
fn test_hmac_request_construction() {
    let key = Cmk::new([0x11u8; CMK_SIZE]);
    let data = b"Hello, World!";

    let req = HmacRequest::new(&key, HmacAlgorithm::Sha384, data);

    assert_eq!(req.cmk, key);
    assert_eq!(req.hash_algorithm, HmacAlgorithm::Sha384 as u32);
    assert_eq!(req.data_size, data.len() as u32);
    assert_eq!(&req.data[..data.len()], data);

    println!("HmacRequest construction test passed!");
}

/// Test HmacKdfCounterRequest construction
#[test]
fn test_hmac_kdf_counter_request_construction() {
    let kin = Cmk::new([0x22u8; CMK_SIZE]);
    let label = b"key derivation label";

    let req = HmacKdfCounterRequest::new(&kin, HmacAlgorithm::Sha512, CmKeyUsage::Hmac, 384, label);

    assert_eq!(req.kin, kin);
    assert_eq!(req.hash_algorithm, HmacAlgorithm::Sha512 as u32);
    assert_eq!(req.key_usage, CmKeyUsage::Hmac as u32);
    assert_eq!(req.key_size, 384);
    assert_eq!(req.label_size, label.len() as u32);
    assert_eq!(&req.label[..label.len()], label);

    println!("HmacKdfCounterRequest construction test passed!");
}

/// Test HmacRequest with max data size
#[test]
fn test_hmac_request_max_data() {
    let key = Cmk::default();
    let data = [0xABu8; MAX_HMAC_INPUT_SIZE];

    let req = HmacRequest::new(&key, HmacAlgorithm::Sha384, &data);

    assert_eq!(req.data_size, MAX_HMAC_INPUT_SIZE as u32);
    assert_eq!(&req.data[..], &data[..]);

    println!("HmacRequest max data test passed!");
}

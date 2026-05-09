// Licensed under the Apache-2.0 license

//! Unit tests for ECDSA/ECDH commands using MockMailbox
//!
//! These tests verify the ECDSA and ECDH API functions and types work correctly.

use crate::common::{test_constants::*, MockMailbox};
use caliptra_util_host_command_types::crypto_asymmetric::{
    EcdhFinishRequest, EcdhGenerateRequest, EcdsaPublicKeyRequest, EcdsaSignRequest,
    EcdsaVerifyRequest, CMB_ECDH_ENCRYPTED_CONTEXT_SIZE, CMB_ECDH_EXCHANGE_DATA_MAX_SIZE,
    ECC384_SCALAR_BYTE_SIZE, MAX_CMB_DATA_SIZE,
};
use caliptra_util_host_command_types::crypto_hmac::{CmKeyUsage, Cmk, CMK_SIZE};
use caliptra_util_host_commands::api::crypto_asymmetric::{
    caliptra_cmd_ecdh_generate, caliptra_cmd_ecdsa_public_key, caliptra_cmd_ecdsa_sign,
};
use caliptra_util_host_session::CaliptraSession;
use caliptra_util_host_transport::Mailbox;

/// Test ECDSA public key request construction
#[test]
fn test_ecdsa_public_key_request_construction() {
    let cmk = Cmk::new([0x11u8; CMK_SIZE]);

    let req = EcdsaPublicKeyRequest::new(&cmk);

    assert_eq!(req.cmk, cmk);

    println!("EcdsaPublicKeyRequest construction test passed!");
}

/// Test ECDSA sign request construction
#[test]
fn test_ecdsa_sign_request_construction() {
    let cmk = Cmk::new([0x22u8; CMK_SIZE]);
    let message = b"Test message to sign";

    let req = EcdsaSignRequest::new(&cmk, message);

    assert_eq!(req.cmk, cmk);
    assert_eq!(req.message_size, message.len() as u32);
    assert_eq!(&req.message[..message.len()], message);

    println!("EcdsaSignRequest construction test passed!");
}

/// Test ECDSA verify request construction
#[test]
fn test_ecdsa_verify_request_construction() {
    let cmk = Cmk::new([0x33u8; CMK_SIZE]);
    let message = b"Test message to verify";
    let signature_r = [0xAAu8; ECC384_SCALAR_BYTE_SIZE];
    let signature_s = [0xBBu8; ECC384_SCALAR_BYTE_SIZE];

    let req = EcdsaVerifyRequest::new(&cmk, message, &signature_r, &signature_s);

    assert_eq!(req.cmk, cmk);
    assert_eq!(req.message_size, message.len() as u32);
    assert_eq!(&req.message[..message.len()], message);
    assert_eq!(req.signature_r, signature_r);
    assert_eq!(req.signature_s, signature_s);

    println!("EcdsaVerifyRequest construction test passed!");
}

/// Test ECDH generate request construction
#[test]
fn test_ecdh_generate_request_construction() {
    let req = EcdhGenerateRequest::new();

    // Just verify it constructs without panicking
    // The _reserved field is private, so we just verify the struct is valid
    let _ = req;

    println!("EcdhGenerateRequest construction test passed!");
}

/// Test ECDH finish request construction
#[test]
fn test_ecdh_finish_request_construction() {
    let context = [0x44u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE];
    let incoming_exchange_data = [0x55u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE];

    let req = EcdhFinishRequest::new(&context, CmKeyUsage::Aes, &incoming_exchange_data);

    assert_eq!(req.context, context);
    assert_eq!(req.key_usage, CmKeyUsage::Aes as u32);
    assert_eq!(req.incoming_exchange_data, incoming_exchange_data);

    println!("EcdhFinishRequest construction test passed!");
}

/// Test ECDSA sign request with max message size
#[test]
fn test_ecdsa_sign_request_max_message() {
    let cmk = Cmk::default();
    let message = [0xCDu8; MAX_CMB_DATA_SIZE];

    let req = EcdsaSignRequest::new(&cmk, &message);

    assert_eq!(req.message_size, MAX_CMB_DATA_SIZE as u32);
    assert_eq!(&req.message[..], &message[..]);

    println!("EcdsaSignRequest max message test passed!");
}

/// Test ECDSA public key command with disconnected session
#[test]
fn test_ecdsa_public_key_disconnected_session() {
    println!("Testing ECDSA public key with disconnected session...");

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

    let cmk = Cmk::default();
    let result = caliptra_cmd_ecdsa_public_key(&mut session, &cmk);

    // Should fail because session is not connected
    match result {
        Ok(_) => {
            panic!("Expected ECDSA public key to fail with disconnected session, but it succeeded");
        }
        Err(e) => {
            println!(
                "ECDSA public key correctly failed with disconnected session: {:?}",
                e
            );
        }
    }

    println!("ECDSA public key disconnected session test completed!");
}

/// Test ECDSA sign command with disconnected session
#[test]
fn test_ecdsa_sign_disconnected_session() {
    println!("Testing ECDSA sign with disconnected session...");

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

    let cmk = Cmk::default();
    let message = b"test message";
    let result = caliptra_cmd_ecdsa_sign(&mut session, &cmk, message);

    match result {
        Ok(_) => {
            panic!("Expected ECDSA sign to fail with disconnected session, but it succeeded");
        }
        Err(e) => {
            println!(
                "ECDSA sign correctly failed with disconnected session: {:?}",
                e
            );
        }
    }

    println!("ECDSA sign disconnected session test completed!");
}

/// Test ECDH generate command with disconnected session
#[test]
fn test_ecdh_generate_disconnected_session() {
    println!("Testing ECDH generate with disconnected session...");

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

    let result = caliptra_cmd_ecdh_generate(&mut session);

    match result {
        Ok(_) => {
            panic!("Expected ECDH generate to fail with disconnected session, but it succeeded");
        }
        Err(e) => {
            println!(
                "ECDH generate correctly failed with disconnected session: {:?}",
                e
            );
        }
    }

    println!("ECDH generate disconnected session test completed!");
}

/// Test constants are correct
#[test]
fn test_asymmetric_constants() {
    // ECC384 scalar size should be 48 bytes (384 bits)
    assert_eq!(ECC384_SCALAR_BYTE_SIZE, 48);

    // ECDH exchange data is X || Y coordinates = 96 bytes
    assert_eq!(CMB_ECDH_EXCHANGE_DATA_MAX_SIZE, 96);

    // ECDH encrypted context = 48 (scalar) + 12 (IV) + 16 (tag) = 76 bytes
    assert_eq!(CMB_ECDH_ENCRYPTED_CONTEXT_SIZE, 76);

    // Max message size
    assert_eq!(MAX_CMB_DATA_SIZE, 4096);

    println!("Asymmetric constants test passed!");
}

/// Test CmKeyUsage includes Ecdsa variant
#[test]
fn test_cm_key_usage_ecdsa() {
    assert_eq!(CmKeyUsage::from(3u32), CmKeyUsage::Ecdsa);
    assert_eq!(u32::from(CmKeyUsage::Ecdsa), 3);

    println!("CmKeyUsage Ecdsa test passed!");
}

/// Test ECDSA sign request default values
#[test]
fn test_ecdsa_sign_request_default() {
    let req = EcdsaSignRequest::default();

    assert_eq!(req.cmk, Cmk::default());
    assert_eq!(req.message_size, 0);
    assert!(req.message.iter().all(|&b| b == 0));

    println!("EcdsaSignRequest default test passed!");
}

/// Test ECDH finish request default values
#[test]
fn test_ecdh_finish_request_default() {
    let req = EcdhFinishRequest::default();

    assert!(req.context.iter().all(|&b| b == 0));
    assert_eq!(req.key_usage, CmKeyUsage::Reserved as u32);
    assert!(req.incoming_exchange_data.iter().all(|&b| b == 0));

    println!("EcdhFinishRequest default test passed!");
}

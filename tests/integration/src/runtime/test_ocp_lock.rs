// Licensed under the Apache-2.0 license

use crate::test::{start_runtime_hw_model, TestParams};
use anyhow::Result;
use caliptra_mcu_hw_model::McuHwModel;
use caliptra_mcu_mbox_common::messages::{
    OcpLockRotateHekReq, OcpLockRotateHekResp, OcpLockSetPermaHekReq, OcpLockSetPermaHekResp,
};
use caliptra_mcu_registers_generated::fuses;
use caliptra_mcu_romtime::McuBootMilestones;
use openssl::x509::X509;
use x509_parser::der_parser::ber::parse_ber_sequence;
use x509_parser::nom::Parser;
use x509_parser::prelude::X509CertificateParser;

#[test]
fn test_otp_perma_hek_mailbox() -> Result<()> {
    let _lock = crate::test::TEST_LOCK.lock().unwrap();
    let mut otp = vec![0u8; 4096];
    for slot in 0..8 {
        crate::test_hek::test::setup_otp_hek(&mut otp, slot, true, false);
    }

    let mut hw = start_runtime_hw_model(TestParams {
        otp_memory: Some(otp),
        ..TestParams::from_target(&caliptra_mcu_builder::firmware::targets::TEST_OCP_LOCK)
    });

    // wait for the mailbox to come up
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // 1. Verify initial state in OTP memory is 0
    let otp_before = hw.read_otp_memory();
    assert_eq!(otp_before[fuses::PERMA_HEK_EN.byte_offset] & 0x7, 0);

    // 2. Write to set Perma HEK
    let write_req = OcpLockSetPermaHekReq::default();
    let _write_resp: OcpLockSetPermaHekResp =
        super::execute_authorized_req(&mut hw, write_req).unwrap();

    // 3. Verify OTP memory has been updated
    let otp_after = hw.read_otp_memory();
    assert_eq!(otp_after[fuses::PERMA_HEK_EN.byte_offset] & 0x7, 0x7);

    Ok(())
}

#[test]
#[cfg(not(feature = "fpga_realtime"))]
fn test_otp_perma_hek_mailbox_not_zeroized_failure() -> Result<()> {
    let _lock = crate::test::TEST_LOCK.lock().unwrap();
    let mut otp = vec![0u8; 4096];
    // Program a valid HEK in slot 0 (so it is not zeroized)
    crate::test_hek::test::setup_otp_hek(&mut otp, 0, false, false);
    for slot in 1..8 {
        crate::test_hek::test::setup_otp_hek(&mut otp, slot, true, false);
    }

    let mut hw = start_runtime_hw_model(TestParams {
        otp_memory: Some(otp),
        ..TestParams::from_target(&caliptra_mcu_builder::firmware::targets::TEST_OCP_LOCK)
    });

    // wait for the mailbox to come up
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // 1. Verify initial state in OTP memory is 0
    let otp_before = hw.read_otp_memory();
    assert_eq!(otp_before[fuses::PERMA_HEK_EN.byte_offset] & 0x7, 0);

    // 2. Write to set Perma HEK (should fail because slot 0 is not zeroized)
    let write_req = OcpLockSetPermaHekReq::default();
    let result = super::execute_authorized_req(&mut hw, write_req);
    assert!(result.is_err());

    // 3. Verify OTP memory has NOT been updated
    let otp_after = hw.read_otp_memory();
    assert_eq!(otp_after[fuses::PERMA_HEK_EN.byte_offset] & 0x7, 0);

    Ok(())
}

#[test]
#[cfg(not(feature = "fpga_realtime"))]
fn test_otp_rotate_hek_mailbox() -> Result<()> {
    let _lock = crate::test::TEST_LOCK.lock().unwrap();
    let mut otp = vec![0u8; 4096];

    // Program valid HEK in slot 0 (slot 1 starts empty)
    crate::test_hek::test::setup_otp_hek(&mut otp, 0, false, false);

    let mut hw = start_runtime_hw_model(TestParams {
        otp_memory: Some(otp),
        target: &caliptra_mcu_builder::firmware::targets::TEST_OCP_LOCK,
        ..Default::default()
    });

    // Wait for the mailbox to come up
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Check initial active slot in output
    let initial_output = hw.output().peek();
    assert!(initial_output.contains("[mcu-runtime] HEK state from handoff"));
    assert!(initial_output.contains("active_state=Programmed"));
    assert!(initial_output.contains("active_slot=0"));
    assert!(initial_output.contains("total_slots=8"));

    // OTP offsets for Slot 0 and 1
    let slot0_offset =
        caliptra_mcu_registers_generated::fuses::CPTRA_SS_LOCK_HEK_PROD_0_BYTE_OFFSET;
    let slot1_offset =
        caliptra_mcu_registers_generated::fuses::CPTRA_SS_LOCK_HEK_PROD_1_BYTE_OFFSET;

    // Verify initial OTP state (Slot 0 and Slot 1 are not sanitized)
    let otp_before = hw.read_otp_memory();
    assert_ne!(otp_before[slot0_offset], 0x00);
    assert_ne!(otp_before[slot0_offset], 0xFF);
    assert_ne!(otp_before[slot1_offset], 0xFF);
    assert_eq!(otp_before[slot1_offset], 0x00);

    // Send MC_OCP_LOCK_ROTATE_HEK
    let rotate_req = OcpLockRotateHekReq {
        hek_slot: 1,
        ..Default::default()
    };
    let _rotate_resp: OcpLockRotateHekResp = super::execute_authorized_req(&mut hw, rotate_req)?;

    // Verify Slot 0 OTP memory is sanitized (all 0xFF)
    let otp_after = hw.read_otp_memory();
    for i in 0..48 {
        assert_eq!(
            otp_after[slot0_offset + i],
            0xFF,
            "Slot 0 word {i} should be sanitized (0xFF)"
        );
    }

    // Verify Slot 1 is still valid and modified (since it was programmed with a new random seed)
    let new_seed = &otp_after[slot1_offset..slot1_offset + 32];
    let new_digest_bytes = &otp_after[slot1_offset + 32..slot1_offset + 40];
    let new_digest = u64::from_le_bytes(new_digest_bytes.try_into().unwrap());

    let expected_digest = caliptra_mcu_otp_digest::caliptra_mcu_otp_digest(
        new_seed,
        caliptra_mcu_otp_digest::OTP_DIGEST_IV,
        caliptra_mcu_otp_digest::OTP_DIGEST_CONST,
    );
    assert_eq!(
        new_digest, expected_digest,
        "New digest in Slot 1 should be valid"
    );

    // Reboot the model
    let modified_otp = otp_after;
    drop(hw);

    let mut hw_after_reboot = start_runtime_hw_model(TestParams {
        otp_memory: Some(modified_otp),
        ..TestParams::from_target(&caliptra_mcu_builder::firmware::targets::TEST_OCP_LOCK)
    });

    // Wait for the mailbox to come up
    hw_after_reboot.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Verify that Slot 1 is now the active slot!
    let reboot_output = hw_after_reboot.output().peek();
    assert!(reboot_output.contains("[mcu-runtime] HEK state from handoff"));
    assert!(reboot_output.contains("active_state=Programmed"));
    assert!(reboot_output.contains("active_slot=1"));
    assert!(reboot_output.contains("total_slots=8"));

    Ok(())
}

#[test]
fn test_get_ocp_lock_endorsement_cert_cmd() -> Result<()> {
    let _lock = crate::test::TEST_LOCK.lock().unwrap();
    let mut hw = start_runtime_hw_model(TestParams::from_target(
        &caliptra_mcu_builder::firmware::targets::TEST_OCP_LOCK,
    ));

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let enum_cmd = caliptra_mcu_mbox_common::messages::OcpLockEnumerateHpkeHandlesReq::default();
    let enum_resp = hw.mailbox_execute_req(enum_cmd)?;

    // Find the handle associated with ECDHE (ECDH_P384_HKDF_SHA384_AES_256_GCM)
    let handle = enum_resp.hpke_handles[..enum_resp.hpke_handle_count as usize]
        .iter()
        .find(|h| {
            h.hpke_algorithm
                == caliptra_api::mailbox::HpkeAlgorithms::ECDH_P384_HKDF_SHA384_AES_256_GCM
        })
        .expect("Failed to find ECDHE HPKE handle")
        .clone();

    // 2. Get OCP LOCK Endorsement Certificate from MCU Mailbox
    let cmd = caliptra_mcu_mbox_common::messages::GetOcpLockEndorsementCertReq {
        hdr: caliptra_mcu_mbox_common::messages::MailboxReqHeader::default(),
        hpke_handle: handle,
    };

    let resp = hw.mailbox_execute_req(cmd)?;

    let cert_len = resp.hdr.data_len as usize;
    assert!(cert_len > 0, "Certificate length should be greater than 0");
    assert!(
        cert_len <= caliptra_mcu_mbox_common::messages::MAX_RESP_DATA_SIZE,
        "Certificate length should be within limits"
    );

    // Verify it looks like a DER certificate (starts with 0x30)
    assert_eq!(
        resp.data[0], 0x30,
        "Certificate should start with ASN.1 SEQUENCE tag (0x30)"
    );

    let endorsement_cert_der = &resp.data[..cert_len];
    let endorsement_cert = X509::from_der(endorsement_cert_der)
        .expect("Failed to parse endorsement certificate as DER");

    // Verify the issuer name is what we expected ("DPE Leaf")
    let issuer_name = endorsement_cert.issuer_name();
    let issuer_entry = issuer_name
        .entries()
        .next()
        .expect("No entries in issuer name");
    assert_eq!(
        issuer_entry.data().as_slice(),
        b"DPE Leaf",
        "Issuer name should match what we requested"
    );

    // Verify the subject name is what we expected
    let subject_name = endorsement_cert.subject_name();
    let entry = subject_name
        .entries()
        .next()
        .expect("No entries in subject name");
    assert_eq!(
        entry.data().as_slice(),
        b"Caliptra MCU OCP LOCK Endorsement",
        "Subject name should match what we requested"
    );

    // 3. Verify HPKE Identifiers Extension is present and correct (using x509_parser)
    let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
    let parsed_cert = match parser.parse(endorsement_cert_der) {
        Ok((_, parsed_cert)) => parsed_cert,
        Err(e) => panic!("x509 parsing failed: {:?}", e),
    };

    // Verify Serial Number is the expected 20-byte constant [0x7F; 20]
    assert_eq!(
        parsed_cert.tbs_certificate.serial.to_bytes_be(),
        &[0x7F; 20],
        "Certificate serial number mismatch!"
    );

    // Verify Basic Constraints (critical, not a CA)
    let basic_constraints = parsed_cert
        .basic_constraints()
        .expect("Failed to parse basic constraints")
        .expect("Basic constraints extension missing");
    assert!(
        basic_constraints.critical,
        "Basic constraints should be critical"
    );
    assert!(
        !basic_constraints.value.ca,
        "Certificate should not be a CA"
    );

    // Verify Key Usage (critical, key encipherment only)
    let key_usage = parsed_cert
        .key_usage()
        .expect("Failed to parse key usage")
        .expect("Key usage extension missing");
    assert!(key_usage.critical, "Key usage should be critical");
    assert!(
        key_usage.value.key_encipherment(),
        "Key usage should allow key encipherment"
    );
    assert!(
        !key_usage.value.key_cert_sign(),
        "Key usage should not allow key cert sign"
    );
    assert!(
        !key_usage.value.digital_signature(),
        "Key usage should not allow digital signature"
    );

    let hpke_oid = x509_parser::oid_registry::asn1_rs::oid!(2.23.133 .21 .1 .1);
    let hpke_ext = parsed_cert
        .tbs_certificate
        .extensions()
        .iter()
        .find(|e| e.oid == hpke_oid)
        .expect("HPKE Identifiers extension not found in certificate!");

    // Verify HPKE Identifiers Extension is NOT critical
    assert!(
        !hpke_ext.critical,
        "HPKE Identifiers extension should not be critical"
    );

    let (_, seq) =
        parse_ber_sequence(hpke_ext.value).expect("Failed to parse HPKE identifiers sequence");

    let items = seq
        .content
        .as_sequence()
        .expect("HPKE Identifiers extension is not a sequence");

    assert_eq!(
        items.len(),
        3,
        "HPKE Identifiers sequence must have exactly 3 items"
    );

    let kem_id = items[0]
        .as_u32()
        .expect("Failed to parse KEM ID as integer");
    let kdf_id = items[1]
        .as_u32()
        .expect("Failed to parse KDF ID as integer");
    let aead_id = items[2]
        .as_u32()
        .expect("Failed to parse AEAD ID as integer");

    assert_eq!(kem_id, 17, "KEM ID mismatch (expected 17 for P384)");
    assert_eq!(kdf_id, 2, "KDF ID mismatch (expected 2 for HKDF-SHA384)");
    assert_eq!(aead_id, 2, "AEAD ID mismatch (expected 2 for AES-256-GCM)");

    Ok(())
}

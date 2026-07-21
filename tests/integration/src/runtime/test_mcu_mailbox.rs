// Licensed under the Apache-2.0 license

use crate::runtime::{
    asym_custom_fw, build_asym_fw, build_asym_fw_features, execute_authorized_req_asym,
    vendor_auth_keys,
};
use crate::test::{start_runtime_hw_model, TestParams};
use anyhow::Result;
use caliptra_mcu_command_auth_challenge_signer::LocalVendorAuthSigner;
use caliptra_mcu_hw_model::{LifecycleControllerState, McuHwModel};
use caliptra_mcu_mbox_common::messages::{
    FirmwareVersionReq, McuFeProgReq, OcpLockRotateHekReq, OcpLockRotateHekResp,
    OcpLockSetPermaHekReq, OcpLockSetPermaHekResp,
};
use caliptra_mcu_registers_generated::fuses;
use caliptra_mcu_romtime::McuBootMilestones;

#[test]
fn test_invalid_mailbox_cmd() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });

    // wait another little bit for the mailbox to come up after the runtime
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Send an unknown command (0x0) with an invalid checksum.
    // The firmware should reject it with a mailbox failure.
    let cmd: u32 = 0x0;
    let resp = hw.mailbox_execute(cmd, &[0xaau8; 8]);
    let err_msg = format!("{}", resp.unwrap_err());
    assert!(
        !err_msg.contains("timed out"),
        "Mailbox command should fail with error, not time out. Got: {err_msg}"
    );
    Ok(())
}

#[test]
fn test_firmware_version_cmd() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });

    // wait another little bit for the mailbox to come up after the runtime
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let cmd = FirmwareVersionReq::default();
    let resp = hw.mailbox_execute_req(cmd)?;

    let expected_version = caliptra_mcu_mbox_common::config::TEST_FIRMWARE_VERSIONS[0];
    assert_eq!(resp.hdr.data_len, expected_version.len() as u32);
    let resp_version_str = std::str::from_utf8(&resp.version[..resp.hdr.data_len as usize])
        .expect("Version string is not valid UTF-8");
    assert_eq!(resp_version_str, expected_version);
    Ok(())
}

#[test]
fn test_fe_prog_authorized_req() -> Result<()> {
    let signer = LocalVendorAuthSigner::new(vendor_auth_keys());
    let fw = build_asym_fw(&signer)?;

    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        custom_mcu_runtime: Some(fw.mcu_runtime.clone()),
        custom_caliptra_fw: Some(asym_custom_fw(&fw)),
        lifecycle_controller_state: Some(LifecycleControllerState::Prod),
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Verify FE_PROG authorized request succeeds via the asymmetric path.
    let cmd = McuFeProgReq {
        partition: 0,
        ..Default::default()
    };
    let result = execute_authorized_req_asym(&mut hw, cmd, &signer);
    assert!(
        result.is_ok(),
        "FE_PROG authorized request failed: {result:?}"
    );

    Ok(())
}

#[test]
fn test_otp_perma_hek_mailbox() -> Result<()> {
    let _lock = crate::test::TEST_LOCK.lock().unwrap();
    let signer = LocalVendorAuthSigner::new(vendor_auth_keys());
    let fw = build_asym_fw_features(&signer, &["ocp-lock"])?;
    let mut otp = vec![0u8; 4096];
    for slot in 0..8 {
        crate::test_hek::test::setup_otp_hek(&mut otp, slot, true, false);
    }

    let mut hw = start_runtime_hw_model(TestParams {
        otp_memory: Some(otp),
        ocp_lock_en: true,
        feature: Some("test-mcu-mbox-cmds,ocp-lock"),
        rom_feature: Some("ocp-lock"),
        custom_mcu_runtime: Some(fw.mcu_runtime.clone()),
        custom_caliptra_fw: Some(asym_custom_fw(&fw)),
        ..Default::default()
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
        execute_authorized_req_asym(&mut hw, write_req, &signer).unwrap();

    // 3. Verify OTP memory has been updated
    let otp_after = hw.read_otp_memory();
    assert_eq!(otp_after[fuses::PERMA_HEK_EN.byte_offset] & 0x7, 0x7);

    Ok(())
}

#[test]
fn test_otp_perma_hek_mailbox_not_zeroized_failure() -> Result<()> {
    let _lock = crate::test::TEST_LOCK.lock().unwrap();
    let signer = LocalVendorAuthSigner::new(vendor_auth_keys());
    let fw = build_asym_fw_features(&signer, &["ocp-lock"])?;
    let mut otp = vec![0u8; 4096];
    // Program a valid HEK in slot 0 (so it is not zeroized)
    crate::test_hek::test::setup_otp_hek(&mut otp, 0, false, false);
    for slot in 1..8 {
        crate::test_hek::test::setup_otp_hek(&mut otp, slot, true, false);
    }

    let mut hw = start_runtime_hw_model(TestParams {
        otp_memory: Some(otp),
        ocp_lock_en: true,
        feature: Some("test-mcu-mbox-cmds,ocp-lock"),
        rom_feature: Some("ocp-lock"),
        custom_mcu_runtime: Some(fw.mcu_runtime.clone()),
        custom_caliptra_fw: Some(asym_custom_fw(&fw)),
        ..Default::default()
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
    let result = execute_authorized_req_asym(&mut hw, write_req, &signer);
    assert!(result.is_err());

    // 3. Verify OTP memory has NOT been updated
    let otp_after = hw.read_otp_memory();
    assert_eq!(otp_after[fuses::PERMA_HEK_EN.byte_offset] & 0x7, 0);

    Ok(())
}
#[test]
fn test_otp_rotate_hek_mailbox() -> Result<()> {
    let _lock = crate::test::TEST_LOCK.lock().unwrap();
    let signer = LocalVendorAuthSigner::new(vendor_auth_keys());
    let fw = build_asym_fw_features(&signer, &["ocp-lock"])?;
    let mut otp = vec![0u8; 4096];

    // Program valid HEK in slot 0 (slot 1 starts empty)
    crate::test_hek::test::setup_otp_hek(&mut otp, 0, false, false);

    let mut hw = start_runtime_hw_model(TestParams {
        otp_memory: Some(otp),
        ocp_lock_en: true,
        feature: Some("test-mcu-mbox-cmds,ocp-lock"),
        rom_feature: Some("ocp-lock"),
        custom_mcu_runtime: Some(fw.mcu_runtime.clone()),
        custom_caliptra_fw: Some(asym_custom_fw(&fw)),
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
    let _rotate_resp: OcpLockRotateHekResp =
        execute_authorized_req_asym(&mut hw, rotate_req, &signer)?;

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
        ocp_lock_en: true,
        feature: Some("test-mcu-mbox-cmds,ocp-lock"),
        rom_feature: Some("ocp-lock"),
        custom_mcu_runtime: Some(fw.mcu_runtime.clone()),
        custom_caliptra_fw: Some(asym_custom_fw(&fw)),
        ..Default::default()
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

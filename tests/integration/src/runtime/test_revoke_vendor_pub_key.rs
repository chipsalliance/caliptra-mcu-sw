// Licensed under the Apache-2.0 license

use crate::{
    runtime::{execute_authorized_req_asym, vendor_auth_keys},
    test::{compile_runtime, start_runtime_hw_model, CustomCaliptraFw, TestParams},
};
use anyhow::Result;
use caliptra_api::{error::CaliptraError, mailbox::MailboxReqHeader, SocManager};
use caliptra_mcu_builder::{CaliptraBuildArgs, CaliptraBuilder};
use caliptra_mcu_command_auth_challenge_signer::LocalVendorAuthSigner;
use caliptra_mcu_hw_model::{LifecycleControllerState, McuHwModel};
use caliptra_mcu_mbox_common::messages::{
    FuseRevokeVendorPkHashReq, FuseRevokeVendorPubKeyReq, ProvisionVendorPkHashReq,
    RevokeVendorPubKeyType,
};
use caliptra_mcu_romtime::McuBootMilestones;

/// Build asym firmware (key1 + key2) with a v2 vendor-auth anchor matching `signer`.
/// Returns (fw_key1, fw_key2, vendor_pk_hash, soc_manifest, mcu_runtime).
fn get_fw(
    signer: &LocalVendorAuthSigner,
) -> Result<(Vec<u8>, Vec<u8>, [u8; 48], Vec<u8>, Vec<u8>)> {
    let mcu_runtime_path = compile_runtime(Some("test-mcu-mbox-cmds,asym-cmd-auth"), false);
    let mcu_runtime = std::fs::read(&mcu_runtime_path)?;
    let mut builder = CaliptraBuilder::from_args(&CaliptraBuildArgs {
        mcu_firmware: Some(mcu_runtime_path.clone()),
        ..Default::default()
    })
    .with_vendor_cmd_auth_pk_hash(signer.anchor());
    let fw = std::fs::read(builder.get_caliptra_fw()?)?;
    let mut builder_key2 = CaliptraBuilder::from_args(&CaliptraBuildArgs {
        mcu_firmware: Some(mcu_runtime_path),
        use_second_key: true,
        ..Default::default()
    })
    .with_vendor_cmd_auth_pk_hash(signer.anchor());
    let fw_key2 = std::fs::read(builder_key2.get_caliptra_fw()?)?;
    let pk_hash = hex::decode(builder.get_vendor_pk_hash()?)?;
    let mut pk_hash_arr = [0u8; 48];
    pk_hash_arr.copy_from_slice(&pk_hash);
    let manifest = std::fs::read(builder.get_soc_manifest(None)?)?;
    Ok((fw, fw_key2, pk_hash_arr, manifest, mcu_runtime))
}

#[test]
fn test_revoke_vendor_pub_key0_ecdsa() -> Result<()> {
    let signer = LocalVendorAuthSigner::new(vendor_auth_keys());
    let (caliptra_fw, caliptra_fw_key2, vendor_pk_hash_arr, soc_manifest, mcu_runtime) =
        get_fw(&signer)?;

    // Boot with default caliptra_fw (key_index = 0)
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        custom_mcu_runtime: Some(mcu_runtime),
        custom_caliptra_fw: Some(CustomCaliptraFw {
            fw_bytes: caliptra_fw,
            vendor_pk_hash: vendor_pk_hash_arr,
            soc_manifest: soc_manifest.clone(),
        }),
        lifecycle_controller_state: Some(LifecycleControllerState::Prod),
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Check revoking the boot ECC key fails
    let cmd = FuseRevokeVendorPubKeyReq {
        vendor_pk_hash_slot: 0,
        key_type: RevokeVendorPubKeyType::Ecdsa384.into(),
        key_index: 0,
        ..Default::default()
    };
    let result = execute_authorized_req_asym(&mut hw, cmd, &signer);
    assert!(result.is_err());

    // Check revoking a non-existent slot fails
    let cmd = FuseRevokeVendorPubKeyReq {
        vendor_pk_hash_slot: 16,
        key_type: RevokeVendorPubKeyType::Ecdsa384.into(),
        key_index: 0,
        ..Default::default()
    };
    let result = execute_authorized_req_asym(&mut hw, cmd, &signer);
    assert!(result.is_err());

    // Check revoking an ECC key that wasn't used to boot succeeds
    let cmd = FuseRevokeVendorPubKeyReq {
        vendor_pk_hash_slot: 0,
        key_type: RevokeVendorPubKeyType::Ecdsa384.into(),
        key_index: 1,
        ..Default::default()
    };
    let _resp = execute_authorized_req_asym(&mut hw, cmd, &signer);

    // Read OTP memory so we can use the same config in later boots.
    let otp = hw.read_otp_memory();

    // We use `rom_only: true` here to prevent the emulator initialization from
    // blocking or crashing while waiting for a successful boot that will never happen.
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        custom_caliptra_fw: Some(CustomCaliptraFw {
            fw_bytes: caliptra_fw_key2,
            vendor_pk_hash: vendor_pk_hash_arr,
            soc_manifest,
        }),
        otp_memory: Some(otp),
        rom_only: true,
        ..Default::default()
    });

    // Step the model until a fatal error is reported by Caliptra.
    hw.step_until(|hw| {
        hw.caliptra_soc_manager()
            .soc_ifc()
            .cptra_fw_error_fatal()
            .read()
            != 0
    });

    // Verify that the fatal error corresponds to the revoked key from the last boot
    assert_eq!(
        hw.caliptra_soc_manager()
            .soc_ifc()
            .cptra_fw_error_fatal()
            .read(),
        u32::from(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_REVOKED)
    );
    Ok(())
}

#[test]
fn test_revoke_vendor_pub_key0_lms() -> Result<()> {
    let signer = LocalVendorAuthSigner::new(vendor_auth_keys());
    let (caliptra_fw, caliptra_fw_key2, vendor_pk_hash_arr, soc_manifest, mcu_runtime) =
        get_fw(&signer)?;

    // Boot with default caliptra_fw (key_index = 0)
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        custom_mcu_runtime: Some(mcu_runtime),
        custom_caliptra_fw: Some(CustomCaliptraFw {
            fw_bytes: caliptra_fw,
            vendor_pk_hash: vendor_pk_hash_arr,
            soc_manifest: soc_manifest.clone(),
        }),
        lifecycle_controller_state: Some(LifecycleControllerState::Prod),
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Check revoking the boot PQC key fails
    let cmd = FuseRevokeVendorPubKeyReq {
        vendor_pk_hash_slot: 0,
        key_type: RevokeVendorPubKeyType::Lms.into(),
        key_index: 0,
        ..Default::default()
    };
    let result = execute_authorized_req_asym(&mut hw, cmd, &signer);
    assert!(result.is_err());

    // Check revoking a PQC key that wasn't used to boot succeeds
    let cmd = FuseRevokeVendorPubKeyReq {
        vendor_pk_hash_slot: 0,
        key_type: RevokeVendorPubKeyType::Lms.into(),
        key_index: 1,
        ..Default::default()
    };
    let _resp = execute_authorized_req_asym(&mut hw, cmd, &signer);

    // Read OTP memory so we can use the same config in later boots.
    let otp = hw.read_otp_memory();

    // We use `rom_only: true` here to prevent the emulator initialization from
    // blocking or crashing while waiting for a successful boot that will never happen.
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        custom_caliptra_fw: Some(CustomCaliptraFw {
            fw_bytes: caliptra_fw_key2,
            vendor_pk_hash: vendor_pk_hash_arr,
            soc_manifest,
        }),
        otp_memory: Some(otp),
        rom_only: true,
        ..Default::default()
    });

    // Step the model until a fatal error is reported by Caliptra.
    hw.step_until(|hw| {
        hw.caliptra_soc_manager()
            .soc_ifc()
            .cptra_fw_error_fatal()
            .read()
            != 0
    });

    // Verify that the fatal error corresponds to the revoked key from the last boot
    assert_eq!(
        hw.caliptra_soc_manager()
            .soc_ifc()
            .cptra_fw_error_fatal()
            .read(),
        u32::from(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PQC_PUB_KEY_REVOKED)
    );
    Ok(())
}

#[test]
fn test_rotate_vendor_pk_hash() -> Result<()> {
    let signer = LocalVendorAuthSigner::new(vendor_auth_keys());
    let (caliptra_fw, _caliptra_fw_key2, vendor_pk_hash_arr, soc_manifest, mcu_runtime) =
        get_fw(&signer)?;

    // Boot with default caliptra_fw
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        custom_mcu_runtime: Some(mcu_runtime.clone()),
        custom_caliptra_fw: Some(CustomCaliptraFw {
            fw_bytes: caliptra_fw.clone(),
            vendor_pk_hash: vendor_pk_hash_arr,
            soc_manifest: soc_manifest.clone(),
        }),
        lifecycle_controller_state: Some(LifecycleControllerState::Prod),
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Check revoking the active PK hash fails
    let cmd = FuseRevokeVendorPkHashReq {
        vendor_pk_hash_slot: 0,
        ..Default::default()
    };
    let result = execute_authorized_req_asym(&mut hw, cmd, &signer);
    assert!(result.is_err());

    // We can reuse the existing pk hash,
    // but have to change something for revocation to succeed.
    let mut new_pk_hash = vendor_pk_hash_arr;
    new_pk_hash[0] = 0x42;
    // Provision a new vendor PK hash
    let cmd = ProvisionVendorPkHashReq {
        slot: 1,
        hash: new_pk_hash,
        hdr: MailboxReqHeader::default(),
    };
    let resp = execute_authorized_req_asym(&mut hw, cmd, &signer);
    assert!(resp.is_ok(), "{:?}", resp);

    // Check revoking a pk hash that isn't active succeeds
    let cmd = FuseRevokeVendorPkHashReq {
        vendor_pk_hash_slot: 1,
        ..Default::default()
    };
    let resp = execute_authorized_req_asym(&mut hw, cmd, &signer);
    assert!(resp.is_ok());

    // Read OTP memory so we can use the same config in later boots.
    let otp = hw.read_otp_memory();

    // Boot with caliptra_fw again
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        custom_mcu_runtime: Some(mcu_runtime),
        custom_caliptra_fw: Some(CustomCaliptraFw {
            fw_bytes: caliptra_fw,
            vendor_pk_hash: vendor_pk_hash_arr,
            soc_manifest: soc_manifest.clone(),
        }),
        otp_memory: Some(otp),
        lifecycle_controller_state: Some(LifecycleControllerState::Prod),
        ..Default::default()
    });

    // Wait for the mailbox to become ready, indicating the runtime has booted.
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // TODO: Boot firmware for new vendor key, then revoke the old key in slot 0.
    //       (For this, an image with new keys has to be created first.
    //       The current key 2 image uses the same PK hash.)

    Ok(())
}

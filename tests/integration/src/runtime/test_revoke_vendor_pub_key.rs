// Licensed under the Apache-2.0 license

use crate::{
    runtime::execute_authorized_req,
    test::{compile_runtime, start_runtime_hw_model, CustomCaliptraFw, TestParams},
};
use anyhow::Result;
use caliptra_api::{error::CaliptraError, SocManager};
use caliptra_mcu_builder::{CaliptraBuildArgs, CaliptraBuilder, FirmwareBinaries};
use caliptra_mcu_hw_model::{LifecycleControllerState, McuHwModel};
use caliptra_mcu_mbox_common::messages::{FuseRevokeVendorPubKeyReq, RevokeVendorPubKeyType};
use caliptra_mcu_romtime::McuBootMilestones;

fn get_fw() -> Result<(Vec<u8>, Vec<u8>, [u8; 48], Vec<u8>)> {
    if let Ok(binaries) = FirmwareBinaries::from_env() {
        let fw = binaries.caliptra_fw.clone();
        let fw_key2 = binaries.caliptra_fw_key2.clone();
        let pk_hash = binaries.vendor_pk_hash().unwrap();
        let manifest = binaries.test_soc_manifest("test-mcu-mbox-cmds")?.clone();
        Ok((fw, fw_key2, pk_hash, manifest))
    } else {
        let mcu_runtime_path = compile_runtime(Some("test-mcu-mbox-cmds"), false);
        let mut builder = CaliptraBuilder::new(&CaliptraBuildArgs {
            mcu_firmware: Some(mcu_runtime_path.clone()),
            ..Default::default()
        });
        let fw = std::fs::read(builder.get_caliptra_fw()?).unwrap();
        let mut builder_key2 = CaliptraBuilder::new(&CaliptraBuildArgs {
            mcu_firmware: Some(mcu_runtime_path),
            use_second_key: true,
            ..Default::default()
        });
        let fw_key2 = std::fs::read(builder_key2.get_caliptra_fw()?).unwrap();
        let pk_hash_str = builder.get_vendor_pk_hash()?.to_string();
        let pk_hash = hex::decode(&pk_hash_str).unwrap();
        let mut pk_hash_arr = [0u8; 48];
        pk_hash_arr.copy_from_slice(&pk_hash);
        let manifest = std::fs::read(builder.get_soc_manifest(None)?).unwrap();
        Ok((fw, fw_key2, pk_hash_arr, manifest))
    }
}

#[test]
fn test_revoke_vendor_pub_key0_ecdsa() -> Result<()> {
    let (caliptra_fw, caliptra_fw_key2, vendor_pk_hash_arr, soc_manifest) = get_fw()?;

    // Boot with default caliptra_fw (key_index = 0)
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
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
    let result = execute_authorized_req(&mut hw, cmd);
    assert!(result.is_err());

    // Check revoking a non-existent slot fails
    let cmd = FuseRevokeVendorPubKeyReq {
        vendor_pk_hash_slot: 16,
        key_type: RevokeVendorPubKeyType::Ecdsa384.into(),
        key_index: 0,
        ..Default::default()
    };
    let result = execute_authorized_req(&mut hw, cmd);
    assert!(result.is_err());

    // Check revoking an ECC key that wasn't used to boot succeeds
    let cmd = FuseRevokeVendorPubKeyReq {
        vendor_pk_hash_slot: 0,
        key_type: RevokeVendorPubKeyType::Ecdsa384.into(),
        key_index: 1,
        ..Default::default()
    };
    let _resp = execute_authorized_req(&mut hw, cmd);

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
    let (caliptra_fw, caliptra_fw_key2, vendor_pk_hash_arr, soc_manifest) = get_fw()?;

    // Boot with default caliptra_fw (key_index = 0)
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
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
    let result = execute_authorized_req(&mut hw, cmd);
    assert!(result.is_err());

    // Check revoking a PQC key that wasn't used to boot succeeds
    let cmd = FuseRevokeVendorPubKeyReq {
        vendor_pk_hash_slot: 0,
        key_type: RevokeVendorPubKeyType::Lms.into(),
        key_index: 1,
        ..Default::default()
    };
    let _resp = execute_authorized_req(&mut hw, cmd);

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

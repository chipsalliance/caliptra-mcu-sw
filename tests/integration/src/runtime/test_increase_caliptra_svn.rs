// Licensed under the Apache-2.0 license

use crate::test::{compile_runtime, start_runtime_hw_model, CustomCaliptraFw, TestParams};
use anyhow::Result;
use caliptra_api::{calc_checksum, error::CaliptraError, mailbox::FwInfoResp, SocManager};
use caliptra_mcu_builder::{CaliptraBuildArgs, CaliptraBuilder, FirmwareBinaries};
use caliptra_mcu_hw_model::{LifecycleControllerState, McuHwModel};
use caliptra_mcu_mbox_common::messages::FuseIncreaseCaliptraMinSvnReq;
use caliptra_mcu_romtime::McuBootMilestones;
use zerocopy::{FromBytes, IntoBytes};

#[test]
fn test_increase_caliptra_svn() -> Result<()> {
    // Step 1: Compile runtime with specific features and build initial Caliptra
    // firmware with SVN = 0 and SVN = 7.
    let mcu_runtime_path = compile_runtime(Some("test-mcu-mbox-cmds"), false);
    let (caliptra_fw_svn0, caliptra_fw_svn7, vendor_pk_hash_arr, soc_manifest) =
        if let Ok(binaries) = FirmwareBinaries::from_env() {
            let fw_svn0 = binaries.caliptra_fw.clone();
            let fw_svn7 = binaries.caliptra_fw_svn7.clone();
            let pk_hash = binaries.vendor_pk_hash().unwrap();
            let manifest = binaries.test_soc_manifest("test-mcu-mbox-cmds").unwrap();
            (fw_svn0, fw_svn7, pk_hash, manifest)
        } else {
            let mut builder = CaliptraBuilder::new(&CaliptraBuildArgs {
                svn: Some(0),
                mcu_firmware: Some(mcu_runtime_path.clone()),
                ..Default::default()
            });
            let fw_svn0 = std::fs::read(builder.get_caliptra_fw()?).unwrap();
            let mut builder = CaliptraBuilder::new(&CaliptraBuildArgs {
                svn: Some(7),
                mcu_firmware: Some(mcu_runtime_path),
                ..Default::default()
            });
            let fw_svn7 = std::fs::read(builder.get_caliptra_fw()?).unwrap();
            let pk_hash_str = builder.get_vendor_pk_hash()?.to_string();
            let pk_hash = hex::decode(&pk_hash_str).unwrap();
            let mut pk_hash_arr = [0u8; 48];
            pk_hash_arr.copy_from_slice(&pk_hash);
            let manifest = std::fs::read(builder.get_soc_manifest(None)?).unwrap();
            (fw_svn0, fw_svn7, pk_hash_arr, manifest)
        };

    // Start the hardware model with the custom Caliptra firmware (SVN 7).
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        custom_caliptra_fw: Some(CustomCaliptraFw {
            fw_bytes: caliptra_fw_svn7.clone(),
            vendor_pk_hash: vendor_pk_hash_arr,
            soc_manifest: soc_manifest.clone(),
        }),
        lifecycle_controller_state: Some(LifecycleControllerState::Prod),
        ..Default::default()
    });

    // Wait for the mailbox to become ready, indicating the runtime has booted.
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Check setting the SVN to 0 fails
    let cmd = FuseIncreaseCaliptraMinSvnReq {
        svn: 0,
        ..Default::default()
    };
    let result = hw.mailbox_execute_req(cmd);
    assert!(result.is_err());

    // Check requesting to increase SVN past what is currently running returns an error.
    // Running SVN is 7, so requesting 8 should fail.
    let cmd = FuseIncreaseCaliptraMinSvnReq {
        svn: 8,
        ..Default::default()
    };
    let result = hw.mailbox_execute_req(cmd);
    assert!(result.is_err());

    // Check trying to burn a value greater than 128 returns an error.
    let cmd = FuseIncreaseCaliptraMinSvnReq {
        svn: 129,
        ..Default::default()
    };
    let result = hw.mailbox_execute_req(cmd);
    assert!(result.is_err());

    // Send a command to increase the Caliptra minimum SVN fuses to 7.
    let cmd = FuseIncreaseCaliptraMinSvnReq {
        svn: 7,
        ..Default::default()
    };
    let _resp = hw.mailbox_execute_req(cmd)?;

    // Check requesting twice to burn the SVN of the value currently in fuses passes.
    let cmd = FuseIncreaseCaliptraMinSvnReq {
        svn: 7,
        ..Default::default()
    };
    let _resp = hw.mailbox_execute_req(cmd)?;

    // Read OTP memory so we can use the same config in later boots.
    let otp = hw.read_otp_memory();

    // Step 2: Cold boot with the burned fuses and verify the firmware with SVN 7 can still boot.
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        custom_caliptra_fw: Some(CustomCaliptraFw {
            fw_bytes: caliptra_fw_svn7,
            vendor_pk_hash: vendor_pk_hash_arr,
            soc_manifest: soc_manifest.clone(),
        }),
        otp_memory: Some(otp.clone()),
        ..Default::default()
    });

    // Wait for mailbox ready again.
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Query FW_INFO to check if the reported min_fw_svn matches the burned fuses.
    let fw_info_id = caliptra_api::mailbox::CommandId::FW_INFO.into();
    let payload = caliptra_api::mailbox::MailboxReqHeader {
        chksum: calc_checksum(fw_info_id, &[]),
    };

    let resp = hw
        .caliptra_mailbox_execute(fw_info_id, payload.as_bytes())
        .unwrap()
        .unwrap();
    let caliptra_fw_info = FwInfoResp::read_from_bytes(&resp).unwrap();
    assert_eq!(caliptra_fw_info.min_fw_svn, 7);

    // Check trying to burn a lower SVN returns an error.
    // Current fuses are 7, so trying to burn 6 should fail.
    let cmd = FuseIncreaseCaliptraMinSvnReq {
        svn: 6,
        ..Default::default()
    };
    let resp = hw.mailbox_execute_req(cmd);
    assert!(resp.is_err());

    // Step 3: Negative test. Build firmware with SVN = 0 (less than fuse value 7)
    // and verify that boot fails with the expected error.

    // We use `rom_only: true` here to prevent the emulator initialization from
    // blocking or crashing while waiting for a successful boot that will never happen.
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        custom_caliptra_fw: Some(CustomCaliptraFw {
            fw_bytes: caliptra_fw_svn0.clone(),
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

    // Verify that the fatal error corresponds to the SVN being less than the fuse value.
    assert_eq!(
        hw.caliptra_soc_manager()
            .soc_ifc()
            .cptra_fw_error_fatal()
            .read(),
        u32::from(CaliptraError::IMAGE_VERIFIER_ERR_FIRMWARE_SVN_LESS_THAN_FUSE)
    );
    Ok(())
}

#[test]
fn test_increase_caliptra_svn_max() -> Result<()> {
    // Compile runtime with specific features and build Caliptra firmware with max SVN (128).
    let mcu_runtime_path = compile_runtime(Some("test-mcu-mbox-cmds"), false);
    let (caliptra_fw_svn128, vendor_pk_hash_arr, soc_manifest) =
        if let Ok(binaries) = FirmwareBinaries::from_env() {
            let fw = binaries.caliptra_fw_svn128.clone();
            let pk_hash = binaries.vendor_pk_hash().unwrap();
            let manifest = binaries.test_soc_manifest("test-mcu-mbox-cmds").unwrap();
            (fw, pk_hash, manifest)
        } else {
            let mut builder = CaliptraBuilder::new(&CaliptraBuildArgs {
                svn: Some(128),
                mcu_firmware: Some(mcu_runtime_path.clone()),
                ..Default::default()
            });
            let fw = std::fs::read(builder.get_caliptra_fw()?).unwrap();
            let pk_hash_str = builder.get_vendor_pk_hash()?.to_string();
            let pk_hash = hex::decode(&pk_hash_str).unwrap();
            let mut pk_hash_arr = [0u8; 48];
            pk_hash_arr.copy_from_slice(&pk_hash);
            let manifest = std::fs::read(builder.get_soc_manifest(None)?).unwrap();
            (fw, pk_hash_arr, manifest)
        };

    // Start the hardware model with the custom Caliptra firmware (SVN 128).
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        custom_caliptra_fw: Some(CustomCaliptraFw {
            fw_bytes: caliptra_fw_svn128.clone(),
            vendor_pk_hash: vendor_pk_hash_arr,
            soc_manifest: soc_manifest.clone(),
        }),
        lifecycle_controller_state: Some(LifecycleControllerState::Prod),
        ..Default::default()
    });

    // Wait for the mailbox to become ready, indicating the runtime has booted.
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Send a command to increase the Caliptra minimum SVN fuses to 128.
    let cmd = FuseIncreaseCaliptraMinSvnReq {
        svn: 128,
        ..Default::default()
    };
    let _resp = hw.mailbox_execute_req(cmd)?;

    // Read OTP memory immediately after the command to verify fuses were burned.
    let otp = hw.read_otp_memory();

    // Check SVN value at offset 0x394 using specific decoding logic.
    // The SVN is represented as a bitmask where the number of set bits is the SVN.
    let svn_bytes = &otp[0x394..0x394 + 16];
    let fuse = u128::from_le_bytes(svn_bytes.try_into().unwrap());
    let svn = 128 - fuse.leading_zeros();
    assert_eq!(svn, 128);

    // Verify persistence across cold boot.
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        custom_caliptra_fw: Some(CustomCaliptraFw {
            fw_bytes: caliptra_fw_svn128,
            vendor_pk_hash: vendor_pk_hash_arr,
            soc_manifest: soc_manifest.clone(),
        }),
        otp_memory: Some(otp.clone()),
        ..Default::default()
    });

    // Wait for mailbox ready again.
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Query FW_INFO to check if the reported min_fw_svn matches the burned fuses (128).
    let fw_info_id = caliptra_api::mailbox::CommandId::FW_INFO.into();
    let payload = caliptra_api::mailbox::MailboxReqHeader {
        chksum: calc_checksum(fw_info_id, &[]),
    };

    let resp = hw
        .caliptra_mailbox_execute(fw_info_id, payload.as_bytes())
        .unwrap()
        .unwrap();
    let caliptra_fw_info = FwInfoResp::read_from_bytes(&resp).unwrap();
    assert_eq!(caliptra_fw_info.min_fw_svn, 128);

    Ok(())
}

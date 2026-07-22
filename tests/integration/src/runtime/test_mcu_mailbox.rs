// Licensed under the Apache-2.0 license

use crate::test::{compile_runtime, start_runtime_hw_model, CustomCaliptraFw, TestParams};
use anyhow::Result;
use caliptra_mcu_hw_model::{LifecycleControllerState, McuHwModel};
use caliptra_mcu_mbox_common::messages::{
    FirmwareVersionReq, GetAuthCmdChallengeReq, McuFeProgReq,
};
use caliptra_mcu_romtime::McuBootMilestones;

#[test]
fn test_invalid_mailbox_cmd() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        target: &caliptra_mcu_builder::firmware::targets::TEST_MCU_MBOX_CMDS,
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
        target: &caliptra_mcu_builder::firmware::targets::TEST_MCU_MBOX_CMDS,
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
fn test_get_auth_cmd_challenge_cmd() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        target: &caliptra_mcu_builder::firmware::targets::TEST_MCU_MBOX_CMDS,
        ..Default::default()
    });

    // wait another little bit for the mailbox to come up after the runtime
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let cmd = GetAuthCmdChallengeReq::default();
    let resp = hw.mailbox_execute_req(cmd)?;

    assert_eq!(resp.challenge.len(), 32);
    assert!(
        resp.challenge
            .iter()
            .copied()
            .reduce(|a, b| (a | b))
            .unwrap()
            != 0,
        "Challenge should not be all-zeros"
    );
    Ok(())
}

#[test]
fn test_fe_prog_authorized_req() -> Result<()> {
    use crate::runtime::execute_authorized_req;
    use caliptra_mcu_builder::{CaliptraBuildArgs, CaliptraBuilder, FirmwareBinaries};

    let mcu_runtime_path = compile_runtime(Some("test-mcu-mbox-cmds"), false);
    let (caliptra_fw, vendor_pk_hash_arr, soc_manifest) =
        if let Ok(binaries) = FirmwareBinaries::from_env() {
            let fw = binaries
                .as_bundle(&caliptra_mcu_builder::firmware::targets::TEST_MCU_MBOX_CMDS)
                .caliptra_rt
                .to_vec();
            let pk_hash = binaries.vendor_pk_hash().unwrap();
            let manifest = binaries
                .as_bundle(&caliptra_mcu_builder::firmware::targets::TEST_MCU_MBOX_CMDS)
                .soc_manifest
                .to_vec();
            (fw, pk_hash, manifest)
        } else {
            let mut builder = CaliptraBuilder::new(&CaliptraBuildArgs {
                svn: Some(0),
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

    let mut hw = start_runtime_hw_model(TestParams {
        target: &caliptra_mcu_builder::firmware::targets::TEST_MCU_MBOX_CMDS,
        custom_caliptra_fw: Some(CustomCaliptraFw {
            fw_bytes: caliptra_fw,
            vendor_pk_hash: vendor_pk_hash_arr,
            soc_manifest: soc_manifest,
        }),
        lifecycle_controller_state: Some(LifecycleControllerState::Prod),
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Verify FE_PROG authorized request succeeds
    let cmd = McuFeProgReq {
        partition: 0,
        ..Default::default()
    };
    let result = execute_authorized_req(&mut hw, cmd);
    assert!(
        result.is_ok(),
        "FE_PROG authorized request failed: {result:?}"
    );

    Ok(())
}

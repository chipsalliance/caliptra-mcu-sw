// Licensed under the Apache-2.0 license

use crate::runtime::execute_authorized_req;
use crate::test::{compile_runtime, start_runtime_hw_model, CustomCaliptraFw, TestParams};
use anyhow::Result;
use caliptra_api::{calc_checksum, error::CaliptraError, mailbox::FwInfoResp, SocManager};
use caliptra_mcu_builder::{CaliptraBuildArgs, CaliptraBuilder, FirmwareBinaries};
use caliptra_mcu_hw_model::{LifecycleControllerState, McuHwModel};
use caliptra_mcu_mbox_common::messages::{FuseIncreaseMinSvnReq, FuseWriteReq, SvnTarget};
use caliptra_mcu_registers_generated::fuses::{
    FuseEntryInfo, OTP_CPTRA_CORE_RUNTIME_SVN, OTP_CPTRA_CORE_SOC_MANIFEST_MAX_SVN,
    OTP_CPTRA_CORE_SOC_MANIFEST_SVN,
};
use caliptra_mcu_romtime::McuBootMilestones;
use zerocopy::{FromBytes, IntoBytes};

fn linear_or_svn_from_otp(otp: &[u8], entry: &FuseEntryInfo) -> u32 {
    let bytes: [u8; 16] = otp[entry.byte_offset..entry.byte_offset + 16]
        .try_into()
        .unwrap();
    128 - u128::from_le_bytes(bytes).leading_zeros()
}

// The direct Core requester override used for PL0 installation is emulator-only.
#[cfg(not(feature = "fpga_realtime"))]
mod owner {
    use super::*;
    use crate::test::TEST_LOCK;
    use anyhow::{anyhow, bail};
    use caliptra_api::mailbox::{CommandId, MailboxReqHeader};
    use caliptra_mcu_registers_generated::fuses::OWNER_SOC_MANIFEST_MIN_SVN;
    use std::sync::atomic::Ordering;

    fn core_request(hw: &mut impl McuHwModel, cmd: CommandId, request: &[u8]) -> Result<Vec<u8>> {
        let cmd = u32::from(cmd);
        for _ in 0..10 {
            match hw.caliptra_mailbox_execute(cmd, request) {
                Ok(Some(response)) => return Ok(response),
                Ok(None) => bail!("Core command {cmd:#010x} did not return a response"),
                Err(caliptra_hw_model::ModelError::UnableToLockMailbox) => {
                    for _ in 0..1_000_000 {
                        hw.step();
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        bail!("Core mailbox remained busy for {cmd:#010x}")
    }

    fn read_fw_info(hw: &mut impl McuHwModel) -> Result<FwInfoResp> {
        let request = MailboxReqHeader {
            chksum: calc_checksum(CommandId::FW_INFO.into(), &[]),
        };
        let response = core_request(hw, CommandId::FW_INFO, request.as_bytes())?;
        FwInfoResp::read_from_bytes(&response).map_err(|_| anyhow!("Invalid FW_INFO response"))
    }

    #[test]
    fn test_owner_soc_manifest_svn_is_forwarded_on_cold_boot() -> Result<()> {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-mcu-mbox-cmds"),
            lifecycle_controller_state: Some(LifecycleControllerState::Prod),
            ..Default::default()
        });
        hw.step_until(|hw| {
            hw.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
        });

        let original_strap = hw
            .caliptra_soc_manager()
            .soc_ifc()
            .ss_strap_generic()
            .at(3)
            .read();
        let mut otp = hw.read_otp_memory();
        drop(hw);

        let start = OWNER_SOC_MANIFEST_MIN_SVN.byte_offset;
        let end = start + OWNER_SOC_MANIFEST_MIN_SVN.byte_size;
        let encoded = (1u64 << 63) | 0b11_1111;
        assert_eq!(encoded.count_ones(), 7);
        otp[start..end].copy_from_slice(&encoded.to_le_bytes());

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-mcu-mbox-cmds"),
            lifecycle_controller_state: Some(LifecycleControllerState::Prod),
            otp_memory: Some(otp),
            ..Default::default()
        });
        hw.step_until(|hw| {
            hw.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
        });
        assert_eq!(read_fw_info(&mut hw)?.owner_auth_manifest_min_svn, 7);
        let strap = hw
            .caliptra_soc_manager()
            .soc_ifc()
            .ss_strap_generic()
            .at(3)
            .read();
        assert_eq!((strap >> 8) & 0xff, 7);
        assert_eq!(strap & !(0xff << 8), original_strap & !(0xff << 8));

        lock.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

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
    let cmd = FuseIncreaseMinSvnReq {
        target: SvnTarget::CaliptraRuntime as u32,
        svn: 0,
        ..Default::default()
    };
    let result = execute_authorized_req(&mut hw, cmd);
    assert!(result.is_err());

    // Check requesting to increase SVN past what is currently running returns an error.
    // Running SVN is 7, so requesting 8 should fail.
    let cmd = FuseIncreaseMinSvnReq {
        target: SvnTarget::CaliptraRuntime as u32,
        svn: 8,
        ..Default::default()
    };
    let result = execute_authorized_req(&mut hw, cmd);
    assert!(result.is_err());

    // Check trying to burn a value greater than 128 returns an error.
    let cmd = FuseIncreaseMinSvnReq {
        target: SvnTarget::CaliptraRuntime as u32,
        svn: 129,
        ..Default::default()
    };
    let result = execute_authorized_req(&mut hw, cmd);
    assert!(result.is_err());

    // Send a command to increase the Caliptra minimum SVN fuses to 7.
    let cmd = FuseIncreaseMinSvnReq {
        target: SvnTarget::CaliptraRuntime as u32,
        svn: 7,
        ..Default::default()
    };
    let _resp = execute_authorized_req(&mut hw, cmd)?;

    // Check requesting twice to burn the SVN of the value currently in fuses passes.
    let cmd = FuseIncreaseMinSvnReq {
        target: SvnTarget::CaliptraRuntime as u32,
        svn: 7,
        ..Default::default()
    };
    let _resp = execute_authorized_req(&mut hw, cmd)?;

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
    let cmd = FuseIncreaseMinSvnReq {
        target: SvnTarget::CaliptraRuntime as u32,
        svn: 6,
        ..Default::default()
    };
    let resp = execute_authorized_req(&mut hw, cmd);
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
        rom_feature: Some(""),
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
    let cmd = FuseIncreaseMinSvnReq {
        target: SvnTarget::CaliptraRuntime as u32,
        svn: 128,
        ..Default::default()
    };
    let _resp = execute_authorized_req(&mut hw, cmd)?;

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

#[test]
fn test_increase_soc_manifest_svn() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        lifecycle_controller_state: Some(LifecycleControllerState::Prod),
        ..Default::default()
    });
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let max_svn = FuseWriteReq {
        word_addr: (OTP_CPTRA_CORE_SOC_MANIFEST_MAX_SVN.byte_offset / 4) as u32,
        data: 6,
        mask: u32::MAX,
        ..Default::default()
    };
    let _resp = execute_authorized_req(&mut hw, max_svn)?;

    let cmd = FuseIncreaseMinSvnReq {
        target: SvnTarget::SocManifest as u32,
        svn: 5,
        ..Default::default()
    };
    let _resp = execute_authorized_req(&mut hw, cmd)?;

    let otp = hw.read_otp_memory();
    assert_eq!(
        linear_or_svn_from_otp(&otp, OTP_CPTRA_CORE_SOC_MANIFEST_SVN),
        5
    );
    assert_eq!(linear_or_svn_from_otp(&otp, OTP_CPTRA_CORE_RUNTIME_SVN), 0);

    for cmd in [
        FuseIncreaseMinSvnReq {
            target: SvnTarget::SocManifest as u32,
            svn: 4,
            ..Default::default()
        },
        FuseIncreaseMinSvnReq {
            target: SvnTarget::OwnerSocManifest as u32,
            svn: 5,
            ..Default::default()
        },
        FuseIncreaseMinSvnReq {
            target: u32::MAX,
            svn: 5,
            ..Default::default()
        },
        FuseIncreaseMinSvnReq {
            flags: 1,
            target: SvnTarget::SocManifest as u32,
            svn: 6,
            ..Default::default()
        },
        FuseIncreaseMinSvnReq {
            target: SvnTarget::SocManifest as u32,
            svn: 7,
            ..Default::default()
        },
    ] {
        assert!(execute_authorized_req(&mut hw, cmd).is_err());
    }

    let otp = hw.read_otp_memory();
    assert_eq!(
        linear_or_svn_from_otp(&otp, OTP_CPTRA_CORE_SOC_MANIFEST_SVN),
        5
    );
    assert_eq!(linear_or_svn_from_otp(&otp, OTP_CPTRA_CORE_RUNTIME_SVN), 0);

    Ok(())
}

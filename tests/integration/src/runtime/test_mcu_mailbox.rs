// Licensed under the Apache-2.0 license

use crate::test::{compile_runtime, start_runtime_hw_model, CustomCaliptraFw, TestParams};
use anyhow::Result;
use caliptra_api::{
    calc_checksum,
    mailbox::{CapabilitiesResp, CommandId, MailboxReqHeader},
    SocManager,
};
use caliptra_mcu_config::capabilities::{ExternalCommandCapabilities, McuRuntimeCapabilities};
use caliptra_mcu_hw_model::{LifecycleControllerState, McuHwModel};
use caliptra_mcu_mbox_common::messages::{
    DeviceCapsReq, EcdsaVerifyReq, FirmwareVersionReq, GetAuthCmdChallengeReq, LmsVerifyReq,
    MailboxReqHeader as McuMailboxReqHeader, MailboxRespHeader, McuEcdsa384SigVerifyReq,
    McuFeProgReq, McuFeProgReqPayload, McuLmsSigVerifyReq,
};
use caliptra_mcu_romtime::McuBootMilestones;
use zerocopy::{FromBytes, IntoBytes};

fn semantic_version(packed_version: u32) -> String {
    format!(
        "{}.{}.{}",
        (packed_version >> 24) & 0xff,
        (packed_version >> 16) & 0xff,
        packed_version & 0xffff
    )
}

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

    let caliptra_runtime_version = hw
        .caliptra_soc_manager()
        .soc_ifc()
        .cptra_fw_rev_id()
        .at(1)
        .read();
    let expected_versions = [
        semantic_version(caliptra_runtime_version),
        semantic_version(caliptra_mcu_config::version::get_mcu_runtime_version()),
    ];

    for (index, expected_version) in expected_versions.iter().enumerate() {
        let cmd = FirmwareVersionReq {
            index: index as u32,
            ..Default::default()
        };
        let resp = hw.mailbox_execute_req(cmd)?;

        assert_eq!(resp.hdr.data_len, expected_version.len() as u32);
        let resp_version_str = std::str::from_utf8(&resp.version[..resp.hdr.data_len as usize])
            .expect("Version string is not valid UTF-8");
        assert_eq!(resp_version_str, expected_version);
    }

    for index in [2, 99] {
        let cmd = FirmwareVersionReq {
            index,
            ..Default::default()
        };
        assert!(hw.mailbox_execute_req(cmd).is_err());
    }
    Ok(())
}

#[test]
fn test_device_capabilities_cmd() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let core_req = MailboxReqHeader {
        chksum: calc_checksum(CommandId::CAPABILITIES.into(), &[]),
    };
    let core_resp = hw
        .caliptra_mailbox_execute(CommandId::CAPABILITIES.into(), core_req.as_bytes())?
        .expect("Core CAPABILITIES returned no response");
    let core_caps = CapabilitiesResp::read_from_bytes(&core_resp)
        .expect("invalid Core CAPABILITIES response")
        .capabilities;

    let resp = hw.mailbox_execute_req(DeviceCapsReq::default())?;
    assert_eq!(&resp.caps[..16], &core_caps);
    assert_eq!(u32::from_be_bytes(resp.caps[16..20].try_into().unwrap()), 0);
    assert_eq!(
        u32::from_be_bytes(resp.caps[20..24].try_into().unwrap()),
        McuRuntimeCapabilities::MCI_MAILBOX_SERVICE.bits()
    );
    assert_eq!(
        u32::from_be_bytes(resp.caps[24..28].try_into().unwrap()),
        ExternalCommandCapabilities::GET_ATTESTATION.bits()
    );
    assert_eq!(u32::from_be_bytes(resp.caps[28..32].try_into().unwrap()), 0);
    assert_eq!(&resp.caps[32..], &[0; 4]);
    Ok(())
}

#[test]
fn test_get_auth_cmd_challenge_cmd() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });

    // wait another little bit for the mailbox to come up after the runtime
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let cmd = GetAuthCmdChallengeReq::default();
    let resp = hw.mailbox_execute_req(cmd)?;

    assert_eq!(
        resp.challenge.len(),
        caliptra_mcu_command_auth_challenge_signer::AUTH_CMD_NONCE_LEN
    );
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
fn test_mcu_mbox_ecdsa384_sig_verify() -> Result<()> {
    use caliptra_image_crypto::RustCrypto;
    use caliptra_image_fake_keys::{VENDOR_ECC_KEY_0_PRIVATE, VENDOR_ECC_KEY_0_PUBLIC};
    use caliptra_image_gen::{from_hw_format, to_hw_format, ImageGeneratorCrypto};

    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let digest = [0x5au8; 48];
    let signature = RustCrypto::default().ecdsa384_sign(
        &to_hw_format(&digest),
        &VENDOR_ECC_KEY_0_PRIVATE,
        &VENDOR_ECC_KEY_0_PUBLIC,
    )?;
    let signature_r = from_hw_format(&signature.r);
    let signature_s = from_hw_format(&signature.s);

    let resp = hw.mailbox_execute_req(McuEcdsa384SigVerifyReq(EcdsaVerifyReq {
        hdr: McuMailboxReqHeader::default(),
        pub_key_x: from_hw_format(&VENDOR_ECC_KEY_0_PUBLIC.x),
        pub_key_y: from_hw_format(&VENDOR_ECC_KEY_0_PUBLIC.y),
        signature_r,
        signature_s,
        hash: digest,
    }))?;
    assert_eq!(
        resp.0.fips_status,
        MailboxRespHeader::FIPS_STATUS_NOT_APPROVED_USER_SUPPLIED_DIGEST
    );

    let mut invalid_signature_r = signature_r;
    invalid_signature_r[0] ^= 1;
    let invalid = McuEcdsa384SigVerifyReq(EcdsaVerifyReq {
        hdr: McuMailboxReqHeader::default(),
        pub_key_x: from_hw_format(&VENDOR_ECC_KEY_0_PUBLIC.x),
        pub_key_y: from_hw_format(&VENDOR_ECC_KEY_0_PUBLIC.y),
        signature_r: invalid_signature_r,
        signature_s,
        hash: digest,
    });
    assert!(hw.mailbox_execute_req(invalid).is_err());
    Ok(())
}

#[cfg(not(feature = "fpga_realtime"))]
#[test]
fn test_mcu_mbox_lms_sig_verify() -> Result<()> {
    use caliptra_image_crypto::RustCrypto;
    use caliptra_image_fake_keys::{VENDOR_LMS_KEY_0_PRIVATE, VENDOR_LMS_KEY_0_PUBLIC};
    use caliptra_image_gen::{to_hw_format, ImageGeneratorCrypto};

    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let digest = [0xa5u8; 48];
    let signature =
        RustCrypto::default().lms_sign(&to_hw_format(&digest), &VENDOR_LMS_KEY_0_PRIVATE)?;
    let signature_ots = signature.ots.as_bytes().try_into().unwrap();

    let resp = hw.mailbox_execute_req(McuLmsSigVerifyReq(LmsVerifyReq {
        hdr: McuMailboxReqHeader::default(),
        pub_key_tree_type: u32::from(VENDOR_LMS_KEY_0_PUBLIC.tree_type.0),
        pub_key_ots_type: u32::from(VENDOR_LMS_KEY_0_PUBLIC.otstype.0),
        pub_key_id: VENDOR_LMS_KEY_0_PUBLIC.id,
        pub_key_digest: VENDOR_LMS_KEY_0_PUBLIC
            .digest
            .as_bytes()
            .try_into()
            .unwrap(),
        signature_q: u32::from(signature.q),
        signature_ots,
        signature_tree_type: u32::from(signature.tree_type.0),
        signature_tree_path: signature.tree_path.as_bytes().try_into().unwrap(),
        hash: digest,
    }))?;
    assert_eq!(
        resp.0.fips_status,
        MailboxRespHeader::FIPS_STATUS_NOT_APPROVED_USER_SUPPLIED_DIGEST
    );

    let mut invalid_signature_ots = signature_ots;
    invalid_signature_ots[4] ^= 1;
    let invalid = McuLmsSigVerifyReq(LmsVerifyReq {
        hdr: McuMailboxReqHeader::default(),
        pub_key_tree_type: u32::from(VENDOR_LMS_KEY_0_PUBLIC.tree_type.0),
        pub_key_ots_type: u32::from(VENDOR_LMS_KEY_0_PUBLIC.otstype.0),
        pub_key_id: VENDOR_LMS_KEY_0_PUBLIC.id,
        pub_key_digest: VENDOR_LMS_KEY_0_PUBLIC
            .digest
            .as_bytes()
            .try_into()
            .unwrap(),
        signature_q: u32::from(signature.q),
        signature_ots: invalid_signature_ots,
        signature_tree_type: u32::from(signature.tree_type.0),
        signature_tree_path: signature.tree_path.as_bytes().try_into().unwrap(),
        hash: digest,
    });
    assert!(hw.mailbox_execute_req(invalid).is_err());
    Ok(())
}

#[cfg(feature = "fpga_realtime")]
#[test]
fn test_mcu_mbox_lms_sig_verify() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let request = McuLmsSigVerifyReq(LmsVerifyReq {
        hdr: McuMailboxReqHeader::default(),
        pub_key_tree_type: 0,
        pub_key_ots_type: 0,
        pub_key_id: [0; 16],
        pub_key_digest: [0; 24],
        signature_q: 0,
        signature_ots: [0; 1252],
        signature_tree_type: 0,
        signature_tree_path: [0; 360],
        hash: [0; 48],
    });
    assert!(hw.mailbox_execute_req(request).is_err());
    Ok(())
}

#[test]
fn test_fe_prog_authorized_req() -> Result<()> {
    use crate::runtime::execute_authorized_req;
    use caliptra_mcu_builder::{CaliptraBuildArgs, CaliptraBuilder, FirmwareBinaries};

    let mcu_runtime_path = compile_runtime(Some("test-mcu-mbox-cmds"), false);
    let (caliptra_fw, vendor_pk_hash_arr, soc_manifest) =
        if let Ok(binaries) = FirmwareBinaries::from_env() {
            let fw = binaries.caliptra_fw.clone();
            let pk_hash = binaries.vendor_pk_hash().unwrap();
            let manifest = binaries.test_soc_manifest("test-mcu-mbox-cmds").unwrap();
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
        feature: Some("test-mcu-mbox-cmds"),
        custom_caliptra_fw: Some(CustomCaliptraFw {
            fw_bytes: caliptra_fw,
            vendor_pk_hash: vendor_pk_hash_arr,
            soc_manifest,
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
        payload: McuFeProgReqPayload { partition: 0 },
        ..Default::default()
    };
    let result = execute_authorized_req(&mut hw, cmd);
    assert!(
        result.is_ok(),
        "FE_PROG authorized request failed: {result:?}"
    );

    Ok(())
}

// Licensed under the Apache-2.0 license

use crate::test::{compile_runtime, start_runtime_hw_model, CustomCaliptraFw, TestParams};
use anyhow::Result;
use caliptra_api::{
    calc_checksum,
    mailbox::{CapabilitiesResp, CommandId, MailboxReqHeader},
    SocManager,
};
use caliptra_mcu_config::capabilities::{
    AuthorizedSubcommandCapabilities, ExternalCommandCapabilities, McuRuntimeCapabilities,
};
use caliptra_mcu_hw_model::{LifecycleControllerState, McuHwModel};
use caliptra_mcu_mbox_common::messages::{
    CommandId as McuCommandId, DeviceCapsReq, EcdsaVerifyReq, FirmwareVersionReq, LmsVerifyReq,
    MailboxReqHeader as McuMailboxReqHeader, MailboxRespHeader, McuEcdsa384SigVerifyReq,
    McuFeProgReq, McuLmsSigVerifyReq, VendorPkHashStatusReq, VENDOR_PQC_KEY_TYPE_LMS,
};
use caliptra_mcu_romtime::{handoff::McuRomCapabilities, McuBootMilestones};
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
fn test_legacy_direct_authorized_command_is_rejected() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let command = McuCommandId::MC_GET_AUTH_CMD_CHALLENGE.0;
    let mut request = [0u8; 12];
    let checksum = caliptra_mcu_mbox_common::messages::calc_checksum(command, &request[4..]);
    request[..4].copy_from_slice(&checksum.to_le_bytes());
    let error = hw.mailbox_execute(command, &request).unwrap_err();
    assert!(!error.to_string().contains("timed out"));
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
    let expected_rom =
        (McuRomCapabilities::STREAMING_BOOT_I3C | McuRomCapabilities::DOT_BOOT).bits();
    assert_eq!(
        u32::from_be_bytes(resp.caps[16..20].try_into().unwrap()),
        expected_rom
    );
    assert_eq!(
        u32::from_be_bytes(resp.caps[20..24].try_into().unwrap()),
        McuRuntimeCapabilities::MCI_MAILBOX_SERVICE.bits()
    );
    assert_eq!(
        u32::from_be_bytes(resp.caps[24..28].try_into().unwrap()),
        (ExternalCommandCapabilities::GET_ATTESTATION
            | ExternalCommandCapabilities::AUTHORIZED_COMMAND
            | ExternalCommandCapabilities::DEVICE_OWNERSHIP_TRANSFER)
            .bits()
    );
    assert_eq!(
        u32::from_be_bytes(resp.caps[28..32].try_into().unwrap()),
        (AuthorizedSubcommandCapabilities::GET_AUTH_CHALLENGE
            | AuthorizedSubcommandCapabilities::PROVISION_VENDOR_PK_HASH
            | AuthorizedSubcommandCapabilities::FUSE_INCREASE_MIN_SVN
            | AuthorizedSubcommandCapabilities::PROGRAM_FIELD_ENTROPY
            | AuthorizedSubcommandCapabilities::FUSE_REVOKE_VENDOR_PUBLIC_KEY
            | AuthorizedSubcommandCapabilities::FUSE_REVOKE_VENDOR_PK_HASH
            | AuthorizedSubcommandCapabilities::FUSE_LOCK_PARTITION
            | AuthorizedSubcommandCapabilities::PROVISION_OWNER_PK_HASH
            | AuthorizedSubcommandCapabilities::DOT_ENABLE
            | AuthorizedSubcommandCapabilities::DOT_LOCK
            | AuthorizedSubcommandCapabilities::DOT_DISABLE
            | AuthorizedSubcommandCapabilities::DOT_ROTATE
            | AuthorizedSubcommandCapabilities::GET_DOT_BACKUP_BLOB)
            .bits()
    );
    assert_eq!(&resp.caps[32..48], &[0; 16]);
    assert_eq!(&resp.caps[48..64], &[0; 16]);
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

    let challenge = super::get_auth_cmd_challenge(&mut hw)?;

    assert_eq!(
        challenge.len(),
        caliptra_mcu_command_auth_challenge_signer::AUTH_CMD_NONCE_LEN
    );
    assert!(
        challenge.iter().copied().reduce(|a, b| a | b).unwrap() != 0,
        "Challenge should not be all-zeros"
    );

    let target = McuCommandId::MC_GET_AUTH_CMD_CHALLENGE.0.to_le_bytes();
    for body in [
        vec![],
        target[..3].to_vec(),
        [target.as_slice(), &[0u8; 8]].concat(),
    ] {
        let checksum = calc_checksum(McuCommandId::MC_AUTHORIZED_COMMAND.0, &body);
        let mut request = checksum.to_le_bytes().to_vec();
        request.extend_from_slice(&body);
        let error = hw
            .mailbox_execute(McuCommandId::MC_AUTHORIZED_COMMAND.0, &request)
            .unwrap_err();
        assert!(!error.to_string().contains("timed out"));
    }
    Ok(())
}

#[test]
fn test_vendor_pk_hash_status_cmd_does_not_require_authorization() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let resp = hw.mailbox_execute_req(VendorPkHashStatusReq::default())?;
    assert_eq!(resp.used_slots_bitmap, 1 << 0);
    assert_eq!(resp.key_types[0], VENDOR_PQC_KEY_TYPE_LMS);
    assert_eq!(&resp.key_types[1..], &[0; 15]);

    let cmd = caliptra_mcu_mbox_common::messages::CommandId::MC_VENDOR_PK_HASH_STATUS.into();
    assert!(hw.mailbox_execute(cmd, &[0u8; 3]).is_err());

    let mut oversized = [0u8; 8];
    oversized[4..].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    let checksum = calc_checksum(cmd, &oversized[4..]);
    oversized[..4].copy_from_slice(&checksum.to_le_bytes());
    assert!(hw.mailbox_execute(cmd, &oversized).is_err());
    assert!(hw.mailbox_execute(cmd, &[0u8; 4]).is_err());
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

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
    CommandId as McuCommandId, DeviceCapsReq, DeviceCapsResp, DpeSignerContextCertReq,
    EcdsaVerifyReq, FirmwareVersionReq, GetAuthCmdChallengeReq, GetDpeCertChainReq, LmsVerifyReq,
    MailboxReqHeader as McuMailboxReqHeader, MailboxRespHeader, MailboxRespHeaderVarSize,
    McuEcdsa384SigVerifyReq, McuFeProgReq, McuFipsPeriodicEnableReq, McuFipsPeriodicEnableResp,
    McuFipsPeriodicStatusResp, McuFipsSelfTestGetResultsResp, McuFipsSelfTestStartResp,
    McuLmsSigVerifyReq, McuProdDebugUnlockReqReq, McuProdDebugUnlockReqResp,
    McuProdDebugUnlockTokenReq, ProductionAuthDebugUnlockReq, ProductionAuthDebugUnlockToken,
};
use caliptra_mcu_romtime::{handoff::McuRomCapabilities, McuBootMilestones};
use std::mem::size_of;
use zerocopy::{FromBytes, IntoBytes};

fn semantic_version(packed_version: u32) -> String {
    format!(
        "{}.{}.{}",
        (packed_version >> 24) & 0xff,
        (packed_version >> 16) & 0xff,
        packed_version & 0xffff
    )
}

fn assert_response_checksum(response: &[u8]) {
    assert!(response.len() >= size_of::<u32>());
    assert_eq!(
        u32::from_le_bytes(response[..size_of::<u32>()].try_into().unwrap()),
        calc_checksum(0, &response[size_of::<u32>()..])
    );
}

fn raw_request(cmd: u32, payload: &[u8]) -> Vec<u8> {
    let mut request = calc_checksum(cmd, payload).to_le_bytes().to_vec();
    request.extend_from_slice(payload);
    request
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
fn test_invalid_mailbox_cmd_with_valid_checksum() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });

    // wait another little bit for the mailbox to come up after the runtime
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Send an unknown command (0x0) with an valid checksum.
    // The firmware should reject it with a mailbox failure.
    let cmd = 0;
    let request = calc_checksum(cmd, &[]).to_le_bytes();
    let err_msg = hw.mailbox_execute(cmd, &request).unwrap_err().to_string();
    assert!(
        !err_msg.contains("timed out"),
        "Mailbox command should fail with error, not time out. Got: {err_msg}"
    );
    Ok(())
}

#[test]
fn test_valid_mailbox_cmd_with_invalid_checksum() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Send an known command ("MFWV") with an invalid checksum.
    // The firmware should reject it with a mailbox failure.
    let cmd = McuCommandId::MC_FIRMWARE_VERSION.0;
    let err_msg = hw
        .mailbox_execute(cmd, &[0; size_of::<FirmwareVersionReq>()])
        .unwrap_err()
        .to_string();
    assert!(
        !err_msg.contains("timed out"),
        "Mailbox command should fail with error, not time out. Got: {err_msg}"
    );
    Ok(())
}

#[test]
fn test_mailbox_transport_rejects_request_shorter_than_header() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Send an known command ("MFWV") but with a request shorter than the header.
    // The firmware should reject it with a mailbox failure.
    let cmd = McuCommandId::MC_FIRMWARE_VERSION.0;
    let err_msg = hw
        .mailbox_execute(cmd, &[0; size_of::<McuMailboxReqHeader>() - 1])
        .unwrap_err()
        .to_string();
    assert!(
        !err_msg.contains("timed out"),
        "Mailbox command should fail with error, not time out. Got: {err_msg}"
    );
    Ok(())
}

#[test]
fn test_rejects_missing_dot_subcommands() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });

    // wait another little bit for the mailbox to come up after the runtime
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Send the device ownership transfer command without any subcommands.
    // The firmware should reject it with a mailbox failure.
    let cmd = McuCommandId::MC_DEVICE_OWNERSHIP_TRANSFER.0;
    let request = calc_checksum(cmd, &[]).to_le_bytes();
    let err_msg = hw.mailbox_execute(cmd, &request).unwrap_err().to_string();
    assert!(
        !err_msg.contains("timed out"),
        "Mailbox command should fail with error, not time out. Got: {err_msg}"
    );
    Ok(())
}

#[test]
fn test_rejects_unknown_dot_subcommands() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });

    // wait another little bit for the mailbox to come up after the runtime
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Send the device ownership transfer command with an unknown subcommand.
    // The firmware should reject it with a mailbox failure.
    let cmd = McuCommandId::MC_DEVICE_OWNERSHIP_TRANSFER.0;
    let subcommand = 0xDEAD_BEEFu32.to_le_bytes();
    let mut request = calc_checksum(cmd, &subcommand).to_le_bytes().to_vec();
    request.extend_from_slice(&subcommand);
    let err_msg = hw.mailbox_execute(cmd, &request).unwrap_err().to_string();
    assert!(
        !err_msg.contains("timed out"),
        "Mailbox command should fail with error, not time out. Got: {err_msg}"
    );
    Ok(())
}

#[test]
fn test_feature_gated_command_is_rejected_when_disabled() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });

    // wait another little bit for the mailbox to come up after the runtime
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Send the FIPS periodic status command while the feature is disabled.
    // The firmware should reject it with a mailbox failure.
    let cmd = McuCommandId::MC_FIPS_PERIODIC_STATUS.0;
    let request = calc_checksum(cmd, &[]).to_le_bytes();
    let err_msg = hw.mailbox_execute(cmd, &request).unwrap_err().to_string();
    assert!(
        !err_msg.contains("timed out"),
        "Mailbox command should fail with error, not time out. Got: {err_msg}"
    );
    Ok(())
}

#[test]
fn test_succesful_response_checksum() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });

    // wait another little bit for the mailbox to come up after the runtime
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Send a valid device capabilities command
    let cmd = McuCommandId::MC_DEVICE_CAPABILITIES.0;
    let request = calc_checksum(cmd, &[]).to_le_bytes();
    let response = hw
        .mailbox_execute(cmd, &request)?
        .expect("MC_DEVICE_CAPABILITIES returned no response");

    // Make sure it's the right checksum, and response length
    assert_eq!(response.len(), size_of::<DeviceCapsResp>());
    assert_eq!(
        u32::from_le_bytes(response[..size_of::<u32>()].try_into().unwrap()),
        calc_checksum(0, &response[size_of::<u32>()..])
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
        let cmd = McuCommandId::MC_FIRMWARE_VERSION.0;
        let response = hw
            .mailbox_execute(cmd, &raw_request(cmd, &(index as u32).to_le_bytes()))?
            .expect("MC_FIRMWARE_VERSION returned no response");
        assert_response_checksum(&response);
        let header = MailboxRespHeaderVarSize::read_from_prefix(&response)
            .expect("invalid firmware-version response")
            .0;
        assert_eq!(
            response.len(),
            size_of::<MailboxRespHeaderVarSize>() + header.data_len as usize
        );
        assert_eq!(
            header.hdr.fips_status,
            MailboxRespHeader::FIPS_STATUS_APPROVED
        );
        assert_eq!(header.data_len as usize, expected_version.len());
        assert_eq!(
            &response[size_of::<MailboxRespHeaderVarSize>()..],
            expected_version.as_bytes()
        );
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
    let expected_rom = (McuRomCapabilities::STREAMING_BOOT_I3C
        | McuRomCapabilities::FLASH_BOOT
        | McuRomCapabilities::DOT_BOOT)
        .bits();
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
        ExternalCommandCapabilities::GET_ATTESTATION.bits()
    );
    assert_eq!(u32::from_be_bytes(resp.caps[28..32].try_into().unwrap()), 0);
    assert_eq!(&resp.caps[32..48], &[0; 16]);
    assert_eq!(&resp.caps[48..64], &[0; 16]);
    Ok(())
}

#[test]
fn test_get_and_clear_log_cmds() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-defmt-logging-release"),
        seeded_log_entries: Some(caliptra_mcu_mbox_common::config::TEST_DEBUG_LOG_ENTRIES),
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let get_log_cmd = McuCommandId::MC_GET_LOG.0;
    let get_log_request = calc_checksum(get_log_cmd, &[]).to_le_bytes();
    let expected_log: Vec<u8> = caliptra_mcu_mbox_common::config::TEST_DEBUG_LOG_ENTRIES
        .iter()
        .flat_map(|entry| entry.iter().copied())
        .collect();

    let response = hw
        .mailbox_execute(get_log_cmd, &get_log_request)?
        .expect("MC_GET_LOG returned no response");
    assert_response_checksum(&response);
    let header = MailboxRespHeaderVarSize::read_from_prefix(&response)
        .expect("invalid log header")
        .0;
    assert_eq!(
        response.len(),
        size_of::<MailboxRespHeaderVarSize>() + header.data_len as usize
    );
    assert_eq!(
        header.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    let payload = &response[size_of::<MailboxRespHeaderVarSize>()..];
    assert_eq!(u32::from_le_bytes(payload[..4].try_into().unwrap()), 0);
    assert!(
        payload[4..]
            .windows(expected_log.len())
            .any(|window| window == expected_log),
        "response did not contain the seeded log fixture"
    );

    let drained = hw
        .mailbox_execute(get_log_cmd, &get_log_request)?
        .expect("second MC_GET_LOG returned no response");
    assert_response_checksum(&drained);
    let drained_header = MailboxRespHeaderVarSize::read_from_prefix(&drained)
        .expect("invalid log header")
        .0;
    assert_eq!(
        drained.len(),
        size_of::<MailboxRespHeaderVarSize>() + drained_header.data_len as usize
    );
    assert_eq!(
        drained_header.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert_eq!(drained_header.data_len, size_of::<u32>() as u32);
    let drained_payload = &drained[size_of::<MailboxRespHeaderVarSize>()..];
    assert_eq!(drained_payload, 0u32.to_le_bytes());

    let clear_log_cmd = McuCommandId::MC_CLEAR_LOG.0;
    let clear_log_request = calc_checksum(clear_log_cmd, &[]).to_le_bytes();
    for _ in 0..2 {
        let cleared = hw
            .mailbox_execute(clear_log_cmd, &clear_log_request)?
            .expect("MC_CLEAR_LOG returned no response");
        assert_eq!(cleared.len(), size_of::<MailboxRespHeader>());
        assert_response_checksum(&cleared);
        let header =
            MailboxRespHeader::read_from_bytes(&cleared).expect("invalid clear-log response");
        assert_eq!(header.fips_status, MailboxRespHeader::FIPS_STATUS_APPROVED);
    }

    let after_clear = hw
        .mailbox_execute(get_log_cmd, &get_log_request)?
        .expect("post-clear MC_GET_LOG returned no response");
    assert_response_checksum(&after_clear);
    let after_clear_header = MailboxRespHeaderVarSize::read_from_prefix(&after_clear)
        .expect("invalid post-clear log header")
        .0;
    assert_eq!(
        after_clear.len(),
        size_of::<MailboxRespHeaderVarSize>() + after_clear_header.data_len as usize
    );
    assert_eq!(
        after_clear_header.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert!(after_clear_header.data_len >= size_of::<u32>() as u32);
    let after_clear_payload = &after_clear[size_of::<MailboxRespHeaderVarSize>()..];
    assert!(u32::from_le_bytes(after_clear_payload[..4].try_into().unwrap()) <= 1);

    Ok(())
}

#[test]
fn test_core_log_and_debug_request_failures() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    for cmd in [
        McuCommandId::MC_DEVICE_CAPABILITIES.0,
        McuCommandId::MC_GET_LOG.0,
        McuCommandId::MC_CLEAR_LOG.0,
    ] {
        let request = raw_request(cmd, &0u32.to_le_bytes());
        assert!(
            hw.mailbox_execute(cmd, &request).is_err(),
            "command {cmd:#010x} accepted an oversized request"
        );
    }

    let firmware_cmd = McuCommandId::MC_FIRMWARE_VERSION.0;
    let short_firmware_request = raw_request(firmware_cmd, &[]);
    assert!(
        hw.mailbox_execute(firmware_cmd, &short_firmware_request)
            .is_err(),
        "MC_FIRMWARE_VERSION accepted a request without an index"
    );

    let debug_req_cmd = McuCommandId::MC_PROD_DEBUG_UNLOCK_REQ.0;
    let mut invalid_debug_req = McuProdDebugUnlockReqReq(ProductionAuthDebugUnlockReq {
        hdr: McuMailboxReqHeader::default(),
        length: 1,
        unlock_level: 1,
        reserved: [0; 3],
    });
    invalid_debug_req.0.hdr.chksum =
        calc_checksum(debug_req_cmd, &invalid_debug_req.0.as_bytes()[4..]);
    assert!(
        hw.mailbox_execute(debug_req_cmd, invalid_debug_req.0.as_bytes())
            .is_err(),
        "MC_PROD_DEBUG_UNLOCK_REQ accepted an invalid length field"
    );

    let mut debug_req = McuProdDebugUnlockReqReq(ProductionAuthDebugUnlockReq {
        hdr: McuMailboxReqHeader::default(),
        length: 2,
        unlock_level: 1,
        reserved: [0; 3],
    });
    debug_req.0.hdr.chksum = calc_checksum(debug_req_cmd, &debug_req.0.as_bytes()[4..]);
    assert!(
        hw.mailbox_execute(debug_req_cmd, debug_req.0.as_bytes())
            .is_err(),
        "MC_PROD_DEBUG_UNLOCK_REQ should fail outside Production lifecycle"
    );

    let debug_token_cmd = McuCommandId::MC_PROD_DEBUG_UNLOCK_TOKEN.0;
    assert!(
        hw.mailbox_execute(debug_token_cmd, &raw_request(debug_token_cmd, &[]))
            .is_err(),
        "MC_PROD_DEBUG_UNLOCK_TOKEN accepted a truncated request"
    );

    let mut debug_token = McuProdDebugUnlockTokenReq::default();
    debug_token
        .populate_caliptra_chksum()
        .expect("failed to populate inner debug-token checksum");
    debug_token.hdr.chksum = calc_checksum(debug_token_cmd, &debug_token.as_bytes()[4..]);
    assert!(
        hw.mailbox_execute(debug_token_cmd, debug_token.as_bytes())
            .is_err(),
        "MC_PROD_DEBUG_UNLOCK_TOKEN should fail without a challenge"
    );

    Ok(())
}

#[test]
fn test_prod_debug_unlock_complete_responses() -> Result<()> {
    use caliptra_image_fake_keys::{
        VENDOR_ECC_KEY_0_PRIVATE, VENDOR_ECC_KEY_0_PUBLIC, VENDOR_MLDSA_KEY_0_PRIVATE,
        VENDOR_MLDSA_KEY_0_PUBLIC,
    };
    use caliptra_image_types::{ECC384_SCALAR_BYTE_SIZE, ECC384_SCALAR_WORD_SIZE};
    use caliptra_mcu_debug_unlock_signer::{
        DebugUnlockKeys, DebugUnlockSigner, LocalDebugUnlockSigner, ProdDebugUnlockChallenge,
    };

    let mut ecc_public_key_words = [0u32; ECC384_SCALAR_WORD_SIZE * 2];
    ecc_public_key_words[..ECC384_SCALAR_WORD_SIZE].copy_from_slice(&VENDOR_ECC_KEY_0_PUBLIC.x);
    ecc_public_key_words[ECC384_SCALAR_WORD_SIZE..].copy_from_slice(&VENDOR_ECC_KEY_0_PUBLIC.y);
    let ecc_public_key = ecc_public_key_words.as_bytes().try_into().unwrap();

    let mldsa_public_key_words: Vec<u32> = VENDOR_MLDSA_KEY_0_PUBLIC
        .0
        .as_bytes()
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
        .collect();
    let mldsa_public_key = mldsa_public_key_words.as_bytes().try_into().unwrap();

    let unlock_level = 1u8;
    let mut prod_dbg_unlock_keypairs = vec![([0u8; 96], [0u8; 2592]); 8];
    prod_dbg_unlock_keypairs[usize::from(unlock_level - 1)] = (ecc_public_key, mldsa_public_key);

    let mut ecc_private_key_bytes = [0u8; ECC384_SCALAR_BYTE_SIZE];
    for (index, word) in VENDOR_ECC_KEY_0_PRIVATE.iter().enumerate() {
        ecc_private_key_bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    let mldsa_private_key_bytes = VENDOR_MLDSA_KEY_0_PRIVATE.0.as_bytes().to_vec();
    let signer = LocalDebugUnlockSigner::new(DebugUnlockKeys {
        ecc_private_key_bytes,
        ecc_public_key: ecc_public_key_words,
        mldsa_private_key_bytes,
        mldsa_public_key: mldsa_public_key_words.try_into().unwrap(),
    });
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        i3c_port: Some(random_port::PortPicker::new().random(true).pick().unwrap()),
        use_strap_secrets: true,
        lifecycle_controller_state: Some(LifecycleControllerState::Prod),
        debug_intent: true,
        prod_dbg_unlock_keypairs,
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let request_cmd = McuCommandId::MC_PROD_DEBUG_UNLOCK_REQ.0;
    let request_payload = ProductionAuthDebugUnlockReq {
        hdr: McuMailboxReqHeader::default(),
        length: 2,
        unlock_level,
        reserved: [0; 3],
    };
    hw.caliptra_soc_manager()
        .soc_ifc()
        .ss_dbg_service_reg_req()
        .write(|w| w.prod_dbg_unlock_req(true));
    let challenge_response = hw
        .mailbox_execute(
            request_cmd,
            &raw_request(request_cmd, &request_payload.as_bytes()[4..]),
        )?
        .expect("MC_PROD_DEBUG_UNLOCK_REQ returned no response");
    assert_eq!(
        challenge_response.len(),
        size_of::<McuProdDebugUnlockReqResp>()
    );
    assert_response_checksum(&challenge_response);
    let challenge = McuProdDebugUnlockReqResp::read_from_bytes(&challenge_response)
        .expect("invalid debug-unlock challenge response");
    assert_eq!(
        challenge.0.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert_eq!(challenge.0.length, 21);

    let signed_token = signer.sign_debug_unlock_token(
        &ProdDebugUnlockChallenge {
            unique_device_identifier: challenge.0.unique_device_identifier,
            challenge: challenge.0.challenge,
        },
        unlock_level,
    )?;
    let mut token_request = McuProdDebugUnlockTokenReq {
        hdr: McuMailboxReqHeader::default(),
        token: ProductionAuthDebugUnlockToken {
            hdr: McuMailboxReqHeader::default(),
            length: signed_token.length,
            unique_device_identifier: signed_token.unique_device_identifier,
            unlock_level: signed_token.unlock_level,
            reserved: signed_token.reserved,
            challenge: signed_token.challenge,
            ecc_public_key: signed_token.ecc_public_key,
            mldsa_public_key: signed_token.mldsa_public_key,
            ecc_signature: signed_token.ecc_signature,
            mldsa_signature: signed_token.mldsa_signature,
        },
    };
    token_request
        .populate_caliptra_chksum()
        .expect("failed to populate inner debug-token checksum");
    let token_cmd = McuCommandId::MC_PROD_DEBUG_UNLOCK_TOKEN.0;
    hw.caliptra_soc_manager()
        .soc_ifc()
        .ss_dbg_service_reg_req()
        .write(|w| w.prod_dbg_unlock_req(true));
    let token_response = hw
        .mailbox_execute(
            token_cmd,
            &raw_request(token_cmd, &token_request.as_bytes()[4..]),
        )?
        .expect("MC_PROD_DEBUG_UNLOCK_TOKEN returned no response");
    assert_eq!(token_response.len(), size_of::<MailboxRespHeader>());
    assert_response_checksum(&token_response);
    let token_response = MailboxRespHeader::read_from_bytes(&token_response)
        .expect("invalid debug-unlock token response");
    assert_eq!(
        token_response.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    Ok(())
}

#[test]
fn test_fips_self_test_start_complete_response() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-fips-self-test"),
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let results_cmd = McuCommandId::MC_FIPS_SELF_TEST_GET_RESULTS.0;
    let request = raw_request(results_cmd, &[]);
    assert!(
        hw.mailbox_execute(results_cmd, &request).is_err(),
        "self-test results should be unavailable before start"
    );

    let start_cmd = McuCommandId::MC_FIPS_SELF_TEST_START.0;
    let request = raw_request(start_cmd, &[]);
    let response = hw
        .mailbox_execute(start_cmd, &request)?
        .expect("MC_FIPS_SELF_TEST_START returned no response");
    assert_eq!(response.len(), size_of::<McuFipsSelfTestStartResp>());
    assert_response_checksum(&response);
    let response = McuFipsSelfTestStartResp::read_from_bytes(&response)
        .expect("invalid self-test start response");
    assert_eq!(
        response.0.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    let mut results = None;
    for _ in 0..60 {
        for _ in 0..500_000 {
            hw.step();
        }
        if let Ok(Some(response)) = hw.mailbox_execute(results_cmd, &raw_request(results_cmd, &[]))
        {
            results = Some(response);
            break;
        }
    }
    let results = results.expect("MC_FIPS_SELF_TEST_GET_RESULTS did not complete");
    assert_eq!(results.len(), size_of::<McuFipsSelfTestGetResultsResp>());
    assert_response_checksum(&results);
    let results = McuFipsSelfTestGetResultsResp::read_from_bytes(&results)
        .expect("invalid self-test results response");
    assert_eq!(
        results.0.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    let repeated_start = hw
        .mailbox_execute(start_cmd, &raw_request(start_cmd, &[]))?
        .expect("repeated MC_FIPS_SELF_TEST_START returned no response");
    assert_eq!(repeated_start.len(), size_of::<McuFipsSelfTestStartResp>());
    assert_response_checksum(&repeated_start);
    let repeated_start = McuFipsSelfTestStartResp::read_from_bytes(&repeated_start)
        .expect("invalid repeated self-test start response");
    assert_eq!(
        repeated_start.0.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    Ok(())
}

#[test]
fn test_fips_periodic_complete_responses_and_repeated_operations() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-fips-periodic"),
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let status_cmd = McuCommandId::MC_FIPS_PERIODIC_STATUS.0;
    assert!(
        hw.mailbox_execute(status_cmd, &raw_request(status_cmd, &[0; 4]))
            .is_err(),
        "MC_FIPS_PERIODIC_STATUS accepted an oversized request"
    );
    let status_request = raw_request(status_cmd, &[]);
    let status = hw
        .mailbox_execute(status_cmd, &status_request)?
        .expect("MC_FIPS_PERIODIC_STATUS returned no response");
    assert_eq!(status.len(), size_of::<McuFipsPeriodicStatusResp>());
    assert_response_checksum(&status);
    let status =
        McuFipsPeriodicStatusResp::read_from_bytes(&status).expect("invalid periodic status");
    assert_eq!(
        status.header.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert_eq!(status.enabled, 0);
    assert_eq!(status.iterations, 0);
    assert_eq!(status.last_result, 0);

    let enable_cmd = McuCommandId::MC_FIPS_PERIODIC_ENABLE.0;
    for enable in [1, 1, 0, 0] {
        let request = McuFipsPeriodicEnableReq {
            header: McuMailboxReqHeader::default(),
            enable,
        };
        let request = raw_request(enable_cmd, &request.as_bytes()[4..]);
        let response = hw
            .mailbox_execute(enable_cmd, &request)?
            .expect("MC_FIPS_PERIODIC_ENABLE returned no response");
        assert_eq!(response.len(), size_of::<McuFipsPeriodicEnableResp>());
        assert_response_checksum(&response);
        let response = McuFipsPeriodicEnableResp::read_from_bytes(&response)
            .expect("invalid periodic enable response");
        assert_eq!(
            response.0.fips_status,
            MailboxRespHeader::FIPS_STATUS_APPROVED
        );

        let status = hw
            .mailbox_execute(status_cmd, &status_request)?
            .expect("MC_FIPS_PERIODIC_STATUS returned no response");
        assert_eq!(status.len(), size_of::<McuFipsPeriodicStatusResp>());
        assert_response_checksum(&status);
        let status =
            McuFipsPeriodicStatusResp::read_from_bytes(&status).expect("invalid periodic status");
        assert_eq!(
            status.header.fips_status,
            MailboxRespHeader::FIPS_STATUS_APPROVED
        );
        assert_eq!(status.enabled, enable);
    }

    let oversized_request = raw_request(enable_cmd, &[0; 8]);
    assert!(
        hw.mailbox_execute(enable_cmd, &oversized_request).is_err(),
        "MC_FIPS_PERIODIC_ENABLE accepted an oversized request"
    );

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

#[test]
fn test_dpe_signer_context_cert_cmd() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ocp_lock_en: true,
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // 1. Fetch DPE Certificate Chain via MC_GET_DPE_CERTIFICATE_CHAIN (looping across chunks)
    let mut chain_der = Vec::new();
    let mut offset = 0u32;
    loop {
        let chain_req = GetDpeCertChainReq {
            offset,
            size: 1024,
            ..Default::default()
        };
        let chain_resp = hw.mailbox_execute_req(chain_req)?;
        let chunk_len = chain_resp.hdr.data_len as usize;
        if chunk_len == 0 {
            break;
        }
        chain_der.extend_from_slice(&chain_resp.cert_data[..chunk_len]);
        offset += chunk_len as u32;
        if chunk_len < 1024 {
            break;
        }
    }
    assert!(
        !chain_der.is_empty(),
        "DPE Certificate Chain response data length should be non-zero"
    );
    assert_eq!(
        chain_der[0], 0x30,
        "DPE Cert Chain should start with ASN.1 SEQUENCE tag 0x30"
    );

    let mut chain_certs = Vec::new();
    let mut remaining: &[u8] = &chain_der;
    while !remaining.is_empty() && remaining[0] == 0x30 {
        if let Ok(c) = openssl::x509::X509::from_der(remaining) {
            if let Ok(der_bytes) = c.to_der() {
                let der_len = der_bytes.len();
                chain_certs.push(c);
                if remaining.len() >= der_len {
                    remaining = &remaining[der_len..];
                    continue;
                }
            }
        }
        break;
    }
    assert!(
        !chain_certs.is_empty(),
        "Parsed DPE certificate chain should not be empty"
    );

    // 2. Fetch DPE Signer Context Certificate via MC_DPE_SIGNER_CONTEXT_CERT
    let req = DpeSignerContextCertReq::default();
    let resp = hw.mailbox_execute_req(req)?;
    let cert_len = resp.hdr.data_len as usize;
    assert!(cert_len > 0, "Response data length should be non-zero");

    let cert_der = &resp.cert_data[..cert_len];
    assert_eq!(
        cert_der[0], 0x30,
        "Certificate should start with ASN.1 SEQUENCE tag 0x30"
    );

    let cert = openssl::x509::X509::from_der(cert_der)
        .expect("Failed to parse DPE derived leaf certificate as DER");

    // Validate Serial Number (SN)
    let serial_bn = cert
        .serial_number()
        .to_bn()
        .expect("Failed to get serial number BigNum");
    let serial_hex = serial_bn
        .to_hex_str()
        .expect("Failed to convert serial number to hex");
    assert!(!serial_hex.is_empty(), "Serial number should not be empty");

    // Validate Subject CN
    let subject_cn = cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .expect("DPE leaf certificate must have a Common Name entry in Subject");
    let subject_cn_str = std::str::from_utf8(subject_cn.data().as_slice())
        .expect("Subject Common Name should be valid UTF-8");
    assert_eq!(
        subject_cn_str, "DPE Exported CDI",
        "DPE leaf certificate Subject CN should match expected 'DPE Exported CDI'"
    );

    let expected_issuer_cn = "Caliptra 2.1 Ecc384 Rt Alias";

    // Validate Issuer CN
    let issuer_cn = cert
        .issuer_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .expect("DPE leaf certificate must have a Common Name entry in Issuer");
    let issuer_cn_str = std::str::from_utf8(issuer_cn.data().as_slice())
        .expect("Issuer Common Name should be valid UTF-8");

    assert_eq!(issuer_cn_str, expected_issuer_cn,);

    // Verify leaf certificate was signed by the runtime alias key
    let expected_signer = chain_certs
        .iter()
        .find(|cert| {
            let sn = cert
                .subject_name()
                .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                .last()
                .unwrap();

            let sn = std::str::from_utf8(sn.data().as_slice()).unwrap();
            sn == expected_issuer_cn
        })
        .unwrap();

    let pubkey = expected_signer.public_key().unwrap();
    assert!(cert.verify(&pubkey).is_ok());

    Ok(())
}

// Licensed under the Apache-2.0 license

use crate::test::{compile_runtime, start_runtime_hw_model, CustomCaliptraFw, TestParams};
use anyhow::Result;
use caliptra_api::{
    calc_checksum,
    mailbox::{CapabilitiesResp, CommandId, MailboxReqHeader},
    SocManager,
};
use caliptra_image_types::MLDSA87_SIGNATURE_BYTE_SIZE;
use caliptra_mcu_config::capabilities::{
    AuthorizedSubcommandCapabilities, ExternalCommandCapabilities, McuRuntimeCapabilities,
};
use caliptra_mcu_hw_model::{DefaultHwModel, LifecycleControllerState, McuHwModel};
use caliptra_mcu_mbox_common::messages::{
    CmEcdhFinishReq, CmEcdhGenerateReq, CmEcdsaPublicKeyReq, CmEcdsaSignReq, CmEcdsaVerifyReq,
    CmImportReq, CmKeyUsage, CmMldsaPublicKeyReq, CmMldsaSignReq, CmMldsaVerifyReq, Cmk,
    CommandId as McuCommandId, DeviceCapsReq, DeviceCapsResp, DpeSignerContextCertReq,
    EcdsaVerifyReq, EndorsementAlgorithm, ExportAttestedCsrReq, FirmwareVersionReq,
    GetAttestationReq, GetAuthCmdChallengeResp, GetCertChainInfoReq, GetCertChainInfoResp,
    GetCertChainReq, GetDpeCertChainReq, HekStatusReq, LmsVerifyReq,
    MailboxReqHeader as McuMailboxReqHeader, MailboxRespHeader, MailboxRespHeaderVarSize,
    McuCmImportReq, McuEcdhFinishReq, McuEcdhFinishResp, McuEcdhGenerateReq, McuEcdhGenerateResp,
    McuEcdsa384SigVerifyReq, McuEcdsaCmkPublicKeyReq, McuEcdsaCmkPublicKeyResp, McuEcdsaCmkSignReq,
    McuEcdsaCmkSignResp, McuEcdsaCmkVerifyReq, McuFeProgReq, McuFeStatusReq,
    McuFipsPeriodicEnableReq, McuFipsPeriodicEnableResp, McuFipsPeriodicStatusResp,
    McuFipsSelfTestGetResultsResp, McuFipsSelfTestStartResp, McuLmsSigVerifyReq, McuMailboxReq,
    McuMldsaCmkPublicKeyReq, McuMldsaCmkPublicKeyResp, McuMldsaCmkSignReq, McuMldsaCmkSignResp,
    McuMldsaCmkVerifyReq, McuProdDebugUnlockReqReq, McuProdDebugUnlockReqResp,
    McuProdDebugUnlockTokenReq, ProductionAuthDebugUnlockReq, ProductionAuthDebugUnlockToken,
    SetCertChainReq, SetCertChainResp, VendorPkHashStatusReq, GET_ATTESTATION_RESP_PREFIX_LEN,
    MAX_RESP_DATA_SIZE, VENDOR_PQC_KEY_TYPE_LMS,
};
use caliptra_mcu_romtime::{handoff::McuRomCapabilities, McuBootMilestones};
use minicbor::Decoder;
use std::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

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

fn execute_raw_mcu_req(hw: &mut impl McuHwModel, mut request: McuMailboxReq) -> Result<Vec<u8>> {
    request
        .populate_chksum()
        .expect("failed to populate checksum");
    let cmd = request.cmd_code().0;
    Ok(hw
        .mailbox_execute(cmd, request.as_bytes().expect("failed to encode request"))?
        .expect("command returned no response"))
}

fn import_cmk(hw: &mut impl McuHwModel, key_usage: CmKeyUsage, key: &[u8]) -> Result<Cmk> {
    let mut request = CmImportReq {
        key_usage: key_usage.into(),
        input_size: key.len() as u32,
        ..Default::default()
    };
    request.input[..key.len()].copy_from_slice(key);
    Ok(hw.mailbox_execute_req(McuCmImportReq(request))?.0.cmk)
}

fn assert_fixed_response<T: FromBytes + Immutable + KnownLayout>(response: &[u8]) -> &T {
    assert_eq!(response.len(), size_of::<T>());
    assert_response_checksum(response);
    T::ref_from_bytes(response).expect("invalid fixed-size response")
}

fn execute_var_mcu_req(hw: &mut impl McuHwModel, request: McuMailboxReq) -> Result<Vec<u8>> {
    let response = execute_raw_mcu_req(hw, request)?;
    assert_response_checksum(&response);
    let (header, body) =
        MailboxRespHeaderVarSize::ref_from_prefix(&response).expect("invalid response header");
    assert_eq!(
        header.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert_eq!(
        response.len(),
        size_of::<MailboxRespHeaderVarSize>() + header.data_len as usize
    );
    Ok(body.to_vec())
}

fn assert_signed_eat(data: &[u8], nonce: &[u8], expected_algorithms: &[i64], expect_csr: bool) {
    const TAG_SELF_DESCRIBED_CBOR: u64 = 55799;
    const TAG_CWT: u64 = 61;
    const TAG_COSE_SIGN1: u64 = 18;
    const HEADER_ALGORITHM: i64 = 1;
    const ALGORITHM_ESP384: i64 = -51;
    const ALGORITHM_MLDSA87: i64 = -50;
    const ESP384_SIGNATURE_LEN: usize = 96;
    const MLDSA87_SIGNATURE_LEN: usize = 4627;
    const CLAIM_NONCE: i64 = 10;
    const CLAIM_MEASUREMENTS: i64 = 273;
    const CLAIM_CSR: i64 = -70001;
    const CLAIM_KEY_ATTRIBUTES: i64 = -70002;

    let mut decoder = Decoder::new(data);
    let mut tag = decoder.tag().expect("missing CWT tag").as_u64();
    if tag == TAG_SELF_DESCRIBED_CBOR {
        tag = decoder.tag().expect("missing CWT tag").as_u64();
    }
    assert_eq!(tag, TAG_CWT);
    assert_eq!(
        decoder.tag().expect("missing COSE_Sign1 tag").as_u64(),
        TAG_COSE_SIGN1
    );
    assert_eq!(
        decoder
            .array()
            .expect("invalid COSE_Sign1 array")
            .expect("indefinite COSE_Sign1 array"),
        4
    );
    let protected = decoder.bytes().expect("invalid protected header");
    let mut protected_decoder = Decoder::new(protected);
    let protected_len = protected_decoder.map().unwrap().unwrap();
    assert!(protected_len > 0);
    assert_eq!(protected_decoder.i64().unwrap(), HEADER_ALGORITHM);
    let algorithm = protected_decoder.i64().unwrap();
    for _ in 1..protected_len {
        protected_decoder.skip().unwrap();
        protected_decoder.skip().unwrap();
    }
    assert_eq!(
        protected_decoder.position(),
        protected.len(),
        "trailing protected header data"
    );
    assert!(
        expected_algorithms.contains(&algorithm),
        "unexpected protected algorithm {algorithm}"
    );
    let expected_signature_len = match algorithm {
        ALGORITHM_ESP384 => ESP384_SIGNATURE_LEN,
        ALGORITHM_MLDSA87 => MLDSA87_SIGNATURE_LEN,
        _ => panic!("unsupported COSE signature algorithm {algorithm}"),
    };
    let unprotected_len = decoder
        .map()
        .expect("invalid unprotected header")
        .expect("indefinite unprotected header");
    for _ in 0..unprotected_len {
        decoder.skip().expect("invalid unprotected header key");
        decoder.skip().expect("invalid unprotected header value");
    }
    let payload = decoder.bytes().expect("invalid EAT payload");
    assert_eq!(
        decoder.bytes().expect("invalid COSE signature").len(),
        expected_signature_len,
        "unexpected COSE signature length"
    );
    assert_eq!(decoder.position(), data.len(), "trailing COSE data");

    let mut claims = Decoder::new(payload);
    let claims_len = claims
        .map()
        .expect("EAT payload is not a claims map")
        .expect("indefinite EAT claims map");
    let mut found_nonce = false;
    let mut found_measurements = false;
    let mut found_csr = false;
    let mut found_key_attributes = false;
    for _ in 0..claims_len {
        let key = claims.i64().expect("EAT claim key is not an integer");
        match key {
            CLAIM_NONCE => {
                assert!(!found_nonce, "duplicate nonce claim");
                assert_eq!(
                    claims.bytes().expect("nonce claim is not a byte string"),
                    nonce
                );
                found_nonce = true;
            }
            CLAIM_MEASUREMENTS => {
                assert!(!found_measurements, "duplicate measurements claim");
                let measurements_len = claims
                    .array()
                    .expect("measurements claim is not an array")
                    .expect("indefinite measurements array");
                assert!(measurements_len > 0, "measurements claim is empty");
                for _ in 0..measurements_len {
                    claims.skip().expect("invalid measurement");
                }
                found_measurements = true;
            }
            CLAIM_CSR => {
                assert!(!found_csr, "duplicate CSR claim");
                let csr_der = claims.bytes().expect("CSR claim is not a byte string");
                let csr =
                    openssl::x509::X509Req::from_der(csr_der).expect("invalid DER PKCS#10 CSR");
                assert_eq!(csr.to_der().expect("failed to encode CSR"), csr_der);
                found_csr = true;
            }
            CLAIM_KEY_ATTRIBUTES => {
                assert!(!found_key_attributes, "duplicate key attributes claim");
                claims.skip().expect("invalid key attributes claim");
                found_key_attributes = true;
            }
            _ => claims.skip().expect("invalid EAT claim value"),
        }
    }
    assert_eq!(claims.position(), payload.len(), "trailing EAT claims data");
    assert!(found_nonce, "missing nonce claim");
    if expect_csr {
        assert!(found_csr, "missing CSR claim");
        assert!(found_key_attributes, "missing key attributes claim");
    } else {
        assert!(found_measurements, "missing measurements claim");
    }
}

fn start_crypto_mailbox_hw() -> DefaultHwModel {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });
    hw
}

fn start_dpe_mailbox_hw() -> DefaultHwModel {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ocp_lock_en: true,
        ..Default::default()
    });
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });
    hw
}

fn assert_mcu_req_fails(hw: &mut impl McuHwModel, mut request: McuMailboxReq) {
    request
        .populate_chksum()
        .expect("failed to populate checksum");
    assert_mailbox_cmd_failed(hw.mailbox_execute(
        request.cmd_code().0,
        request.as_bytes().expect("failed to encode request"),
    ));
}

fn assert_mailbox_cmd_failed<T>(result: Result<T>) {
    let error = match result {
        Ok(_) => panic!("mailbox command unexpectedly succeeded"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("firmware error"),
        "expected mailbox command failure, got {error:#}"
    );
}

fn ecdsa_verify_req(
    cmk: Cmk,
    message: &[u8],
    signature_r: [u8; 48],
    signature_s: [u8; 48],
) -> McuEcdsaCmkVerifyReq {
    let mut request = CmEcdsaVerifyReq {
        cmk,
        signature_r,
        signature_s,
        message_size: message.len() as u32,
        ..Default::default()
    };
    request.message[..message.len()].copy_from_slice(message);
    McuEcdsaCmkVerifyReq(request)
}

fn mldsa_verify_req(
    cmk: Cmk,
    message: &[u8],
    signature: [u8; MLDSA87_SIGNATURE_BYTE_SIZE],
) -> McuMldsaCmkVerifyReq {
    let mut request = CmMldsaVerifyReq {
        cmk,
        signature,
        message_size: message.len() as u32,
        ..Default::default()
    };
    request.message[..message.len()].copy_from_slice(message);
    McuMldsaCmkVerifyReq(request)
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
    assert!(hw.mailbox_execute(command, &request).is_err());
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
        (ExternalCommandCapabilities::GET_ATTESTATION
            | ExternalCommandCapabilities::EXPORT_ATTESTED_CSR
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
            | AuthorizedSubcommandCapabilities::ZEROIZE_UDS_FE_AND_ENTER_RMA
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
fn test_get_and_clear_log_cmds() -> Result<()> {
    const ISOLATED_PROCESS_ENV: &str = "CALIPTRA_MCU_ISOLATED_LOG_CMD_TEST";
    const TEST_NAME: &str = "runtime::test_mcu_mailbox::test_get_and_clear_log_cmds";

    if std::env::var_os(ISOLATED_PROCESS_ENV).is_none() {
        // Nextest archives can run in a different workspace than the build.
        let working_dir = tempfile::tempdir_in(std::env::current_dir()?)?;
        let status = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(ISOLATED_PROCESS_ENV, "1")
            .current_dir(working_dir.path())
            .status()?;
        assert!(status.success(), "isolated log command test failed");
        return Ok(());
    }

    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-defmt-logging-release"),
        profile: Some("release"),
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
    use caliptra_mcu_builder::{CaliptraBuildArgs, CaliptraBuilder, FirmwareBinaries};
    use caliptra_mcu_debug_unlock_signer::{
        DebugUnlockKeys, DebugUnlockSigner, LocalDebugUnlockSigner, ProdDebugUnlockChallenge,
    };
    use caliptra_mcu_registers_generated::fuses::{
        OTP_CPTRA_CORE_PQC_KEY_TYPE_0, OTP_CPTRA_CORE_VENDOR_PK_HASH_0,
        OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_0, OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_1,
        OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_2, OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_3,
        OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_4, OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_5,
        OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_6, OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_7,
        VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET,
    };
    use sha2::{Digest, Sha384};

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

    let mut otp_memory = vec![0u8; VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET + 256];
    let mut vendor_pk_hash = if let Ok(binaries) = FirmwareBinaries::from_env() {
        binaries.vendor_pk_hash().unwrap().to_vec()
    } else {
        let mut builder = CaliptraBuilder::new(&CaliptraBuildArgs::default());
        hex::decode(builder.get_vendor_pk_hash()?)?
    };
    for word in vendor_pk_hash.chunks_exact_mut(4) {
        word.reverse();
    }
    let offset = OTP_CPTRA_CORE_VENDOR_PK_HASH_0.byte_offset;
    otp_memory[offset..offset + vendor_pk_hash.len()].copy_from_slice(&vendor_pk_hash);
    let offset = OTP_CPTRA_CORE_PQC_KEY_TYPE_0.byte_offset;
    otp_memory[offset..offset + 4].copy_from_slice(&0x3fu32.to_le_bytes());

    for (entry, (ecc, mldsa)) in [
        OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_0,
        OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_1,
        OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_2,
        OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_3,
        OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_4,
        OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_5,
        OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_6,
        OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_7,
    ]
    .into_iter()
    .zip(&prod_dbg_unlock_keypairs)
    {
        let hash = Sha384::new()
            .chain_update(ecc)
            .chain_update(mldsa)
            .finalize();
        for (index, chunk) in hash.chunks_exact(4).enumerate() {
            let word = u32::from_be_bytes(chunk.try_into().unwrap());
            let offset = entry.byte_offset + index * 4;
            otp_memory[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
        }
    }

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
        otp_memory: Some(otp_memory),
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
    const MAILBOX_READY_TIMEOUT_CYCLES: u64 = 100_000_000;

    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-fips-periodic"),
        ..Default::default()
    });

    let start_cycles = hw.cycle_count();
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
            || hw.cycle_count().saturating_sub(start_cycles) >= MAILBOX_READY_TIMEOUT_CYCLES
    });
    anyhow::ensure!(
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY),
        "Firmware mailbox did not become ready within {} cycles; milestones: {:#06x}",
        MAILBOX_READY_TIMEOUT_CYCLES,
        hw.mci_boot_milestones().bits(),
    );

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
fn test_get_auth_cmd_challenge_invalid_fields() -> Result<()> {
    let mut hw = start_crypto_mailbox_hw();
    let cmd = McuCommandId::MC_AUTHORIZED_COMMAND.0;
    let target = McuCommandId::MC_GET_AUTH_CMD_CHALLENGE.0.to_le_bytes();

    let mut invalid_flags = target.to_vec();
    invalid_flags.extend_from_slice(&1u32.to_le_bytes());
    assert!(
        hw.mailbox_execute(cmd, &raw_request(cmd, &invalid_flags))
            .is_err(),
        "MC_GET_AUTH_CMD_CHALLENGE accepted invalid flags"
    );

    let mut invalid_reserved = target.to_vec();
    invalid_reserved.extend_from_slice(&0u32.to_le_bytes());
    invalid_reserved.extend_from_slice(&1u32.to_le_bytes());
    assert!(
        hw.mailbox_execute(cmd, &raw_request(cmd, &invalid_reserved))
            .is_err(),
        "MC_GET_AUTH_CMD_CHALLENGE accepted a nonzero reserved field"
    );

    Ok(())
}

#[test]
fn test_get_auth_cmd_challenge_successive_generation() -> Result<()> {
    let mut hw = start_crypto_mailbox_hw();
    let cmd = McuCommandId::MC_AUTHORIZED_COMMAND.0;
    let target = McuCommandId::MC_GET_AUTH_CMD_CHALLENGE.0.to_le_bytes();
    let request = raw_request(cmd, &target);
    let first_response = hw
        .mailbox_execute(cmd, &request)?
        .expect("MC_GET_AUTH_CMD_CHALLENGE returned no response");
    let first = assert_fixed_response::<GetAuthCmdChallengeResp>(&first_response);
    assert_eq!(
        first.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert_eq!(first.reserved, 0);
    assert!(first.challenge.iter().any(|&byte| byte != 0));

    let second_response = hw
        .mailbox_execute(cmd, &request)?
        .expect("successive MC_GET_AUTH_CMD_CHALLENGE returned no response");
    let second = assert_fixed_response::<GetAuthCmdChallengeResp>(&second_response);
    assert_eq!(
        second.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert_eq!(second.reserved, 0);
    assert!(second.challenge.iter().any(|&byte| byte != 0));
    assert_ne!(first.challenge, second.challenge);

    Ok(())
}

#[test]
fn test_mcu_mbox_ecdh_commands() -> Result<()> {
    let mut hw = start_crypto_mailbox_hw();

    let generate_response = execute_raw_mcu_req(
        &mut hw,
        McuMailboxReq::EcdhGenerate(McuEcdhGenerateReq(CmEcdhGenerateReq::default())),
    )?;
    let generate = assert_fixed_response::<McuEcdhGenerateResp>(&generate_response);
    assert_eq!(
        generate.0.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert_ne!(generate.0.context, [0; 76]);
    assert_ne!(generate.0.exchange_data, [0; 96]);

    let finish_response = execute_raw_mcu_req(
        &mut hw,
        McuMailboxReq::EcdhFinish(McuEcdhFinishReq(CmEcdhFinishReq {
            context: generate.0.context,
            key_usage: CmKeyUsage::Aes.into(),
            incoming_exchange_data: generate.0.exchange_data,
            ..Default::default()
        })),
    )?;
    let finish = assert_fixed_response::<McuEcdhFinishResp>(&finish_response);
    assert_eq!(
        finish.0.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert_ne!(finish.0.output, Cmk::default());

    for invalid in [
        CmEcdhFinishReq {
            key_usage: CmKeyUsage::Aes.into(),
            incoming_exchange_data: generate.0.exchange_data,
            ..Default::default()
        },
        CmEcdhFinishReq {
            context: generate.0.context,
            key_usage: u32::MAX,
            incoming_exchange_data: generate.0.exchange_data,
            ..Default::default()
        },
        CmEcdhFinishReq {
            context: generate.0.context,
            key_usage: CmKeyUsage::Aes.into(),
            incoming_exchange_data: [0; 96],
            ..Default::default()
        },
    ] {
        assert_mailbox_cmd_failed(hw.mailbox_execute_req(McuEcdhFinishReq(invalid)));
    }
    Ok(())
}

#[test]
fn test_mcu_mbox_ecdsa_cmk_commands() -> Result<()> {
    let mut hw = start_crypto_mailbox_hw();

    let cmk = import_cmk(&mut hw, CmKeyUsage::Ecdsa, &[0; 48])?;
    let public_key_response = execute_raw_mcu_req(
        &mut hw,
        McuMailboxReq::EcdsaCmkPublicKey(McuEcdsaCmkPublicKeyReq(CmEcdsaPublicKeyReq {
            cmk,
            ..Default::default()
        })),
    )?;
    let public_key = assert_fixed_response::<McuEcdsaCmkPublicKeyResp>(&public_key_response);
    assert_eq!(
        public_key.0.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert_ne!(public_key.0.public_key_x, [0; 48]);
    assert_ne!(public_key.0.public_key_y, [0; 48]);

    let message = b"ECDSA mailbox test";
    let mut sign_request = CmEcdsaSignReq {
        cmk,
        message_size: message.len() as u32,
        ..Default::default()
    };
    sign_request.message[..message.len()].copy_from_slice(message);
    let sign_response = execute_raw_mcu_req(
        &mut hw,
        McuMailboxReq::EcdsaCmkSign(McuEcdsaCmkSignReq(sign_request)),
    )?;
    let signature = assert_fixed_response::<McuEcdsaCmkSignResp>(&sign_response);
    assert_eq!(
        signature.0.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert_ne!(signature.0.signature_r, [0; 48]);
    assert_ne!(signature.0.signature_s, [0; 48]);

    let verify_response = execute_raw_mcu_req(
        &mut hw,
        McuMailboxReq::EcdsaCmkVerify(ecdsa_verify_req(
            cmk,
            message,
            signature.0.signature_r,
            signature.0.signature_s,
        )),
    )?;
    assert_eq!(
        assert_fixed_response::<MailboxRespHeader>(&verify_response).fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    let mut invalid_signature = signature.0.signature_r;
    invalid_signature[0] ^= 1;
    assert_mcu_req_fails(
        &mut hw,
        McuMailboxReq::EcdsaCmkVerify(ecdsa_verify_req(
            cmk,
            message,
            invalid_signature,
            signature.0.signature_s,
        )),
    );

    let aes_cmk = import_cmk(&mut hw, CmKeyUsage::Aes, &[0xa5; 32])?;
    for invalid_cmk in [Cmk::default(), aes_cmk] {
        for request in [
            McuMailboxReq::EcdsaCmkPublicKey(McuEcdsaCmkPublicKeyReq(CmEcdsaPublicKeyReq {
                cmk: invalid_cmk,
                ..Default::default()
            })),
            McuMailboxReq::EcdsaCmkSign(McuEcdsaCmkSignReq(CmEcdsaSignReq {
                cmk: invalid_cmk,
                ..Default::default()
            })),
            McuMailboxReq::EcdsaCmkVerify(ecdsa_verify_req(invalid_cmk, &[], [0; 48], [0; 48])),
        ] {
            assert_mcu_req_fails(&mut hw, request);
        }
    }
    Ok(())
}

#[test]
fn test_fe_status_cmd_does_not_require_authorization() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let resp = hw.mailbox_execute_req(McuFeStatusReq::default())?;
    assert_eq!(resp.already_provisioned, 0);

    let cmd = McuCommandId::MC_FE_STATUS.into();

    let truncated = [0u8; 3];
    assert!(hw.mailbox_execute(cmd, &truncated).is_err());

    let mut oversized = [0u8; 8];
    oversized[4..].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    let oversized_checksum = calc_checksum(cmd, &oversized[4..]);
    oversized[..4].copy_from_slice(&oversized_checksum.to_le_bytes());
    assert!(hw.mailbox_execute(cmd, &oversized).is_err());

    let invalid_checksum = [0u8; 4];
    assert!(hw.mailbox_execute(cmd, &invalid_checksum).is_err());
    Ok(())
}

#[test]
fn test_mcu_mbox_mldsa_cmk_commands() -> Result<()> {
    let mut hw = start_crypto_mailbox_hw();

    let cmk = import_cmk(&mut hw, CmKeyUsage::Mldsa, &[0x5a; 32])?;
    let public_key_response = execute_raw_mcu_req(
        &mut hw,
        McuMailboxReq::MldsaCmkPublicKey(McuMldsaCmkPublicKeyReq(CmMldsaPublicKeyReq {
            cmk,
            ..Default::default()
        })),
    )?;
    let public_key = assert_fixed_response::<McuMldsaCmkPublicKeyResp>(&public_key_response);
    assert_eq!(
        public_key.0.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert!(public_key.0.public_key.iter().any(|byte| *byte != 0));

    let message = b"ML-DSA mailbox test";
    let mut sign_request = CmMldsaSignReq {
        cmk,
        message_size: message.len() as u32,
        ..Default::default()
    };
    sign_request.message[..message.len()].copy_from_slice(message);
    let sign_response = execute_raw_mcu_req(
        &mut hw,
        McuMailboxReq::MldsaCmkSign(McuMldsaCmkSignReq(sign_request)),
    )?;
    let signature = assert_fixed_response::<McuMldsaCmkSignResp>(&sign_response);
    assert_eq!(
        signature.0.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert!(signature.0.signature.iter().any(|byte| *byte != 0));

    let verify_response = execute_raw_mcu_req(
        &mut hw,
        McuMailboxReq::MldsaCmkVerify(mldsa_verify_req(cmk, message, signature.0.signature)),
    )?;
    assert_eq!(
        assert_fixed_response::<MailboxRespHeader>(&verify_response).fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    let mut invalid_signature = signature.0.signature;
    invalid_signature[0] ^= 1;
    assert_mcu_req_fails(
        &mut hw,
        McuMailboxReq::MldsaCmkVerify(mldsa_verify_req(cmk, message, invalid_signature)),
    );

    let aes_cmk = import_cmk(&mut hw, CmKeyUsage::Aes, &[0xa5; 32])?;
    for invalid_cmk in [Cmk::default(), aes_cmk] {
        for request in [
            McuMailboxReq::MldsaCmkPublicKey(McuMldsaCmkPublicKeyReq(CmMldsaPublicKeyReq {
                cmk: invalid_cmk,
                ..Default::default()
            })),
            McuMailboxReq::MldsaCmkSign(McuMldsaCmkSignReq(CmMldsaSignReq {
                cmk: invalid_cmk,
                ..Default::default()
            })),
            McuMailboxReq::MldsaCmkVerify(mldsa_verify_req(
                invalid_cmk,
                &[],
                [0; MLDSA87_SIGNATURE_BYTE_SIZE],
            )),
        ] {
            assert_mcu_req_fails(&mut hw, request);
        }
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

    let cmd = McuCommandId::MC_VENDOR_PK_HASH_STATUS.into();

    let truncated = [0u8; 3];
    assert!(hw.mailbox_execute(cmd, &truncated).is_err());

    let mut oversized = [0u8; 8];
    oversized[4..].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    let oversized_checksum = calc_checksum(cmd, &oversized[4..]);
    oversized[..4].copy_from_slice(&oversized_checksum.to_le_bytes());
    assert!(hw.mailbox_execute(cmd, &oversized).is_err());

    let invalid_checksum = [0u8; 4];
    assert!(hw.mailbox_execute(cmd, &invalid_checksum).is_err());
    Ok(())
}

#[test]
fn test_hek_status_cmd_does_not_require_authorization() -> Result<()> {
    let _lock = crate::test::TEST_LOCK.lock().unwrap();
    let mut otp = vec![0u8; 4096];
    crate::test_hek::test::setup_otp_hek(&mut otp, 0, false, false);
    crate::test_hek::test::setup_otp_hek(&mut otp, 2, true, false);

    let mut hw = start_runtime_hw_model(TestParams {
        otp_memory: Some(otp),
        ocp_lock_en: true,
        feature: Some("test-ekp"),
        rom_feature: Some("ocp-lock"),
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let resp = hw.mailbox_execute_req(HekStatusReq::default())?;
    assert_eq!(resp.used_slots_bitmap, (1 << 0) | (1 << 2));
    assert_eq!(resp.used_slots_bitmap.count_ones(), 2);
    assert_eq!(resp.total_slots, 8);

    let cmd = McuCommandId::MC_HEK_STATUS.into();

    let truncated = [0u8; 3];
    assert!(hw.mailbox_execute(cmd, &truncated).is_err());

    let mut oversized = [0u8; 8];
    oversized[4..].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    let oversized_checksum = calc_checksum(cmd, &oversized[4..]);
    oversized[..4].copy_from_slice(&oversized_checksum.to_le_bytes());
    assert!(hw.mailbox_execute(cmd, &oversized).is_err());
    let invalid_checksum = [0u8; 4];
    assert!(hw.mailbox_execute(cmd, &invalid_checksum).is_err());
    assert!(hw.mailbox_execute(cmd, &invalid_checksum).is_err());
    Ok(())
}

#[test]
fn test_mcu_mbox_ecdsa384_sig_verify() -> Result<()> {
    use caliptra_image_crypto::RustCrypto;
    use caliptra_image_fake_keys::{
        VENDOR_ECC_KEY_0_PRIVATE, VENDOR_ECC_KEY_0_PUBLIC, VENDOR_ECC_KEY_1_PUBLIC,
    };
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
    let pub_key_x = from_hw_format(&VENDOR_ECC_KEY_0_PUBLIC.x);
    let pub_key_y = from_hw_format(&VENDOR_ECC_KEY_0_PUBLIC.y);

    let request = EcdsaVerifyReq {
        hdr: McuMailboxReqHeader::default(),
        pub_key_x,
        pub_key_y,
        signature_r,
        signature_s,
        hash: digest,
    };
    let cmd = McuCommandId::MC_ECDSA384_SIG_VERIFY.0;
    let response = hw
        .mailbox_execute(cmd, &raw_request(cmd, &request.as_bytes()[4..]))?
        .expect("MC_ECDSA384_SIG_VERIFY returned no response");
    let resp = assert_fixed_response::<MailboxRespHeader>(&response);
    assert_eq!(
        resp.fips_status,
        MailboxRespHeader::FIPS_STATUS_NOT_APPROVED_USER_SUPPLIED_DIGEST
    );

    let mut invalid_signature_r = signature_r;
    invalid_signature_r[0] ^= 1;
    let invalid = McuEcdsa384SigVerifyReq(EcdsaVerifyReq {
        hdr: McuMailboxReqHeader::default(),
        pub_key_x,
        pub_key_y,
        signature_r: invalid_signature_r,
        signature_s,
        hash: digest,
    });
    assert_mailbox_cmd_failed(hw.mailbox_execute_req(invalid));

    let mut invalid_digest = digest;
    invalid_digest[0] ^= 1;
    assert_mailbox_cmd_failed(
        hw.mailbox_execute_req(McuEcdsa384SigVerifyReq(EcdsaVerifyReq {
            hdr: McuMailboxReqHeader::default(),
            pub_key_x,
            pub_key_y,
            signature_r,
            signature_s,
            hash: invalid_digest,
        })),
    );
    assert_mailbox_cmd_failed(
        hw.mailbox_execute_req(McuEcdsa384SigVerifyReq(EcdsaVerifyReq {
            hdr: McuMailboxReqHeader::default(),
            pub_key_x: from_hw_format(&VENDOR_ECC_KEY_1_PUBLIC.x),
            pub_key_y: from_hw_format(&VENDOR_ECC_KEY_1_PUBLIC.y),
            signature_r,
            signature_s,
            hash: digest,
        })),
    );
    Ok(())
}

#[cfg(not(feature = "fpga_realtime"))]
#[test]
fn test_mcu_mbox_lms_sig_verify() -> Result<()> {
    use caliptra_image_crypto::RustCrypto;
    use caliptra_image_fake_keys::{
        VENDOR_LMS_KEY_0_PRIVATE, VENDOR_LMS_KEY_0_PUBLIC, VENDOR_LMS_KEY_1_PUBLIC,
    };
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
    let pub_key_digest = VENDOR_LMS_KEY_0_PUBLIC
        .digest
        .as_bytes()
        .try_into()
        .unwrap();
    let signature_tree_path = signature.tree_path.as_bytes().try_into().unwrap();

    let request = LmsVerifyReq {
        hdr: McuMailboxReqHeader::default(),
        pub_key_tree_type: u32::from(VENDOR_LMS_KEY_0_PUBLIC.tree_type.0),
        pub_key_ots_type: u32::from(VENDOR_LMS_KEY_0_PUBLIC.otstype.0),
        pub_key_id: VENDOR_LMS_KEY_0_PUBLIC.id,
        pub_key_digest,
        signature_q: u32::from(signature.q),
        signature_ots,
        signature_tree_type: u32::from(signature.tree_type.0),
        signature_tree_path,
        hash: digest,
    };
    let cmd = McuCommandId::MC_LMS_SIG_VERIFY.0;
    let response = hw
        .mailbox_execute(cmd, &raw_request(cmd, &request.as_bytes()[4..]))?
        .expect("MC_LMS_SIG_VERIFY returned no response");
    let resp = assert_fixed_response::<MailboxRespHeader>(&response);
    assert_eq!(
        resp.fips_status,
        MailboxRespHeader::FIPS_STATUS_NOT_APPROVED_USER_SUPPLIED_DIGEST
    );

    let mut invalid_signature_ots = signature_ots;
    invalid_signature_ots[4] ^= 1;
    let invalid = McuLmsSigVerifyReq(LmsVerifyReq {
        hdr: McuMailboxReqHeader::default(),
        pub_key_tree_type: u32::from(VENDOR_LMS_KEY_0_PUBLIC.tree_type.0),
        pub_key_ots_type: u32::from(VENDOR_LMS_KEY_0_PUBLIC.otstype.0),
        pub_key_id: VENDOR_LMS_KEY_0_PUBLIC.id,
        pub_key_digest,
        signature_q: u32::from(signature.q),
        signature_ots: invalid_signature_ots,
        signature_tree_type: u32::from(signature.tree_type.0),
        signature_tree_path,
        hash: digest,
    });
    assert_mailbox_cmd_failed(hw.mailbox_execute_req(invalid));

    let mut invalid_digest = digest;
    invalid_digest[0] ^= 1;
    assert_mailbox_cmd_failed(hw.mailbox_execute_req(McuLmsSigVerifyReq(LmsVerifyReq {
        hdr: McuMailboxReqHeader::default(),
        pub_key_tree_type: u32::from(VENDOR_LMS_KEY_0_PUBLIC.tree_type.0),
        pub_key_ots_type: u32::from(VENDOR_LMS_KEY_0_PUBLIC.otstype.0),
        pub_key_id: VENDOR_LMS_KEY_0_PUBLIC.id,
        pub_key_digest,
        signature_q: u32::from(signature.q),
        signature_ots,
        signature_tree_type: u32::from(signature.tree_type.0),
        signature_tree_path,
        hash: invalid_digest,
    })));
    assert_mailbox_cmd_failed(hw.mailbox_execute_req(McuLmsSigVerifyReq(LmsVerifyReq {
        hdr: McuMailboxReqHeader::default(),
        pub_key_tree_type: u32::MAX,
        pub_key_ots_type: u32::from(VENDOR_LMS_KEY_0_PUBLIC.otstype.0),
        pub_key_id: VENDOR_LMS_KEY_0_PUBLIC.id,
        pub_key_digest,
        signature_q: u32::from(signature.q),
        signature_ots,
        signature_tree_type: u32::from(signature.tree_type.0),
        signature_tree_path,
        hash: digest,
    })));
    assert_mailbox_cmd_failed(
        hw.mailbox_execute_req(McuLmsSigVerifyReq(LmsVerifyReq {
            hdr: McuMailboxReqHeader::default(),
            pub_key_tree_type: u32::from(VENDOR_LMS_KEY_1_PUBLIC.tree_type.0),
            pub_key_ots_type: u32::from(VENDOR_LMS_KEY_1_PUBLIC.otstype.0),
            pub_key_id: VENDOR_LMS_KEY_1_PUBLIC.id,
            pub_key_digest: VENDOR_LMS_KEY_1_PUBLIC
                .digest
                .as_bytes()
                .try_into()
                .unwrap(),
            signature_q: u32::from(signature.q),
            signature_ots,
            signature_tree_type: u32::from(signature.tree_type.0),
            signature_tree_path,
            hash: digest,
        })),
    );
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
fn test_export_attested_csr_cmd() -> Result<()> {
    let mut hw = start_crypto_mailbox_hw();

    for algorithm in [
        ExportAttestedCsrReq::ALGO_ECC384,
        ExportAttestedCsrReq::ALGO_MLDSA87,
    ] {
        let expected_algorithms: &[i64] = match algorithm {
            ExportAttestedCsrReq::ALGO_ECC384 => &[-51],
            ExportAttestedCsrReq::ALGO_MLDSA87 => &[-50],
            _ => unreachable!(),
        };
        let nonce = [algorithm as u8; 32];
        let body = execute_var_mcu_req(
            &mut hw,
            McuMailboxReq::ExportAttestedCsr(ExportAttestedCsrReq {
                device_key_id: ExportAttestedCsrReq::KEY_ID_RT_ALIAS,
                algorithm,
                nonce,
                ..Default::default()
            }),
        )?;
        assert_signed_eat(&body, &nonce, expected_algorithms, true);
    }

    for request in [
        ExportAttestedCsrReq {
            device_key_id: u32::MAX,
            algorithm: ExportAttestedCsrReq::ALGO_ECC384,
            nonce: [0x5a; 32],
            ..Default::default()
        },
        ExportAttestedCsrReq {
            device_key_id: ExportAttestedCsrReq::KEY_ID_RT_ALIAS,
            algorithm: u32::MAX,
            nonce: [0x5a; 32],
            ..Default::default()
        },
    ] {
        assert_mcu_req_fails(&mut hw, McuMailboxReq::ExportAttestedCsr(request));
    }
    Ok(())
}

#[test]
fn test_get_attestation_cmd() -> Result<()> {
    const FORMAT_QUERY: u32 = 0;
    const FORMAT_OCP_EAT: u32 = 1;
    const ALGO_ECC384: u32 = 1;
    const ALGO_MLDSA87: u32 = 2;
    const SLOT_VENDOR: u32 = 0;
    const SLOT_OWNER: u32 = 1;

    let mut hw = start_crypto_mailbox_hw();

    let query = execute_var_mcu_req(
        &mut hw,
        McuMailboxReq::GetAttestation(GetAttestationReq {
            evidence_format: FORMAT_QUERY,
            ..Default::default()
        }),
    )?;
    assert_eq!(
        query.len(),
        GET_ATTESTATION_RESP_PREFIX_LEN + size_of::<u32>()
    );
    assert_eq!(
        u32::from_le_bytes(query[..GET_ATTESTATION_RESP_PREFIX_LEN].try_into().unwrap()),
        FORMAT_QUERY
    );
    let formats = u32::from_le_bytes(query[GET_ATTESTATION_RESP_PREFIX_LEN..].try_into().unwrap());
    assert_eq!(formats, 1 << FORMAT_OCP_EAT);

    for algorithm in [ALGO_ECC384, ALGO_MLDSA87] {
        let expected_algorithm = match algorithm {
            ALGO_ECC384 => -51,
            ALGO_MLDSA87 => -50,
            _ => unreachable!(),
        };
        let nonce = [0x40 | algorithm as u8; 32];
        let body = execute_var_mcu_req(
            &mut hw,
            McuMailboxReq::GetAttestation(GetAttestationReq {
                evidence_format: FORMAT_OCP_EAT,
                algorithm,
                pki_entity_slot: SLOT_VENDOR,
                nonce,
                ..Default::default()
            }),
        )?;
        assert!(body.len() > GET_ATTESTATION_RESP_PREFIX_LEN);
        assert_eq!(
            u32::from_le_bytes(body[..GET_ATTESTATION_RESP_PREFIX_LEN].try_into().unwrap()),
            FORMAT_OCP_EAT
        );
        let evidence = &body[GET_ATTESTATION_RESP_PREFIX_LEN..];
        assert_signed_eat(evidence, &nonce, &[expected_algorithm], false);
    }

    for request in [
        GetAttestationReq {
            evidence_format: u32::MAX,
            algorithm: ALGO_ECC384,
            pki_entity_slot: SLOT_VENDOR,
            ..Default::default()
        },
        GetAttestationReq {
            evidence_format: FORMAT_OCP_EAT,
            algorithm: u32::MAX,
            pki_entity_slot: SLOT_VENDOR,
            ..Default::default()
        },
        GetAttestationReq {
            evidence_format: FORMAT_OCP_EAT,
            algorithm: ALGO_ECC384,
            pki_entity_slot: SLOT_OWNER,
            ..Default::default()
        },
        GetAttestationReq {
            evidence_format: FORMAT_OCP_EAT,
            algorithm: ALGO_ECC384,
            pki_entity_slot: u32::MAX,
            ..Default::default()
        },
    ] {
        assert_mcu_req_fails(&mut hw, McuMailboxReq::GetAttestation(request));
    }
    Ok(())
}

#[test]
fn test_dpe_signer_context_cert_cmd() -> Result<()> {
    let mut hw = start_dpe_mailbox_hw();

    // 1. Fetch DPE Certificate Chain via MC_GET_DPE_CERTIFICATE_CHAIN (looping across chunks)
    let mut chain_der = Vec::new();
    let mut offset = 0u32;
    loop {
        let chunk = execute_var_mcu_req(
            &mut hw,
            McuMailboxReq::GetDpeCertChain(GetDpeCertChainReq {
                offset,
                size: 1024,
                ..Default::default()
            }),
        )?;
        let chunk_len = chunk.len();
        assert!(chunk_len <= 1024);
        if chunk_len == 0 {
            break;
        }
        chain_der.extend_from_slice(&chunk);
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
    while !remaining.is_empty() {
        let (rest, _) =
            x509_parser::parse_x509_certificate(remaining).expect("invalid certificate chain DER");
        let cert_len = remaining.len() - rest.len();
        chain_certs.push(
            openssl::x509::X509::from_der(&remaining[..cert_len])
                .expect("failed to parse chain certificate"),
        );
        remaining = rest;
    }
    assert!(
        !chain_certs.is_empty(),
        "Parsed DPE certificate chain should not be empty"
    );
    assert!(remaining.is_empty(), "trailing certificate chain data");

    // 2. Fetch DPE Signer Context Certificate via MC_DPE_SIGNER_CONTEXT_CERT
    let cert_der = execute_var_mcu_req(
        &mut hw,
        McuMailboxReq::DpeSignerContextCert(DpeSignerContextCertReq::default()),
    )?;
    assert!(!cert_der.is_empty(), "Response data should be non-zero");
    assert_eq!(
        cert_der[0], 0x30,
        "Certificate should start with ASN.1 SEQUENCE tag 0x30"
    );

    let cert = openssl::x509::X509::from_der(&cert_der)
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

    assert_mcu_req_fails(
        &mut hw,
        McuMailboxReq::DpeSignerContextCert(DpeSignerContextCertReq::default()),
    );

    for request in [
        McuMailboxReq::GetDpeCertChain(GetDpeCertChainReq {
            offset: 0,
            size: MAX_RESP_DATA_SIZE as u32 + 1,
            ..Default::default()
        }),
        McuMailboxReq::GetDpeCertChain(GetDpeCertChainReq {
            offset: u32::MAX,
            size: 1,
            ..Default::default()
        }),
    ] {
        assert_mcu_req_fails(&mut hw, request);
    }

    let mut mldsa_hw = start_dpe_mailbox_hw();
    assert_mcu_req_fails(
        &mut mldsa_hw,
        McuMailboxReq::DpeSignerContextCert(DpeSignerContextCertReq {
            algorithm: EndorsementAlgorithm(u32::MAX),
            ..Default::default()
        }),
    );
    let mldsa_cert = execute_var_mcu_req(
        &mut mldsa_hw,
        McuMailboxReq::DpeSignerContextCert(DpeSignerContextCertReq {
            algorithm: EndorsementAlgorithm::MLDSA_87,
            ..Default::default()
        }),
    )?;
    let (remaining, cert) =
        x509_parser::parse_x509_certificate(&mldsa_cert).expect("invalid ML-DSA certificate DER");
    assert!(remaining.is_empty(), "trailing ML-DSA certificate data");
    let mldsa87_oid = x509_parser::oid_registry::asn1_rs::oid!(2.16.840 .1 .101 .3 .4 .3 .19);
    assert_eq!(
        cert.tbs_certificate.subject_pki.algorithm.algorithm,
        mldsa87_oid
    );
    assert_eq!(cert.signature_algorithm.algorithm, mldsa87_oid);

    Ok(())
}

fn synthetic_der_cert(body_len: usize, fill: u8) -> Vec<u8> {
    let mut der = Vec::with_capacity(4 + body_len);
    der.push(0x30);
    der.push(0x82);
    der.extend_from_slice(&(body_len as u16).to_be_bytes());
    der.extend(std::iter::repeat_n(fill, body_len));
    der
}

fn read_full_mci_cert_chain(
    hw: &mut impl McuHwModel,
    pki_entity_slot: u32,
    algorithm: u32,
    chunk_size: u32,
) -> Result<Vec<u8>> {
    let mut chain = Vec::new();
    let mut offset = 0u32;
    loop {
        let chunk = execute_var_mcu_req(
            hw,
            McuMailboxReq::GetCertChain(GetCertChainReq {
                pki_entity_slot,
                algorithm,
                offset,
                length: chunk_size,
                ..Default::default()
            }),
        )?;
        assert!(chunk.len() <= chunk_size as usize);
        if chunk.is_empty() {
            break;
        }
        chain.extend_from_slice(&chunk);
        offset += chunk.len() as u32;
        if (chunk.len() as u32) < chunk_size {
            break;
        }
    }
    Ok(chain)
}

#[test]
fn test_cert_chain_and_all_role_attestation_cmds() -> Result<()> {
    use sha2::{Digest, Sha384};

    const FORMAT_OCP_EAT: u32 = 1;
    const ALGO_ECC384: u32 = 1;
    const ALGO_MLDSA87: u32 = 2;
    const SLOT_VENDOR: u32 = 0;
    const SLOT_OWNER: u32 = 1;
    const SLOT_TENANT: u32 = 2;
    const KEY_ID_DEFAULT: u32 = 0;
    const KEY_ID_LDEV_ID: u32 = 1;
    const KEY_ID_FMC_ALIAS: u32 = 2;

    let mut hw = start_crypto_mailbox_hw();

    // 1. Vendor slot: read-only, anchored at IDevID (device_key_id == 0).
    for (algo, chunk_size) in [(ALGO_ECC384, 512u32), (ALGO_MLDSA87, 2048u32)] {
        let info_resp = execute_raw_mcu_req(
            &mut hw,
            McuMailboxReq::GetCertChainInfo(GetCertChainInfoReq {
                pki_entity_slot: SLOT_VENDOR,
                algorithm: algo,
                ..Default::default()
            }),
        )?;
        let info = assert_fixed_response::<GetCertChainInfoResp>(&info_resp);
        assert_eq!(
            info.hdr.fips_status,
            MailboxRespHeader::FIPS_STATUS_APPROVED
        );
        assert_eq!(info.device_key_id, 0);
        assert!(info.chain_len > 0);

        let chain = read_full_mci_cert_chain(&mut hw, SLOT_VENDOR, algo, chunk_size)?;
        assert_eq!(chain.len(), info.chain_len as usize);
        let expected_digest: [u8; 48] = Sha384::digest(&chain).into();
        assert_eq!(info.chain_digest, expected_digest);

        // Reading at offset == chain_len returns an empty chunk.
        let eof_chunk = execute_var_mcu_req(
            &mut hw,
            McuMailboxReq::GetCertChain(GetCertChainReq {
                pki_entity_slot: SLOT_VENDOR,
                algorithm: algo,
                offset: info.chain_len,
                length: 64,
                ..Default::default()
            }),
        )?;
        assert!(eof_chunk.is_empty());
    }

    // Writing to Vendor slot must fail (read-only).
    let vendor_write_der = synthetic_der_cert(128, 0xAA);
    let mut vendor_set_req = SetCertChainReq {
        pki_entity_slot: SLOT_VENDOR,
        algorithm: ALGO_ECC384,
        device_key_id: KEY_ID_LDEV_ID,
        offset: 0,
        total_size: vendor_write_der.len() as u32,
        data_len: vendor_write_der.len() as u32,
        ..Default::default()
    };
    vendor_set_req.cert_data[..vendor_write_der.len()].copy_from_slice(&vendor_write_der);
    assert_mcu_req_fails(&mut hw, McuMailboxReq::SetCertChain(vendor_set_req));

    // 2. Unprovisioned Owner and Tenant slots reject info, chain read, and attestation.
    for slot in [SLOT_OWNER, SLOT_TENANT] {
        assert_mcu_req_fails(
            &mut hw,
            McuMailboxReq::GetCertChainInfo(GetCertChainInfoReq {
                pki_entity_slot: slot,
                algorithm: ALGO_ECC384,
                ..Default::default()
            }),
        );
        assert_mcu_req_fails(
            &mut hw,
            McuMailboxReq::GetCertChain(GetCertChainReq {
                pki_entity_slot: slot,
                algorithm: ALGO_ECC384,
                offset: 0,
                length: 256,
                ..Default::default()
            }),
        );
        assert_mcu_req_fails(
            &mut hw,
            McuMailboxReq::GetAttestation(GetAttestationReq {
                evidence_format: FORMAT_OCP_EAT,
                algorithm: ALGO_ECC384,
                pki_entity_slot: slot,
                nonce: [0x11; 32],
                ..Default::default()
            }),
        );
    }

    // 3. Provision Owner slot in two chunks with policy default device_key_id == 0 (resolves to LDevID == 1).
    let mut owner_endorsement = synthetic_der_cert(300, 0x21);
    owner_endorsement.extend_from_slice(&synthetic_der_cert(260, 0x22));
    let split = 256usize;
    for (offset, chunk) in [
        (0usize, &owner_endorsement[..split]),
        (split, &owner_endorsement[split..]),
    ] {
        let mut req = SetCertChainReq {
            pki_entity_slot: SLOT_OWNER,
            algorithm: ALGO_ECC384,
            device_key_id: KEY_ID_DEFAULT,
            offset: offset as u32,
            total_size: owner_endorsement.len() as u32,
            data_len: chunk.len() as u32,
            ..Default::default()
        };
        req.cert_data[..chunk.len()].copy_from_slice(chunk);
        let resp = execute_raw_mcu_req(&mut hw, McuMailboxReq::SetCertChain(req))?;
        assert_eq!(
            assert_fixed_response::<SetCertChainResp>(&resp)
                .hdr
                .fips_status,
            MailboxRespHeader::FIPS_STATUS_APPROVED
        );
    }

    let owner_info_resp = execute_raw_mcu_req(
        &mut hw,
        McuMailboxReq::GetCertChainInfo(GetCertChainInfoReq {
            pki_entity_slot: SLOT_OWNER,
            algorithm: ALGO_ECC384,
            ..Default::default()
        }),
    )?;
    let owner_info = assert_fixed_response::<GetCertChainInfoResp>(&owner_info_resp);
    assert_eq!(owner_info.device_key_id, KEY_ID_LDEV_ID);
    assert!((owner_info.chain_len as usize) > owner_endorsement.len());

    let owner_chain = read_full_mci_cert_chain(&mut hw, SLOT_OWNER, ALGO_ECC384, 400)?;
    assert_eq!(owner_chain.len(), owner_info.chain_len as usize);
    assert!(owner_chain.starts_with(&owner_endorsement));
    let owner_digest: [u8; 48] = Sha384::digest(&owner_chain).into();
    assert_eq!(owner_info.chain_digest, owner_digest);

    // After the endorsement prefix, an LDevID-anchored chain has 3 X.509 DER certs:
    // FMC Alias, RT Alias, and DPE Leaf.
    let mut rem = &owner_chain[owner_endorsement.len()..];
    let mut dpe_cert_count = 0usize;
    while !rem.is_empty() {
        let (rest, _) =
            x509_parser::parse_x509_certificate(rem).expect("invalid appended DPE certificate DER");
        rem = rest;
        dpe_cert_count += 1;
    }
    assert_eq!(dpe_cert_count, 3);

    let owner_nonce = [0x51u8; 32];
    let owner_att = execute_var_mcu_req(
        &mut hw,
        McuMailboxReq::GetAttestation(GetAttestationReq {
            evidence_format: FORMAT_OCP_EAT,
            algorithm: ALGO_ECC384,
            pki_entity_slot: SLOT_OWNER,
            nonce: owner_nonce,
            ..Default::default()
        }),
    )?;
    assert_signed_eat(
        &owner_att[GET_ATTESTATION_RESP_PREFIX_LEN..],
        &owner_nonce,
        &[-51],
        false,
    );

    // 4. Tenant slot policy: device_key_id == 0 and unsupported key IDs (e.g. FmcAlias == 2) are rejected.
    let tenant_endorsement = synthetic_der_cert(340, 0x33);
    for bad_key_id in [KEY_ID_DEFAULT, KEY_ID_FMC_ALIAS, 99] {
        let mut bad_req = SetCertChainReq {
            pki_entity_slot: SLOT_TENANT,
            algorithm: ALGO_ECC384,
            device_key_id: bad_key_id,
            offset: 0,
            total_size: tenant_endorsement.len() as u32,
            data_len: tenant_endorsement.len() as u32,
            ..Default::default()
        };
        bad_req.cert_data[..tenant_endorsement.len()].copy_from_slice(&tenant_endorsement);
        assert_mcu_req_fails(&mut hw, McuMailboxReq::SetCertChain(bad_req));
    }

    // Provision Tenant using variable-length request framing (`SetCertChainReq::HEADER_SIZE + data_len`).
    let mut tenant_req = SetCertChainReq {
        pki_entity_slot: SLOT_TENANT,
        algorithm: ALGO_ECC384,
        device_key_id: KEY_ID_LDEV_ID,
        offset: 0,
        total_size: tenant_endorsement.len() as u32,
        data_len: tenant_endorsement.len() as u32,
        ..Default::default()
    };
    tenant_req.cert_data[..tenant_endorsement.len()].copy_from_slice(&tenant_endorsement);
    let set_cmd = McuCommandId::MC_SET_CERT_CHAIN.0;
    let var_len = SetCertChainReq::HEADER_SIZE + tenant_endorsement.len();
    let var_payload = &tenant_req.as_bytes()[4..var_len];
    let tenant_set_resp = hw
        .mailbox_execute(set_cmd, &raw_request(set_cmd, var_payload))?
        .expect("MC_SET_CERT_CHAIN returned no response");
    assert_eq!(
        assert_fixed_response::<SetCertChainResp>(&tenant_set_resp)
            .hdr
            .fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    let tenant_info_resp = execute_raw_mcu_req(
        &mut hw,
        McuMailboxReq::GetCertChainInfo(GetCertChainInfoReq {
            pki_entity_slot: SLOT_TENANT,
            algorithm: ALGO_ECC384,
            ..Default::default()
        }),
    )?;
    let tenant_info = assert_fixed_response::<GetCertChainInfoResp>(&tenant_info_resp);
    assert_eq!(tenant_info.device_key_id, KEY_ID_LDEV_ID);
    let tenant_chain = read_full_mci_cert_chain(&mut hw, SLOT_TENANT, ALGO_ECC384, 1024)?;
    assert_eq!(tenant_chain.len(), tenant_info.chain_len as usize);
    assert!(tenant_chain.starts_with(&tenant_endorsement));
    let tenant_digest: [u8; 48] = Sha384::digest(&tenant_chain).into();
    assert_eq!(tenant_info.chain_digest, tenant_digest);

    let tenant_nonce = [0x62u8; 32];
    let tenant_att = execute_var_mcu_req(
        &mut hw,
        McuMailboxReq::GetAttestation(GetAttestationReq {
            evidence_format: FORMAT_OCP_EAT,
            algorithm: ALGO_ECC384,
            pki_entity_slot: SLOT_TENANT,
            nonce: tenant_nonce,
            ..Default::default()
        }),
    )?;
    assert_signed_eat(
        &tenant_att[GET_ATTESTATION_RESP_PREFIX_LEN..],
        &tenant_nonce,
        &[-51],
        false,
    );

    // 5. Erase Tenant slot (`offset == 0 && total_size == 0 && data_len == 0`) and verify it is unprovisioned again.
    let erase_resp = execute_raw_mcu_req(
        &mut hw,
        McuMailboxReq::SetCertChain(SetCertChainReq {
            pki_entity_slot: SLOT_TENANT,
            algorithm: ALGO_ECC384,
            device_key_id: KEY_ID_LDEV_ID,
            offset: 0,
            total_size: 0,
            data_len: 0,
            ..Default::default()
        }),
    )?;
    assert_eq!(
        assert_fixed_response::<SetCertChainResp>(&erase_resp)
            .hdr
            .fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert_mcu_req_fails(
        &mut hw,
        McuMailboxReq::GetCertChainInfo(GetCertChainInfoReq {
            pki_entity_slot: SLOT_TENANT,
            algorithm: ALGO_ECC384,
            ..Default::default()
        }),
    );

    // 6. Negative boundary checks for GetCertChainInfo, GetCertChain, and SetCertChain.
    for req in [
        McuMailboxReq::GetCertChainInfo(GetCertChainInfoReq {
            pki_entity_slot: u32::MAX,
            algorithm: ALGO_ECC384,
            ..Default::default()
        }),
        McuMailboxReq::GetCertChainInfo(GetCertChainInfoReq {
            pki_entity_slot: SLOT_VENDOR,
            algorithm: u32::MAX,
            ..Default::default()
        }),
        McuMailboxReq::GetCertChain(GetCertChainReq {
            pki_entity_slot: SLOT_VENDOR,
            algorithm: ALGO_ECC384,
            offset: 0,
            length: 0,
            ..Default::default()
        }),
        McuMailboxReq::GetCertChain(GetCertChainReq {
            pki_entity_slot: SLOT_VENDOR,
            algorithm: ALGO_ECC384,
            offset: 0,
            length: MAX_RESP_DATA_SIZE as u32 + 1,
            ..Default::default()
        }),
        McuMailboxReq::GetCertChain(GetCertChainReq {
            pki_entity_slot: SLOT_VENDOR,
            algorithm: ALGO_ECC384,
            offset: u32::MAX,
            length: 64,
            ..Default::default()
        }),
        McuMailboxReq::SetCertChain(SetCertChainReq {
            pki_entity_slot: SLOT_OWNER,
            algorithm: ALGO_ECC384,
            device_key_id: KEY_ID_LDEV_ID,
            offset: 16,
            total_size: 32,
            data_len: 16,
            ..Default::default()
        }),
    ] {
        assert_mcu_req_fails(&mut hw, req);
    }

    Ok(())
}

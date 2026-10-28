// Licensed under the Apache-2.0 license

use anyhow::Result;
use caliptra_api::{
    calc_checksum,
    mailbox::{CapabilitiesResp, CommandId},
    SocManager,
};
use caliptra_image_types::MLDSA87_SIGNATURE_BYTE_SIZE;
use caliptra_mcu_hw_model::{DefaultHwModel, McuHwModel};
use caliptra_mcu_mbox_common::messages::{
    CmEcdhFinishReq, CmEcdhGenerateReq, CmEcdsaPublicKeyReq, CmEcdsaSignReq, CmEcdsaVerifyReq,
    CmImportReq, CmKeyUsage, CmMldsaPublicKeyReq, CmMldsaSignReq, CmMldsaVerifyReq, Cmk,
    CommandId as McuCommandId, EcdsaVerifyReq, FirmwareVersionReq, GetAuthCmdChallengeResp,
    HekStatusResp, LmsVerifyReq, MailboxReqHeader as McuMailboxReqHeader, MailboxRespHeader,
    MailboxRespHeaderVarSize, McuCmImportReq, McuEcdhFinishReq, McuEcdhFinishResp,
    McuEcdhGenerateReq, McuEcdhGenerateResp, McuEcdsa384SigVerifyReq, McuEcdsaCmkPublicKeyReq,
    McuEcdsaCmkPublicKeyResp, McuEcdsaCmkSignReq, McuEcdsaCmkSignResp, McuEcdsaCmkVerifyReq,
    McuFeStatusResp, McuFipsSelfTestGetResultsResp, McuFipsSelfTestStartResp, McuLmsSigVerifyReq,
    McuMailboxReq, McuMldsaCmkPublicKeyReq, McuMldsaCmkPublicKeyResp, McuMldsaCmkSignReq,
    McuMldsaCmkSignResp, McuMldsaCmkVerifyReq, VendorPkHashStatusResp,
};
use std::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Wire contracts extracted from the selected runtime's messages, dispatcher and
/// common-command implementation, not inferred from its release label.
#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SelectedMailboxAbi {
    /// 36 capability bytes; MACC is direct with flags/reserved in its request.
    Legacy36Direct,
    /// 64 capability bytes; MACC is a target inside authorized command 0x12.
    Capabilities64Envelope,
}

#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SelectedCryptoAbi {
    /// The selected dispatcher preserves the imported Core request/response
    /// layouts and translates IDs only; the booted Core is the fixed fixture.
    FixedCoreE5d1f27,
}

/// The compatibility caller verifies source/artifact provenance before supplying
/// this contract and boots the exact selected images before invoking the checks.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SelectedMailboxExpectations {
    pub runtime_version: String,
    /// Exact bytes after the 16 Core capability bytes, including reserved bytes.
    pub mcu_capabilities: Vec<u8>,
    pub abi: SelectedMailboxAbi,
    pub crypto_abi: SelectedCryptoAbi,
    /// Symbol names and numeric IDs extracted from the selected messages.rs.
    pub command_ids: std::collections::BTreeMap<String, u32>,
    pub provisioning_status: SelectedProvisioningStatusSupport,
}

/// Missing/unknown support is a prerequisite error, never an implicit exclusion.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SelectedProvisioningStatusSupport {
    UnavailableInSource,
    Supported(SelectedProvisioningStatus),
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SelectedProvisioningStatus {
    pub field_entropy_provisioned: u32,
    pub vendor_used_slots: u32,
    pub vendor_key_types: [u8; 16],
    pub hek: SelectedHekStatusExpectation,
}

#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SelectedHekStatusExpectation {
    /// The command exists, but OTP_GET_HEK_METADATA requires the OCP-lock kernel
    /// context and ROM handoff that the agreed images do not enable.
    UnavailableInConfiguration,
    Supported {
        used_slots: u32,
        total_slots: u32,
    },
}

impl SelectedMailboxExpectations {
    fn require_commands(&self, commands: &[(&str, McuCommandId)]) -> Result<()> {
        for (name, command) in commands {
            anyhow::ensure!(
                self.command_ids.get(*name) == Some(&command.0),
                "selected source does not establish {name} wire ID {:#x}",
                command.0
            );
        }
        Ok(())
    }

    fn validate_capabilities(&self) -> Result<()> {
        let expected_len = match self.abi {
            SelectedMailboxAbi::Legacy36Direct => 36 - 16,
            SelectedMailboxAbi::Capabilities64Envelope => 64 - 16,
        };
        anyhow::ensure!(
            self.mcu_capabilities.len() == expected_len,
            "selected capability layout does not match the source-derived mailbox ABI"
        );
        Ok(())
    }
}

/// Production mailbox checks, without compiling firmware or selecting a model.
///
/// Required source evidence: common/mcu-mbox/src/messages.rs IDs and response
/// layouts; mcu-mbox-lib/src/cmd_interface.rs passthrough/feature dispatch;
/// caliptra_cmd_handler capabilities/version implementations; selected Core's
/// mailbox layouts matching the fixed e5d1f27 Core fixture. Periodic FIPS and
/// disable-lms-sig-verify must be off in the agreed runtime configuration.
/// Self-test start/results are *ungated* Core passthrough commands in all three
/// selected sources; their test-feature wrapper is not a production prerequisite.
#[cfg(not(feature = "fpga_realtime"))]
pub(crate) fn run_selected_mailbox_checks(
    hw: &mut DefaultHwModel,
    expected: &SelectedMailboxExpectations,
) -> Result<()> {
    expected.validate_capabilities()?;
    let SelectedCryptoAbi::FixedCoreE5d1f27 = expected.crypto_abi;
    expected.require_commands(&[
        ("MC_FIRMWARE_VERSION", McuCommandId::MC_FIRMWARE_VERSION),
        (
            "MC_DEVICE_CAPABILITIES",
            McuCommandId::MC_DEVICE_CAPABILITIES,
        ),
        (
            "MC_FIPS_SELF_TEST_START",
            McuCommandId::MC_FIPS_SELF_TEST_START,
        ),
        (
            "MC_FIPS_SELF_TEST_GET_RESULTS",
            McuCommandId::MC_FIPS_SELF_TEST_GET_RESULTS,
        ),
        (
            "MC_FIPS_PERIODIC_STATUS",
            McuCommandId::MC_FIPS_PERIODIC_STATUS,
        ),
        ("MC_IMPORT", McuCommandId::MC_IMPORT),
        ("MC_ECDH_GENERATE", McuCommandId::MC_ECDH_GENERATE),
        ("MC_ECDH_FINISH", McuCommandId::MC_ECDH_FINISH),
        (
            "MC_ECDSA_CMK_PUBLIC_KEY",
            McuCommandId::MC_ECDSA_CMK_PUBLIC_KEY,
        ),
        ("MC_ECDSA_CMK_SIGN", McuCommandId::MC_ECDSA_CMK_SIGN),
        ("MC_ECDSA_CMK_VERIFY", McuCommandId::MC_ECDSA_CMK_VERIFY),
        (
            "MC_MLDSA_CMK_PUBLIC_KEY",
            McuCommandId::MC_MLDSA_CMK_PUBLIC_KEY,
        ),
        ("MC_MLDSA_CMK_SIGN", McuCommandId::MC_MLDSA_CMK_SIGN),
        ("MC_MLDSA_CMK_VERIFY", McuCommandId::MC_MLDSA_CMK_VERIFY),
        (
            "MC_ECDSA384_SIG_VERIFY",
            McuCommandId::MC_ECDSA384_SIG_VERIFY,
        ),
        ("MC_LMS_SIG_VERIFY", McuCommandId::MC_LMS_SIG_VERIFY),
    ])?;

    // Keep malformed requests distinct from unsupported-command success checks.
    assert_mailbox_cmd_failed(hw.mailbox_execute(0, &[0xaa; 8]));
    assert_mailbox_cmd_failed(hw.mailbox_execute(0, &raw_request(0, &[])));
    let version_cmd = McuCommandId::MC_FIRMWARE_VERSION.0;
    assert_mailbox_cmd_failed(
        hw.mailbox_execute(version_cmd, &[0; size_of::<FirmwareVersionReq>()]),
    );
    assert_mailbox_cmd_failed(
        hw.mailbox_execute(version_cmd, &[0; size_of::<McuMailboxReqHeader>() - 1]),
    );

    let core_version = hw
        .caliptra_soc_manager()
        .soc_ifc()
        .cptra_fw_rev_id()
        .at(1)
        .read();
    let versions = [
        semantic_version(core_version),
        expected.runtime_version.clone(),
    ];
    for (index, version) in versions.iter().enumerate() {
        let response = hw
            .mailbox_execute(
                version_cmd,
                &raw_request(version_cmd, &(index as u32).to_le_bytes()),
            )?
            .expect("MC_FIRMWARE_VERSION returned no response");
        assert_response_checksum(&response);
        let (header, body) = MailboxRespHeaderVarSize::ref_from_prefix(&response)
            .expect("invalid firmware-version response");
        assert_eq!(
            header.hdr.fips_status,
            MailboxRespHeader::FIPS_STATUS_APPROVED
        );
        assert_eq!(header.data_len as usize, version.len());
        assert_eq!(body, version.as_bytes());
    }
    for index in [2u32, 99] {
        assert_mailbox_cmd_failed(
            hw.mailbox_execute(version_cmd, &raw_request(version_cmd, &index.to_le_bytes())),
        );
    }

    let core_cmd = CommandId::CAPABILITIES.into();
    let core_response = hw
        .caliptra_mailbox_execute(core_cmd, &raw_request(core_cmd, &[]))?
        .expect("Core CAPABILITIES returned no response");
    let core_caps = assert_fixed_response::<CapabilitiesResp>(&core_response);
    assert_eq!(
        core_caps.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    let caps_cmd = McuCommandId::MC_DEVICE_CAPABILITIES.0;
    let response = hw
        .mailbox_execute(caps_cmd, &raw_request(caps_cmd, &[]))?
        .expect("MC_DEVICE_CAPABILITIES returned no response");
    assert_response_checksum(&response);
    let (header, capabilities) =
        MailboxRespHeader::ref_from_prefix(&response).expect("invalid capabilities response");
    assert_eq!(header.fips_status, MailboxRespHeader::FIPS_STATUS_APPROVED);
    assert_eq!(capabilities.len(), 16 + expected.mcu_capabilities.len());
    assert_eq!(&capabilities[..16], &core_caps.capabilities);
    assert_eq!(&capabilities[16..], expected.mcu_capabilities);

    let periodic_cmd = McuCommandId::MC_FIPS_PERIODIC_STATUS.0;
    assert_mailbox_cmd_failed(hw.mailbox_execute(periodic_cmd, &raw_request(periodic_cmd, &[])));
    run_fips_self_test_checks(hw)?;
    run_ecdh_checks(hw)?;
    run_ecdsa_cmk_checks(hw)?;
    run_mldsa_cmk_checks(hw)?;
    run_ecdsa384_verify_checks(hw)?;
    run_lms_verify_checks(hw)?;
    Ok(())
}

/// Non-mutating provisioning protocol checks for the agreed zero-owner/Raw OTP.
/// This preserves nonce freshness, checksum/FIPS/layout and malformed-envelope
/// checks; it does not claim successful authenticated fuse programming. The
/// existing positive FE_PROG test requires a different Production lifecycle.
pub(crate) fn run_selected_provisioning_checks(
    hw: &mut DefaultHwModel,
    expected: &SelectedMailboxExpectations,
) -> Result<()> {
    let status_commands = [
        ("MC_FE_STATUS", McuCommandId::MC_FE_STATUS),
        (
            "MC_VENDOR_PK_HASH_STATUS",
            McuCommandId::MC_VENDOR_PK_HASH_STATUS,
        ),
        ("MC_HEK_STATUS", McuCommandId::MC_HEK_STATUS),
    ];
    match &expected.provisioning_status {
        SelectedProvisioningStatusSupport::Supported(status) => {
            expected.require_commands(&status_commands)?;
            run_selected_provisioning_status_checks(hw, status)?;
        }
        SelectedProvisioningStatusSupport::UnavailableInSource => {
            anyhow::ensure!(
                status_commands
                    .iter()
                    .all(|(name, _)| !expected.command_ids.contains_key(*name)),
                "provisioning status exclusion contradicts selected command IDs"
            );
        }
    }
    expected.require_commands(&[(
        "MC_GET_AUTH_CMD_CHALLENGE",
        McuCommandId::MC_GET_AUTH_CMD_CHALLENGE,
    )])?;
    let challenge_cmd = McuCommandId::MC_GET_AUTH_CMD_CHALLENGE.0;
    let (command, payload) = match expected.abi {
        SelectedMailboxAbi::Legacy36Direct => (challenge_cmd, vec![0; 8]),
        SelectedMailboxAbi::Capabilities64Envelope => {
            expected.require_commands(&[(
                "MC_AUTHORIZED_COMMAND",
                McuCommandId::MC_AUTHORIZED_COMMAND,
            )])?;
            let command = McuCommandId::MC_AUTHORIZED_COMMAND.0;
            // Legacy direct authorization is not accepted by the envelope ABI.
            assert_mailbox_cmd_failed(
                hw.mailbox_execute(challenge_cmd, &raw_request(challenge_cmd, &[0; 8])),
            );
            for invalid in [vec![1, 0, 0, 0], vec![0, 0, 0, 0, 1, 0, 0, 0]] {
                let mut payload = challenge_cmd.to_le_bytes().to_vec();
                payload.extend_from_slice(&invalid);
                assert_mailbox_cmd_failed(
                    hw.mailbox_execute(command, &raw_request(command, &payload)),
                );
            }
            (command, challenge_cmd.to_le_bytes().to_vec())
        }
    };
    let mut previous = None;
    for _ in 0..2 {
        let response = hw
            .mailbox_execute(command, &raw_request(command, &payload))?
            .expect("MC_GET_AUTH_CMD_CHALLENGE returned no response");
        // Both ABIs encode 8-byte status, a zero reserved word, and 48-byte nonce.
        // The envelope's zero word is not a variable-response data length.
        let challenge = assert_fixed_response::<GetAuthCmdChallengeResp>(&response);
        assert_eq!(
            challenge.hdr.fips_status,
            MailboxRespHeader::FIPS_STATUS_APPROVED
        );
        assert_eq!(challenge.reserved, 0);
        assert!(challenge.challenge.iter().any(|&byte| byte != 0));
        if let Some(previous) = previous {
            assert_ne!(challenge.challenge, previous);
        }
        previous = Some(challenge.challenge);
    }
    Ok(())
}

fn run_selected_provisioning_status_checks(
    hw: &mut DefaultHwModel,
    expected: &SelectedProvisioningStatus,
) -> Result<()> {
    let fe_cmd = McuCommandId::MC_FE_STATUS.0;
    let response = hw
        .mailbox_execute(fe_cmd, &raw_request(fe_cmd, &[]))?
        .expect("MC_FE_STATUS returned no response");
    let status = assert_fixed_response::<McuFeStatusResp>(&response);
    assert_eq!(
        status.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert_eq!(
        status.already_provisioned,
        expected.field_entropy_provisioned
    );

    let vendor_cmd = McuCommandId::MC_VENDOR_PK_HASH_STATUS.0;
    let response = hw
        .mailbox_execute(vendor_cmd, &raw_request(vendor_cmd, &[]))?
        .expect("MC_VENDOR_PK_HASH_STATUS returned no response");
    let status = assert_fixed_response::<VendorPkHashStatusResp>(&response);
    assert_eq!(
        status.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert_eq!(status.used_slots_bitmap, expected.vendor_used_slots);
    assert_eq!(status.key_types, expected.vendor_key_types);

    let hek_cmd = McuCommandId::MC_HEK_STATUS.0;
    let response = hw.mailbox_execute(hek_cmd, &raw_request(hek_cmd, &[]));
    match expected.hek {
        SelectedHekStatusExpectation::UnavailableInConfiguration => {
            assert_mailbox_cmd_failed(response);
        }
        SelectedHekStatusExpectation::Supported {
            used_slots,
            total_slots,
        } => {
            let response = response?.expect("MC_HEK_STATUS returned no response");
            let status = assert_fixed_response::<HekStatusResp>(&response);
            assert_eq!(
                status.hdr.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED
            );
            assert_eq!(status.used_slots_bitmap, used_slots);
            assert_eq!(status.total_slots, total_slots);
        }
    }

    for command in [fe_cmd, vendor_cmd, hek_cmd] {
        assert_mailbox_cmd_failed(hw.mailbox_execute(command, &[0; 3]));
        assert_mailbox_cmd_failed(hw.mailbox_execute(
            command,
            &raw_request(command, &0x1234_5678u32.to_le_bytes()),
        ));
        assert_mailbox_cmd_failed(hw.mailbox_execute(command, &[0; 4]));
    }
    Ok(())
}

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

fn run_fips_self_test_checks(hw: &mut impl McuHwModel) -> Result<()> {
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

fn run_ecdh_checks(hw: &mut impl McuHwModel) -> Result<()> {
    let generate_response = execute_raw_mcu_req(
        hw,
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
        hw,
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

fn run_ecdsa_cmk_checks(hw: &mut impl McuHwModel) -> Result<()> {
    let cmk = import_cmk(hw, CmKeyUsage::Ecdsa, &[0; 48])?;
    let public_key_response = execute_raw_mcu_req(
        hw,
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
        hw,
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
        hw,
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
        hw,
        McuMailboxReq::EcdsaCmkVerify(ecdsa_verify_req(
            cmk,
            message,
            invalid_signature,
            signature.0.signature_s,
        )),
    );

    let aes_cmk = import_cmk(hw, CmKeyUsage::Aes, &[0xa5; 32])?;
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
            assert_mcu_req_fails(hw, request);
        }
    }
    Ok(())
}

fn run_mldsa_cmk_checks(hw: &mut impl McuHwModel) -> Result<()> {
    let cmk = import_cmk(hw, CmKeyUsage::Mldsa, &[0x5a; 32])?;
    let public_key_response = execute_raw_mcu_req(
        hw,
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
        hw,
        McuMailboxReq::MldsaCmkSign(McuMldsaCmkSignReq(sign_request)),
    )?;
    let signature = assert_fixed_response::<McuMldsaCmkSignResp>(&sign_response);
    assert_eq!(
        signature.0.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert!(signature.0.signature.iter().any(|byte| *byte != 0));

    let verify_response = execute_raw_mcu_req(
        hw,
        McuMailboxReq::MldsaCmkVerify(mldsa_verify_req(cmk, message, signature.0.signature)),
    )?;
    assert_eq!(
        assert_fixed_response::<MailboxRespHeader>(&verify_response).fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    let mut invalid_signature = signature.0.signature;
    invalid_signature[0] ^= 1;
    assert_mcu_req_fails(
        hw,
        McuMailboxReq::MldsaCmkVerify(mldsa_verify_req(cmk, message, invalid_signature)),
    );

    let aes_cmk = import_cmk(hw, CmKeyUsage::Aes, &[0xa5; 32])?;
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
            assert_mcu_req_fails(hw, request);
        }
    }
    Ok(())
}

fn run_ecdsa384_verify_checks(hw: &mut impl McuHwModel) -> Result<()> {
    use caliptra_image_crypto::RustCrypto;
    use caliptra_image_fake_keys::{
        VENDOR_ECC_KEY_0_PRIVATE, VENDOR_ECC_KEY_0_PUBLIC, VENDOR_ECC_KEY_1_PUBLIC,
    };
    use caliptra_image_gen::{from_hw_format, to_hw_format, ImageGeneratorCrypto};

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

fn run_lms_verify_checks(hw: &mut impl McuHwModel) -> Result<()> {
    use caliptra_image_crypto::RustCrypto;
    use caliptra_image_fake_keys::{
        VENDOR_LMS_KEY_0_PRIVATE, VENDOR_LMS_KEY_0_PUBLIC, VENDOR_LMS_KEY_1_PUBLIC,
    };
    use caliptra_image_gen::{to_hw_format, ImageGeneratorCrypto};

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

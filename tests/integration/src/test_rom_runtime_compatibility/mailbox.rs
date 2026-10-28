// Licensed under the Apache-2.0 license

use anyhow::Result;
use caliptra_api::{
    calc_checksum,
    mailbox::{CapabilitiesResp, CommandId},
    SocManager,
};
use caliptra_mcu_hw_model::{DefaultHwModel, McuHwModel};
use caliptra_mcu_mbox_common::messages::{
    CommandId as McuCommandId, FirmwareVersionReq, GetAuthCmdChallengeResp, HekStatusResp,
    MailboxReqHeader as McuMailboxReqHeader, MailboxRespHeader, MailboxRespHeaderVarSize,
    McuFeStatusResp, VendorPkHashStatusResp,
};
use std::mem::size_of;
use zerocopy::{FromBytes, Immutable, KnownLayout};

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

/// The compatibility caller verifies source/artifact provenance before supplying
/// this contract and boots the exact selected images before invoking the checks.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SelectedMailboxExpectations {
    pub runtime_version: String,
    /// Exact bytes after the 16 Core capability bytes, including reserved bytes.
    pub mcu_capabilities: Vec<u8>,
    pub abi: SelectedMailboxAbi,
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

/// Release-specific version/capability checks. Crypto regressions remain in
/// the existing mailbox suite rather than being duplicated for every pair.
pub(crate) fn run_selected_mailbox_checks(
    hw: &mut DefaultHwModel,
    expected: &SelectedMailboxExpectations,
) -> Result<()> {
    expected.validate_capabilities()?;
    expected.require_commands(&[
        ("MC_FIRMWARE_VERSION", McuCommandId::MC_FIRMWARE_VERSION),
        (
            "MC_DEVICE_CAPABILITIES",
            McuCommandId::MC_DEVICE_CAPABILITIES,
        ),
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

fn assert_fixed_response<T: FromBytes + Immutable + KnownLayout>(response: &[u8]) -> &T {
    assert_eq!(response.len(), size_of::<T>());
    assert_response_checksum(response);
    T::ref_from_bytes(response).expect("invalid fixed-size response")
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

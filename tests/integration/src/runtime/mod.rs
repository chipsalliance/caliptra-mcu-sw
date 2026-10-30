// Licensed under the Apache-2.0 license

use crate::test_caliptra_util_host_mcu_mailbox_validator::test::{
    TEST_ECC_PRIV_KEY, TEST_MLDSA_SEED,
};
use anyhow::{anyhow, bail, Result};
use caliptra_mcu_command_auth_challenge_signer::{
    AsymmetricCommandAuthorizer, CommandAuthChallengeSigner,
};
use caliptra_mcu_config::capabilities::{
    AuthorizedSubcommandCapabilities, ExternalCommandCapabilities, McuRuntimeCapabilities,
};
use caliptra_mcu_hw_model::{DefaultHwModel, McuHwModel};
use caliptra_mcu_mbox_common::authorization::AuthorizationMetadata;
use caliptra_mcu_mbox_common::messages::{
    calc_checksum, CommandId, DeviceCapsResp, GetAuthCmdChallengeResp, MailboxReqHeader,
    MailboxRespHeader, McuMailboxResp, AUTH_CMD_NONCE_LEN, DEVICE_CAPS_SIZE,
};
use caliptra_mcu_romtime::handoff::McuRomCapabilities;
use core::mem::size_of;
use zerocopy::{FromBytes, IntoBytes};

mod test_fuse_mailbox;
mod test_increase_caliptra_svn;
mod test_mcu_mailbox;
mod test_ocp_lock;
mod test_revoke_vendor_pub_key;

/// Golden response for `test-mcu-mbox-cmds`, shared by emulator and FPGA tests.
pub(crate) fn expected_mcu_mailbox_capabilities(core_capabilities: [u8; 16]) -> McuMailboxResp {
    let mut caps = [0; DEVICE_CAPS_SIZE];
    caps[..16].copy_from_slice(&core_capabilities);
    caps[16..20].copy_from_slice(
        &(McuRomCapabilities::STREAMING_BOOT_I3C
            | McuRomCapabilities::FLASH_BOOT
            | McuRomCapabilities::DOT_BOOT)
            .bits()
            .to_be_bytes(),
    );
    caps[20..24].copy_from_slice(
        &McuRuntimeCapabilities::MCI_MAILBOX_SERVICE
            .bits()
            .to_be_bytes(),
    );
    caps[24..28].copy_from_slice(
        &(ExternalCommandCapabilities::GET_ATTESTATION
            | ExternalCommandCapabilities::EXPORT_ATTESTED_CSR
            | ExternalCommandCapabilities::AUTHORIZED_COMMAND
            | ExternalCommandCapabilities::DEVICE_OWNERSHIP_TRANSFER)
            .bits()
            .to_be_bytes(),
    );
    caps[28..32].copy_from_slice(
        &(AuthorizedSubcommandCapabilities::GET_AUTH_CHALLENGE
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
            .to_be_bytes(),
    );
    let mut response = McuMailboxResp::DeviceCaps(DeviceCapsResp {
        hdr: MailboxRespHeader::default(),
        caps,
    });
    response
        .populate_chksum()
        .expect("valid device capabilities response");
    response
}

pub(crate) fn start_command_authorized_runtime(
    params: crate::test::TestParams<'_>,
) -> DefaultHwModel {
    #[cfg(not(feature = "fpga_realtime"))]
    let params = {
        let mut params = params;
        params.caliptra_soc_axi_user.get_or_insert(1);
        params
    };
    let pqc = params
        .vendor_pqc_type
        .unwrap_or(caliptra_image_types::FwVerificationPqcKeyType::LMS);
    let mut hw = crate::test::start_runtime_hw_model(params);
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(caliptra_mcu_romtime::McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });
    install_test_owner_auth_manifest(&mut hw, pqc, 0)
        .expect("failed to provision the command-authorization test manifest");
    hw
}

pub(crate) fn core_request(
    hw: &mut impl McuHwModel,
    command: caliptra_api::mailbox::CommandId,
    request: &[u8],
) -> Result<Vec<u8>> {
    let command = u32::from(command);
    for _ in 0..10 {
        match hw.caliptra_mailbox_execute(command, request) {
            Ok(Some(response)) => return Ok(response),
            Ok(None) => bail!("Core command {command:#010x} did not return a response"),
            Err(caliptra_hw_model::ModelError::UnableToLockMailbox) => {
                for _ in 0..1_000_000 {
                    hw.step();
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    bail!("Core mailbox remained busy for {command:#010x}")
}

pub(crate) fn install_test_owner_auth_manifest(
    hw: &mut impl McuHwModel,
    pqc: caliptra_image_types::FwVerificationPqcKeyType,
    svn: u32,
) -> Result<()> {
    use caliptra_api::mailbox::{
        CommandId as CoreCommandId, MailboxReqHeader as CoreReqHeader, SetOwnerAuthManifestReq,
    };
    use caliptra_mcu_builder::{CaliptraBuildArgs, CaliptraBuilder};

    let directory = tempfile::tempdir()?;
    let signer = AsymmetricCommandAuthorizer::new(&TEST_ECC_PRIV_KEY, &TEST_MLDSA_SEED)?;
    let mut builder = CaliptraBuilder::new(&CaliptraBuildArgs {
        owner_manifest_svn: Some(svn),
        pqc_key_type: Some(pqc),
        target_dir: Some(directory.path().to_path_buf()),
        ..Default::default()
    })
    .with_command_auth_key_digests(None, Some(signer.anchor()?))?;
    let manifest = std::fs::read(builder.get_owner_auth_manifest(None)?)?;
    let mut request = SetOwnerAuthManifestReq {
        manifest_size: u32::try_from(manifest.len())?,
        ..Default::default()
    };
    request
        .manifest
        .get_mut(..manifest.len())
        .ok_or_else(|| anyhow!("Owner SoC Manifest exceeds mailbox capacity"))?
        .copy_from_slice(&manifest);
    let request = request
        .as_bytes_partial_mut()
        .map_err(|error| anyhow!("Invalid Owner SoC Manifest request size: {error:?}"))?;
    let checksum = calc_checksum(
        CoreCommandId::SET_OWNER_AUTH_MANIFEST.into(),
        &request[size_of::<CoreReqHeader>()..],
    );
    request[..size_of::<CoreReqHeader>()].copy_from_slice(&checksum.to_le_bytes());
    core_request(hw, CoreCommandId::SET_OWNER_AUTH_MANIFEST, request)?;
    Ok(())
}

pub fn get_auth_cmd_challenge(hw: &mut impl McuHwModel) -> Result<[u8; AUTH_CMD_NONCE_LEN]> {
    let mut request = vec![0u8; size_of::<MailboxReqHeader>()];
    request.extend_from_slice(&CommandId::MC_GET_AUTH_CMD_CHALLENGE.0.to_le_bytes());
    let checksum = calc_checksum(
        CommandId::MC_AUTHORIZED_COMMAND.0,
        &request[size_of::<MailboxReqHeader>()..],
    );
    request[..size_of::<MailboxReqHeader>()].copy_from_slice(&checksum.to_le_bytes());
    let response = hw
        .mailbox_execute(CommandId::MC_AUTHORIZED_COMMAND.0, &request)?
        .ok_or_else(|| anyhow!("MACC returned no response"))?;
    let resp = GetAuthCmdChallengeResp::read_from_bytes(&response)
        .map_err(|_| anyhow!("MACC returned an invalid response"))?;
    Ok(resp.challenge)
}

pub fn sign_auth_cmd_with_metadata(
    metadata: &AuthorizationMetadata,
    nonce: &[u8; AUTH_CMD_NONCE_LEN],
    cmd_id: u32,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let authorizer = AsymmetricCommandAuthorizer::new(&TEST_ECC_PRIV_KEY, &TEST_MLDSA_SEED)?;
    let sigs = authorizer.authorize_with_metadata(cmd_id, payload, metadata, nonce)?;
    let (ecc_pub_x, ecc_pub_y, mldsa_pub) = authorizer.public_keys()?;

    let mut tail = metadata.as_bytes().to_vec();
    tail.extend_from_slice(nonce);
    tail.extend_from_slice(&ecc_pub_x);
    tail.extend_from_slice(&ecc_pub_y);
    tail.extend_from_slice(&mldsa_pub);
    tail.extend_from_slice(sigs.as_bytes());
    Ok(tail)
}

pub fn authorize_cmd(hw: &mut impl McuHwModel, target: u32, cmd: &[u8]) -> Result<Vec<u8>> {
    let challenge = get_auth_cmd_challenge(hw)?;
    authorize_cmd_with_context(target, cmd, &AuthorizationMetadata::default(), &challenge)
}

pub fn authorize_cmd_with_context(
    target: u32,
    cmd: &[u8],
    metadata: &AuthorizationMetadata,
    nonce: &[u8; AUTH_CMD_NONCE_LEN],
) -> Result<Vec<u8>> {
    let body = cmd
        .get(size_of::<MailboxReqHeader>()..)
        .ok_or_else(|| anyhow!("Authorized request is missing its payload"))?;
    let sigs = sign_auth_cmd_with_metadata(metadata, nonce, target, body)?;
    let mut auth_cmd = vec![0u8; size_of::<MailboxReqHeader>()];
    auth_cmd.extend_from_slice(&target.to_le_bytes());
    auth_cmd.extend_from_slice(body);
    auth_cmd.extend_from_slice(&sigs);
    Ok(auth_cmd)
}

pub fn execute_authorized_req_raw<R: caliptra_mcu_mbox_common::messages::Request>(
    hw: &mut impl McuHwModel,
    mut req: R,
) -> Result<Vec<u8>> {
    let req_bytes = req.as_mut_bytes();

    // Authorize (sign)
    let mut auth_cmd = authorize_cmd(hw, u32::from(R::ID), req_bytes)?;

    // Populate the request checksum over the complete authorized command.
    let checksum = calc_checksum(
        CommandId::MC_AUTHORIZED_COMMAND.0,
        &auth_cmd[size_of::<i32>()..],
    );
    let hdr: &mut MailboxReqHeader =
        MailboxReqHeader::mut_from_bytes(&mut auth_cmd[..size_of::<MailboxReqHeader>()]).unwrap();
    hdr.chksum = checksum;

    // Send the request to the mailbox
    hw.mailbox_execute(CommandId::MC_AUTHORIZED_COMMAND.0, &auth_cmd)?
        .ok_or_else(|| anyhow!("Authorized command returned no response"))
}

pub fn execute_authorized_req<R: caliptra_mcu_mbox_common::messages::Request>(
    hw: &mut impl McuHwModel,
    req: R,
) -> Result<R::Resp> {
    let mut response = execute_authorized_req_raw(hw, req)?;

    // Check the response checksum
    if response.len() < 4 {
        bail!("Response too short to contain checksum");
    }
    let received_chksum = u32::from_le_bytes(response[..4].try_into().unwrap());
    let calculated_chksum = calc_checksum(0, &response[4..]);
    if received_chksum != calculated_chksum {
        bail!(
            "Response checksum mismatch: expected {:08x}, calculated {:08x}",
            received_chksum,
            calculated_chksum
        );
    }

    if response.len() < std::mem::size_of::<R::Resp>() {
        response.resize(std::mem::size_of::<R::Resp>(), 0);
    }
    let response = R::Resp::read_from_bytes(&response).map_err(|_| {
        anyhow!(
            "Failed to read response into struct: expected len {}, response len {}",
            std::mem::size_of::<R::Resp>(),
            response.len()
        )
    })?;
    Ok(response)
}

pub fn execute_authorized_req_tampered<R: caliptra_mcu_mbox_common::messages::Request>(
    hw: &mut impl McuHwModel,
    mut req: R,
    tamper: impl FnOnce(&mut Vec<u8>),
) -> Result<R::Resp> {
    let req_bytes = req.as_mut_bytes();

    let mut auth_cmd = authorize_cmd(hw, u32::from(R::ID), req_bytes)?;
    tamper(&mut auth_cmd);

    let checksum = calc_checksum(
        CommandId::MC_AUTHORIZED_COMMAND.0,
        &auth_cmd[size_of::<i32>()..],
    );
    let hdr: &mut MailboxReqHeader =
        MailboxReqHeader::mut_from_bytes(&mut auth_cmd[..size_of::<MailboxReqHeader>()]).unwrap();
    hdr.chksum = checksum;

    let mut response = hw
        .mailbox_execute(CommandId::MC_AUTHORIZED_COMMAND.0, &auth_cmd)?
        .unwrap_or_default();

    if response.len() < 4 {
        bail!("Response too short to contain checksum");
    }
    let received_chksum = u32::from_le_bytes(response[..4].try_into().unwrap());
    let calculated_chksum = calc_checksum(0, &response[4..]);
    if received_chksum != calculated_chksum {
        bail!(
            "Response checksum mismatch: expected {:08x}, calculated {:08x}",
            received_chksum,
            calculated_chksum
        );
    }

    if response.len() < std::mem::size_of::<R::Resp>() {
        response.resize(std::mem::size_of::<R::Resp>(), 0);
    }
    R::Resp::read_from_bytes(&response).map_err(|_| {
        anyhow!(
            "Failed to read response into struct: expected len {}, response len {}",
            std::mem::size_of::<R::Resp>(),
            response.len()
        )
    })
}

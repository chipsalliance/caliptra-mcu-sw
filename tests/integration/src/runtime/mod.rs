// Licensed under the Apache-2.0 license

use crate::test_caliptra_util_host_mcu_mailbox_validator::test::{
    TEST_ECC_PRIV_KEY, TEST_MLDSA_SEED,
};
use anyhow::{anyhow, bail, Result};
use caliptra_mcu_command_auth_challenge_signer::{
    AsymmetricCommandAuthorizer, CommandAuthChallengeSigner,
};
use caliptra_mcu_hw_model::McuHwModel;
use caliptra_mcu_mbox_common::messages::{calc_checksum, GetAuthCmdChallengeReq, MailboxReqHeader};
use core::mem::size_of;
use zerocopy::{FromBytes, IntoBytes};

mod test_increase_caliptra_svn;
mod test_mcu_mailbox;
mod test_revoke_vendor_pub_key;

pub fn get_auth_cmd_challenge(hw: &mut impl McuHwModel) -> Result<[u8; 32]> {
    let cmd = GetAuthCmdChallengeReq::default();
    let resp = hw.mailbox_execute_req(cmd)?;
    Ok(resp.challenge)
}

pub fn sign_auth_cmd_challenge(challenge: &[u8; 32], cmd_id: u32, cmd: &[u8]) -> Result<Vec<u8>> {
    let authorizer = AsymmetricCommandAuthorizer::new(&TEST_ECC_PRIV_KEY, &TEST_MLDSA_SEED)?;
    let cmd_body = &cmd[size_of::<MailboxReqHeader>()..];
    let sigs = authorizer.authorize(cmd_id, cmd_body, challenge)?;
    Ok(sigs.as_bytes().to_vec())
}

pub fn authorize_cmd(hw: &mut impl McuHwModel, cmd_id: u32, cmd: &[u8]) -> Result<Vec<u8>> {
    let challenge = get_auth_cmd_challenge(hw)?;
    let sigs = sign_auth_cmd_challenge(&challenge, cmd_id, cmd)?;
    let mut auth_cmd = cmd.to_vec();
    auth_cmd.extend_from_slice(&sigs);
    Ok(auth_cmd)
}

pub fn execute_authorized_req<R: caliptra_mcu_mbox_common::messages::Request>(
    hw: &mut impl McuHwModel,
    mut req: R,
) -> Result<R::Resp> {
    let req_bytes = req.as_mut_bytes();

    // Authorize (sign)
    let mut auth_cmd = authorize_cmd(hw, u32::from(R::ID), req_bytes)?;

    // Populate the request checksum over body + MAC
    let checksum = calc_checksum(R::ID.into(), &auth_cmd[size_of::<i32>()..]);
    let hdr: &mut MailboxReqHeader =
        MailboxReqHeader::mut_from_bytes(&mut auth_cmd[..size_of::<MailboxReqHeader>()]).unwrap();
    hdr.chksum = checksum;

    // Send the request to the mailbox
    let mut response = hw
        .mailbox_execute(R::ID.into(), &auth_cmd)?
        .unwrap_or_default();

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

// Licensed under the Apache-2.0 license

use anyhow::{anyhow, bail, Result};
use caliptra_api::calc_checksum;
use caliptra_api::mailbox::MailboxReqHeader;
use caliptra_mcu_command_auth_challenge_signer::{VendorAuthSigner, VENDOR_AUTH_NONCE_SIZE};
use caliptra_mcu_hw_model::McuHwModel;
use caliptra_mcu_mbox_common::messages::{GetAuthCmdChallengeReq, VendorAuthHelloReq};
use core::mem::size_of;
use hmac::{Hmac, Mac};
use sha2::Sha384;
use zerocopy::FromBytes;

mod test_increase_caliptra_svn;
mod test_mcu_mailbox;
mod test_revoke_vendor_pub_key;
mod test_vendor_auth_asym;

pub const TEST_AUTH_CMD_HMAC_KEY: [u8; 48] = [
    0x72, 0xec, 0x12, 0x02, 0x77, 0x69, 0xb9, 0xdc, 0x04, 0xbd, 0xd0, 0xc0, 0x86, 0xca, 0x1b, 0x20,
    0x2f, 0x47, 0x1e, 0xee, 0xf2, 0x8c, 0x2d, 0xa8, 0xc5, 0x4c, 0x75, 0xc2, 0x48, 0xa6, 0x80, 0x0a,
    0x11, 0xbf, 0xd5, 0xcd, 0x09, 0xed, 0x57, 0x0c, 0xb4, 0xc2, 0xa1, 0x37, 0x6b, 0xa2, 0xcb, 0xcd,
];

pub fn get_auth_cmd_challenge(hw: &mut impl McuHwModel) -> Result<[u8; 32]> {
    let cmd = GetAuthCmdChallengeReq::default();
    let resp = hw.mailbox_execute_req(cmd)?;
    Ok(resp.challenge)
}

pub fn sign_auth_cmd_challenge(challenge: &[u8; 32], cmd_id: u32, cmd: &[u8]) -> Result<[u8; 48]> {
    type HmacSha384 = Hmac<Sha384>;
    let cmd_id_bytes = cmd_id.to_be_bytes();
    let cmd_body = &cmd[size_of::<MailboxReqHeader>()..];
    let mut mac = HmacSha384::new_from_slice(&TEST_AUTH_CMD_HMAC_KEY)?;
    mac.update(&cmd_id_bytes);
    mac.update(cmd_body);
    mac.update(challenge);
    let result: [u8; 48] = mac.finalize().into_bytes().into();
    Ok(result)
}

pub fn authorize_cmd(hw: &mut impl McuHwModel, cmd_id: u32, cmd: &[u8]) -> Result<Vec<u8>> {
    let challenge = get_auth_cmd_challenge(hw)?;
    let mac = sign_auth_cmd_challenge(&challenge, cmd_id, cmd)?;
    let mut auth_cmd = cmd.to_vec();
    auth_cmd.extend_from_slice(&mac);
    Ok(auth_cmd)
}

/// Fetch a Caliptra-minted one-time nonce via `MC_VENDOR_AUTH_HELLO` (asym path).
pub fn get_vendor_auth_nonce(
    hw: &mut impl McuHwModel,
) -> Result<[u8; VENDOR_AUTH_NONCE_SIZE]> {
    let resp = hw.mailbox_execute_req(VendorAuthHelloReq::default())?;
    println!("[HSM-test]   HELLO -> nonce = {}", hex::encode(resp.challenge));
    Ok(resp.challenge)
}

/// Build the full asym-authorized command `[header | body | tag]` for `req` under a fresh
/// HELLO nonce. `tamper` may mutate the assembled buffer before the checksum is fixed
/// (negative tests); the checksum is always recomputed afterward so the buffer still
/// clears the MCU checksum gate. Returns `(cmd_id, bytes)` ready for `hw.mailbox_execute`.
pub fn build_asym_authorized_cmd<R: caliptra_mcu_mbox_common::messages::Request>(
    hw: &mut impl McuHwModel,
    mut req: R,
    signer: &dyn VendorAuthSigner,
    tamper: impl FnOnce(&mut Vec<u8>),
) -> Result<(u32, Vec<u8>)> {
    let cmd_id: u32 = R::ID.into();
    let nonce = get_vendor_auth_nonce(hw)?;

    let req_bytes = req.as_mut_bytes();
    let body = &req_bytes[size_of::<MailboxReqHeader>()..];
    let tag = signer.sign_vendor_auth(cmd_id, body, &nonce)?;

    let mut auth_cmd = req_bytes.to_vec();
    auth_cmd.extend_from_slice(&tag.to_bytes());
    tamper(&mut auth_cmd);

    let checksum = calc_checksum(cmd_id, &auth_cmd[size_of::<i32>()..]);
    MailboxReqHeader::mut_from_bytes(&mut auth_cmd[..size_of::<MailboxReqHeader>()])
        .unwrap()
        .chksum = checksum;
    Ok((cmd_id, auth_cmd))
}

/// Full asymmetric authorization: HELLO for a fresh nonce, sign `(cmd_id, body, nonce)`
/// with the vendor keys, append the tag, and send. Twin of [`execute_authorized_req`]
/// (HMAC) but drives the hybrid ECDSA-P384 + ML-DSA-87 verify in Caliptra.
pub fn execute_authorized_req_asym<R: caliptra_mcu_mbox_common::messages::Request>(
    hw: &mut impl McuHwModel,
    req: R,
    signer: &dyn VendorAuthSigner,
) -> Result<R::Resp> {
    println!("[HSM-test] === asym authorize cmd_id=0x{:08x} ===", u32::from(R::ID));
    let (cmd_id, auth_cmd) = build_asym_authorized_cmd(hw, req, signer, |_| {})?;
    println!("[HSM-test]   sending {} B to MCU mailbox ...", auth_cmd.len());

    let mut response = hw.mailbox_execute(cmd_id, &auth_cmd)?.unwrap_or_default();
    println!("[HSM-test]   MCU authorized + executed; resp {} B", response.len());

    if response.len() < 4 {
        bail!("Response too short to contain checksum");
    }
    let received = u32::from_le_bytes(response[..4].try_into().unwrap());
    let calculated = calc_checksum(0, &response[4..]);
    if received != calculated {
        bail!("Response checksum mismatch: expected {received:08x}, got {calculated:08x}");
    }
    if response.len() < size_of::<R::Resp>() {
        response.resize(size_of::<R::Resp>(), 0);
    }
    R::Resp::read_from_bytes(&response)
        .map_err(|_| anyhow!("Failed to read response into struct"))
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

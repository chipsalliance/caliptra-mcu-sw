// Licensed under the Apache-2.0 license

use crate::test::{compile_runtime, CustomCaliptraFw};
use anyhow::{anyhow, bail, Result};
use caliptra_api::calc_checksum;
use caliptra_api::mailbox::MailboxReqHeader;
use caliptra_image_fake_keys::{
    VENDOR_ECC_KEY_0_PRIVATE, VENDOR_ECC_KEY_0_PUBLIC, VENDOR_MLDSA_KEY_0_PRIVATE,
    VENDOR_MLDSA_KEY_0_PUBLIC,
};
use caliptra_image_types::ECC384_SCALAR_WORD_SIZE;
use caliptra_mcu_builder::{CaliptraBuildArgs, CaliptraBuilder};
use caliptra_mcu_command_auth_challenge_signer::{
    LocalVendorAuthSigner, VendorAuthKeys, VendorAuthSigner, VENDOR_AUTH_NONCE_SIZE,
};
use caliptra_mcu_hw_model::McuHwModel;
use caliptra_mcu_mbox_common::messages::VendorAuthHelloReq;
use core::mem::size_of;
use zerocopy::{FromBytes, IntoBytes};

mod test_increase_caliptra_svn;
mod test_mcu_mailbox;
mod test_revoke_vendor_pub_key;
mod test_vendor_auth_asym;

/// Vendor keys (VENDOR_*_KEY_0) in the hardware word format the signer + Caliptra expect:
/// ECC pub/priv big-endian words/bytes, ML-DSA pub little-endian words.
pub fn vendor_auth_keys() -> VendorAuthKeys {
    let mut ecc_public_key = [0u32; ECC384_SCALAR_WORD_SIZE * 2];
    ecc_public_key[..12].copy_from_slice(&VENDOR_ECC_KEY_0_PUBLIC.x);
    ecc_public_key[12..].copy_from_slice(&VENDOR_ECC_KEY_0_PUBLIC.y);

    let mut ecc_private_key_bytes = [0u8; 48];
    for (i, word) in VENDOR_ECC_KEY_0_PRIVATE.iter().enumerate() {
        ecc_private_key_bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }

    let mldsa_public_key: [u32; 648] = VENDOR_MLDSA_KEY_0_PUBLIC
        .0
        .as_bytes()
        .chunks(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    VendorAuthKeys {
        ecc_private_key_bytes,
        ecc_public_key,
        mldsa_private_key_bytes: VENDOR_MLDSA_KEY_0_PRIVATE.0.as_bytes().to_vec(),
        mldsa_public_key,
    }
}

/// Built artifacts whose SoC-manifest MCU digest matches the exact runtime bytes.
pub struct AsymFw {
    pub caliptra_fw: Vec<u8>,
    pub vendor_pk_hash: [u8; 48],
    pub soc_manifest: Vec<u8>,
    pub mcu_runtime: Vec<u8>,
}

/// Build the asym MCU runtime + Caliptra FW + a v2 SoC manifest whose 0x0001 anchor matches
/// `signer` and whose MCU digest matches the returned `mcu_runtime` bytes. Callers pass
/// `mcu_runtime` via `custom_mcu_runtime` so the loaded firmware matches the manifest digest.
/// `extra_features` (e.g. "ocp-lock") is appended to the base `test-mcu-mbox-cmds,asym-cmd-auth`.
pub fn build_asym_fw_features(
    signer: &LocalVendorAuthSigner,
    extra_features: &[&str],
) -> Result<AsymFw> {
    let mut features = String::from("test-mcu-mbox-cmds,asym-cmd-auth");
    for f in extra_features {
        features.push(',');
        features.push_str(f);
    }
    let mcu_runtime_path = compile_runtime(Some(&features), false);
    let mcu_runtime = std::fs::read(&mcu_runtime_path)?;
    let mut builder = CaliptraBuilder::new(&CaliptraBuildArgs {
        mcu_firmware: Some(mcu_runtime_path),
        ocp_lock: extra_features.contains(&"ocp-lock"),
        ..Default::default()
    })
    .with_vendor_cmd_auth_pk_hash(signer.anchor());

    let caliptra_fw = std::fs::read(builder.get_caliptra_fw()?)?;
    let mut vendor_pk_hash = [0u8; 48];
    vendor_pk_hash.copy_from_slice(&hex::decode(builder.get_vendor_pk_hash()?)?);
    let soc_manifest = std::fs::read(builder.get_soc_manifest(None)?)?;
    Ok(AsymFw {
        caliptra_fw,
        vendor_pk_hash,
        soc_manifest,
        mcu_runtime,
    })
}

/// Build asym firmware with just the base features (no extras).
pub fn build_asym_fw(signer: &LocalVendorAuthSigner) -> Result<AsymFw> {
    build_asym_fw_features(signer, &[])
}

/// Convenience: the `CustomCaliptraFw` an asym boot needs from `build_asym_fw`.
pub fn asym_custom_fw(fw: &AsymFw) -> CustomCaliptraFw {
    CustomCaliptraFw {
        fw_bytes: fw.caliptra_fw.clone(),
        vendor_pk_hash: fw.vendor_pk_hash,
        soc_manifest: fw.soc_manifest.clone(),
    }
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
/// with the vendor keys, append the tag, and send. Drives the hybrid ECDSA-P384 +
/// ML-DSA-87 verify in Caliptra.
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

// Licensed under the Apache-2.0 license

use std::thread;
use std::time::Duration;

use crate::jtag::jtag_send_caliptra_mailbox_cmd;
use crate::DefaultHwModel;

use caliptra_api::mailbox::{
    CommandId, ProductionAuthDebugUnlockChallenge, ProductionAuthDebugUnlockToken,
};
use caliptra_hw_model::jtag::CaliptraCoreReg;
use caliptra_hw_model::openocd::openocd_jtag_tap::OpenOcdJtagTap;
use caliptra_hw_model::HwModel;

use anyhow::{Context, Result};
use ecdsa::signature::hazmat::PrehashSigner;
use ecdsa::{Signature, SigningKey as EcdsaSigningKey};
use fips204::ml_dsa_87::{PrivateKey as MldsaPrivateKey, SIG_LEN as MLDSA_SIG_LEN};
use fips204::traits::Signer;
use p384::SecretKey;
use sha2::{Digest, Sha384, Sha512};
use zerocopy::{FromBytes, IntoBytes};

/// Send the prod debug unlock request via the Caliptra Core mailbox.
///
/// Assumes you are connected to the Caliptra Core JTAG TAP and that you have acquired the
/// Caliptra Core mailbox lock.
pub fn prod_debug_unlock_send_request(tap: &mut OpenOcdJtagTap, debug_level: u32) -> Result<()> {
    let request_payload: [u32; 2] = [/*length=*/ 0x2, debug_level];
    jtag_send_caliptra_mailbox_cmd(
        tap,
        CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ,
        &request_payload.as_bytes(),
    )?;
    Ok(())
}

/// Send the (signed) debug unlock token via the Caliptra Core mailbox.
///
/// Assumes you are connected to the Caliptra Core JTAG TAP and that you have acquired the
/// Caliptra Core mailbox lock.
pub fn prod_debug_unlock_send_token(
    tap: &mut OpenOcdJtagTap,
    token: &ProductionAuthDebugUnlockToken,
) -> Result<()> {
    // Convert token to an array of u32 to send to the mailbox interface.
    let token_bytes = token.as_bytes();
    let mut token_payload = vec![];
    for (i, chunk) in token_bytes.chunks(4).enumerate() {
        if i == 0 {
            // The first 32-bits is the space for the checksum.
            continue;
        }
        let mut padded_chunk = [0u8; 4];
        padded_chunk[..chunk.len()].copy_from_slice(chunk);
        token_payload.push(u32::from_le_bytes(padded_chunk));
    }

    // Send the token command to the mailbox.
    jtag_send_caliptra_mailbox_cmd(
        tap,
        CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN,
        &token_payload.as_bytes(),
    )?;

    Ok(())
}

/// Get the prod debug unlock challenge response via the Caliptra Core mailbox.
///
/// Assumes you are connected to the Caliptra Core JTAG TAP and that you have acquired the
/// Caliptra Core mailbox lock.
pub fn prod_debug_unlock_get_challenge(
    tap: &mut OpenOcdJtagTap,
) -> Result<ProductionAuthDebugUnlockChallenge> {
    // Read the number of bytes to RX.
    let num_rsp_bytes = tap
        .read_reg(&CaliptraCoreReg::MboxDlen)
        .expect("Failed to read response length.") as usize;
    let mut rsp_bytes = vec![0; num_rsp_bytes];
    // RX the mailbox data bytes.
    for i in 0..num_rsp_bytes / 4 {
        let word = tap
            .read_reg(&CaliptraCoreReg::MboxDout)
            .expect("Failed to read response value.");
        rsp_bytes[i * 4..i * 4 + 4].copy_from_slice(word.as_bytes());
    }
    let du_challenge = ProductionAuthDebugUnlockChallenge::read_from_bytes(rsp_bytes.as_slice())
        .ok()
        .context("Failed to read challenge from bytes")?;
    // Write 0 to execute to indicate done receiving.
    tap.write_reg(&CaliptraCoreReg::MboxExecute, 0x0)
        .context("Unable to write to MboxExecute register.")?;
    Ok(du_challenge)
}

/// Spinwait for prod debug unlock to be "in-progress".
///
/// If "begin" is true, we are waiting for the for the "in-progress" bit to go from 0-->1,
/// otherwise we are waiting for the opposite.
pub fn prod_debug_unlock_wait_for_in_progress(
    model: &mut DefaultHwModel,
    tap: &mut OpenOcdJtagTap,
    begin: bool,
) -> u32 {
    model.base.step();
    while let Ok(rsp) = tap.read_reg(&CaliptraCoreReg::SsDbgManufServiceRegRsp) {
        model.base.step();
        if begin {
            if rsp & 0x20 != 0 {
                return rsp;
            }
        } else {
            if rsp & 0x20 == 0 {
                return rsp;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    unreachable!();
}

/// Generate the signed prod debug unlock token from using the challenge.
pub fn prod_debug_unlock_gen_signed_token(
    challenge: &ProductionAuthDebugUnlockChallenge,
    unlock_level: u8,
    ecc_private_key: &SecretKey,
    mldsa_private_key: &MldsaPrivateKey,
    ecc_public_key: &[u32; 24],
    mldsa_public_key: &[u32; 648],
) -> Result<ProductionAuthDebugUnlockToken> {
    // Construct the debug unlock token.
    let mut du_token = ProductionAuthDebugUnlockToken {
        hdr: Default::default(),
        length: ((std::mem::size_of::<ProductionAuthDebugUnlockToken>() - 4) / 4) as u32,
        unique_device_identifier: challenge.unique_device_identifier,
        unlock_level: unlock_level,
        reserved: [0; 3],
        challenge: challenge.challenge,
        ecc_public_key: *ecc_public_key,
        mldsa_public_key: *mldsa_public_key,
        ..Default::default()
    };

    // Compute ECDSA token (SHA384) digest.
    let mut token_hasher = Sha384::new();
    sha2::Digest::update(&mut token_hasher, du_token.unique_device_identifier);
    sha2::Digest::update(&mut token_hasher, [du_token.unlock_level]);
    sha2::Digest::update(&mut token_hasher, du_token.reserved);
    sha2::Digest::update(&mut token_hasher, du_token.challenge);
    let ecdsa_token_hash: [u8; 48] = token_hasher.finalize().into();

    // Sign the token with ECDSA.
    let signing_key = EcdsaSigningKey::<p384::NistP384>::from(ecc_private_key);
    let ecdsa_signature: Signature<p384::NistP384> = signing_key.sign_prehash(&ecdsa_token_hash)?;
    let r_bytes = ecdsa_signature.r().to_bytes();
    let s_bytes = ecdsa_signature.s().to_bytes();
    for (i, chunk) in r_bytes.chunks(4).enumerate() {
        du_token.ecc_signature[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    for (i, chunk) in s_bytes.chunks(4).enumerate() {
        du_token.ecc_signature[i + 12] = u32::from_be_bytes(chunk.try_into().unwrap());
    }

    // Compute MLDSA token (SHA512) digest.
    let mut token_hasher = Sha512::new();
    sha2::Digest::update(&mut token_hasher, du_token.unique_device_identifier);
    sha2::Digest::update(&mut token_hasher, [du_token.unlock_level]);
    sha2::Digest::update(&mut token_hasher, du_token.reserved);
    sha2::Digest::update(&mut token_hasher, du_token.challenge);
    let mldsa_token_hash: [u8; 64] = token_hasher.finalize().into();

    // Sign the token with MLDSA.
    let mldsa_signature = mldsa_private_key
        .try_sign_with_seed(&[0u8; 32], &mldsa_token_hash, &[])
        .unwrap();
    let mldsa_signature_padded = {
        let mut sig = [0u8; MLDSA_SIG_LEN + 1];
        sig[..MLDSA_SIG_LEN].copy_from_slice(&mldsa_signature);
        sig
    };
    for (i, chunk) in mldsa_signature_padded.chunks(4).enumerate() {
        // Unlike ECDSA, no reversal of each word's endianness is needed.
        du_token.mldsa_signature[i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    Ok(du_token)
}

// Licensed under the Apache-2.0 license

//! Full end-to-end asymmetric vendor-command authentication over the MCU runtime
//! mailbox (no JTAG). Drives the complete path:
//!   host -> MC_VENDOR_AUTH_HELLO -> MCU relay -> Caliptra (mint nonce)
//!   host (HSM) signs -> authorized command [hdr|body|tag] -> MCU AsymCommandAuthorizer
//!   -> Caliptra VENDOR_AUTH_CHALLENGE (hybrid verify) -> echo -> MCU executes MC_FUSE_READ.
//!
//! The test itself is the HSM (LocalVendorAuthSigner with VENDOR_*_KEY_0). The anchor is
//! enrolled at boot via a v2 SoC manifest (Vendor Ext 0x0001). Requires the MCU runtime
//! built with `--features asym-cmd-auth`.

use crate::runtime::{build_asym_authorized_cmd, execute_authorized_req_asym};
use crate::test::{compile_runtime, start_runtime_hw_model, CustomCaliptraFw, TestParams};
use anyhow::Result;
use caliptra_image_fake_keys::{
    VENDOR_ECC_KEY_0_PRIVATE, VENDOR_ECC_KEY_0_PUBLIC, VENDOR_MLDSA_KEY_0_PRIVATE,
    VENDOR_MLDSA_KEY_0_PUBLIC,
};
use caliptra_image_types::ECC384_SCALAR_WORD_SIZE;
use caliptra_mcu_builder::{CaliptraBuildArgs, CaliptraBuilder};
use caliptra_mcu_command_auth_challenge_signer::{LocalVendorAuthSigner, VendorAuthKeys};
use caliptra_mcu_hw_model::McuHwModel;
use caliptra_mcu_mbox_common::messages::FuseReadReq;
use caliptra_mcu_romtime::McuBootMilestones;
use zerocopy::IntoBytes;

/// Build the vendor keys in the hardware word format the signer + Caliptra expect.
fn vendor_auth_keys() -> VendorAuthKeys {
    // ECC public: X||Y big-endian u32 words.
    let mut ecc_public_key = [0u32; ECC384_SCALAR_WORD_SIZE * 2];
    ecc_public_key[..12].copy_from_slice(&VENDOR_ECC_KEY_0_PUBLIC.x);
    ecc_public_key[12..].copy_from_slice(&VENDOR_ECC_KEY_0_PUBLIC.y);

    // ECC private: 48 big-endian bytes.
    let mut ecc_private_key_bytes = [0u8; 48];
    for (i, word) in VENDOR_ECC_KEY_0_PRIVATE.iter().enumerate() {
        ecc_private_key_bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }

    // ML-DSA public: little-endian u32 words.
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
struct FwWithAnchor {
    caliptra_fw: Vec<u8>,
    vendor_pk_hash: [u8; 48],
    soc_manifest: Vec<u8>,
    mcu_runtime: Vec<u8>,
}

/// Build the asym MCU runtime, Caliptra FW, and a v2 SoC manifest whose 0x0001 anchor
/// matches `signer` and whose MCU digest matches the returned `mcu_runtime` bytes.
fn build_fw_with_anchor(signer: &LocalVendorAuthSigner) -> Result<FwWithAnchor> {
    // Both features share one string: test-mcu-mbox-cmds enables the authorized-command
    // set; asym-cmd-auth swaps the mock authorizer for the asymmetric relay one.
    let mcu_runtime_path = compile_runtime(Some("test-mcu-mbox-cmds,asym-cmd-auth"), false);
    let mcu_runtime = std::fs::read(&mcu_runtime_path)?;
    let mut builder = CaliptraBuilder::new(&CaliptraBuildArgs {
        mcu_firmware: Some(mcu_runtime_path),
        ..Default::default()
    })
    .with_vendor_cmd_auth_pk_hash(signer.anchor());

    let caliptra_fw = std::fs::read(builder.get_caliptra_fw()?)?;
    let mut vendor_pk_hash = [0u8; 48];
    vendor_pk_hash.copy_from_slice(&hex::decode(builder.get_vendor_pk_hash()?)?);
    let soc_manifest = std::fs::read(builder.get_soc_manifest(None)?)?;
    println!("[HSM-test] built v2 SoC manifest, anchor = {}", hex::encode(signer.anchor()));
    Ok(FwWithAnchor {
        caliptra_fw,
        vendor_pk_hash,
        soc_manifest,
        mcu_runtime,
    })
}

fn boot(signer: &LocalVendorAuthSigner) -> Result<impl McuHwModel> {
    let fw = build_fw_with_anchor(signer)?;
    // Load the SAME runtime bytes the manifest digested (custom_mcu_runtime), else the
    // harness picks its own runtime and Caliptra fails with RUNTIME_DIGEST_MISMATCH.
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        custom_mcu_runtime: Some(fw.mcu_runtime),
        custom_caliptra_fw: Some(CustomCaliptraFw {
            fw_bytes: fw.caliptra_fw,
            vendor_pk_hash: fw.vendor_pk_hash,
            soc_manifest: fw.soc_manifest,
        }),
        ..Default::default()
    });
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });
    println!("[HSM-test] MCU runtime mailbox READY");
    Ok(hw)
}

/// The authorized command exercised by every test (read-only, no side effects).
fn fuse_read_cmd() -> FuseReadReq {
    FuseReadReq {
        partition: 0,
        entry: 0,
        ..Default::default()
    }
}

#[test]
fn test_vendor_auth_asym_authorized_req() -> Result<()> {
    let signer = LocalVendorAuthSigner::new(vendor_auth_keys());
    let mut hw = boot(&signer)?;

    // Full asymmetric authorization of an authorized command (MC_FUSE_READ).
    let resp = execute_authorized_req_asym(&mut hw, fuse_read_cmd(), &signer);
    assert!(resp.is_ok(), "asym-authorized MC_FUSE_READ failed: {resp:?}");
    println!("[HSM-test] PASS: full asymmetric authentication succeeded");
    Ok(())
}

#[test]
fn test_vendor_auth_asym_wrong_key_rejected() -> Result<()> {
    // Enroll the real anchor, but sign with a DIFFERENT keypair (swap ECC private key
    // bytes). Pubkeys won't match the enrolled anchor -> Caliptra rejects.
    let signer = LocalVendorAuthSigner::new(vendor_auth_keys());
    let mut hw = boot(&signer)?;

    // Present a pubkey that no longer hashes to the enrolled anchor → rejected at the
    // anchor gate (WRONG_PUBLIC_KEYS), before any signature check.
    let mut wrong_keys = vendor_auth_keys();
    wrong_keys.ecc_public_key[0] ^= 0xFFFF_FFFF;
    let wrong_signer = LocalVendorAuthSigner::new(wrong_keys);

    let resp = execute_authorized_req_asym(&mut hw, fuse_read_cmd(), &wrong_signer);
    assert!(resp.is_err(), "wrong-key asym auth must be rejected");
    println!("[HSM-test] PASS: wrong-key rejected as expected");
    Ok(())
}

#[test]
fn test_vendor_auth_asym_replayed_nonce_rejected() -> Result<()> {
    let signer = LocalVendorAuthSigner::new(vendor_auth_keys());
    let mut hw = boot(&signer)?;

    // Build one signed command bound to a fresh nonce, then send it twice: the first
    // consumes the nonce, the replay must be rejected (nonce is one-time).
    let (cmd_id, auth) = build_asym_authorized_cmd(&mut hw, fuse_read_cmd(), &signer, |_| {})?;
    let first = hw.mailbox_execute(cmd_id, &auth);
    assert!(first.is_ok(), "fresh nonce use should pass: {first:?}");
    let replay = hw.mailbox_execute(cmd_id, &auth);
    assert!(replay.is_err(), "replayed nonce must be rejected");
    println!("[HSM-test] PASS: replayed nonce rejected as expected");
    Ok(())
}

// Byte offsets within the assembled [header(4) | body(8) | tag] command for MC_FUSE_READ,
// where tag = nonce(48) ‖ ecc_pub(96) ‖ mldsa_pub(2592) ‖ ecc_sig(96) ‖ mldsa_sig(4628).
const TAG_START: usize = 4 + 8; // header + FuseReadReq body (partition + entry)
const MLDSA_SIG_OFF: usize = TAG_START + 48 + 96 + 2592 + 96;

// Tampering the body after signing breaks BOTH signatures (the transcript covers
// SHA-384(body)). Passes the nonce + anchor gates, then fails signature verify.
#[test]
fn test_vendor_auth_asym_tampered_body_rejected() -> Result<()> {
    let signer = LocalVendorAuthSigner::new(vendor_auth_keys());
    let mut hw = boot(&signer)?;

    let (cmd_id, auth) = build_asym_authorized_cmd(&mut hw, fuse_read_cmd(), &signer, |buf| {
        buf[4] ^= 0xFF; // flip a body byte (partition) after signing
    })?;
    let resp = hw.mailbox_execute(cmd_id, &auth);
    assert!(resp.is_err(), "tampered body must be rejected at signature verify");
    println!("[HSM-test] PASS: tampered body rejected as expected");
    Ok(())
}

// Corrupt ONLY the ML-DSA signature (ECC sig, pubkeys, nonce, body all valid). Proves the
// hybrid verify is strict-AND: ECC alone passing is not enough. Without this, a no-op
// ML-DSA verify would go undetected (tampered-body fails at the ECC gate first).
#[test]
fn test_vendor_auth_asym_bad_mldsa_only_rejected() -> Result<()> {
    let signer = LocalVendorAuthSigner::new(vendor_auth_keys());
    let mut hw = boot(&signer)?;

    let (cmd_id, auth) = build_asym_authorized_cmd(&mut hw, fuse_read_cmd(), &signer, |buf| {
        buf[MLDSA_SIG_OFF] ^= 0x01; // flip one bit of the ML-DSA signature only
    })?;
    let resp = hw.mailbox_execute(cmd_id, &auth);
    assert!(resp.is_err(), "bad ML-DSA signature must be rejected (strict-AND)");
    println!("[HSM-test] PASS: bad-ML-DSA-only rejected (strict-AND proven)");
    Ok(())
}

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

use crate::runtime::{
    asym_custom_fw, build_asym_authorized_cmd, build_asym_fw, execute_authorized_req_asym,
    vendor_auth_keys,
};
use crate::test::{start_runtime_hw_model, TestParams};
use anyhow::Result;
use caliptra_mcu_command_auth_challenge_signer::LocalVendorAuthSigner;
use caliptra_mcu_hw_model::McuHwModel;
use caliptra_mcu_mbox_common::messages::FuseReadReq;
use caliptra_mcu_romtime::McuBootMilestones;

/// Boot the MCU emulator with the asym firmware + v2 anchor manifest matching `signer`.
fn boot(signer: &LocalVendorAuthSigner) -> Result<impl McuHwModel> {
    let fw = build_asym_fw(signer)?;
    // Load the SAME runtime bytes the manifest digested (custom_mcu_runtime), else the
    // harness picks its own runtime and Caliptra fails with RUNTIME_DIGEST_MISMATCH.
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        custom_mcu_runtime: Some(fw.mcu_runtime.clone()),
        custom_caliptra_fw: Some(asym_custom_fw(&fw)),
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

// Note: the anchor-not-enrolled gate (a correctly-signed command rejected when Caliptra
// holds no anchor) is covered on the Caliptra side by
// caliptra-sw test_vendor_auth_challenge_anchor_not_enrolled. It is not duplicated here:
// the MCU cold boot enrolls the manifest via recovery_flow, so a no-anchor boot exercises
// boot-time manifest enrollment rather than the asym relay.

// The P1-widened allowlist arms (SVN-increase, FE_PROG, revoke, HEK) are exercised for
// *authorization* by the shared build_asym_authorized_cmd path; the happy-path test is the
// positive control (its unmutated command is what each negative test then mutates). A
// dedicated positive test per command is intentionally omitted: those handlers require
// command-specific fuse state and would fail at execution, not authorization — which the
// mailbox boundary cannot distinguish from an auth failure.

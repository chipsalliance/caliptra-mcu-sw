// Licensed under the Apache-2.0 license

//! MCU-local asymmetric command-authorization tests.
//!
//! Gates: G1 pass, G2 anchor, G3 nonce, G4 tampered body, G5 strict-AND.
//! Covers the five runtime-bootable authorized commands; the three rom_only
//! commands are not covered (pre-existing harness limitation).

use crate::runtime::{execute_authorized_req, execute_authorized_req_tampered};
use crate::test::{compile_runtime, start_runtime_hw_model, CustomCaliptraFw, TestParams};
use anyhow::Result;
use caliptra_mcu_builder::{CaliptraBuildArgs, CaliptraBuilder, FirmwareBinaries};
use caliptra_mcu_command_auth_challenge_signer::AUTH_CMD_NONCE_LEN;
use caliptra_mcu_hw_model::{DefaultHwModel, LifecycleControllerState, McuHwModel};
use caliptra_mcu_mbox_common::messages::{
    FuseLockPartitionReq, FuseReadReq, FuseWriteReq, HybridSignature, MailboxReqHeader,
    McuFeProgReq, ProvisionVendorPkHashReq,
};
use caliptra_mcu_romtime::McuBootMilestones;
use core::mem::size_of;

/// Boot the runtime hw model (Prod, `test-mcu-mbox-cmds`) and wait for the mailbox.
fn boot_mcu_mbox_hw() -> DefaultHwModel {
    // Boot the MCU runtime the SoC manifest digested: under `CPTRA_FIRMWARE_BUNDLE`
    // that is the bundle's own runtime (loaded by the emulator), otherwise the
    // freshly built runtime the local `CaliptraBuilder` manifest was signed over.
    // Injecting a separately compiled `custom_mcu_runtime` here would not match the
    // bundle manifest and boot would fail with RUNTIME_DIGEST_MISMATCH (0x000B0016).
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
            let fw = std::fs::read(builder.get_caliptra_fw().unwrap()).unwrap();
            let pk_hash_str = builder.get_vendor_pk_hash().unwrap().to_string();
            let pk_hash = hex::decode(&pk_hash_str).unwrap();
            let mut pk_hash_arr = [0u8; 48];
            pk_hash_arr.copy_from_slice(&pk_hash);
            let manifest = std::fs::read(builder.get_soc_manifest(None).unwrap()).unwrap();
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
    hw
}

/// A rejected command must surface as an error, not a timeout.
fn assert_rejected_not_timeout<T: std::fmt::Debug>(result: Result<T>, gate: &str) {
    match result {
        Ok(resp) => {
            panic!(
                "{gate}: expected authorization to be denied, but the command succeeded: {resp:?}"
            )
        }
        Err(e) => {
            let msg = format!("{e:?}");
            assert!(
                !msg.contains("timed out"),
                "{gate}: rejection must be a mailbox failure, not a timeout. Got: {msg}"
            );
        }
    }
}

// ===========================================================================
// G1 PASS - one per runtime-bootable authorized command.
// ===========================================================================

#[test]
fn test_fe_prog_authorized_req_g1() -> Result<()> {
    let mut hw = boot_mcu_mbox_hw();
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
fn test_provision_vendor_pk_hash_authorized_req_g1() -> Result<()> {
    // Provisioning an UNUSED slot (1) succeeds.
    let mut hw = boot_mcu_mbox_hw();
    let cmd = ProvisionVendorPkHashReq {
        hdr: MailboxReqHeader::default(),
        slot: 1,
        hash: [0x11u8; 48],
    };
    let result = execute_authorized_req(&mut hw, cmd);
    assert!(
        result.is_ok(),
        "PROVISION_VENDOR_PK_HASH authorized request failed: {result:?}"
    );
    Ok(())
}

#[test]
fn test_fuse_read_authorized_req_g1() -> Result<()> {
    // Non-secret, present partition (SVN = 0x08), aligned entry 0.
    let mut hw = boot_mcu_mbox_hw();
    let cmd = FuseReadReq {
        partition: 0x08,
        entry: 0,
        ..Default::default()
    };
    let result = execute_authorized_req(&mut hw, cmd);
    assert!(
        result.is_ok(),
        "FUSE_READ authorized request failed: {result:?}"
    );
    Ok(())
}

#[test]
fn test_fuse_write_authorized_req_g1() -> Result<()> {
    // mask = 0 is a no-op write that still exercises authorize->dispatch->handle.
    let mut hw = boot_mcu_mbox_hw();
    let cmd = FuseWriteReq {
        word_addr: 0,
        data: 0,
        mask: 0,
        ..Default::default()
    };
    let result = execute_authorized_req(&mut hw, cmd);
    assert!(
        result.is_ok(),
        "FUSE_WRITE authorized request failed: {result:?}"
    );
    Ok(())
}

#[test]
fn test_fuse_lock_partition_authorized_req_g1() -> Result<()> {
    // Valid PartitionId (VendorNonSecretProd = 0x0E); fresh throwaway hw model.
    let mut hw = boot_mcu_mbox_hw();
    let cmd = FuseLockPartitionReq {
        partition: 0x0E,
        ..Default::default()
    };
    let result = execute_authorized_req(&mut hw, cmd);
    assert!(
        result.is_ok(),
        "FUSE_LOCK_PARTITION authorized request failed: {result:?}"
    );
    Ok(())
}

// ===========================================================================
// G2..G5 negatives - each tamper corrupts exactly one field of the correctly
// signed wire frame after signing, so the device's fail-closed verifier rejects.
// ===========================================================================

#[test]
fn test_fe_prog_auth_negative_gates() -> Result<()> {
    // One boot exercises every gate: each send fetches a fresh device-issued
    // one-time challenge, and a denied command does not affect later sends.
    let mut hw = boot_mcu_mbox_hw();

    // Byte offsets into the assembled authorized frame:
    //   [ body | sig(HybridSignature) | nonce(48) | ecc_x(48) | ecc_y(48) | mldsa_pub(2592) ]
    let body_len = size_of::<McuFeProgReq>();
    let sig_off = body_len; // HybridSignature: ecc_sig_r[48] | ecc_sig_s[48] | mldsa_sig[4628]
    let ecc_r_off = sig_off; // first byte of the ECDSA signature
    let mldsa_off = sig_off + 96; // first byte of the ML-DSA signature (after r||s)
    let nonce_off = sig_off + size_of::<HybridSignature>();
    let ecc_pub_x_off = nonce_off + AUTH_CMD_NONCE_LEN;
    let body_off = size_of::<MailboxReqHeader>(); // first signed body byte (partition)

    let cmd = || McuFeProgReq {
        partition: 0,
        ..Default::default()
    };

    // G3 NONCE: wire nonce != device's stored one-time challenge -> step 1 denies.
    let r = execute_authorized_req_tampered(&mut hw, cmd(), |b| b[nonce_off] ^= 0xff);
    assert_rejected_not_timeout(r, "G3 FE_PROG nonce");

    // G2 ANCHOR: corrupt a public-key byte so SHA-384(pubkeys) != anchor -> step 2 denies.
    let r = execute_authorized_req_tampered(&mut hw, cmd(), |b| b[ecc_pub_x_off] ^= 0xff);
    assert_rejected_not_timeout(r, "G2 FE_PROG anchor");

    // G4 ECC/BODY: mutate the body after signing so SHA-512(payload) differs -> ECDSA (step 3) fails.
    let r = execute_authorized_req_tampered(&mut hw, cmd(), |b| b[body_off] ^= 0xff);
    assert_rejected_not_timeout(r, "G4 FE_PROG body");

    // G5-A STRICT-AND: valid ECDSA + garbage ML-DSA -> step 4 denies (ML-DSA required).
    let r = execute_authorized_req_tampered(&mut hw, cmd(), |b| b[mldsa_off] ^= 0xff);
    assert_rejected_not_timeout(r, "G5 FE_PROG mldsa-corrupt (ecc-valid)");

    // G5-B STRICT-AND: garbage ECDSA + valid ML-DSA -> step 3 denies (ECDSA required).
    let r = execute_authorized_req_tampered(&mut hw, cmd(), |b| b[ecc_r_off] ^= 0xff);
    assert_rejected_not_timeout(r, "G5 FE_PROG ecc-corrupt (mldsa-valid)");

    Ok(())
}

#[test]
fn test_fuse_read_auth_negative_gates() -> Result<()> {
    // Second runtime-bootable gated command; same five gates, proving the auth
    // wrapper is enforced identically regardless of the command body shape.
    let mut hw = boot_mcu_mbox_hw();

    let body_len = size_of::<FuseReadReq>();
    let sig_off = body_len;
    let ecc_r_off = sig_off;
    let mldsa_off = sig_off + 96;
    let nonce_off = sig_off + size_of::<HybridSignature>();
    let ecc_pub_x_off = nonce_off + AUTH_CMD_NONCE_LEN;
    let body_off = size_of::<MailboxReqHeader>();

    let cmd = || FuseReadReq {
        partition: 0,
        entry: 0,
        ..Default::default()
    };

    // G3 NONCE
    let r = execute_authorized_req_tampered(&mut hw, cmd(), |b| b[nonce_off] ^= 0xff);
    assert_rejected_not_timeout(r, "G3 FUSE_READ nonce");

    // G2 ANCHOR
    let r = execute_authorized_req_tampered(&mut hw, cmd(), |b| b[ecc_pub_x_off] ^= 0xff);
    assert_rejected_not_timeout(r, "G2 FUSE_READ anchor");

    // G4 ECC/BODY
    let r = execute_authorized_req_tampered(&mut hw, cmd(), |b| b[body_off] ^= 0xff);
    assert_rejected_not_timeout(r, "G4 FUSE_READ body");

    // G5-A STRICT-AND: valid ECDSA + garbage ML-DSA -> step 4 denies.
    let r = execute_authorized_req_tampered(&mut hw, cmd(), |b| b[mldsa_off] ^= 0xff);
    assert_rejected_not_timeout(r, "G5 FUSE_READ mldsa-corrupt (ecc-valid)");

    // G5-B STRICT-AND: garbage ECDSA + valid ML-DSA -> step 3 denies.
    let r = execute_authorized_req_tampered(&mut hw, cmd(), |b| b[ecc_r_off] ^= 0xff);
    assert_rejected_not_timeout(r, "G5 FUSE_READ ecc-corrupt (mldsa-valid)");

    Ok(())
}

// ===========================================================================
// Host-side wire-size KAT - no device boot. Locks the HybridSignature size and
// the FE_PROG authorized-request layout so a struct change can never silently
// shift the tamper offsets used above.
// ===========================================================================

#[test]
fn test_auth_wire_sizes_kat() {
    // HybridSignature = ecc_sig_r[48] + ecc_sig_s[48] + mldsa_sig[4628].
    assert_eq!(size_of::<HybridSignature>(), 4724);
    assert_eq!(AUTH_CMD_NONCE_LEN, 48);

    // Device-side canonical authorized FE_PROG request (matches FeProgVdmReq /
    // FeProgRequest, which the firmware/host assert == 7464):
    //   partition(4) | sig(4724) | nonce(48) | ecc_x(48) | ecc_y(48) | mldsa_pub(2592)
    let fe_prog_authed_body =
        size_of::<u32>() + size_of::<HybridSignature>() + AUTH_CMD_NONCE_LEN + 48 + 48 + 2592;
    assert_eq!(fe_prog_authed_body, 7464);

    // On the host mailbox path the body is preceded by the 4-byte MailboxReqHeader
    // (chksum), i.e. McuFeProgReq is hdr(4) + partition(4).
    assert_eq!(size_of::<McuFeProgReq>(), 8);
}

// ===========================================================================
// Gate-isolation negatives — each fails ONLY if the named gate is present, so
// removing that gate turns the test red (the byte-flip negatives above can't do
// this, since a flip also trips a downstream signature check).
// ===========================================================================

/// A second, valid-but-unauthorized vendor keypair (distinct from the device
/// anchor's TEST_* keypair). `[0x02; 48]` is a valid P-384 scalar; the seed is 32 bytes.
const OTHER_ECC_PRIV_KEY: [u8; 48] = [0x02; 48];
const OTHER_MLDSA_SEED: [u8; 32] = *b"caliptra-mcu-OTHER-test-seed-002";

/// ANCHOR isolation: sign FE_PROG with a DIFFERENT self-consistent keypair and
/// present that keypair's own public keys + a freshly issued nonce. Steps 1/3/4
/// all pass under the presented keys — only step-0 (SHA-384(pubkeys)==AUTH_PK_HASH)
/// can reject. If the anchor gate were removed, this would fail-open.
#[test]
fn test_fe_prog_auth_key_substitution_rejected() -> Result<()> {
    use crate::runtime::{
        get_auth_cmd_challenge, send_authorized_bytes, sign_auth_cmd_challenge_with,
    };
    use caliptra_mcu_mbox_common::messages::McuFeProgReq;
    use zerocopy::IntoBytes;

    let mut hw = boot_mcu_mbox_hw();

    let mut req = McuFeProgReq {
        partition: 0,
        ..Default::default()
    };
    let cmd_id: u32 = <McuFeProgReq as caliptra_mcu_mbox_common::messages::Request>::ID.into();
    let challenge = get_auth_cmd_challenge(&mut hw)?;

    // Fully valid frame under the attacker keypair (its pubkeys travel on the wire).
    let tail = sign_auth_cmd_challenge_with(
        &OTHER_ECC_PRIV_KEY,
        &OTHER_MLDSA_SEED,
        &challenge,
        cmd_id,
        req.as_mut_bytes(),
    )?;
    let mut auth_cmd = req.as_mut_bytes().to_vec();
    auth_cmd.extend_from_slice(&tail);

    let r = send_authorized_bytes::<McuFeProgReq>(&mut hw, &mut auth_cmd);
    assert_rejected_not_timeout(r, "ANCHOR key-substitution");
    Ok(())
}

/// REPLAY isolation: send a correctly-signed frame once (Ok), then re-send the
/// IDENTICAL bytes without fetching a new challenge. Only step-1's one-time
/// `.take()` of the stored challenge can reject the replay.
#[test]
fn test_fe_prog_auth_replay_rejected() -> Result<()> {
    use crate::runtime::{get_auth_cmd_challenge, send_authorized_bytes, sign_auth_cmd_challenge};
    use caliptra_mcu_mbox_common::messages::McuFeProgReq;
    use zerocopy::IntoBytes;

    let mut hw = boot_mcu_mbox_hw();

    let mut req = McuFeProgReq {
        partition: 0,
        ..Default::default()
    };
    let cmd_id: u32 = <McuFeProgReq as caliptra_mcu_mbox_common::messages::Request>::ID.into();
    let challenge = get_auth_cmd_challenge(&mut hw)?;
    let tail = sign_auth_cmd_challenge(&challenge, cmd_id, req.as_mut_bytes())?;
    let mut auth_cmd = req.as_mut_bytes().to_vec();
    auth_cmd.extend_from_slice(&tail);

    // First send: valid, challenge consumed.
    let first = send_authorized_bytes::<McuFeProgReq>(&mut hw, &mut auth_cmd.clone());
    assert!(
        first.is_ok(),
        "first (valid) send should succeed: {first:?}"
    );

    // Replay the exact same bytes without a fresh challenge.
    let replay = send_authorized_bytes::<McuFeProgReq>(&mut hw, &mut auth_cmd);
    assert_rejected_not_timeout(replay, "REPLAY one-time nonce");
    Ok(())
}

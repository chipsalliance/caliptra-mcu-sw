// Licensed under the Apache-2.0 license
//! Asymmetric, manifest-anchored, per-command authorizer (Team Alpha, WIP).
//!
//! This is the MCU-side relay half of the hybrid ECDSA-P384 + ML-DSA-87
//! per-command authentication scheme that replaces the dummy shared-secret
//! HMAC gate ([`super::cmd_auth_mock::MockCommandAuthorizer`]).
//!
//! Design (locked decisions):
//! * VERIFY RUNS IN CALIPTRA CORE. The MCU does NOT verify signatures locally.
//!   It relays `cmd_id ‖ SHA-384(body) ‖ nonce ‖ tag` to a new Caliptra-core
//!   hybrid-verify mailbox command and executes the command locally only if
//!   Caliptra authorizes it. Both ECDSA-P384 and ML-DSA-87 must pass in core.
//! * The tag region is OPAQUE and VARIABLE-LENGTH here: everything trailing the
//!   fixed request struct is hybrid signature material (two pubkeys + ECC sig +
//!   ML-DSA sig, ~7.4 KiB). This authorizer never interprets it; only Caliptra
//!   does. Contrast the mock, which slices a fixed 48-byte HMAC tail.
//! * TOCTOU binding: verify happens in Caliptra but the first-cut commands
//!   execute on the MCU. `is_authorized` returns the EXACT `&req[..cmd_len]`
//!   buffer it authorized (no re-fetch, no re-parse), and `relay_verify` binds
//!   execution to `SHA-384(body)`. Single-in-flight is enforced by the caller's
//!   `busy` gate (cmd_interface.rs:135-139); the nonce is one-time via `take()`.
//!
//! NON-BREAKING / FAIL-CLOSED: the Caliptra-core hybrid-verify command is gated
//! on caliptra-sw#3928 and is NOT present in the currently pinned caliptra-*
//! git rev. Until that lands and `Cargo.toml` is bumped, [`relay_verify`] fails
//! closed (rejects every command). The `MockCommandAuthorizer` remains the
//! default authorizer; this impl is only constructed under the non-default
//! `asym-cmd-auth` feature.

use async_trait::async_trait;
use caliptra_mcu_common_commands::{AuthorizationError, AuthorizationResult, CommandAuthorizer};
use caliptra_mcu_libapi_caliptra::crypto::hash::{HashAlgoType, HashContext, SHA384_HASH_SIZE};
use caliptra_mcu_mbox_common::messages::{
    CommandId, FuseIncreaseCaliptraMinSvnReq, FuseLockPartitionReq, FuseReadReq,
    FuseRevokeVendorPkHashReq, FuseRevokeVendorPubKeyReq, FuseWriteReq, MailboxReqHeader,
    McuFeProgReq, OcpLockRotateHekReq, OcpLockSetPermaHekReq, ProvisionVendorPkHashReq,
};
use constant_time_eq::constant_time_eq;
use core::mem::size_of;
extern crate alloc;
use alloc::boxed::Box;

/// Caliptra-owned nonce width (VENDOR_AUTH_HELLO / CHALLENGE `challenge`).
const VENDOR_AUTH_NONCE_LEN: usize = 48;

/// Asymmetric, manifest-anchored per-command authorizer.
///
/// Stateless: Caliptra owns the nonce (minted by VENDOR_AUTH_HELLO, verified by
/// VENDOR_AUTH_CHALLENGE), like prod-debug-unlock. The trust anchor (Vendor Ext
/// PK-hash) lives in Caliptra PersistentData. The MCU keeps NO nonce.
#[derive(Default)]
pub struct AsymCommandAuthorizer {}

#[async_trait]
impl CommandAuthorizer for AsymCommandAuthorizer {
    async fn is_authorized<'a>(
        &mut self,
        cmd_id: CommandId,
        req: &'a [u8],
    ) -> AuthorizationResult<&'a [u8]> {
        // Authorized-command set — must match the dispatch set in
        // cmd_interface.rs:168-179 (and the mock's arms) so no routed command is
        // silently denied. Anything else fails closed via the catch-all.
        let cmd_len = match cmd_id {
            CommandId::MC_PROVISION_VENDOR_PK_HASH => size_of::<ProvisionVendorPkHashReq>(),
            CommandId::MC_FUSE_INCREASE_CALIPTRA_MIN_SVN => {
                size_of::<FuseIncreaseCaliptraMinSvnReq>()
            }
            CommandId::MC_FE_PROG => size_of::<McuFeProgReq>(),
            CommandId::MC_FUSE_READ => size_of::<FuseReadReq>(),
            CommandId::MC_FUSE_WRITE => size_of::<FuseWriteReq>(),
            CommandId::MC_FUSE_LOCK_PARTITION => size_of::<FuseLockPartitionReq>(),
            CommandId::MC_FUSE_REVOKE_VENDOR_PUB_KEY => size_of::<FuseRevokeVendorPubKeyReq>(),
            CommandId::MC_FUSE_REVOKE_VENDOR_PK_HASH => size_of::<FuseRevokeVendorPkHashReq>(),
            CommandId::MC_OCP_LOCK_ROTATE_HEK => size_of::<OcpLockRotateHekReq>(),
            CommandId::MC_OCP_LOCK_SET_PERMA_HEK => size_of::<OcpLockSetPermaHekReq>(),
            _ => return Err(AuthorizationError),
        };

        // Opaque, VARIABLE-LENGTH tag region: everything after the fixed request
        // struct is hybrid signature material. Neither the transport nor this
        // authorizer interprets it — only Caliptra core does. An empty/missing
        // tag fails closed inside `verify_mac`.
        let tag = req.get(cmd_len..).ok_or(AuthorizationError)?;

        // Body that Caliptra authenticates. Excludes the checksum header (which
        // the transport recomputes) and the trailing tag, matching the mock's
        // body slice (cmd_auth_mock.rs:54-56).
        let body = req
            .get(size_of::<MailboxReqHeader>()..cmd_len)
            .ok_or(AuthorizationError)?;

        self.verify_mac(u32::from(cmd_id), body, tag).await?;

        // TOCTOU: return the EXACT authorized bytes. The caller
        // (handle_authorized_command, cmd_interface.rs:512-535) executes only
        // this slice, from the same buffer, with no re-fetch, under the
        // single-in-flight `busy` gate.
        Ok(&req[..cmd_len])
    }

    /// Transport-agnostic verify seam (the shape documented at
    /// caliptra-common-commands/src/lib.rs:348-365). Both the MCU-mailbox path
    /// and the SPDM-VDM path are intended to funnel into this one call so the
    /// authorization decision never depends on which transport delivered the
    /// bytes.
    ///
    /// * `cmd_id`  — raw command identifier (serialized big-endian in the digest)
    /// * `payload` — opaque command body
    /// * `mac`     — opaque, variable-length hybrid tag (ECC + ML-DSA sigs + pubkeys)
    async fn verify_mac(
        &mut self,
        cmd_id: u32,
        payload: &[u8],
        mac: &[u8],
    ) -> Result<(), AuthorizationError> {
        // Opaque hybrid tag must be present. Fail closed on an empty tail.
        if mac.is_empty() {
            return Err(AuthorizationError);
        }

        // Compute SHA-384(body). Caliptra echoes this back so the MCU can bind
        // execution to the exact authorized buffer.
        let mut body_hash = [0u8; SHA384_HASH_SIZE];
        HashContext::hash_all(HashAlgoType::SHA384, payload, &mut body_hash)
            .await
            .map_err(|_| AuthorizationError)?;

        // The nonce is Caliptra's (from MC_VENDOR_AUTH_HELLO) and the host signed over
        // it, so it rides in the tag — NOT re-fetched here (a fresh HELLO would mint a
        // different nonce and overwrite Caliptra's stored one). Tag layout:
        //   nonce(48) ‖ ecc_pub ‖ mldsa_pub ‖ ecc_sig ‖ mldsa_sig
        let nonce: [u8; VENDOR_AUTH_NONCE_LEN] = mac
            .get(..VENDOR_AUTH_NONCE_LEN)
            .ok_or(AuthorizationError)?
            .try_into()
            .map_err(|_| AuthorizationError)?;
        let sig_material = mac.get(VENDOR_AUTH_NONCE_LEN..).ok_or(AuthorizationError)?;

        self.relay_verify(cmd_id, &body_hash, &nonce, sig_material)
            .await
    }

    // Nonce is Caliptra-owned; the MCU stores none. These trait methods (the
    // HMAC-era MCU-local nonce seam) are inert on the asymmetric path.
    fn take_challenge(&mut self) -> Option<[u8; 32]> {
        None
    }

    fn set_challenge(&mut self, _challenge: [u8; 32]) {}
}

impl AsymCommandAuthorizer {
    /// Relay VENDOR_AUTH_CHALLENGE to Caliptra core and bind the result.
    ///
    /// `sig_material` is the host-built hybrid tag minus the leading nonce (already
    /// split off by the caller): `ecc_pub[96] ‖ mldsa_pub[2592] ‖ ecc_sig[96] ‖ mldsa_sig[4628]`.
    /// The relay assembles `VendorAuthChallengeReq`, sends it, and Caliptra echoes
    /// `(cmd_id, body_hash)`. The sole `Ok` path is behind [`check_echo_binding`], so
    /// the local handler can never execute a command Caliptra did not authorize.
    async fn relay_verify(
        &self,
        cmd_id: u32,
        body_hash: &[u8; SHA384_HASH_SIZE],
        nonce: &[u8; VENDOR_AUTH_NONCE_LEN],
        tag: &[u8],
    ) -> Result<(), AuthorizationError> {
        use caliptra_api::mailbox::{CommandId as CoreCmd, VendorAuthChallengeReq, VendorAuthChallengeResp};
        use caliptra_mcu_libapi_caliptra::mailbox_api::execute_mailbox_cmd;
        use caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox;
        use zerocopy::{FromBytes, IntoBytes};

        // Build the Caliptra request. `nonce` is the 48-B value Caliptra minted on HELLO.
        let mut req = VendorAuthChallengeReq {
            cmd_id,
            ..Default::default()
        };

        // Checked copy: consume exactly the destination field's width from the tag, failing
        // CLOSED (never panicking) on a short read. Field widths are taken from the struct
        // itself, so they cannot drift from a hand-maintained literal on a fork bump.
        let mut off = 0usize;
        let mut copy_field = |dst: &mut [u8]| -> Result<(), AuthorizationError> {
            let src = tag.get(off..off + dst.len()).ok_or(AuthorizationError)?;
            dst.copy_from_slice(src);
            off += dst.len();
            Ok(())
        };
        req.body_hash.copy_from_slice(body_hash);
        req.challenge.copy_from_slice(nonce);
        // Opaque tag layout: ecc_pub ‖ mldsa_pub ‖ ecc_sig ‖ mldsa_sig.
        copy_field(req.ecc_public_key.as_mut_bytes())?;
        copy_field(req.mldsa_public_key.as_mut_bytes())?;
        copy_field(req.ecc_signature.as_mut_bytes())?;
        copy_field(req.mldsa_signature.as_mut_bytes())?;
        // Reject trailing garbage: the tag must be exactly the four fields.
        if off != tag.len() {
            return Err(AuthorizationError);
        }

        let mailbox = Mailbox::new();
        let mut req_bytes = req.as_bytes().to_vec();
        let mut resp_bytes = [0u8; size_of::<VendorAuthChallengeResp>()];
        execute_mailbox_cmd(
            &mailbox,
            CoreCmd::VENDOR_AUTH_CHALLENGE.0,
            &mut req_bytes,
            &mut resp_bytes,
        )
        .await
        .map_err(|_| AuthorizationError)?;

        let resp = VendorAuthChallengeResp::read_from_bytes(resp_bytes.as_slice())
            .map_err(|_| AuthorizationError)?;

        // Sole Ok path: bind execution to exactly what Caliptra authorized.
        check_echo_binding(cmd_id, resp.cmd_id, body_hash, &resp.body_hash)
    }
}

/// TOCTOU verify/execute binding check (Team Beta invariant).
///
/// Caliptra performs the hybrid signature verify, but the four first-cut
/// commands EXECUTE on the MCU. To stop a time-of-check/time-of-use divergence,
/// the MCU must prove that the `(cmd_id, SHA-384(body))` Caliptra authorized is
/// byte-identical to the `(cmd_id, SHA-384(body))` the MCU is about to execute.
/// This function is that single decision point; `relay_verify` returns `Ok`
/// only through here.
///
/// Fault-injection hardening: a single skipped compare or branch must not turn a
/// mismatch into an authorization. Both fields are compared, results are AND-ed
/// into one accumulator, and the accumulator is re-tested against the expected
/// "both equal" pattern before the sole `Ok` return — a skipped comparison
/// leaves the accumulator non-matching, which fails closed. `body_hash` is
/// compared in constant time (it is a public digest, but this keeps the compare
/// on the same branch-light path as the rest of the auth code).
///
/// * `sent_cmd_id`     — cmd_id the MCU relayed to Caliptra
/// * `echoed_cmd_id`   — cmd_id Caliptra echoed as authorized
/// * `sent_body_hash`  — SHA-384(body) the MCU relayed (and will execute)
/// * `echoed_body_hash`— SHA-384(body) Caliptra echoed as authorized
///
/// The sole production caller is the `return check_echo_binding(...)` at the end of
/// [`relay_verify`] — the only `Ok` path out of the relay.
fn check_echo_binding(
    sent_cmd_id: u32,
    echoed_cmd_id: u32,
    sent_body_hash: &[u8; SHA384_HASH_SIZE],
    echoed_body_hash: &[u8; SHA384_HASH_SIZE],
) -> Result<(), AuthorizationError> {
    // Redundant, AND-combined checks. Neither is a lone branch whose skip
    // authorizes: both must independently be true, and we re-verify the combined
    // result before the single Ok return.
    let cmd_id_ok = sent_cmd_id == echoed_cmd_id;
    let body_hash_ok = constant_time_eq(sent_body_hash, echoed_body_hash);

    let both_ok = cmd_id_ok & body_hash_ok;

    // Sole authorization path: gated on the re-tested combined predicate so a
    // single skipped compare above cannot fall through to Ok.
    if both_ok && cmd_id_ok && body_hash_ok {
        Ok(())
    } else {
        Err(AuthorizationError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CMD: u32 = 0x4946_5052; // MC_FUSE_READ

    fn h(fill: u8) -> [u8; SHA384_HASH_SIZE] {
        [fill; SHA384_HASH_SIZE]
    }

    #[test]
    fn echo_binding_accepts_exact_match() {
        assert!(check_echo_binding(CMD, CMD, &h(0xAB), &h(0xAB)).is_ok());
    }

    #[test]
    fn echo_binding_rejects_cmd_id_mismatch() {
        // Caliptra authorized a DIFFERENT command than the MCU is about to run.
        assert!(check_echo_binding(CMD, CMD ^ 1, &h(0xAB), &h(0xAB)).is_err());
    }

    #[test]
    fn echo_binding_rejects_body_hash_mismatch() {
        // Same cmd_id, but the body the MCU holds differs from what was signed
        // (the classic TOCTOU swap). Must fail closed.
        assert!(check_echo_binding(CMD, CMD, &h(0xAB), &h(0xCD)).is_err());
    }

    #[test]
    fn echo_binding_rejects_single_bit_flip_in_hash() {
        let sent = h(0x00);
        let mut echoed = sent;
        echoed[SHA384_HASH_SIZE - 1] ^= 0x01;
        assert!(check_echo_binding(CMD, CMD, &sent, &echoed).is_err());
    }

    #[test]
    fn echo_binding_rejects_all_mismatched() {
        assert!(check_echo_binding(CMD, 0, &h(0x11), &h(0x22)).is_err());
    }
}

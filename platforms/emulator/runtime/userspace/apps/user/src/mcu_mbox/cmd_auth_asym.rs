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
    CommandId, FuseLockPartitionReq, FuseReadReq, FuseWriteReq, MailboxReqHeader,
    ProvisionVendorPkHashReq,
};
use constant_time_eq::constant_time_eq;
use core::mem::size_of;
extern crate alloc;
use alloc::boxed::Box;

/// Placeholder for the Caliptra-core hybrid-verify mailbox command code.
///
/// TODO(caliptra-sw#3928 / Team Alpha PR3): replace with the real
/// `CommandId` + request/response structs from `caliptra-sw`
/// (`api/src/mailbox.rs`) once they land and the pinned caliptra-* git rev is
/// bumped in `Cargo.toml`. Referenced only from [`AsymCommandAuthorizer::relay_verify`].
#[allow(dead_code)]
const CORE_HYBRID_VERIFY_CMD_PENDING: u32 = 0;

/// Asymmetric, manifest-anchored per-command authorizer.
///
/// Holds only the one-time challenge nonce; the trust root (the Vendor Ext
/// PK-hash `SHA-384(ECC_pub ‖ MLDSA_pub)`) lives in Caliptra `PersistentData`,
/// NOT here.
#[derive(Default)]
pub struct AsymCommandAuthorizer {
    challenge: Option<[u8; 32]>,
}

#[async_trait]
impl CommandAuthorizer for AsymCommandAuthorizer {
    async fn is_authorized<'a>(
        &mut self,
        cmd_id: CommandId,
        req: &'a [u8],
    ) -> AuthorizationResult<&'a [u8]> {
        // First-cut command set (re-provision + in-field fuse ops). This closes
        // the FUSE_READ/WRITE/LOCK_PARTITION gap that the mock leaves rejected
        // (cmd_auth_mock.rs:39-50 has no arms for them). Every other command
        // fails closed via the catch-all below.
        let cmd_len = match cmd_id {
            CommandId::MC_PROVISION_VENDOR_PK_HASH => size_of::<ProvisionVendorPkHashReq>(),
            CommandId::MC_FUSE_READ => size_of::<FuseReadReq>(),
            CommandId::MC_FUSE_WRITE => size_of::<FuseWriteReq>(),
            CommandId::MC_FUSE_LOCK_PARTITION => size_of::<FuseLockPartitionReq>(),
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
        // Consume the challenge nonce (one-time use). No nonce -> fail closed.
        let nonce = self.challenge.take().ok_or(AuthorizationError)?;

        // Opaque hybrid tag must be present. Fail closed on an empty tail.
        if mac.is_empty() {
            return Err(AuthorizationError);
        }

        // Compute SHA-384(body). This is the value Caliptra must echo back so
        // the MCU can bind execution to the exact authorized buffer.
        let mut body_hash = [0u8; SHA384_HASH_SIZE];
        HashContext::hash_all(HashAlgoType::SHA384, payload, &mut body_hash)
            .await
            .map_err(|_| AuthorizationError)?;

        // Relay to Caliptra-core hybrid verify. Fails closed until the core
        // command lands (see `relay_verify`).
        self.relay_verify(cmd_id, &body_hash, &nonce, mac).await
    }

    fn take_challenge(&mut self) -> Option<[u8; 32]> {
        self.challenge.take()
    }

    fn set_challenge(&mut self, challenge: [u8; 32]) {
        self.challenge = Some(challenge);
    }
}

impl AsymCommandAuthorizer {
    /// Relay the hybrid-verify request to Caliptra core and enforce the TOCTOU
    /// echo check.
    ///
    /// Wire contract (Team Alpha, gated on caliptra-sw#3928):
    /// * request  = `cmd_id(BE,4) ‖ body_hash(48) ‖ nonce(32) ‖ tag(opaque)`
    /// * response = the authorized `(cmd_id, SHA-384(body))` echoed back
    ///
    /// On success the relay MUST verify the echoed `cmd_id` and `body_hash`
    /// are byte-identical to the values sent here BEFORE returning `Ok`; any
    /// mismatch is a fail-closed error so the local handler never executes a
    /// command Caliptra did not authorize. That check is factored out into
    /// [`check_echo_binding`] so it is a single, testable, fail-closed decision
    /// that the wiring below physically cannot bypass (the only `Ok(())` return
    /// path in this function is behind it).
    ///
    /// FAIL-CLOSED STUB: the Caliptra-core command does not exist in the pinned
    /// caliptra-* rev yet, so there is no authoritative echo to bind against.
    /// This returns `Err` unconditionally. When PR3 lands and the rev is bumped,
    /// replace the marked block with an
    /// `execute_mailbox_cmd(&Mailbox::new(), <real CommandId>, req, resp)` call
    /// (same relay mechanism as `handle_crypto_passthrough`,
    /// cmd_interface.rs:485-504) that parses the echoed `(cmd_id, body_hash)`
    /// out of the response, then feeds them to `check_echo_binding` — do NOT add
    /// any other `Ok` path.
    async fn relay_verify(
        &self,
        cmd_id: u32,
        body_hash: &[u8; SHA384_HASH_SIZE],
        nonce: &[u8; 32],
        tag: &[u8],
    ) -> Result<(), AuthorizationError> {
        // ---- BEGIN Caliptra-core relay (stub until caliptra-sw#3928) --------
        // The real implementation MUST bind execution to what Caliptra
        // authorized. Concretely, after the mailbox round-trip it will parse the
        // echoed identifiers and return exactly:
        //
        //     return check_echo_binding(cmd_id, echoed_cmd_id, body_hash, echoed_body_hash);
        //
        // Until then there is no authoritative echo, so fail closed. All inputs are
        // consumed by the mailbox request / echo check in the real relay.
        let _ = (cmd_id, body_hash, nonce, tag, CORE_HYBRID_VERIFY_CMD_PENDING);
        Err(AuthorizationError)
        // ---- END Caliptra-core relay ---------------------------------------
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
/// Currently exercised only by unit tests; the sole production caller is the
/// `return check_echo_binding(...)` line that lands in [`relay_verify`] when the
/// Caliptra-core command (caliptra-sw#3928) is wired in. `allow(dead_code)` so
/// the pre-cutover firmware build stays warning-clean (mirrors
/// `CORE_HYBRID_VERIFY_CMD_PENDING`).
#[allow(dead_code)]
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

All anchors verified against current code. Producing the plan.

---

# Removing dummy-HMAC command-auth → asymmetric (ECDSA-P384 + ML-DSA-87) manifest-anchored auth

*caliptra-mcu-sw @ `raunakgupta/vendor-auth`. Every file:line below re-verified against the working tree.*

## 1. Scope & end-state

After this work there is **zero HMAC command-authentication in the MCU-mailbox path**: `AsymCommandAuthorizer` is the *only* authorizer, selected unconditionally (no `asym-cmd-auth` feature gate). `MockCommandAuthorizer`, its HMAC-SHA384 `verify_mac`, and **both** in-firmware copies of `TEST_AUTH_CMD_HMAC_KEY` (mailbox authorizer `cmd_auth_mock.rs:21`, test orchestrator `tests/integration/src/runtime/mod.rs:19`) are deleted. The MCU-local freshness nonce (`MC_GET_AUTH_CMD_CHALLENGE` / `set_challenge` / `take_challenge`) is gone; freshness is Caliptra-owned via `MC_VENDOR_AUTH_HELLO`. The asym authorizer authorizes the **full 10-command set** (parity with the old mock) before it becomes the default. The **SPDM-VDM FE_PROG HMAC path** and its **third key copy** (`spdm/caliptra_vdm.rs:42`) + **host key mirror** (`apps/spdm/test-config.toml:33`) are handled explicitly (P6) — either converted or consciously staged, never silently left live-and-forgotten.

## 2. Hard blockers (must clear before P3–P7 can land on `main-2.1`)

**B1 — Fork-branch pin (blocks the default flip, and blocks *any* off-fork build).**
`Cargo.toml:358-383` pins all 24 `caliptra-*` crates to `branch = "raunakgupta/vendor-auth"` on the RaunakGu fork (mutable branch, `Cargo.lock` rev `5e6a161b`, fork head already drifted to `77bf8af9`). This is the sole source of `VENDOR_AUTH_HELLO` / `VENDOR_AUTH_CHALLENGE`.
Critical nuance (verified): off-fork compilation **already fails today**, independent of the asym flip — `cmd_interface.rs:498-503` (`handle_vendor_auth_hello`) references `caliptra_api::mailbox::{VendorAuthHelloReq, CommandId::VENDOR_AUTH_HELLO}` *unconditionally* (`pub mod cmd_interface`, no cfg). Flipping asym-to-default only *adds* the `VENDOR_AUTH_CHALLENGE` coupling (`cmd_auth_asym.rs:160,198`) to the default build surface.
**Blocks:** merging P3/P4 (and truly the whole feature) to `main-2.1`.
**Gate to clear:** (a) land `caliptra-sw#3928` + the vendor-auth PR into `chipsalliance/caliptra-sw`; (b) re-point all 24 pins from the fork *branch* to the single upstream-merged **immutable rev** (leave the two `caliptra-cfi-*` chipsalliance pins at `Cargo.toml:363-364` untouched); (c) `cargo update` to rebuild `Cargo.lock`; (d) delete `VENDOR_AUTH_FORK_PIN_REVERT.md`.

**B2 — No asym VDM relay exists (blocks retiring VDM HMAC).**
The SPDM-VDM FE_PROG path (`spdm/caliptra_vdm.rs:230 verify_fe_prog_mac`) verifies HMAC **terminally on the MCU** and then calls plain unauthenticated Caliptra FE_PROG. There is **no** `VENDOR_AUTH_HELLO`/`CHALLENGE` relay on the VDM transport (grep confirms zero hits), the nonce is MCU-local 32 B (vs Caliptra's 48 B), and the fixed `4 + 48` framing gate (`authorized_command.rs:78`) plus its characterization tests (`caliptra_vdm/mod.rs:663-788`) are baked into the shared transport-agnostic lib. A ~7.5 KiB hybrid tag also exceeds the 4 KiB VDM envelope (`mod.rs:28-31`).
**Blocks:** converting VDM to asym in lockstep with the mailbox path.
**Gate to clear:** build a net-new Caliptra VDM `VENDOR_AUTH_CHALLENGE` relay + resize the VDM envelope + rewrite the framing tests. This is materially larger than the mailbox conversion → **staged separately (P6), does not block P1–P5/P7.**

## 3. Ordered phases (each = one commit)

### P1 — Close the asym allowlist gap 4 → 10 (PREREQUISITE; do first, doable NOW on fork)

**Why:** `cmd_auth_asym.rs:64-70` authorizes only 4 IDs (`MC_PROVISION_VENDOR_PK_HASH`, `MC_FUSE_READ/WRITE/LOCK_PARTITION`) — a strict *subset* of the mock's 10 (`cmd_auth_mock.rs:40-51`). The dispatcher (`cmd_interface.rs:168-179`) routes **all 10** to `handle_authorized_command → is_authorized`. If the flip (P3) happens first, the 6 missing IDs — `MC_FUSE_INCREASE_CALIPTRA_MIN_SVN`, `MC_FE_PROG`, `MC_FUSE_REVOKE_VENDOR_PUB_KEY`, `MC_FUSE_REVOKE_VENDOR_PK_HASH`, `MC_OCP_LOCK_ROTATE_HEK`, `MC_OCP_LOCK_SET_PERMA_HEK` — silently fail closed at the catch-all (`cmd_auth_asym.rs:69`). These are the SVN-burn, field-entropy, key-revocation and HEK commands — the most security-critical ones.

**Edits (`platforms/emulator/runtime/userspace/apps/user/src/mcu_mbox/cmd_auth_asym.rs`):**
- Add the 6 arms to the `match cmd_id` at lines 64-70, each mapping to `size_of::<…Req>()` exactly as the mock does: `FuseIncreaseCaliptraMinSvnReq`, `McuFeProgReq`, `FuseRevokeVendorPubKeyReq`, `FuseRevokeVendorPkHashReq`, `OcpLockRotateHekReq`, `OcpLockSetPermaHekReq`.
- Extend the `use caliptra_mcu_mbox_common::messages::{…}` import at lines 33-36 to bring in those 6 request types (mirror the mock's import list at `cmd_auth_mock.rs:6-10`).
- **Fix the stale/inverted comment at lines 60-63** — it claims asym "closes the FUSE_READ/WRITE/LOCK_PARTITION gap that the mock leaves rejected (cmd_auth_mock.rs:39-50 has no arms for them)." This is **false**: the mock *does* have those arms (lines 45-47). Replace with an accurate statement that asym now matches the mock's full 10-command set.

**Acceptance:** `cargo build -p …user --features test-mcu-mbox-cmds,asym-cmd-auth` compiles. Ideally add per-ID unit coverage or rely on P2 e2e. No behavior change to the default (still mock) build.

### P2 — Harden asym e2e coverage before trusting it as the only path (NOW on fork)

**Why:** After P4 there is no HMAC fallback; the asym suite becomes the sole gate. The 5 existing tests (`test_vendor_auth_asym.rs`) cover happy-path, wrong-key, replay, tampered-body, and bad-ML-DSA-only — but only for `MC_FUSE_READ`, and there is **no anchor-not-enrolled control** proving auth fails when Caliptra holds no anchor.

**Edits:**
- Add an **anchor-not-enrolled negative control** in `test_vendor_auth_asym.rs`: boot without `with_vendor_cmd_auth_pk_hash(...)` (drop the `.with_vendor_cmd_auth_pk_hash` call in a variant of `build_fw_with_anchor`, ~line 78), then assert a correctly-signed `execute_authorized_req_asym` is **rejected**. This proves the anchor gate is load-bearing (guards against a "verify always passes" regression).
- Add **positive controls for the P1-added commands** on at least one non-`FUSE_READ`, no-side-effect ID (e.g. a `MC_FUSE_READ`-style positive plus one authorize-only check on `MC_FUSE_INCREASE_CALIPTRA_MIN_SVN` value 0) to prove the 6 new arms actually authorize, not just compile.

**Acceptance:** `cargo test -p caliptra-runtime-integration-tests --test … test_vendor_auth_asym` (per memory: the asym suite runs green 5/5 on hw-model) now passes with the added controls on the **fork rev**.

### P3 — Flip the default authorizer mock → asym (GATED on B1)

**Why:** This is the cutover. Type-erased seam (`&mut dyn CommandAuthorizer`, `mod.rs:56-61`) makes it a one-line binding change.

**Edits:**
- `mcu_mbox/mod.rs:49-52` — delete lines 49-50 (the `#[cfg(not(feature="asym-cmd-auth"))]` mock binding) and strip the `#[cfg(feature="asym-cmd-auth")]` attribute on line 51 so `let mut cmd_authorizer = cmd_auth_asym::AsymCommandAuthorizer::default();` is unconditional. Update the CUTOVER comment (42-48).
- `mcu_mbox/mod.rs:3` — loosen the asym-module gate from `#[cfg(all(feature="mcu-mbox-service", feature="asym-cmd-auth"))]` to `#[cfg(feature="mcu-mbox-service")]`.
- `platforms/emulator/runtime/userspace/apps/user/Cargo.toml:70` — add `"asym-cmd-auth"` to the `all-features` list (so `default = ["all-features"]` pulls asym). Kernel stub `platforms/emulator/runtime/Cargo.toml:96 asym-cmd-auth = []` stays as-is (harmless no-op; leave it so the shared feature string still forwards).

**Do NOT do this on `main-2.1` until B1 is cleared** — flipping while pinned to the fork makes the default (all-features) build fork-only and removes the fail-closed HMAC fallback before asym is proven against the *upstream* command shape.

**Acceptance:** default build (`cargo build -p …user`, all-features) compiles; P2 asym suite green; a smoke run of one authorized command (`MC_FUSE_READ`) through the daemon authorizes and executes.

### P4 — Delete `MockCommandAuthorizer` + mailbox `TEST_AUTH_CMD_HMAC_KEY` (GATED on B1; must follow P3)

**Why:** Removes the hardcoded symmetric secret (image-extraction forgery risk) and all HMAC crypto from the mailbox authorizer. Safe only once asym is the sole binding (P3) and at parity (P1).

**Edits:**
- Delete the entire file `mcu_mbox/cmd_auth_mock.rs` (107 lines) — removes the struct, the 10-arm match, HMAC `verify_mac`, the `Hmac`/`Import`/`CmKeyUsage` imports (lines 4-5), and `TEST_AUTH_CMD_HMAC_KEY` (21-25) in one edit.
- `mcu_mbox/mod.rs:5-6` — delete the `#[cfg(feature="mcu-mbox-service")] pub(crate) mod cmd_auth_mock;` declaration.
- **Do NOT touch** `cmd_handler_mock` (`mod.rs:7-8`, `NonCryptoCmdHandlerMock`) — it is a separate non-crypto command *handler*, still referenced at `mod.rs:37`. Not part of the HMAC surface.

**Acceptance:** `grep -r "MockCommandAuthorizer\|TEST_AUTH_CMD_HMAC_KEY\|cmd_auth_mock" platforms/emulator/runtime` returns nothing; user-app builds; asym suite green.

### P5 — Retire the HMAC-era nonce seam: `MC_GET_AUTH_CMD_CHALLENGE` + `set_challenge`/`take_challenge` (single commit; GATED on B1, bundle with P4)

**Why:** With the mock gone, `set_challenge` has no functional user (asym's is a no-op) and `take_challenge` was already dead trait API (zero `.take_challenge(` callers repo-wide). `MC_GET_AUTH_CMD_CHALLENGE` mints the MCU-local nonce the mock consumed — obsolete under Caliptra-owned nonces. Removing `set_challenge`/`MC_GET_AUTH_CMD_CHALLENGE` is only safe once the mock is dead, hence bundled with P4 (or immediately after).

**Edits (all in one commit, else the exhaustive matches won't compile):**
- Trait `runtime/userspace/api/caliptra-common-commands/src/lib.rs` — delete `take_challenge` (367-370) and `set_challenge` (372-373). **Keep** `is_authorized` (342) and `verify_mac` (360) — both still used by asym's `is_authorized → self.verify_mac` (`cmd_auth_asym.rs:85`).
- Asym impl `cmd_auth_asym.rs:136-142` — delete the two inert stub methods.
- Dispatch `mcu-mbox-lib/src/cmd_interface.rs` — delete the `MC_GET_AUTH_CMD_CHALLENGE` match arm (162-164), delete `handle_get_auth_cmd_challenge` (467-486, the sole `set_challenge` caller at 483), and drop the now-unused `GetAuthCmdChallengeReq/Resp` imports. **Keep** `MC_VENDOR_AUTH_HELLO` (165-167, 490-518) and the authorized-command arm (168-179).
- Messages `common/mcu-mbox/src/messages.rs` — delete the const (130), the `GetAuthCmdChallengeReq/Resp` structs + impls (1462-1483), the `McuMailboxReq::GetAuthCmdChallenge` variant (210) and its arms (272, 332, 394), and the `McuMailboxResp::GetAuthCmdChallenge` variant (477) and its arms (598, 657).

**Acceptance:** `grep -r "GetAuthCmdChallenge\|MC_GET_AUTH_CMD_CHALLENGE\|set_challenge\|take_challenge" runtime common platforms` returns nothing (except the deliberately-separate SPDM-VDM `GET_AUTH_CHALLENGE_CMD_ID` handled in P6); workspace compiles; asym suite green. **Compiler tripwire:** the in-repo integration tests break here (they still use `GetAuthCmdChallengeReq`) — that is expected and resolved in P7.

### P6 — SPDM-VDM path: stage separately with explicit rationale (GATED on B2)

**Why:** Independent trait (`CaliptraVdmCommands`), separate dispatch, separate 32 B nonce store (`caliptra_vdm.rs:48`), separate key copy (`caliptra_vdm.rs:42`), separate verifier (`verify_fe_prog_mac`, 230). The Rust compiler will **not** flag it when P4/P5 delete the mailbox `CommandAuthorizer` HMAC — it is a different crate. FE_PROG is the only VDM-reachable authorized action.

**Decision for this commit: STAGE, do not convert now** (blocked on B2). Concrete actions:
- Add a tracking marker (a `// TODO(vendor-auth-VDM):` at `caliptra_vdm.rs:230` and `authorized_command.rs:16`) referencing this plan and B2, so the VDM HMAC surface is not mistaken for live/forgotten dead code.
- Leave `spdm/caliptra_vdm.rs` (key at 42, nonce static at 48, `verify_fe_prog_mac` at 230), the shared-lib framing (`authorized_command.rs:78`, `caliptra_vdm/mod.rs` trait 84-98), the characterization tests (`caliptra_vdm/mod.rs:663-788`), and the host mirror (`test-config.toml:33`, `apps/spdm/client/src/main.rs:119-125`) intact **and functional**.
- **Do NOT** delete the shared host `HmacCommandAuthorizer` (`common/command-auth-challenge-signer/src/lib.rs`) yet — it still backs the VDM host path (`apps/spdm/client/src/validator.rs:395`) and the mailbox host validator (see P7). The asym building blocks already exist beside it (`vendor_auth.rs`: `LocalVendorAuthSigner`/`VendorAuthSigner`/`VendorAuthTag`).

Full VDM conversion (net-new Caliptra VDM relay, 32→48 B Caliptra nonce, `4+48`→variable framing, envelope resize, tests rewrite) is a **follow-up feature after B2**, not this series.

**Acceptance:** VDM path still builds and the SPDM-VDM validator's FE_PROG sub-test still passes (unchanged); markers present.

### P7 — Delete HMAC test orchestrator + convert/retire HMAC tests (GATED on B1; last)

**Why:** `execute_authorized_req` + helpers are the compile-time tripwire; convert callers first, delete the orchestrator last (single Cargo test crate — even `#[ignore]` tests must compile).

**Edits (`tests/integration/`):**
- **Convert to asym (10 call sites):** `test_mcu_mailbox.rs` (139/177/216/272), `test_revoke_vendor_pub_key.rs` (74/84/94/161/171/236/249/257), `test_increase_caliptra_svn.rs` (75/84/92/100/107/161/255). Swap `execute_authorized_req` → `execute_authorized_req_asym`, and rework each test's boot block to the asym harness (`build_fw_with_anchor`/`boot` from `test_vendor_auth_asym.rs`: `--features test-mcu-mbox-cmds,asym-cmd-auth` + v2 SoC-manifest anchor + `LocalVendorAuthSigner`). This is **not** a 1-line identifier swap — each `start_runtime_hw_model` param block changes.
- **Delete** `test_mcu_mailbox.rs:63 test_get_auth_cmd_challenge_cmd` — it tests the removed `MC_GET_AUTH_CMD_CHALLENGE`; nonce coverage already lives in `test_vendor_auth_asym_replayed_nonce_rejected`.
- **Delete** the HMAC orchestrator + helpers in `runtime/mod.rs`: `TEST_AUTH_CMD_HMAC_KEY` (19), `get_auth_cmd_challenge` (25), `sign_auth_cmd_challenge` (31), `authorize_cmd` (43), `execute_authorized_req` (118), and the now-unused `hmac`/`sha2`/`GetAuthCmdChallengeReq` imports (8, 10-11). **Keep** the asym twins (`build_asym_authorized_cmd` 64, `execute_authorized_req_asym` 91, `get_vendor_auth_nonce` 52) and the 5 `test_vendor_auth_asym.rs` tests unchanged.
- **Host-validator caveat (do not silently drop):** `test_caliptra_util_host_mcu_mailbox_validator.rs:205-207` references `crate::runtime::TEST_AUTH_CMD_HMAC_KEY` via `HmacCommandAuthorizer::new` — and `caliptra-util-host` has **no** `AsymCommandAuthorizer` yet (host asym gap confirmed). It cannot be mechanically converted. Minimum: inline/relocate the 48-byte constant into that `#[ignore]` test (or feature-gate the file) so deleting `mod.rs:19` doesn't break the crate's compile. Flag full host-asym conversion as a follow-up (paired with P6's host side).

**Acceptance:** `cargo test -p …integration --no-run` compiles the whole crate; converted mailbox tests pass on the upstream-merged rev; no reference to `TEST_AUTH_CMD_HMAC_KEY`/`execute_authorized_req`/`GetAuthCmdChallengeReq` remains except the one intentionally-retained host-validator constant.

## 4. NOW (fork branch) vs. gated on upstream-merge/unpin

**Doable NOW on `raunakgupta/vendor-auth` (fork rev has both VENDOR_AUTH_HELLO+CHALLENGE; asym e2e green):**
- **P1** (allowlist 4→10 + stale-comment fix) — pure edit to a file already compiled only under `asym-cmd-auth` (fork-only anyway).
- **P2** (harden asym tests: anchor-not-enrolled + positive controls) — runs against the fork rev.
- **P6 markers** — comment-only.

These are safe to commit on the fork branch now because they change **no default behavior** and add **no new default fork coupling** (asym module is still feature-gated until P3).

**GATED on B1 (upstream merge + immutable-rev re-pin + `Cargo.lock` rebuild + delete `VENDOR_AUTH_FORK_PIN_REVERT.md`) before merging to `main-2.1`:**
- **P3** (default flip), **P4** (delete mock+key), **P5** (retire nonce-seam trait methods + `MC_GET_AUTH_CMD_CHALLENGE`), **P7** (delete HMAC orchestrator + convert tests). All four make asym (and its `VENDOR_AUTH_CHALLENGE` relay) part of the **default** build surface, which is fork-only until upstream lands.

**GATED on B2 (net-new Caliptra VDM relay + envelope/framing rework):**
- **P6 full conversion** — the actual removal of `verify_fe_prog_mac`, the VDM key copy, and the host FE_PROG HMAC. Staged as a follow-up; does not block P1–P5/P7.

**Dependency order:** P1 → P2 → **[B1]** → P3 → P4 → P5 → P7; P6 runs independently behind **[B2]**.

## 5. Risk callouts (things that could silently reduce security)

- **[P1, highest] Silent authorization loss for 6 critical commands.** Flipping default (P3) before P1 lands strands `MC_FUSE_INCREASE_CALIPTRA_MIN_SVN`, `MC_FE_PROG`, `MC_FUSE_REVOKE_VENDOR_PUB_KEY`, `MC_FUSE_REVOKE_VENDOR_PK_HASH`, `MC_OCP_LOCK_ROTATE_HEK`, `MC_OCP_LOCK_SET_PERMA_HEK` — they hit asym's catch-all (`cmd_auth_asym.rs:69`) and fail closed with a generic `AuthorizationError`. No compile error, no obvious signal: SVN-burn, field-entropy, key-revocation and HEK rotation just stop working. **P1 must precede P3.**
- **[B2/P6] VDM left on HMAC.** If P4/P5 delete the mailbox HMAC and nobody revisits VDM, FE_PROG over SPDM-VDM keeps a hardcoded 48-byte symmetric key (`caliptra_vdm.rs:42`) that image extraction forges — and the compiler never warns (separate crate/trait). The P6 markers exist specifically so this is not forgotten. Worse trap: deleting `verify_fe_prog_mac` *without* first wiring the Caliptra VDM relay would leave FE_PROG **unauthenticated** — a privilege-escalation hole. Order within any future P6: build relay first, delete local verifier last.
- **[P3/P4] Loss of fail-closed fallback validated only on the fork.** The `mod.rs:43-48` gate requires the asym HELLO/CHALLENGE e2e green **on the upstream-merged rev**, not just the fork. If the upstream command shape differs (`VendorAuthChallengeReq`/`Resp` field order/width), asym silently fails closed on every command and there is no mock to fall back to. Re-run P2 against the re-pinned upstream rev before P4.
- **[P5] Dropped nonce freshness if mis-sequenced.** `set_challenge`/`MC_GET_AUTH_CMD_CHALLENGE` are the mock's *only* freshness source (`verify_mac` consumes `self.challenge.take()`). Removing them while the mock is still selectable (before P3/P4) makes the mock fail closed on every command — not a security *hole*, but a silent DoS. Keep P5 bundled with/after P4. Asym freshness is unaffected (Caliptra-owned nonce rides in the tag; the two stubs it deletes are already inert).
- **[P7 host-validator] Silent coverage drop.** `caliptra-util-host` has no asym authorizer, so the UDP-to-mailbox host validator (`test_caliptra_util_host_mcu_mailbox_validator.rs`) and the SPDM-VDM validator cannot convert. Deleting the key without relocating its reference breaks compile of the whole `#[ignore]`d test crate; blanket-deleting the tests instead would quietly drop the only host-side FE_PROG-over-UDP / FE_PROG-over-VDM coverage. Retain (feature-gate/inline the constant), do not delete.
- **[B1 supply chain] Mutable branch pin.** The pin is by *branch*, and the fork head has already drifted (`5e6a161b` locked vs `77bf8af9` head). A stray `cargo update` today silently moves the lock on a security-critical auth path. The immutable-rev re-pin in B1 is part of the fix, not just a URL change.
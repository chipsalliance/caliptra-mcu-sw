# Vendor-Auth — End-to-End Testing Guide

How to run and understand the full asymmetric vendor-command-authentication e2e
(host → MCU → Caliptra), and the Caliptra-core verify tests it pairs with.

## TL;DR

```bash
# MCU-side full asym e2e (host → MCU relay → Caliptra hybrid verify → execute):
cd /users/ssdrive/calipta_root/caliptra-mcu-sw
cargo test -p caliptra-mcu-tests-integration --lib -- \
  test_vendor_auth_asym --nocapture --test-threads=1        # 5/5

# Caliptra-core verify tests (the signature verification, on the hw-model):
cd /users/ssdrive/calipta_root/caliptra-sw
cargo test -p caliptra-runtime --test runtime_integration_tests test_vendor_auth   # 12/12
```

## Full verified command set (after the HMAC→asym cutover)

All authorized-command tests now use the asymmetric path. Run them **individually**
(`--test-threads=1`, one test filter at a time) — see the rom_only caveat below.

```bash
cd /users/ssdrive/calipta_root/caliptra-mcu-sw

# Core asym e2e suite — success + 4 negatives (nonce/anchor/ECC/ML-DSA gates):   PASS 5/5
cargo test -p caliptra-mcu-tests-integration --lib -- test_vendor_auth_asym --test-threads=1

# FE_PROG over the asym path:                                                     PASS
cargo test -p caliptra-mcu-tests-integration --lib -- test_fe_prog_authorized_req --test-threads=1

# OCP-LOCK HEK (perma-set, not-zeroized-failure, rotate) via asym:                PASS
cargo test -p caliptra-mcu-tests-integration --lib -- test_otp_perma_hek_mailbox --test-threads=1
cargo test -p caliptra-mcu-tests-integration --lib -- test_otp_perma_hek_mailbox_not_zeroized_failure --test-threads=1
cargo test -p caliptra-mcu-tests-integration --lib -- test_otp_rotate_hek_mailbox --test-threads=1

# --- Compile clean + convert-verified, but do NOT run green on this branch (see caveat) ---
# vendor-key revocation + Caliptra-SVN-increase: use the harness `rom_only` boot path.
cargo test -p caliptra-mcu-tests-integration --lib -- test_revoke_vendor_pub_key --test-threads=1
cargo test -p caliptra-mcu-tests-integration --lib -- test_rotate_vendor_pk_hash --test-threads=1
cargo test -p caliptra-mcu-tests-integration --lib -- test_increase_caliptra_svn --test-threads=1

# add --nocapture to any of the above to see the [HSM-test] + Caliptra UART trace.
```

**Run individually, not in one batch.** With `--test-threads=1` the failing
`rom_only` tests below can poison shared build state for the others in the same run;
each passes on its own.

**rom_only caveat (pre-existing, NOT the asym change):** `test_revoke_*`,
`test_rotate_vendor_pk_hash`, and `test_increase_caliptra_svn*` boot with
`rom_only: true`, which drives the harness ROM rebuild
(`start_runtime_hw_model` → `compile_rom(params.feature)`, lib.rs:1123). That path
passes `test-mcu-mbox-cmds` to the ROM crate `caliptra-mcu-rom-emulator`, which does
not define that feature → `error: the package 'caliptra-mcu-rom-emulator' does not
contain this feature: test-mcu-mbox-cmds`. This is a harness limitation independent
of the HMAC→asym work (the `rom_only`/ROM-feature wiring was untouched). These tests
compile and their asym conversion is correct; they will run once the harness ROM
feature-forwarding is fixed (or a `CPTRA_FIRMWARE_BUNDLE` is provided).

## What the MCU e2e proves

`test_vendor_auth_asym` drives the complete path with the test acting as the HSM
(real ECDSA-P384 + ML-DSA-87 keys, private keys never leave the signer):

```
test HSM ─▶ Host ─▶ MCU RT ─▶ Caliptra RT ─▶ Caliptra PersistentData
  (LocalVendorAuthSigner) (AsymCommandAuthorizer) (VendorAuth)

PRE  boot   : v2 SoC manifest (Vendor Ext 0x0001 anchor) enrolled at cold boot
A    HELLO  : MC_VENDOR_AUTH_HELLO → relay → Caliptra mints 48-B one-time nonce
B    SIGN   : sign  cmd_id(BE) ‖ SHA-384(body) ‖ nonce   (ECDSA + ML-DSA)
C    CMD     : [header | body | tag] → MCU AsymCommandAuthorizer
              tag = nonce(48) ‖ ecc_pub(96) ‖ mldsa_pub(2592) ‖ ecc_sig(96) ‖ mldsa_sig(4628)
D    VERIFY  : relay VENDOR_AUTH_CHALLENGE → Caliptra: nonce · anchor · ECDSA · ML-DSA (strict-AND)
E    BIND    : Caliptra echoes (cmd_id, body_hash); MCU check_echo_binding (TOCTOU)
F    EXECUTE : MCU runs MC_FUSE_READ on the exact authorized bytes
```

### The 5 tests and the gate each exercises

| Test | Result | Caliptra gate | Error code |
|---|---|---|---|
| `test_vendor_auth_asym_authorized_req` | pass | all gates pass → executes | — |
| `test_vendor_auth_asym_wrong_key_rejected` | reject | anchor (B) | `0xE00A1` WRONG_PUBLIC_KEYS |
| `test_vendor_auth_asym_replayed_nonce_rejected` | reject | nonce (A, one-time) | `0xE00A0` NONCE_MISMATCH |
| `test_vendor_auth_asym_tampered_body_rejected` | reject | ECC verify (C) | `0xE00A2` INVALID_SIGNATURE |
| `test_vendor_auth_asym_bad_mldsa_only_rejected` | reject | ML-DSA verify (D), proves strict-AND | `0xE00A2` INVALID_SIGNATURE |

Run all 5 together (recommended — one emulator suite, ~2 min):
```bash
cargo test -p caliptra-mcu-tests-integration --lib -- \
  test_vendor_auth_asym --nocapture --test-threads=1
```

Or run each gate individually:
```bash
cargo test -p caliptra-mcu-tests-integration --lib -- test_vendor_auth_asym_authorized_req      --nocapture --test-threads=1
cargo test -p caliptra-mcu-tests-integration --lib -- test_vendor_auth_asym_wrong_key_rejected  --nocapture --test-threads=1
cargo test -p caliptra-mcu-tests-integration --lib -- test_vendor_auth_asym_replayed_nonce_rejected --nocapture --test-threads=1
cargo test -p caliptra-mcu-tests-integration --lib -- test_vendor_auth_asym_tampered_body_rejected  --nocapture --test-threads=1
cargo test -p caliptra-mcu-tests-integration --lib -- test_vendor_auth_asym_bad_mldsa_only_rejected --nocapture --test-threads=1
```

`--nocapture` prints `[HSM-test]` lines + the Caliptra UART trace so you can watch
`MVAH` → `VAHL` (nonce) → `VACH` (verify) → fuse read in the log.

## Reading the log

```
[HSM-test] === asym authorize cmd_id=0x49465052 ===          MC_FUSE_READ ("IFPR")
  mbox 0x4d564148 (MVAH) → [rt] 0x5641484c (VAHL)            HELLO relayed to Caliptra
[HSM-test]   HELLO -> nonce = <48 hex bytes>                 Caliptra minted the nonce
[HSM-test]   signed: body=8 B, tag=7460 B                    HSM produced the hybrid tag
  mbox 0x49465052 (7472 B) → [rt] 0x56414348 (VACH, 7516 B)  CHALLENGE relayed; Caliptra verifies
  [otp-provision] DAI read ...                               command executed after auth
[HSM-test] PASS: full asymmetric authentication succeeded
```
A rejected negative shows `Error copying from mailbox: MailboxCmdFailed(<code>)`
where the code decodes per the table above.

## Gotchas

- **Package name:** `caliptra-mcu-tests-integration` (with the `s`). It is a `--lib`
  test (like `test_revoke_vendor_pub_key`), NOT a `--test '*'` target.
- **`custom_mcu_runtime` is required:** the SoC manifest digests the MCU runtime, and
  the harness would otherwise load a *different* runtime → Caliptra fatal
  `0x000B0016` (RUNTIME_DIGEST_MISMATCH) at boot. The test builds the runtime once,
  digests it in the manifest, and injects the SAME bytes via `custom_mcu_runtime`.
- **Feature string:** the runtime is built with `test-mcu-mbox-cmds,asym-cmd-auth`.
  `test-mcu-mbox-cmds` enables the authorized-command set; `asym-cmd-auth` swaps the
  mock authorizer for the asymmetric relay one (the app has the real feature; the
  kernel crate carries a no-op stub so the shared feature string builds).
- **From-source vs prebuilt:** with no `CPTRA_FIRMWARE_BUNDLE` env var set, everything
  builds from source (slow first run). Other integration tests that rely on the
  harness's default firmware selection may fail to boot on this fork-pinned branch;
  the asym e2e is self-contained (injects all artifacts) and is unaffected.
- **Fork pin:** the asym path only compiles against the caliptra-* fork branch
  (`raunakgupta/vendor-auth`) that contains the Caliptra `VENDOR_AUTH_*` commands.
  Do not merge to `main-2.1` until upstream lands and the pin is reverted
  (see `VENDOR_AUTH_FORK_PIN_REVERT.md`).

## Caliptra-core verify tests (paired)

`caliptra-sw` `test_vendor_auth` (12 tests) exercises the verification itself on the
Caliptra hw-model — anchor enrolled via a real v2 Auth Manifest + SET_AUTH_MANIFEST,
real keys, and negative cases asserting specific `CaliptraError` codes per gate
(nonce value-mismatch, invalid length, wrong cmd checksum, anchor-not-enrolled,
tampered cmd_id, bad-ECC-only, bad-ML-DSA-only). Run them together with the MCU e2e
for full coverage of both the relay and the verifier.
```
cd /users/ssdrive/calipta_root/caliptra-sw
cargo test -p caliptra-runtime --test runtime_integration_tests test_vendor_auth
```

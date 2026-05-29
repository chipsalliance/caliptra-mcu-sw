# Phase 10 Cherry-Pick Tracking Document

**Branch**: `phase10-debug` (PR #1529)  
**Base**: `main-2.1`  

## Current Status

- **CI Run 6** (26637231996): FAILED — tests 6.12.7, 6.13.7 (CHALLENGE signature verification)
- **Root cause**: Incomplete cherry-picks created API mismatches (sign_hash param order, measurement_summary_hash signature, LargeMessageCtx unification, etc.)


## 1. caliptra-sw Cherry-Picks Needed (caliptra-2.0 → main)



| PR | Description |
|----|-------------|
| [#3622](https://github.com/chipsalliance/caliptra-sw/pull/3622) | runtime: DPE ML-DSA hybrid support with stack overflow fix |







## 2. SPDM-lib Cherry-Picks Needed (caliptra-mcu-sw)

These are the commits on `origin/main` (present in the successful reference) that are **missing** from `phase10-debug`, specifically in `runtime/userspace/api/spdm-lib/`. They must be applied in dependency order.

### Tier 1: Infrastructure (must be applied in merge order)

| # | PR | Commit | Description | Impact | Depends on | Status |
|---|-----|--------|-------------|--------|------------|--------|
| 1 | [#1339](https://github.com/chipsalliance/caliptra-mcu-sw/pull/1339) | `46c3e280` | **Implement SPDM CHUNK_SEND handling** | Adds `LargeRequestCtx`, `chunk_send_ack_rsp` (730 new lines) | — | **MISSING** |
| 2 | [#1371](https://github.com/chipsalliance/caliptra-mcu-sw/pull/1371) | `32fc09f6` | **Unify large request/response into shared LargeMessageCtx** | **CRITICAL**: Replaces `large_resp_context`+`large_req_context` with unified `large_msg_ctx` | #1339 | **MISSING** |
| 3 | [#1353](https://github.com/chipsalliance/caliptra-mcu-sw/pull/1353) | `bf7410ba` | **Refactor SpdmCertStore for cert slot management** | Changes `MAX_CERT_SLOTS_SUPPORTED` 2→4, swaps `sign_hash` param order, adds `write_cert_chain`/`erase_cert_chain` | — (independent) | **MISSING** |
| 4 | [#1351](https://github.com/chipsalliance/caliptra-mcu-sw/pull/1351)/[#1359](https://github.com/chipsalliance/caliptra-mcu-sw/pull/1359) | `cc986baa` | **Refactor large VDM responses and Caliptra VDM command handler** | Renames `UnifiedCommandHandler` → `CaliptraCmdHandler`; only touches `export_attested_csr.rs` in spdm-lib | — (independent) | **MISSING** |
| 5 | [#1408](https://github.com/chipsalliance/caliptra-mcu-sw/pull/1408) | `825bafaa` | **Share large message buffer via static pool** | `LargeMsgBufProvider` trait, replaces raw buffer params in `SpdmContext::new()` | #1371 | **MISSING** |
| 6 | [#1412](https://github.com/chipsalliance/caliptra-mcu-sw/pull/1412) | `81d7eb3e` | **Remove measurement staging buffer, use shared large message buffer** | Adds `buf` param to `measurement_summary_hash()`; required by challenge_auth_rsp | #1408 | **MISSING** |

### Tier 2: Features that depend on Tier 1

| PR | Commit | Description | Impact | Status |
|----|--------|-------------|--------|--------|
| [#1334](https://github.com/chipsalliance/caliptra-mcu-sw/pull/1334) | `b55397fd` | Add ExportAttestedCsr command on MCU mailbox and SPDM-over-MCTP transports | New VDM command | Ref only in build fix on phase10 |
| [#1370](https://github.com/chipsalliance/caliptra-mcu-sw/pull/1370) | `2d5f5460` | Add ExportIdevidCsr VDM command | New VDM command | **MISSING** |
| [#1373](https://github.com/chipsalliance/caliptra-mcu-sw/pull/1373) | `2660cc96` | Add SET_CERTIFICATE handling with persistent cert storage | New SPDM command (`set_certificate_rsp.rs` — 756 new lines) | **MISSING** |
| [#1388](https://github.com/chipsalliance/caliptra-mcu-sw/pull/1388) | `555d295a` | Add GetLog/ClearLog commands support | New VDM commands | **MISSING** |
| [#1426](https://github.com/chipsalliance/caliptra-mcu-sw/pull/1426) | `dfb49ed7` | Add VDM streaming for ProdDebugUnlock on MCU side | VDM streaming, `VdmStreamHandler` trait | **MISSING** |

## 4. Dependency Bumps Required


### caliptra-dpe

| Field | phase10-debug | origin/main (target) |
|-------|---------------|----------------------|
| **Git rev** | `337f7e4151f60add8e97445f71fc1393afc661a8` | `a26db5b869f13f0d2c5762b75f8892b9fe2d8055` |
| **Features** | `p384` | `p384`, **`arbitrary_max_handles`** (new) |
| **Crates used** | `dpe` only | `dpe`, **`crypto`**, **`platform`** (new) |

---

## 5. CI / Workflow Changes

### fpga-spdm.yml differences (phase10-debug vs. reference)

| Area | phase10-debug (current) | reference/main (target) |
|------|------------------------|-------------------------|
| Trigger | `push: branches: [phase10-debug]` | `pull_request` + `workflow_dispatch` |
| Concurrency | None | Group-based with cancel-in-progress |
| Build tool | Manual `cargo xtask-fpga all-build` | `cargo xtask-fpga fpga build --configuration subsystem` |
| Test build | Manual `cargo nextest archive` | `cargo xtask-fpga fpga build-test --configuration subsystem` |
| spdm-emu repo | `parvathib/spdm-emu` (pbhogaraju/spdm_emu_main_custom) | `chipsalliance/caliptra-spdm-emu` (caliptra-main) |
| spdm-emu cmake | No `MAX_CERT_CHAIN_SIZE` | `-DLIBSPDM_MAX_CERT_CHAIN_SIZE=0x2000` |
| Bitstream download | Manual `caliptra-bitstream-downloader` | `cargo xtask-fpga fpga download-bitstream` |
| Bitstream load | Manual `fpga_manager` sysfs write | `xtask fpga bootstrap --bitstream ...` |
| CA cert path | `ocp-eat-verifier/ocptoken-rs/test-data/...` | `ocp-eat-verifier/ocptoken/test-data/...` |
| xtask binary | `caliptra-mcu-xtask` | `xtask` |
| Firmware bundle | `target/all-fw.zip` | `all-fw.zip` |
| Install deps | Includes `libclang-dev` | No `libclang-dev` |
| RUNTIME_FEATURES | Explicit env var | None (built into xtask) |

---

## 6. Specific API Mismatches Causing Test Failures

These are the exact code differences between `phase10-debug` and the successful reference that directly cause SPDM conformance test failures:

### 6.1 `sign_hash()` parameter order (causes 6.12.7/6.13.7 CHALLENGE failures)
```
// phase10-debug (WRONG):
sign_hash(slot_id, asym_algo, &tbs, &mut signature)

// reference/main (CORRECT):
sign_hash(asym_algo, slot_id, &tbs, &mut signature)
```
**Fix**: Comes from PR #1353 (SpdmCertStore refactor)

### 6.2 `measurement_summary_hash()` missing buffer parameter
```
// phase10-debug (WRONG - 2 params):
measurement_summary_hash(meas_summary_hash_type, &mut meas_summary_hash)

// reference/main (CORRECT - 3 params):
measurement_summary_hash(meas_summary_hash_type, &mut meas_summary_hash, ctx.large_msg_ctx.buf)
```
**Fix**: Comes from PR #1412 (shared large message buffer for measurements)

### 6.3 `LargeResponseCtx` / `LargeRequestCtx` → unified `LargeMessageCtx`
```
// phase10-debug:
pub(crate) large_resp_context: LargeResponseCtx<'a>
pub(crate) large_req_context: LargeRequestCtx<'a>

// reference/main:
pub(crate) large_msg_ctx: LargeMessageCtx<'a>
```
**Fix**: Comes from PR #1371 (Unify large request/response)

### 6.4 `MAX_CERT_SLOTS_SUPPORTED` (2 vs 4)
```
// phase10-debug:
pub const MAX_CERT_SLOTS_SUPPORTED: u8 = 2;

// reference/main:
pub const MAX_CERT_SLOTS_SUPPORTED: u8 = 4;
```
**Fix**: Comes from PR #1353 (SpdmCertStore refactor)

---

# Released ROM/runtime compatibility

Linux/WSL-only tests. This is the Caliptra 2.0 port of the `main-2.1` matrix:
released `rom-sdk-2.0.0` and `rom-sdk-2.0.1` against the current `main`
runtime, **two pairs**. Released runtime SDKs (`rt-sdk-2.0.0`) are not paired
yet.

## What runs

The [workflow](../../../../.github/workflows/rom-runtime-compatibility.yml):

1. Builds pinned images with their native toolchains, lockfiles and submodules.
   ROMs use their release's `xtask rom-build --platform emulator`. The runtime
   is the commit the workflow runs on.
2. Uses Caliptra 2.0 hardware, repository test keys and the Core ROM from
   `e5ceee831f1b6b49a8d139a705133e47deab8711`, the Core pinned by
   `rt-sdk-2.0.0` (as the 2.1 matrix pins the Core of `rt-sdk-2.1.1`). Core
   firmware ships with the MCU runtime, so the runtime uses the Core firmware
   it pins.
3. Runs ignored compatibility tests with the `nightly-emulator` profile and one
   test thread, then uploads results, logs, JUnit, build commands and hashes.

The 14 cases cover boot, mailbox commands, authentication/SVN, resets and
applicable service checks. The streaming configuration produces **14 result
records per pair**, including unsupported cases.

SPDM/EAT checks require successful boot and SoC loading. EAT uses non-TCB,
TCB and mixed configurations with signed reference values. There is no
standalone provisioning or TDISP/IDE case.

Warm reset checks readiness, firmware-version/capability responses, preserved
OTP/flash, and MCTP discovery plus PLDM GetTID. It completes the initial
streaming boot before resetting, but does not repeat firmware download,
owner-artifact measurement or SoC activation after reset.

Released firmware is not patched, and missing artifacts never fall back to
current firmware. Existing current/current CI is unchanged.

The streaming-fixture regression compares the complete container with canonical
builder output, without assuming an internal flash-header layout.

## Inputs

`EXPECTED_CAPABILITIES` in [`fixtures.rs`](fixtures.rs) holds the reviewed
`MC_DEVICE_CAPABILITIES` bytes for each runtime and boot mode:

```json
{
  "main": {"streaming": "<64-byte hex>"}
}
```

A capability change in the runtime or its Core firmware fails
`runtime_commands` and `warm_reset` until these bytes are updated. The
`expected-capabilities` workflow input (`MCU_COMPAT_CAPABILITIES`) overrides
them. For local fixture preparation, `MCU_COMPAT_RUNTIME` limits work to one
runtime.

## Reading results

Open the Actions summary or `compatibility-summary` artifact for per-case
results, reasons, timings and source revisions.

- **PASS:** the check ran and passed.
- **FAIL:** an assertion, execution or evidence check failed.
- **BLOCKED:** required inputs or prerequisites are unavailable.
- **NOT APPLICABLE:** the selected configuration does not enable the feature.
- **KNOWN INCOMPATIBLE:** the inputs match a documented incompatibility;
  the case still checks everything before it.

FAIL and BLOCKED fail the matrix; KNOWN INCOMPATIBLE is listed in the summary
but does not. N/A is not executed coverage, even though
Nextest counts those invocations as successful. Use the per-case results.

## Caliptra 2.0 differences

- **Streaming only:** 2.0 MCU ROMs reject flash boot unless built with
  `hw-2-1`, so `flash_cold_boot` and `cold_reboot` are not applicable.
- **No handoff table:** 2.0 ROMs predate the DCCM ROM handoff table. The
  runtime then falls back to streaming boot, which `recovery_cold_boot` and the
  other boot cases exercise; `handoff` is not applicable.
- **OTP layout:** the released 2.0 ROMs share `main`'s fuse map, so fixtures
  use the generated `fuses` offsets.

# Released ROM/runtime compatibility

Linux/WSL-only tests from the
[task plan](../../../../rom-runtime-compatibility-matrix-2.md).
Temporarily tests only GA `rom-sdk-2.1.0` against `rt-sdk-2.1.0`,
`rt-sdk-2.1.1`, and current `main-2.1`: **three pairs**. The RC ROM is excluded.

## What runs

The [workflow](../../../../.github/workflows/rom-runtime-compatibility.yml):

1. Builds pinned images with their native toolchains, lockfiles and submodules.
   Resolves `main-2.1` once per run.
2. Uses Caliptra 2.1 hardware, repository test keys and the Core ROM from
   `b99535ded32492d6c23bbc56f95e787a1e275b59`. Core firmware ships with the
   MCU runtime, so each runtime uses the Core firmware it pins: `557fd1a` for
   `rt-sdk-2.1.0`, `b99535d` for `rt-sdk-2.1.1`, and `main-2.1`'s pin.
3. Runs ignored compatibility tests with the `emulator` profile and one test
   thread, then uploads results, logs, JUnit, build commands and hashes.

The 21 cases cover boot, handoff, mailbox commands, authentication/SVN, resets
and applicable service checks. Flash and streaming configurations produce
**42 result records per pair**, including unsupported cases.

SPDM/EAT checks require successful boot and SoC loading. EAT uses non-TCB,
TCB and mixed configurations with signed reference values. There is no
standalone provisioning or TDISP/IDE case.

Warm reset checks readiness, firmware-version/capability responses, preserved
OTP/flash, and streaming-mode MCTP discovery plus PLDM GetTID. It completes the
initial streaming boot before resetting, but does not repeat firmware download,
owner-artifact measurement or SoC activation after reset.

Released firmware is not patched, and missing artifacts never fall back to
current firmware. Existing current/current CI is unchanged.

The streaming-fixture regression compares the complete container with canonical
builder output, without assuming an internal flash-header layout.

## Required inputs

Run manually or through `workflow_call`, supplying:

| Workflow input | Repository-variable alternative | Value |
|---|---|---|
| `fixture-agreement` | `MCU_COMPAT_FIXTURE_AGREEMENT` | Approval of the Core, signing/OTP and release configurations. |
| `expected-capabilities` | `MCU_COMPAT_CAPABILITIES` | Reviewed capability bytes for each runtime and mode. |

Capability JSON uses this shape:

```json
{
  "rt-sdk-2.1.0": {"flash": "<36-byte hex>", "streaming": "<36-byte hex>"},
  "rt-sdk-2.1.1": {"flash": "<64-byte hex>", "streaming": "<64-byte hex>"},
  "main-2.1": {"flash": "<64-byte hex>", "streaming": "<64-byte hex>"}
}
```

Missing inputs block execution.
For local fixture preparation, `MCU_COMPAT_RUNTIME` limits work to one runtime.

## Reading results

Open the Actions summary or `compatibility-summary` artifact for per-case
results, reasons, timings and source revisions.

- **PASS:** the check ran and passed.
- **FAIL:** an assertion, execution or evidence check failed.
- **BLOCKED:** required inputs or prerequisites are unavailable.
- **NOT APPLICABLE:** the selected configuration does not enable the feature.

FAIL and BLOCKED fail the matrix. N/A is not executed coverage, even though
Nextest counts those invocations as successful. Use the per-case results.

## Known failures

- **Flash boot:** the ROM requires a raw header at offset zero; the runtimes
  require a partition table there. No flash swapping or streaming fallback
  hides this incompatibility.
- **SDK 2.1.0 services:** its attestation features reload SoC images from
  flash after any streaming load and predate the SPDM-ready milestone, so its
  service images load SoC images from flash, as its own tests did.
- **Core firmware ABI:** `GET_IMAGE_INFO` grew from 8 to 12 bytes in
  caliptra-sw `3382bdb0`. Pairing a runtime with Core firmware from the other
  side of that change fails SoC loading with `0x000e0003`; each runtime
  therefore uses its own Core firmware.

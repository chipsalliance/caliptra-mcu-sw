# Released ROM/runtime compatibility

Linux/WSL-only tests for the six pairs in the
[task document](../../../../rom-runtime-compatibility-matrix-2.md).
Existing tests and current/current workflows are unchanged.

## What runs

The [workflow](../../../../.github/workflows/rom-runtime-compatibility.yml):

1. Builds the two pinned ROMs and three runtimes with their own toolchains,
   lockfiles and submodules. Resolves `main-2.1` once per run.
2. Prepares signed fixtures using Caliptra 2.1, repository test keys and Core
   `b99535ded32492d6c23bbc56f95e787a1e275b59`.
3. Runs each pair in flash and streaming configurations using ignored Nextest
   tests, the `emulator` profile and one test thread.
4. Uploads results, logs, JUnit, build commands and image hashes.

Cases come only from task-document sections 3 and 5: boot, handoff, commands,
authentication/SVN, reset and applicable service suites. Historical firmware
is not patched, and missing images never fall back to current firmware.
Failed batches do not stop independent checks; service suites run only when
their boot prerequisites pass.

There are **23 distinct cases**, each recorded for flash and streaming
configurations: **46 records per pair**, not 46 different tests.

| Task-document requirement | Cases |
|---|---|
| Section 3: recovery, flash, streaming, handoff, commands, cold reboot, warm reset | 7 |
| Section 3: corrupt runtime, corrupt manifest, SVN rollback, SVN boundary | 4 |
| Section 5: attestation modes, SPDM transports, provisioning, optional ownership/boot | 12 |

Discovery assertions are part of streaming boot. The core command and handoff
checks also cover those requirements in section 5; they are not rerun as suites.
Unsupported optional cases record N/A or BLOCKED, not passing coverage.

Service suites use three additional release configurations per runtime:
non-TCB, TCB and mixed SoC policies, using each release's native cold-boot
attestation feature to retain services after loading. Each suite verifies PLDM
loading and activation on its own model before SPDM. EAT evidence is
authenticated and appraised against signed reference values generated from
that configuration's manifest.

## Required inputs

Run the workflow manually or through `workflow_call`. Supply:

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

Missing inputs block execution; they do not produce a pass.
For local fixture preparation, `MCU_COMPAT_RUNTIME` limits work to one runtime.

## Reading results

Open the Actions summary or `compatibility-summary` artifact. Each pair shows
PASS, FAIL, BLOCKED and N/A counts, followed by failure reasons and timings.
Per-case JSON records include source SHAs and distinguish input-validation
failures from scenario failures. Logs contain error codes and expected/actual
values where available.

- **PASS:** the check ran and passed.
- **FAIL:** an assertion, execution or evidence check failed.
- **BLOCKED:** required inputs, prerequisites or coverage are unavailable.
- **NOT APPLICABLE:** the selected configuration does not enable the feature.

FAIL and BLOCKED keep the matrix nonpassing. N/A is not executed coverage.

## Known limitations

- Production ROMs expect a raw flash header at offset zero; release runtimes
  expect a partition table there. Flash failures remain visible; the tests do
  not swap flash contents or use streaming fallback to hide them.
- Emulator warm reset resets both CPUs and checks fresh runtime readiness,
  mailbox commands and OTP/flash preservation. The RC ROM with SDK 2.1.0 runtime
  passed in flash configuration; other pairs and streaming remain unverified.
- Missing SPDM/EAT tools, signed reference values or trust anchors block the
  corresponding service checks. Protocol or appraisal failures are FAIL, not PASS.

Focused validation passed all three EAT modes on RC ROM + SDK 2.1.1 streaming,
including authentication and appraisal. Full SPDM conformance and other pairs
were not rerun locally.

The [last executed baseline](https://github.com/chipsalliance/caliptra-mcu-sw/actions/runs/40789714542)
had 39 passing cases, but also flash/handoff failures and blocked coverage.
Its workflow exited after the first batch, leaving 40 cases per pair unrun.
The Core, ROM-build and batch-continuation corrections have not yet been
verified by a new firmware matrix run.

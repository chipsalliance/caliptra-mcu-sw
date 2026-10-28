# Released ROM/runtime compatibility

This Linux/WSL-only lane follows
[the compatibility handoff](../../../../rom-runtime-compatibility-matrix-2.md).
Existing tests and current/current workflows are unchanged.

## What runs

The [workflow](../../../../.github/workflows/rom-runtime-compatibility.yml):

1. Resolves `main-2.1` once.
2. Builds the two pinned ROMs and three runtimes with their own toolchains,
   lockfiles and submodules. Each runtime has flash-only and streaming/service
   configurations; neither configuration uses test firmware.
3. Builds one Nextest archive. The ignored `fixtures::prepare_inputs` test uses
   the existing builder APIs to produce fixed Core, OTP and signed manifests.
   The selected ROM's own flash producer creates its native flash package.
4. Runs exactly six ROM/runtime jobs. Each runs the new ignored boot checks,
   then applicable service checks, using the `emulator` profile and one test
   thread. Nextest already isolates test cases; there is no extra test runner.
5. Always reports all six pairs and uploads logs, commands, hashes and JUnit.

The Core source is fixed at
`e5d1f27b15ba02e4e0a57b942bbde39b74cab2eb`, with 2.1 hardware, repository LMS
test keys, Raw OTP and SVN 0. The boundary fixture uses a separately signed
SVN-1 manifest and matching OTP floor.

## Required owner inputs

Section 1 of the handoff requires agreement, not guessed defaults. Supply these
manual/reusable workflow inputs, or their repository-variable equivalents:

- `fixture-agreement` / `MCU_COMPAT_FIXTURE_AGREEMENT`: approval of the fixed
  Core, OTP/signing and release configurations above.
- `expected-capabilities` / `MCU_COMPAT_CAPABILITIES`: reviewed capability bytes
  for each selected runtime and configuration, not bytes learned from the
  firmware under test. The JSON shape is:

  ```json
  {
    "rt-sdk-2.1.0": {"flash": "<36-byte hex>", "streaming": "<36-byte hex>"},
    "rt-sdk-2.1.1": {"flash": "<64-byte hex>", "streaming": "<64-byte hex>"},
    "main-2.1": {"flash": "<64-byte hex>", "streaming": "<64-byte hex>"}
  }
  ```

Missing inputs block preparation and the six-pair report; they never produce a
compatibility pass. Version strings and command IDs come from each selected
source's build metadata.

## Coverage and limitations

Boot checks cover recovery, flash without streaming fallback, streaming/PLDM
activation, old handoff layouts, mailbox version/capabilities, preserved-flash
cold reboot, corruption rejection and the SVN boundary. Service checks exercise
MCTP SPDM and non-mutating provisioning status/challenge behavior.

Warm reset remains **BLOCKED** until a validated FPGA lane or emulator support
exists. Production EAT modes remain **BLOCKED** until embedded-policy,
measurement-completion and appraisal fixtures exist. Disabled PCR, DOE,
ownership, network and USB configurations are explicitly **NOT APPLICABLE**,
not counted as executed coverage. No historical firmware is patched to enable
them.

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
   Before either runtime build, it writes matching embedded attestation and
   image-descriptor inputs for images 4096/4097 (non-TCB, neither an AK target).
   SDK 2.1.0's embedded policy contains only those images; SDK 2.1.1 and
   `main-2.1` also include vendor key 4 (TCB), matching their native builders.
   Both input files and their SHA-256 hashes are retained with the image.
3. Builds one Nextest archive. The ignored `fixtures::prepare_inputs` test uses
   the existing builder APIs to produce fixed Core, OTP and signed manifests.
   The selected ROM's own flash producer creates its native raw flash payload.
   Both native-ROM and runtime payloads are wrapped with image A at `0x10000`
   and a checksummed partition table at offset zero before certificate seeding
   and hashing; the native payload format is not rewritten.
4. Runs exactly six ROM/runtime jobs. Each runs the new ignored boot checks,
   then applicable service checks, using the `emulator` profile and one test
   thread. Nextest already isolates test cases; there is no extra test runner.
5. Always reports all six pairs and uploads logs, commands, hashes and JUnit.

The Core source is fixed at
`e5d1f27b15ba02e4e0a57b942bbde39b74cab2eb`, with 2.1 hardware, repository LMS
test keys, Raw OTP and SVN 0. The boundary fixture uses a separately signed
SVN-1 manifest and matching OTP floor.
Before hashing, all primary/runtime flash artifacts (including SVN-1) are seeded
with the existing integration `ECC_DEVID_CERT_DER` and `MLDSA_IDEVID_CERT`
fixtures, using `build_primary_flash_initial_contents`' external-OTP layout.
The selected boot payloads are preserved.

## Required owner inputs

Section 1 of the handoff requires agreement, not guessed defaults. Supply these
manual/reusable workflow inputs, or their repository-variable equivalents:

- `fixture-agreement` / `MCU_COMPAT_FIXTURE_AGREEMENT`: approval of the fixed
  Core, OTP/signing, IDevID certificates, embedded boot policy and release
  configurations above.
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
mailbox and non-mutating provisioning status/challenge behavior.

Full streaming MCTP SPDM conformance is **BLOCKED** until the same model has
completed PLDM loading and verified SoC measurement setup, with a live responder
after loading. Separate streaming-boot results do not initialize the fresh
conformance model. The selected production configuration can exit after loading;
no test-only runtime is substituted to keep it alive.

Warm reset remains **BLOCKED** until a validated FPGA lane or emulator support
exists. Production EAT modes remain **BLOCKED** until embedded-policy,
measurement-completion and appraisal fixtures exist. Disabled PCR, DOE,
ownership, network and USB configurations are explicitly **NOT APPLICABLE**,
not counted as executed coverage. No historical firmware is patched to enable
them.

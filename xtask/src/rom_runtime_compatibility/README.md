# Released ROM/runtime compatibility xtask

These Linux/WSL commands implement the step-4 pipeline and step-5 suite selection from the
[compatibility requirements](../../../rom-runtime-compatibility-matrix%201.md).
They use the existing Rust xtask, builder and PLDM libraries, rather than a
separate Python orchestration layer or standalone fixture Cargo workspace.
They do not add legacy-flash
support to production firmware or implement the FPGA lane.

The [reusable/manual workflow](../../../.github/workflows/rom-runtime-compatibility.yml)
resolves `main-2.1` once. Every subsequent job uses that immutable SHA.
Historical image SHAs and toolchains are pinned in the tools. Core ROM and
firmware remain fixed at `e5d1f27b15ba02e4e0a57b942bbde39b74cab2eb`.
Only repository test keys are used.

## Pipeline

1. As in the existing build/test workflow, xtask and an integration-test Nextest
   archive are built once and shared with subsequent jobs. Orchestration and
   harness regression tests must pass before image builds start. Five image jobs
   build each released ROM once and each runtime once per baseline/service
   configuration, or restore an exact-key cached image with its build provenance.
   Image cache keys cover the pinned source selection, build code, lockfile,
   toolchain settings and workflow; the current-runtime cache additionally uses
   its resolved SHA. Fixture generation still verifies all image evidence.
   Historical worktrees are outside the primary Cargo workspace. Sources, locks,
   toolchains and submodules must stay unchanged.
2. One fixture job produces the shared Core/OTP collateral, signed manifests,
   native legacy packages, separate v3 runtime/streaming packages, and all pair
   configurations. Generated ROM linker scripts travel with image evidence;
   the fixture job does not rebuild ROMs to recover their handoff addresses.
   All 12 generated configurations must pass the existing input-integrity test
   before pair jobs start; preflight logs are retained with the fixture inputs.
   The checks use the shared test archive, not another compilation.
3. Exactly six pair jobs run both configurations, using only
   `cargo nextest run --profile emulator --run-ignored only --test-threads=1
   --no-fail-fast --no-tests fail`.
   The boot phase selects
   `test(test_rom_runtime_compatibility) - test(test_suite_)`, including the
   artifact-integrity case. The subsequent suite phase selects
   `test(test_rom_runtime_compatibility::test_suite_)`.
   Host helper suites are not repeated for each pair.
   CI sets `MCU_COMPAT_TEST_ARCHIVE` so every phase uses the shared archive with
   workspace remapping. Local invocations without it retain source builds;
   a configured but missing archive fails rather than silently rebuilding.
4. An always-run report collects case dispositions, image/configuration hashes,
   commands, process status and reasons. Missing cases become BLOCKED, never
   PASS. Missing JUnit, zero selected tests, silent skip messages or nonzero
   Nextest exits fail the lane. Raw Nextest JUnit and per-case logs remain in
   pair artifacts; aggregate JUnit also represents blocked/excluded cases.

There are 132 emulator scenario dispositions plus 12 explicit warm-reset
exclusions (one per pair/configuration). The exclusions are not FPGA coverage.
Step 5 adds 14 explicit suite dispositions per pair/configuration (168 total).
The aggregate therefore contains 312 scenario/suite records, with boot and suite
counts separated. Input-integrity results remain in the raw boot JUnit reports.

Host and fixture Cargo dependencies/build outputs are cached separately by
platform, toolchain and locked build inputs; Cargo revalidates outputs restored
from an earlier source revision. Only image and fixture builds on 16-core runners
use eight build/Rayon threads. Emulator tests remain serial. Case results and
JUnit are never reused from a previous workflow run.

## Selected-image CI suites

The existing current/current workflows and tests keep their default behavior.
Dedicated ignored compatibility wrappers reuse protocol checks on the verified
historical images; they never build feature-specific test firmware.

Every suite has a source/configuration-backed decision in `suite-support.json`,
whose hash is bound into the pair configuration. Known disabled features are
NOT APPLICABLE; unresolved support or prerequisites are BLOCKED, never PASS.
Supported SPDM decisions retain their typed version/algorithm contract through
configuration parsing and evidence comparison; unknown fields remain rejected.
A supported suite additionally requires successful boot/runtime-command records
for this exact configuration hash (and streaming/discovery for service images).
Missing, failed or stale boot records block execution.

Mailbox expectations select the released wire ABI and command IDs from pinned
sources and verify imported Core crypto layouts. Unknown layouts are BLOCKED.
Handoff reuses the successful phase-3 selected-layout assertions and retains a
hash-bound copy of that result instead of booting special handoff test firmware.

The cases distinguish cold-boot EAT non-TCB/TCB/mixed, PCR quote, MCTP SPDM
conformance, DOE/spdm-rs, mailbox, provisioning, DOT, stable-owner-key,
handoff, network boot and USB recovery. Unselected optional configurations are
explicit exclusions, not coverage claims. EAT remains BLOCKED: component classes
are compiled into these production images, successful image loading terminates
the emulator, and owner-policy reference appraisal is incomplete. Host-only
manifest changes do not resolve those constraints; no test-feature firmware is
substituted.

SPDM tooling is built once through the existing validator workflow's optional
tools-only mode, using a distinct artifact/concurrency suffix. This does not run
its current/current tests or change their normal invocation. Missing tools must
be surfaced by applicable suite checks. Per-case evidence is retained under the
pair's result directory, including failures.

Both shared SPDM tool builds use exact-key binary caches covering the resolved
source SHA, compiler fingerprint, runner platform and workflow build settings.
Cache hits still validate the required executables and package fresh revision
metadata for the current run.

The shared SPDM workflow uses job-local HTTPS rewrites for SPDM-RS's public SSH
dependencies, checks tool binaries before publishing, and limits Cargo/Rayon
parallelism to two. Tool builds are capped at 60 minutes. Current/current SPDM
test commands use the emulator profile's 30-minute limit, terminating their
process group (with forced cleanup after 30 seconds) on timeout. Existing
always-run log uploads and failure checks remain in place; a timeout is not a
PASS. Compatibility pairs retain their existing single-test concurrency,
30-minute per-test limit and 90-minute job limit. They do not run the broad
workspace or ignored register-access tests.

## Entry points

Use `cargo xtask rom-runtime-compatibility` with one of:

- `build-images --label LABEL`
- `prepare-fixtures`
- `run-pair --rom ROM --runtime RUNTIME`
- `report`

CI invokes the same commands using the prebuilt `/tmp/xtask` binary. Historical
builds still use each selected source's own xtask. Fixture generation calls the
existing Rust builder/PLDM APIs directly. No new Python files are required.

- `MCU_COMPAT_CURRENT_RUNTIME_SHA` is required. No job independently resolves
  the moving branch.
- `MCU_COMPAT_ROOT` selects the shared artifact layout; its local default is
  `target/rom-runtime-compatibility/ci`.
- `MCU_COMPAT_SOURCES` selects historical worktrees and must be outside any
  ancestor containing `Cargo.toml`. CI uses the default sibling directory,
  `../caliptra-compatibility-builds`.
- `MCU_COMPAT_TEST_ARCHIVE` optionally selects the shared Nextest archive for
  `run-pair`. CI supplies the archive built from the resolved checkout.
- Run from a checkout at the selected current-runtime SHA with the pinned Rust
  toolchains, system build dependencies and cargo-nextest installed.

The workflow has no schedule or PR trigger and is not included in `nightly.yml`
while standalone validation is pending. Run it manually on `main-2.1` using
`workflow_dispatch`; `workflow_call` remains available for future integration.

Local WSL validation built the selected images and ran all six pairs against
current-runtime SHA `679541c500cdb74cc110226c7f44df870ea101a1`. The report records
64 PASS, 57 FAIL, 47 BLOCKED and 144 NOT APPLICABLE dispositions. Reports and
per-case evidence are retained under
`target/local-validation-20261027/compatibility`. All 8 xtask tests, 19 integration
helper/regression tests and 12 generated configuration integrity checks passed.

These results do not establish full compatibility: boot prerequisites prevent
many service checks from reaching protocol execution, and the compatibility
failures remain unresolved. Live CI and FPGA execution remain unvalidated.

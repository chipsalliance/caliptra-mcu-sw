# Caliptra Subsystem 2.2 Firmware Impact Assessment

Research snapshot: **2026-10-20**.

This is a source-based compatibility assessment of the transition from Caliptra
Subsystem 2.1 to the current 2.2 development RTL. It is not a finalized release
specification, completed hardware bring-up, or security review. Findings marked
as integration gaps are based on source inspection, not demonstrated test
failures.

## Executive Summary

The transition is not just USB enablement. The highest-priority firmware
contracts are:

1. Caliptra ROM/FMC boot sequencing and hardware-enforced Key Vault policy.
2. HMAC driver changes affecting DICE derivation and cryptographic services.
3. MCU ROM fuse-lock semantics, early hardware configuration, and measurement
   submission.
4. Hardware ICCM measurement and PCR ownership.
5. MCU mailbox SRAM ownership and forwarding.
6. USB recovery initialization, register layout, access width, and ownership.

Although the primary scope is Caliptra ROM, MCU ROM, Caliptra Runtime, and MCU
Runtime, **Caliptra FMC must also be included**: the new hardware explicitly
enforces ROM -> FMC -> Runtime transitions.

Do not assume a 2.1 ROM can be paired with new RTL by replacing Runtime alone.
Qualify both ROM images and the FMC/Runtime bundle against the selected RTL
configuration. MCU ROM patch SRAM is a pre-production facility, not a production
escape hatch for incompatible ROM.

## Scope and Reproducible Baselines

| Component | Revision examined |
|---|---|
| MCU software checkout | `cc35e8489dbd22391a15223f8834310dd6660314`, 2026-10-16 |
| Hardware gitlink committed by MCU software | `3350c70a296bf897abe8c02e5ec0da69cc83ee16`, 2026-03-27 |
| Hardware actually checked out during research | `dfa6c631dbfc00c8e0c7e6b256619d03d74f0bdc`, 2026-09-24 |
| Core RTL in that local hardware checkout | `521cf3199720a49e442275c58c92f4ce0891ba51` |
| Caliptra software dependency in MCU Cargo manifest | `b99535ded32492d6c23bbc56f95e787a1e275b59`, 2026-09-26 |
| Target subsystem main | [`af14a79869c7df7296352fd41bdd51fba3c44464`](https://github.com/chipsalliance/caliptra-ss/tree/af14a79869c7df7296352fd41bdd51fba3c44464) |
| Core RTL pinned by target | [`7b901d59ba92d8d3b19b7f63ecb77806404503f2`](https://github.com/chipsalliance/caliptra-rtl/tree/7b901d59ba92d8d3b19b7f63ecb77806404503f2) |
| USB pinned by target | [`352bfe54e341b6fdf9632267515f602fb0a98be2`](https://github.com/chipsalliance/usb2/tree/352bfe54e341b6fdf9632267515f602fb0a98be2) |
| I3C pinned by target | [`9a8a322582444fed63ae3fe9a86230f32b478375`](https://github.com/chipsalliance/i3c-core/tree/9a8a322582444fed63ae3fe9a86230f32b478375) |
| Caliptra software main additionally checked for support | [`898be94aad08d5c616497ccd19980595cef46f14`](https://github.com/chipsalliance/caliptra-sw/tree/898be94aad08d5c616497ccd19980595cef46f14) |

Comparison started with subsystem `css-v2.1` (`28ef1cef`, 2025-10-13), with
`css-v2.1.2` (`753308dd`, 2026-03-22) also checked. These are relevant changes on
the path to current main; not every fix is necessarily exclusive to 2.2 or absent
from a backport.

The hardware checkout was already ahead of the gitlink committed in MCU software.
Fuse hardening and mailbox ownership changes already apply to that local
checkout. ROM patch SRAM, DCLS integration, newer core hardening, and later USB
fixes add further changes when advancing to the target.

At this snapshot, the returned subsystem tag list had no `css-v2.2` release. The
subsystem specification identifies 2p2 as WIP, and
[chipsalliance/caliptra-rtl#1432](https://github.com/chipsalliance/caliptra-rtl/pull/1432)
contains open draft release notes. Open/merged status in this document is as of
the research date.

The [submodule configuration](../../.gitmodules) does not select a compatible
firmware/RTL bundle. Normal updates follow the committed gitlink; remote updates
can advance it. Preserve the target subsystem's nested component pins instead
of independently advancing every nested submodule to its own main.

## Firmware Impact Matrix

Legend:

- **D**: direct firmware/interface work.
- **V**: validation, diagnostics, or downstream behavioral impact.
- **C**: conditional on feature/platform use.

| Hardware change | Caliptra ROM | MCU ROM | Caliptra Runtime | MCU Runtime | Assessment |
|---|---|---|---|---|---|
| USB virtual hub, MCU DEV0 / SoC DEV1 | C | D | C | D/C | New transport and ownership; MCU initializes hub |
| USB OCP EP0/FIFO streaming boot | D/C | D | D/C | C | Recovery base, handshakes, status, DMA |
| USB register layout, filtering, DWORD-only accesses | D/C | D | D/C | D/C | Concrete compatibility requirements |
| DCLS and MCI disable/lock control | V | D | V | V | MCU policy configuration; fatal telemetry |
| ABR masking and implementation changes | D/V | V | D/V | V | Drivers, KATs, errors, timing |
| HMAC seed / LAST / readiness changes | D | V | D | V | Concrete driver mismatch in examined Caliptra SW |
| ECC / ML-DSA VERIFY_PASS | D | V | D | V | Hardware verdict and software cross-checks |
| Dual-source TRNG / SHA3-384 combiner | D | C/V | D/V | V | ROM KAT and lock; entropy/error behavior |
| MCU ROM patch SRAM | V/C | D/C | V/C | D/C | Pre-production; identity and reset restrictions |
| Boot-flow / KV transition enforcement | D | V | D | V | Also affects FMC; potential production boot blocker |
| Hardware ICCM hash / PCR4 and PCR5 | D/V | V | D | V/C | Hardware-owned measurements and reference values |
| KV length / reset isolation / AES masking | D | V | D | V | Key lengths, errors, update sequencing |
| Sparse FSMs and fatal states | D/V | D | D/V | D/V | Reporting and reset recovery |
| PK-hash / ratchet-seed volatile locks | V/C | D | C | D/C | Ordinal-to-W1S-bitmask contract change |
| Debug intent / secret digest privacy | D/V | D | D/V | D/V | Provisioning, debug, identity observability |
| Exclusive MCU mailbox SRAM ownership | C/V | D/V | D/C | D | Role-specific ownership and handoff |
| Measurement stash register bank | C | D | D | C | MCU deposit and Caliptra Runtime drain |
| DMA access / size / tracking changes | D/V | C/V | D/V | C/V | Caliptra-only programming; route limits |
| I3C v1p6 and controller fixes | V | D/V | V | D/V | Recovery and normal I3C regressions |

Indirect impact does not mean MCU software implements cryptography. MCU remains
outside the Caliptra crypto boundary and uses Caliptra services, but service
failures, timing, attestation, and provisioning behavior affect MCU workflows.

## Highest-Priority Contracts

### Boot-Flow Monitor and Key Vault Transition Policy

Hardware detects ROM -> FMC -> Runtime transitions from ICCM accesses. Before
entering FMC, ROM must program the FMC/Runtime ICCM-relative bounds using two
matching writes per shadow register, then set the region lock. Uncommitted
bounds or invalid transitions can trigger fatal KV errors and flush keys.

The monitor also checks DICE slot permissions and crypto write counts, applies
slot locks/clears at transitions, and locks DOE after ROM. Reconcile key
allocation, derivation order, destination-valid masks, and reset behavior.
Stable-owner-key and OCP LOCK slots have specific preservation rules; MEK slot
23 is always cleared at transitions.

The searched production ROM/driver/FMC paths in examined Caliptra software main
did not show the new ICCM-region programming. This is a source-inspection
integration gap, not a demonstrated boot failure.

**Validation trap:** the pinned core sets `sim_boot_flow_monitor_dis = 1` under
`SIMULATION`. In production, the monitor is enabled with debug locked and scan
mode off. Ordinary simulation success can miss a production incompatibility.
Explicitly test the enabled monitor under production-like conditions.

Sources:
[chipsalliance/caliptra-rtl#1260](https://github.com/chipsalliance/caliptra-rtl/pull/1260),
[pinned boot-policy specification](https://github.com/chipsalliance/caliptra-rtl/blob/7b901d59ba92d8d3b19b7f63ecb77806404503f2/docs/CaliptraHardwareSpecification.md#key-vault-boot-flow-transition-enforcement),
[monitor enable RTL](https://github.com/chipsalliance/caliptra-rtl/blob/7b901d59ba92d8d3b19b7f63ecb77806404503f2/src/integration/rtl/caliptra_top.sv#L651).

### HMAC Is a Functional Driver Migration

The new engine exposes six LFSR-seed DWORDs instead of twelve and a LAST control
bit marking the final INIT/NEXT block. Readiness and completion handling must
match the shared engine.

Examined Caliptra software main still constructs/writes twelve seed DWORDs.
The inspected block submission writes INIT/NEXT/mode/CSR mode without LAST.
The open seed-width fix is not evidence that the complete protocol is integrated.
Regenerating register bindings alone is insufficient.

Affected users include Caliptra ROM DICE/identity, FMC derivation, Runtime
KDF/crypto services, manufacturing, and MCU workflows using those services.

Sources:
[chipsalliance/caliptra-rtl#1274](https://github.com/chipsalliance/caliptra-rtl/pull/1274),
[pinned HMAC RDL](https://github.com/chipsalliance/caliptra-rtl/blob/7b901d59ba92d8d3b19b7f63ecb77806404503f2/src/hmac/rtl/hmac_reg.rdl),
[examined driver](https://github.com/chipsalliance/caliptra-sw/blob/898be94aad08d5c616497ccd19980595cef46f14/drivers/src/hmac.rs#L230),
[open adaptation, chipsalliance/caliptra-sw#4217](https://github.com/chipsalliance/caliptra-sw/pull/4217).

### MCU Fuse-Lock Helper Versus W1S Bitmasks

The newer fuse controller defines separate sticky W1S lock masks for
manufacturing PK hash, production PK hashes, and ratchet seeds. Each bit
protects one item; locks clear on subsystem reset.

The current [OTP helper](../../romtime/src/otp.rs) writes `index + 1` to the
production PK-hash lock register. Its [ROM caller](../../rom/src/rom.rs) describes
locking the selected slot and all higher slots. An ordinal write does not
implement that policy on the new per-bit interface, and manufacturing slot 0
has its own lock CSR.

Map the selected slot to its lock domain, construct the complete policy mask,
and reapply on cold and warm boot. Test every configured slot. This mismatch
already matters with the hardware checkout used during research.

Sources:
[chipsalliance/caliptra-ss#1166](https://github.com/chipsalliance/caliptra-ss/pull/1166),
[pinned fuse-lock specification](https://github.com/chipsalliance/caliptra-ss/blob/af14a79869c7df7296352fd41bdd51fba3c44464/docs/CaliptraSSHardwareSpecification.md#locking-the-validated-public-key-partition).

### Hardware ICCM Measurement and PCR Ownership

The SHA accelerator automatically measures actual ICCM writes, finalizes on
ICCM lock, and extends:

- PCR4: ICCM Current, cleared on firmware-update ICCM unlock.
- PCR5: ICCM Journey, cleared only on cold reset.

Normal firmware PCR paths cannot write arbitrary nonzero values into these
entries. Hardware also owns the SHA accelerator during measurement. Qualify
ROM load/lock order, accelerator arbitration, firmware-update resets, Runtime
quotes/logs, and verifier reference values.

A manifest digest is not automatically the same as this write-stream
measurement. Validate exact content/order, byte ordering, PCR formula, and reset
lifetime. This does not replace signature authentication or all software
post-copy integrity checks.

Sources:
[chipsalliance/caliptra-rtl#1292](https://github.com/chipsalliance/caliptra-rtl/pull/1292),
[pinned measurement specification](https://github.com/chipsalliance/caliptra-rtl/blob/7b901d59ba92d8d3b19b7f63ecb77806404503f2/docs/CaliptraHardwareSpecification.md#iccm-write-hash-measurement-pcr4pcr5),
[hitless-update unlock/hash fix, chipsalliance/caliptra-rtl#1417](https://github.com/chipsalliance/caliptra-rtl/pull/1417).

### Measurement Stash Register Bank

The target core implements eight addressable slot layouts of 26 DWORDs each,
but **only slot 0 is writable in subsystem builds**. Each contains metadata,
SHA-384 measurement, context, and SVN. Slot commit, end-of-stash, post-drain
locks, and mailbox AXI-user authorization govern access.

[MCU ROM](../../rom/src/cold_boot.rs) currently submits its ROM measurement
through `STASH_MEASUREMENT`. Caliptra software main conditionally removes that
ROM mailbox command under `stash-measurement-registers`; Runtime draining is
still open integration work. Coordinate producer, consumer, feature selection,
and locking. The legacy path is not universally removed in all builds.

Sources:
[merged bank, chipsalliance/caliptra-rtl#1395](https://github.com/chipsalliance/caliptra-rtl/pull/1395),
[pinned bank RDL](https://github.com/chipsalliance/caliptra-rtl/blob/7b901d59ba92d8d3b19b7f63ecb77806404503f2/src/soc_ifc/rtl/soc_ifc_external_reg.rdl#L565),
[conditional ROM removal, chipsalliance/caliptra-sw#4238](https://github.com/chipsalliance/caliptra-sw/pull/4238),
[open drain, chipsalliance/caliptra-sw#4265](https://github.com/chipsalliance/caliptra-sw/pull/4265).

## Features Listed on the Slide

### USB Virtual Hub and Streaming Boot

MCU owns DEV0 and the virtual hub; designated SoC firmware owns DEV1. MCU
Runtime may need USB/MCTP for SPDM/PLDM depending on the product. Caliptra does
not need a full USB stack if its recovery/DMA layer uses the OCP aperture
correctly.

At the pinned target:

- Combo base + `0x0800` is the Recovery aperture; hub starts at + `0x1000`.
- MCU LSU and Caliptra DMA must be authorized for Combo; DEV1 has separate
  authorization.
- All four USB AXI interfaces require aligned, full 32-bit accesses. Byte
  copies and partial/strobed writes are not supported MMIO operations.
- OCP offsets changed to align with I3C: Recovery-local `RECOVERY_CTRL` is
  `0x3c`; `INDIRECT_FIFO_DATA` is `0x68`.
- Filter policies are live integration inputs, not automatically locked USB
  configuration registers. Coordinate SoC policy locking.

Audit MCU ROM hub/descriptors/DEV0 setup, recovery selection/status, Caliptra
ROM/Runtime recovery-base and DMA routing, Runtime endpoints, and host
enumeration/abort/reset behavior.

The [emulator USB driver](../../platforms/emulator/rom/usb/src/lib.rs) is an
exemplar using `usbdev`, not proof of qualified real-controller support.
The subsystem's USB Streaming Boot section is still "Coming Soon"; supplement
it with RTL, RDL, tests, and integration requirements.

Sources:
[pinned USB specification](https://github.com/chipsalliance/caliptra-ss/blob/af14a79869c7df7296352fd41bdd51fba3c44464/docs/CaliptraSSHardwareSpecification.md#caliptra-ss-usb2),
[integration requirements](https://github.com/chipsalliance/caliptra-ss/blob/af14a79869c7df7296352fd41bdd51fba3c44464/docs/CaliptraSSIntegrationSpecification.md#usb-integration-requirements),
[offsets/isolation, chipsalliance/usb2#48](https://github.com/chipsalliance/usb2/pull/48),
[filtering, chipsalliance/usb2#42](https://github.com/chipsalliance/usb2/pull/42).

### DCLS and Core Fault Countermeasures

There is no firmware-visible second CPU to schedule. MCU ROM controls the
comparison policy: MCI `HW_CAPABILITIES[2]` is a break-glass disable, so zero
means enabled. Preserve it when selecting streaming boot, leave it clear
normally, and lock configuration with `CAP_LOCK`. Caliptra observes
`CPTRA_HW_CONFIG.DCLS_en`.

New telemetry includes `rv_dcls_err`. Sticky status and the fatal output have
different clearing/reset behavior; W1C status clearing is not recovery.

The pinned specification says DCCM write-readback and ICCM/DCCM address-XOR
countermeasures are **compiled out of the delivered configuration**. Qualify
them only if re-enabled. Do not treat a draft feature inventory as proof of
enabled protection. Register-file comparison is part of the imported VeeR work.

Open PRs still address passive-profile reporting and synchronizer placement;
the target subsystem does not implicitly include them.

Sources:
[MCI DCLS policy](https://github.com/chipsalliance/caliptra-ss/blob/af14a79869c7df7296352fd41bdd51fba3c44464/docs/CaliptraSSIntegrationSpecification.md#caliptra-core-dcls-corruption-detection-control),
[core configuration caveats](https://github.com/chipsalliance/caliptra-rtl/blob/7b901d59ba92d8d3b19b7f63ecb77806404503f2/docs/CaliptraHardwareSpecification.md#dual-core-lockstep-dcls),
[chipsalliance/caliptra-rtl#1435](https://github.com/chipsalliance/caliptra-rtl/pull/1435),
[chipsalliance/caliptra-rtl#1454](https://github.com/chipsalliance/caliptra-rtl/pull/1454).

### ABR, ECC, and Explicit Verification Status

ABR architectural masking, Keccak/SHAKE masking, SRAM timing, and pipeline/storage
changes require driver, KAT, timeout, zeroization, and error-path qualification.
Do not infer identical latency or software speedup from area claims.

ECC and ML-DSA now expose explicit `VERIFY_PASS` status: ECC bit 2 and ML-DSA bit
4. It clears on command start/reset/zeroization/error and is a verdict for the
completed relevant operation. ROM/Runtime drivers should consume it at completion
and retain software result cross-checks as fault-attack defense. FMC crypto
users are also in scope.

Sources:
[chipsalliance/caliptra-rtl#1335](https://github.com/chipsalliance/caliptra-rtl/pull/1335),
[chipsalliance/adams-bridge#297](https://github.com/chipsalliance/adams-bridge/pull/297),
[draft ABR inventory](https://github.com/chipsalliance/caliptra-rtl/pull/1432).

### Dual-Source TRNG

Dual mode combines independent entropy-source outputs using SHA3-384. Caliptra
ROM must qualify configuration, run the combiner power-on KAT, set policy, and
apply its write-once AHB lock. Runtime must not assume it can rerun the locked
KAT or weaken policy. Test starvation, faults, zeroization, and reseeding.

MCU does not become the entropy producer or implement the combiner. Its impacts
are configuration, boot latency, and Caliptra-service failures. Single-source
bypass remains supported when dual mode is disabled.

Sources:
[chipsalliance/caliptra-rtl#1349](https://github.com/chipsalliance/caliptra-rtl/pull/1349),
[pinned combiner/KAT/lock specification](https://github.com/chipsalliance/caliptra-rtl/blob/7b901d59ba92d8d3b19b7f63ecb77806404503f2/docs/CaliptraHardwareSpecification.md#dual-itrng-entropy-combiner).

### MCU ROM Patch SRAM

This is optional pre-production patch memory, not arbitrary field patching:

- MCU LSU loads sequential full words from offset zero in allowed
  TEST_LOCKED/TEST_UNLOCKED/DEV states, before Caliptra first leaves reset in
  the power cycle.
- Pad to a 16-byte boundary for IFU fetch and respect the loaded-word boundary.
- Any accepted write marks the device patched until cold reset.
- Patched UDS/FE delivered to Caliptra are zeroized; secret provisioning/digest
  commands are discarded.
- Patch and status survive warm reset; ROM reuses rather than reloads.
- Unpatched SRAM becomes data-only memory when MCU Runtime runs, and closes
  again on warm reset. It is not generally executable Runtime RAM.
- Size zero removes the mapped patch SRAM.

Adoption needs an explicit patch source/format/policy and ROM load/dispatch
hooks. Runtime must honor patch/data-memory lifetimes, and provisioning/identity
tests must distinguish patched devices. Hardware alone supplies no software
patch ABI.

Sources:
[chipsalliance/caliptra-ss#1335](https://github.com/chipsalliance/caliptra-ss/pull/1335),
[pinned patch specification](https://github.com/chipsalliance/caliptra-ss/blob/af14a79869c7df7296352fd41bdd51fba3c44464/docs/CaliptraSSHardwareSpecification.md#mcu-rom-patch-sram).

## Additional Changes Beyond the Slide's High-Level List

### Exclusive MCU Mailbox SRAM Ownership

MCI distinguishes Requester, Root, and Target. SRAM belongs to one owner at a
time; trusted AXI-user status alone is insufficient. Target-valid configuration
and terminal target-status transitions govern handoff. Audit MCU Runtime
drivers/capsules, ROM/manufacturing helpers, and Caliptra-forwarded requests for
access after transfer or before ownership reacquisition.

Sources:
[chipsalliance/caliptra-ss#1262](https://github.com/chipsalliance/caliptra-ss/pull/1262),
[pinned ownership specification](https://github.com/chipsalliance/caliptra-ss/blob/af14a79869c7df7296352fd41bdd51fba3c44464/docs/CaliptraSSHardwareSpecification.md#mcu-mailbox-sram-ownership).

### Sparse FSMs, Fatal Reporting, and Reset Recovery

MCI invalid-state detection enters BOOT_ERROR, holds MCU and Caliptra in reset,
and sets an unmaskable fatal error. Warm reset recovers the FSM; status persists
for diagnosis until cleared. A reset-held MCU cannot publish status: reporting
must involve post-reset ROM and/or an external SoC agent.

Existing MCU issue #2183 requests reporting through active I3C/USB OCP
DEVICE_STATUS. Core sparse encoding does not imply changing every software
constant: the target explicitly preserves compact
`CPTRA_FLOW_STATUS.boot_fsm_ps`, including BOOT_DONE = 4.

Sources:
[chipsalliance/caliptra-ss#1314](https://github.com/chipsalliance/caliptra-ss/pull/1314),
[#2183](https://github.com/chipsalliance/caliptra-mcu-sw/issues/2183),
[reset behavior](https://github.com/chipsalliance/caliptra-ss/blob/af14a79869c7df7296352fd41bdd51fba3c44464/docs/CaliptraSSIntegrationSpecification.md#boot-fsm-error-reset-behavior),
[software state encoder](https://github.com/chipsalliance/caliptra-rtl/blob/7b901d59ba92d8d3b19b7f63ecb77806404503f2/src/soc_ifc/rtl/soc_ifc_pkg.sv#L160).

### KV Length, AES, and Update Isolation

KV consumers reject undersized entries with `KV_RD_LEN_MISMATCH`; larger entries
may support safe prefix reads. Drivers must check errors rather than treating
ready/stopped as success. Firmware-update reset blocks/aborts KV transactions.
AES keys are masked at the KV interface and entropy reseeding is restricted.
Qualify ROM KATs, Runtime crypto, OCP LOCK, and updates with operations in flight.

Sources:
[chipsalliance/caliptra-rtl#1353](https://github.com/chipsalliance/caliptra-rtl/pull/1353),
[chipsalliance/caliptra-rtl#1388](https://github.com/chipsalliance/caliptra-rtl/pull/1388),
[chipsalliance/caliptra-rtl#1225](https://github.com/chipsalliance/caliptra-rtl/pull/1225).

### Fuse/Debug Identity Behavior

Physical debug intent suppresses loading secrets into fuse buffers. MCU-driven
debug intent and `SECRET_DIGEST_READ_LOCK` mask digest observations: named
digest CSRs can return a provisioned indicator, while DAI reads are zero.
Physical debug intent can instead leave named digest CSRs zero because sensing
was suppressed. Do not interpret those values as raw digest contents.

In subsystem mode, core UDS/FE come from fuse ports rather than SoC writes to
core secret registers. Audit manufacturing/debug injection and readback tests.
MCU ROM must set permitted early debug policy before sticky configuration lock.

Sources:
[chipsalliance/caliptra-ss#1215](https://github.com/chipsalliance/caliptra-ss/pull/1215),
[chipsalliance/caliptra-ss#1209](https://github.com/chipsalliance/caliptra-ss/pull/1209),
[chipsalliance/caliptra-rtl#1425](https://github.com/chipsalliance/caliptra-rtl/pull/1425).

### DMA and I3C

SoC AXI access to core DMA registers now returns SLVERR: programming is
Caliptra-uC-only. MCU/host code should request Caliptra services instead.
Maximum payload increased to 2 GiB, but route-specific limits, alignment, and
address ranges still apply. Do not raise every software limit to 2 GiB.
Response-tracking and mailbox ECC fixes warrant load/decrypt/update regressions.

I3C remains relevant with USB enabled. The target pins v1p6 changes covering CCC
handoff/reset/error handling and parameter-based configuration. Retain normal
I3C/MCTP and I3C/AXI recovery tests and verify the MCU/Caliptra DMA AXI-user policy.

Sources:
[chipsalliance/caliptra-rtl#1350](https://github.com/chipsalliance/caliptra-rtl/pull/1350),
[chipsalliance/caliptra-rtl#1374](https://github.com/chipsalliance/caliptra-rtl/pull/1374),
[chipsalliance/caliptra-rtl#1369](https://github.com/chipsalliance/caliptra-rtl/pull/1369),
[chipsalliance/caliptra-ss#1376](https://github.com/chipsalliance/caliptra-ss/pull/1376).

## Recommended Migration and Acceptance Tests

### P0: Establish a Coherent, Bootable Bundle

1. Freeze subsystem/core/ABR/USB/I3C pins, ROM images, Caliptra software,
   register-generation inputs, and feature selection.
2. Regenerate MCU and Caliptra bindings; review offsets and access policies,
   not only compilation failures.
3. Integrate HMAC protocol/seed changes, boot-monitor programming, and
   compatible FMC/KV derivation.
4. Correct fuse-lock masks/domains, preserve/lock DCLS policy, and coordinate
   stash producer/consumer gating.
5. Validate cold, warm, and update boots with the monitor enabled and
   debug-locked, production-like conditions.

### P1: Qualify Identity, Attestation, and Shared Interfaces

1. Test valid/invalid ECC and ML-DSA verification, including both operation
   orderings, and check verdict freshness.
2. Validate DICE/certificates/quotes, PCR4/PCR5 formulas and reset lifetimes,
   and SHA accelerator arbitration.
3. Run KATs and entropy starvation/fault/reseed/zeroization tests in single-
   and dual-source modes; verify combiner policy/KAT lock.
4. Exercise mailbox Requester -> Root -> Target -> completion, denied
   accesses, aborts, and reset clearing.
5. Test every configured fuse-lock slot/domain, warm-reset reapplication,
   debug secret/digest visibility, provisioning errors, and OCP LOCK key
   preservation.
6. Inject MCI/core fatal conditions; verify external/post-reset reporting and
   actual reset recovery rather than just W1C status clearing.

### P2: Enable Product-Specific Features

1. Test the real USB controller: hub and both devices, descriptors, ownership,
   FIFO recovery, short/final transfers, abort/reset/retry, concurrent DEV1,
   full-DWORD MMIO, and unauthorized AXI users.
2. Qualify MCU Runtime USB/MCTP/SPDM/PLDM if needed; retain I3C, flash, and
   network boot coverage.
3. If adopted, test patch-SRAM cold/warm reuse, production/RMA denial,
   sequential-load/fetch bounds, identity restrictions, and data-only release.

Priorities express migration sequencing. USB is naturally a boot prerequisite
for a USB-only product.

## Open Questions and Non-Hardware Work

- The slide's "NMI hardening" has not been mapped to a confirmed new firmware
  ABI. The pinned core still exposes a programmable internal NMI vector.
  Qualify NMI/watchdog/error behavior and obtain the intended RTL change before
  claiming a new lock bit or ROM sequence.
- Open DCLS, entropy-source, and software PRs may change requirements beyond
  this pinned snapshot.
- Dedicated PCR quote signing keys are open software work,
  [chipsalliance/caliptra-sw#4064](https://github.com/chipsalliance/caliptra-sw/pull/4064),
  not an established mandatory RTL interface.
- MCU LMS fallback issue
  [#2182](https://github.com/chipsalliance/caliptra-mcu-sw/issues/2182) is relevant
  2.2 signing/release policy, not evidence of a new LMS hardware block.
- The closed unified-build prototype
  [chipsalliance/caliptra-sw#4242](https://github.com/chipsalliance/caliptra-sw/pull/4242)
  was not merged; do not assume production multi-version support is available.
- No firmware build, RTL simulation, or FPGA qualification was performed for
  this research. Acceptance tests above remain to be executed.

## Code Starting Points

| Area | Repository starting points |
|---|---|
| Fuse locks | [OTP helper](../../romtime/src/otp.rs), [ROM caller](../../rom/src/rom.rs) |
| Measurement deposit | [MCU cold boot](../../rom/src/cold_boot.rs), `rom_digest_integrity` / `stash_measurement` |
| Boot/configuration/status | [ROM](../../rom/src/rom.rs), [cold boot](../../rom/src/cold_boot.rs), [warm boot](../../rom/src/warm_boot.rs), [MCI](../../romtime/src/mci.rs) |
| Hardware-specific ROM | [FPGA setup](../../platforms/fpga/rom/src/riscv.rs) |
| USB | [OCP abstraction](../../common/ocp/src/usb/), [recovery provider](../../rom/src/recovery/ocp.rs), [emulator exemplar](../../platforms/emulator/rom/usb/src/lib.rs) |
| MCU mailbox | [HIL](../../runtime/kernel/drivers/mcu_mbox/), [platform driver](../../platforms/emulator/runtime/kernel/drivers/mcu_mbox/src/lib.rs), [ROM helpers](../../romtime/src/mci_mbox_cmd.rs) |
| Registers/models | [Generator](../../registers/generator/), [firmware bindings](../../registers/generated-firmware/), [emulator bindings](../../registers/generated-emulator/), [peripherals](../../emulator/periph/), [hardware model](../../hw/model/) |
| Caliptra ROM/FMC/Runtime | [Pinned Caliptra software](https://github.com/chipsalliance/caliptra-sw/tree/b99535ded32492d6c23bbc56f95e787a1e275b59); shared HMAC/ECC/ML-DSA/TRNG/PCR drivers and ROM/FMC/Runtime flows |

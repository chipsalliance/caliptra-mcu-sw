# MCU and SoC Firmware Measurement Stashing: Recommendations

## Topics for Discussion

- During Recovery boot flow, should MCU FW measurement be stashed?
- During FW Update,  should MCU FW measurement be stashed (extended)?
- During Image Loading, should SoC FW measurements be stashed?
- During FW Update, should SoC FW measurements be stashed (extended)?

## Background

During the Caliptra recovery/boot flow and hitless update flows, firmware images (MCU RT FW and SoC FW)
are authorized via the `AUTHORIZE_AND_STASH` mailbox command. This command has a `SKIP_STASH` flag
that controls whether the firmware measurement is stashed into DPE (as a DICE context node) and
extended into PCR31, or whether only authorization (hash verification against the SoC Manifest) is performed.

This document analyzes the current behavior, the specification requirements, and provides recommendations.

---

## Current Behavior

| Flow | File | `SKIP_STASH`? | Stashed into DPE? | Extended into PCR31? |
|------|------|:---:|:---:|:---:|
| **MCU FW — Cold Boot (Recovery Flow)** | `runtime/src/recovery_flow.rs` | Yes (via `..Default::default()`) | No | No |
| **MCU FW — Hitless Update** | `runtime/src/activate_firmware.rs` | Yes (explicit) | No | No |
| **SoC FW — Boot/Update (via MCU)** | Caller chooses flags in `AUTHORIZE_AND_STASH` | Depends on caller | Depends on caller | Depends on caller |

### Code References

**Recovery Flow** (`runtime/src/recovery_flow.rs`, lines 94–102):
```rust
let auth_and_stash_req = AuthorizeAndStashReq {
    fw_id: [2, 0, 0, 0],
    measurement: digest,
    source: ImageHashSource::InRequest.into(),
    ..Default::default()  // flags defaults to SKIP_STASH (0x1)
};
```

**Hitless Update** (`runtime/src/activate_firmware.rs`, line 214):
```rust
let auth_and_stash_req = AuthorizeAndStashReq {
    fw_id: ActivateFirmwareReq::MCU_IMAGE_ID.to_le_bytes(),
    measurement: [0; 48],
    source: ImageHashSource::LoadAddress.into(),
    flags: AuthAndStashFlags::SKIP_STASH.bits(),  // Explicitly skipped
    ..Default::default()
};
```

---

## Specification Excerpts Supporting Measurement Stashing

### 1. Caliptra Checklist — MUST requirement for SoC FW measurement

> *"SOC firmware that interacts with Caliptra as the privileged PA_USER **MUST** be measured, and those
> measurements **MUST** be submitted to Caliptra. Other SOC firmware **SHOULD** be measured. Configuration
> data that modifies the security properties of firmware **MUST** also be measured."*
>
> *"Measurements of firmware and configuration **MUST** be submitted to Caliptra **before execution** of the
> firmware, or usage of the configuration data."*
>
> — `CaliptraChecklistAndEvaluationMethodology.md`, line 200

### 2. Boot flow — firmware chain-of-trust requires measurement deposit

> *"Each firmware fetches, authenticates, measures, and executes the next firmware needed to establish
> the device operating environment. Each firmware **deposits the next firmware's measurements into Caliptra**
> prior to execution."*
>
> — `doc/Caliptra.md`, line 278

### 3. Measurement Vault — Caliptra's stated purpose includes stashing

> *"**Measurement Vault**: Caliptra shall support stashing of measurements for the code and
> configuration of the SoC. Caliptra can provide these measurements via PCR Quote API or via DPE."*
>
> — `doc/Caliptra.md`, line 683

### 4. Remote attestation depends on stashed measurements

> *"An Alias_RT-signed certificate over a leaf DPE key, which includes PCR3 as read by runtime
> firmware, along with **other measurements previously stashed in SRAM**."*
>
> — `doc/Caliptra.md`, line 807

> *"The verifier can also optionally inspect other measurements in (4) to evaluate the journey of
> **other SoC components, whose measurements were previously stored within Caliptra's SRAM**."*
>
> — `doc/Caliptra.md`, line 819

### 5. Journey measurement tracking for SoC components

> *"Caliptra shall maintain a reboot counter for each component. Caliptra shall increment the
> reboot counter and **update the journey measurement** for calls that indicate that the component's
> state changed."*
>
> — `doc/Caliptra.md`, line 839


## PL0 Privilege Enforcement in Code

PL0 is the high-privilege PAUSER level — only one PAUSER in the SoC may be PL0, and it is
designated in the signed Caliptra firmware image header (`pl0_pauser` field). The following
runtime commands enforce PL0-only access:

| Command | File | Enforcement |
|---|---|---|
| `STASH_MEASUREMENT` | `runtime/src/stash_measurement.rs` (line 42) | Only PL0 can call — PL1 returns `RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL` |
| `CertifyKey` (X.509) | `runtime/src/invoke_dpe.rs` (line 90) | Only PL0 can request X.509 format |
| `ExportCDI` | `runtime/src/invoke_dpe.rs` (line 95) | Only PL0 can export CDIs |
| `SignWithExportedEcdsa` | `runtime/src/sign_with_exported_ecdsa.rs` (line 62) | Only PL0 |
| `CertifyKeyExtended` | `runtime/src/certify_key_extended.rs` (line 41) | Only PL0 |
| `RevokeExportedCdiHandle` | `runtime/src/revoke_exported_cdi_handle.rs` (line 29) | Only PL0 |
| `ReallocateDpeContextLimits` | `runtime/src/reallocate_dpe_context_limits.rs` (line 44) | Only PL0 |
| OCP LOCK commands | `runtime/src/ocp_lock/mod.rs` (line 1274) | Only PL0 |


---

## Journey Measurements: Caliptra FW vs SoC/MCU FW

### What is a journey measurement?

A journey measurement is a **cumulative cryptographic record** of every firmware/configuration
state a component has passed through since cold boot. Unlike a "current" measurement (which
captures only what is running *right now*), the journey captures the full update path.

**Example:** A device cold boots firmware A, hitlessly updates to B, then to C.
- **Current measurement** = hash(C) — only the latest state
- **Journey measurement** = extend(extend(hash(A), hash(B)), hash(C)) — the full path \[A→B→C\]

This matters because vulnerabilities in firmware B might have tainted the device even though
B is no longer running. A remote verifier can walk the journey to detect if a known-bad
version ever ran since cold boot.

### Caliptra's own FW: dedicated current/cumulative PCR pairs

Caliptra uses paired PCR registers to track the journey of its own internal firmware:

| PCR | Type | Extended By | Purpose |
|-----|------|-------------|---------|
| PCR0 | Current | ROM | Current FMC measurement + ROM policy config |
| PCR1 | Cumulative | ROM | **Journey** of FMC measurement + ROM policy config |
| PCR2 | Current | FMC | Current RT FW + manifest measurements |
| PCR3 | Cumulative | FMC | **Journey** of RT FW + manifest measurements |

**"RT FW" here refers to Caliptra's own Runtime firmware** — the firmware running on the
Caliptra microcontroller itself (not MCU or SoC firmware). The Caliptra boot chain is:

| Stage | Full Name | Description |
|-------|-----------|-------------|
| ROM | Caliptra ROM | Immutable boot code baked into silicon |
| FMC | First Mutable Code | First updatable Caliptra firmware, launched by ROM |
| RT | Caliptra Runtime | Caliptra's runtime firmware, launched by FMC — handles mailbox commands, DPE, attestation |

FMC extends both PCR2 (current) and PCR3 (cumulative) every time it loads an RT image
(`fmc/src/flow/pcr.rs`, lines 64–67):

```rust
env.pcr_bank.extend_pcr(RT_FW_CURRENT_PCR, &mut env.sha2_512_384, data)?;  // PCR2
env.pcr_bank.extend_pcr(RT_FW_JOURNEY_PCR, &mut env.sha2_512_384, data)?;  // PCR3
```

On every hitless update, PCR2 is **erased and re-extended** with the new RT measurement, while
PCR3 **accumulates** (never erased — only reset on cold boot). The journey PCR (PCR3) is then
copied into the DPE root context's `tci_cumulative` (`runtime/src/drivers.rs`, line 569):

```rust
env.state.contexts[root_idx].tci.tci_cumulative =
    TciMeasurement(drivers.pcr_bank.read_pcr(RT_FW_JOURNEY_PCR).into());
```

PCR3 is included in DPE leaf key certificates, so a remote verifier can confirm through the
certificate chain and the PCR log that no bad Caliptra RT firmware ever ran since cold boot.

### SoC/MCU FW: no dedicated PCR pairs — uses PCR31 + DPE

SoC and MCU firmware components do **NOT** get their own current/cumulative PCR pairs. Instead,
their journey tracking relies on a different mechanism:

| Mechanism | Storage | How it's populated |
|-----------|---------|-------------------|
| **PCR31** (cumulative) | Hardware register | Extended by each `STASH_MEASUREMENT` / `AUTHORIZE_AND_STASH` (without `SKIP_STASH`) |
| **DPE child context nodes** | SRAM | A new DPE context node created per stash, building a tree |
| **Reboot counter** | Per-component counter | Incremented on state changes |

Per the spec ("Attestation of SoC update journey", `doc/Caliptra.md`, line 839):

> *"Caliptra **shall** maintain a reboot counter for each component. Caliptra **shall** increment
> the reboot counter and **update the journey measurement** for calls that indicate that the
> component's state changed."*

If MCU FW were properly stashed (not skipped), the journey would work like this:

1. Cold boot → stash MCU FW A → PCR31 = extend(0, hash(A)), DPE context node created
2. Hitless update to B → stash MCU FW B → PCR31 = extend(prev, hash(B)), another DPE node created
3. Verifier can reconstruct the \[A→B\] journey from the DPE tree + PCR31 + event log

### Current gap: NO journey tracking for MCU FW

Since `SKIP_STASH` is set for MCU FW in both `recovery_flow.rs` (cold boot) and
`activate_firmware.rs` (hitless update), **there is currently no journey tracking for MCU FW
at all**. The measurement is authorized (hash-checked against the SoC Manifest) but never
recorded — not in PCR31, not in DPE, and not in any dedicated PCR. This means:

- A remote verifier **cannot** confirm which MCU FW version is running
- A remote verifier **cannot** detect if a known-bad MCU FW version ran at any point since cold boot
- The spec's journey tracking requirement for SoC components is not fulfilled for MCU FW

---

## DPE Tree Structure and MCU Journey Management Options

### Resulting DPE tree after cold boot (current implementation)

During `initialize_dpe()` on cold boot, RT builds the DPE tree in this order:

1. **Root context (auto-init):** `DpeInstance::new_auto_init(tci_type="RTMR", measurement=PCR2)`,
   then `tci_cumulative` overwritten with PCR3 (RT FW journey). Locality = `CALIPTRA_LOCALITY` (0xFFFFFFFF).
2. **Valid PAUSER hash node:** `DeriveContext(default, hash(mbox_valid_pausers), tci_type="MBVP",
   MAKE_DEFAULT | CHANGE_LOCALITY)`. Changes locality to `pl0_pauser`.
3. **ROM measurement replay (0..N):** For each `STASH_MEASUREMENT` logged by ROM, a `DeriveContext`
   with `MAKE_DEFAULT` chains below the PAUSER node at `pl0_pauser` locality.

```
Root (CALIPTRA_LOCALITY = 0xFFFFFFFF)
│  tci_type: "RTMR"
│  tci_current: PCR2 (current Caliptra RT FW measurement)
│  tci_cumulative: PCR3 (Caliptra RT FW journey)
│
└── Valid PAUSER Hash (pl0_pauser locality, e.g. 0x1)
    │  tci_type: "MBVP"
    │  tci_current: SHA384(locked mbox valid pausers)
    │
    └── ROM Measurement 0 (pl0_pauser locality)
        └── ROM Measurement 1
            └── ... ROM Measurement N  ← current default handle
```

> **Note:** Each `DeriveContext` uses `MAKE_DEFAULT`, so the tree is a **linear chain** — each
> new node becomes the default handle. The chain represents temporal order of stashing.

### After MCU FW A is stashed and SoC images are authorized (proposed fix applied)

If `recovery_flow.rs` is fixed to set `flags: 0` (stash enabled), and the MCU subsequently
authorizes SoC images without `SKIP_STASH`:

```
Root ("RTMR" — Caliptra RT identity)
└── Valid PAUSER Hash ("MBVP")
    └── [ROM stashes 0..N]
        └── MCU FW A                          ← stashed during recovery flow
            │  tci_type: [2,0,0,0]
            │  tci_current: SHA384(MCU FW A image)
            │
            └── SoC Image 1                   ← stashed by MCU via AUTHORIZE_AND_STASH
                └── SoC Image 2
                    └── SoC Image 3           ← current default handle
```

The DPE leaf key derived from the default handle now includes **every** measurement in the
path: Caliptra RT → PAUSER config → ROM stashes → MCU FW A → SoC images. A `CertifyKey`
on the default handle produces a certificate with all these in its DICE extensions.

### Impact of MCU FW hitless update (naive stash — new node appended)

If `activate_firmware.rs` also stashes MCU FW B (without `SKIP_STASH`), the new measurement
chains below the **current default handle** (SoC Image 3, not MCU FW A):

```
Root ("RTMR")
└── PAUSER ("MBVP")
    └── [ROM stashes]
        └── MCU FW A
            └── SoC Image 1          ← authorized by MCU FW A
                └── SoC Image 2
                    └── SoC Image 3
                        └── MCU FW B              ← appended after SoC images
                            │                       (parent is SoC Image 3, not MCU FW A)
                            └── [default handle]
```

**Problems with naive stash on hitless update:**

- MCU FW B's parent is SoC Image 3, not MCU FW A — **doesn't reflect logical trust hierarchy**
- If MCU FW B re-authorizes the same SoC images, **duplicates** are created
- Each MCU update + SoC re-auth consumes additional DPE slots — **exhausts the 32-slot limit** quickly
- With 3 SoC images, each MCU update cycle consumes 4 slots (1 MCU + 3 SoC re-stash)

---

### Options for MCU Journey Measurement Management

The following options address how to track MCU FW journey measurements during hitless updates
without the problems of naive stashing.

---

#### Option 1: Use Dedicated PCRs

**Concept:** Allocate a separate general-purpose PCR (from PCR4–PCR30) specifically for MCU RT
FW journey measurements. Do not use DPE for MCU journey tracking.

**Flow:**

```
Cold boot:
  EXTEND_PCR(PCR_MCU, hash(MCU FW A))       → PCR_MCU = extend(0, hash(A))
  (MCU FW A node is stashed into DPE via recovery flow — one-time)

Hitless update A→B:
  EXTEND_PCR(PCR_MCU, hash(MCU FW B))       → PCR_MCU = extend(prev, hash(B))
  (No new DPE node created)

Hitless update B→C:
  EXTEND_PCR(PCR_MCU, hash(MCU FW C))       → PCR_MCU = extend(prev, hash(C))
```

**DPE tree stays fixed after cold boot** — no new nodes on update:
```
Root ("RTMR")
└── PAUSER ("MBVP")
    └── [ROM stashes]
        └── MCU FW A  (cold boot stash — never changes)
            └── SoC Image 1 → SoC Image 2 → SoC Image 3
```

**MCU journey is tracked in PCR_MCU** and queryable via `PCR_QUOTE`.

| Aspect | Assessment |
|--------|-----------|
| DPE slots consumed per update | 0 |
| MCU journey visible | Yes — via dedicated PCR + event log |
| MCU in DPE leaf certificate | Only cold boot measurement (static) |
| Leaf key changes on MCU update | No — DPE tree unchanged |
| Sealed secrets affected | No — leaf key stable |
| Implementation complexity | Low — one `EXTEND_PCR` call per update |

---

#### Option 2: Use Default DPE Context with In-Place Update (`add_tci_measurement` / `RECURSIVE`)

**Concept:** The MCU FW context is part of the default chain. On hitless update, instead of
creating a new child node, **update the existing MCU context in-place** using DPE's
`DeriveContext` with the `RECURSIVE` flag (or the internal `add_tci_measurement` function).

`add_tci_measurement` updates the context without creating a new node:
```rust
// tci_cumulative = HASH(tci_cumulative || new_measurement)  — journey accumulates
// tci_current = new_measurement                              — reflects current FW
```

**Flow:**

```
Cold boot:
  DeriveContext(default, hash(MCU FW A), tci_type=[2,0,0,0], MAKE_DEFAULT)
    → MCU node created in chain

  Tree:
  Root → PAUSER → [ROM] → MCU FW A → SoC 1 → SoC 2 → SoC 3
                           tci_current: hash(A)
                           tci_cumulative: hash(A)

Hitless update A→B (in-place update on MCU node):
  add_tci_measurement(MCU_handle, hash(MCU FW B))

  Tree (SAME structure — no new nodes):
  Root → PAUSER → [ROM] → MCU FW A → SoC 1 → SoC 2 → SoC 3
                           tci_current: hash(B)           ← updated
                           tci_cumulative: HASH(hash(A) || hash(B))  ← journey

Hitless update B→C:
  add_tci_measurement(MCU_handle, hash(MCU FW C))

  Tree (still the same structure):
  Root → PAUSER → [ROM] → MCU FW A → SoC 1 → SoC 2 → SoC 3
                           tci_current: hash(C)
                           tci_cumulative: HASH(HASH(hash(A)||hash(B)) || hash(C))
```

| Aspect | Assessment |
|--------|-----------|
| DPE slots consumed per update | 0 — one node forever |
| MCU journey visible | Yes — `tci_cumulative` in the DPE node captures full journey |
| MCU in DPE leaf certificate | Yes — always in the default chain, included in leaf cert DICE extensions |
| Leaf key changes on MCU update | Yes — cumulative TCI changes, so derived leaf key changes |
| Sealed secrets affected | Yes — must reseal before update (can use DPE simulation contexts) |
| Implementation complexity | Medium — need to retrieve MCU handle and call `DeriveContext(RECURSIVE)` or internal API |
| Remark | MCU context is in the default chain, so it's included in **all** PL0 DPE operations (CertifyKey, Sign, etc.) |

---

#### Option 3: Use Non-Default DPE Context Handle (separate branch)

**Concept:** Keep the MCU FW context as a **sibling branch** (not in the default chain) so it
doesn't affect normal PL0 SoC DPE operations. Use `RotateContext` to manage handles.

**Flow:**

```
Cold boot — creating MCU as a sibling branch:

  Step 1: RotateContext(default) → parent gets random handle H_parent
  Step 2: DeriveContext(H_parent, hash(MCU FW A), RETAIN_PARENT) → MCU node created, returns H_mcu
  Step 3: RotateContext(H_parent, TARGET_IS_DEFAULT) → parent becomes default again

  Tree:
  Root → PAUSER → [ROM] → Parent (default handle)
                            ├── MCU FW A (non-default handle H_mcu — saved in persistent data)
                            └── SoC 1 → SoC 2 → SoC 3 (default chain continues here)

Hitless update A→B:
  Retrieve H_mcu from persistent storage (or scan DPE contexts for tci_type=[2,0,0,0] in PL0 locality)
  add_tci_measurement(H_mcu, hash(MCU FW B))

  Tree (MCU node updated in place, default chain unaffected):
  Root → PAUSER → [ROM] → Parent (default)
                            ├── MCU FW (H_mcu) — tci_current: hash(B), tci_cumulative: journey
                            └── SoC 1 → SoC 2 → SoC 3 (unchanged)
```

| Aspect | Assessment |
|--------|-----------|
| DPE slots consumed per update | 0 — one node forever |
| MCU journey visible | Yes — `tci_cumulative` on the MCU branch |
| MCU in DPE leaf certificate | **No** — not in the default path. Only visible if verifier queries the MCU branch specifically |
| Leaf key on default path | Unchanged by MCU updates — SoC operations unaffected |
| Sealed secrets on default path | Unaffected — default leaf key stable across MCU updates |
| Implementation complexity | High — requires RotateContext + DeriveContext with RETAIN_PARENT + RotateContext back + persistent handle storage |
| Remark | MCU handle must be stored in persistent storage or retrieved by scanning for `tci_type` in PL0 locality |

---

### Comparison of options

| Aspect | Option 1: Dedicated PCR | Option 2: Default + in-place | Option 3: Non-default branch |
|--------|:-:|:-:|:-:|
| **DPE slots per update** | 0 | 0 | 0 |
| **MCU in DPE leaf cert** | No (only via PCR Quote) | Yes (always) | Only on MCU-specific branch |
| **Leaf key includes MCU** | No | Yes | Not on default path |
| **Journey tracking** | PCR only | DPE `tci_cumulative` + PCR31 | DPE `tci_cumulative` + PCR31 |
| **Impact on SoC FW ops** | None | MCU always in derivation path | None |
| **Sealed secret stability** | Stable | Changes on MCU update | Stable on default path |
| **Implementation effort** | Low | Medium | High |
| **Spec compliance** | Partial — MCU not in DPE tree for attestation | Full — MCU in attestation chain | Partial — MCU not in default attestation |

**Recommendation:** Option 2 provides the best balance of spec compliance, attestation
completeness, and implementation simplicity. MCU FW running at PL0 privilege is
security-critical, and having it in the default DPE derivation path ensures its measurement
is always included in leaf certificates and key derivations — which is what the spec intends.

---

## Recommendations

### Recommendation 1: MCU FW measurement SHOULD be stashed during cold boot recovery flow

The MCU RT FW is the most security-sensitive SoC component loaded during recovery. It runs on the
MCU and interacts with Caliptra at PL0 privilege, making it subject to the MUST requirement in the
Caliptra Checklist. The current code uses `..Default::default()` which inadvertently sets `SKIP_STASH`.

**Proposed fix** in `recovery_flow.rs`:
```rust
let auth_and_stash_req = AuthorizeAndStashReq {
    fw_id: [2, 0, 0, 0],
    measurement: digest,
    source: ImageHashSource::InRequest.into(),
    flags: 0,  // Do NOT skip stash — record in DPE + PCR31
    ..Default::default()
};
```

### Recommendation 2: MCU FW hitless update — SKIP_STASH is acceptable IF the boot measurement is already stashed

During hitless updates, the measurement was (or should have been) already recorded at cold boot.
Re-stashing would create duplicate DPE nodes and extend PCR31 redundantly. The current explicit
`SKIP_STASH` in `activate_firmware.rs` is reasonable **only if** the cold boot path stashes the
measurement first.

However, if journey tracking of MCU FW updates is desired (to track [A→B→C] update paths for
attestation), the hitless update path should also stash or extend a journey measurement.

### Recommendation 3: SoC FW measurements MUST be stashed (for PL0-interacting firmware)

Per the Caliptra Checklist MUST requirement, any SoC firmware interacting with Caliptra at PL0
must have its measurement submitted. The MCU-SW firmware update flow already uses
`AUTHORIZE_AND_STASH` for SoC images — the MCU should ensure `SKIP_STASH` is **not** set for
security-sensitive SoC components.

### Recommendation 4: Consider changing the Default for AuthorizeAndStashReq

The current `Default` impl sets `flags: SKIP_STASH`, which is a footgun — callers using
`..Default::default()` will silently skip stashing. Since the spec says stashing is the
default intent, consider changing the default to `flags: 0` (stash enabled).

---

## Pros and Cons Analysis

### Stashing MCU FW measurement during cold boot recovery

| | Stash (flags = 0) | Skip Stash (flags = SKIP_STASH) |
|---|---|---|
| **Attestation completeness** | Remote verifier can confirm which MCU FW is running via DPE leaf certificates and PCR31 quotes | Gap in attestation chain — verifier cannot verify MCU FW identity |
| **Chain of trust** | Complete: ROM → FMC → RT → MCU FW all measured | Broken at MCU FW — authorization without attestation record |
| **Spec compliance** | Aligns with Caliptra Checklist MUST requirement and boot flow spec | May violate MUST requirement for PL0-interacting firmware |
| **DPE tree impact** | Adds one DPE context node (consumes 1 of 32 slots) | No additional DPE context consumed |
| **PCR31 impact** | PCR31 reflects MCU FW measurement — queryable via PCR Quote | PCR31 does not include MCU FW |
| **Performance** | Slight overhead for DeriveContext + PCR extend (~negligible) | No overhead |
| **Backward compatibility** | Changes existing behavior — may affect tests/verifiers | Preserves current behavior |

### Stashing MCU FW measurement during hitless update

| | Stash (journey tracking) | Skip Stash (current behavior) |
|---|---|---|
| **Journey tracking** | Verifier can see MCU FW update path [A→B→C] via DPE and PCR31 | No journey tracking for MCU FW updates |
| **Spec alignment** | Matches spec requirement for reboot counter + journey measurement updates | Does not track component state changes |
| **DPE context usage** | Each update adds a DPE node — could exhaust 32-slot limit over many updates | No additional DPE contexts consumed |
| **PCR31 growth** | PCR31 continues to accumulate — cannot distinguish which extensions are MCU vs SoC | PCR31 unchanged after boot |
| **Sealed secrets** | Leaf key changes on each update — sealed secrets must be re-sealed | Leaf key stable across MCU updates |
| **Complexity** | Need to handle DPE context cleanup or rotation on update | Simple — authorize only |

### Stashing SoC FW measurements

| | Stash | Skip Stash |
|---|---|---|
| **Spec compliance** | MUST for PL0-interacting FW, SHOULD for others | Violates MUST requirement for privileged FW |
| **Attestation** | Verifier can confirm all SoC components loaded | Verifier cannot distinguish which SoC FW components ran |
| **DPE context usage** | Each SoC image consumes a DPE slot — may need careful budget management | No DPE contexts consumed |
| **Security posture** | Full measurement chain — compromised SoC FW is detectable | Silent gaps — compromised SoC FW could go undetected |
| **Flexibility** | MCU caller controls stashing per-image via flags | N/A |

---

## Summary of Action Items

| # | Action | Priority | Files Affected |
|---|--------|----------|---------------|
| 1 | Set `flags: 0` in `recovery_flow.rs` to stash MCU FW measurement at cold boot | High | `runtime/src/recovery_flow.rs` |
| 2 | Consider changing `AuthorizeAndStashReq::default()` to not set `SKIP_STASH` | Medium | `api/src/mailbox.rs` |
| 3 | Evaluate whether MCU FW hitless update should track journey measurements | Medium | `runtime/src/activate_firmware.rs` |
| 4 | Ensure MCU-SW firmware update code does not set `SKIP_STASH` for PL0 SoC images | Medium | `caliptra-mcu-sw` (MCU-side code) |
| 5 | Add integration tests verifying MCU FW measurement appears in DPE tree and PCR31 after recovery | Low | `runtime/tests/` |

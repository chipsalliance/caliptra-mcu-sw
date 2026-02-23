# MCU and SoC Firmware Measurement Stashing: Recommendations

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

**Default Implementation** (`api/src/mailbox.rs`, line 2155):
```rust
impl Default for AuthorizeAndStashReq {
    fn default() -> Self {
        Self {
            // ...
            flags: AuthAndStashFlags::SKIP_STASH.bits(),  // Default is SKIP
            // ...
        }
    }
}
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

### 3. Subsystem mode — security-sensitive code MUST be stashed

> *"Any security-sensitive code (eg. PLL programming) or configuration (eg. Fuse based Patching)
> loaded by the MCU prior to Caliptra firmware boot **must be stashed within Caliptra**. If the MCU
> exceeds Caliptra ROM's measurement stash capacity, attestation must be disabled until the next
> cold reset."*
>
> — `doc/Caliptra.md`, line 289

### 4. Measurement Vault — Caliptra's stated purpose includes stashing

> *"**Measurement Vault**: Caliptra shall support stashing of measurements for the code and
> configuration of the SoC. Caliptra can provide these measurements via PCR Quote API or via DPE."*
>
> — `doc/Caliptra.md`, line 683

### 5. Remote attestation depends on stashed measurements

> *"An Alias_RT-signed certificate over a leaf DPE key, which includes PCR3 as read by runtime
> firmware, along with **other measurements previously stashed in SRAM**."*
>
> — `doc/Caliptra.md`, line 807

> *"The verifier can also optionally inspect other measurements in (4) to evaluate the journey of
> **other SoC components, whose measurements were previously stored within Caliptra's SRAM**."*
>
> — `doc/Caliptra.md`, line 819

### 6. AUTHORIZE_AND_STASH — stashing is the default intent

> *"The command also enables **stashing of the image hash by default** with an option to skip
> stashing if needed."*
>
> — `runtime/README.md`, line 1240

### 7. Journey measurement tracking for SoC components

> *"Caliptra shall maintain a reboot counter for each component. Caliptra shall increment the
> reboot counter and **update the journey measurement** for calls that indicate that the component's
> state changed."*
>
> — `doc/Caliptra.md`, line 839

### 8. MCU ROM must stash its own measurement

> *"Stash the MCU ROM and other security-sensitive measurements to Caliptra."*
>
> — `caliptra-mcu-sw/docs/src/rom.md`, line 72

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

# Security Version Number (SVN) Anti-Rollback Specification

## Overview

Each firmware component tracks two SVN values:

- **`current_svn`** — the security version of the running image, declared by
  the image. Used for enforcement and attestation.
- **`min_svn`** — the minimum acceptable security version, stored in OTP fuses.
  Any image with `current_svn < min_svn` is rejected.

`min_svn` is set independently of `current_svn`. A release may carry
`current_svn = 10` but `min_svn = 7`, allowing rollback to versions 7–9 while
the device runs version 10. The deployer chooses when to permanently commit a
new minimum.

This document covers three categories of components:

1. **Caliptra Core firmware** — enforced by Caliptra Core ROM.
2. **MCU Runtime firmware** — enforced by MCU ROM.
3. **SoC component images** — manifest-level SVN enforced by Caliptra Core;
   optional per-component enforcement by MCU.

## Threat Model

SVN anti-rollback prevents an attacker who controls the firmware delivery path
(flash, recovery interface, network boot server) from downgrading firmware to
a signed-but-older version with known vulnerabilities. Enforcement relies on
OTP fuses as a tamper-resistant monotonic store, signed images that declare an
SVN, and ROM code that compares the two before execution.

## SVN Fuses

### Caliptra Core SVN Fuses (existing)

These fuses live in the `SVN_PARTITION` (partition 8) and are owned by Caliptra
Core. MCU ROM reads them from OTP and writes them to Caliptra's fuse registers
during cold boot; Caliptra Core enforces anti-rollback internally.

| Fuse | Size | Purpose |
|---|---|---|
| `CPTRA_CORE_FMC_KEY_MANIFEST_SVN` | 4 B | FMC key manifest (currently unused — see note below) |
| `CPTRA_CORE_RUNTIME_SVN` | 16 B | Caliptra Runtime firmware |
| `CPTRA_CORE_SOC_MANIFEST_SVN` | 16 B | SoC manifest |
| `CPTRA_CORE_SOC_MANIFEST_MAX_SVN` | 4 B | Maximum allowed SoC manifest SVN |

> **Note:** `CPTRA_CORE_FMC_KEY_MANIFEST_SVN` is reserved in the OTP map. MCU
> ROM forwards it to Caliptra's `FUSE_FMC_KEY_MANIFEST_SVN` register (alongside
> the other SVN fuses), but neither MCU nor Caliptra Core currently consumes
> the value for any check. It is documented here for completeness;
> integrators do not need to provision it for current behavior.

The pre-existing `CPTRA_CORE_ANTI_ROLLBACK_DISABLE` fuse (in
`sw_manuf_partition`) controls enforcement for both Caliptra Core and MCU. When
set, neither side rejects lower-SVN images and no SVN fuses are burned. MCU
reuses this fuse rather than introducing a separate MCU-only switch. The fuse
defaults to 0 (enforcement on) and should be set only on development or
manufacturing devices.

### New MCU SVN Fuses

Added in a vendor partition (e.g., `VENDOR_NON_SECRET_PROD_PARTITION`):

| Fuse | Size | Recommended Encoding | Purpose |
|---|---|---|---|
| `MCU_RT_MIN_SVN` | 16 B | `OneHotLinearOr{bits:N, dupe:3}` | MCU Runtime min SVN |
| `SOC_IMAGE_MIN_SVN[0..M]` | 4 B each | `OneHotLinearOr{bits:N, dupe:3}` | Per-slot SoC image min SVN (optional) |

The number of `SOC_IMAGE_MIN_SVN` slots (`M`) and the number of one-hot bits
per slot are integrator-defined.

#### Encoding

SVN fuses **must** use a one-hot encoding so that incrementing requires only
burning an additional bit (any other encoding would either need 1→0 transitions
or provide no rollback protection). The recommended layout is `OneHotLinearOr`
with 3× duplication: OR semantics tolerate single-bit read errors without ECC,
which is incompatible with fields written more than once. OR is preferred over
majority vote because OTP bits are far more likely to fail stuck-at-0 than to
spontaneously flip to 1.

Integrators with hardware-level fuse redundancy can use a plain `OneHot{bits:N}`
layout. Other one-hot variants (e.g., `OneHotLinearMajorityVote`) are also
acceptable. Non-one-hot encodings (e.g., `Single`) cannot be used.

See [Fuse Layout Options](fuses.md#fuse-layout-options) for encoding details.

## MCU Image Header

The MCU Runtime binary starts with an `McuImageHeader`:

| Field | Size | Description |
|---|---|---|
| `current_svn` | 2 B | Security version of this image |
| `min_svn` | 2 B | Requested new floor to burn into `MCU_RT_MIN_SVN` (0 = no update) |
| `reserved` | 4 B | Reserved |

Constraints (validated by ROM; image is rejected on violation):

- `min_svn ≤ current_svn`
- Both values must fit within the maximum representable in `MCU_RT_MIN_SVN`'s
  one-hot encoding.

The firmware bundler sets these via `--svn <current>` and `--min-svn <min>`.

## MCU Component SVN Manifest (Optional)

For per-component SoC image anti-rollback, the MCU SDK supports an optional
**MCU Component SVN Manifest** mapping each SoC `component_id` to a
`(current_svn, min_svn)` pair. Each `component_id` is then mapped to a specific
`SOC_IMAGE_MIN_SVN[i]` fuse slot via the platform's SVN Fuse Map (see
[Component SVN Fuse Map](#component-svn-fuse-map)).

If this manifest is omitted, only the SoC manifest-level SVN (enforced by
Caliptra Core) provides rollback protection for SoC images, and the
`SOC_IMAGE_MIN_SVN` fuses are unused.

### Format

The manifest is fixed-size, sized to match Caliptra's
`AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT` (127 entries) — the maximum number of
components a single SoC manifest can describe.

| Field | Size | Description |
|---|---|---|
| Magic | 4 B | `0x4D435356` (`"MCSV"`) |
| Version | 4 B | Manifest format version |
| Entries | 8 B × 127 | `(component_id: u32, current_svn: u16, min_svn: u16)` |

Total: 1024 bytes. SVNs are `u16`; even a single 65535-bit one-hot fuse would
be impractically large.

An entry where all fields are zero (`component_id == current_svn == min_svn == 0`)
is treated as an empty slot and ignored, allowing manifests to declare fewer
than 127 entries by zero-padding.

Per-entry constraints (validated; entry is rejected on violation):

- `min_svn ≤ current_svn`
- Both values must fit within the corresponding fuse slot's one-hot range.

### `component_id` and Fuse Mapping

`component_id` is the same 32-bit identifier Caliptra uses in
`AuthManifestImageMetadata.component_id`. No new identifier scheme is
introduced.

Mapping `component_id → SOC_IMAGE_MIN_SVN[i]` is done by the platform-defined
`SVN_FUSE_MAP`, a static table compiled into ROM and runtime. The integrator
keeps three things in sync: `component_id` in the SoC manifest, `component_id`
in the MCU Component SVN Manifest, and `component_id → fuse slot` in
`SVN_FUSE_MAP`.

If a manifest entry's `component_id` is not in `SVN_FUSE_MAP`, per-component
enforcement is skipped for that component (with a logged warning) — this allows
new components without dedicated fuse slots to ship without breaking boot.

The map is **many-to-one**: multiple `component_id` values may share the same
`SOC_IMAGE_MIN_SVN[i]` slot, in which case those components share a `min_svn`
floor. This is appropriate for components that always update together as a
unit and conserves fuse space. Sharing components must agree on `min_svn` per
release; the build system should validate this.

### Loading and Authentication

The manifest is delivered as a SoC image (with its own `component_id` and
digest in the SoC manifest), via the recovery interface or a PLDM firmware
update. After delivery, MCU Runtime issues `AUTHORIZE_AND_STASH` to Caliptra
to verify the digest against the SoC manifest. On success, MCU Runtime parses
and caches the manifest. Authentication failure is logged and per-component
enforcement is skipped.

This roots the manifest's integrity in the same trust chain as every other
SoC image — the SoC manifest signature verified by Caliptra Core.

```mermaid
sequenceDiagram
    participant Source as Flash / Recovery I/F
    participant MCU as MCU Runtime
    participant Caliptra

    Source->>MCU: Component SVN Manifest data
    MCU->>Caliptra: AUTHORIZE_AND_STASH
    Caliptra-->>MCU: Authorization result
    alt authorized
        MCU->>MCU: Parse and cache entries
    else failed
        MCU->>MCU: Log error, skip enforcement
    end
```

## Enforcement Flows

### Cold Boot — Caliptra Core SVNs

MCU ROM reads the Caliptra Core SVN fuses from OTP and writes them to
Caliptra's fuse registers (`CPTRA_CORE_FMC_KEY_MANIFEST_SVN` is forwarded but
unused; see the note above). Caliptra Core ROM authenticates its firmware,
compares image SVN against fuse SVN, rejects on mismatch, and updates its own
SVN fuses if the image SVN is higher and `CPTRA_CORE_ANTI_ROLLBACK_DISABLE` is
not set. MCU ROM has no role beyond fuse transport.

### Cold Boot and Hitless Update — MCU Runtime SVN

After Caliptra loads MCU Runtime into MCU SRAM, MCU ROM enforces and
potentially burns the MCU SVN before jumping to firmware. The same logic
applies on cold boot and hitless update reset:

1. Read `McuImageHeader` from SRAM.
2. Read `MCU_RT_MIN_SVN` and `CPTRA_CORE_ANTI_ROLLBACK_DISABLE` from OTP.
3. If anti-rollback is not disabled and `header.current_svn < fuse_min_svn`:
   reject with `ROM_MCU_SVN_CHECK_FAILED`.
4. If anti-rollback is not disabled and `header.min_svn > fuse_min_svn`:
   burn `MCU_RT_MIN_SVN` to `header.min_svn`, then read back and verify.
5. Continue to firmware.

```mermaid
sequenceDiagram
    participant ROM as MCU ROM
    participant SRAM
    participant OTP

    ROM->>SRAM: Read McuImageHeader
    ROM->>OTP: Read MCU_RT_MIN_SVN, CPTRA_CORE_ANTI_ROLLBACK_DISABLE

    alt anti-rollback not disabled
        alt header.current_svn < fuse_min_svn
            ROM->>ROM: Fatal error
        else
            opt header.min_svn > fuse_min_svn
                ROM->>OTP: Burn MCU_RT_MIN_SVN
            end
            ROM->>ROM: Continue to firmware
        end
    else
        ROM->>ROM: Continue to firmware
    end
```

The Firmware Boot flow (entered after cold boot triggers a reset) does not
re-check SVN; SRAM contents are unchanged since the cold-boot check.

### Cold Boot and Hitless Update — SoC Component min_svn Burn

If the MCU Component SVN Manifest is present and previously authenticated, MCU
ROM also burns `SOC_IMAGE_MIN_SVN[i]` slots from manifest entries. For each
entry with `min_svn > 0`:

1. Look up `component_id` in `SVN_FUSE_MAP` to find the fuse slot.
2. If `entry.min_svn > fuse_min_svn` and anti-rollback is not disabled:
   burn the fuse.

### PLDM Firmware Update — SVN Verification

When firmware is delivered via PLDM (covering both initial provisioning and
hitless updates that drive the Activate-then-reset flow), MCU Runtime performs
SVN checks during the **Verify Component** phase of the PLDM update flow,
alongside the existing digest checks (see
[Firmware Update](firmware_update.md)). Failing the SVN check at this stage
rejects the bundle before it can be applied or activated, so a downgrade
attempt never makes it to the hitless reset.

For each component in the bundle:

1. **MCU Runtime image** — read `McuImageHeader.current_svn` and
   `header.min_svn` from the new image. Reject if `current_svn < fuse_min_svn`,
   if `min_svn > current_svn`, or if either value exceeds the
   `MCU_RT_MIN_SVN` one-hot range.
2. **SoC component images** — for each component whose `component_id` is in
   both the MCU Component SVN Manifest and `SVN_FUSE_MAP`:
   - Use the platform's `SocComponentSvn` trait (below) to extract the SVN
     directly from the component bytes.
   - Verify the trait-extracted SVN matches the MCU Component SVN Manifest's
     `current_svn` for that component. A mismatch means the manifest and
     image disagree — reject the bundle.
   - Reject if `current_svn < fuse_min_svn`, or if either `current_svn` or
     `min_svn` exceeds the slot's one-hot range.
3. **MCU Component SVN Manifest itself** — verify the per-entry constraints
   (see [Format](#format)). Reject the bundle on any violation.

Components without a `SocComponentSvn` implementation skip the
manifest-vs-image cross-check (a logged warning) but still get the
`current_svn < fuse_min_svn` check using the manifest's value. This allows
opaque or pre-existing component formats to participate in fuse-level
rollback protection without forcing the integrator to parse them.

After PLDM verification succeeds, the bundle is applied and activated. The
hitless update reset then triggers MCU ROM, which performs the actual
fuse burns described in
[Cold Boot and Hitless Update — MCU Runtime SVN](#cold-boot-and-hitless-update--mcu-runtime-svn)
and
[Cold Boot and Hitless Update — SoC Component min_svn Burn](#cold-boot-and-hitless-update--soc-component-min_svn-burn).

#### `SocComponentSvn` Trait

Integrators provide an implementation per SoC component type so the SDK can
extract the running SVN from the component's binary without knowing the
internal format:

```rust
pub trait SocComponentSvn {
    /// Extract the current SVN encoded in this component's image bytes.
    /// Returns `None` if the component has no embedded SVN (in which case
    /// the manifest cross-check is skipped for this component).
    fn current_svn(&self, image: &[u8]) -> Option<u16>;
}
```

The platform registers a `SocComponentSvn` per `component_id` (typically in
the same place as `SVN_FUSE_MAP`).

### Runtime — SoC Image SVN Enforcement on Loading (Optional)

When MCU Runtime loads SoC images at boot (after a cold boot or after the
hitless update reset has placed new images in their flash partitions), it
enforces per-component SVN before each image is loaded to its target. For
each image whose `component_id` is in both the MCU Component SVN Manifest and
`SVN_FUSE_MAP`:

1. Read `current_svn` from the manifest (and optionally cross-check against
   the trait, as in PLDM verify).
2. Read the corresponding `SOC_IMAGE_MIN_SVN[i]` fuse.
3. If `current_svn < fuse_min_svn`: reject the image.

If the manifest is absent, per-component enforcement is skipped; only the
Caliptra-enforced SoC manifest SVN applies.

## SVN Fuse Burning

`min_svn` fuses are **only burned by MCU ROM**. Runtime never burns SVN fuses,
ensuring fuse programming runs in the most trusted execution context before
mutable firmware has control.

Burns are triggered exclusively by authenticated firmware images: the
`McuImageHeader.min_svn` field for MCU Runtime, and MCU Component SVN Manifest
entries for SoC components. ROM only burns when the requested `min_svn`
strictly exceeds the current fuse value.

The burn is power-fail safe: one-hot encoding plus OR semantics mean a partial
burn can never decrease the fuse value, and any incomplete burn will be
re-attempted (and complete) on the next boot.

| Component | Burned by | Source of `min_svn` |
|---|---|---|
| Caliptra Core FMC/RT | Caliptra Core ROM | Caliptra image SVN |
| MCU Runtime | MCU ROM | `McuImageHeader.min_svn` |
| SoC images (optional) | MCU ROM | MCU Component SVN Manifest entry |

## Platform Configuration

### Fuse Definition

In `vendor_fuses.hjson`:

```js
{
  non_secret_vendor: [
    {"mcu_rt_min_svn": 16},
    {"soc_image_min_svn_0": 4},
    {"soc_image_min_svn_1": 4},
    // ... additional slots as needed
  ],
  fields: [
    {name: "mcu_rt_min_svn", bits: 32},
    {name: "soc_image_min_svn_0", bits: 8},
    {name: "soc_image_min_svn_1", bits: 8},
  ]
}
```

`CPTRA_CORE_ANTI_ROLLBACK_DISABLE` is part of the standard Caliptra fuse map
and does not need to be redeclared.

### Component SVN Fuse Map

Compiled into ROM and MCU Runtime:

```rust
pub struct SvnFuseMapEntry {
    pub component_id: u32,
    pub fuse_entry: &'static FuseEntryInfo,
}

pub static SVN_FUSE_MAP: &[SvnFuseMapEntry] = &[
    SvnFuseMapEntry { component_id: 0x0000_0002, fuse_entry: &OTP_MCU_RT_MIN_SVN },
    SvnFuseMapEntry { component_id: 0x0000_1000, fuse_entry: &OTP_SOC_IMAGE_MIN_SVN_0 },
    SvnFuseMapEntry { component_id: 0x0000_1001, fuse_entry: &OTP_SOC_IMAGE_MIN_SVN_0 }, // shares slot 0
    SvnFuseMapEntry { component_id: 0x0000_1002, fuse_entry: &OTP_SOC_IMAGE_MIN_SVN_1 },
];
```

### ImageVerifier

ROM uses an `ImageVerifier` implementation to enforce the MCU Runtime SVN:

```rust
impl ImageVerifier for McuImageVerifier {
    fn verify_header(&self, header: &[u8], otp: &Otp) -> bool {
        let Ok((header, _)) = McuImageHeader::ref_from_prefix(header) else {
            return false;
        };
        if otp.read_anti_rollback_disable().unwrap_or(0) != 0 {
            return true;
        }
        let Ok(fuse_min_svn) = otp.read_mcu_rt_min_svn() else {
            return false;
        };
        header.current_svn >= fuse_min_svn
    }
}
```

## Security Considerations

**`min_svn` vs `current_svn` separation.** Storing only `min_svn` in fuses
gives deployers control over when to permanently commit a new floor and avoids
leaking the running version through OTP state. A release can carry a high
`current_svn` while keeping `min_svn` lower for staged rollout.

**ROM-only fuse burning.** All `min_svn` burns occur in ROM, before mutable
firmware runs. Runtime cannot be exploited to advance `min_svn` to
attacker-chosen values; the only inputs to ROM are signed images and signed
manifests.

**One-way commitment.** OTP can only burn 0→1, so `min_svn` only increases. A
release that mistakenly raises `min_svn` cannot be undone — recovery requires a
new release with `current_svn ≥` the committed value.

**Anti-rollback disable polarity.** `CPTRA_CORE_ANTI_ROLLBACK_DISABLE` uses
disable polarity (burning removes a security property) for compatibility with
the existing Caliptra fuse. Provisioning flows must never set this fuse on
production devices; ROM should add lifecycle-state checks to enforce this.

**SVN exhaustion.** With one-hot encoding, the maximum `min_svn` equals the
number of allocated bits (e.g., 32 bits → max SVN of 32). Since `current_svn`
can advance without `min_svn`, exhaustion is rare in practice. At exhaustion,
no further `min_svn` updates are possible but the device continues to enforce
the maximum value.

**Device Ownership Transfer.** SVN fuses are orthogonal to ownership. DOT does
not reset `min_svn`. A new owner inherits the existing `min_svn` state.

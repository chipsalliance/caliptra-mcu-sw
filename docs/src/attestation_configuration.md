# Attestation Configuration

## 1. Introduction

Attestation configuration specifies how measured boot and attestation evidence collection are carried out across a SoC that integrates Caliptra Subsystem. The configuration consists of three artifacts:

1. **SoC Authorization Manifest**: Authorizes the firmware images permitted to run. Caliptra Core verifies the manifest signature and uses its image metadata to authenticate component reference digests and validate load/staging addresses.
2. **Attestation Manifest**: Defines the measurement routing policy for each configured component ID (`fw_id`). It specifies whether a component is measured into a DPE context (TCB) or Software PCR storage (non-TCB), designates the Attestation Key (AK) target node, and provides platform identity for attestation evidence.
3. **SoC Image Load List**: Defines the deterministic sequential order in which the MCU loads and measures SoC components at boot. For DPE-backed measurements, this sequence governs the runtime parent-child derivation order in the DPE context tree.

These artifacts are defined across two configuration layers:
- **Base Vendor Layer**: Embedded at build time in the MCU Runtime user image.
- **Owner Layer**: Staged externally (Component `0x00000005` in [Flash TOC](./flash_layout.md) / PLDM) and dynamically authenticated via the Owner SoC Manifest.

### Configuration Artifacts

| SoC Config | Artifact | Lives In | Authenticated By | Purpose |
|---|---|---|---|---|
| **Base Vendor** | [Auth Manifest](https://github.com/chipsalliance/caliptra-sw/blob/main/auth-manifest/README.md) | Caliptra RT (DCCM) | Caliptra RT (Auth manifest verification) | Authorization of SoC image metadata; querying SoC image metadata via `GET_IMAGE_INFO` |
| **Base Vendor** | Attestation Manifest (`MCAM`) | MCU RT Image | Caliptra RT (As part of MCU RT image verification) | Per-`fw_id` measurement routing policy (TCB vs. Non-TCB, AK target) |
| **Base Vendor** | SoC Image Load List | MCU RT Image | Caliptra RT (As part of MCU RT image verification) | Ordered `fw_id` list used for SoC image loading, DPE topology, and hitless updates |
| **Owner** | [Owner Auth Manifest](https://github.com/chipsalliance/caliptra-sw/blob/main/auth-manifest/README.md#owner-authorization-manifest) | Caliptra RT (DCCM) | Caliptra RT (Owner auth manifest verification) | Authorization of owner SoC image metadata; querying owner metadata via `GET_IMAGE_INFO` |
| **Owner** | Owner Attestation Manifest (`MOAM`) | Component `0x00000005` ([Flash TOC](./flash_layout.md) / PLDM) | Caliptra RT (Authorized against Owner SoC Manifest) | Per-`fw_id` measurement routing policy for owner components |
| **Owner** | Owner SoC Image Load List (`MOLL`) | Component `0x00000005` ([Flash TOC](./flash_layout.md) / PLDM) | Caliptra RT (Authorized against Owner SoC Manifest) | Ordered `fw_id` list used for owner SoC image loading and DPE topology |

---

## 2. Base Vendor Configuration

The base configuration is compiled directly into the MCU Runtime user image from integrator build-time descriptors.

### Base Attestation Manifest (`MCAM`)

Consists of a 28-byte fixed header prefix, a 200-byte platform information region, and a variable array of 8-byte entries (`header_size = 228`).

#### Header Format (228 bytes)

| Offset | Field | Size | Description |
|---:|---|---:|---|
| 0 | `marker` | 4 bytes | Magic `0x4D41_434D` (`MCAM` in LE). |
| 4 | `size` | 4 bytes | Total bytes: `228 + entry_count * 8`. |
| 8 | `version` | 4 bytes | Version `1`. |
| 12 | `header_size` | 4 bytes | Must be `228`. |
| 16 | `entry_count` | 4 bytes | Number of component entries. |
| 20 | `tcb_entry_count` | 4 bytes | Number of entries with `SOC_TCB_DPE` flag set. |
| 24 | `vendor_len` | 2 bytes | Length of UTF-8 vendor string (max 100). |
| 26 | `model_len` | 2 bytes | Length of UTF-8 model string (max 100). |
| 28 | `vendor` | 100 bytes | UTF-8 vendor name (unused bytes zeroed). |
| 128 | `model` | 100 bytes | UTF-8 model name (unused bytes zeroed). |

#### Entry Format (8 bytes per entry)

| Offset | Field | Size | Description |
|---:|---|---:|---|
| 0 | `fw_id` | 4 bytes | Firmware identifier. |
| 4 | `attestation_flags` | 4 bytes | `Bit 0 (SOC_TCB_DPE)`: 1 = DPE context, 0 = Software PCR.<br>`Bit 1 (AK_TARGET)`: 1 = Attestation Key target (max 1, requires Bit 0).<br>`Bits 2-31`: Reserved (must be zero). |

If no entry asserts `AK_TARGET`, `MCU_RT` (`0x0000_0002`) is the default AK target.

### Base SoC Image Load List (`SOC_IMAGE_LOAD_LIST`)

An ordered array of little-endian `u32` firmware identifiers:
```rust
pub const SOC_IMAGE_LOAD_LIST: &[u32] = &[
    0x0000_1000, // SoC Vendor Component 1
    0x0000_2000, // SoC Vendor Component 2
];
```

#### Policy Digest Binding

```text
base_policy_digest = SHA384(canonical_MCAM_bytes || canonical_ordered_soc_image_load_list_bytes)
```

Stored in preserved measurement metadata at cold boot. On hitless update, any mismatch rejects the update and requires cold boot.

---

## 3. Owner Configuration Layer (Component 0x00000005)

The Owner Measurement Policy component packages the **Owner Attestation Manifest** and **Owner SoC Image Load List** contiguously into a single container staged in [Flash TOC](./flash_layout.md) or delivered via PLDM:

```text
+---------------------------------------------------------------------------------+
|                  Owner Measurement Policy (Component 0x00000005)                |
+---------------------------------------------------------------------------------+
|  Owner Attestation Manifest (MOAM)                                              |
|  - 28-byte Header (marker: 0x4D41_4F4D, size, version: 1, header_size: 28,      |
|    entry_count, tcb_entry_count, vendor_len: 0, model_len: 0)                   |
|  - Variable Entry Array: [fw_id: u32, attestation_flags: u32] * entry_count     |
+---------------------------------------------------------------------------------+
|  Owner SoC Image Load List (MOLL)                                               |
|  - 16-byte Header (marker: 0x4C4C_4F4D, size, version: 1, entry_count)          |
|  - Ordered Array: [fw_id: u32] * entry_count                                    |
+---------------------------------------------------------------------------------+
```

### Owner Attestation Manifest (`MOAM`)

Unlike the base manifest, the owner manifest omits platform strings (inheriting platform identity from the base layer):

#### Header Format (28 bytes)

| Offset | Field | Size | Description |
|---:|---|---:|---|
| 0 | `marker` | 4 bytes | Magic `0x4D41_4F4D` (`MOAM` in LE). |
| 4 | `size` | 4 bytes | Total bytes: `28 + entry_count * 8`. |
| 8 | `version` | 4 bytes | Version `1`. |
| 12 | `header_size` | 4 bytes | Must be `28`. |
| 16 | `entry_count` | 4 bytes | Number of serialized entries. |
| 20 | `tcb_entry_count` | 4 bytes | Must match leading TCB entry count. |
| 24 | `vendor_len` | 2 bytes | Must be `0`. |
| 26 | `model_len` | 2 bytes | Must be `0`. |

#### Owner Manifest Invariants
1. **TCB Contiguity**: All entries with `SOC_TCB_DPE` set must appear contiguously at the beginning of the entry array.
2. **Mandatory Reserved Entries**: Every owner manifest must include TCB entries for:
   - `0x0000_0005`: Owner Measurement Policy
   - `0x0000_0006`: Owner Authorization Key (`O_AUTH_KEY_ID`)
3. **AK Target Prohibition**: Setting `AK_TARGET` on any owner component is rejected.
4. **Allocated ID Range**: All loadable owner firmware IDs must fall in `0x0001_0000..=0xFFFF_FFFF`. IDs below `0x0001_0000` (except reserved IDs `0x5` and `0x6`) are rejected.

### Owner SoC Image Load List (`MOLL`)

Defines the ordered execution sequence of owner firmware images:

#### Header Format (16 bytes)

| Offset | Field | Size | Description |
|---:|---|---:|---|
| 0 | `marker` | 4 bytes | Magic `0x4C4C_4F4D` (`MOLL` in LE). |
| 4 | `size` | 4 bytes | Total bytes: `16 + entry_count * 4`. |
| 8 | `version` | 4 bytes | Version `1`. |
| 12 | `entry_count` | 4 bytes | Number of firmware IDs in list. |

Following the header is an array of `entry_count` little-endian `u32` firmware IDs.

#### Owner SoC Image Load List Invariants
1. **Reserved ID Exclusion**: Reserved identifiers (Owner Measurement Policy `0x0000_0005` and Owner Authorization Key `0x0000_0006`) are measured separately and must **not** appear in the load list.
2. **Load List and Attestation Manifest Parity**: Every firmware component in the Owner SoC Image Load List (`MOLL`) must have a matching entry in the Owner Attestation Manifest (`MOAM`). Conversely, all non-reserved components in the Owner Attestation Manifest must be present in the Owner SoC Image Load List.
3. **Unique Entries**: Duplicate `fw_id`s are rejected.

### Canonical Policy Digest

The complete container is bound by:
```text
owner_policy_digest = SHA384(Owner Measurement Policy payload)
```
Caliptra Core authenticates this payload against the `expected_digest` recorded in the Owner SoC Manifest (via `AUTHORIZE_AND_STASH` with `SKIP_STASH`) before MCU Runtime enforces the policy and measures it into DPE.

---

## 4. End-to-End Boot and Loading Flow

At system startup, Caliptra MCU coordinates authorization, loading, and measurements in this strict chronological order:

```text
 1. Initialize Base State
    ├── Validate embedded Base Attestation Manifest (MCAM) and Base SoC Image Load List
    ├── Rotate default DPE context handle and tag MCU_RT context (0x00000002)
    └── Initialize DPE and Software PCR stores
         │
 2. Measure Vendor Auth Key (0x00000004)
    └── Extend Vendor Key digest under MCU_RT context
         │
 3. Install & Measure Owner SoC Manifest (OWSM)
    ├── Caliptra Core verifies Owner Auth Manifest signature via SET_OWNER_AUTH_MANIFEST
    └── MCU extends Owner SoC Manifest preamble to DPE (creating OWSM context)
         │
 4. Load, Authorize & Measure Owner Measurement Policy (0x00000005)
    ├── Fetch Component 0x5 from [Flash TOC](./flash_layout.md) / PLDM package
    ├── Authenticate against Owner SoC Manifest and validate MOAM + MOLL consistency
    └── Extend SHA384(Component 0x5 payload) under OWSM context
         │
 5. Measure Owner Auth Key (0x00000006)
    └── Extend Owner Key digest under Owner Policy context
         │
 6. Load Base Firmware Images
    └── For each fw_id in SOC_IMAGE_LOAD_LIST:
        ├── Authorize via Caliptra Core (Base SoC Manifest with SKIP_STASH)
        └── Record DPE / Software PCR measurement; extend PCR31
         │
 7. Load Owner Firmware Images
    └── For each fw_id in Owner SoC Image Load List (MOLL):
        ├── Authorize via Caliptra Core (Owner SoC Manifest with SKIP_STASH)
        └── Record DPE / Software PCR measurement; extend PCR31
```

---

## 5. Symmetrical Consistency Rules

The exact same consistency principles govern both the Base and Owner layers:

| Principle | Base Layer Rule | Owner Layer Rule |
|---|---|---|
| **Identifier Uniqueness** | `fw_id`s in Base Manifest and Base SoC Image Load List must be unique. | `fw_id`s in `MOAM` and `MOLL` must be unique. |
| **Range Allocation** | Base IDs occupy the base range (`< 0x0001_0000`). | Owner IDs occupy the owner range (`0x0001_0000..=0xFFFF_FFFF`), except reserved IDs `0x5` and `0x6`. |
| **Non-Loadable Entries** | `MCAM` may contain non-loadable entries such as the Vendor Authorization Key (`0x0000_0004`), which is excluded from `SOC_IMAGE_LOAD_LIST`. | `MOAM` contains reserved IDs `0x5` (Policy) and `0x6` (Owner Authorization Key), which are excluded from `MOLL`. |
| **Cross-Artifact Parity** | Every loadable `fw_id` in `SOC_IMAGE_LOAD_LIST` must exist in `MCAM` and Base SoC Manifest. | Every loadable `fw_id` in `MOLL` must exist in `MOAM` and Owner SoC Manifest. |
| **Hitless Update Protection** | `base_policy_digest` must match the value preserved in reserved SRAM (`DpeHandleStore` header). | `owner_policy_digest` must match the preserved cold-boot measurement of the Owner Measurement Policy in its DPE context or software-PCR record. It is not stored in the `DpeHandleStore` header. |

### Hitless Update Policy Preservation

During cold boot, MCU Runtime stores the base-policy digest in the
`DpeHandleStore` header's `attestation_policy_digest` field at offset 24.

The Owner policy digest, `SHA384(Owner Measurement Policy payload)`,
is captured as the policy component's measurement in its DPE context
or software-PCR record. It is neither combined with the base-policy
digest nor stored separately in the `DpeHandleStore` header.

On a hitless-update reset:

1. Recompute the base-policy digest and validate it against the preserved
   store header using the existing `VALIDATE_STORE` flow.
2. Authenticate and validate the incoming Owner Measurement Policy,
   recompute its digest, and compare it against the policy's preserved
   cold-boot measurement. Use the DPE context's current measurement or
   the software-PCR record's `current_digest`, not a cumulative or
   journey digest.
3. Perform this comparison before changing Owner measurement state.
   A digest mismatch or missing, invalid preserved measurement rejects
   the update. Do not overwrite the baseline or silently initialize
   fresh state. An unchanged policy reuses its preserved measurement
   without another PCR31 extension.

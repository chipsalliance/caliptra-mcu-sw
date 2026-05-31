# MCU RT Identity Attestation in the Caliptra DICE Architecture

## Overview

This document describes how MCU Runtime (RT) firmware is integrated into the DICE layering architecture by adding it as a DPE (DICE Protection Environment) managed context. By placing MCU RT into the DPE context chain in PL0 locality, Caliptra RT generates and maintains claims for the MCU RT firmware — including firmware digest, journey measurement, SVN — enabling standards-based attestation through the DICE certificate hierarchy.

### Identity and Attestation Roles

- **Caliptra Core** provides **identity attestation** for the MCU RT — the MCU RT DPE context and its ancestor chain (RTMR -> MBVP -> ROM stashed measurements) form the basis for attestation key derivation and certificate issuance via `CertifyKey`/`Sign`.
- **MCU** (running SPDM responder) handles **inventory attestation** for remaining SoC components.

---

## DPE Context Model for MCU RT

The MCU RT firmware occupies a specific position in the DPE context hierarchy. The following properties define how MCU RT integrates into the Caliptra DPE measurement chain:

- **MCU RT DPE Context Creation during Recovery Boot** — Caliptra RT creates the MCU RT context as the default context in PL0 PAUSER locality, chained to all prior measurements (RTMR, MBVP, ROM stashed measurements). The context is created with the MCU RT image digest as the measurement and the SoC manifest SVN as the SVN.

- **Keeping Attestation scoped to MCU** — `CertifyKey` and `Sign` operations on the default handle derive keys solely from the MCU RT context and its ancestors in PL0 PAUSER locality. SoC firmware contexts, if any, are derived as children in different (PL1 PAUSER) locality and are excluded from key derivation.

- **Hitless MCU RT updates** — On hitless update, Caliptra RT sends `AUTHORIZE_AND_STASH` with the `UPDATE_EXISTING` flag. This triggers a DPE `RECURSIVE` DeriveContext on the existing MCU RT context, which extends the cumulative TCI in place without allocating a new context slot. After N hitless updates there is still exactly one MCU RT DPE node. The default handle remains stable at `[0x00; 16]` across updates. **Note:** RECURSIVE DeriveContext does not update the SVN — the context retains the SVN set during recovery boot.

- **SoC firmware isolation** — The MCU derives SoC firmware contexts using RETAIN_PARENT and CHANGE_LOCALITY to PL1, while keeping the MCU RT context unchanged in PL0. These SoC firmware contexts are optional, created as child contexts in PL1 PAUSER locality, and do not affect attestation key derivation.

- **MCU RT context must remain an Active leaf** — The `UPDATE_EXISTING` path locates the MCU RT context by searching for an Active context matching `tci_type = "MCFW"` in the mailbox locality. If MCU RT is ever not Active (e.g., it transitions to Retired because a child was derived without `RETAIN_PARENT`), the lookup fails. DPE's RECURSIVE DeriveContext only operates on Active contexts.

Creating the MCU RT DPE context requires invoking `DeriveContextCmd` with both a **measurement** (the SHA-384 digest of the MCU RT image) and an **SVN** (the security version number of the firmware). The measurement is already available from Caliptra RT's image authentication step, but the SVN presents a sourcing challenge described below.

---

## Problem: SVN Sourcing for the MCU RT DPE Context

Caliptra RT authenticates MCU firmware by verifying its SHA-384 digest against the [Authorization Manifest](https://github.com/chipsalliance/caliptra-sw/blob/main/auth-manifest/README.md). This establishes **integrity** and **authenticity**, but **not anti-rollback** — Caliptra RT has no access to MCU SVN fuses. Anti-rollback enforcement is the responsibility of **MCU ROM**, which reads vendor-defined SVN fuses in the MCU domain.

`DeriveContextCmd` requires both a `measurement` and an `svn` to create the MCU RT DPE context. While the measurement is available via the image digest, neither `AuthManifestImageMetadata` entry nor the **recovery or update flows** previously provided an `svn` value.

---

## Design: Use Auth Manifest Preamble SVN

### Requirements

1. **Caliptra RT** needs the `svn` for `DeriveContextCmd` to bind version information into the DPE context for attestation certificates.
2. **MCU ROM** needs the `svn` to validate against its anti-rollback fuses.
3. **MCU RT firmware** needs `current digest, journey digest, svn` claims about MCU RT target environment to report as part of attestation claims.

### Approach

The `AuthManifestPreamble.svn` field (u32) is stored in `PersistentData` during the Set Auth Manifest flow and used as the MCU RT SVN when creating or updating the DPE context. This requires no changes to the Auth Manifest binary format. The SVN value is cryptographically protected by the Auth Manifest vendor/owner signatures.

### Gaps Addressed

Three gaps prevented MCU RT state from being correctly captured for attestation:

| # | Gap | Fix |
|---|-----|-----|
| 1 | Recovery boot creates MCU RT DPE context with **SVN = 0** instead of the SoC manifest SVN | `recovery_flow.rs` reads `soc_manifest_svn` from PersistentData and passes it in `AuthorizeAndStashReq` |
| 2 | SoC manifest SVN is validated but **never persisted** — unavailable when recovery boot needs it | `set_auth_manifest.rs` stores `auth_manifest_preamble.svn` as `soc_manifest_svn` in PersistentData |
| 3 | Hitless update uses `SKIP_STASH` — **DPE context is never updated** | `activate_firmware.rs` now uses `UPDATE_EXISTING` flag, which triggers RECURSIVE DeriveContext via `update_measurement()` |

### Auth Manifest Construction Rules

1. **Flags Bit 0 (`VENDOR_SIGNATURE_REQUIRED`) must be set** — The Auth Manifest `flags` field must have Bit 0 asserted. This ensures that vendor signatures are always verified during authorization, making secure boot verification for MCU RT firmware possible.

2. **Image Metadata Collection must contain an MCU RT entry** — The `AuthManifestImageMetadataCollection` must include an entry for the MCU RT firmware image, identified by `fw_id: 0x0002`. The entry's `digest` field contains the SHA-384 hash of the MCU RT image, used by Caliptra RT for image verification during recovery boot.

3. **SVN field** — OEM tooling must populate `AuthManifestPreamble.svn` with the MCU RT firmware security version number. This value is stored in PersistentData and bound into the MCU RT DPE context.

### Recovery Boot Flow

```
1. OEM builds MCU RT image
2. OEM generates Auth Manifest:
   - preamble.svn = MCU RT FW SVN
   - preamble.flags Bit 0 = 1 (VENDOR_SIGNATURE_REQUIRED)
   - Image Metadata Collection includes MCU RT entry (fw_id=2) with SHA-384 digest
   - Vendor/owner signatures computed over the manifest
3. Caliptra RT: Set Auth Manifest flow (set_auth_manifest.rs):
   - Validates vendor/owner signatures
   - Checks preamble.svn against Caliptra Core anti-rollback fuses
   - Stores preamble.svn as soc_manifest_svn in PersistentData
   - Stores the Auth Manifest for subsequent image authorization
4. Caliptra RT: MCU Recovery Boot flow (recovery_flow.rs):
   - Downloads MCU RT image to MCU SRAM via Recovery Interface
   - Computes SHA-384 over MCU SRAM, verifies against Auth Manifest digest
   - Reads soc_manifest_svn from PersistentData
   - Sends AuthorizeAndStashReq with:
       measurement = SHA-384 digest of MCU RT image
       svn         = soc_manifest_svn
       fw_id       = 2 (mapped to tci_type "MCFW")
   - DeriveContext creates the MCU RT DPE context in PL0 locality
5. MCU ROM flow:
   - MCU ROM retrieves the SVN via GET_IMAGE_INFO() mailbox command
     to Caliptra RT (reads from DPE context)
   - MCU ROM validates MCU RT FW SVN against its own anti-rollback fuses
     (vendor-defined fuses in the MCU domain, separate from Caliptra Core fuses)
6. Attestation:
   - CertifyKey/Sign on the MCU RT default handle derives keys from the
     MCU RT context (measurement + SVN) and its ancestors
   - MCU RT SVN is reflected in TcbInfo via DPE certificate DICE extensions
```

### Hitless Update Flow

```
1. MCU sends SET_AUTH_MANIFEST with updated manifest
   - Caliptra RT validates signatures, updates soc_manifest_svn in PersistentData
2. MCU sends ACTIVATE_FIRMWARE with MCU image in staging
   - Caliptra RT resets MCU, copies FW to SRAM
   - Sends AuthorizeAndStashReq with:
       flags  = UPDATE_EXISTING
       fw_id  = 2 (mapped to tci_type "MCFW")
   - authorize_and_stash() verifies image against Auth Manifest digest
   - update_measurement() finds the existing MCU RT context by tci_type + locality
   - Issues RECURSIVE DeriveContext:
       tci_current    = new firmware measurement
       tci_cumulative = SHA384(old_cumulative || new measurement)
   - Extends PCR31 with the new measurement
3. Result:
   - MCU RT DPE context reflects the updated firmware measurement
   - SVN remains the value from recovery boot (RECURSIVE DeriveContext does not update SVN)
   - No new context slot allocated — one MCU RT node across unlimited hitless updates
```

### MCU ROM SVN Retrieval

During MCU ROM boot, the ROM code retrieves the MCU RT FW SVN using the `GET_IMAGE_INFO()` mailbox command to Caliptra RT, which reads the value from the DPE context. This allows MCU ROM to perform its own anti-rollback checks against vendor-defined fuses in the MCU domain.

---

## Caliptra RT Implementation Changes (`caliptra-sw`, branch `caliptra-2.0`)

| # | Component | File | Change |
|---|-----------|------|--------|
| 1 | PersistentData | `drivers/src/persistent.rs` | Add `soc_manifest_svn: u32` field |
| 2 | Set Auth Manifest | `runtime/src/set_auth_manifest.rs` | Store `preamble.svn` as `soc_manifest_svn` in PersistentData |
| 3 | Recovery Boot | `runtime/src/recovery_flow.rs` | Read `soc_manifest_svn` and pass in `AuthorizeAndStashReq` |
| 4 | API | `api/src/mailbox.rs` | Add `UPDATE_EXISTING = 0x2` flag to `AuthAndStashFlags` |
| 5 | Authorize & Stash | `runtime/src/authorize_and_stash.rs` | Dispatch `UPDATE_EXISTING` flag to `update_measurement()` |
| 6 | Stash Measurement | `runtime/src/stash_measurement.rs` | New `update_measurement()`: find context by tci_type + locality, RECURSIVE DeriveContext, extend PCR31 |
| 7 | Activate Firmware | `runtime/src/activate_firmware.rs` | Change `SKIP_STASH` → `UPDATE_EXISTING` for MCU RT hitless update |

All changes are backward compatible. Callers that don't set `UPDATE_EXISTING` get existing behavior.

> **Note:** Adding `soc_manifest_svn` to `PersistentData` shifts fields after it by 4 bytes. ROM does not access any field past the insertion point, so **no ROM change is needed**. FMC and RT are recompiled together and see the new layout.

---

## Known Limitations

1. **SVN not updated on hitless update** — DPE's RECURSIVE DeriveContext only extends TCI measurements; it does not modify the context's `svn` field. After a hitless update, attestation reflects the new firmware measurement but retains the SVN from recovery boot. If a hitless update brings a higher SVN, attestation will not reflect it until the next full boot.

2. **MCU RT context must remain Active and a leaf** — The `update_measurement()` lookup requires the MCU RT context to be Active. If a child context is derived from MCU RT without `RETAIN_PARENT`, the context transitions to Retired and RECURSIVE DeriveContext will fail. DPE's `get_active_context_pos()` only searches Active contexts.

3. **Hitless update measurement source** — `activate_firmware.rs` passes `measurement: [0; 48]` with `source: LoadAddress`. The `authorize_and_stash()` function computes the real digest from memory for authorization, then uses the same computed digest for the DPE update via the `stash_measurement` variable.

---

## Cherry-Pick to `main`

When porting to `main`, adjust for structural differences:

| caliptra-2.0 | main |
|---|---|
| `persistent_data.soc_manifest_svn` | `persistent_data.fw.soc_manifest_svn` |
| `persistent_data.state` | `persistent_data.fw.dpe.state` |
| `authorize_and_stash(drivers, cmd)` | `authorize_and_stash(drivers, cmd, locality)` |
| `dpe::` (DPE crate import path) | `caliptra_dpe::` |
| No `ALLOW_RECURSIVE` on initial stash | Initial MCU RT stash **must** include `DeriveContextFlags::ALLOW_RECURSIVE` — main's DPE crate enforces per-context gating; without it, RECURSIVE DeriveContext on hitless update will return `InvalidArgument` |

---

## Design Trade-offs

### Advantages

- **Zero Auth Manifest format changes** — All existing struct definitions remain unchanged. No binary layout changes required.
- **Minimal Caliptra RT changes** — Core logic of manifest verification and image authentication remains intact. Changes are additive (new flag, new function, new PersistentData field).
- **Works for encrypted firmware** — MCU RT FW SVN is in the Auth Manifest preamble (always cleartext), not embedded in the MCU image.
- **Cryptographically protected** — The SVN is covered by the Auth Manifest vendor/owner signatures. Tampering with the SVN invalidates the manifest signature.
- **No MCU image format dependency** — Caliptra RT remains agnostic to the MCU image internal structure.
- **Backward compatible** — Existing deployments that set `preamble.svn = 0` continue to work. MCU RT DPE context is created with SVN = 0 in that case.
- **Standard DPE command path** — Hitless update uses RECURSIVE DeriveContext via the standard DPE command interface, not direct context array manipulation.

### Limitations

- **SVN semantics** — The `preamble.svn` field serves double duty as both the Auth Manifest anti-rollback value (checked against Caliptra Core fuses) and the MCU RT FW SVN (bound into the DPE context). If these need to diverge, a future Auth Manifest revision should add a separate field or use SVN field partitioning.
- **MCU ROM SVN retrieval** — MCU ROM must retrieve the MCU RT FW SVN via `GET_IMAGE_INFO()` mailbox command to Caliptra RT unless the MCU image also embeds the SVN internally. This is a cross-boundary dependency during MCU early boot.

---

## Future Update: Separate MCU RT Firmware Manifest

The Auth Manifest was originally scoped for **Owner Authorization** — it was not designed to serve as a secure boot manifest. Conflating these two roles limits the expressiveness of both use cases.

Secure boot for MCU RT firmware has a distinct scope:

- **Allow only Vendor code to execute** — The MCU RT image must be authenticated against a Vendor-signed manifest before execution is permitted.
- **Collect Vendor-authorized claims for attestation** — Claims such as SVN, firmware version, and image digest must be sourced from a Vendor-signed artifact, not repurposed from an authorization manifest.

The proposal is to introduce a **separate Vendor-signed manifest for Caliptra MCU RT firmware**. Under this model:

1. The Vendor signs a dedicated MCU RT firmware manifest containing the image digest, SVN, firmware version, and other metadata.
2. **MCU ROM** authenticates the MCU RT image at boot using a key rooted in **MCU fuses**, collects the digest, SVN, and other claims from the manifest.
3. MCU ROM passes the authenticated digest to **Caliptra Core RT firmware**, which authorizes the digest and creates the MCU RT DPE context.

This cleanly separates the concerns of Owner Authorization (Auth Manifest) and Vendor-controlled secure boot (MCU RT Manifest), eliminating the need for SVN field overloading and implicit conventions.

This proposal requires an RFC to Caliptra 2.2 to define the new manifest format, authentication flow, and integration points with Caliptra Core RT firmware.

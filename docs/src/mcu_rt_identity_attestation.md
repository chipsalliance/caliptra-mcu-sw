# MCU RT Identity Attestation in the Caliptra DICE Architecture

## Overview

This document describes how MCU Runtime (RT) firmware is integrated into the DICE layering architecture by adding it as a DPE (DICE Protection Environment) managed context. By placing MCU RT into the DPE context chain in PL0 locality, Caliptra RT generates and maintains claims for the MCU RT firmware — including firmware digest, journey measurement, SVN — enabling standards-based attestation through the DICE certificate hierarchy.

### Identity and Attestation Roles

- **Caliptra Core** provides **identity attestation** for the MCU RT — the MCU RT DPE context and its ancestor chain (RTMR -> MBVP -> ROM stashed measurements) form the basis for attestation key derivation and certificate issuance via `CertifyKey`/`Sign`.
- **MCU** (running SPDM responder) handles **inventory attestation** for remaining SoC components.

---

## DPE Context Model for MCU RT

The MCU RT firmware occupies a specific position in the DPE context hierarchy. The following properties define how MCU RT integrates into the Caliptra DPE measurement chain:

- **MCU RT DPE Context Creation during Cold Boot** — During MCU recovery boot, Caliptra RT creates the MCU RT context as the default context in PL0 PAUSER locality, chained to all prior measurements (RTMR, MBVP, ROM stashed measurements).

- **Keeping Attestation scoped to MCU** — `CertifyKey` and `Sign` operations on the default handle derive keys solely from the MCU RT context and its ancestors in PL0 PAUSER locality. SoC firmware contexts, if any, are derived as children in different (PL1 PAUSER) locality and are excluded from key derivation.

- **Hitless MCU RT updates** — Caliptra RT updates the MCU RT TCI directly using its privileged access to the DPE context array (similar to RTMR). The default handle remains stable at `[0x00; 16]` across updates.

- **SoC firmware isolation** — The MCU derives SoC firmware contexts using RETAIN_PARENT and CHANGE_LOCALITY to PL1, while keeping the MCU RT context unchanged in PL0. These SoC firmware contexts are optional, created as child contexts in PL1 PAUSER locality, and do not affect attestation key derivation.

Creating the MCU RT DPE context requires invoking `DeriveContextCmd` with both a **measurement** (the SHA-384 digest of the MCU RT image) and an **SVN** (the security version number of the firmware). The measurement is already available from Caliptra RT's image authentication step, but the SVN presents a sourcing challenge described below.

---

## Problem: SVN Sourcing for the MCU RT DPE Context

Caliptra RT authenticates MCU firmware by verifying its SHA-384 digest against the [Authorization Manifest](https://github.com/chipsalliance/caliptra-sw/blob/main/auth-manifest/README.md). This establishes **integrity** and **authenticity**, but **not anti-rollback** — Caliptra RT has no access to MCU SVN fuses. Anti-rollback enforcement is the responsibility of **MCU ROM**, which reads vendor-defined SVN fuses in the MCU domain.

`DeriveContextCmd` requires both a `measurement` and an `svn` to create the MCU RT DPE context. While the measurement is available via the image digest, neither `AuthManifestImageMetadata` entry nor the **recovery or update flows** currently provide an `svn` value. 

---

## Design: Reinterpret Auth Manifest Preamble SVN Field

### Requirements

1. **Caliptra RT** needs the `svn` for `DeriveContextCmd` to bind version information into the DPE context for attestation certificates.
2. **MCU ROM** needs the `svn` to validate against its anti-rollback fuses.
3. **MCU RT firmware** needs `current digest, journey digest, svn` claims about MCU RT target environment to report as part of attestation claims.


This design makes **no changes to Caliptra 2.x** — neither the Auth Manifest data format nor the Caliptra RT firmware verification logic of the current Auth Manifest is modified. Instead, existing fields in `AuthManifestPreamble` are **reinterpreted** with strict rules imposed on how the Auth Manifest is constructed for MCU use. The Auth Manifest version should be updated (from 2 to 3) to indicate that the new semantics are in use, but this is a non-breaking change since the binary layout of the preamble remains the same.

### SVN Field Partitioning

The existing 4-byte `svn` field in `AuthManifestPreamble` is partitioned into two 16-bit sub-fields:

```
AuthManifestPreamble.svn (u32)
+----------------------+----------------------+
|  Bits [31:16]        |  Bits [15:0]         |
|  MCU RT FW SVN       |  Auth Manifest SVN   |
|  (u16)               |  (u16)               |
+----------------------+----------------------+
```

- **Bits [15:0] — Auth Manifest SVN**: Enforced by Caliptra Core anti-rollback fuses. This is existing Caliptra 2.x behavior and requires no change.
- **Bits [31:16] — MCU RT FW SVN**: Not processed or validated by Caliptra RT. Caliptra RT's existing SVN fuse check only examines the lower bits. The upper half is read by Caliptra RT and passed as the `svn` parameter in `DeriveContextCmd` when creating the MCU RT DPE context.

### Auth Manifest Construction Rules

1. **Flags Bit 0 (`VENDOR_SIGNATURE_REQUIRED`) must be set** — The Auth Manifest `flags` field must have Bit 0 asserted. This ensures that vendor signatures are always verified during authorization, making secure boot verification for MCU RT firmware possible. This is a pre-existing flag but is a strict requirement for any Auth Manifest that uses the MCU RT authentication flow.

2. **Image Metadata Collection must contain an MCU RT entry** — The `AuthManifestImageMetadataCollection` must include an entry for the MCU RT firmware image, identified by the universal `fw_id: 0x0002`. The entry's `digest` field contains the SHA-384 hash of the MCU RT image, used by Caliptra RT for image verification during recovery boot.

3. **SVN field encoding** — OEM tooling must populate `AuthManifestPreamble.svn` as:
   ```
   preamble.svn = (mcu_rt_fw_svn << 16) | auth_manifest_svn
   ```
   where `auth_manifest_svn` is the value enforced against Caliptra Core fuses and `mcu_rt_fw_svn` is the MCU runtime firmware security version.

### Boot Flow

```
1. OEM builds MCU RT image (no image format changes required)
2. OEM generates Auth Manifest:
   - preamble.svn[15:0] = Auth Manifest SVN (for Caliptra Core fuse enforcement)
   - preamble.svn[31:16] = MCU RT FW SVN
   - preamble.flags Bit 0 = 1 (VENDOR_SIGNATURE_REQUIRED)
   - Image Metadata Collection includes MCU RT entry with SHA-384 digest
   - Vendor/owner signatures computed over the manifest (covers both SVN sub-fields)
3. Caliptra RT: Set Auth Manifest flow:
   - Validates vendor/owner signatures
   - Checks if the manifest version is compatible
     (if version >= 3, enforces the new semantics; if version < 3, treats svn as a simple u32)
   - If version >= 3, checks preamble.svn[15:0] against Caliptra Core anti-rollback fuses. Stores MCU SVN (preamble.svn[31:16]) in persistent data.
   - Stores the Auth Manifest for subsequent image authorization
4. Caliptra RT: MCU Recovery Boot flow:
   - Caliptra RT downloads MCU RT image to MCU SRAM via Recovery Interface
   - Caliptra RT computes SHA-384 over MCU SRAM, verifies against
     Auth Manifest Image Metadata entry digest
   - Reads MCU RT FW SVN from persistent data (preamble.svn[31:16])
   - DeriveContextCmd is invoked with:
       measurement = SHA-384 digest of MCU RT image
       svn         = preamble.svn[31:16] (MCU RT FW SVN)
     This creates the MCU RT DPE context in PL0 locality
5. MCU ROM flow:
   - MCU ROM retrieves the SVN via GET_IMAGE_INFO() mailbox command
     to Caliptra RT (reads from DPE context)
   - MCU ROM validates MCU RT FW SVN against its own anti-rollback fuses
     (vendor-defined fuses in the MCU domain, separate from Caliptra Core fuses)
6. Attestation:
   - CertifyKey/Sign on the MCU RT default handle derives keys from the
     MCU RT context (measurement + SVN) and its ancestors
   - MCU RT SVN is reflected in TcbInfo via DPE certificate DICE extensions
   - SPDM responder can retrieve MCU RT measurement info
     (digest, journey digest, SVN) via GET_IMAGE_INFO()
```

### MCU ROM SVN Retrieval

During MCU ROM boot, the ROM code retrieves the MCU RT FW SVN using the `GET_IMAGE_INFO()` mailbox command to Caliptra RT, which reads the value from the DPE context. This allows MCU ROM to perform its own anti-rollback checks against vendor-defined fuses in the MCU domain.

---

## Required Implementation Changes

1. **No changes to Auth Manifest tooling or structure** — The Auth Manifest generation tooling and binary structure require no modifications. Only the input values differ — specifically, the `svn` field is populated with the partitioned encoding described above.

2. **Caliptra RT (`caliptra-sw`)** — During the Set Auth Manifest flow, Caliptra RT must check the manifest version. If version >= 3, it enforces anti-rollback using only `preamble.svn[15:0]` against Caliptra Core fuses and stores `preamble.svn[31:16]` (MCU RT FW SVN) in persistent data for later use during `DeriveContextCmd`.

3. **MCU-side DPE context creation (`caliptra-mcu-sw`)** — When creating the MCU RT DPE context during recovery boot after Caliptra RT authenticates the image:
   - Read `mcu_rt_svn` from persistent data.
     - This value was stored by Caliptra RT during the Set Auth Manifest flow, sourced from `preamble.svn[31:16]`.
   - Read the MCU RT image digest from the matching `AuthManifestImageMetadata` entry
   - Call `DeriveContextCmd` with `measurement = digest` and `svn = mcu_rt_svn`

4. **OEM manifest generation tooling** — Update the Auth Manifest builder to accept an MCU RT FW SVN parameter and encode it into the upper 16 bits of `preamble.svn`:
   ```rust
   let svn_field: u32 = ((mcu_rt_fw_svn as u32) << 16) | (auth_manifest_svn as u32);
   preamble.svn = svn_field;
   preamble.flags = AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED.bits();
   ```

5. **Image Metadata Collection** — Ensure the MCU RT firmware image is included as an entry in `AuthManifestImageMetadataCollection` with:
   - `fw_id` set to the MCU RT firmware identifier
   - `digest` set to the SHA-384 hash of the MCU RT image
   - `flags.image_source` set appropriately for the MCU RT image location

6. **`GET_IMAGE_INFO()` mailbox command** — Implement or use the existing `GET_IMAGE_INFO()` mailbox command so MCU ROM can read the SVN from the DPE context for anti-rollback validation against its own fuses.

---

## Design Trade-offs

### Advantages

- **Zero Auth Manifest format changes** — All existing struct definitions remain unchanged. No binary layout changes required.
- **Minimal Caliptra 2.x RT firmware changes** — Caliptra RT's will continue to function as before for the Auth Manifest version 2. For Version 3, the lower 16 bits are interpreted as Auth Manifest SVN and the upper 16 bits are interpreted as MCU RT FW SVN and passed to `DeriveContextCmd`, but the core logic of manifest verification and image authentication remains intact.
- **Works for encrypted firmware** — MCU RT FW SVN is in the Auth Manifest preamble (always cleartext), not embedded in the MCU image.
- **Cryptographically protected** — Both SVN sub-fields are covered by the Auth Manifest vendor/owner signatures. Tampering with either sub-field invalidates the manifest signature.
- **No MCU image format dependency** — Caliptra RT remains agnostic to the MCU image internal structure.
- **<Backward compatible>** — Existing deployments that set `preamble.svn` as a simple 16-bit value (upper bits zero) continue to work. MCU RT FW SVN defaults to 0 in that case.

### Limitations

- **MCU RT FW SVN range limited to 16 bits (u16)** — Maximum value of 65,535. Sufficient for practical SVN lifetimes but a reduction from the theoretical u32 range.
- **Auth Manifest SVN also limited to 16 bits (u16)** — The existing Auth Manifest SVN field is effectively narrowed from u32 to u16 (0-65,535). Sufficient given that Caliptra Core anti-rollback fuses are a finite resource.
- **Overloaded field semantics** — The `svn` field carries two distinct values. OEM tooling authors must understand the bit-field partitioning. Clear documentation and manifest generation library support mitigate this. Also submit an RFC to propose a new future manifest explicitly for MCU RT with SVN and Firmware version fields to eventually replace this overloaded approach in Caliptra 2.2.
- **Implicit contract** — The partitioning of `svn` into two sub-fields is not enforced by the data format itself. It relies on convention and tooling discipline. A manifest generated with incorrect upper bits would still pass Caliptra RT validation but would bind an incorrect SVN into the DPE context.
- **MCU ROM SVN retrieval** — MCU ROM must retrieve the MCU RT FW SVN via `GET_IMAGE_INFO()` mailbox command to Caliptra RT unless the MCU image also embeds the SVN internally. This is a cross-boundary dependency during MCU early boot.

---

## Future Update: Separate MCU RT Firmware Manifest

The Auth Manifest was originally scoped for **Owner Authorization** — it was not designed to serve as a secure boot manifest. Conflating these two roles introduces semantic overloading (e.g., the SVN field partitioning above) and limits the expressiveness of both use cases.

Secure boot for MCU RT firmware has a distinct scope:

- **Allow only Vendor code to execute** — The MCU RT image must be authenticated against a Vendor-signed manifest before execution is permitted.
- **Collect Vendor-authorized claims for attestation** — Claims such as SVN, firmware version, and image digest must be sourced from a Vendor-signed artifact, not repurposed from an authorization manifest.

The proposal is to introduce a **separate Vendor-signed manifest for Caliptra MCU RT firmware**. Under this model:

1. The Vendor signs a dedicated MCU RT firmware manifest containing the image digest, SVN, firmware version, and other metadata.
2. **MCU ROM** authenticates the MCU RT image at boot using a key rooted in **MCU fuses**, collects the digest, SVN, and other claims from the manifest.
3. MCU ROM passes the authenticated digest to **Caliptra Core RT firmware**, which authorizes the digest and creates the MCU RT DPE context.

This cleanly separates the concerns of Owner Authorization (Auth Manifest) and Vendor-controlled secure boot (MCU RT Manifest), eliminating the need for field overloading and implicit conventions. The SVN field partitioning described in this document serves as a pragmatic interim solution until this dedicated manifest is available.

This proposal requires an RFC to Caliptra 2.2 to define the new manifest format, authentication flow, and integration points with Caliptra Core RT firmware.

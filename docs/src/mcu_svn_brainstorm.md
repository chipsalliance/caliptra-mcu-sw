# MCU RT SVN for DPE DeriveContext — Design Options

## Problem Statement

- Caliptra RT authenticates MCU firmware by verifying its SHA-384 digest against the Authorization Manifest. This establishes **integrity** and **authenticity**, but **not anti-rollback** — Caliptra has no access to the MCU SVN fuses.
- Anti-rollback is enforced by **MCU ROM**, which reads vendor-defined SVN fuses in the MCU domain.
- `DeriveContextCmd` requires both a **measurement** and an **SVN** to create the MCU RT DPE context (**Q: HOW IMPORTANT IS IT TO HAVE ALL FIELDS FILLED IN DERIVE CONTEXT?**). 
- The measurement is available from the digest, but **neither `AuthManifestImageMetadata` nor the recovery flow currently carries an SVN value**.

### Constraints

1. Caliptra RT needs the SVN for `DeriveContextCmd` to bind version info into the DPE context for attestation certificates.
2. MCU ROM needs the SVN to validate against its anti-rollback fuses.
3. In the **encrypted firmware** boot path (`recovery_flow.rs:136-166`), the MCU image in SRAM is ciphertext — Caliptra RT **cannot parse** the image contents. MCU ROM decrypts the image after Caliptra RT has already completed authentication.

### Background: MCU RT DPE Context Model 
Previously discussed flow of adding MCU to DPE context hierarchy:
- **MCU RT is the default PL0 context** — during MCU recovery boot, Caliptra RT creates the MCU RT context as the default context in PL0 locality, chained to all prior measurements (`RTMR → MBVP → ROM stashed measurements`).
- **Attestation is scoped to the MCU** — `CertifyKey`/`Sign` operations on the default handle derive keys solely from the MCU RT context and its ancestors. SoC firmware contexts are derived as children and excluded from key derivation.
- **Hitless MCU RT updates** — Caliptra RT updates the MCU RT TCI directly using its privileged access to the DPE context array (similar to RTMR). The default handle remains stable at `[0x00; 16]` across updates.
- **SoC firmware isolation** — the MCU derives SoC firmware contexts using `RETAIN_PARENT` + `CHANGE_LOCALITY` to PL1, leaving the MCU RT context unchanged in PL0.

---

## Option A: SVN in McuImageHeader Only

### Flow

```
1. OEM builds MCU image with McuImageHeader { svn: X, ... } prepended
2. Auth Manifest contains digest = SHA-384(header + payload) — no separate SVN field in AuthManifestImageMetadata entry 
4. Caliptra RT computes SHA-384 over MCU SRAM, verifies against Auth Manifest digest
5. Caliptra RT reads McuImageHeader.svn from MCU SRAM offset 0
6. Caliptra RT calls DeriveContext(measurement=digest, svn=header.svn, ...)
7. MCU ROM boots, reads McuImageHeader.svn from SRAM, validates against fuses
```

### Pros

- No Auth Manifest format change
- MCU ROM has direct local access to SVN
- SVN is integrity-bound via the image digest
- **MCU RT Target environment claim** - SVN is in the DPE context, Caliptra RT can retrieve MCU RT info (`digest, journey digest, svn`) from context and provide via `GET_IMAGE_INFO()` mailbox command to SPDM responder.

### Cons

- **Breaks for encrypted firmware** — Caliptra RT cannot read the header when MCU SRAM contains ciphertext (step 5 fails)
- Couples Caliptra RT to MCU image format — Caliptra RT must know `McuImageHeader` layout
- Requires DMA read from MCU SRAM for SVN extraction

---

## Option B: SVN in AuthManifestImageMetadata Only

### Flow

```
1. OEM builds just the MCU image (no SVN requirement in image header)
2. Auth Manifest contains digest (only payload) + svn field per image entry
3. Caliptra RT downloads image to MCU SRAM
4. Caliptra RT computes SHA-384, verifies against Auth Manifest digest
5. Caliptra RT reads SVN from AuthManifestImageMetadata.svn for MCU image entry
6. Caliptra RT calls DeriveContext(measurement=digest, svn=metadata.svn, ...)
7. MCU ROM boots, needs SVN for fuse validation — must issue mailbox
   command to Caliptra RT to retrieve the SVN
```

### Pros

- Works for both plaintext and encrypted firmware — Auth Manifest is always in cleartext
- Caliptra RT is image-format-agnostic — reads SVN from the same structure used for authentication
- No MCU SRAM parsing needed in Caliptra RT
- Auth Manifest is a signed artifact — SVN gets cryptographic protection from the manifest signature
- **MCU RT Target environment claim** - SVN is in the DPE context, Caliptra RT can retrieve MCU RT info (`digest, journey digest, svn`) from context and provide via `GET_IMAGE_INFO()` mailbox command to SPDM responder. This is the same as Option A, but with the SVN coming from the manifest instead of the image header.
- MCU ROM can also use `GET_IMAGE_INFO()` command to retrieve the SVN — no image format dependency, just a mailbox command to Caliptra RT


### Cons

- MCU ROM would use `GET_IMAGE_INFO()` mailbox command to get the SVN for fuse validation — is this cross-boundary dependency acceptable during MCU's early boot?
- If not, adds latency and failure modes to MCU boot (mailbox timeout handling)
- Auth Manifest format change required (new `svn: u32` field in `AuthManifestImageMetadata`)

---

## Option C: SVN in Both Places (Recommended for Simplicity and Robustness)

### Flow

```
1. OEM builds MCU image with McuImageHeader { svn: X, ... } prepended
2. Auth Manifest contains digest = SHA-384(header + payload) AND svn field
   - digest covers the header, so header.svn and metadata.svn are bound together
3. Caliptra RT downloads image to MCU SRAM
4. Caliptra RT computes SHA-384, verifies against Auth Manifest digest
5. Caliptra RT reads SVN from AuthManifestImageMetadata.svn
   - Works regardless of whether image is encrypted or plaintext
6. Caliptra RT calls DeriveContext(measurement=digest, svn=metadata.svn, ...)
7. MCU ROM boots:
   - Plaintext: reads McuImageHeader.svn directly from SRAM
   - Encrypted: decrypts image first, then reads McuImageHeader.svn
   - Validates SVN against anti-rollback fuses locally — no mailbox needed
```

### Pros

- **Works for both plaintext and encrypted firmware** — Caliptra RT always reads from Auth Manifest (cleartext), never needs to parse MCU SRAM
- **No cross-boundary dependency for MCU ROM** — reads SVN locally from SRAM after decryption, no mailbox round-trip
- **Each consumer reads from the most natural place:**
  - Caliptra RT → Auth Manifest (already parsed during authentication)
  - MCU ROM → Image header (already in local SRAM)
- **Integrity-bound** — for plaintext images, the digest covers the header, so `AuthManifestImageMetadata.svn` and `McuImageHeader.svn` cannot diverge without failing authentication
- **Clean separation of concerns** — Auth Manifest describes authorization policy, image header carries runtime metadata

### Cons

- Auth Manifest format change required (add `svn: u32` to `AuthManifestImageMetadata`)
- SVN exists in two places — but they are bound together by the digest and cannot diverge for authenticated images
- OEM tooling must ensure consistency when generating manifests (though this is enforced automatically since the digest covers the header)

---

## Comparison

| | Option A | Option B | Option C (Recommended) |
|---|---|---|---|
| Caliptra RT SVN source | MCU SRAM header | Auth Manifest | Auth Manifest |
| MCU ROM SVN source | MCU SRAM header | Mailbox to Caliptra RT | MCU SRAM header |
| Encrypted FW support | No | Yes | Yes |
| MCU ROM cross-boundary dep. | None | Mailbox command required | None |
| Auth Manifest format change | No | Yes | Yes |
| Image format change | Yes | No | Yes |

---

## Required Changes for Option C

1. **`auth-manifest/types/src/lib.rs`** — Add `svn: u32` to `AuthManifestImageMetadata`:
   ```rust
   pub struct AuthManifestImageMetadata {
       pub fw_id: u32,
       pub component_id: u32,
       pub classification: u32,
       pub flags: u32,
       pub image_load_address: Addr64,
       pub image_staging_address: Addr64,
       pub digest: [u8; 48],
       pub svn: u32,                    // ***NEW***
   }
   ```

2. **`runtime/src/recovery_flow.rs`** — After authentication, read SVN from the matched Auth Manifest entry and pass to `DeriveContext` for MCU RT context creation.

3. **MCU image format** — Add `McuImageHeader` with `svn: u16` at offset 0 when building the MCU image. The header is included in the digest calculation, so the manifest binds the header SVN to the authorized value.
   ```rust
   pub struct McuImageHeader {
       pub svn: u16,
       pub reserved1: u16,
       pub reserved2: u32,
   }
   ```

4. **Preparing Auth Manifest** — Populate `AuthManifestImageMetadata.svn` to match the image header SVN during manifest generation.

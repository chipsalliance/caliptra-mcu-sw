# MCU Firmware Format

This document describes optional headers placed after the platform's fixed MCU
image header and before the runtime firmware reset vector in MCU SRAM. They give
ROM a way to act on instructions carried by the authenticated firmware image.

All headers described here are **optional**. A firmware image that does
not include any of them still boots normally; the ROM detects each header
by its magic value and silently skips any header that is absent.

## Purpose

Caliptra authenticates the MCU runtime firmware against the SoC manifest before
loading it into MCU SRAM. Any optional header prepended to that image is covered
by the same authenticated image digest.

An integrator may desire that some operations — burning fuses, advancing
ownership state, and similar one-way platform changes — are performed
by immutable code. 

Firmware headers provide an authenticated, idempotent path for ROM to perform a
well-defined set of operations before entering Runtime. The model is:

* The entity authorized to produce the MCU image decides which operations need
  to happen on the next boot.
* Those operations are encoded as a fixed-format header and prepended to
  the firmware image before the SoC manifest digest is generated.
* After Caliptra authenticates and loads the image, ROM inspects the header,
  executes the requested operations, and advances the firmware entry offset
  past the header before jumping to Runtime.
* Each command uses fuse parity or `min_fuse_count` to avoid repeating a
  completed transition when the same header is processed on a later boot.
  Interrupted write/burn sequences have the failure behavior described below.

This keeps the ROM-owned operation set small and auditable while providing an
authenticated alternative to the Runtime management-command paths.

## Image Layout

When one or more headers are present, they are concatenated at the start
of the MCU image, in front of the firmware's reset vector:

```
+-----------------------------------------+ <- MCU_MEMORY_MAP.sram_offset
| Platform MCU image header               |
+-----------------------------------------+ <- + mcu_image_header_size
| Firmware manifest DOT section (optional)|
+-----------------------------------------+
| MCU Component SVN Manifest (optional)   |
+-----------------------------------------+
| MCU runtime firmware (reset vector, ...)|
+-----------------------------------------+
```

Each header starts with a 32-bit little-endian magic value. The ROM
checks the magic at the expected offset; if it does not match, the ROM
assumes no header of that type is present and does not advance the
firmware entry offset for it. The firmware entry offset the ROM jumps
to is:

```
entry = sram_offset + mcu_image_header_size + sum(size_of(present headers))
```

Each supported header type also carries its own integrity check (e.g. a
checksum) and a version field so the format can evolve without breaking
older ROMs.

Header processing is gated both at compile time (by a ROM Cargo
feature) and at runtime (by a field in `RomParameters`), so integrators
opt in explicitly per platform. A header-bearing image must be paired with ROM
support for that header; otherwise ROM does not consume the header or advance
the firmware entry offset past it.

## Firmware Manifest DOT Section

The first header defined in this format is the **firmware manifest DOT
section**, used to request [Device Ownership Transfer](./dot.md) state
changes (lock, unlock, rotate, disable) during firmware updates.

### Summary

* **Magic:** `FW_MANIFEST_DOT_MAGIC = 0x444F_5443` (u32). Stored
  little-endian, the four bytes on disk at offset `0x00` are
  `0x43 0x54 0x4F 0x44` — i.e. the ASCII string `"CTOD"`. The source
  code comment spells this magic as `"DOTC"` because the hex digits
  of the constant, read most-significant byte first, are `44 4F 54 43`;
  the actual byte order in the image file is the reverse.
* **Size:** 128 bytes, naturally aligned
* **Version:** 1
* **Cargo feature:** `fw-manifest-dot` on the ROM crate
* **Runtime gate:** `RomParameters::fw_manifest_dot_enabled`
* **Source of truth:** `FwManifestDotSection` in
  [`rom/src/device_ownership_transfer.rs`](https://github.com/chipsalliance/caliptra-mcu-sw/blob/main/rom/src/device_ownership_transfer.rs)

### Layout

```text
offset  size  field          description
------  ----  -------------  -------------------------------------------------
 0x00     4   magic          FW_MANIFEST_DOT_MAGIC = 0x444F_5443 (u32).
                              On disk (little-endian): 43 54 4F 44 ("CTOD").
 0x04     4   checksum       ones-complement of the wrapping sum of
                              little-endian u32 words in bytes[8..end]
 0x08     4   version        format version (must be 1)
 0x0C     4   num_commands   number of valid entries in `commands` (<= 8)
 0x10     4   min_fuse_count ROTATE idempotency threshold (ignored otherwise)
 0x14     8   commands       up to 8 command bytes, executed in order
 0x1C    48   cak_digest     SHA-384 digest of the CAK for LOCK/ROTATE (12x u32)
 0x4C    48   lak_digest     SHA-384 digest of the LAK public-key set (12x u32)
 0x7C     4   _reserved      reserved; included in checksum but not interpreted
```

The `checksum` is a ones-complement over every byte after the magic and
checksum fields. It protects against accidental image corruption. It is
**not** a substitute for authentication — the real authentication comes
from the firmware image signature verified by the SoC manifest flow.

### Commands

Each byte in `commands` encodes one of the following operations. All
commands re-read the current DOT fuse state from OTP before acting and
skip themselves if the requested transition has already been applied,
so the header is safe to leave in place across reboots.

| Value | Name     | Meaning                                                                                 |
|-------|----------|-----------------------------------------------------------------------------------------|
| `0`   | NOP      | Padding / no-op.                                                                        |
| `1`   | LOCK     | Transition from unlocked (EVEN) to locked (ODD), using `cak_digest` and `lak_digest`.   |
| `2`   | UNLOCK   | Transition from ODD to EVEN and write a zero-CAK blob using the section's `lak_digest`. |
| `3`   | ROTATE   | Burn two DOT fuses to advance the effective key while preserving lock/unlock parity. Idempotency is controlled by `min_fuse_count`: rotation is applied only when the currently burned count is below this threshold. |
| `4`   | DISABLE  | Ensure the device is in ODD (locked/disabled) state. Equivalent at the fuse level to LOCK, but the associated DOT blob contains a zero CAK digest. |

Unknown command values cause the ROM to fail the firmware boot with
`ROM_COLD_BOOT_FW_MANIFEST_DOT_ERROR`. Version mismatches are treated
the same way.

A section containing both LOCK/DISABLE and UNLOCK is rejected before any
command executes. If `dot_initialized` is clear, the first non-NOP command ends
section processing without an error or state change. The manifest path writes
the `cak_digest` and `lak_digest` values as supplied; unlike the corresponding
Runtime commands, it does not reject zero digests. A zero CAK produces no
DOT-supplied owner, and a zero LAK prevents the normal LAK unlock flow.

The authenticated MCU image authorizes these directives. Manifest UNLOCK does
not inspect the current DOT_BLOB's LAK digest or run the Runtime `MDUC`/`MDUL`
challenge-and-signature protocol; it stores the section's `lak_digest` in the
post-transition blob.

### ROM Processing

The header is consumed by the ROM as part of the Firmware Boot Flow
(see the [Reference ROM Specification](./rom.md)):

1. During cold boot, firmware in MCU SRAM is always decrypted by the
   time the Firmware Boot Flow runs, so the ROM can read the header
   in place.
2. The ROM looks for `FW_MANIFEST_DOT_MAGIC` at
  `sram_offset + mcu_image_header_size`. If the magic is absent, no DOT
  header processing is done and the firmware entry offset is unchanged.
3. If the magic is present, the ROM verifies the checksum and version,
   then executes the commands in order against the live DOT fuse/blob
   state.
4. On success, the ROM advances the firmware entry offset by the size
   of the section and jumps to the firmware's reset vector.
5. Any error in header validation or command execution is fatal and
   halts the boot.

During the **Hitless Firmware Update Flow**, ROM performs the same manifest
detection and command execution as during the firmware-boot path. A new image
delivered by hitless update can therefore apply its authenticated DOT directives
on that boot.

### DOT Blob Updates and Power-Loss Behavior

Every command that changes DOT fuse state must also leave a consistent
DOT blob on flash, otherwise the next boot will see fuse state that
does not match the sealed blob and the part will be unbootable via the
DOT path. The exact sequence the ROM uses per command is:

* **LOCK / DISABLE** (EVEN → ODD): the ROM first seals the DOT blob
  with the new CAK digest and LAK digest (LOCK), or a zero CAK digest and
  new LAK digest (DISABLE), with the target ODD epoch key derived from
  the current EVEN state, writes it to DOT flash,
  and only then burns the lock fuse. If power is lost between the
  blob write and the fuse burn, the fuses still report "unlocked" on
  the next boot and the command is re-attempted idempotently.
* **UNLOCK** (ODD → EVEN): the ROM pre-computes the *post-burn* fuse
  state, seals a zero-CAK blob containing the section's `lak_digest` against
  that future effective key,
  writes it to DOT flash, and then burns the unlock fuse. If power is
  lost between the blob write and the fuse burn, the already-written
  blob is sealed against a key that the device cannot yet derive, so
  the next boot will see a valid-looking but HMAC-failing blob and
  must recover via a DOT recovery handler (see [DOT](./dot.md)).
* **ROTATE**: the ROM burns both rotation fuses first and only then
  re-seals the DOT blob against the rotated effective key. If power
  is lost after a fuse burn but before the blob is re-sealed, the next
  boot can see a stale blob that no longer matches the current
  fuse-derived key.
* **NOP**: nothing is written.

The remaining failure windows are between the pre-computed UNLOCK blob write
and its fuse burn, between the individual ROTATE fuse burns, and between the
completed ROTATE fuse burns and its blob write. A reset in one of these windows
can leave a blob that does not authenticate at the current epoch. Current ROM
invokes the configured locked-state recovery policy for an ODD-state mismatch;
an EVEN-state mismatch is a fatal DOT boot error.

See [DOT Recovery Mechanisms](./dot.md#recovery-mechanisms) for the implemented
ROM and Runtime recovery paths.

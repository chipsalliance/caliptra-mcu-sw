# MCU Firmware Format

This document describes optional headers that may be prepended to the MCU
runtime firmware image. These headers sit **in front of** the firmware's
reset vector in MCU SRAM and give the ROM a way to act on instructions
carried by the firmware image itself.

All headers described here are **optional**. A firmware image that does
not include any of them still boots normally; the ROM detects each header
by its magic value and silently skips any header that is absent.

## Purpose

The ROM is the trusted component of the MCU. The MCU runtime firmware is
authenticated against the code-signing keys (via the Caliptra
SoC manifest) before the ROM jumps to it, which means any bytes that the
ROM consumes from the start of the firmware image inherit the same
authorization guarantees as the firmware itself.

An integrator may desire that some operations — burning fuses, advancing
ownership state, and similar one-way platform changes — are performed
by immutable code. 

Firmware headers give the runtime an **easy, signed, idempotent path** to
ask the ROM to perform a well-defined set of privileged operations on
its behalf. The model is:

* The firmware image author (the signer who holds the owner code-signing
  key) decides which operations need to happen on the next boot.
* Those operations are encoded as a fixed-format header and prepended to
  the firmware image before signing.
* The ROM authenticates the whole image as usual, then — before jumping
  to the firmware — inspects the header, executes the requested
  operations, and advances the firmware entry offset past the header.
* Every command is idempotent: if the requested state change has
  already been applied on a previous boot, the command is a no-op. This
  makes it safe to leave the header in place across resets and hitless
  updates.

This keeps the set of operations the ROM will perform small, auditable,
and explicitly authorized, while avoiding the need to implement
privileged paths in the runtime firmware.

## Image Layout

When one or more headers are present, they are concatenated at the start
of the MCU image, in front of the firmware's reset vector:

```
+-----------------------------------------+ <- MCU_MEMORY_MAP.sram_offset
| Optional header #1 (e.g. DOT manifest)  |
+-----------------------------------------+
| Optional header #2 (future)             |
+-----------------------------------------+
| ...                                     |
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
opt in explicitly per platform. A ROM built without the feature pays no
code-size cost and ignores any such header.

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
 0x04     4   checksum       ones-complement of the u32 sum of bytes[8..end]
 0x08     4   version        format version (must be 1)
 0x0C     4   num_commands   number of valid entries in `commands` (<= 8)
 0x10     4   min_fuse_count ROTATE idempotency threshold (ignored otherwise)
 0x14     8   commands       up to 8 command bytes, executed in order
 0x1C    48   cak            Code Authentication Key for LOCK/ROTATE (12x u32)
 0x4C    48   lak            Lock Authentication Key for LOCK/DISABLE (12x u32)
 0x7C     4   _reserved      must be zero
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
| `1`   | LOCK     | Transition from unlocked (EVEN) to locked (ODD), using `cak` and `lak`.                 |
| `2`   | UNLOCK   | Transition from locked (ODD) to unlocked (EVEN).                                        |
| `3`   | ROTATE   | Burn two DOT fuses to advance the effective key while preserving lock/unlock parity. Idempotency is controlled by `min_fuse_count`: rotation is applied only when the currently burned count is below this threshold. |
| `4`   | DISABLE  | Ensure the device is in ODD (locked/disabled) state. Equivalent at the fuse level to LOCK, but the associated DOT blob contains no CAK. |

Unknown command values cause the ROM to fail the firmware boot with
`ROM_COLD_BOOT_FW_MANIFEST_DOT_ERROR`. Version mismatches are treated
the same way.

### ROM Processing

The header is consumed by the ROM as part of the Firmware Boot Flow
(see the [Reference ROM Specification](./rom.md)):

1. During cold boot, firmware in MCU SRAM is always decrypted by the
   time the Firmware Boot Flow runs, so the ROM can read the header
   in place.
2. The ROM looks for `FW_MANIFEST_DOT_MAGIC` at `sram_offset`. If the
   magic is absent, no DOT header processing is done and the firmware
   entry offset is unchanged.
3. If the magic is present, the ROM verifies the checksum and version,
   then executes the commands in order against the live DOT fuse/blob
   state.
4. On success, the ROM advances the firmware entry offset by the size
   of the section and jumps to the firmware's reset vector.
5. Any error in header validation or command execution is fatal and
   halts the boot.

During the **Hitless Firmware Update Flow**, the ROM performs the same
manifest detection and command execution as during cold boot — a new
firmware image delivered via hitless update may carry a different DOT
header, and its owner-signed commands are applied on this boot rather
than deferred to the next cold reset.

### DOT Blob Updates and Power-Loss Behavior

Every command that changes DOT fuse state must also leave a consistent
DOT blob on flash, otherwise the next boot will see fuse state that
does not match the sealed blob and the part will be unbootable via the
DOT path. The exact sequence the ROM uses per command is:

* **LOCK / DISABLE** (EVEN → ODD): the ROM first re-seals the DOT blob
  with the new CAK/LAK (LOCK) or zero CAK + new LAK (DISABLE) against
  the *current* fuse-derived effective key, writes it to DOT flash,
  and only then burns the lock fuse. If power is lost between the
  blob write and the fuse burn, the fuses still report "unlocked" on
  the next boot and the command is re-attempted idempotently.
* **UNLOCK** (ODD → EVEN): the ROM pre-computes the *post-burn* fuse
  state, seals a new unlock blob against that future effective key,
  writes it to DOT flash, and then burns the unlock fuse. If power is
  lost between the blob write and the fuse burn, the already-written
  blob is sealed against a key that the device cannot yet derive, so
  the next boot will see a valid-looking but HMAC-failing blob and
  must recover via a DOT recovery handler (see [DOT](./dot.md)).
* **ROTATE**: the ROM burns both rotation fuses first and only then
  re-seals the DOT blob against the rotated effective key. If power
  is lost after the first fuse burn but before the blob is re-sealed,
  the next boot will again see a stale blob that no longer matches
  the current fuse-derived key and must recover via a DOT recovery
  handler.
* **NOP**: nothing is written.

In all cases, the DOT blob is written **before** the irreversible fuse
burn whenever possible, so that the most common failure window leaves
the device in the pre-command state. The remaining windows — between
individual fuse burns inside ROTATE, and between the pre-computed
UNLOCK blob and its fuse burn — cannot be closed by code alone: once
fuses are partially burned there is no way to roll back. A power
interruption in those windows may leave the device in a state that
requires a DOT recovery flow on the next boot, and in the worst case
may leave the part unbootable via DOT until such a recovery succeeds.

This risk is inherent to mixing single-shot fuse burns with flash
updates. It can be reduced — though not fully eliminated — by
platform-level mitigations outside the scope of this format, for
example:

* Maintaining redundant backup copies of both the *current* and *next*
  DOT blob in flash, so that a partially-updated primary copy can
  always be reconciled against a known-good backup.
* Using more sophisticated sequence locks backed by fuses (e.g., a
  small monotonic counter burned in a defined order) so that the ROM
  can unambiguously determine which step of a multi-step transition
  was in progress when power was lost, and either roll it forward or
  fall back to a backup blob.

Integrators who need stronger power-loss guarantees should layer such
mechanisms on top of the firmware manifest DOT section; the format
itself intentionally keeps the ROM-side logic minimal.

## Future Headers

Additional headers of the same shape — magic, version, checksum,
payload — can be added in the same image area (before the firmware
reset vector). Each new header will define its own magic and be
independently detected and skipped by the ROM, subject to its own
compile-time and runtime opt-in gates.

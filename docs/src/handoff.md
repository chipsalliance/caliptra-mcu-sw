# Firmware Handoff

MCU ROM passes boot state to MCU Runtime through `HandoffData`, a shared
structure in a `NOLOAD` DCCM region. The platform reserves 1 KiB for this
structure at a fixed address supplied to both ROM and Runtime linker scripts.
The handoff is volatile: Runtime may use it after the ROM-to-Runtime reset, but
software must not treat it as persistent storage across a power cycle.

## Ownership

`HandoffData` begins with two fixed-size tables:

| Offset | Size | Owner | Purpose |
|---:|---:|---|---|
| 0 | 64 bytes | ROM | Data produced by ROM and consumed by Runtime |
| 64 | 64 bytes | Runtime | Data produced or updated by Runtime |
| 128 | 132 bytes | ROM | Stable owner key CMK extension |

ROM initializes the complete defined structure during cold boot. Runtime must
treat the ROM table and ROM extensions as read-only. Runtime may update the
Runtime table only after ensuring that no conflicting references exist.

The stable owner key extension is part of the shared layout regardless of
whether a particular ROM build enables stable owner key derivation. This keeps
the ROM and Runtime layouts identical across feature combinations.

## Validation and Versioning

Runtime accepts a handoff only when the marker and major version match. A
consumer of a field added in a later minor version must also verify that the
producer's minor version includes that field and validate any field-specific
validity marker.

Use the version numbers as follows:

- Increment the minor version for an append-only, backward-compatible change.
- Increment the major version for an incompatible change, including moving or
  reinterpreting an existing field.
- Never insert an extension before an existing field or change the size of one
  of the original 64-byte tables.
- Keep layout fields unconditional. If a feature is disabled, retain the same
  bytes as reserved or invalid data.
- Add compile-time size and offset assertions for every ABI change.

This permits an older Runtime to ignore appended data from a newer ROM. A newer
Runtime must use the minor version to avoid interpreting uninitialized bytes
when booted by an older ROM. The complete structure must remain within the
platform's 1 KiB reservation.

## Stable Owner Key

Handoff version 1.1 adds `StableOwnerKeyHandoff` at offset 128. It contains the
128-byte encrypted Caliptra Cryptographic Manager key blob (CMK) followed by a
32-bit validity marker. The CMK is an opaque capability; plaintext stable owner
key material does not leave Caliptra.

During cold boot, ROM:

1. Initializes the CMK bytes to zero and the validity marker to invalid.
2. Derives the stable owner key through `CM_DERIVE_STABLE_KEY`.
3. Invalidates the marker, writes the complete encrypted CMK, and writes the
   valid marker last.

Runtime retrieves the CMK through `HandOff::stable_owner_key()`. The accessor
returns `None` for handoff version 1.0, when derivation is disabled, or when the
valid marker is absent. Runtime must keep the CMK in machine-mode-owned memory,
must not log its contents, and must not expose it directly to userspace.

## Adding Data

Small fields may replace reserved bytes when doing so preserves the size and
offset of every existing field. Larger fields must be added as fixed-layout
extensions after the last defined block. Each extension that can be populated
later than initial handoff creation should provide an explicit validity signal,
which the producer publishes only after writing all associated data.
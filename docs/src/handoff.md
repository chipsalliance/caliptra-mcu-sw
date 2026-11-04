# Firmware Handoff

MCU ROM passes boot state to MCU Runtime through `HandoffData`, a shared
structure in a `NOLOAD` DCCM region. The platform reserves 1 KiB for this
structure at a fixed address supplied to both ROM and Runtime linker scripts.
The handoff is volatile: Runtime may use it after the ROM-to-Runtime reset, but
software must not treat it as persistent storage across a power cycle.

Runtime validates the marker and major version with volatile reads before
borrowing the table. ROM writes this memory in a separate executable, so ordinary
reads of Runtime's zero-initialized static can otherwise be constant-folded by
LTO. Linker `NOLOAD` and `KEEP` directives alone do not prevent that optimization.
All Runtime entry points, including the OCP LOCK state accessor, use this
validation.

ROM and Runtime must also use the same memory layout. On the emulator, `devel`
places the handoff at `0x50003800`, while `release` uses `0x50003C00`. Build both
images with matching `--profile` values (`cargo xtask rom-build --profile release`
and `cargo xtask runtime-build --profile release` for shipping layouts).
Profile-specific build directories keep the ROM artifacts separate. FPGA uses
`0x50003C00` for both profiles.

## Ownership

`HandoffData` begins with two fixed-size tables:

| Offset | Size | Owner | Purpose |
|---:|---:|---|---|
| 0 | 64 bytes | ROM | Version, firmware boot type, capabilities, and ROM state consumed by Runtime |
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

## ROM Handoff Table

The 64-byte `RomHandoffTable` has the following layout:

| Offset | Size | Field | Description |
|---:|---:|---|---|
| 0 | 4 bytes | `fht_marker` | Handoff marker, `0x4855434D` (`MCUH` in little-endian) |
| 4 | 2 bytes | `fht_major_ver` | Major ABI version |
| 6 | 2 bytes | `fht_minor_ver` | Minor ABI version |
| 8 | 12 bytes | `ocp_lock` or `reserved_hek` | OCP LOCK state when enabled; otherwise reserved |
| 20 | 1 byte | `firmware_boot_type` | Source used to boot MCU firmware |
| 21 | 3 bytes | `reserved` | Reserved for alignment and future byte-sized fields |
| 24 | 4 bytes | `mcu_rom_capabilities` | MCU ROM capability bitmap |
| 28 | 4 bytes | `mcu_rom_version` | Packed ROM version, available starting with handoff ABI 1.4 |
| 32 | 32 bytes | `padding` | Reserved for backward-compatible fields |

Handoff version 1.2 defines `firmware_boot_type` as follows:

| Value | Boot type | Description |
|---:|---|---|
| 0 | Unknown | Source is unavailable |
| 1 | Flash | MCU ROM loaded the firmware from flash |
| 2 | Streaming | Early firmware was streamed through the OCP recovery interface; remainder firmware uses the Runtime streaming loader (typically PLDM) |
| 3 | Network | Firmware was loaded over the network |
| Other | Invalid | Runtime rejects the value |

Runtime uses `HandOff::firmware_boot_type()` so tables from versions before 1.2
and invalid values are reported as unavailable. Userspace applications use
`System::firmware_boot_type()`; the System capsule validates the handoff while
keeping the DCCM region inaccessible to userspace. The Runtime image-loading
task uses this API to select the streaming loader or flash loader. For handoff
versions before 1.2, the task preserves the legacy streaming-boot behavior.

Handoff version 1.3 defines `mcu_rom_capabilities` as follows:

| Bit | Name | Description |
|---:|---|---|
| 0 | `STREAMING_BOOT_I3C` | MCU ROM supports streaming boot over I3C |
| 1 | `FLASH_BOOT` | MCU ROM supports flash boot |
| 2 | `NETWORK_BOOT` | MCU ROM supports network boot |
| 3:31 | Reserved | ROM writes zero; consumers ignore these bits |

The bitmap describes capabilities implemented by the ROM image, independent of
the source selected for the current boot. Runtime reports zero when paired with
a handoff version before 1.3.

Handoff version 1.4 adds `mcu_rom_version`. ROM v2.1.1 reports `0x02010001`:
major occupies bits 31:24, minor bits 23:16, and patch bits 15:0.
`System::mcu_rom_version()` exposes this value through System command 4.
A valid older handoff returns `NoSupport`; an invalid handoff or a reported
zero version returns `Invalid`. Runtime preserves this ROM-owned data across
hitless updates.

The firmware updater uses this field to gate flash image formats. With a valid
legacy handoff that lacks the field, v1 and v2 are allowed, but customers must
select the format their ROM actually supports. New ROM builds report v2.1.1 and
support v3 only; Runtime rejects v1/v2 updates when paired with those ROMs.

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

## Regression Coverage

The `test-handoff` kernel hook checks layout and HEK state. Its exit status must
not be overwritten by `test-exit-immediately`; a negative integration test
supplies the wrong HEK slot and requires a firmware failure.

The emulator's `test-handoff-syscalls` feature enables release logging behavior
even in development bundles, without the address-observing kernel hook. A
userspace test checks the exact boot type, capability bitmap, ROM version, and
programmed HEK state through production syscalls. It is also built into the
release bundle and selected by the `nightly-release` nextest profile. Tests using
a firmware bundle require their feature-specific runtime and OCP LOCK ROM to
be present rather than silently compiling a replacement image.
Source-built syscall tests default to `release`; `MCU_TEST_PROFILE=devel` also
exercises the development layout without restoring address-observing diagnostics.
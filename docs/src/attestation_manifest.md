# Attestation Manifest Format

## Purpose

The Attestation Manifest is an integrator-owned, canonical binary manifest embedded in the authenticated MCU Runtime user app image. It describes platform-specific information and the SoC firmware components that participate in attestation evidence.

The manifest is generated at build time from the ordered SoC image information used to create Auth Manifest metadata, plus an attestation-specific `u32 attestation_flags` field carried next to each integrator SoC image descriptor. `attestation_flags` is distinct from Auth Manifest flags. Auth Manifest metadata remains authorization and loading metadata; it does not define attestation TCB class or attestation key target selection.

At runtime, the MCU Measurement API owns this manifest and uses it as the static attestation configuration for routing component measurements, deriving the attestation target, and assembling evidence.

Measurement initialization computes an attestation manifest digest over the canonical representation. Cold boot stores this digest in the DPE Handle Storage metadata header for later validation.

The Measurement API reads the manifest and uses its platform-specific information (`vendor`, `model`) and configured component `fw_id`s when encoding measurement claims.

All multi-byte scalar fields are little-endian. The digest covers the complete canonical byte string: fixed header, fixed platform-information arrays, and all entries.

## Binary Layout

The manifest has three regions:

1. A fixed 28-byte scalar header prefix.
2. A fixed 200-byte platform-information region containing `vendor[100]` and `model[100]` byte arrays.
3. A variable-size entry array containing `entry_count` entries.

There is no fixed-size entry array and no trailing zero-padded entry region. The total manifest length is exactly:

```text
size = header_size + entry_count * 8
```

Entries begin at byte offset `header_size`.

## Header Fields

The fixed scalar header prefix is 28 bytes. The fixed platform-information arrays immediately follow it, so entries begin at byte offset `228`.

| Offset | Field | Size | Description |
| ---: | --- | ---: | --- |
| 0 | `marker` | 4 bytes | Manifest marker. Value is `0x4d41_434d` (`MCAM` in little-endian bytes), short for MCU Attestation Manifest. |
| 4 | `size` | 4 bytes | Total canonical manifest size in bytes. Must equal `header_size + entry_count * 8`. |
| 8 | `version` | 4 bytes | Manifest format version. Version `1` is the initial supported format. |
| 12 | `header_size` | 4 bytes | Byte offset where entries begin. Must equal `228`. |
| 16 | `entry_count` | 4 bytes | Number of serialized entries. The body is variable-size. |
| 20 | `tcb_entry_count` | 4 bytes | Total number of entries with `SOC_TCB_DPE` set. Used to validate storage capacity and manifest consistency. |
| 24 | `vendor_len` | 2 bytes | Length in bytes of the canonical UTF-8 vendor string. Must be at most `100`. |
| 26 | `model_len` | 2 bytes | Length in bytes of the canonical UTF-8 model string. Must be at most `100`. |

## Platform Information Payload

The platform-information payload starts immediately after the fixed scalar header prefix and has a fixed size of 200 bytes.

| Field | Size | Description |
| --- | ---: | --- |
| `vendor` | 100 bytes | Canonical UTF-8 vendor string stored in the first `vendor_len` bytes. No NUL terminator. Unused bytes must be zero. |
| `model` | 100 bytes | Canonical UTF-8 model string stored in the first `model_len` bytes. No NUL terminator. Unused bytes must be zero. |

The entry array starts at byte offset `header_size`. Because the platform-information arrays are fixed-size and the length fields are packed as two `u16` values, no separate alignment padding is required. The parser rejects invalid UTF-8, vendor/model lengths greater than `100` bytes, non-zero unused platform-information bytes, and mismatches between `header_size` and the fixed entry start offset.

## Entry Format

Entries begin at byte offset `header_size`. Each entry is 8 bytes.

| Offset Within Entry | Field | Size | Description |
| ---: | --- | ---: | --- |
| 0 | `fw_id` | 4 bytes | Firmware ID for a SoC component. The ordered list comes from the integrator SoC image descriptors that also feed Auth Manifest metadata generation. |
| 4 | `attestation_flags` | 4 bytes | Attestation-specific flags for this component. This field is distinct from Auth Manifest flags. |

Each listed entry is part of the static attestation configuration and is measured according to its `attestation_flags`. Entry order follows the SoC manifest, excluding the MCU RT component. Duplicate `fw_id` values are invalid.

## Attestation Flags

`attestation_flags` is a W1 attestation-specific `u32`. It must not be confused with Auth Manifest image metadata flags.

| Bit | Name | Meaning |
| ---: | --- | --- |
| 0 | `SOC_TCB_DPE` | If set, this SoC component is part of the TCB and is measured through the DPE-backed TCB path. If clear, the component is non-TCB and is measured through the software PCR path. |
| 1 | `AK_TARGET` | If set, this entry selects the SoC TCB component that should be used as the attestation key target. The bit may be set on at most one entry and requires `SOC_TCB_DPE` to also be set. |
| 2-31 | Reserved | Must be zero. Runtime rejects manifests with any reserved bit set. |

If no entry sets `AK_TARGET`, Measurement API derives the attestation target as `MCU_RT_FW_ID`. This is the default because Auth Manifest metadata does not identify the AK node.

## Validation

Measurement API validates the manifest before digesting it or exposing values to callers. Validation covers the marker, version, canonical size, header size, platform-information lengths and unused bytes, entry count, duplicate `fw_id` values, supported `attestation_flags`, AK target selection, TCB entry count consistency, and store-layout consistency when preserved measurement state is checked.

Invalid manifests are rejected and must not be used for measurement routing, attestation target derivation, or measurement-claim encoding.

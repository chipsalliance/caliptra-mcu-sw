# Static Integrator Configuration

## Purpose

Static integrator configuration is the integrator-owned build-time configuration that ties together Caliptra Runtime SoC image authorization, MCU-managed image loading, and attestation measurement routing.

The configuration is generated from one integrator SoC image descriptor source. That source feeds:

1. [SoC/Auth Manifest image metadata](https://github.com/chipsalliance/caliptra-sw/blob/main/auth-manifest/README.md#image-metadata-collection) used by Caliptra Runtime for authorization and loading metadata lookup.
2. The Attestation Manifest embedded in the authenticated MCU Runtime user app image.
3. The SoC image load list used by MCU Runtime image loading, boot-initialization validation, and activation.

For MCU-managed SoC firmware images, the `fw_id` field is the join key across these artifacts and must be unique. It also identifies the SoC component whose measurement is reported in attestation claims.

## Configuration artifacts

| Artifact | Where it exists | How it is authenticated/authorized | Purpose |
| --- | --- | --- | --- |
| [SoC/Auth Manifest image metadata](https://github.com/chipsalliance/caliptra-sw/blob/main/auth-manifest/README.md#image-metadata-collection) | Set in Caliptra Runtime. | Authenticated by Caliptra Runtime Auth Manifest verification. | Provides Caliptra Runtime authorization and image metadata for `GET_IMAGE_INFO(fw_id)`, including digest, load/staging addresses, Auth Manifest flags, `component_id`, and activation metadata. |
| Attestation Manifest | Embedded in the MCU Runtime user app image. | Authenticated by Caliptra Runtime as part of MCU Runtime image verification. | Provides the attestation routing policy for each configured SoC firmware ID, including DPE-backed vs Software-PCR-backed measurement handling and optional AK target selection. |
| SoC image load list | Embedded in the MCU Runtime user app image. | Authenticated by Caliptra Runtime as part of MCU Runtime image verification. | Provides the ordered `fw_id` list used by MCU Runtime boot-initialization validation, initial image loading, and activation. |

The Attestation Manifest does not replace the SoC/Auth Manifest. Auth Manifest metadata remains the source for authorization and loading metadata. The Attestation Manifest is the source for attestation measurement routing and AK target policy.

## SoC image load list

The SoC image load list is a generated `fw_id` list embedded in the MCU Runtime user app image. It is generated from the same SoC image descriptor source that generates the SoC/Auth Manifest metadata and Attestation Manifest entries, and is authenticated by Caliptra Runtime as part of MCU Runtime image verification.

At startup, MCU Runtime passes the generated list to Measurement API boot initialization and to the image-loading task. Boot initialization uses the list for configuration consistency checks. Image loading uses the list to drive `GET_IMAGE_INFO(fw_id)`, image load, Measurement API `authorize_and_stash`, and activation.

The generated list contains only firmware IDs:

`SOC_IMAGE_LOAD_LIST` is an array of SoC image descriptor entries. Each entry has the following field:

| Offset Within Entry | Field | Size | Description |
| ---: | --- | ---: | --- |
| 0 | `fw_id` | 4 bytes | Firmware ID for a SoC component. |

MCU Runtime gets the metadata it needs for loading through `GET_IMAGE_INFO(fw_id)`, and Caliptra Runtime uses the Auth Manifest metadata for authorization and activation behavior.

`SOC_IMAGE_LOAD_LIST` order is the MCU-managed initial-load topology authority. For DPE-backed SoC measurements, this order determines the runtime parent/child derivation order. The Attestation Manifest is a keyed policy table; its serialized entry order is not the topology authority and does not need to match `SOC_IMAGE_LOAD_LIST` order.

## Attestation Manifest artifact

The Attestation Manifest is an integrator-owned canonical binary manifest embedded in the authenticated MCU Runtime user app image. It describes platform-specific information and the SoC firmware components that participate in attestation evidence.

At runtime, the MCU Measurement API owns this manifest and uses it for routing component measurements, deriving the attestation target, and assembling evidence.

Measurement initialization computes a policy/topology digest over the canonical Attestation Manifest representation and the ordered `SOC_IMAGE_LOAD_LIST`. Cold boot stores this digest in preserved measurement metadata for later validation:

```text
measurement_policy_digest = SHA384(
    canonical_attestation_manifest_bytes ||
    canonical_ordered_soc_image_load_list_bytes
)
```

Hitless update recomputes this digest and rejects preserved measurement state if it differs.

The Measurement API reads the manifest and uses its platform-specific information (`vendor`, `model`) and configured component `fw_id`s when encoding measurement claims.

All multi-byte scalar fields are little-endian. The digest covers the complete canonical byte string: fixed header, fixed platform-information arrays, and all entries.

## Attestation Manifest binary layout

The manifest has three regions:

1. A fixed 28-byte scalar header prefix.
2. A fixed 200-byte platform-information region containing `vendor[100]` and `model[100]` byte arrays.
3. A variable-size entry array containing `entry_count` entries.

There is no fixed-size entry array and no trailing zero-padded entry region. The total manifest length is exactly:

```text
size = header_size + entry_count * 8
```

Entries begin at byte offset `header_size`.

## Header fields

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

## Platform information payload

The platform-information payload starts immediately after the fixed scalar header prefix and has a fixed size of 200 bytes.

| Field | Size | Description |
| --- | ---: | --- |
| `vendor` | 100 bytes | Canonical UTF-8 vendor string stored in the first `vendor_len` bytes. No NUL terminator. Unused bytes must be zero. |
| `model` | 100 bytes | Canonical UTF-8 model string stored in the first `model_len` bytes. No NUL terminator. Unused bytes must be zero. |

The entry array starts at byte offset `header_size`. Because the platform-information arrays are fixed-size and the length fields are packed as two `u16` values, no separate alignment padding is required. The parser rejects invalid UTF-8, vendor/model lengths greater than `100` bytes, non-zero unused platform-information bytes, and mismatches between `header_size` and the fixed entry start offset.

## Entry format

Entries begin at byte offset `header_size`. Each entry is 8 bytes.

| Offset Within Entry | Field | Size | Description |
| ---: | --- | ---: | --- |
| 0 | `fw_id` | 4 bytes | Firmware ID for a configured SoC component. For MCU-managed SoC firmware image entries, this `fw_id` must be present in `SOC_IMAGE_LOAD_LIST`. |
| 4 | `attestation_flags` | 4 bytes | Attestation-specific flags for this component. This field is distinct from Auth Manifest flags. |

Each listed entry is part of the static attestation configuration and is measured according to its `attestation_flags`. Duplicate `fw_id` values are invalid. Entry order is not the MCU-managed initial-load topology; `SOC_IMAGE_LOAD_LIST` defines that topology.

## Attestation flags

`attestation_flags` is a W1 attestation-specific `u32`. It must not be confused with Auth Manifest image metadata flags.

| Bit | Name | Meaning |
| ---: | --- | --- |
| 0 | `SOC_TCB_DPE` | If set, this SoC component is measured through the DPE-backed TCB path. If clear, the component is measured through the Software PCR path. |
| 1 | `AK_TARGET` | If set, this entry selects the SoC component that should be used as the attestation key target. The bit may be set on at most one entry and requires `SOC_TCB_DPE` to also be set. |
| 2-31 | Reserved | Must be zero. Runtime rejects manifests with any reserved bit set. |

If no entry sets `AK_TARGET`, Measurement API derives the attestation target as `MCU_RT_FW_ID`. This is the default because Auth Manifest metadata does not identify the AK node.

## Validation

Measurement API validates the manifest before digesting it or exposing values to callers. Validation covers the marker, version, canonical size, header size, platform-information lengths and unused bytes, entry count, duplicate `fw_id` values, supported `attestation_flags`, AK target selection, TCB entry count consistency, store-layout consistency when preserved measurement state is checked, and consistency with `SOC_IMAGE_LOAD_LIST` for MCU-managed SoC firmware image entries.

Invalid manifests are rejected and must not be used for measurement routing, attestation target derivation, or measurement-claim encoding.

## Consistency rules

The generated configuration must satisfy these rules:

1. SoC/Auth Manifest image metadata has unique `fw_id` values.
2. Attestation Manifest entries have unique `fw_id` values.
3. Generated `SOC_IMAGE_LOAD_LIST` entries are unique `fw_id` values.
4. Every MCU-managed SoC firmware image `fw_id` in `SOC_IMAGE_LOAD_LIST` must have a corresponding SoC/Auth Manifest image metadata entry and Attestation Manifest entry.
5. The Attestation Manifest may contain entries that are not loaded through `SOC_IMAGE_LOAD_LIST`, such as hardware or configuration measurements.
6. The SoC/Auth Manifest, Attestation Manifest, and `SOC_IMAGE_LOAD_LIST` do not need the same order.

On cold boot, MCU Runtime validates that every `fw_id` in `SOC_IMAGE_LOAD_LIST` has corresponding SoC/Auth Manifest image metadata and Attestation Manifest entries before initial-load measurements are recorded. Unknown, missing, or duplicate `fw_id` values in the MCU-managed image-load configuration are rejected.

On MCU hitless update, preserved measurement state can only be reused if both the Attestation Manifest canonical bytes and the ordered `SOC_IMAGE_LOAD_LIST` are unchanged. Any change to either configuration requires cold boot because preserved DPE Handle Storage and Software PCR Storage are interpreted under the previous policy and topology.

Firmware update must also validate the new SoC/Auth Manifest before it is made active. After `VERIFY_AUTH_MANIFEST` succeeds and before `SET_AUTH_MANIFEST` / Apply / Activation, MCU Runtime verifies that the new SoC/Auth Manifest image metadata contains the same MCU-managed image-load `fw_id` set initialized at cold boot:

```text
set(new MCU-managed SoC/Auth Manifest image_metadata.fw_id) == set(cold_boot SOC_IMAGE_LOAD_LIST.fw_id)
```

This check protects hitless-update measurement state. The active SoC/Auth Manifest must not add a new SoC component after cold boot and must not remove a component that was initialized at cold boot. A partial update may update only a subset of component payloads, but the manifest that becomes active must still describe the full cold-boot SoC component set.

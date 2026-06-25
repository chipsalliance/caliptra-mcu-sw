# Measurement API

This document describes the MCU Runtime measurement API used to collect, store, and report attestation measurement state.

The measurement API provides a single userspace interface for image loading, firmware update, and OCP EAT Evidence generation. Callers do not need to know whether a component's claims are represented by Caliptra DPE state or by the Software PCR Storage capsule.

![Measurement API surface](images/attestation_measurement_api.svg)

## API entry points

| Interface | Caller | Purpose |
| --- | --- | --- |
| `measurement_boot_init(boot_context)` | Main user-app startup | Initializes measurement state after reset. Cold boot clears stale state and creates the MCU Runtime root DPE record. MCU hitless update preserves state and validates it against the authenticated attestation policy. |
| `authorize_and_stash(fw_id, image_metadata)` | Image loading and firmware update | Authorizes a component, enforces anti-rollback policy, and stores its measurement through either the DPE Handle Storage capsule or the Software PCR Storage capsule. `image_metadata` includes the component metadata fields derived from `GET_IMAGE_INFO(fw_id)` and the current load/update operation. |
| `encode_measurement_evidence(buffer)` | OCP EAT encoder | Iterates the configured component list and writes the CBOR-encoded concise evidence triple array into a caller-provided buffer. Returns the encoded length or a required-size error. The caller owns the outer OCP EAT and COSE structures. |
| `read_measurement(fw_id)` | Tests / diagnostics / internal helper | Returns the component measurement claims for a configured `fw_id`, using DPE tagged-TCI for SoC TCB components or the Software PCR Storage capsule for SoC non-TCB components. |
| `read_attestation_target_handle()` | OCP EAT / COSE signing path | Returns the current DPE context handle for the configured attestation target. |

Only the measurement API layer owns mutation of DPE Handle Storage capsule and Software PCR Storage capsule state. Image loading, firmware update, OCP EAT generation, and SPDM responders must not write those stores directly.

The Tock capsule syscall drivers and reserved SRAM layout used by these APIs are described in [Tock Capsules](./attestation-tock-capsules.md).

## Data interfaces

The Measurement API uses three inputs: integrator configuration for component classification and target selection, SoC component image metadata for authorization/loading, and caller-provided image metadata for initial image load or component update.

### Firmware identifier source

`GET_IMAGE_INFO(fw_id)` is a lookup by firmware identifier; it does not enumerate which images should be loaded.

The caller gets `fw_id` from the flow it owns:

| Caller | `fw_id` source |
| --- | --- |
| Image loader | Integrator/platform image load list for boot-time SoC images. The image loader uses this `fw_id` to call `GET_IMAGE_INFO(fw_id)` before loading the image. |
| Firmware update | Update package metadata or update flow state for the component being updated. The update flow uses this `fw_id` to call `GET_IMAGE_INFO(fw_id)` before authorizing the update. |
| OCP EAT encoder | Does not need to know the `fw_id` list. It asks the Measurement API to encode configured measurement claims into the EAT payload buffer. SPDM is one transport path that can carry the resulting Evidence. |

The `fw_id` values used by these flows must match the integrator static attestation configuration and the SoC component image metadata returned by `GET_IMAGE_INFO(fw_id)`. A configured component is a component whose `fw_id` is explicitly listed in the integrator static attestation configuration. The Measurement API must fail unknown or unsupported `fw_id` values explicitly.

### Integrator static attestation configuration

This is static configuration provided by the integrator in the MCU Runtime image. The Measurement API uses it to decide whether each listed `fw_id` is recorded through the DPE Handle Storage capsule or the Software PCR Storage capsule, whether the component is reported as OCP EAT inventory evidence, and which DPE-backed component is the attestation target.

| Field | Description |
| --- | --- |
| `fw_id` | Component firmware identifier used as the lookup key. |
| `measurement_class` | Routes the component as `SoC TCB` or `SoC non-TCB`. |
| `attestation_target` | Marks the SoC TCB component whose DPE record becomes the attestation target. |
| `inventory_evidence` | Marks whether the component is emitted as OCP EAT inventory evidence. |

The `measurement_class`, `attestation_target`, and `inventory_evidence` decisions come from this configuration. They are not supplied by callers and are not derived from `GET_IMAGE_INFO(fw_id)`.

`measurement_boot_init()` computes `attestation_policy_digest` over a canonical representation of this policy. Cold boot stores the digest in the DPE Handle Storage metadata header. On hitless update, the Measurement API recomputes the digest from the authenticated MCU Runtime image and compares it with the stored value before using preserved DPE/PCR state. A mismatch puts MCU Runtime in an attestation error state: normal attestation Evidence and component measurement-state updates are disabled until cold boot reinitializes measurement state.

### SoC component image metadata

`GET_IMAGE_INFO(fw_id)` remains the source for SoC component image metadata used by authorization and loading. Existing fields such as component ID, digest, load address, staging address, and related authorization metadata are used by the image loading and authorization paths.

`GET_IMAGE_INFO(fw_id)` is not used to classify components or select the attestation target.

The Measurement API does not need to issue `GET_IMAGE_INFO(fw_id)` again in the normal authorize/stash path. The image loader or firmware update flow already needs that response to locate and load the image, so it passes the required component metadata fields into `authorize_and_stash()`.

### Caller-provided operation metadata

`authorize_and_stash()` receives image metadata from image loading for `InitialLoad` or from firmware update for `ComponentUpdate`:

| Field | Description |
| --- | --- |
| `operation` | `InitialLoad` for boot-time image loading or `ComponentUpdate` for firmware update. |
| `image_info` | Component metadata fields derived from the `GET_IMAGE_INFO(fw_id)` response fetched by image loading or firmware update. |
| `source` | Image source, such as load address, staging address, or digest-in-request. |
| `image_size` | Image size when the source is an address. |
| `measurement` | Component measurement digest. |
| `journey_digest` | Journey or integrity-register digest. |
| `svn` | Component SVN used for rollback checks and claims. |
| `version` | Component version used for claims, encoded as `u32`. |
| `flags` | Caller flags, such as skip-stash behavior. |

### DPE tagging

For SoC TCB components, DPE `tci_type` is the component `fw_id`. The Measurement API also tags each newly created SoC TCB DPE context with `DPE_TAG_TCI(handle=<context_handle>, tag=fw_id)`.

The tag gives the read path a stable way to retrieve TCI values for that component later. DPE context handles can rotate after derive/update operations, but the tag remains associated with the DPE context. When inventory Evidence is generated, the Measurement API can call `DPE_GET_TAGGED_TCI(tag=fw_id)` to read the tagged context's current and cumulative TCI values without requiring the caller to know the current DPE handle.

## Boot initialization

On cold boot, persistent DPE/PCR state is treated as stale. `measurement_boot_init()` computes `attestation_policy_digest`, initializes DPE Handle Storage with that digest, initializes Software PCR Storage, rotates the default DPE handle, tags the MCU Runtime context, and writes the MCU Runtime root DPE record.

```mermaid
sequenceDiagram
    participant UserMain as "user app main task"
    participant MApi as "Measurement API"
    box rgb(239, 248, 255) Tock syscall capsules
        participant Mci as "MCI"
        participant Mailbox as "Mailbox<br/>to Caliptra Core/DPE"
        participant DpeStore as "DPE Handle Storage"
        participant PcrStore as "Software PCR Storage"
    end

    Note over UserMain: Started after Caliptra Core loads and verifies MCU RT
    UserMain->>Mci: Read RESET_REASON
    Mci-->>UserMain: reset_reason
    UserMain->>UserMain: Classify ColdBoot or FW_HITLESS_UPD_RESET
    UserMain->>MApi: measurement_boot_init(boot_context)
    MApi->>MApi: Compute attestation_policy_digest
    MApi->>DpeStore: INITIALIZE_STORE(attestation_policy_digest)
    MApi->>PcrStore: INITIALIZE_STORE
    MApi->>Mailbox: RotateContext(DEFAULT_HANDLE)
    Mailbox-->>MApi: rotated_mcu_context_handle
    MApi->>Mailbox: DPE_TAG_TCI(handle=rotated_mcu_context_handle, tag=MCU_RT_FW_ID)
    MApi->>DpeStore: WRITE_RECORD(MCU_RT_FW_ID, rotated_mcu_context_handle)
```

The MCU Runtime root DPE record contains:

| Field | Value |
| --- | --- |
| `fw_id` | `MCU_RT_FW_ID` |
| `parent_fw_id` | `None` |
| `context_handle` | Rotated MCU Runtime DPE context handle |
| `tci_tag` | `MCU_RT_FW_ID` |
| `attestation_target` | `true` by default |

On `FW_HITLESS_UPD_RESET`, the reserved SRAM backing the stores must not be reset or reinitialized. `measurement_boot_init()` recomputes `attestation_policy_digest`, calls DPE Handle Storage `VALIDATE_STORE(attestation_policy_digest)`, and calls Software PCR Storage `VALIDATE_STORE` before using preserved state. It then validates preserved records against the static attestation policy instead of clearing them. If the policy digest mismatches, the MCU Runtime DPE record is missing, the active DPE leaf is missing, or Software PCR Storage validation fails, the flow must enter the attestation error state rather than silently creating a new lineage.

## Initial image loading

For each SoC component, image loading calls `authorize_and_stash(fw_id, image_metadata)` with `operation=InitialLoad`.

```mermaid
sequenceDiagram
    participant Loader as "image_loading_task"
    participant MApi as "Measurement API"
    box rgb(239, 248, 255) Tock syscall capsules
        participant Mailbox as "Mailbox<br/>to Caliptra Core/DPE"
        participant DpeStore as "DPE Handle Storage"
        participant PcrStore as "Software PCR Storage"
    end

    Loader->>Mailbox: GET_IMAGE_INFO(fw_id)
    Mailbox-->>Loader: image_info(digest, load/staging address)
    Loader->>Loader: Load image using image_info
    Loader->>Loader: Extract component metadata fields
    Loader->>MApi: authorize_and_stash(fw_id, image_metadata)
    MApi->>MApi: Lookup integrator attestation config(fw_id)
    MApi->>MApi: verify_component_svn(fw_id, svn, image_metadata)
    MApi->>Mailbox: Authorize component
    Mailbox-->>MApi: Authorization result

    alt SoC TCB component
        MApi->>DpeStore: READ_LEAF_RECORD
        DpeStore-->>MApi: parent DPE record
        MApi->>Mailbox: DeriveContext(parent_handle, tci_type=fw_id, measurement, RETAIN_PARENT_CONTEXT)
        Mailbox-->>MApi: child_handle, rotated_parent_handle
        MApi->>Mailbox: DPE_TAG_TCI(handle=child_handle, tag=fw_id)
        MApi->>DpeStore: WRITE_RECORD(parent_fw_id, rotated_parent_handle)
        MApi->>DpeStore: WRITE_RECORD(fw_id, child_handle)
    else SoC non-TCB component
        MApi->>PcrStore: CREATE_MEASUREMENT(fw_id, measurement_update)
    end

    MApi-->>Loader: Authorization/stash status
```

For a SoC TCB component, the previous active leaf is used as the parent. The parent record is updated with the rotated parent handle returned by `DeriveContext`, and the child record is appended with the child handle. The active DPE leaf is the last valid DPE record in load order.

For a SoC non-TCB component, the measurement API creates a Software PCR record and leaves the DPE record log unchanged. If the record already exists during initial load, the API fails rather than overwriting it.

## SoC component update

For component update, firmware update calls `authorize_and_stash(fw_id, image_metadata)` with `operation=ComponentUpdate`.

```mermaid
sequenceDiagram
    participant FwUpdate as "firmware_update"
    participant MApi as "Measurement API"
    box rgb(239, 248, 255) Tock syscall capsules
        participant Mailbox as "Mailbox<br/>to Caliptra Core/DPE"
        participant DpeStore as "DPE Handle Storage"
        participant PcrStore as "Software PCR Storage"
    end

    FwUpdate->>Mailbox: GET_IMAGE_INFO(fw_id)
    Mailbox-->>FwUpdate: image_info(digest, staging address)
    FwUpdate->>FwUpdate: Extract component metadata fields
    FwUpdate->>MApi: authorize_and_stash(fw_id, image_metadata)
    MApi->>MApi: Lookup integrator attestation config(fw_id)
    MApi->>MApi: verify_component_svn(fw_id, svn, image_metadata)
    MApi->>Mailbox: Authorize updated image
    Mailbox-->>MApi: Authorization result

    alt SoC TCB component
        MApi->>DpeStore: READ_RECORD(fw_id)
        DpeStore-->>MApi: component DPE record
        MApi->>DpeStore: READ_RECORD(parent_fw_id)
        DpeStore-->>MApi: parent DPE record
        MApi->>Mailbox: UpdateContextMeasurement(parent_handle, tci_type=fw_id, measurement)
        Mailbox-->>MApi: new_context_handle, new_parent_context_handle
        MApi->>DpeStore: WRITE_RECORD(parent_fw_id, new_parent_context_handle)
        MApi->>DpeStore: WRITE_RECORD(fw_id, new_context_handle)
    else SoC non-TCB component
        MApi->>PcrStore: UPDATE_MEASUREMENT(fw_id, measurement_update)
    end
```

Component updates do not re-tag DPE contexts. The existing `fw_id` tag remains associated with the DPE context across handle rotations.

## Measurement evidence encoding path

For inventory Evidence generation, the OCP EAT encoder provides a buffer and calls `encode_measurement_evidence(buffer)`. The Measurement API writes the CBOR-encoded concise evidence triple array into that buffer and returns the encoded length.

| Layer | Responsibility |
| --- | --- |
| Measurement API | Encodes the concise evidence triple array for configured SoC measurements. |
| OCP EAT encoder | Embeds the encoded concise evidence into the OCP EAT claims payload and owns EAT-level fields such as nonce, issuer, profile, debug status, and `cti`. |
| COSE signing path | Wraps the OCP EAT payload in `COSE_Sign1` and asks Caliptra Core to sign the corresponding bytes using the configured AK. |

The API must fail cleanly on insufficient buffer space, unknown configuration, or missing measurement state. It must not emit truncated Evidence or silently substitute zero digests.

```mermaid
sequenceDiagram
    participant Transport as "Evidence transport"
    participant Encoder as "OCP EAT encoder"
    participant MApi as "Measurement API"
    box rgb(239, 248, 255) Tock syscall capsules
        participant Mailbox as "Mailbox<br/>to Caliptra Core/DPE"
        participant PcrStore as "Software PCR Storage"
    end

    Transport->>Encoder: Build inventory Evidence
    Encoder->>Encoder: Provide concise evidence buffer
    Encoder->>MApi: encode_measurement_evidence(buffer)

    loop For each configured component
        MApi->>MApi: Read config entry (fw_id, measurement_class)

        alt SoC TCB
            MApi->>Mailbox: DPE_GET_TAGGED_TCI(tag=fw_id)
            Mailbox-->>MApi: tci_current, tci_cumulative
            MApi->>MApi: Encode TCB evidence triple into buffer
        else SoC non-TCB
            MApi->>PcrStore: READ_MEASUREMENT(fw_id)
            PcrStore-->>MApi: measurement_record
            MApi->>MApi: Encode non-TCB evidence triple into buffer
        else unsupported measurement_class
            MApi-->>Encoder: Error
        end
    end

    MApi-->>Encoder: Encoded concise evidence length
    Encoder->>Encoder: Embed concise evidence in OCP EAT payload
    Encoder-->>Transport: Encoded OCP EAT payload
```

## SoC component anti-rollback enforcement

SoC component images must be validated for rollback protection before measurements are stored.

During `authorize_and_stash()`, MCU Runtime reads or receives the component's current SVN for `fw_id`, compares it against the fuse-backed or platform-policy minimum SVN, and rejects the component if `current_svn < min_svn`.

The measurement API updates the DPE Handle Storage capsule or Software PCR Storage capsule only after anti-rollback validation succeeds.

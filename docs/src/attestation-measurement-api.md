# Measurement API

The `MCU Runtime` Measurement API (`caliptra-mcu-measurement-api`) provides the internal userspace interface for recording SoC measurements, managing attestation keys, and generating signed Evidence according to the [attestation configuration](./attestation_configuration.md).

It abstracts DPE context rotation and [Tock capsule storage](./attestation-tock-capsules.md) behind a single library-owned state instance so that image loading, firmware update, SPDM, and Evidence providers do not manipulate Caliptra DPE handles or Software PCR records directly. External requester transport paths (SPDM over MCTP/DOE and MCU mailbox `GET_ATTESTATION`) are described in [Attestation](./attestation.md) and [Common Caliptra Commands](./caliptra_common_commands.md).

![Measurement API surface](images/attestation_measurement_api.svg)

## API entry points

The API surface is grouped by consumer:

| Consumer | Interface | Purpose |
| --- | --- | --- |
| **User app startup / Boot init** | `init()` | Initializes the library-owned Measurement API instance from the base policy. Cold boot initializes stores and the MCU Runtime root record; hitless update validates preserved state. |
| **User app startup / Boot init** | `policy_contains_component()` | Tests membership in the base policy or an attached owner policy. |
| **User app startup / Boot init** | `measure_vendor_auth_key()` | Creates or synchronizes the Vendor Authorization Key control measurement. |
| **User app startup / Boot init** | `disable_attestation()` | Transitions the API to `Error` on boot or image-loading failure, blocking normal measurement and Evidence operations. |
| **OCP EAT provider** | `measure_and_sign_evidence()` | Serializes selected-AK identification, concise-evidence encoding, payload construction, and signing under one Measurement API lock. |
| **SPDM cert store / Responder** | `leaf_cert_size()` | Returns the DPE leaf certificate size and persists the rotated target handle. |
| **SPDM cert store / Responder** | `leaf_cert_slice()` | Returns one DPE leaf certificate slice and persists the rotated target handle. |
| **SPDM cert store / Responder** | `sign()` | Signs a typed input with the selected AK, persists its rotated handle, and returns the signature length. |
| **Exported-CDI consumers (e.g., OCP LOCK)** | `export_cdi_and_stash()` | Derives an exported CDI, stores its handle, persists the rotated target handle, and returns the certificate length. |
| **Exported-CDI consumers (e.g., OCP LOCK)** | `read_exported_cdi()` | Reads the stored handle; rejects an all-zero, not-yet-derived handle. |
| **Image loading / Firmware update** | `validate_and_set_owner_policy()` | Parses and attaches already-authenticated `MOAM`/`MOLL` bytes without resetting base state. |
| **Image loading / Firmware update** | `measure_owsm()` | Creates or synchronizes the MCU-managed Owner Authorization Manifest preamble measurement. |
| **Image loading / Firmware update** | `measure_owner_measurement_policy()` | Creates the owner-policy measurement on cold boot; verifies it is unchanged on hitless update. |
| **Image loading / Firmware update** | `measure_owner_auth_key()` | Creates or synchronizes the Owner Authorization Key control measurement. |
| **Image loading / Firmware update** | `authorize_and_stash()` | Requests Caliptra authorization, then records the accepted component measurement through DPE or Software PCR Storage. |
| **Image loading / Firmware update** | `mark_initial_soc_load_complete()` | Validates records for the configured load list and transitions to `Active`. |

The Tock capsule syscall drivers and reserved SRAM layout used by these APIs are described in [Tock Capsules](./attestation-tock-capsules.md).

## Data interfaces

Callers retrieve authorization metadata (`GET_IMAGE_INFO(fw_id)`) for each `fw_id` in the configured load list (`SOC_IMAGE_LOAD_LIST` or `MOLL`) or firmware-update package, load or stage the image, and pass the resulting metadata (`InitialLoad` or `ComponentUpdate`) into `authorize_and_stash()`. The Measurement API supplies `SKIP_STASH` so Caliptra Core authorizes the image without independently stashing the MCU-managed measurement, then routes the measurement to DPE or Software PCR Storage according to the [attestation configuration](./attestation_configuration.md).

### DPE tagging

For SoC TCB components, DPE `tci_type` is the component `fw_id`. The Measurement API also tags each newly created SoC TCB DPE context with `DPE_TAG_TCI(handle=<context_handle>, tag=fw_id)`. Because the tag stays with the context across handle rotations, inventory Evidence generation can read the context's current and cumulative TCI values via `DPE_GET_TAGGED_TCI(tag=fw_id)` without tracking the current handle.

## Boot initialization

On cold boot, persistent DPE and Software PCR state is treated as stale. `init()` validates the base load list against `MCAM`, computes the base-policy digest, initializes both stores, rotates and tags the MCU Runtime DPE context (`MCU_RT_FW_ID`), writes its root record, and marks it as the initial AK target.

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
    UserMain->>UserMain: Classify BootKind::ColdBoot or BootKind::HitlessUpdate
    UserMain->>MApi: init(manifest_bytes, soc_image_load_fw_ids, boot_kind, readiness_policy, alloc)
    MApi->>MApi: measurement_policy_digest()
    alt BootKind::ColdBoot
        MApi->>DpeStore: INITIALIZE_STORE(base_policy_digest)
        MApi->>PcrStore: INITIALIZE_STORE
        MApi->>Mailbox: RotateContext(DEFAULT_HANDLE)
        Mailbox-->>MApi: rotated_mcu_context_handle
        MApi->>Mailbox: DPE_TAG_TCI(handle=rotated_mcu_context_handle, tag=MCU_RT_FW_ID)
        MApi->>DpeStore: WRITE_RECORD(MCU_RT_FW_ID, rotated_mcu_context_handle)
        MApi->>DpeStore: MARK_ATTESTATION_TARGET(MCU_RT_FW_ID)
    else BootKind::HitlessUpdate
        MApi->>DpeStore: VALIDATE_STORE(base_policy_digest)
        MApi->>PcrStore: VALIDATE_STORE
        MApi->>DpeStore: READ_RECORD(MCU_RT_FW_ID)
        MApi->>DpeStore: READ_LEAF_RECORD
        opt Configured AK target in manifest
            MApi->>DpeStore: READ_ATTESTATION_TARGET
        end
        MApi->>MApi: Validate root and configured AK target
    end
```

On `FW_HITLESS_UPD_RESET`, the stores are not reset or reinitialized. Boot initialization recomputes the base-policy digest, validates both store headers, and checks the preserved MCU Runtime root, readable active leaf, and attestation target against the unchanged cold-boot policy. Failure transitions the API to `Error` rather than recreating state. Owner-policy validation occurs later during image loading.

### Readiness and failure gating

| State | Measurement operations | Evidence and AK operations |
| --- | --- | --- |
| `Uninitialized` | Blocked | Blocked |
| `InitialMeasurementsPending` | Initial-load and component-update operations allowed | Blocked |
| `Active` | Allowed | Allowed |
| `Error` | Blocked | Blocked |

`ReadyAfterBootInit` enters `Active` immediately after `init()`; `RequireInitialSocLoadComplete` stays in `InitialMeasurementsPending` until `mark_initial_soc_load_complete()` succeeds. Any initialization, loading, or measurement failure calls `disable_attestation()` to enter `Error` so incomplete measurement state is never reported.

## Owner artifacts and control measurements

The image loader handles flash/PLDM retrieval and `SET_OWNER_AUTH_MANIFEST` installation; the Measurement API manages the resulting measurement state:

1. Boot initialization measures the Vendor Authorization Key (`0x4`) when configured in `MCAM`.
2. The loader installs the Owner Authorization Manifest via `SET_OWNER_AUTH_MANIFEST`, authenticates the Owner Measurement Policy (`0x5`) against `GET_IMAGE_INFO(0x5).digest`, and attaches it with `validate_and_set_owner_policy()`.
3. The loader records the control chain in order via `measure_owsm()`, `measure_owner_measurement_policy()`, and `measure_owner_auth_key()`:

```text
MCU_RT (0x2) -> Vendor Auth Key (0x4) -> OWSM (0x3)
            -> Owner Measurement Policy (0x5) -> Owner Auth Key (0x6)
```

On hitless update, `measure_owner_measurement_policy()` runs **before** updating `OWSM` or the Owner Authorization Key and verifies that the policy digest matches the preserved DPE measurement:

| Measurement | Hitless behavior |
| --- | --- |
| Owner Measurement Policy | `VerifyUnchanged`: matching digest preserves state without another PCR31 extension; a mismatch rejects the flow. |
| Vendor key, `OWSM`, owner key | `UpdateIfChanged`: matching digest preserves state; a changed accepted digest updates the existing context and extends PCR31 once. |
| Firmware component update | `AlwaysRecord`: records the accepted update, including when its digest matches the previous value. |

## Attestation key operations

Callers do not invoke DPE `CertifyKeyChunks`, `CertifyKey`, `Sign`, or `ExportCdi` directly on Measurement API-managed contexts. Each AK or Exported-CDI entry point reads the current attestation target record, issues one DPE command, and writes the rotated context handle back to DPE Handle Storage before returning (`GetCertificateChain` does not take or rotate a DPE context handle). If the DPE command succeeds but persisting the rotated handle fails, the API enters `Error` to prevent reuse of a stale handle.

## Initial image loading

For each `fw_id` in the configured load list (`SOC_IMAGE_LOAD_LIST` and, when present, `MOLL`), image loading calls `authorize_and_stash()` with `operation=InitialLoad`.

```mermaid
sequenceDiagram
    participant Loader as "image_loading_task"
    participant MApi as "Measurement API"
    box rgb(239, 248, 255) Tock syscall capsules
        participant Mailbox as "Mailbox<br/>to Caliptra Core/DPE"
        participant DpeStore as "DPE Handle Storage"
        participant PcrStore as "Software PCR Storage"
    end

    loop For each fw_id in configured load list
        Loader->>Mailbox: GET_IMAGE_INFO(fw_id)
        Mailbox-->>Loader: image_info(digest, load/staging address)
        Loader->>Loader: Load image using image_info
        Loader->>Loader: Extract component metadata fields
        Loader->>MApi: authorize_and_stash(alloc, fw_id, image_metadata)
        MApi->>MApi: Lookup base or attached owner policy(fw_id)
        MApi->>Mailbox: AUTHORIZE_AND_STASH(SKIP_STASH=true)
        Mailbox-->>MApi: Authorization result

        alt SoC TCB component
            MApi->>DpeStore: READ_LEAF_RECORD
            DpeStore-->>MApi: parent DPE record
            MApi->>Mailbox: DeriveContext(parent_handle, tci_type=fw_id, measurement, RETAIN_PARENT_CONTEXT)
            Mailbox-->>MApi: child_handle, rotated_parent_handle
            MApi->>DpeStore: WRITE_RECORD(parent_fw_id, rotated_parent_handle)
            MApi->>DpeStore: WRITE_RECORD(fw_id, child_handle)
            MApi->>Mailbox: DPE_TAG_TCI(handle=child_handle, tag=fw_id)
            opt configured base AK target
                MApi->>DpeStore: MARK_ATTESTATION_TARGET(fw_id)
            end
        else SoC non-TCB component
            MApi->>PcrStore: CREATE_MEASUREMENT(fw_id, measurement_update)
        end
        MApi->>Mailbox: EXTEND_PCR(PCR31, measurement)
        MApi-->>Loader: Authorization/stash status
    end
```

SoC TCB derivations use the active leaf as the parent, update the parent handle, append and tag the child record, and mark the attestation target when configured. SoC non-TCB components create a Software PCR record (failing if one already exists during initial load). PCR31 is extended after authorization and store updates succeed; any post-command persistence failure transitions the API to `Error`.

## SoC component update

For runtime firmware updates, the update flow calls `authorize_and_stash()` with `operation=ComponentUpdate`.

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
    FwUpdate->>MApi: authorize_and_stash(alloc, fw_id, image_metadata)
    MApi->>MApi: Lookup base or attached owner policy(fw_id)
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
        MApi->>PcrStore: READ_MEASUREMENT(fw_id)
        MApi->>MApi: Compute current and extended journey values
        MApi->>PcrStore: UPDATE_MEASUREMENT(fw_id, measurement_update)
    end
    MApi->>Mailbox: EXTEND_PCR(PCR31, measurement)
```

Component updates do not re-tag DPE contexts; the existing `fw_id` tag stays with the context across handle rotations.

## Measurement evidence encoding path

For signed inventory Evidence, the OCP EAT provider calls `measure_and_sign_evidence()` with an `EvidenceBuilder`. The Measurement API holds its mutex across selected-AK identification, concise-evidence encoding (excluding TCB components on the selected-AK lineage), payload construction, and signing so concurrent component updates cannot interleave between reading measurements and signing. If encoding fails, callers must discard the output buffer rather than returning partial Evidence.

```mermaid
sequenceDiagram
    participant Transport as "Evidence transport"
    participant Encoder as "OCP EAT encoder"
    participant MApi as "Measurement API"
    box rgb(239, 248, 255) Tock syscall capsules
        participant Mailbox as "Mailbox<br/>to Caliptra Core/DPE"
        participant DpeStore as "DPE Handle Storage"
        participant PcrStore as "Software PCR Storage"
    end

    Transport->>Encoder: Build inventory Evidence
    Encoder->>MApi: measure_and_sign_evidence(alloc, key_label, slot, builder)
    Note over MApi: Hold Measurement API mutex through final signing
    MApi->>Mailbox: Get selected-AK public data
    Mailbox-->>MApi: Public data and rotated target handle
    MApi->>DpeStore: Persist rotated target handle

    loop For each eligible configured entry
        MApi->>MApi: Read policy and apply selected-AK lineage filtering

        alt SoC TCB
            MApi->>Mailbox: DPE_GET_TAGGED_TCI(tag=fw_id)
            Mailbox-->>MApi: tci_current, tci_cumulative
            MApi->>MApi: Encode TCB evidence triple into buffer
        else SoC non-TCB
            MApi->>PcrStore: READ_MEASUREMENT(fw_id)
            PcrStore-->>MApi: measurement_record
            MApi->>MApi: Encode non-TCB evidence triple into buffer
        end
    end

    MApi->>Encoder: Prepare payload and typed signing input
    Encoder-->>MApi: ECC digest or ML-DSA mu
    MApi->>Mailbox: Sign using selected AK
    Mailbox-->>MApi: Signature and rotated target handle
    MApi->>DpeStore: Persist rotated target handle
    MApi-->>Encoder: Complete signed Evidence length
    Encoder-->>Transport: Signed OCP EAT
```

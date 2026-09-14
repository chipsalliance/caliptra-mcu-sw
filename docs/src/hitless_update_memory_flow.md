# Hitless Update Memory Flow

This document describes how the firmware update `StagingMemory`, the Caliptra
External Staging Area, and the Caliptra mailbox participate in a hitless update.
It focuses on the `FIRMWARE_LOAD`, `SET_AUTH_MANIFEST`, and
`ACTIVATE_FIRMWARE` commands.

## Memory Roles

| Memory | Purpose | Access requirements |
| --- | --- | --- |
| Firmware update `StagingMemory` | Platform-defined storage that receives the complete PLDM package. It may be RAM, flash, or another storage device. | MCU runtime must be able to read and write it. It does not have to be directly accessible to Caliptra DMA. |
| External Staging Area | DMA-accessible memory used for oversized Caliptra mailbox requests and for images that Caliptra processes through DMA. | MCU and Caliptra must be able to address it. The integrator must prevent other agents from reading or modifying data while Caliptra is processing it. |
| Caliptra mailbox SRAM | Carries commands, small request payloads, responses, and the wrapper for oversized requests. | Access is controlled by the Caliptra mailbox protocol. The subsystem mailbox size is 16 KiB. |
| MCU SRAM execution region | Holds the authenticated MCU runtime image after Caliptra installs it. | MCI and Caliptra control write access and MCU reset during the hitless update. |

`StagingMemory` and the External Staging Area are different logical roles. They
may use the same physical memory only when that memory is DMA-accessible and the
integration enforces the External Staging Area access-control requirements.

## Hitless Update Overview

```mermaid
sequenceDiagram
    autonumber
    actor UA as PLDM Update Agent
    participant MCU as MCU Runtime
    participant Stage as Firmware Update<br/>StagingMemory
    participant Ext as Protected External<br/>Staging Area
    participant Caliptra as Caliptra Core
    participant MCI as MCI
    participant MCU_SRAM as MCU SRAM<br/>Execution Region

    UA->>Stage: Download firmware package

    Stage->>Ext: Stage FIRMWARE_VERIFY request<br/>(copy Caliptra FMC/RT bundle)
    Caliptra->>Ext: Verify bundle

    Stage->>Ext: Stage VERIFY_AUTH_MANIFEST request<br/>(copy Auth Manifest)
    Caliptra->>Ext: Verify manifest

    MCU->>Stage: Hash MCU and SoC images
    MCU->>MCU: Compare hashes with verified manifest metadata
    MCU->>Stage: Apply image_valid policy or persist package

    UA->>MCU: ActivateFirmware

    Stage->>Ext: Stage FIRMWARE_LOAD request<br/>(copy Caliptra FMC/RT bundle)
    Caliptra->>Ext: Authenticate bundle
    Caliptra->>Caliptra: Load new Caliptra firmware

    Stage->>Ext: Stage SET_AUTH_MANIFEST request<br/>(copy Auth Manifest)
    Caliptra->>Ext: Authenticate manifest
    Caliptra->>Caliptra: Install image authorization metadata

    Stage->>Ext: DMA-copy MCU runtime image
    Caliptra->>Ext: Authenticate MCU image
    Caliptra->>MCI: Request MCU hitless reset
    MCI->>MCU_SRAM: Restrict execution-region access
    Caliptra->>MCU_SRAM: Install authenticated MCU image
    Caliptra->>MCI: Set reset reason and release MCU
```

The verification commands shown before activation are the PLDM verification
phase. Activation must still authenticate the bytes consumed by each command;
the earlier checks alone do not remove a time-of-check/time-of-use risk.

## FIRMWARE_LOAD

The firmware update API creates a payload stream over the Caliptra firmware
bundle in `StagingMemory`. For a request larger than 16 KiB, the mailbox capsule
copies the complete inner request to the External Staging Area and sends an
`EXTERNAL_MAILBOX_CMD` wrapper through the Caliptra mailbox. The wrapper contains
the `FIRMWARE_LOAD` command ID, request size, and external AXI address.

```mermaid
sequenceDiagram
    autonumber
    participant MCU as MCU Runtime<br/>Firmware Update API
    participant Stage as Firmware Update<br/>StagingMemory
    participant Capsule as Mailbox Capsule
    participant Ext as Protected External<br/>Staging Area
    participant MBox as Caliptra Mailbox<br/>16 KiB SRAM
    participant Caliptra as Caliptra Core

    MCU->>Stage: Open stream over Caliptra firmware bundle
    MCU->>Capsule: Start FIRMWARE_LOAD request with total length
    loop Payload chunks
        MCU->>Stage: Read next chunk
        MCU->>Capsule: Send chunk
        Capsule->>Ext: DMA-copy chunk at next offset
    end
    Note over Capsule,Ext: Oversized request uses external staging
    Capsule->>MBox: EXTERNAL_MAILBOX_CMD wrapper
    MBox-->>Caliptra: Command available
    Caliptra->>MBox: Read and validate wrapper
    Caliptra->>Ext: DMA-read FIRMWARE_LOAD request
    Caliptra->>Caliptra: Validate request and authenticate firmware
    Caliptra->>Caliptra: Load FMC and runtime firmware
    Caliptra-->>MCU: Command response
```

If the complete request fits in the 16 KiB Caliptra mailbox, the capsule writes
the original `FIRMWARE_LOAD` request directly to mailbox SRAM and does not use
the External Staging Area for that request.

## SET_AUTH_MANIFEST

`SET_AUTH_MANIFEST` uses the same streamed mailbox path. Caliptra authenticates
the manifest read from the External Staging Area before installing its image
authorization metadata.

```mermaid
sequenceDiagram
    autonumber
    participant MCU as MCU Runtime<br/>Firmware Update API
    participant Stage as Firmware Update<br/>StagingMemory
    participant Capsule as Mailbox Capsule
    participant Ext as Protected External<br/>Staging Area
    participant MBox as Caliptra Mailbox<br/>16 KiB SRAM
    participant Caliptra as Caliptra Core

    MCU->>Stage: Read manifest and calculate inner checksum
    MCU->>Capsule: Start SET_AUTH_MANIFEST request
    loop Header and manifest chunks
        MCU->>Stage: Read next manifest chunk
        MCU->>Capsule: Send request chunk
        Capsule->>Ext: DMA-copy chunk at next offset
    end
    Capsule->>MBox: EXTERNAL_MAILBOX_CMD wrapper
    MBox-->>Caliptra: Command available
    Caliptra->>MBox: Read and validate wrapper
    Caliptra->>Ext: DMA-read SET_AUTH_MANIFEST request
    Caliptra->>Caliptra: Validate checksum and manifest signature
    Caliptra->>Caliptra: Install validated image metadata
    Caliptra-->>MCU: Command response
```

As with `FIRMWARE_LOAD`, a request that fits in the Caliptra mailbox bypasses
the External Staging Area.

## ACTIVATE_FIRMWARE

For an MCU runtime update, the firmware update API first obtains the MCU image
staging address from Caliptra. It then copies the MCU image from `StagingMemory`
to that DMA-accessible address. The `ACTIVATE_FIRMWARE` request is small and is
sent directly through the Caliptra mailbox; the MCU image itself remains in the
External Staging Area for Caliptra to authenticate and install.

```mermaid
sequenceDiagram
    autonumber
    participant MCU as MCU Runtime<br/>Firmware Update API
    participant Stage as Firmware Update<br/>StagingMemory
    participant Ext as Protected External<br/>Staging Area
    participant MBox as Caliptra Mailbox
    participant Caliptra as Caliptra Core
    participant MCI as MCI
    participant MCU_SRAM as MCU SRAM<br/>Execution Region

    MCU->>MBox: GET_IMAGE_INFO(MCU image ID)
    Caliptra-->>MCU: MCU staging AXI address and expected metadata
    loop MCU image chunks
        MCU->>Stage: Read next image chunk
        MCU->>Ext: DMA-copy chunk to MCU staging address
    end
    Note over MCU,Ext: Complete one-way ownership handoff<br/>and block unauthorized access

    MCU->>MBox: ACTIVATE_FIRMWARE(image ID, image size)
    MBox-->>Caliptra: Command available
    Caliptra->>Ext: DMA-read staged MCU image
    Caliptra->>Caliptra: Hash and authorize image against installed manifest
    Caliptra->>MCI: Clear MCU FW execution control
    MCI-->>MCU: Notify firmware reset request
    MCU->>MCI: Request MCU reset
    MCI->>MCI: Halt MCU and assert reset
    Caliptra->>MCU_SRAM: Copy authenticated image into execution region
    Caliptra->>MCI: Set FW_HITLESS_UPD_RESET
    Caliptra->>MCI: Set MCU FW execution control
    MCI->>MCU: Deassert reset
    MCU->>MCI: Read reset reason
    MCU->>MCU_SRAM: Execute updated MCU runtime
```

## Security Requirements

The External Staging Area is part of the Caliptra cryptographic boundary while
Caliptra processes its contents. The SoC integrator must implement mailbox-like
access restrictions that prevent unauthorized agents from reading or modifying
the staged request or image. For a one-way ownership handoff, the integrator
must lock the completed staging contents for exclusive Caliptra access and must
not release that lock until Caliptra completes the operation.

Copying data from `StagingMemory` to the External Staging Area is not, by itself,
a security check. Caliptra must authenticate the bytes it consumes after the
copy, and the destination must remain protected from authentication through
use. Modification of an untrusted `StagingMemory` may cause an update to fail,
but it must not result in unauthenticated firmware execution.

See also:

- [Firmware Update](./firmware_update.md)
- [Caliptra Mailbox Command Processing](./caliptra_mailbox_processing.md)
- [Caliptra External Staging Area](https://github.com/chipsalliance/caliptra-rtl/blob/patch_v2.1/docs/CaliptraIntegrationSpecification.md#external-staging-area)
- [MCU Hitless Firmware Update](https://github.com/chipsalliance/caliptra-ss/blob/main/docs/CaliptraSSIntegrationSpecification.md#mcu-hitless-fw-update)

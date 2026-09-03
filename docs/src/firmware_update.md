# Firmware Update

## Overview

The MCU SDK offers a comprehensive API designed to facilitate firmware updates for Caliptra FMC & RT, MCU RT, and other SoC images. These updates are performed using the PLDM - T5 protocol and are supported for both streaming boot systems and flash boot systems.

## Architecture

The MCU PLDM stack handles PLDM firmware messages from an external Firmware Update Agent. The stack generates upstream notifications to the Firmware Update API to handle application-specific actions such as writing firmware chunks to a staging or SPI Flash storage location, verifying components, etc. 

```mermaid
graph TD;
    A[Application / Initiator] <--> B[API];
    subgraph B[API]
        direction LR
        B1[Firmware Update API];
        B1 <--> B3[DMA]
        B1 <--> B4[Flash]
        B1 <--> B5[Mailbox]
        B1 <--> B6[PLDM]
    end
```

## PLDM Firmware Download Sequence

The end-to-end sequence below assumes `skip_activation = false` and
`verify_same_image = false`. Therefore, activation is performed and the optional
comparison against the currently running image is omitted.

```mermaid
sequenceDiagram
    title End-to-End Firmware Update (Activation Enabled)
    participant BMC as BMC (PLDM Recovery Agent)
    participant MCU_RT as MCU RT
    participant MCU_ROM as MCU ROM
    participant Caliptra as Caliptra Core
    participant Flash as Flash Storage
    participant ExtSRAM as External Staging SRAM
    participant SRAM as MCU SRAM

    Note over MCU_RT,BMC: Initialize and discover firmware-device capabilities
    MCU_RT->>MCU_RT: Start FirmwareUpdater and PLDM firmware-device service
    BMC->>MCU_RT: QueryDeviceIdentifiers
    MCU_RT-->>BMC: Device identifiers
    BMC->>MCU_RT: GetFirmwareParameters
    MCU_RT-->>BMC: Component parameters and capabilities
    BMC->>MCU_RT: RequestUpdate
    MCU_RT-->>BMC: Transfer parameters
    BMC->>MCU_RT: PassComponentTable and UpdateComponent (full image)
    MCU_RT->>MCU_RT: Validate component and staging capacity
    MCU_RT-->>BMC: Component can be updated

    Note over MCU_RT,Flash: Download the full flash image
    loop Until the full component is downloaded
        MCU_RT->>BMC: RequestFirmwareData(offset, length)
        BMC-->>MCU_RT: FirmwareData(chunk)
        MCU_RT->>Flash: Write chunk to flash staging partition<br/>at component-relative offset
    end
    MCU_RT->>BMC: TransferComplete(success)
    BMC-->>MCU_RT: TransferComplete response

    Note over MCU_RT,Caliptra: Verify the component from the flash staging partition
    MCU_RT->>Flash: Read and verify FlashHeader and each ImageHeader checksum
    Flash-->>MCU_RT: Caliptra FMC + Runtime bundle
    MCU_RT->>Caliptra: FIRMWARE_VERIFY(bundle stream)
    Caliptra->>Caliptra: Verify Caliptra image manifest, signatures,<br/>anti-rollback policy, FMC, and Runtime digests
    Caliptra-->>MCU_RT: FirmwareVerifyResp(success)
    Flash-->>MCU_RT: SoC authorization manifest
    MCU_RT->>Caliptra: VERIFY_AUTH_MANIFEST(manifest stream)
    Caliptra->>Caliptra: Verify manifest signature and authorization policy
    Caliptra-->>MCU_RT: Success
    loop MCU RT and each SoC image
        MCU_RT->>Flash: Read image in SHA-384 chunks
        MCU_RT->>MCU_RT: Compute SHA-384 and compare with<br/>the verified manifest digest
    end
    Note right of MCU_RT: verify_same_image is false:<br/>do not compare with running firmware
    MCU_RT->>BMC: VerifyComplete(success)
    BMC-->>MCU_RT: VerifyComplete response

    Note over MCU_RT,Flash: Apply the verified component
    MCU_RT->>Flash: Mark inactive partition INVALID
    MCU_RT->>Flash: Copy full image from staging partition<br/>to inactive partition
    MCU_RT->>Flash: Mark inactive partition VALID
    MCU_RT->>BMC: ApplyComplete(success)
    BMC-->>MCU_RT: ApplyComplete response
    BMC->>MCU_RT: ActivateFirmware(self-contained activation)
    MCU_RT-->>BMC: ActivateFirmware response
    Note right of MCU_RT: skip_activation is false:<br/>continue with activation

    Note over MCU_RT,Caliptra: Activate the new Caliptra FMC + Runtime
    MCU_RT->>Flash: Read Caliptra FMC + Runtime bundle
    Flash-->>MCU_RT: Bundle stream
    MCU_RT->>Caliptra: FIRMWARE_LOAD(bundle stream)
    Caliptra->>Caliptra: Assert Caliptra update reset
    Caliptra->>Caliptra: Caliptra ROM authenticates and launches FMC
    Caliptra->>Caliptra: FMC authenticates and launches Runtime
    loop Until the new Caliptra Runtime accepts commands
        MCU_RT->>Caliptra: FW_INFO
        Caliptra-->>MCU_RT: Busy/error or firmware information
    end

    Note over MCU_RT,Caliptra: Install the manifest used to authorize MCU/SoC images
    MCU_RT->>Flash: Read SoC authorization manifest
    Flash-->>MCU_RT: Manifest stream
    MCU_RT->>Caliptra: SET_AUTH_MANIFEST(manifest stream)
    Caliptra->>Caliptra: Store verified image metadata and staging addresses
    Caliptra-->>MCU_RT: Success

    Note over MCU_RT,SRAM: Stage and activate the new MCU Runtime
    MCU_RT->>Caliptra: GET_IMAGE_INFO(MCU_RT identifier)
    Caliptra-->>MCU_RT: DMA-accessible external SRAM address from manifest
    MCU_RT->>Flash: Read MCU RT subimage in chunks
    MCU_RT->>ExtSRAM: Copy MCU RT subimage to DMA staging address
    Note right of ExtSRAM: Caliptra can DMA-read this SRAM.<br/>The image is not executable here.
    MCU_RT->>Caliptra: ACTIVATE_FIRMWARE(MCU_RT identifier, image size)

    rect rgb(235, 245, 255)
        Note over MCU_RT,Caliptra: Caliptra Core MCU hitless-update flow
        Caliptra->>Caliptra: Validate request and manifest metadata
        Caliptra->>Caliptra: Set RESET_REASON = FW_HITLESS_UPD_RESET
        Caliptra->>Caliptra: Clear MCU FW_EXEC_CTRL
        Caliptra-->>MCU_RT: MCU-reset-request notification interrupt
        MCU_RT->>MCU_RT: Acknowledge interrupt and set RESET_REQUEST.mcu_req
        Caliptra->>Caliptra: Wait until MCU reset is asserted
        Caliptra->>ExtSRAM: DMA-read staged MCU RT image
        Caliptra->>SRAM: Copy image into MCU SRAM updatable region
        Caliptra->>SRAM: SHA-384 hash image from its load address
        Caliptra->>Caliptra: AuthorizeAndStash and compare digest<br/>with verified manifest metadata
        Caliptra->>Caliptra: Update MCU RT DPE measurement context
        Caliptra->>Caliptra: Set MCU FW_EXEC_CTRL / firmware-ready indication
        Caliptra->>MCU_ROM: Release MCU reset
    end

    MCU_ROM->>MCU_ROM: Detect FW_HITLESS_UPD_RESET
    MCU_ROM->>Caliptra: Complete original ACTIVATE_FIRMWARE mailbox response
    MCU_ROM->>Caliptra: Poll firmware-ready indication
    Caliptra-->>MCU_ROM: MCU image ready in SRAM
    MCU_ROM->>SRAM: Parse optional headers and determine firmware entry
    MCU_ROM->>MCU_ROM: Set FIRMWARE_BOOT_FLOW_COMPLETE milestone
    MCU_ROM->>SRAM: Jump to new MCU Runtime entry point
    SRAM-->>MCU_RT: Execute updated MCU RT
```

### Loading Updated SoC Images After MCU Reboot

After the hitless reset, the updated MCU Runtime detects the firmware-update
reset reason and loads SoC images from the pending flash partition. The
authorization manifest was installed before the reset, so it is not installed
again in this path.

```mermaid
sequenceDiagram
    title Post-Reboot SoC Image Update
    participant MCU_RT as Updated MCU RT
    participant Flash as Flash Storage
    participant Caliptra as Caliptra Core
    participant SocMemory as SoC Executable Regions
    participant SoC as SoC Components

    MCU_RT->>MCU_RT: Read RESET_REASON and detect FW_HITLESS_UPD_RESET
    MCU_RT->>MCU_RT: Release firmware-update SRAM lock
    MCU_RT->>Flash: Read active and pending partition metadata
    Flash-->>MCU_RT: Pending partition is VALID
    MCU_RT->>MCU_RT: Select pending partition for image loading
    Note over MCU_RT,Caliptra: SET_AUTH_MANIFEST is skipped because the updater<br/>installed the new manifest before the hitless reset.

    loop For each configured SoC firmware ID
        MCU_RT->>Caliptra: GET_IMAGE_INFO(firmware ID)
        Caliptra-->>MCU_RT: Component ID, executable load address,<br/>size metadata, and expected SHA-384 digest
        MCU_RT->>Flash: Read FlashHeader and locate component in TOC
        loop Until the SoC image is copied
            MCU_RT->>Flash: Read image chunk from pending partition
            MCU_RT->>SocMemory: DMA-write chunk to executable load address
        end
        MCU_RT->>Caliptra: AUTHORIZE_AND_STASH(firmware ID,<br/>source = LoadAddress, image size)
        Caliptra->>SocMemory: SHA-384 hash image at executable load address
        Caliptra->>Caliptra: Compare digest with verified authorization manifest
        Caliptra-->>MCU_RT: Image authorized
        MCU_RT->>MCU_RT: Update component attestation measurement state
    end

    MCU_RT->>Flash: Mark pending partition BOOT_SUCCESSFUL
    MCU_RT->>Flash: Set pending partition as ACTIVE
    MCU_RT->>Caliptra: ACTIVATE_FIRMWARE(all SoC firmware IDs,<br/>MCU image size = 0)
    Caliptra->>Caliptra: Resolve each firmware ID to its manifest EXEC bit
    Caliptra->>SoC: Publish corresponding FW_EXEC_CTRL bits
    SoC->>SocMemory: Begin execution from updated image regions
    Caliptra-->>MCU_RT: ActivateFirmwareResp(success)
    Note over MCU_RT,SoC: All updated SoC images are loaded, authorized, and active.
```

The diagrams below break the PLDM portions of this sequence into individual
protocol phases.


```mermaid
sequenceDiagram
    title Firmware Update Service Initialization

    actor App as Initiator
    participant API as Firmware Update API
    participant Firmware as PLDM Stack - T5
    participant PLDM as Update Agent

    App->>API: Start Firmware Update Service
    loop for all components
    API->>API: Retrieve firmware metadata from Caliptra core
    end

    API->>Firmware: Start Firmware Update Service
    Firmware->>Firmware: Start listen loop
    activate Firmware
```

### **Query Device Information**

```mermaid
sequenceDiagram
    title Query Device Information

    actor App as Initiator
    participant API as Firmware Update API
    participant Firmware as PLDM Stack - T5
    participant PLDM as Update Agent

    PLDM->>Firmware: QueryDeviceIdentifiers
    Firmware-->>PLDM: DeviceIdentifiers

    PLDM->>Firmware: GetFirmwareParameters
    Firmware-->>PLDM: FirmwareParameters
```

### **Request Update and Pass Components**

```mermaid
sequenceDiagram
    title Request Update and Pass Components

    actor App as Initiator
    participant API as Firmware Update API
    participant Firmware as PLDM Stack - T5
    participant PLDM as Update Agent

    PLDM->>Firmware: RequestUpdate
    Firmware->>API: Get Transfer Size
    API-->>Firmware: Transfer Size
    Firmware-->>PLDM: RequestUpdate Response

    loop until all component info passed
        PLDM->>Firmware: PassComponent(component)
        Firmware-->>PLDM: PassComponent Response
    end
```

### **Updating Components**

```mermaid
sequenceDiagram
    title Updating Components

    actor App as Initiator
    participant API as Firmware Update API
    participant Firmware as PLDM Stack - T5
    participant PLDM as Update Agent

    loop for every component
        PLDM->>Firmware: UpdateComponent(component)
        Firmware->>API: Handle Component callback
        API->>Firmware: CompCanBeUpdated
        Firmware-->>PLDM: UpdateComponent Response
    end
```

### **Requesting and Transferring Firmware Data**

```mermaid
sequenceDiagram
    title Requesting and Transferring Firmware Data

    actor App as Initiator
    participant API as Firmware Update API
    participant Firmware as PLDM Stack - T5
    participant PLDM as Update Agent

    loop until component is downloaded
        Firmware->>PLDM: RequestFirmwareData
        PLDM-->>Firmware: FirmwareData
        Firmware->>API: FirmwareData Notification
        API->>API: Write to Staging Area
        API-->>Firmware: Ok
    end

    Firmware-->>PLDM: Transfer Complete
```

### **Verifying Components**

```mermaid
sequenceDiagram
    title Verifying Components

    actor App as Initiator
    participant API as Firmware Update API
    participant Firmware as PLDM Stack - T5
    participant PLDM as Update Agent

    Firmware->>API: Verify Component Notification

    API->>API: Verify Caliptra FW using FIRMWARE_VERIFY mbox command
    API->>API: Verify SOC Manifest using VERIFY_MANIFEST mbox command
    API->>API: Hash MCU Image and verify with SOC Manifest Digest
    loop for all SOC Images
        API->>API: Hash SOC Image and verify with SOC Manifest Digest
    end

    API-->>Firmware: Ok
    Firmware-->>PLDM: VerifyComplete
```

### **Applying Components**

```mermaid
sequenceDiagram
    title Applying Components

    actor App as Initiator
    participant API as Firmware Update API
    participant Firmware as PLDM Stack - T5
    participant PLDM as Update Agent

    Firmware->>API: Apply component Notification
    API->>API: Set flash staging partition table status to `VALID`

    API->>Firmware: Ok
    Firmware->>PLDM: ApplyComplete

```

### **Activating Firmware**

```mermaid
sequenceDiagram
    title Activating Firmware

    actor App as Initiator
    participant API as Firmware Update API
    participant Firmware as PLDM Stack - T5
    participant PLDM as Update Agent

    PLDM->>Firmware: ActivateFirmware
    Firmware->>API: Activate Notification
    Firmware-->>PLDM: Activate Response (Self Activation)
    API->>API: Send Caliptra FW_LOAD command
    API-->>Firmware: Ok

    API->>API: Set the new Auth Manifest to Caliptra  (SET_AUTH_MANIFEST)  
    API->>API: Copy MCU image to MCU staging address
    API->>API: Send Activate Image Mailbox Command
    API->>API: MCU Hitless Update Reset Flow
    API->>API: Use Image loader to load updated SOC images to SOCs
    API->>API: Mark partition as 'ACTIVE'
```

#### MCU Hitless Update Reset Flow

```mermaid
sequenceDiagram
    title MCU Hitless Update Reset Flow
    participant Caliptra as Caliptra FW
    participant MCU as MCU FW
    participant MCI as MCI Reset Ctrl

    MCU->>Caliptra: ActivateFirmware(2)
    Caliptra->>Caliptra: Clear FW_EXEC_CTRL[2] 
    MCI-->>MCU: Interrupt (MCU image ready)
    MCU-->>MCU: handle notif_cptra_mcu_reset_req_sts interrupt
    MCU->>MCI: Clear interrupt status
    MCU->>MCI: Set RESET_REQUEST.mcu_req

    MCI->>MCU: Assert MCU reset
    loop until RESET_STATUS.MCU_RESET_STS = 0
    Caliptra-->>MCI: Read RESET_STATUS.MCU_RESET_STS
    MCI-->>Caliptra: RESET_STATUS.MCU_RESET_STS
    end
    Caliptra->>Caliptra: Update MCU SRAM updatable region
    Caliptra->>MCI: Set RESET_REASON.FW_HITLESS_UPD_RESET
    Caliptra->>Caliptra: Set FW_EXEC_CTRL[2]
    MCI-->>MCU: Release reset
    MCU->>MCI: Read RESET_REASON
    MCI->>MCU: RESET_REASON=HitlessUpdate
    MCU->>MCU: Jump to MCU SRAM
```
 

## Firmware Update Flow

### Full Image Update for Flash Boot System

**Updating the full flash image as a single PLDM firmware component**

The PLDM package only contains a single component which contains a full flash image as defined in [flash_layout.md](https://github.com/chipsalliance/caliptra-mcu-sw/blob/main/docs/src/flash_layout.md).


| PLDM FW Update Package                                |
| ----------------------------------------------------- |
| Package Header Information                            |
| Firmware Dev ID Descriptors                           |
| Downstream Dev ID Descriptors                         |
| Component Image Information                           |
| Package Header Checksum                               |
| Package Payload Checksum                              |
| **Component (Full image for flash-boot system)**      |



| Component                      |
| ------------------------------ |
| Flash header
| Checksum
| Image Info (Caliptra FMC + RT) |
| Image Info (SoC Manifest)      |
| Image Info (MCU RT)            |
| Image Info (SoC Image 1)       |
| ...                            |
| Image Info (SoC Image N - 3)   |
| Caliptra FMC + RT              |
| SoC Manifest                   |
| MCU RT                         |
| SoC Image 1                    |
| ...                            |
| SoC Image N - 3                |


To support full image updates, a SoC-defined staging memory must be provided to store the incoming payload. The designated staging area for the Component must be accessible by the Caliptra ROM to fetch and authorize the image. This staging area could be located in MCU SRAM or MCI mailbox SRAM, as defined in Caliptra 2.1. If the SoC-defined staging memory does not meet this requirement, the image must be copied to the compliant region, which may slightly impact performance. For other components, if the staging memory (e.g., a staging partition on flash) is not directly accessible by the Caliptra core's DMA engine for reading and hashing the image, the MCU must perform the cryptographic operations to compute the hash. The computed hash is then sent via a mailbox command for authorization.

**Detailed steps**:
*Note: Actions below are performed by MCU RT Firmware*

1. An initiator, such as a custom user application, starts the firmware update service through the Firmware Update API. This action initializes the responder loop in the PLDM stack, enabling it to listen for incoming PLDM messages from the PLDM agent. The API queries firmware component metadata from the Caliptra core (e.g., component version numbers, classifications, etc.) using a mailbox command. This metadata is used to construct the Device Identifiers and Firmware Parameters, as specified in the DMTF DSP0267 1.3.0 standard. 
2. The PLDM stack notifies the API when a firmware image becomes available for update.
3. The PLDM stack notifies the API which component is being downloaded using the UpdateComponent notification.
4. The PLDM stack sends a FirmwareData notification to the API for each received firmware chunk, including the data, size, and chunk offset. The API's download handler writes the received firmware data to the staging memory. If the staging memory to be used is in flash, MCU will write the chunks in the staging partition.
5. Once all firmware chunks are downloaded, the PLDM stack notifies the API to verify the component. The API processes the component to extract and identify individual embedded images, referred to as subcomponents. The verification process is performed sequentially for each subcomponent:
    a. For the Caliptra FW Bundle, the MCU verifies the bundle thorugh the `FIRMWARE_VERIFY` mailbox command.
    b. For the SoC Manifest subcomponent, the MCU sends it to the Caliptra core using the `VERIFY_MANIFEST` mailbox command. The mailbox response confirms the authenticity and correctness of the manifest.
    d. For MCU RT or SoC Image subcomponents, the MCU computes the hash of the MCU RT image and verifies it against the the digest in the verified SoC Manifest. The same is done with the SoC Image subcomponents
6. After verification, the PLDM stack notifies the API to apply the image. If the staging area is not flash, the MCU writes the images from the temporary staging area to the inactive flash partition. Refer to [A/B Partition Mechanism](#a-b-partition-mechanism) for more details.
7. When the Update Agent issues the `ActivateFirmware` command:
    a. The MCU activates the Caliptra core FW using the `FIRMWARE_LOAD ` mailbox command. This will also reset Caliptra core and boot up with the updated image.
    b. MCU sets new Auth Manifest to Caliptra using `SET_AUTH_MANIFEST` mailbox command
    c. MCU will perform a Hitless Update Reset to reset the MCU. MCU copies the MCU RT image from the staging memory to the DMA staging address allocated to it in the SoC Manifest. MCU then sends `ACTIVATE_FIRMWARE` mailbox command to Caliptra. Caliptra will then initiate the reset of the MCU and set The `RESET_REASON` to `FW_HITLESS_UPD_RESET`. Refer to the [MCU Hitless Update](https://github.com/chipsalliance/caliptra-ss/blob/main/docs/CaliptraSSIntegrationSpecification.md#mcu-hitless-fw-update) section of the Caliptra subsystem integration specification for the details of the MCU Hitless Update Reset flow.
    d. MCU boots up with the updated MCU image. 
    e. During Image loading since `RESET_REASON` is `FW_HITLESS_UPD_RESET`, MCU will check for non-active `VALID` partitions and load the downloaded SoC images. The integrator will need to implement platform specific logic to update the SoC component. This may need clearing the corresponding `FW_EXEC_CTRL` bit of the SoC before loading the new image and setting it back after to indicate to the SoC component the new firmware is ready. 
    d. If all images have been loaded correctly, then the partition is marked as `ACTIVE`.


### A/B Partition Mechanism

The A/B partition mechanism is a robust approach to ensure seamless and reliable firmware updates for flash boot systems.
When partition A is active, it contains the currently running firmware, while partition B remains inactive and is used as the target for firmware updates. This ensures that the system can always revert to the previous active partition in case of an update failure.

#### Partition Layout

The location of A/B partitions can either reside on a single flash device or be distributed across separate flash devices. In a single flash device setup, both partitions share the same physical storage, simplifying design and reducing costs. However, this approach may introduce performance bottlenecks during simultaneous read/write operations and poses a single point of failure. On the other hand, using separate flash devices for A/B partitions enhances redundancy and reliability, allowing parallel operations that improve update performance. This configuration, while more expensive and complex, is ideal for systems requiring high reliability and scalability. The choice between these configurations depends on the specific requirements of the system, such as cost constraints, performance needs, and reliability expectations.

| Partition A (Active)           | Partition B (Inactive)         |
| -------------------------------| -------------------------------|
| Flash header                   | Flash header                  |
| Checksum                       | Checksum                       |
| Image Info (Caliptra FMC + RT) | Image Info (Caliptra FMC + RT) |
| Image Info (SoC Manifest)      | Image Info (SoC Manifest)      |
| Image Info (MCU RT)            | Image Info (MCU RT)            |
| Image Info (SoC Image 1)       | Image Info (SoC Image 1)       |
| ...                            | ...                            |
| Image Info (SoC Image N)       | Image Info (SoC Image N)       |
| Caliptra FMC + RT              | Caliptra FMC + RT              |
| SoC Manifest                   | SoC Manifest                   |
| MCU RT                         | MCU RT                         |
| SoC Image 1                    | SoC Image 1                    |
| ...                            | ...                            |
| SoC Image N                    | SoC Image N                    |

#### Partition Selection

- **Partition Table**

For the A/B partition mechanism, the bootloader (MCU ROM) determines which partition to load the firmware image from by using a partition selection mechanism. The implementation of partition selection is system-specific. A common approach involves using a partition table stored in a reserved area of flash. The table below shows an example partition table format:

| Field Name         | Size   | Description                                 |
|---------------------|--------|--------------------------------------------|
| Active Partition    | 1 byte | Indicates the active partition (A or B).   |
| Partition A Status   | 1 byte | Refer to Partition Status  for values |
| Partition B Status   | 1 byte | Refer to Partition Status  for values.   |
| Rollback Flag       | 1 byte | Indicates if rollback is required.         |
| Reserved            | 4 byte | Reserved                                   |
| CheckSum            | 4 byte |                                            |

- **Partition Status**

Bits 7:4:  Boot Attempt Count

Bits 3:0:
| Value | Description     |
|-------|-----------------|
|   0   | Invalid         |
|   1   | Valid           |
|   2   | Boot Failed     |
|   3   | Boot Successful |

- **Partition Table Usage**
    - During Normal Boot
        - The  MCU ROM reads the partition table to determine:
            - The active partition to boot from.
            - Whether the active partition is valid and bootable.
        - If the `RESET_REASON` is `FW_HITLESS_UPD_RESET`:
            - MCU RT will attempt to load images from the partition containing downloaded update images
        - If the `RESET_REASON` is not `FW_HITLESS_UPD_RESET`:
            - If the active partition is valid, the bootloader loads the firmware image from it and boots the system.
        - If the firmware fails to boot (e.g., due to corruption or verification failure), the bootloader:
            - Checks the Rollback Flag.
            - Switches to the other partition if rollback is required.
    - During Firmware Update
        - In the `ActivateFirmware` phase, the partition status flags are updated to mark as `VALID`. The active partition will not be changed.
        - Steps to Update:
            1. Download the update images to the non-active partition.
            2. Mark this partition as `VALID`.
            3. Do a Hitless Update Reset
            4. Load images from the non-active partition with the `VALID` status.
            5. If all images load properly, mark the partition as `ACTIVE`.



## Interfaces

```rust
pub struct FirmwareUpdater<'a, D: DMAMapping> {


    /// Creates a new FirmwareUpdater instance.
    ///
    /// # Arguments
    /// staging_memory: An abstraction of the staging memory. The `StagingMemory` trait contains read and write
    /// operations to read from or write to the firmware update staging area.
    /// dma_mapping: This contains the DMA mapping information for the firmware update process. This includes
    /// converting virtual addresses to physical addresses for DMA transfers.
    /// spawner: The async task spawner used to spawn tasks.
    pub fn new(
        staging_memory: &'static dyn StagingMemory,
        params: &'a PldmFirmwareDeviceParams,
        dma_mapping: &'a D,
        spawner: Spawner,
    ) -> Self;

    /// Starts the firmware update process. This call will block until update has been completed or encountered an error.
    /// Returns `Ok(())` on success or an `ErrorCode` on failure.
    fn start(&self) -> Result<(), ErrorCode>;

}
```

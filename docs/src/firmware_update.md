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

The diagram below shows the steps and interactions between different software layers during the firmware update process.


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
| Flash header                   |
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

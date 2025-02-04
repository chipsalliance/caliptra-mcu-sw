# Firmware Update

## Overview

The MCU SDK provides an API that allows for updating the firmware of Caliptra FMC & RT, MCU RT, and other SoC images through PLDM - T5.

## Architecture

The MCU PLDM stack handles PLDM firmware messages from an external Firmware Update Agent. The stack generates upstream notifications to the Firmware Update API to handle application-specific actions such as writing firmware chunks to a staging or SPI Flash storage location, verifying components, etc through the Image Loading API. The API notifies the application of the start and completion of the firmware update process.

```mermaid
graph TD;
    A[Application / Initiator] <--> B[API];
    subgraph B[API]
        direction LR
        B1[Firmware Update] <--> B2[Image Loading];
        B2 <--> B3[DMA]
        B2 <--> B4[Flash]
        B2 <--> B5[Mailbox]
    end
    B <--> C[PLDM];
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
    Firmware->>API: Update Available Notification
    API->>App: Update Available Notification
    API-->>Firmware: Ok
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
        Firmware->>API: UpdateComponent Notification

        alt Caliptra FMC+RT or SoC Manifest
            API->>API: Acquire mailbox lock
        else MCU RT or SoC Image
            API->>API: GET_STAGING_ADDRESS
        end

        API-->>Firmware: Ok
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

        alt SoC Manifest
            API->>API: Stream as SoC_MANIFEST<br/>Mailbox command
        else Caliptra FMC+RT
            API->>API: Stream as CALIPTRA_FW_LOAD<br/>Mailbox Command
        else MCU RT or SoC Image
            API->>API: Write to Staging Area
        end
        API-->>Firmware: Ok
    end

    API-->>API: Release Mailbox Lock (if acquired)

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

    alt SoC Manifest
        API->>API: Process SET_AUTH_MANIFEST<br/> Mailbox Command Response
    else MCU RT or SoC image
        API->>API: Verify through AUTHORIZE_AND_STASH<br/>Mailbox Command
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
    alt Firmware Update for devices with Flash
        alt SoC Manifest
            API->>API: Write SoC Manifest to Flash Storage
        else MCU RT or SoC Image
            API->>API: Copy image from Staging to Flash Storage
        end
    end

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
    alt MCU RT or SoC Image
        API->>API: Send Activate Image Mailbox Command
    end
    API-->>Firmware: Ok
    API->>App: UpdateComplete
    Firmware-->>PLDM: Activate Response
```

## Firmware Update Steps

**Note:** Actions below are performed by MCU RT Firmware.

1. An initiator (such as a custom user application) starts the firmware service through the Firmware Update API. This will start the responder loop in the PLDM stack that will listen for PLDM messages coming from the PLDM agent. The API queries firmware component metadata from the Caliptra core (e.g., component version numbers, classification, etc.) using a mailbox command to construct the Device Identifiers and Firmware Parameters, as defined by the DMTF DSP0267 1.3.0 specification, needed by the PLDM stack.
2. The PLDM stack notifies the API if a firmware image is available for update.
3. The PLDM stack notifies the API which component is being downloaded using the UpdateComponent notification. If the image is an MCU RT or SoC Image, the staging address is retrieved from the SoC Manifest stored in the Caliptra Core using a mailbox command. For Caliptra FMC+RT and the SoC Manifest, the mailbox lock is acquired since these images are streamed directly through the mailbox interface. The lock is released after all chunks of the image have been transferred.
4. The PLDM stack sends a FirmwareData notification to the API for each received firmware chunk, including the data, size, and chunk offset.
   1. If the component is a SoC Manifest, it is streamed to the mailbox via the SET_AUTH_MANIFEST mailbox command.
   2. If the component is Caliptra FMC+RT, it is streamed to the Caliptra core using the CALIPTRA_FW_UPLOAD mailbox command.
   3. If the component is an MCU RT or SoC Image, it is written to a staging area determined in step 3.
5. Once all firmware chunks are downloaded, the PLDM stack notifies the API to verify the component.
   1. If the component is a SoC Manifest, the MCU waits for the SET_AUTH_MANIFEST mailbox command response, which indicates the authenticity and correctness of the manifest.
   2. If the component is an MCU RT or SoC Image, the MCU sends the AUTHORIZE_AND_STASH command, indicating that the image to be verified is in the staging area.
   **Note:** The AUTHORIZE_AND_STASH command computes the SHA of the image via the SHA-Acc by streaming the image from the staging area to the SHA-Acc through DMA. The computed SHA is compared against the SHA in the SoC Manifest for the specific image.
6. After verification, the PLDM stack notifies the API to apply the image. The MCU writes the images to SPI Flash storage from the temporary staging area (if flash is available on the device).
7. When the Update Agent sends the `ActivateFirmware` command, the API sends an `ActivateImage` mailbox command to the Caliptra core. The Caliptra core processes the activation according to the [Caliptra specification](https://github.com/chipsalliance/Caliptra/blob/main/doc/Caliptra.md#subsystem-support-for-hitless-updates).

## Interfaces

```rust
pub trait FirmwareUpdateApi {

    /// Start the firmware update service.
    /// 
    /// # Returns
    /// Returns a future that will remain unset until the service is stopped.
    /// Ok(()) - The service has been terminated successfully.
    /// Err(FirmwareUpdateError) - The service has been terminated with an error.
    async fn start_service(&self) -> Result<(), FirmwareUpdateError>;

    /// Stop the firmware update service.
    /// 
    /// # Returns
    /// Ok() - The service has been terminated successfully.
    /// Err(ErrorCode) - The service can not be stopped.
    fn stop_service(&self) -> Result<(), ErrorCode>;

    /// Register a callback to be called when a firmware update event occurs.
    /// 
    /// # Arguments
    /// callback - The callback to be called when a firmware update event occurs.
    fn register_callback(&self, callback: FirmwareUpdateCallback);


}

/// Define the callback function signature for firmware update events.
/// Returns Ok(()) if the notification is handled successfully, otherwise an error code.
pub type FirmwareUpdateCallback = fn(FirmwareUpdateNotification) -> Result<(),ErrorCode>;

pub enum FirmwareUpdateNotification<'a>{
    // Firmware Update is available and ready for download.
    UpdateAvailable,

    // Firmware Update is complete.
    UpdateComplete,

    // Firmware Update is canceled.
    UpdateCanceled,

}
```
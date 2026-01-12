# BMC Network Recovery Boot - Design Document

## Overview

This document outlines the design for a lightweight network recovery boot utility for the Caliptra subsystem. The system enables the Caliptra SS to download firmware images over the network through a dedicated Network Boot Coprocessor within a ROM environment, providing a resilient fallback path when flash memory is corrupted.

The network boot coprocessor acts as an intermediary between remote image servers and the Caliptra SS, handling network communications including DHCP configuration, TFTP server discovery, and firmware image downloads. The system supports downloading multiple firmware components including Caliptra FMC+RT images, SoC manifests, and MCU runtime images through a firmware ID-based mapping system.

## Motivation

### Flash Dependency Risk
- Boot failure if **both flashes are corrupted**

### Recovery Challenge
- Physical intervention is costly in **hyperscale environments**

### Design Goals
- Minimal **MCU ROM** footprint
- Consistent with **OCP streaming boot model** for early firmware (Caliptra FMC + RT, SoC Manifest, MCU RT)
- Secure image retrieval
- Resilient fallback path

### Final Solution
- Use a **dedicated co-processor** with a lightweight network stack
- Automatically configure networking via **DHCP**
- Securely download **Caliptra early firmware images** into the Caliptra subsystem

## System Architecture

```mermaid
flowchart LR
    subgraph Caliptra_Subsystem["Caliptra Subsystem"]
        Caliptra["Caliptra"]
        RecoveryIF["Recovery I/F"]
        MCU_ROM["MCU ROM"]
        Mailbox["Mailbox"]
        MCU_RT["MCU Runtime"]

        Caliptra <--> RecoveryIF
        RecoveryIF <--> MCU_ROM
        Caliptra <--> Mailbox
        Mailbox <--> MCU_RT
    end

    MCU_ROM <--> Network_ROM["Network ROM<br/>- DHCP<br/>- TFTP Client<br/>- FW ID Mapping"]
    MCU_RT <--> Network_ROM
    Network_ROM <--> Image_Server["Image Server<br/>- Image Store<br/>- DHCP<br/>- TFTP Server<br/>- Config File"]
```

## Network Recovery Boot Flow

The following diagram illustrates the high-level flow using the `BootSourceProvider` interface, showing how `discover()` drives DHCP and TOC fetch:

```mermaid
sequenceDiagram
    participant CRIF as Caliptra Recovery I/F
    participant MCU as MCU ROM
    participant NET as Network ROM (BootSourceProvider)
    participant IMG as Image Server

    MCU->>NET: InitiateBoot()
    NET->>IMG: DHCP Discovery
    IMG-->>NET: DHCP Offer
    NET->>IMG: Get TOC
    IMG->>NET: TOC
    NET->>MCU: InitiateBoot response()
```

### Image Transfer Sequence

Once the boot source is initialized, the MCU ROM uses the `BootSourceProvider` methods to fetch each firmware component:

```mermaid
sequenceDiagram
    participant CRIF as Caliptra Recovery I/F
    participant MCU as MCU ROM
    participant NET as Network ROM (BootSourceProvider)
    participant IMG as Image Server

    loop For each image id (0,1,2)
        MCU->>CRIF: Poll recovery readiness
        CRIF-->>MCU: Awaiting recovery image id

        MCU->>NET: get_image_metadata(id)
        NET-->>MCU: ImageMetadata { size, checksum, version }

        MCU->>CRIF: Set image size (INDIRECT_FIFO_CTRL.write)

        MCU->>NET: download_image(id)
        NET->>IMG: TFTP GET mapped filename

        loop Image transfer by chunk
            IMG-->>NET: Image chunk
            NET-->>MCU: Forward image chunk (ImageStream::read_chunk)
            MCU->>CRIF: Write chunk
            MCU-->>NET: Chunk ACK
        end
    end

    MCU->>CRIF: Finalize recovery
    MCU->>NET: Finalize
```

## Runtime SoC Image Loading

This section describes the flow for loading and authenticating SoC images at runtime through the MCU Runtime. The MCU Runtime coordinates image authorization with the Caliptra Core, while Network ROM handles downloading image data from the network.

```mermaid
sequenceDiagram
    participant CORE as Caliptra Core
    participant MCURT as MCU RT
    participant NET as Network ROM
    participant IMG as Image Server

    MCURT->>NET: InitiateBoot
    NET->>IMG: Get TOC
    IMG->>NET: TOC
    NET-->>MCURT: InitiateBoot response

    loop For each SoC image (image_id)
        MCURT->>CORE: get_image_info(image_id)
        CORE-->>MCURT: ImageInfo { load_address, component_id }

        MCURT->>NET: get_image_metadata(id)
        NET-->>MCURT: ImageMetadata { size, checksum, version }

        MCURT->>NET: download_image(image_id)
        NET->>IMG: TFTP GET image file
        loop Image transfer by chunk
            IMG-->>NET: Image chunk
            NET-->>MCURT: Image chunk

            MCURT->>MCURT: Write chunk to load_address
        end

        MCURT->>CORE: authorize(component_id)
        CORE-->>MCURT: Success/Error response
    end

    MCURT->>NET: Finalize
```

## Messaging Protocol

The boot source provider communication uses a simple request-response messaging protocol. The following section defines the message types, packet formats, and field definitions.

### Message Types and Packet Formats

#### 1. Initiate Boot Request
Initiates the boot source discovery process.

**Request Packet:**
```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     Message Type       0x01 - InitiateBoot
1       3     Reserved           Must be 0
4       4     Protocol Version   Version of the messaging protocol
8       N     Source Specific    Source-specific initialization parameters
```

**Response Packet:**
```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     Message Type       0x81 - InitiateBoot Response
1       1     Status             0x00=Started, 0x01=InProgress, non-zero=Error
2       2     Reserved           Must be 0
```

#### 2. Get Image Metadata Request
Queries metadata about a specific firmware image.

**Request Packet:**
```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     Message Type       0x02 - Image Info Request
1       1     Firmware ID        0=CaliptraFmcRt, 1=SocManifest, 2=McuRt, 3..-SoC
2       2     Reserved           Must be 0
```

**Response Packet:**
```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     Message Type       0x82 - Image Info Response
1       1     Status             0x00=Success, non-zero=Error
2       2     Reserved           Must be 0
4       4     Image Size         Total size in bytes
8       4     Checksum Type      0=None, 1=SHA256, 2=Other
12      32    Checksum           Checksum/hash of the image
44      4     Version            Image version number
48      4     Flags              Bit 0: Compressed, Bit 1: Signed, etc.
52      4     Reserved           For future use
```

#### 3. Image Download Request
Initiates download of a firmware image.

**Request Packet:**
```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     Message Type       0x03 - Image Download Request
1       1     Firmware ID        0=CaliptraFmcRt, 1=SocManifest, 2=McuRt
2       2     Reserved           Must be 0
4       4     Reserved           Can be extended to support flash-based boot
8       4     Reserved           Can be extended to support flash-based boot
```

**Response Packet (per chunk):**
```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     Message Type       0x83 - Image Chunk
1       1     Status             0x00=Success, non-zero=Error
2       2     Sequence Number    For ordered delivery
4       4     Offset             Current byte offset in image (TBD: Check if needed)
8       4     Chunk Size         Size of data in this chunk
12      4     Total Size         Total image size (0 if unknown)
16      N     Image Data         Chunk payload (size = Chunk Size field)
```

#### 4. Chunk Acknowledgment
Acknowledges receipt of an image chunk and provides flow control.

**Request Packet:**
```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     Message Type       0x04 - Chunk ACK
1       1     Firmware ID        Firmware being transferred
2       2     Sequence Number    Sequence number to be acknowledged
4       4     Reserved           
8       4     Flags              Bit 0: Ready for next, Bit 1: Error detected
```



#### 5. Finalize
Notifies the boot source of recovery completion or error.

**Request Packet:**
```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     Message Type       0x05 - Finalize
1       1     Status             0x00=Success, non-zero=Error
2       2     Error Code         Specific error code if Status != 0
4       4     Reserved           For future use
```

**Response Packet:**
```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     Message Type       0x85 - Finalize ACK
1       1     Status             0x00=Acknowledged, non-zero=Error
2       2     Reserved           Must be 0
4       4     Cleanup Flags      Bit 0: Clear TOC, Bit 1: Reset connection
8       4     Reserved           For future use
```

### Message Summary Table

| Message Type | Code | Direction | Purpose |
|-------|------|-----------|---------|
| Initiate Boot Request | 0x01 | MCU → Source | Initiate boot source discovery |
| Initiate Boot Response | 0x81 | Source → MCU | Confirm discovery and image availability |
| Image Metadata Request | 0x02 | MCU → Source | Query image metadata |
| Image Metadata Response | 0x82 | Source → MCU | Return image metadata and checksums |
| Image Download Request | 0x03 | MCU → Source | Start image transfer |
| Image Chunk | 0x83 | Source → MCU | Send image data chunk |
| Chunk ACK | 0x04 | MCU → Source | Acknowledge chunk and flow control |
| Finalize | 0x05 | MCU → Source | Notify recovery completion/error |
| Finalize ACK | 0x85 | Source → MCU | Final acknowledgment |

### Error Codes

```
Error Code  Description
----------  -----------
0x00        Success / No Error
0x01        Invalid Message Type
0x02        Invalid Firmware ID
0x03        Image Not Found / Not Available
0x04        Checksum Mismatch
0x05        Transfer Timeout
0x06        Source Not Ready
0x07        Invalid Parameters
0x08        Corrupted Data
0x09        Insufficient Space
0x0A        Checksum Verification Failed
0xFF        Unknown / Unspecified Error
```

## Protocol Support

The boot source provider supports a minimal set of protocols optimized for the Caliptra ROM environment:

### DHCP (Dynamic Host Configuration Protocol)
- **Purpose**: Automatic network configuration
- **Advantages**: 
  - Standard network configuration protocol
  - Minimal overhead for basic IP assignment
  - Simple UDP-based protocol
- **Implementation**: Client-side DHCP for IP address, gateway, and boot server discovery

### TFTP (Trivial File Transfer Protocol)
- **Purpose**: Lightweight file transfer for firmware images
- **Advantages**: 
  - Extremely lightweight - minimal overhead perfect for ROM environments
  - Simple UDP-based protocol - easy to implement securely
  - Small code footprint (~5-10KB implementation)
  - Standard protocol for network boot scenarios
- **Implementation**: Client-side TFTP for firmware image download

### IPv4 and IPv6 Support
- **Dual-Stack**: Support both IPv4 and IPv6 throughout discovery and transfer
- **UDPv4/UDPv6**: TFTP runs over UDP; ensure lwIP `IPv6` and `UDP` are enabled
- **DHCPv4/DHCPv6**: Acquire network configuration via DHCP for both families
- **Address Selection**: Prefer IPv6 when available; fall back to IPv4
- **TOC URLs**: TOC entries may reference IPv4 or IPv6 hosts; support `tftp://[IPv6]` URLs

### DHCP Options for TFTP
- **DHCPv4 (RFC 2132)**
    - Option 66: TFTP server name (hostname or IP address)
    - Option 67: Bootfile name (path to TOC or image)
    - Optional: Option 43 (Vendor-Specific) for custom parameters
- **DHCPv6 (RFC 5970)**
    - Option 59: Bootfile URL (e.g., `tftp://server/path/to/toc.json`)
    - Option 60: Bootfile Parameters (optional, for additional metadata)
    - Note: DHCPv6 does not define a separate TFTP server option; use Bootfile URL
## Boot Source Provider Interface Design

The Boot Source Provider Interface defines a generic contract for boot image providers, enabling support for multiple boot sources (network boot coprocessor, flash device, or other custom implementations). The MCU ROM communicates with any boot source through this unified interface.

### Core Operations

Boot source providers implement the following core operations:

#### Initialization
- **Source Initialization**: Initialize the boot source and make it ready for image requests
- **Status Discovery**: Determine availability and readiness of the boot source
- **Configuration Discovery**: Discover firmware image metadata and availability

#### Image Provisioning
- **Image Metadata Query**: Query information about available firmware images (size, checksums, etc.)
- **Image Download**: Download firmware images by firmware ID
- **Data Streaming**: Stream image data to the MCU ROM for direct transfer to Caliptra SS

#### Supported Firmware IDs
- **ID 0**: Caliptra FMC+RT image
- **ID 1**: SoC Manifest
- **ID 2**: MCU RT image
- **ID 0x10000000 - 0x1FFFFFFF**: Reserved for SoC Images (range supports up to 268,435,456 distinct SoC image IDs)

### Boot Source Provider Interface

```rust
/// Generic boot source provider interface for the MCU ROM
/// This interface abstracts different boot sources (network, flash, etc.)
pub trait BootSourceProvider {
    type Error;
    
    /// Initialize the boot source
    /// This performs source-specific initialization (e.g., DHCP for network, etc.)
    fn initiate_boot(&mut self) -> Result<BootSourceStatus, Self::Error>;
    
    /// Get information about a firmware image
    fn get_image_metadata(&self, firmware_id: FirmwareId) -> Result<ImageInfo, Self::Error>;
    
    /// Download firmware image by ID
    /// Returns a stream for reading image data in chunks
    fn download_image(&mut self, firmware_id: FirmwareId) -> Result<ImageStream, Self::Error>;
    
    /// Get boot source status and capabilities
    fn get_boot_source_status(&self) -> Result<BootSourceStatus, Self::Error>;

    /// Deinitialize the boot source
    fn finalize(&self) -> Result<BootSourceStatus, Self::Error>;
}

/// Firmware ID enumeration
#[derive(Debug, Clone, Copy)]
pub enum FirmwareId {
    /// Caliptra FMC+RT image
    CaliptraFmcRt = 0,
    /// SoC Manifest
    SocManifest = 1,
    /// MCU RT image
    McuRt = 2,
    /// SoC Image (raw u32 value in range 0x10000000 - 0x1FFFFFFF)
    SocImage(u32),
}

/// Boot source initialization and capability status
#[derive(Debug)]
pub struct BootSourceStatus {
    pub ready: bool,
    pub initialized: bool,
    pub config_available: bool,
    pub available_images: Vec<u32>,
}

/// Metadata for a firmware image
#[derive(Debug, Clone)]
pub struct ImageInfo {
    pub firmware_id: FirmwareId,
    pub size: u64,
    pub checksum: Option<[u8; 32]>,
    pub version: Option<String>,
    pub metadata: Vec<u8>,
}

/// Streaming interface for image data
pub trait ImageStream {
    /// Read next chunk of image data
    fn read_chunk(&mut self, buffer: &mut [u8]) -> Result<usize, Error>;
    
    /// Get total image size if known
    fn total_size(&self) -> Option<u64>;
    
    /// Check if stream is complete
    fn is_complete(&self) -> bool;
}
```

### Implementation Example: Network Boot Coprocessor

For a network boot coprocessor implementation, the boot source provider would:

1. **Initialize**: Perform DHCP discovery, locate TFTP server, download TOC
2. **Get Image Metadata**: Query image metadata from downloaded TOC
3. **Download Image**: Fetch image from TFTP server and stream to MCU ROM

```rust
/// Network-based boot source provider implementation
pub struct NetworkBootSource {
    dhcp_client: DhcpClient,
    tftp_client: TftpClient,
    toc: TableOfContents,
}

impl BootSourceProvider for NetworkBootSource {
    type Error = NetworkBootError;
    
    fn initiate_boot(&mut self) -> Result<BootSourceStatus, Self::Error> {
        // 1. Perform DHCP discovery
        self.dhcp_client.discover()?;
        
        // 2. Download TOC via TFTP
        self.toc = self.tftp_client.download_config()?;
        
        Ok(BootSourceStatus {
            ready: true,
            initialized: true,
            config_available: true,
            available_images: self.toc.firmware_mappings.keys().copied().collect(),
        })
    }
    
    fn get_image_metadata(&self, firmware_id: FirmwareId) -> Result<ImageInfo, Self::Error> {
        let mapping = self.toc.get_mapping(firmware_id)?;
        Ok(ImageInfo {
            firmware_id,
            size: mapping.size,
            checksum: mapping.checksum,
            version: mapping.version.clone(),
        })
    }
    
    fn download_image(&mut self, firmware_id: FirmwareId) -> Result<ImageStream, Self::Error> {
        let mapping = self.toc.get_mapping(firmware_id)?;
        self.tftp_client.get_file(&mapping.filename)
    }
    
    fn get_boot_source_status(&self) -> Result<BootSourceStatus, Self::Error> {
        // Return current network and TFTP status
        Ok(BootSourceStatus {
            ready: self.tftp_client.is_reachable(),
            initialized: true,
            config_available: true,
            available_images: self.toc.firmware_mappings.keys().copied().collect(),
        })
    }

    fn finalize(&self) -> Result<BootSourceStatus, Self::Error> {
        Ok(BootSourceStatus::Success)
    }
}
```

### Usage Example

```rust
// Example: MCU ROM boot process using generic boot source
fn perform_boot_from_source(mut boot_source: &mut dyn BootSourceProvider) -> Result<(), Error> {
    // 1. Initialize boot source
    let status = boot_source.initiate_boot()?;
    
    if !status.ready || !status.initialized {
        return Err(Error::BootSourceNotAvailable);
    }
    
    // 2. Download each firmware image
    for firmware_id in [FirmwareId::CaliptraFmcRt, FirmwareId::SocManifest, FirmwareId::McuRt] {
        // Get image metadata
        let image_info = boot_source.get_image_metadata(firmware_id)?;
        
        // Set up recovery interface with image size
        set_recovery_image_size(image_info.size)?;
        
        // Download image
        let mut stream = boot_source.download_image(firmware_id)?;
        
        // Stream image chunks to recovery interface
        load_image_stream(stream, ImageDestination::Recovery)?;
    }
    
    // 3. Finalize recovery
    boot_source.finalize()?;
    
    Ok(())
}

fn load_image_stream(mut stream: ImageStream, dest: ImageDestination) -> Result<(), Error> {
    let mut buffer = [0u8; 4096];
    while !stream.is_complete() {
        let bytes_read = stream.read_chunk(&mut buffer)?;
        if bytes_read > 0 {
            write_image_chunk(dest, &buffer[..bytes_read])?;
        }
    }
    Ok(())
}
```

### Configuration File Format (TOC - Table of Contents)

The network boot coprocessor downloads a configuration file (TOC) that maps firmware IDs to filenames and metadata:

```json
{
  "firmware_mappings": {
    "0": { "filename": "caliptra-fmc-rt.bin", "size": 1048576 },
    "1": { "filename": "soc-manifest.bin", "size": 65536 },
    "2": { "filename": "mcu-runtime.bin", "size": 262144 },
    "268435456": { "filename": "soc-pci-device.bin", "size": 524288, "component_id": 1 },
    "268435457": { "filename": "soc-nvme-device.bin", "size": 262144, "component_id": 2 },
    "268435458": { "filename": "soc-security-engine.bin", "size": 131072, "component_id": 3 }
  }
}
```

**Notes**:
- Firmware IDs 0-2 are reserved for early boot firmware
- SoC image IDs use the range `0x10000000` (268435456 in decimal) and above
- Each SoC image entry includes an optional `component_id` field used for authorization with Caliptra
- The `filename` field specifies the TFTP path relative to the TFTP server root

## MCU and Network ROM Interface

The interface between the MCU and Network ROM is integrator defined.

For emulation purposes, a sample interprocess communication interface will be provided that uses a **shared external memory** and **memory-mapped registers** for synchronization. This section defines a generic message-passing interface that allows the MCU and Network ROM to exchange arbitrary messages.

### Architecture Overview

The MCU and Network ROM share a contiguous region of external memory organized as follows:

```
┌────────────────────────────────────────────┐
│ Shared External Memory (MCU ↔ Network ROM) │
├────────────────────────────────────────────┤
│ Synchronization Registers (256 bytes)      │ ← Memory-mapped control registers
├────────────────────────────────────────────┤
│ Shared Message Buffer (8 KB)               │ ← Bidirectional message buffer
├────────────────────────────────────────────┤
│ Reserved for Future Use                    │
└────────────────────────────────────────────┘
```

**Note**: Since communication is one-way at a time (either MCU → Network ROM or Network ROM → MCU), a single message buffer is sufficient. The LOCK bit in the control register ensures exclusive access.

### Synchronization Registers

Memory-mapped registers enable notification and handshaking between MCU and Network ROM. The LOCK bit provides mutual exclusion similar to mailbox designs.

**Synchronization Register Layout (at base address `SHM_BASE`):**

```
Offset  Size  Name                          Description
------  ----  ----                          -----------
0x00    4     CTRL                          Control and status flags
0x04    4     MSG_SIZE                      Size of message payload in bytes
0x08    4     MSG_OFFSET                    Offset of message in shared buffer (typically 0)
0x0C    4     SEQUENCE                      Sequence counter for message ordering
0x10    4     INTERRUPT_ENABLE              Interrupt enable bits
0x14    4     INTERRUPT_STATUS              Interrupt/event status bits
0x18    4     ERROR_CODE                    Last error code (if applicable)
0x1C    4     RESERVED                      For future use
0x20    4     RESERVED                      For future use
0x24    4     RESERVED                      For future use
```

**Control Register (CTRL) Bit Fields:**

```
Bit     Name                Description
---     ----                -----------
[0]     LOCK                Mailbox lock (1=locked, 0=unlocked)
                            - Sender acquires lock before writing message
                            - Receiver releases lock after reading message
[1]     DATA_READY          Message ready to process (set by sender after lock acquired)
[2]     ERROR               Error occurred during processing
[3]     DIRECTION           Message direction (0=MCU→Network ROM, 1=Network ROM→MCU)
[4:31]  RESERVED            Reserved for future use
```

### Message Passing Protocol

The protocol uses a LOCK-based mechanism for mutual exclusion, similar to mailbox designs. Since communication is one-way at a time, a single shared buffer serves both directions.

#### Sending a Message

**Sender Side (MCU or Network ROM):**
1. Acquire lock: Write `1` to `CTRL[LOCK]` and verify it reads back as `1`
   - If lock acquisition fails (reads `0`), retry or wait
2. Set direction bit: `CTRL[DIRECTION]` = `0` (MCU→Network ROM) or `1` (Network ROM→MCU)
3. Write message to shared buffer at offset `MSG_OFFSET` (typically 0)
4. Update `MSG_SIZE` with actual message size in bytes
5. Increment `SEQUENCE` counter for message ordering
6. Set `CTRL[DATA_READY]` to `1` to signal message is ready
7. Generate interrupt/notification (optional, implementation-dependent)
8. Keep lock held until receiver acknowledges

**Receiver Side (Network ROM or MCU):**
1. Poll or wait for `CTRL[DATA_READY]` to be set
2. Verify `CTRL[DIRECTION]` matches expected direction
3. Read message size from `MSG_SIZE`
4. Read message from shared buffer at offset `MSG_OFFSET`
5. Process message
6. Clear `CTRL[DATA_READY]` to acknowledge receipt
7. Release lock: Write `0` to `CTRL[LOCK]`

#### Request-Response Pattern

For request-response communication:

1. **Request**: Sender acquires lock, sends request, waits for response with lock held
2. **Response**: Receiver processes request, writes response to same buffer, sets `DATA_READY`, releases lock
3. **Completion**: Original sender reads response, clears `DATA_READY`, releases lock

**Alternative (Lock Handoff)**:
1. **Request**: Sender acquires lock, sends request, releases lock
2. **Response**: Receiver waits for lock, acquires it, sends response
3. **Completion**: Original sender waits for lock, reads response, releases lock

### Example: Full MCU Message Handler

```rust
use portable_atomic::{AtomicU32, Ordering};
use heapless::Vec;

const SHM_BASE: usize = 0x50000000;
const MSG_BUFFER_OFFSET: usize = 0x100;  // Offset to shared message buffer
const BUFFER_SIZE: usize = 8192;          // 8 KB shared buffer

// Register offsets
const CTRL_REG: usize = 0x00;
const MSG_SIZE_REG: usize = 0x04;
const MSG_OFFSET_REG: usize = 0x08;
const SEQUENCE_REG: usize = 0x0C;

// Control register bit masks
const CTRL_LOCK: u32 = 1 << 0;
const CTRL_DATA_READY: u32 = 1 << 1;
const CTRL_ERROR: u32 = 1 << 2;
const CTRL_DIRECTION: u32 = 1 << 3;  // 0=MCU→Net, 1=Net→MCU

pub struct NetworkRomInterface {
    base: *const u32,
}

unsafe impl Send for NetworkRomInterface {}
unsafe impl Sync for NetworkRomInterface {}

impl NetworkRomInterface {
    pub fn new(base: usize) -> Self {
        Self {
            base: base as *const u32,
        }
    }
    
    fn read_register(&self, offset: usize) -> u32 {
        unsafe { core::ptr::read_volatile(self.base.add(offset / 4)) }
    }
    
    fn write_register(&self, offset: usize, value: u32) {
        unsafe { core::ptr::write_volatile(self.base.add(offset / 4) as *mut u32, value) }
    }
    
    /// Acquire the mailbox lock
    fn acquire_lock(&self) -> Result<(), &'static str> {
        // Attempt to acquire lock
        self.write_register(CTRL_REG, CTRL_LOCK);
        
        // Verify lock was acquired
        let ctrl = self.read_register(CTRL_REG);
        if ctrl & CTRL_LOCK != 0 {
            Ok(())
        } else {
            Err("Failed to acquire lock")
        }
    }
    
    /// Release the mailbox lock
    fn release_lock(&self) {
        let ctrl = self.read_register(CTRL_REG);
        self.write_register(CTRL_REG, ctrl & !CTRL_LOCK);
    }
    
    /// Send a message to the Network ROM
    pub fn send_message(&self, msg: &[u8]) -> Result<(), &'static str> {
        // Acquire lock with retry
        loop {
            if self.acquire_lock().is_ok() {
                break;
            }
            core::hint::spin_loop();
        }
        
        // Set direction: MCU → Network ROM
        let mut ctrl = self.read_register(CTRL_REG);
        ctrl &= !CTRL_DIRECTION;  // Clear direction bit
        self.write_register(CTRL_REG, ctrl);
        
        // Write message to shared buffer
        let base_ptr = (SHM_BASE + MSG_BUFFER_OFFSET) as *mut u8;
        unsafe {
            core::ptr::copy_nonoverlapping(
                msg.as_ptr(),
                base_ptr,
                msg.len().min(BUFFER_SIZE),
            );
        }
        
        // Update message size and sequence
        self.write_register(MSG_SIZE_REG, msg.len() as u32);
        let seq = self.read_register(SEQUENCE_REG);
        self.write_register(SEQUENCE_REG, seq.wrapping_add(1));
        
        // Signal data ready
        ctrl = self.read_register(CTRL_REG);
        self.write_register(CTRL_REG, ctrl | CTRL_DATA_READY);
        
        Ok(())
    }
    
    /// Receive a message from the Network ROM
    pub fn receive_message(&self) -> Result<Vec<u8, 8192>, &'static str> {
        // Wait for data ready with expected direction (Network ROM → MCU)
        loop {
            let ctrl = self.read_register(CTRL_REG);
            if (ctrl & CTRL_DATA_READY != 0) && (ctrl & CTRL_DIRECTION != 0) {
                break;
            }
            core::hint::spin_loop();
        }
        
        // Read message size
        let size = self.read_register(MSG_SIZE_REG) as usize;
        
        // Read message from shared buffer
        let base_ptr = (SHM_BASE + MSG_BUFFER_OFFSET) as *const u8;
        let mut msg = Vec::new();
        unsafe {
            let slice = core::slice::from_raw_parts(base_ptr, size);
            msg.extend_from_slice(slice).map_err(|_| "Buffer overflow")?;
        }
        
        // Clear data ready flag
        let ctrl = self.read_register(CTRL_REG);
        self.write_register(CTRL_REG, ctrl & !CTRL_DATA_READY);
        
        // Release lock
        self.release_lock();
        
        Ok(msg)
    }
}
```

## Network Stack Implementation

For the Network Boot Coprocessor implementation, we use **lwIP (Lightweight IP)** with Rust bindings/wrappers to support DHCP and TFTP while meeting ROM environment constraints.

### lwIP (Lightweight IP) with Rust Bindings

**Repository**: https://git.savannah.nongnu.org/cgit/lwip.git (upstream C)  
**Rust Bindings**: https://github.com/embassy-rs/lwip (Embassy lwIP bindings)  

**Description**: Mature, lightweight TCP/IP stack originally written in C with Rust FFI bindings.

**Advantages**:
- ✅ **Built-in DHCP and TFTP Support**: Native support for required protocols
- ✅ **Mature and Battle-Tested**: Currently used by u-boot and other embedded systems
- ✅ **Minimal Configuration**: Can be configured for UDP-only operation
- ✅ **Proven in Production**: Field-tested in hyperscale deployments and firmware boot scenarios

**Required Protocol Support**:
- ✅ DHCP client
- ✅ TFTP client
- ✅ UDP sockets



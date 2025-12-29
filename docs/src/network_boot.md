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

### Potential Solution
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

        Caliptra <--> RecoveryIF
        RecoveryIF <--> MCU_ROM
    end

    MCU_ROM <--> Network_ROM["Network ROM<br/>- DHCP<br/>- TFTP Client<br/>- FW ID Mapping"]
    Network_ROM <--> Image_Server["Image Server<br/>- Image Store<br/>- DHCP<br/>- TFTP Server<br/>- Config File"]
```

## Network Recovery Boot Flow

The following diagram illustrates the high-level flow using the `BootSourceProvider` interface, showing how `initialize()` drives DHCP and TOC fetch:

```mermaid
sequenceDiagram
    participant CRIF as Caliptra Recovery I/F
    participant MCU as MCU ROM
    participant NET as Network ROM (BootSourceProvider)
    participant IMG as Image Server

    MCU->>NET: initialize()
    NET->>IMG: DHCP Discovery
    IMG-->>NET: DHCP Offer
    NET->>IMG: TFTP GET config (TOC)
    IMG-->>NET: TOC
    NET-->>MCU: BootSourceStatus { ready=true, config_available=true }
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

        MCU->>NET: get_image_info(id)
        NET-->>MCU: ImageInfo { size, checksum, version }

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
```

## Messaging Protocol

The network boot system uses a simple messaging protocol between the MCU ROM and Network ROM:

| Message | Direction | Fields | Purpose |
|-------|----------|--------|----------|
| Network Boot Discovery | MCU → Network ROM | — | Start network boot |
| Image Info Request | MCU → Network ROM | firmware_id | Query image metadata |
| Image Download Request | MCU → Network ROM | firmware_id | Start transfer |
| Chunk ACK | MCU → Network ROM | firmware_id, offset | Flow control |
| Boot Complete / Error | MCU → Network ROM | status, error_code | Completion |

## Protocol Support

The network boot coprocessor supports a minimal set of protocols optimized for the Caliptra ROM environment:
## Messaging Protocol

The boot source provider communication uses a simple request-response messaging protocol. The following section defines the message types, packet formats, and field definitions.

### Message Types and Packet Formats

#### 1. Network Boot Discovery Request
Initiates the boot source discovery process.

**Request Packet:**
```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     Message Type       0x01 - Network Boot Discovery
1       3     Reserved           Must be 0
4       4     Protocol Version   Version of the messaging protocol
8       N     Source Specific    Source-specific initialization parameters
```

**Response Packet:**
```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     Message Type       0x81 - Discovery Response
1       1     Status             0x00=Success, non-zero=Error
2       2     Reserved           Must be 0
4       4     Available Images   Bitmask of available firmware images
8       4     Config Version     Version of the configuration/TOC
12      4     Reserved           For future use
16      N     Source Specific    Source-specific response data
```

#### 2. Image Info Request
Queries metadata about a specific firmware image.

**Request Packet:**
```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     Message Type       0x02 - Image Info Request
1       1     Firmware ID        0=CaliptraFmcRt, 1=SocManifest, 2=McuRt
2       2     Reserved           Must be 0
4       4     Request Flags      Bit 0: Request checksum
8       4     Reserved           For future use
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
56      8     Metadata           Flexible metadata field for extensions
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
4       4     Offset             Starting byte offset (for resumable transfers)
8       4     Max Chunk Size     Maximum chunk size in bytes (0=default)
12      4     Flags              Bit 0: Verify checksum, Bit 1: Compression
16      4     Timeout            Transfer timeout in milliseconds
```

**Response Packet (per chunk):**
```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     Message Type       0x83 - Image Chunk
1       1     Status             0x00=Success, non-zero=Error
2       2     Sequence Number    For ordered delivery
4       4     Offset             Current byte offset in image
8       4     Chunk Size         Size of data in this chunk
12      4     Total Size         Total image size (0 if unknown)
16      4     Checksum           CRC32 of this chunk (optional)
20      N     Image Data         Chunk payload (size = Chunk Size field)
```

#### 4. Chunk Acknowledgment
Acknowledges receipt of an image chunk and provides flow control.

**Request Packet:**
```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     Message Type       0x04 - Chunk ACK
1       1     Firmware ID        Firmware being transferred
2       2     Reserved           Must be 0
4       4     Offset             Byte offset of last received chunk
8       4     Flags              Bit 0: Ready for next, Bit 1: Error detected
12      4     Reserved           For future use
```

**Response Packet:**
```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     Message Type       0x84 - ACK Response
1       1     Status             0x00=Continue, 0x01=End of transfer, non-zero=Error
2       2     Reserved           Must be 0
4       4     Next Offset        Offset for next chunk (can resume)
8       4     Reserved           For future use
```

#### 5. Boot Complete / Recovery Status
Notifies the boot source of recovery completion or error.

**Request Packet:**
```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     Message Type       0x05 - Recovery Complete
1       1     Status             0x00=Success, non-zero=Error
2       2     Error Code         Specific error code if Status != 0
4       4     Images Processed   Bitmask of successfully received images
8       4     Validation Result  0=Valid, non-zero=Invalid
12      4     Reserved           For future use
```

**Response Packet:**
```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     Message Type       0x85 - Recovery ACK
1       1     Status             0x00=Acknowledged, non-zero=Error
2       2     Reserved           Must be 0
4       4     Cleanup Flags      Bit 0: Clear TOC, Bit 1: Reset connection
8       4     Reserved           For future use
```

### Message Summary Table

| Message Type | Code | Direction | Purpose |
|-------|------|-----------|---------|
| Network Boot Discovery Request | 0x01 | MCU → Source | Initiate boot source discovery |
| Network Boot Discovery Response | 0x81 | Source → MCU | Confirm discovery and image availability |
| Image Info Request | 0x02 | MCU → Source | Query image metadata |
| Image Info Response | 0x82 | Source → MCU | Return image metadata and checksums |
| Image Download Request | 0x03 | MCU → Source | Start image transfer |
| Image Chunk | 0x83 | Source → MCU | Send image data chunk |
| Chunk ACK | 0x04 | MCU → Source | Acknowledge chunk and flow control |
| Chunk ACK Response | 0x84 | Source → MCU | Ready for next chunk or end transfer |
| Recovery Complete | 0x05 | MCU → Source | Notify recovery completion/error |
| Recovery ACK | 0x85 | Source → MCU | Final acknowledgment |

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

### Boot Source Provider Interface

```rust
/// Generic boot source provider interface for the MCU ROM
/// This interface abstracts different boot sources (network, flash, etc.)
pub trait BootSourceProvider {
    type Error;
    
    /// Initialize the boot source
    /// This performs source-specific initialization (e.g., DHCP for network, etc.)
    fn initialize(&mut self) -> Result<BootSourceStatus, Self::Error>;
    
    /// Get information about a firmware image
    fn get_image_info(&self, firmware_id: FirmwareId) -> Result<ImageInfo, Self::Error>;
    
    /// Download firmware image by ID
    /// Returns a stream for reading image data in chunks
    fn download_image(&mut self, firmware_id: FirmwareId) -> Result<ImageStream, Self::Error>;
    
    /// Get boot source status and capabilities
    fn get_boot_source_status(&self) -> Result<BootSourceStatus, Self::Error>;
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
}

/// Boot source initialization and capability status
#[derive(Debug)]
pub struct BootSourceStatus {
    pub ready: bool,
    pub initialized: bool,
    pub config_available: bool,
    pub available_images: u32,
}

/// Metadata for a firmware image
#[derive(Debug, Clone)]
pub struct ImageInfo {
    pub firmware_id: FirmwareId,
    pub size: u64,
    pub checksum: Option<[u8; 32]>,
    pub version: Option<String>,
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
2. **Get Image Info**: Query image metadata from downloaded TOC
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
    
    fn initialize(&mut self) -> Result<BootSourceStatus, Self::Error> {
        // 1. Perform DHCP discovery
        self.dhcp_client.discover()?;
        
        // 2. Download TOC via TFTP
        self.toc = self.tftp_client.download_config()?;
        
        Ok(BootSourceStatus {
            ready: true,
            initialized: true,
            config_available: true,
            available_images: self.toc.firmware_mappings.len() as u32,
        })
    }
    
    fn get_image_info(&self, firmware_id: FirmwareId) -> Result<ImageInfo, Self::Error> {
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
            available_images: self.toc.firmware_mappings.len() as u32,
        })
    }
}
```

### Usage Example

```rust
// Example: MCU ROM boot process using generic boot source
fn perform_boot_from_source(mut boot_source: &mut dyn BootSourceProvider) -> Result<(), Error> {
    // 1. Initialize boot source
    let status = boot_source.initialize()?;
    
    if !status.ready || !status.initialized {
        return Err(Error::BootSourceNotAvailable);
    }
    
    // 2. Download each firmware image
    for firmware_id in [FirmwareId::CaliptraFmcRt, FirmwareId::SocManifest, FirmwareId::McuRt] {
        // Get image metadata
        let image_info = boot_source.get_image_info(firmware_id)?;
        
        // Set up recovery interface with image size
        set_recovery_image_size(image_info.size)?;
        
        // Download image
        let mut stream = boot_source.download_image(firmware_id)?;
        
        // Stream image chunks to recovery interface
        load_image_stream(stream, ImageDestination::Recovery)?;
    }
    
    // 3. Finalize recovery
    finalize_recovery()?;
    
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
    "2": { "filename": "mcu-runtime.bin", "size": 262144 }
  }
}
```

## Implementation Timeline (lwIP, ~10 weeks)

- **Weeks 1–2: Scope & Interfaces** — Finalize boot-source provider trait + C FFI surface; define lwIP raw API use (UDP, DHCP) and TFTP shim; choose buffer/allocator model; error mapping and protocol alignment.
- **Weeks 3–4: Build & Platform Bring-up** — Cross-compile lwIP minimal config (UDP-only, DHCP, raw API); build scripts + bindgen; validate lwIP init + DHCP in emulator/target; stub TFTP hooks.
- **Weeks 5–6: TFTP Client Path** — Implement/adapt minimal TFTP client on lwIP raw API; Rust wrapper for TFTP GET with chunk callbacks; end-to-end path in emu (DHCP → TOC TFTP GET → chunk delivery).
- **Weeks 7–8: Boot Source Integration** — Implement `BootSourceProvider` (network) with TOC parsing, get_image_info, download_image streaming; wire chunk flow into recovery interface (INDIRECT_FIFO_CTRL writes, ACKs); retries/timeouts and error mapping.
- **Week 9: Robustness & Footprint** — Trim lwIP config, buffer sizing, watchdog hooks; resume offsets, per-chunk CRC checks; memory audit for ROM limits.
- **Week 10: Testing & Hardening** — Automated emu tests (DHCP fail, TFTP retry, checksum mismatch, timeout, negative parsing); throughput/latency tuning; finalize docs on FFI boundary, init order, buffers; integrate into ROM build/linker; hardware bring-up checklist.

### Emulation & Image Server Tasks
- Provide a reproducible Image Server (container) with DHCP + TFTP + TOC hosting; fixtures for FMC/RT, SoC manifest, MCU RT images.
- Emulator harness to run full flow: boot → DHCP → TOC fetch → per-image TFTP GET → chunk ACKs → finalize.
- Scenario tests: no-DHCP, DHCP with wrong options, missing TOC, missing image, checksum mismatch, chunk loss/retry, offset resume.
- Latency/jitter profiles to tune timeouts and chunk sizes; MTU variation.
- CI hook to spin the image-server container and run regression suites.

## Network Stack Implementation

For the Network Boot Coprocessor implementation, we need a minimal network stack that supports DHCP and TFTP while meeting the constraints of a ROM environment.

### Option 1: lwIP (Lightweight IP) with Rust Bindings

**Repository**: https://git.savannah.nongnu.org/cgit/lwip.git (upstream C)  
**Rust Bindings**: https://github.com/embassy-rs/lwip (Embassy lwIP bindings)  

**Description**: Mature, lightweight TCP/IP stack originally written in C with Rust FFI bindings.

**Advantages**:
- ✅ **Built-in DHCP and TFTP Support**: Native support for required protocols
- ✅ **Mature and Battle-Tested**: Currently used by u-boot and other embedded systems
- ✅ **Minimal Configuration**: Can be configured for UDP-only operation

**Disadvantages**:
- ❌ **C Language Security Risks**: Inherits buffer overflow and memory safety vulnerabilities from C
- ❌ **FFI Complexity**: Rust-C interop adds complexity and potential for safety violations

**Required Protocol Support**:
- ✅ DHCP client
- ✅ TFTP client
- ✅ UDP sockets

### Option 2: smoltcp + Custom TFTP

**Core**: https://github.com/smoltcp-rs/smoltcp (0BSD License)  
**TFTP**: Custom implementation on UDP

**Description**: Pure Rust network stack with custom TFTP implementation for minimal footprint.

**Advantages**:
- ✅ **Memory Safety**: Pure Rust eliminates entire classes of security vulnerabilities
- ✅ **ROM Optimized**: Minimal footprint with only required features included
- ✅ **Modular Design**: Include only DHCP and TFTP to minimize code size
- ✅ **No FFI Overhead**: Native Rust performance without C interop costs
- ✅ **Strong Type Safety**: Compile-time prevention of many networking bugs
- ✅ **Excellent Licensing**: 0BSD license is very permissive

**Disadvantages**:
- ❌ **Custom TFTP Implementation**: Must implement TFTP protocol from scratch
- ❌ **Less Battle-Tested**: Newer ecosystem compared to lwIP

**Required Protocol Support**:
- ✅ UDP sockets (smoltcp)
- ✅ DHCP client (smoltcp) 
- ⚠️ TFTP (custom implementation required)

### Recommended Approach

**For Production Caliptra System**: **smoltcp + Custom TFTP**

**Rationale**:
- **Security First**: Memory safety is critical for Root of Trust systems
- **ROM Constraints**: Minimal footprint with only DHCP and TFTP support
- **Simplicity**: Reduced complexity with only essential protocols
- **Control**: Custom TFTP implementation allows Caliptra-specific optimizations

**Implementation Strategy**:
1. **Phase 1**: Implement core UDP networking with smoltcp
2. **Phase 2**: Add DHCP client functionality  
3. **Phase 3**: Implement lightweight TFTP client for firmware downloads

**Protocol Implementation Order**:
1. **UDP Sockets**: Foundation for all network communication
2. **DHCP Client**: Automatic network configuration
3. **TFTP Client**: Firmware image download capability



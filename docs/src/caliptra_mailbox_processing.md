# Caliptra Mailbox Command Processing

MCU runtime communicates with Caliptra Core through the memory-mapped Caliptra
mailbox. On main-2.1, requests larger than the Caliptra subsystem mailbox use
the DMA-accessible external staging SRAM for their payload. The Caliptra mailbox
then carries only an `ExternalMailboxCmdReq` wrapper that identifies the
original command and describes the external payload.

The Caliptra mailbox SRAM shown below is distinct from the MCU mailbox SRAM used
by external SoC agents to send commands to MCU runtime.

## Large Request Example: SET_AUTH_MANIFEST

```mermaid
sequenceDiagram
    autonumber
    participant MCU_RT as MCU RT
    participant MBox as Caliptra Mailbox<br/>CSR, FSM, and SRAM
    participant ExtSRAM as External Staging SRAM
    participant Caliptra as Caliptra Core

    MCU_RT->>MCU_RT: Build SET_AUTH_MANIFEST header and stream
    MCU_RT->>MCU_RT: Calculate inner request checksum
    Note over MCU_RT: Request exceeds the subsystem mailbox size

    loop 256-byte userspace chunks
        MCU_RT->>ExtSRAM: DMA-copy request bytes at the next offset
    end
    MCU_RT->>MCU_RT: Build ExternalMailboxCmdReq wrapper
    Note over MCU_RT: Wrapper contains SET_AUTH_MANIFEST ID,<br/>request length, and staging SRAM AXI address
    MCU_RT->>MCU_RT: Calculate wrapper checksum

    MCU_RT->>MBox: Read MBOX_LOCK to acquire lock
    MCU_RT->>MBox: Set command to EXTERNAL_MAILBOX_CMD
    MCU_RT->>MBox: Write wrapper and set execute
    MBox-->>Caliptra: Notify command available

    Caliptra->>MBox: Read and validate wrapper
    Caliptra->>ExtSRAM: DMA-read inner request using AXI address and length
    Caliptra->>Caliptra: Validate inner request checksum
    Caliptra->>Caliptra: Dispatch SET_AUTH_MANIFEST
    Caliptra->>Caliptra: Parse and verify authorization manifest
    Caliptra->>Caliptra: Install validated image metadata

    Caliptra->>MBox: Write checksummed response and DataReady status
    MBox-->>MCU_RT: Command no longer busy
    MCU_RT->>MBox: Read and validate response
    MCU_RT->>MBox: Clear execute and release mailbox lock
    MCU_RT->>MCU_RT: Complete the waiting userspace request
```

For requests that fit in the Caliptra subsystem mailbox, MCU runtime skips the
external staging path and writes the original command payload directly to the
Caliptra mailbox SRAM. The response path is the same in both cases.
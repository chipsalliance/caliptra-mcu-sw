# Proposal: Chunked Caliptra Mailbox Passthrough over MCTP VDM

## Problem Statement

The MCTP VDM transport path from `caliptra-util-host` needs to support the
Production Auth Debug Unlock Token command (`ProdDebugUnlockToken` / 0x7011).
This command requires sending a `ProductionAuthDebugUnlockToken` payload that is
approximately **7,516 bytes** in size (header + ECC public key + ML-DSA-87
public key + ECC signature + ML-DSA-87 signature).

The current MCTP stack limits messages to **2,048 bytes**
(`MCTP_MAX_MESSAGE_SIZE` in `runtime/kernel/capsules/src/mctp/driver.rs`). The
token payload exceeds this limit by a factor of ~3.7×, making it impossible to
deliver via a single MCTP message.

## Current MCTP Buffer Architecture

Each MCTP driver instance allocates **3 buffers** of `MCTP_MAX_MESSAGE_SIZE`:

| Buffer            | Purpose                                              |
|-------------------|------------------------------------------------------|
| `rx_msg_buf`      | Assembles incoming multi-packet messages              |
| `tx_msg_buf`      | Holds the outgoing message during packetization       |
| `buffered_rx_msg` | Buffers a completed message awaiting userspace pickup |

The emulator platform has **3 active MCTP driver instances** (SPDM, PLDM,
Caliptra VDM), totaling **9 buffers × 2,048 = 18,432 bytes** of kernel SRAM
dedicated to MCTP.

## Why Increasing `MCTP_MAX_MESSAGE_SIZE` Is Not Viable

To accommodate the ~7.5 KB token, `MCTP_MAX_MESSAGE_SIZE` would need to increase
to at least **8,192 bytes** (4× the current value). The impact:

| Metric                        | Current (2,048) | Proposed (8,192) | Delta     |
|-------------------------------|-----------------|------------------|-----------|
| Buffers per driver instance   | 3 × 2,048       | 3 × 8,192        | +18,432   |
| Total kernel MCTP buffers (3) | 18,432 bytes    | 73,728 bytes     | +55,296   |
| Total kernel MCTP buffers (4) | 24,576 bytes    | 98,304 bytes     | +73,728   |

This increase has been tested and results in:

1. **Kernel data exceeds SRAM allocation** — the user-app process fails to load
   with `Bytes 135168 would exceed remaining memory space 131072`.
2. **PMP (Physical Memory Protection) faults** — increasing SRAM to compensate
   causes `StoreFault` exceptions because the locked PMP entries do not cover
   the extended memory region.
3. **Global impact** — all MCTP driver instances (SPDM, PLDM, VDM) grow equally,
   even though only VDM needs the larger buffer. There is no mechanism to set
   per-instance buffer sizes.
4. **Only one command needs it** — the debug unlock token is the only payload
   that exceeds 2 KB. Permanently quadrupling all MCTP buffers for a single
   command is wasteful.

## Proposed Solution: Chunked Caliptra Mailbox Passthrough

Instead of buffering the entire payload in the MCTP layer, introduce a
**three-command protocol** that streams payload chunks directly into the Caliptra
mailbox SRAM, bypassing the MCTP message buffer entirely.

### New VDM Commands

| VDM Command Code | Name                        | Direction | Purpose                                         |
|-------------------|-----------------------------|-----------|--------------------------------------------------|
| `0x0C`            | `InitiateCptraMboxCmd`      | Request   | Lock the Caliptra mailbox and set the command ID |
| `0x0D`            | `SendCptraMboxPayloadChunk` | Request   | Write a chunk of payload into the mailbox SRAM   |
| `0x0E`            | `ExecCptraMboxCmd`          | Request   | Execute the mailbox command and return response  |

### Protocol Flow

```
Host (caliptra-util-host)                 MCU (VDM cmd_interface)
    │                                          │
    │  InitiateCptraMboxCmd(caliptra_cmd_id)   │
    │─────────────────────────────────────────►│
    │                                          │  Lock Caliptra mailbox
    │                                          │  Write command ID
    │  completion_code = SUCCESS               │
    │◄─────────────────────────────────────────│
    │                                          │
    │  SendCptraMboxPayloadChunk(data)         │
    │─────────────────────────────────────────►│
    │                                          │  Append data to mbox SRAM
    │  completion_code = SUCCESS               │
    │◄─────────────────────────────────────────│
    │                                          │
    │  SendCptraMboxPayloadChunk(data)         │  (repeat for each chunk)
    │─────────────────────────────────────────►│
    │  completion_code = SUCCESS               │
    │◄─────────────────────────────────────────│
    │                                          │
    │  ExecCptraMboxCmd(total_length)          │
    │─────────────────────────────────────────►│
    │                                          │  Set data length
    │                                          │  Execute command
    │                                          │  Read response
    │  completion_code + response_payload      │
    │◄─────────────────────────────────────────│
```

### Message Formats

#### InitiateCptraMboxCmd Request (0x0C)

```
┌──────────────────────────┬───────┐
│ VdmMsgHeader (4 bytes)   │       │
├──────────────────────────┤       │
│ caliptra_cmd_id (u32)    │ 8 B   │
└──────────────────────────┴───────┘
```

#### InitiateCptraMboxCmd Response

```
┌──────────────────────────┬───────┐
│ VdmMsgHeader (4 bytes)   │       │
├──────────────────────────┤       │
│ completion_code (u32)    │ 8 B   │
└──────────────────────────┴───────┘
```

#### SendCptraMboxPayloadChunk Request (0x0D)

```
┌──────────────────────────┬─────────────┐
│ VdmMsgHeader (4 bytes)   │             │
├──────────────────────────┤             │
│ data (variable, ≤ 2000 B)│ 4 + N bytes │
└──────────────────────────┴─────────────┘
```

Chunks are appended sequentially to the mailbox SRAM in the order they
are received. The chunk size must fit within a single MCTP message
(`MCTP_MAX_MESSAGE_SIZE` minus MCTP/VDM overhead ≈ 2,000 bytes usable).

#### SendCptraMboxPayloadChunk Response

```
┌──────────────────────────┬───────┐
│ VdmMsgHeader (4 bytes)   │       │
├──────────────────────────┤       │
│ completion_code (u32)    │ 8 B   │
└──────────────────────────┴───────┘
```

#### ExecCptraMboxCmd Request (0x0E)

```
┌──────────────────────────┬────────┐
│ VdmMsgHeader (4 bytes)   │        │
├──────────────────────────┤        │
│ total_length (u32)       │ 8 B    │
└──────────────────────────┴────────┘
```

#### ExecCptraMboxCmd Response

```
┌──────────────────────────┬──────────────┐
│ VdmMsgHeader (4 bytes)   │              │
├──────────────────────────┤              │
│ completion_code (u32)    │ 8 + N bytes  │
├──────────────────────────┤              │
│ response_data (variable) │              │
└──────────────────────────┴──────────────┘
```

### Advantages

1. **No MCTP buffer increase required** — each individual chunk fits within the
   existing 2,048-byte message limit.
2. **Generic** — supports any Caliptra mailbox command, not just debug unlock.
   Future large-payload commands (e.g., firmware update, certificate provisioning)
   work without protocol changes.
3. **Minimal kernel impact** — no changes to `MCTP_MAX_MESSAGE_SIZE`, PMP
   configuration, or SRAM layout.
4. **Caliptra mailbox is the buffer** — the mailbox SRAM (128 KB) absorbs the
   payload directly; no intermediate copy needed.
5. **Transport-agnostic design** — the chunking is at the VDM command level, so
   the same approach works regardless of the underlying MCTP transport binding
   (I3C, PCIe, etc.).

### Implementation Scope

| Layer             | Changes Required                                              |
|-------------------|---------------------------------------------------------------|
| `mctp-vdm-common` | Add 3 new message types and VDM command codes (0x0C–0x0E)     |
| `mctp-vdm-lib`    | Add 3 new handlers in `cmd_interface.rs` using direct mailbox syscalls |
| `caliptra-util-host` transport | Add encode/decode handlers and dispatch entries |
| `caliptra-util-host` client    | Add `send_caliptra_mailbox_cmd()` helper that chunks automatically |
| Integration test  | Update VDM validator to use chunked path for debug unlock token |

### Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Mailbox held across multiple MCTP round-trips | Add a timeout; `ExecCptraMboxCmd` releases the lock on completion or error |
| Chunk arrives out of order | Chunks are strictly sequential; MCU tracks the write offset internally |
| Concurrent VDM clients | Mailbox lock ensures serialization; second `InitiateCptraMboxCmd` returns BUSY |
| Partial transfer (client disconnects) | Watchdog timer on MCU releases the mailbox if `ExecCptraMboxCmd` is not received within N seconds |

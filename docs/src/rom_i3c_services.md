# ROM I3C Services

The ROM provides an optional I3C services mode where the MCU enters a
command/response loop over the I3C Target Transaction Interface (TTI). A BMC or
other I3C controller sends commands as private writes; the MCU responds via
In-Band Interrupts (IBI) with inline payload data.

## Entering I3C Services

I3C services are gated by the `RomParameters` supplied by the platform:

| Parameter | Type | Description |
|-----------|------|-------------|
| `i3c_services` | `Option<I3cServicesModes>` | Bitmask of enabled service modes. `None` disables all I3C services. |
| `force_i3c_services` | `bool` | When `true`, the ROM enters I3C services unconditionally during cold boot, regardless of trigger conditions. |

### Trigger Conditions

The ROM enters I3C services when **any** of the following are true:

1. **`force_i3c_services` is set** — the ROM enters I3C services unconditionally
   after the Device Ownership Transfer (DOT) phase of cold boot.
2. **DOT recovery failure with `DOT_RECOVERY` enabled** — when a DOT blob is
   corrupt or missing while in ODD state, and `I3cServicesModes::DOT_RECOVERY`
   is set, the ROM enters I3C services to allow the BMC to supply a recovery
   blob. See [DOT I3C Recovery Protocol](dot_i3c.md) for details.

### Boot Status Checkpoints

The ROM reports boot milestones via MCI when entering and leaving I3C services:

| Milestone | Description |
|-----------|-------------|
| `I3cServicesStarted` | Emitted when the ROM enters the I3C mailbox loop. |
| `I3cServicesComplete` | Emitted when the ROM exits the I3C mailbox loop. |

## Framing

### Packetized Transport

The I3C TTI RX FIFO on the target is limited to 256 bytes per private write.
Commands with payloads larger than a single packet (e.g., DOT_OVERRIDE at
~7.4 KB) must be split into multiple I3C private writes using the packetized
framing described below.

Every private write — single-packet or multi-packet — uses the same 4-byte
packet header:

```
Byte 0: Command ID     (u8)
Byte 1: Payload length  (u8) — bytes of payload in THIS packet (0–248)
Byte 2: Sequence number (u8) — 0-based packet index
Byte 3: Total sequences (u8) — total number of packets for this command
Bytes 4+: Payload chunk  (variable, up to 248 bytes)
```

**Maximum chunk size:** 248 bytes per packet. This accounts for the 4-byte
header, the 1-byte PEC (CRC-8/SMBus) appended by the I3C controller, and
4-byte alignment required by the ROM's word-based reassembly buffer:
`256 − 4 (header) − 1 (PEC) = 251`, rounded down to 248 for alignment.

**Single-packet commands:** `total_seqs = 1`, `seq_num = 0`. Dispatched
immediately upon receipt.

**Multi-packet commands:** The ROM reassembles packets in order
(`seq_num` = 0, 1, 2, …). Once all packets arrive (`seq_num + 1 == total_seqs`),
the command is dispatched. Out-of-order or mismatched packets reset the
reassembly state.

The reassembly buffer is backed by the MCI mailbox SRAM (16 KB, word-aligned
u32 access) which the ROM acquires at service entry.

### BMC → MCU (Private Write)

After reassembly, the command payload visible to the handler is:

```
Byte 0:    Command ID (u8)   — from the packet header
Bytes 1+:  Payload (variable length, command-specific)
```

The packet header fields (payload_len, seq_num, total_seqs) are consumed by the
reassembly layer and not passed to the command handler.

### MCU → BMC (Private Read)

Command responses are queued via the TTI TX path. The BMC reads them with
a private read transaction:

```
Byte 0:    Status code (u8)
Bytes 1+:  Response data (variable length, command-specific)
```

### MCU → BMC (IBI)

The MCU uses IBI with Mandatory Data Byte (MDB) `0x1F` only for unsolicited
notifications (e.g., the initial `AWAITING` status on entry to I3C services).

### MDB Value

| MDB  | Description |
|------|-------------|
| 0x1F | I3C services IBI with inline payload data |

## Status Codes

| Code | Name | Meaning |
|------|------|---------|
| 0x00 | `SUCCESS` | Command completed successfully |
| 0x01 | `INVALID_CMD` | Unknown or unsupported command ID |
| 0x02 | `INVALID_PAYLOAD` | Payload length is invalid for the given command |
| 0x03 | `ERROR` | Command-specific error (see individual command docs) |
| 0x80 | `AWAITING` | Handler is ready for commands (sent on entry) |

## Commands

| Cmd ID | Name | Request Payload | Response Payload | Description |
|--------|------|-----------------|------------------|-------------|
| 0x00 | PING | (none) | `[0x00] "PONG"` (5 bytes) | Connectivity test; returns status `SUCCESS` and ASCII `"PONG"` |
| 0x01 | DOT_STATUS | (none) | `[0x00, enabled, locked, burned_lo, burned_hi]` | Query DOT fuse state (requires `DOT_RECOVERY` mode) |
| 0x02 | DOT_RECOVERY | backup DOT blob | `[status]` | Supply backup blob for recovery (requires `DOT_RECOVERY` mode) |
| 0x03 | DOT_UNLOCK_CHALLENGE | ECC PK + MLDSA PK | `[0x00] + 48-byte challenge` | Start DOT override (requires `DOT_RECOVERY` mode) |
| 0x04 | DOT_OVERRIDE | ECC PK + sigs + MLDSA PK + sig | `[status]` | Complete DOT override (requires `DOT_RECOVERY` mode) |

### PING (0x00)

A simple liveness check. The BMC sends a zero-length command and receives a
success status byte followed by the four ASCII bytes `PONG`.

**Request:** `[0x00]` (command byte only, no payload)

**Response IBI:** MDB 0x1F + `[0x00] [0x50 0x4F 0x4E 0x47]` (`SUCCESS` + "PONG")

For DOT-specific commands (DOT_STATUS, DOT_RECOVERY, etc.), see
[DOT I3C Recovery Protocol](dot_i3c.md).

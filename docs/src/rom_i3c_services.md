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

### BMC → MCU (Private Write)

```
Byte 0:    Command ID (u8)
Bytes 1+:  Payload (variable length, command-specific)
```

### MCU → BMC (IBI)

The MCU responds via IBI using Mandatory Data Byte (MDB) `0x1F`, followed by
inline payload data:

```
MDB:       0x1F (vendor-defined, I3C services)
Byte 0:    Status code (u8)
Bytes 1+:  Response data (variable length, command-specific)
```

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
| 0x80 | `AWAITING` | Handler is ready for commands (sent on entry) |

## Commands

| Cmd ID | Name | Request Payload | Response Payload | Description |
|--------|------|-----------------|------------------|-------------|
| 0x00 | PING | (none) | `[0x00] "PONG"` (5 bytes) | Connectivity test; returns status `SUCCESS` and ASCII `"PONG"` |

### PING (0x00)

A simple liveness check. The BMC sends a zero-length command and receives a
success status byte followed by the four ASCII bytes `PONG`.

**Request:** `[0x00]` (command byte only, no payload)

**Response IBI:** MDB 0x1F + `[0x00] [0x50 0x4F 0x4E 0x47]` (`SUCCESS` + "PONG")

For DOT-specific commands (DOT_STATUS, DOT_RECOVERY, etc.), see
[DOT I3C Recovery Protocol](dot_i3c.md).

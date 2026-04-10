# DOT I3C Recovery Protocol

This document specifies the I3C-based transport protocol used for Device Ownership Transfer (DOT) recovery and override in the MCU ROM. For the overall DOT specification, see [Device Ownership Transfer](dot.md). For the general I3C services framework and framing, see [ROM I3C Services](rom_i3c_services.md).

## Overview

When the MCU ROM detects a corrupted or missing DOT blob while in ODD state (Locked or Disabled), the device enters DOT recovery mode via the ROM's I3C services handler (with `I3cServicesModes::DOT_RECOVERY` enabled). In this mode, the ROM waits for an external recovery agent to supply a backup DOT blob or perform a DOT override via challenge/response authentication over I3C.

### Recovery Trigger Conditions

DOT I3C recovery is entered when **any** of the following conditions are met:

1. **Empty/erased DOT blob with DOT enabled**: The DOT blob in flash is all zeros or all 0xFF, but the `DOT_INITIALIZED` fuse is set, indicating the device expects a valid DOT blob.
2. **Corrupt DOT blob in locked state**: The DOT blob exists in flash but fails HMAC authentication using the DOT_EFFECTIVE_KEY, and the DOT_FUSE_ARRAY is in ODD state (locked).
3. **Both A/B copies invalid**: If the device stores redundant DOT blob copies (A/B partitions) and both copies are missing or fail authentication, recovery is triggered.

### Recovery Options

The BMC has two recovery paths available over I3C:

- **DOT_RECOVERY** — Supply a backup DOT blob (HMAC'd with the current DOT effective key). This restores the blob without changing fuse state.
- **DOT_OVERRIDE** — Challenge/response authentication with the VendorKey. This burns a fuse (ODD→EVEN transition) and writes a new empty DOT blob, effectively factory-resetting device ownership.

### `DOT_RECOVERY` Flow

```mermaid
sequenceDiagram
    participant MCU as MCU ROM
    participant BMC

    Note over MCU: Boots, detects corrupt DOT blob
    MCU->>BMC: IBI (MDB=0x1F) payload: [0x80] (AWAITING status)

    opt BMC checks status
        BMC->>MCU: DOT_STATUS (0x01) query (private write)
        MCU->>BMC: Private read: [0x00, enabled, locked, burned_lo, burned_hi]
    end

    BMC->>MCU: DOT_RECOVERY (0x02) + backup blob (private write)
    MCU->>BMC: Private read: [status] (0x00 = success, 0x03 = error)

    Note over MCU: On success, writes blob to flash and triggers warm reset
```

### `DOT_OVERRIDE` Flow

```mermaid
sequenceDiagram
    participant MCU as MCU ROM
    participant BMC

    Note over MCU: Boots, detects corrupt DOT blob
    MCU->>BMC: IBI (MDB=0x1F) payload: [0x80] (AWAITING status)

    BMC->>MCU: DOT_UNLOCK_CHALLENGE (0x03) + ECC PK + MLDSA PK
    Note over MCU: Verifies vendor PK hash against OTP fuses
    MCU->>BMC: Private read: [0x00] + 48-byte challenge

    BMC->>MCU: DOT_OVERRIDE (0x04) + ECC PK + ECC sig + MLDSA PK + MLDSA sig
    Note over MCU: Re-verifies PK hash, verifies ECDSA + MLDSA signatures
    Note over MCU: Burns DOT fuse, writes empty blob, triggers reset
    MCU->>BMC: Private read: [status] (0x00 = success)
```

## Commands

All commands follow the [ROM I3C Services framing](rom_i3c_services.md), including the packetized transport for commands exceeding the 256-byte TTI FIFO (DOT_UNLOCK_CHALLENGE at ~2.7 KB and DOT_OVERRIDE at ~7.4 KB require multiple packets). The command byte is the first byte of every packet header. Responses are read via private read transactions.

| Cmd ID | Name | Payload | Description |
|--------|------|---------|-------------|
| 0x01 | DOT_STATUS | (none) | Query current DOT fuse state |
| 0x02 | DOT_RECOVERY | backup DOT blob | Supply a backup DOT blob for recovery |
| 0x03 | DOT_UNLOCK_CHALLENGE | ECC PK + MLDSA PK | Start override: send vendor public keys |
| 0x04 | DOT_OVERRIDE | ECC PK + ECC sig + MLDSA PK + MLDSA sig | Complete override: send signed challenge response |

### DOT_STATUS (0x01)

Query the current DOT fuse state. No payload required.

**Request (private write):** `[0x01]`

**Response (private read):** `[status, enabled, locked, burned_lo, burned_hi]`

| Field | Size | Description |
|-------|------|-------------|
| status | 1 byte | `0x00` (SUCCESS) |
| enabled | 1 byte | `1` if DOT is initialized, `0` otherwise |
| locked | 1 byte | `1` if device is in ODD (locked) state |
| burned_lo | 1 byte | Low byte of DOT_FUSE_ARRAY burned count |
| burned_hi | 1 byte | High byte of DOT_FUSE_ARRAY burned count |

### DOT_RECOVERY (0x02)

Supply a backup DOT blob. The blob must be HMAC'd with the current DOT effective key (matching the device's fuse state).

**Request (private write):** `[0x02] [blob bytes...]`

The payload is the raw DOT blob (same format as stored in flash). Since the blob
exceeds 256 bytes, it is sent using the
[packetized transport](rom_i3c_services.md#packetized-transport).

**Response (private read):** `[status]`

- `0x00` — SUCCESS: blob authenticated and written to flash; device will reset.
- `0x02` — INVALID_PAYLOAD: payload too small.
- `0x03` — ERROR: blob authentication failed or flash write error.

### DOT_UNLOCK_CHALLENGE (0x03)

Initiate a DOT override by sending the vendor's public keys (ECC P-384 + MLDSA-87). The ROM verifies the public key hash against the `VENDOR_RECOVERY_PK_HASH` stored in OTP fuses, then generates a random 48-byte challenge.

**Request (private write):**

The payload below is sent using the [packetized transport](rom_i3c_services.md#packetized-transport) (11 packets at 248 bytes each). Offsets are relative to the reassembled payload (after the packet header is stripped).

| Offset | Size | Field |
|--------|------|-------|
| 0 | 48 | ECC P-384 public key X coordinate (LE) |
| 48 | 48 | ECC P-384 public key Y coordinate (LE) |
| 96 | 2592 | MLDSA-87 public key |

**Response (private read):** `[status] [challenge...]`

- On success: `[0x00]` + 48-byte random challenge.
- On error: `[0x03]` (device not locked, no PK hash, PK hash mismatch, or RNG failure).

### DOT_OVERRIDE (0x04)

Complete the override by sending the vendor's public keys and signatures over the challenge. Must be preceded by a successful DOT_UNLOCK_CHALLENGE.

**Request (private write):**

The payload below is sent using the [packetized transport](rom_i3c_services.md#packetized-transport) (~30 packets at 248 bytes each). Offsets are relative to the reassembled payload.

| Offset | Size | Field |
|--------|------|-------|
| 0 | 48 | ECC P-384 public key X coordinate (LE) |
| 48 | 48 | ECC P-384 public key Y coordinate (LE) |
| 96 | 48 | ECDSA P-384 signature R (LE) |
| 144 | 48 | ECDSA P-384 signature S (LE) |
| 192 | 2592 | MLDSA-87 public key |
| 2784 | 4628 | MLDSA-87 signature |

**Response (private read):** `[status]`

- `0x00` — SUCCESS: signatures verified, fuse burned, empty DOT blob written; device will reset.
- `0x02` — INVALID_PAYLOAD: payload too small.
- `0x03` — ERROR: no prior challenge, PK hash mismatch, signature verification failed, fuse burn error, or flash write error.

## Security Considerations

- The ECDSA signature is verified over `SHA-384(challenge)`, while the MLDSA signature is verified over the raw 48-byte challenge.
- The PK hash is re-verified in the DOT_OVERRIDE message (not just DOT_UNLOCK_CHALLENGE) to prevent an attacker from substituting different keys between the two messages.
- All commands are gated by `I3cServicesModes::DOT_RECOVERY` — they are not available unless the platform explicitly enables them.

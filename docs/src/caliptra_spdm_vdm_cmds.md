# Caliptra SPDM VDM Commands

## Overview

This document describes how Caliptra common commands are transported over SPDM Vendor Defined Messages (VDM) via MCTP. This is the **out-of-band (OOB)** path for standard, vendor-neutral Caliptra device management commands that require SPDM-defined semantics, SPDM authorization, or SPDM streaming/chunking.

For command definitions (categories, payloads, and completion codes), see [Caliptra Common Commands](caliptra_common_commands.md).

For the unified software architecture shared between OOB (SPDM VDM) and in-band (MCI Mailbox) paths, see [Unified Caliptra Command Handling](unified_caliptra_command_handling.md).

## Transport Stack

```text
┌─────────────────────────────────────────┐
│        Caliptra VDM Commands            │
│ (FirmwareVersion, ExportAttestedCsr, …) │
├─────────────────────────────────────────┤
│      Caliptra Command Header            │
│     (Command Version, Command Code)     │
├─────────────────────────────────────────┤
│        OCP SPDM VDM Framing             │
│     (IANA Registry ID, Vendor ID)       │
├─────────────────────────────────────────┤
│              SPDM                       │
│     (VENDOR_DEFINED_REQUEST/RESPONSE)   │
├─────────────────────────────────────────┤
│              MCTP                       │
│        (Message Type 0x05)              │
├─────────────────────────────────────────┤
│         Physical Layer                  │
│              (I3C)                      │
└─────────────────────────────────────────┘
```

## SPDM VDM Encapsulation

Caliptra commands assigned to SPDM VDM are carried within SPDM `VENDOR_DEFINED_REQUEST` and `VENDOR_DEFINED_RESPONSE` messages using the OCP-assigned Vendor ID (`42623`). The command range `0x01`-`0x20` is [reserved in the OCP registry](https://github.com/opencomputeproject/ocp-registry/blob/main/command-registry.md) and defined by the Caliptra Working Group.

### OCP VDM Header

The SPDM VDM standard header identifies the vendor organization:

| Field            | Size    | Value        | Description                                       |
| ---------------- | ------- | ------------ | ------------------------------------------------- |
| Standard ID      | 2 bytes | `0x0004`     | IANA Enterprise ID format                         |
| Vendor ID Length | 1 byte  | `0x04`       | Length of the Vendor ID field (4 bytes)           |
| Vendor ID (IANA) | 4 bytes | `0x0000A67F` | OCP Caliptra Working Group IANA Enterprise Number |

### Caliptra VDM Message Header

Following the OCP VDM standard header, the Caliptra-specific message header appears:

| Field           | Size   | Description                                                                           |
| --------------- | ------ | ------------------------------------------------------------------------------------- |
| Command Version | 1 byte | Protocol version. Current value: `0x01`                                               |
| Command Code    | 1 byte | Identifies the command (see [Command List](caliptra_common_commands.md#command-list)) |

### Response Format

Responses follow the same header structure. The Command Code in the response mirrors the request. The response payload begins with a `CaliptraCompletionCode` (1 byte) indicating success or failure. Command-specific response data, if any, follows the completion code:

| Field           | Size    | Description                            |
| --------------- | ------- | -------------------------------------- |
| Command Version | 1 byte  | `0x01`                                 |
| Command Code    | 1 byte  | Same as request command code           |
| Completion Code | 1 byte  | OCP completion code (`0x00` = Success) |
| Payload         | N bytes | Command-specific response data         |

See [Completion Codes](caliptra_common_commands.md#completion-codes) for the full list of error codes.

The SPDM VDM completion code is transport-specific response status and is not included in the transport-agnostic common response payload tables.

## Command Codes

The following table maps SPDM VDM command codes to Caliptra common commands. For command payload definitions, see [Caliptra Common Commands](caliptra_common_commands.md#command-definitions).

These command codes are assigned from the Caliptra range reserved in the [OCP command registry](https://github.com/opencomputeproject/ocp-registry/blob/main/command-registry.md).

| Command Code | Command Name              | R/O | Description                                                                |
| ------------ | ------------------------- | --- | -------------------------------------------------------------------------- |
| `0x05`       | GetAttestation            | O   | Retrieve signed attestation evidence in a requester-selected format.       |
| `0x06`       | RequestDebugUnlock        | O   | Request debug unlock in production environment.                            |
| `0x07`       | AuthorizeDebugUnlockToken | O   | Send debug unlock token to device for authorization.                       |
| `0x08`       | ExportAttestedCsr         | O   | Export attested CSR for a Caliptra device identity key.                    |
| `0x12`       | AuthorizedCommand         | O   | Carry challenge-authorized provisioning and fuse subcommands.              |

R = Required, O = Optional

Implemented commands are advertised in the `external_commands` field returned by `DeviceCapabilities`. Implemented operations under `AuthorizedCommand` are advertised individually in `authorized_subcommands`. Recognized but unimplemented commands are not advertised. See [Device Capabilities](caliptra_common_commands.md#device-capabilities).

## Authorization-Gated Subcommands

The following subcommands are assigned to the SPDM VDM IANA authorization-gated path and are carried under `AuthorizedCommand`. Multi-byte payload integers and the subcommand ID are encoded little-endian on the wire.

| Subcommand ID          | Name                       | Status        | Description                                         |
| ---------------------- | -------------------------- | ------------- | --------------------------------------------------- |
| `0x4D41_4343` (`MACC`) | GetAuthChallenge           | Supported     | Acquire a one-use 48-byte authorization challenge.  |
| `0x5056_504B` (`PVPK`) | ProvisionVendorPkHash      | Supported     | Provision vendor public key hash.                   |
| `0x4D43_4D53` (`MCMS`) | FuseIncreaseCaliptraMinSvn | Supported     | Increase Caliptra minimum SVN.                      |
| `0x4D43_4650` (`MCFP`) | ProgramFieldEntropy        | Supported     | Program field entropy.                              |
| `0x4D52_564B` (`MRVK`) | FuseRevokeVendorPubKey     | Supported     | Revoke vendor public key.                           |
| `0x5256_4B48` (`RVKH`) | FuseRevokeVendorPkHash     | Supported     | Revoke vendor public key hash.                      |
| `0x4946_504B` (`IFPK`) | FuseLockPartition          | Planned (TBD) | Lock fuse partition.                                |

### Authorization Flow

1. Send `GetAuthChallenge` with an empty subcommand payload. The successful response data is a 48-byte challenge.
2. Serialize the target subcommand payload exactly as listed below, excluding the common authorization trailer.
3. Sign `subcommand_id(BE) || payload || challenge` with both the authorized ECC P-384 and ML-DSA-87 keys. The signed command ID is big-endian even though the `AuthorizedCommand` wire field is little-endian.
4. Append the common authorization trailer and submit the complete request under `AuthorizedCommand`.

The common authorization trailer is:

```text
nonce[48] || ecc_pub_x[48] || ecc_pub_y[48] || mldsa_pub[2592] || HybridSignature
```

`nonce` echoes the challenge. `HybridSignature` is `ecc_sig_r[48] || ecc_sig_s[48] || mldsa_sig[4628]`. The challenge is consumed by the verification attempt and cannot be reused. Requests must have the exact documented size; missing, truncated, and oversized trailers are rejected with `InvalidPayloadSize`, while failed authorization returns `AccessDenied`.

### Implemented Subcommand Payloads

Byte offsets below begin immediately after the four-byte `subcommand_id` and include the complete authorization trailer.

| Subcommand | Bytes | Field | Encoding |
| ---------- | ----- | ----- | -------- |
| PVPK | 0:3 | `slot` | u32, little-endian |
| | 4:51 | `hash` | u8[48] |
| | 52:99 | `nonce` | u8[48] |
| | 100:147 | `ecc_pub_x` | u8[48] |
| | 148:195 | `ecc_pub_y` | u8[48] |
| | 196:2787 | `mldsa_pub` | u8[2592] |
| | 2788:7511 | `signature` | HybridSignature |
| MCMS | 0:3 | `flags` | u32, little-endian; must be zero |
| | 4:7 | `svn` | u32, little-endian |
| | 8:55 | `nonce` | u8[48] |
| | 56:103 | `ecc_pub_x` | u8[48] |
| | 104:151 | `ecc_pub_y` | u8[48] |
| | 152:2743 | `mldsa_pub` | u8[2592] |
| | 2744:7467 | `signature` | HybridSignature |
| MCFP | 0:3 | `partition` | u32, little-endian |
| | 4:51 | `nonce` | u8[48] |
| | 52:99 | `ecc_pub_x` | u8[48] |
| | 100:147 | `ecc_pub_y` | u8[48] |
| | 148:2739 | `mldsa_pub` | u8[2592] |
| | 2740:7463 | `signature` | HybridSignature |
| MRVK | 0:3 | `reserved` | u32, little-endian; must be zero |
| | 4:7 | `slot` | u32, little-endian |
| | 8:11 | `key_type` | u32, little-endian |
| | 12:15 | `key_index` | u32, little-endian |
| | 16:63 | `nonce` | u8[48] |
| | 64:111 | `ecc_pub_x` | u8[48] |
| | 112:159 | `ecc_pub_y` | u8[48] |
| | 160:2751 | `mldsa_pub` | u8[2592] |
| | 2752:7475 | `signature` | HybridSignature |
| RVKH | 0:3 | `reserved` | u32, little-endian; must be zero |
| | 4:7 | `slot` | u32, little-endian |
| | 8:55 | `nonce` | u8[48] |
| | 56:103 | `ecc_pub_x` | u8[48] |
| | 104:151 | `ecc_pub_y` | u8[48] |
| | 152:2743 | `mldsa_pub` | u8[2592] |
| | 2744:7467 | `signature` | HybridSignature |

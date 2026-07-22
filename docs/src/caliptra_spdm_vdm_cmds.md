# Caliptra SPDM VDM Commands

## Overview

This document describes how Caliptra common commands are transported over SPDM Vendor Defined Messages (VDM) via MCTP. This is the **out-of-band (OOB)** path for standard, vendor-neutral Caliptra device management commands that require SPDM-defined semantics, SPDM authorization, or SPDM streaming/chunking.

For command definitions (categories, payloads, and completion codes), see [Caliptra Common Commands](caliptra_common_commands.md).

For the unified software architecture shared between OOB (SPDM VDM) and in-band (MCI Mailbox) paths, see [Unified Caliptra Command Handling](unified_caliptra_command_handling.md).

## Transport Stack

```
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
| `0x05`       | GetAttestation            | O   | Retrieve attestation evidence.                                             |
| `0x06`       | RequestDebugUnlock        | O   | Request debug unlock in production environment.                            |
| `0x07`       | AuthorizeDebugUnlockToken | O   | Send debug unlock token to device for authorization.                       |
| `0x08`       | ExportAttestedCsr         | O   | Export attested CSR for a Caliptra device identity key.                    |
| `0x12`       | AuthorizedCommand         | O   | Carry authorization-gated subcommands. The SPDM authorization flow is TBD. |

R = Required, O = Optional

## Authorization-Gated Subcommands

The following subcommands are assigned to the SPDM VDM IANA authorization-gated path and are carried under `AuthorizedCommand`. Only subcommands marked Supported are currently dispatched; requests for Planned subcommands return `InvalidParameter`. `AuthorizedCommand` does not define the authorization mechanism by itself. The concrete SPDM authorization mechanism and message flow are still under design and will be specified separately.

| Subcommand ID          | Name                       | Status        | Description                                        |
| ---------------------- | -------------------------- | ------------- | -------------------------------------------------- |
| `0x4D41_4343` (`MACC`) | GetAuthChallenge           | Supported     | Challenge acquisition for authorization-gated use. |
| `0x5056_504B` (`PVPK`) | ProvisionVendorPkHash      | Planned (TBD) | Provision vendor public key hash.                  |
| `0x4D43_4D53` (`MCMS`) | FuseIncreaseCaliptraMinSvn | Planned (TBD) | Increase Caliptra minimum SVN.                     |
| `0x4D43_4650` (`MCFP`) | ProgramFieldEntropy        | Supported     | Program field entropy.                             |
| `0x4D52_564B` (`MRVK`) | FuseRevokeVendorPubKey     | Planned (TBD) | Revoke vendor public key.                          |
| `0x5256_4B48` (`RVKH`) | FuseRevokeVendorPkHash     | Planned (TBD) | Revoke vendor public key hash.                     |
| `0x4946_504B` (`IFPK`) | FuseLockPartition          | Planned (TBD) | Lock fuse partition.                               |

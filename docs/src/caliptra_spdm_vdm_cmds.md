# Caliptra SPDM VDM Commands

## Overview

This document describes how Caliptra external commands are transported over SPDM Vendor Defined Messages (VDM) via MCTP. This is the **out-of-band (OOB)** path for accessing Caliptra device management commands from an external agent such as a BMC.

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

Common Caliptra commands are carried within SPDM `VENDOR_DEFINED_REQUEST` and `VENDOR_DEFINED_RESPONSE` messages using the OCP-assigned Vendor ID (`42623`). The command range `0x01`–`0x20` is [reserved in the OCP registry](https://github.com/opencomputeproject/ocp-registry/blob/main/command-registry.md) and defined by the Caliptra Working Group.

### OCP VDM Header

The SPDM VDM standard header identifies the vendor organization:

| Field               | Size    | Value      | Description                                      |
|---------------------|---------|------------|--------------------------------------------------|
| Standard ID         | 2 bytes | `0x0005`   | IANA Enterprise ID format                        |
| Vendor ID Length    | 1 byte  | `0x04`     | Length of the Vendor ID field (4 bytes)           |
| Vendor ID (IANA)   | 4 bytes | `0x0000A67F`| OCP Caliptra Working Group IANA Enterprise Number |

### Caliptra VDM Message Header

Following the OCP VDM standard header, the Caliptra-specific message header appears:

| Field              | Size   | Description                                                      |
|--------------------|--------|------------------------------------------------------------------|
| Command Version    | 1 byte | Protocol version. Current value: `0x01`                          |
| Command Code       | 1 byte | Identifies the command (see [Command List](caliptra_common_commands.md#command-list)) |

### Response Format

Responses follow the same header structure. The Command Code in the response mirrors the request. The response payload begins with an `CaliptraCompletionCode` (1 byte) indicating success or failure:

| Field              | Size   | Description                                         |
|--------------------|--------|-----------------------------------------------------|
| Command Version    | 1 byte | `0x01`                                              |
| Command Code       | 1 byte | Same as request command code                        |
| Completion Code    | 1 byte | OCP completion code (`0x00` = Success)              |
| Payload            | N bytes| Command-specific response data                      |

See [Completion Codes](caliptra_common_commands.md#completion-codes) for the full list of error codes.

## Command Codes

The following table maps SPDM VDM command codes to Caliptra common commands. For command payload definitions, see [Caliptra Common Commands](caliptra_common_commands.md#command-definitions).

| Command Code | Command Name                 | R/O | Description                                         |
|--------------|------------------------------|-----|-----------------------------------------------------|
| `0x01`       | Firmware Version             | R   | Retrieve firmware version information.              |
| `0x02`       | Device Capabilities          | R   | Retrieve device capabilities.                       |
| `0x03`       | Device ID                    | R   | Retrieve device ID.                                 |
| `0x04`       | Device Information           | R   | Retrieve device information.                        |
| `0x05`       | Get Debug Log                | R   | Retrieve debug log.                                 |
| `0x06`       | Clear Debug Log              | R   | Clear debug log.                                    |
| `0x07`       | Get Attestation Log          | O   | Retrieve attestation measurement log.               |
| `0x08`       | Clear Attestation Log        | O   | Clear attestation log (requires authorization).     |
| `0x09`       | Get Attestation              | O   | Retrieve attestation evidence.                      |
| `0x0A`       | Request Debug Unlock         | O   | Request debug unlock in production environment.     |
| `0x0B`       | Authorize Debug Unlock Token | O   | Send debug unlock token for authorization.          |
| `0x0C`       | Export IDevID CSR            | R   | Export IDevID certificate signing request.          |
| `0x0D`       | Set Slot 0 Cert             | R   | Set CA-signed IDevID certificate in slot 0.         |
| `0x0E`       | Get Slot 0 State            | O   | Check provisioning state of certificate slot 0.     |
| `0x0F`       | Export Attested CSR          | O   | Export attested CSR for a device identity key.      |
| `0x10`       | Program Field Entropy        | O   | Program field entropy into the device.              |
| `0x11`       | Device Ownership Transfer    | O   | Transfer device ownership.                          |

R = Required, O = Optional

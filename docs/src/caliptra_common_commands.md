# Caliptra Common Commands

## Overview

This document defines the common Caliptra device management commands. These commands are transport-agnostic and common across all vendors integrating the Caliptra subsystem. They are accessed via the following transport mechanisms:

- [MCTP VDM (out-of-band)](external_mctp_vdm_cmds.md)
- [SPDM VDM over MCTP (out-of-band)](caliptra_spdm_vdm_cmds.md)
- [MCI Mailbox (in-band)](external_mailbox_cmds.md)

For the unified software architecture that handles both paths, see [Unified Caliptra Command Handling](unified_caliptra_command_handling.md).

Transport-specific command codes are defined by the transport documents. This document defines the common command names, transport assignment, and payload semantics.

### Transport Selection

Commands are assigned to MCTP VDM IANA when they do not require SPDM authorization, SPDM-defined semantics, or SPDM streaming/chunking. Commands are assigned to SPDM VDM IANA when they require those properties. The MCI mailbox provides the in-band path for the same common command semantics where implemented.

## Command List

The following table describes the commands defined under this specification. There are two categories: (1) Required commands (R) that are mandatory for all implementations, (2) Optional commands (O) that may be utilized if the specific implementation requires it.

| Message Name                    | R/O | Transport(s)               | Description                                                                               |
| ------------------------------- | --- | -------------------------- | ----------------------------------------------------------------------------------------- |
| Firmware Version                | R   | MCTP VDM, MCI Mailbox      | Retrieve firmware version information.                                                    |
| Device Capabilities             | R   | MCTP VDM, MCI Mailbox      | Retrieve device capabilities.                                                             |
| Get Debug Log                   | R   | MCTP VDM, MCI Mailbox      | Retrieve debug log.                                                                       |
| Clear Debug Log                 | R   | MCTP VDM, MCI Mailbox      | Clear debug log.                                                                          |
| Get Attestation                 | O   | SPDM VDM, MCI Mailbox      | Retrieve attestation evidence.                                                           |
| Request Debug Unlock            | O   | SPDM VDM, MCI Mailbox      | Request debug unlock in production environment.                                           |
| Authorize Debug Unlock Token    | O   | SPDM VDM, MCI Mailbox      | Send debug unlock token to device for authorization.                                      |
| Export Attested CSR             | O   | SPDM VDM, MCI Mailbox      | Export attested CSR for a Caliptra device identity key (LDevID, FMC Alias, or RT Alias).  |
| Authorization-Gated Subcommands | O   | SPDM VDM, MCI Mailbox      | Security-sensitive provisioning and fuse subcommands. The SPDM authorization flow is TBD. |

### Authorization-Gated Subcommands

The following subcommands are assigned to the SPDM VDM IANA authorization-gated path and are also available through the MCI mailbox path where implemented. The concrete SPDM authorization mechanism and message flow are still under design and will be specified separately. For the MCI mailbox path, access control is governed by the mailbox security boundary and platform policy.

| Subcommand Name                | Transport(s)               | Description                                        |
| ------------------------------ | -------------------------- | -------------------------------------------------- |
| Get Auth Challenge             | SPDM VDM IANA, MCI Mailbox | Challenge acquisition for authorization-gated use. |
| Provision Vendor PK Hash       | SPDM VDM IANA, MCI Mailbox | Provision vendor public key hash.                  |
| Fuse Increase Caliptra Min SVN | SPDM VDM IANA, MCI Mailbox | Increase Caliptra minimum SVN.                     |
| Program Field Entropy          | SPDM VDM IANA, MCI Mailbox | Program field entropy.                             |
| Fuse Revoke Vendor Public Key  | SPDM VDM IANA, MCI Mailbox | Revoke vendor public key.                          |
| Fuse Revoke Vendor PK Hash     | SPDM VDM IANA, MCI Mailbox | Revoke vendor public key hash.                     |
| Fuse Lock Partition            | SPDM VDM IANA, MCI Mailbox | Lock fuse partition.                               |


## Command Definitions

This section defines the request and response payloads for each command.

### Firmware Version

Retrieves the version of the target firmware.

**Request Payload**:

| Byte(s) | Name       | Type | Description                                                                                                          |
| ------- | ---------- | ---- | -------------------------------------------------------------------------------------------------------------------- |
| 0:3     | area_index | u32  | Area Index: <br>- `00h` = Caliptra core firmware <br>- `01h` = MCU runtime firmware; Additional indexes are reserved |

**Response Payload**:

| Byte(s) | Name            | Type   | Description                             |
| ------- | --------------- | ------ | --------------------------------------- |
| 0:3     | completion_code | u32    | Command completion status               |
| 4:35    | version         | u8[32] | Firmware Version Number in ASCII format |

### Device Capabilities

**Request Payload**: Empty

**Response Payload**:

| Byte(s) | Name            | Type   | Description                                                                                                                                                                                                                                                                    |
| ------- | --------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0:3     | completion_code | u32    | Command completion status                                                                                                                                                                                                                                                      |
| 4:35    | caps            | u8[32] | Device Capabilities: <br>- Bytes [0:7]: Reserved for Caliptra RT <br>- Bytes [8:11]: Reserved for Caliptra FMC <br>- Bytes [12:15]: Reserved for Caliptra ROM <br>- Bytes [16:23]: Reserved for MCU RT <br>- Bytes [24:27]: Reserved for MCU ROM <br>- Bytes [28:31]: Reserved |

### Get Debug Log

Retrieves the debug log for the MCU Runtime.

**Request Payload**: Empty

**Response Payload**:

| Byte(s) | Name            | Type          | Description                         |
| ------- | --------------- | ------------- | ----------------------------------- |
| 0:3     | completion_code | u32           | Command completion status           |
| 4:7     | more_data       | u32           | `1` if more log data remains        |
| 8:11    | data_size       | u32           | Size of the valid log data in bytes |
| 12:N    | data            | u8[data_size] | Debug log contents                  |

For defmt-based debug logs, the device exposes a sequential drain interface rather than random access to individual log entries. Callers drain the debug log by repeating this command until `more_data` is `0`. Each response contains zero or more complete defmt frames. The host concatenates the returned data and decodes the resulting frame stream using the matching firmware ELF.

**Debug Log Format**:

The debug log payload is an opaque byte stream. For the MCU Runtime debug log, the current implementation uses the [defmt](https://crates.io/crates/defmt) crate. Each `defmt` log macro emits one complete rzCOBS-encoded frame, and the MCU runtime logging backend appends that complete frame as one flash log entry. `Get Debug Log` returns the concatenated raw frame bytes.

The device does not store human-readable log strings in the debug log. A host tool decodes the returned byte stream with `defmt-decoder` or `defmt-print` using the exact app's ELF that produced the log; the ELF `.defmt` section contains the interned format strings and metadata required to render readable messages.

### Clear Debug Log

Clears the debug log in the MCU Runtime. No authorization is required.

**Request Payload**: Empty

**Response Payload**:

| Byte(s) | Name            | Type | Description               |
| ------- | --------------- | ---- | ------------------------- |
| 0:3     | completion_code | u32  | Command completion status |

### Get Attestation

Retrieves attestation evidence. This command is assigned to SPDM VDM IANA. The payload format is TBD.

**Request Payload**: TBD

**Response Payload**: TBD

### Request Debug Unlock

Requests debug unlock in production environment.

**Request Payload**:

| Byte(s) | Name         | Type  | Description                     |
| ------- | ------------ | ----- | ------------------------------- |
| 0:3     | length       | u32   | Length of the message in DWORDs |
| 4       | unlock_level | u8    | Debug unlock level (1-8)        |
| 5:7     | reserved     | u8[3] | Reserved field                  |

**Response Payload**:

| Byte(s) | Name                     | Type   | Description                              |
| ------- | ------------------------ | ------ | ---------------------------------------- |
| 0:3     | completion_code          | u32    | Command completion status                |
| 4:7     | length                   | u32    | Length of the message in DWORDs          |
| 8:39    | unique_device_identifier | u8[32] | Device identifier of the Caliptra device |
| 40:87   | challenge                | u8[48] | Random number challenge                  |

### Authorize Debug Unlock Token

Authorizes the debug unlock token.
The request body is identical for MCI mailbox and SPDM VDM transports; the
leading `checksum` is part of the common command body, not transport framing.

**Request Payload**:

| Byte(s)   | Name                     | Type         | Description                                                                 |
|-----------|--------------------------|--------------|-----------------------------------------------------------------------------|
| 0:3       | checksum                 | u32          | Caliptra RT mailbox request checksum (`MailboxReqHeader.checksum`)          |
| 4:7       | length                   | u32          | Length of the message in DWORDs                                             |
| 8:39      | unique_device_identifier | u8[32]       | Device identifier of the Caliptra device                                    |
| 40        | unlock_level             | u8           | Debug unlock level (1-8)                                                    |
| 41:43     | reserved                 | u8[3]        | Reserved field                                                              |
| 44:91     | challenge                | u8[48]       | Random number challenge                                                     |
| 92:187    | ecc_public_key           | u32[24]      | ECC public key in hardware format (little endian)                           |
| 188:2639  | mldsa_public_key         | u32[648]     | MLDSA public key in hardware format (little endian)                         |
| 2640:2735 | ecc_signature            | u32[24]      | ECC P-384 signature of the message hashed using SHA2-384 (R and S coordinates) |
| 2736:6199 | mldsa_signature          | u32[1157]    | MLDSA signature of the message hashed using SHA2-512 (4627 bytes + 1 reserved byte) |

**Response Payload**:

| Byte(s) | Name            | Type | Description               |
| ------- | --------------- | ---- | ------------------------- |
| 0:3     | completion_code | u32  | Command completion status |

### Export Attested CSR

Exports an attested Certificate Signing Request (CSR) for a specified device key.

**Request Payload**:

| Byte(s) | Name          | Type | Description                                                                                         |
| ------- | ------------- | ---- | --------------------------------------------------------------------------------------------------- |
| 0:3     | device_key_id | u32  | Device Key Identifier: <br>- `0x0001` = LDevID <br>- `0x0002` = FMC Alias <br>- `0x0003` = RT Alias |
| 4:7     | algorithm     | u32  | Asymmetric Algorithm: <br>- `0x0000` = ECC P-384 <br>- `0x0001` = ML-DSA-87                         |

**Response Payload**:

| Byte(s) | Name            | Type          | Description                              |
| ------- | --------------- | ------------- | ---------------------------------------- |
| 0:3     | completion_code | u32           | Command completion status                |
| 4:7     | data_size       | u32           | Length in bytes of the attested CSR data |
| 8:N     | data            | u8[data_size] | Attested CSR data blob                   |

### Authorization-Gated Subcommand Wrapper

Security-sensitive provisioning and fuse subcommands are assigned to the SPDM VDM IANA authorization-gated path and the MCI mailbox path. The SPDM authorization mechanism and message flow are TBD. The SPDM VDM transport uses an `Authorized Command` wrapper to carry subcommands, but the wrapper does not define the authorization mechanism by itself.

#### Request Payload

| Byte(s) | Name        | Type  | Description                                         |
| ------- | ----------- | ----- | --------------------------------------------------- |
| 0:3     | sub_cmd_id  | u32   | Subcommand identifier defined by the SPDM VDM spec. |
| 4:N     | sub_payload | u8[N] | Subcommand-specific payload.                        |

#### Response Payload

| Byte(s) | Name            | Type  | Description                                                             |
| ------- | --------------- | ----- | ----------------------------------------------------------------------- |
| 0       | completion_code | u8    | OCP completion code (`0x00` = Success, `0x0C` = Access Denied).         |
| 1:N     | sub_response    | u8[N] | Subcommand-specific response data, absent if completion_code != `0x00`. |

The subcommands covered by this wrapper are listed in [Authorization-Gated Subcommands](#authorization-gated-subcommands).

Subcommand-specific payloads are defined by the corresponding command specifications. Any additional SPDM authorization wrapper fields are TBD.

## Completion Codes

Command responses include a completion code indicating the result of the operation. Standard codes (0x00-0x0F) follow the [OCP command registry](https://github.com/opencomputeproject/ocp-registry/blob/main/command-registry.md). Codes 0xC0-0xFF are reserved for Caliptra project-specific errors.

### OCP Standard Codes

| Code   | Name                    | Description                              |
| ------ | ----------------------- | ---------------------------------------- |
| `0x00` | Success                 | Command completed successfully           |
| `0x01` | General Error           | Unspecified error                        |
| `0x02` | Invalid Parameter       | One or more parameters are invalid       |
| `0x03` | Invalid Length          | Request/response length mismatch         |
| `0x04` | Invalid Identifier      | Unknown or invalid identifier            |
| `0x05` | Operation Failed        | Operation could not be completed         |
| `0x06` | Insufficient Resources  | Not enough resources to complete command |
| `0x07` | Unsupported Operation   | Command is not supported                 |
| `0x08` | Device Not Ready        | Device is not ready to process command   |
| `0x09` | Invalid Command Version | Command version not supported            |
| `0x0A` | Invalid Payload Size    | Payload size does not match expected     |
| `0x0B` | Timeout                 | Operation timed out                      |
| `0x0C` | Access Denied           | Authorization required                   |
| `0x0D` | Resource Unavailable    | Requested resource is not available      |
| `0x0E` | Policy Violation        | Operation violates configured policy     |
| `0x0F` | Invalid State           | Device is not in the correct state       |

### Caliptra Project-Specific Codes (0xC0-0xFF)

| Code   | Name                      | Description                   |
| ------ | ------------------------- | ----------------------------- |
| `0xC0` | Caliptra Mailbox Busy     | Caliptra mailbox is not ready |
| `0xC1` | Caliptra Buffer Too Small | Response buffer too small     |

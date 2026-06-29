# Caliptra Common Commands

## Overview

This document defines the common Caliptra device management commands. These commands are transport-agnostic and common across all vendors integrating the Caliptra subsystem. They are accessed via the following transport mechanisms:

- [SPDM VDM over MCTP (out-of-band)](caliptra_spdm_vdm_cmds.md)
- [MCI Mailbox (in-band)](external_mailbox_cmds.md)

For the unified software architecture that handles both paths, see [Unified Caliptra Command Handling](unified_caliptra_command_handling.md).

## Command List

The following table describes the commands defined under this specification. There are two categories: (1) Required commands (R) that are mandatory for all implementations, (2) Optional commands (O) that may be utilized if the specific implementation requires it.

**Device Information**

| Message Name                  | R/O | Description                                         |
|-------------------------------|-----|-----------------------------------------------------|
| Firmware Version              | R   | Retrieve firmware version information.              |
| Device Capabilities           | R   | Retrieve device capabilities.                       |
| Device ID                     | R   | Retrieve device ID.                                 |
| Device Information            | R   | Retrieve device information.                        |

**Logging**

| Message Name                  | R/O | Description                                         |
|-------------------------------|-----|-----------------------------------------------------|
| Get Debug Log                 | R   | Retrieve debug log.                                 |
| Clear Debug Log               | R   | Clear debug log.                                    |
| Get Attestation Log           | O   | Retrieve attestation measurement log.               |
| Clear Attestation Log         | O   | Clear attestation log (requires authorization).     |

**Attestation**

| Message Name                  | R/O | Description                                         |
|-------------------------------|-----|-----------------------------------------------------|
| Get Attestation               | O   | Retrieve attestation evidence. Supports OCP EAT claims token and signed PCR quote formats. |

**Debug Unlock**

| Message Name                  | R/O | Description                                         |
|-------------------------------|-----|-----------------------------------------------------|
| Request Debug Unlock          | O   | Request debug unlock in production environment.     |
| Authorize Debug Unlock Token  | O   | Send debug unlock token to device for authorization. |

**Lifecycle & Provisioning**

*Certificate Provisioning*

| Message Name                  | R/O | Description                                         |
|-------------------------------|-----|-----------------------------------------------------|
| Export IDevID CSR             | R   | Export IDevID self-signed certificate signing request. Only available when device lifecycle state is Manufacturing. |
| Set Slot 0 Cert               | R   | Set CA-signed IDevID certificate in slot 0 (Vendor PKI). |
| Get Slot 0 State              | O   | Check the provisioning state of certificate slot 0 (Vendor PKI). |
| Export Attested CSR           | O   | Export attested CSR for a Caliptra device identity key (LDevID, FMC Alias, or RT Alias). |

*Authorized Commands*

| Message Name              | R/O | Description                                                         |
|---------------------------|-----|---------------------------------------------------------------------|
| Get Auth Challenge        | O   | Request a one-time 32-byte nonce to authorize a subsequent command. |
| Program Field Entropy     | O   | Program field entropy into a specific OTP partition.                |

*Device Lifecycle*

| Message Name                  | R/O | Description                                        |
|-------------------------------|-----|----------------------------------------------------|
| Device Ownership Transfer     | O   | Transfer device ownership. Requires authorization. |

## Command Definitions

This section defines the request and response payloads for each command.

### Firmware Version

Retrieves the version of the target firmware.

**Request Payload**:

| Byte(s) | Name        | Type | Description                                                                 |
|---------|-------------|------|-----------------------------------------------------------------------------|
| 0:3     | area_index  | u32  | Area Index: <br>- `00h` = Caliptra core firmware <br>- `01h` = MCU runtime firmware <br>- `02h` = SoC firmware <br>Additional indexes are firmware-specific |

**Response Payload**:

| Byte(s) | Name            | Type    | Description                                   |
|---------|-----------------|---------|-----------------------------------------------|
| 0:3     | completion_code | u32     | Command completion status                     |
| 4:35    | version         | u8[32]  | Firmware Version Number in ASCII format       |

### Device Capabilities

**Request Payload**: Empty

**Response Payload**:

| Byte(s) | Name            | Type    | Description                                   |
|---------|-----------------|---------|-----------------------------------------------|
| 0:3     | completion_code | u32     | Command completion status                     |
| 4:35    | caps            | u8[32]  | Device Capabilities: <br>- Bytes [0:7]: Reserved for Caliptra RT <br>- Bytes [8:11]: Reserved for Caliptra FMC <br>- Bytes [12:15]: Reserved for Caliptra ROM <br>- Bytes [16:23]: Reserved for MCU RT <br>- Bytes [24:27]: Reserved for MCU ROM <br>- Bytes [28:31]: Reserved |

### Device ID

This command retrieves the device ID.

**Request Payload**: Empty

**Response Payload**:

| Byte(s) | Name                | Type | Description                |
|---------|---------------------|------|----------------------------|
| 0:3     | completion_code     | u32  | Command completion status  |
| 4:5     | vendor_id           | u16  | Vendor ID; LSB             |
| 6:7     | device_id           | u16  | Device ID; LSB             |
| 8:9     | subsystem_vendor_id | u16  | Subsystem Vendor ID; LSB   |
| 10:11   | subsystem_id        | u16  | Subsystem ID; LSB          |

### Device Information

This command retrieves information about the target device.

**Request Payload**:

| Byte(s) | Name       | Type | Description |
|---------|------------|------|-------------|
| 0:3     | info_index | u32  | Information Index: <br>- `00h` = Unique Chip Identifier <br>Additional indexes are firmware-specific |

**Response Payload**:

| Byte(s) | Name            | Type         | Description                                   |
|---------|-----------------|--------------|-----------------------------------------------|
| 0:3     | completion_code | u32          | Command completion status                     |
| 4:7     | data_size       | u32          | Size of the requested data in bytes           |
| 8:N     | data            | u8[data_size]| Requested information in binary format        |

### Export IDevID CSR

Exports the IDevID Certificate Signing Request (CSR) so that a Certificate Authority (CA) can endorse it and issue an IDevID certificate. The CSR is available in two algorithm variants: ECC P-384 and ML-DSA (post-quantum). This command is only available when the device lifecycle state is `Manufacturing`.

**Request Payload**:

| Byte(s) | Name  | Type | Description |
|---------|-------|------|-------------|
| 0:3     | algorithm | u32  | Asymmetric Algorithm: <br>- `0x0000` = ECC P-384 <br>- `0x0001` = ML-DSA-87 |

**Response Payload**:

| Byte(s) | Name            | Type         | Description                                   |
|---------|-----------------|--------------|-----------------------------------------------|
| 0:3     | completion_code | u32          | Command completion status                     |
| 4:7     | data_size       | u32          | Length in bytes of the valid data in the data field |
| 8:N     | data            | u8[data_size]| DER-encoded IDevID certificate signing request|

### Set Slot 0 Cert

Sets the CA-signed IDevID certificate in certificate slot 0 (Vendor slot). This is a one-time operation performed during manufacturing — the command will fail if slot 0 has already been provisioned.

**Request Payload**:

| Byte(s) | Name         | Type        | Description                                 |
|---------|--------------|-------------|---------------------------------------------|
| 0:3     | cert_size    | u32         | Size of the DER-encoded IDevID certificate. |
| 4:N     | cert         | u8[cert_size]| DER-encoded CA-signed IDevID certificate   |

**Response Payload**:

| Byte(s) | Name            | Type | Description                |
|---------|-----------------|------|----------------------------|
| 0:3     | completion_code | u32  | Command completion status  |

### Get Slot 0 State

Determines the provisioning state of certificate slot 0 (Vendor PKI). This slot holds the device identity certificate provisioned during manufacturing. For other certificate slots (Owner, Tenant), use the SPDM `GET_DIGESTS` command.

**Request Payload**: Empty

**Response Payload**:

| Byte(s) | Name            | Type | Description                |
|---------|-----------------|------|----------------------------|
| 0:3     | completion_code | u32  | Command completion status  |
| 4:7     | state           | u32  | Slot State: <br>- `0` = Not provisioned — slot does not have a certificate. <br>- `1` = Provisioned — slot has a certificate. |

### Get Debug Log

Retrieves the debug log for the RoT. The debug log contains RoT application information and machine state, useful for diagnostics and troubleshooting.

**Request Payload**: Empty

**Response Payload**:

| Byte(s) | Name            | Type         | Description                                   |
|---------|-----------------|--------------|-----------------------------------------------|
| 0:3     | completion_code | u32          | Command completion status                     |
| 4:7     | data_size       | u32          | Size of the log data in bytes                 |
| 8:N     | data            | u8[data_size]| Debug log contents                            |

The length is determined by the end of the log or the packet size based on device capabilities. If the response spans multiple messages, the end of the response will be determined by a message with a payload smaller than the maximum payload supported by both devices.

**Debug Log Format**:

The debug log reported by the device has no specified format, as this can vary between different devices and is not necessary for attestation. It is expected that diagnostic utilities for the device will be able to understand the exposed log information. A recommended entry format is provided here:

| Offset     | Description                              |
|------------|------------------------------------------|
| 1:7        | Log Entry Header                        |
| 8:9        | Format of the entry (e.g., `1` for current format) |
| 10         | Severity of the entry                   |
| 11         | Identifier for the component that generated the message |
| 12         | Identifier for the entry message        |
| 13:16      | Message-specific argument               |
| 17:20      | Message-specific argument               |

### Clear Debug Log

Clears the debug log in the RoT subsystem. No authorization is required.

**Request Payload**: Empty

**Response Payload**:

| Byte(s) | Name            | Type | Description                |
|---------|-----------------|------|----------------------------|
| 0:3     | completion_code | u32  | Command completion status  |

### Request Debug Unlock

Requests debug unlock in production environment.

**Request Payload**:

| Byte(s) | Name         | Type    | Description                                 |
|---------|--------------|---------|---------------------------------------------|
| 0:3     | length       | u32     | Length of the message in DWORDs             |
| 4       | unlock_level | u8      | Debug unlock level (1-8)                    |
| 5:7     | reserved     | u8[3]   | Reserved field                              |

**Response Payload**:

| Byte(s) | Name                    | Type      | Description                                         |
|---------|-------------------------|-----------|-----------------------------------------------------|
| 0:3     | completion_code         | u32       | Command completion status                           |
| 4:7     | length                  | u32       | Length of the message in DWORDs                     |
| 8:39    | unique_device_identifier| u8[32]    | Device identifier of the Caliptra device            |
| 40:87   | challenge               | u8[48]    | Random number challenge                             |

### Authorize Debug Unlock Token

Authorizes the debug unlock token.

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

| Byte(s) | Name            | Type | Description                |
|---------|-----------------|------|----------------------------|
| 0:3     | completion_code | u32  | Command completion status  |

### Export Attested CSR

Exports an attested Certificate Signing Request (CSR) for a specified device key.

**Request Payload**:

| Byte(s) | Name          | Type | Description                                                                 |
|---------|---------------|------|-----------------------------------------------------------------------------|
| 0:3     | device_key_id | u32  | Device Key Identifier: <br>- `0x0001` = LDevID <br>- `0x0002` = FMC Alias <br>- `0x0003` = RT Alias |
| 4:7     | algorithm     | u32  | Asymmetric Algorithm: <br>- `0x0000` = ECC P-384 <br>- `0x0001` = ML-DSA-87 |

**Response Payload**:

| Byte(s) | Name            | Type          | Description                                   |
|---------|-----------------|---------------|-----------------------------------------------|
| 0:3     | completion_code | u32           | Command completion status                     |
| 4:7     | data_size       | u32           | Length in bytes of the attested CSR data       |
| 8:N     | data            | u8[data_size] | Attested CSR data blob                        |

### Authorized Commands

All commands that require cryptographic authorization are dispatched through the single `Authorized Command (0x12)` SPDM VDM code using a 1-byte `sub_cmd_id` field. This ensures a consistent challenge-response flow regardless of which operation is being authorized.

#### Authorization Flow

The requester must first obtain a one-time challenge nonce from the device, then compute an HMAC-SHA384 MAC over the nonce and command parameters, and include that MAC in the subsequent command request.

```
Requester                                       Device
    |                                               |
    |-- Authorized Command (sub_cmd_id=0x01) ------>|
    |                                               |-- generate 32-byte nonce
    |<-- challenge[32] -----------------------------|    stored internally (one-time use)
    |                                               |
    | compute MAC:                                  |
    |   HMAC-SHA384(key,                            |
    |     cmd_id_be32(4) || payload_le(N) ||        |
    |     challenge(32))                            |
    |                                               |
    |-- Authorized Command (sub_cmd_id=0x02,        |
    |   payload + mac) ---------------------------->|
    |                                               |-- verify MAC, execute command
    |<-- completion_code ---------------------------|
```

The `cmd_id` used in the HMAC input is the `sub_cmd_id` itself, serialized as a 4-byte big-endian integer. Because sub-command IDs match the canonical MCU mailbox command IDs, the HMAC input is identical across SPDM VDM and MCU mailbox transports.

#### Request Payload

| Byte(s) | Name        | Type  | Description                                          |
|---------|-------------|-------|------------------------------------------------------|
| 0:3     | sub_cmd_id  | u32   | Sub-command identifier (see Sub-Command List below)  |
| 4:N     | sub_payload | u8[N] | Sub-command-specific payload (see sub-command definitions) |

#### Response Payload

| Byte(s) | Name            | Type  | Description                                                          |
|---------|-----------------|-------|----------------------------------------------------------------------|
| 0       | completion_code | u8    | OCP completion code (`0x00` = Success, `0x0C` = Access Denied)       |
| 1:N     | sub_response    | u8[N] | Sub-command-specific response data (absent if completion_code != 0x00) |

#### Sub-Command List

| Sub-Command ID   | Name                  | Description                                                       |
|------------------|-----------------------|-------------------------------------------------------------------|
| `0x4D41_4343`    | Get Auth Challenge    | Request a one-time 32-byte nonce to authorize a subsequent command. |
| `0x4D43_4650`    | Program Field Entropy | Program field entropy into a specific OTP partition.              |

#### Sub-Command: Get Auth Challenge

Requests a one-time 32-byte challenge nonce from the device. The nonce is stored internally and consumed after the next authorized command is received (or discarded if another `Get Auth Challenge` is issued).

**Sub-Payload**: Empty

**Sub-Response**:

| Byte(s) | Name      | Type   | Description                                                                       |
|---------|-----------|--------|-----------------------------------------------------------------------------------|
| 0:31    | challenge | u8[32] | Random 32-byte nonce. One-time use — consumed after the next authorized command.  |

#### Sub-Command: Program Field Entropy

Programs device-unique entropy into a specific OTP partition. This operation is write-once and irreversible. The requester must have previously obtained a challenge nonce via `Get Auth Challenge` and computed a valid MAC.

**MAC input**: `HMAC-SHA384(key, sub_cmd_id_be32(4) || partition_le(4) || challenge(32))`

where `sub_cmd_id = 0x4D43_4650` (`MC_FE_PROG`). Because the sub-command ID is the same as the canonical MCU mailbox command ID, the HMAC input is identical across SPDM VDM and MCU mailbox transports.

**Sub-Payload**:

| Byte(s) | Name      | Type   | Description                                                                                              |
|---------|-----------|--------|----------------------------------------------------------------------------------------------------------|
| 0:3     | partition | u32    | OTP partition index to program (little-endian).                                                          |
| 4:51    | mac       | u8[48] | HMAC-SHA384 authorization token computed over `cmd_id_be32(4) || partition_le(4) || challenge(32)`. |

**Sub-Response**: Empty (success indicated by outer `completion_code = 0x00`).

### Device Ownership Transfer

Transfers device ownership. Requires authorization.

**Request Payload**: TBD

**Response Payload**:

| Byte(s) | Name            | Type | Description                |
|---------|-----------------|------|----------------------------|
| 0:3     | completion_code | u32  | Command completion status  |

## Completion Codes

Command responses include a completion code indicating the result of the operation. Standard codes (0x00-0x0F) follow the [OCP command registry](https://github.com/opencomputeproject/ocp-registry/blob/main/command-registry.md). Codes 0xC0-0xFF are reserved for Caliptra project-specific errors.

### OCP Standard Codes

| Code   | Name                   | Description                                |
|--------|------------------------|--------------------------------------------|
| `0x00` | Success                | Command completed successfully             |
| `0x01` | General Error          | Unspecified error                          |
| `0x02` | Invalid Parameter      | One or more parameters are invalid         |
| `0x03` | Invalid Length         | Request/response length mismatch           |
| `0x04` | Invalid Identifier     | Unknown or invalid identifier              |
| `0x05` | Operation Failed       | Operation could not be completed           |
| `0x06` | Insufficient Resources | Not enough resources to complete command   |
| `0x07` | Unsupported Operation  | Command is not supported                   |
| `0x08` | Device Not Ready       | Device is not ready to process command     |
| `0x09` | Invalid Command Version| Command version not supported              |
| `0x0A` | Invalid Payload Size   | Payload size does not match expected       |
| `0x0B` | Timeout                | Operation timed out                        |
| `0x0C` | Access Denied          | Authorization required                     |
| `0x0D` | Resource Unavailable   | Requested resource is not available        |
| `0x0E` | Policy Violation       | Operation violates configured policy       |
| `0x0F` | Invalid State          | Device is not in the correct state         |

### Caliptra Project-Specific Codes (0xC0-0xFF)

| Code   | Name                      | Description                             |
|--------|---------------------------|-----------------------------------------|
| `0xC0` | Caliptra Mailbox Busy     | Caliptra mailbox is not ready           |
| `0xC1` | Caliptra Buffer Too Small | Response buffer too small               |

# External MCTP VDM Commands Spec

## Overview

This document specifies the external command protocol used by the Baseboard Management Controller (BMC) to communicate with the device integrating the Caliptra RoT subsystem for querying device-specific information, retrieving debug logs and attestation logs, managing certificates and secure debug unlock etc. The protocol is based on the MCTP (Management Component Transport Protocol) over the I3C interface and uses a vendor-defined message type (`0x7E`).

- **Device Identification and Capabilities**
    - Retrieve firmware versions, unique device identifiers, and device capabilities to ensure compatibility and proper configuration.
    - Query device-specific information such as chip identifiers or subsystem details.

- **Debugging and Diagnostics**
    - Retrieve debug logs to analyze device behavior, diagnose issues, and monitor runtime states.
    - Clear logs to reset diagnostic data and maintain storage efficiency.

- **Certificate Management**
    - Export Certificate Signing Requests (CSRs) for device keys to facilitate secure provisioning.
    - Import signed certificates to establish a trusted certificate chain for device authentication.

- **Debug Unlock Mechanisms**
    - Facilitate secure debugging in production environments
    - Ensure controlled access to debugging features

### Protocol

- **Transport Layer**: MCTP
- **Message Type**: The message type is `0x7E` as per the MCTP Base Specification. This message type supports Vendor Defined Messages, where the vendor is identified by the PCI-based Vendor ID. The initial message header is specified in the MCTP Base Specification and detailed below for completeness:

| Field Name                  | Byte(s) | Description                                                             |
|-----------------------------|---------|-------------------------------------------------------------------------|
| **Request Data**            |         |                                                                         |
| PCI/PCIe Vendor ID          | 1:2     | The MCTP Vendor ID formatted per `00h` Vendor ID format offset.         |
| Vendor-Defined Message Body | 3:N     | Vendor-defined message body, 0 to N bytes.                              |
| **Response Data**           |         |                                                                         |
| PCI/PCIe Vendor ID          | 1:2     | The value is formatted per `00h` Vendor ID offset.                      |
| Vendor-Defined Message Body | 3:M     | Vendor-defined message body, 0 to M bytes.                              |

The Vendor ID is a 16-bit unsigned integer, described in the PCI 2.3 specification. The value identifies the device manufacturer. The message body and content are described in the sections below.

### Message Format

This section describes the MCTP message format used to support Caliptra subsystem external command protocol. The request/response message body encapsulates the Vendor Defined MCTP message within the MCTP transport. Details of MCTP message encapsulation can be found in the MCTP Base Specification. The MCTP Get Vendor Defined Message Support command allows discovery of the vendor-defined messages supported by an endpoint. This discovery process identifies the vendor organization and the supported message types. The format of this request is specified in the MCTP Base Specification.

For the Caliptra external command protocol, the following information is returned in response to the MCTP Get Vendor Defined Message Support request:
- **Vendor ID Format**: `0`
- **PCI Vendor ID**: `0x1414`
- **Command Set Version**: `4`

The following table provides detailed descriptions of the fields used in the Caliptra external command protocol:

| Field Name           | Description                                                                                                   |
|----------------------|---------------------------------------------------------------------------------------------------------------|
| **IC**               | (MCTP Integrity Check bit) Indicates whether the MCTP message is covered by an overall MCTP message payload integrity check. |
| **Message Type**     | Indicates an MCTP Vendor Defined Message.                                                                     |
| **MCTP PCI Vendor**  | ID for PCI Vendor. Caliptra messages use the Microsoft PCI ID of `0x1414`.                                    |
| **Request Type**     | Distinguishes between request and response messages: set to `1` for requests, and `0` for responses. |
| **Crypt**            | Indicates whether the Message Payload and Command are encrypted.                                              |
| **Command Code**     | The command ID for the operation to execute.                                                                  |
| **Msg Integrity Check** | Represents the optional presence of a message type-specific integrity check over the contents of the message body. If present (indicated by the IC bit), the Message Integrity Check field is carried in the last bytes of the message body. |

The following table describes the MCTP message format used in the Caliptra external command protocol:

*Table: MCTP Vendor Defined Message Format*
<img src="images/mctp_vdm_format.svg" alt="Vendor defined message format" align="center" />

The protocol header fields are to be included only in the first packet of a multiple-packet MCTP message. After reconstruction of the message body, the protocol header will be used to interpret the message contents. Reserved fields must be set to `0`.

## Command List

The following table describes the commands defined under this specification. There are two categories: (1) Required commands (R) that are mandatory for all implementations, (2) Optional commands (O) that may be utilized if the specific implementation requires it.

| Message Name                  | Command | R/O | Description                                         |
|-------------------------------|---------|-----|-----------------------------------------------------|
| Firmware Version              | 01h     | R   | Retrieve firmware version information.              |
| Device Capabilities           | 02h     | R   | Retrieve device capabilities.                       |
| Device ID                     | 03h     | R   | Retrieve device ID.                                 |
| Device Information            | 04h     | R   | Retrieve device information.                        |

**Logging**

| Message Name                  | Command | R/O | Description                                         |
|-------------------------------|---------|-----|-----------------------------------------------------|
| Get Debug Log                 | 05h     | R   | Retrieve debug log.                                 |
| Clear Debug Log               | 06h     | R   | Clear debug log.                                    |
| Get Attestation Log           | 07h     | O   | Retrieve attestation measurement log.               |
| Clear Attestation Log         | 08h     | O   | Clear attestation log (requires authorization).     |

**Attestation**

| Message Name                  | Command | R/O | Description                                         |
|-------------------------------|---------|-----|-----------------------------------------------------|
| Get Attestation               | 09h     | O   | Retrieve attestation evidence. Supports OCP EAT claims token and signed PCR quote formats. |

**Debug Unlock**

| Message Name                  | Command | R/O | Description                                         |
|-------------------------------|---------|-----|-----------------------------------------------------|
| Request Debug Unlock          | 0Ah     | O   | Request debug unlock in production environment.     |
| Authorize Debug Unlock Token  | 0Bh     | O   | Send debug unlock token to device for authorization. |

**Lifecycle & Provisioning**

*Certificate Provisioning*

| Message Name                  | Command | R/O | Description                                         |
|-------------------------------|---------|-----|-----------------------------------------------------|
| Export IDevID CSR             | 0Ch     | R   | Export IDevID self-signed certificate signing request. Only available when device lifecycle state is Manufacturing. |
| Set Slot 0 Cert               | 0Dh     | R   | Set CA-signed IDevID certificate in slot 0 (Vendor PKI). |
| Get Slot 0 State              | 0Eh     | O   | Check the provisioning state of certificate slot 0 (Vendor PKI). |
| Export Attested CSR           | 0Fh     | O   | Export attested CSR for a Caliptra device identity key (LDevID, FMC Alias, or RT Alias). |

*Device Lifecycle*

| Message Name                  | Command | R/O | Description                                         |
|-------------------------------|---------|-----|-----------------------------------------------------|
| Program Field Entropy         | 10h     | O   | Program field entropy into the device. Requires authorization. |
| Device Ownership Transfer     | 11h     | O   | Transfer device ownership. Requires authorization.  |

## Command Format

This section defines the structure of the `Message Payload` field, as referenced in the "MCTP Vendor Defined Message Format" table for each command's request and response messages.

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

This command retrieves the device ID. The request for this command contains no additional payload.

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

Exports the IDevID Certificate Signing Request(CSR) so that a Certificate Authority (CA) can endorse it and issue an IDevID certificate. The CSR is available in two algorithm variants: ECC P-384 and ML-DSA (post-quantum). This command is only available when the device lifecycle state is `Manufacturing`.

**Request Payload**:

| Byte(s) | Name  | Type | Description |
|---------|-------|------|-------------|
| 0:3     | index | u32  | Index: Default = `0` <br>- `00h` = IDevID ECC P-384 CSR <br>- `01h` = IDevID ML-DSA CSR |

**Response Payload**:

| Byte(s) | Name            | Type         | Description                                   |
|---------|-----------------|--------------|-----------------------------------------------|
| 0:3     | completion_code | u32          | Command completion status                     |
| 4:7     | data_size       | u32          | Length in bytes of the valid data in the data field |
| 8:N     | data            | u8[data_size]| DER-encoded IDevID certificate signing request|

### Set Slot 0 Cert

Sets the CA-signed IDevID certificate in certificate slot 0 (Vendor PKI). This is a one-time operation performed during manufacturing — the command will fail if slot 0 has already been provisioned.

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
| 4:7     | state           | u32  | Slot State (per SPDM slot provisioning model): <br>- `0` = Does not exist — slot is not supported. <br>- `1` = Exists and empty — slot is supported but not provisioned. <br>- `2` = Exists with key — slot has a key but no certificate. <br>- `3` = Exists with key and cert — slot has both a key and a certificate. |

### Get Debug Log

Retrieves the debug log for the RoT. The debug log contains RoT application information and machine state, useful for diagnostics and troubleshooting.

**Request Payload**: Empty

**Response Payload**:

| Byte(s) | Name            | Type         | Description                                   |
|---------|-----------------|--------------|-----------------------------------------------|
| 0:3     | completion_code | u32          | Command completion status                     |
| 4:7     | data_size       | u32          | Size of the log data in bytes                 |
| 8:N     | data            | u8[data_size]| Debug log contents                            |

The length is determined by the end of the log or the packet size based on device capabilities. If the response spans multiple MCTP messages, the end of the response will be determined by an MCTP message with a payload smaller than the maximum payload supported by both devices. To guarantee a response will never fall exactly on the max payload boundary, the responder must send back an extra packet with zero payload.

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
| 0:3       | length                   | u32          | Length of the message in DWORDs                                             |
| 4:35      | unique_device_identifier | u8[32]       | Device identifier of the Caliptra device                                    |
| 36        | unlock_level             | u8           | Debug unlock level (1-8)                                                    |
| 37:39     | reserved                 | u8[3]        | Reserved field                                                              |
| 40:87     | challenge                | u8[48]       | Random number challenge                                                     |
| 88:183    | ecc_public_key           | u32[24]      | ECC public key in hardware format (little endian)                           |
| 184:2635  | mldsa_public_key         | u32[648]     | MLDSA public key in hardware format (little endian)                         |
| 2636:2731 | ecc_signature            | u32[24]      | ECC P-384 signature of the message hashed using SHA2-384 (R and S coordinates) |
| 2732:6195 | mldsa_signature          | u32[1157]    | MLDSA signature of the message hashed using SHA2-512 (4627 bytes + 1 reserved byte) |

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
| 4:7     | algorithm     | u32  | Asymmetric Algorithm: <br>- `0x0001` = ECC P-384 <br>- `0x0002` = ML-DSA-87 |

**Response Payload**:

| Byte(s) | Name            | Type          | Description                                   |
|---------|-----------------|---------------|-----------------------------------------------|
| 0:3     | completion_code | u32           | Command completion status                     |
| 4:7     | data_size       | u32           | Length in bytes of the attested CSR data       |
| 8:N     | data            | u8[data_size] | Attested CSR data blob                        |

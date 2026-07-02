# External MCTP VDM Commands Spec

## Overview

This document specifies the external command protocol used by the Baseboard Management Controller (BMC) to communicate with the device integrating the Caliptra RoT subsystem. The protocol is based on the MCTP (Management Component Transport Protocol) over the I3C interface and uses a vendor-defined IANA message type (`0x7F`).

### Protocol

- **Transport Layer**: MCTP
- **Message Type**: The message type is `0x7F` as per the MCTP Base Specification. This message type supports Vendor Defined Messages, where the vendor is identified by an IANA enterprise number. The initial message header is specified in the MCTP Base Specification and detailed below for completeness:

| Field Name                  | Byte(s) | Description                                                     |
| --------------------------- | ------- | --------------------------------------------------------------- |
| **Request Data**            |         |                                                                 |
| IANA Enterprise ID          | 1:4     | The MCTP Vendor ID formatted per `01h` Vendor ID format offset. |
| Vendor-Defined Message Body | 5:N     | Vendor-defined message body, 0 to N bytes.                      |
| **Response Data**           |         |                                                                 |
| IANA Enterprise ID          | 1:4     | The value is formatted per `01h` Vendor ID offset.              |
| Vendor-Defined Message Body | 5:M     | Vendor-defined message body, 0 to M bytes.                      |

The IANA Enterprise ID is a 32-bit unsigned integer assigned by IANA. The message body and content are described in the sections below.

### Message Format

This section describes the MCTP message format used to support Caliptra subsystem external command protocol. The request/response message body encapsulates the Vendor Defined MCTP message within the MCTP transport. Details of MCTP message encapsulation can be found in the MCTP Base Specification. The MCTP Get Vendor Defined Message Support command allows discovery of the vendor-defined messages supported by an endpoint. This discovery process identifies the vendor organization and the supported message types. The format of this request is specified in the MCTP Base Specification.

For the Caliptra external command protocol, the following information is returned in response to the MCTP Get Vendor Defined Message Support request:
- **Vendor ID Format**: `1`
- **OCP Vendor ID**: `42623`

The following table describes the Caliptra direct MCTP VDM message body layout. Byte offsets are zero-based from the first byte of the MCTP message body.

| Byte Offset            | Bit(s) | Field Name                  | Value / Description                                                                                                                                                          |
| ---------------------- | ------ | --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| +0                     | 7      | **IC**                      | MCTP integrity check bit. Indicates whether the MCTP message is covered by an overall MCTP message payload integrity check.                                                  |
| +0                     | 6:0    | **Message Type**            | MCTP Vendor Defined Message type. Caliptra direct MCTP VDM uses message type `0x7F`.                                                                                         |
| +1:+4                  | 31:0   | **MCTP IANA Enterprise ID** | IANA enterprise ID for the vendor. Caliptra messages use the OCP Vendor ID `42623` (`0x0000A67F`), encoded most-significant byte first.                                      |
| +5                     | 7      | **Request Type**            | Set to `1` for requests and `0` for responses.                                                                                                                               |
| +5                     | 6:0    | **Reserved**                | Reserved and set to `0`.                                                                                                                                                     |
| +6                     | 7:0    | **Command Code**            | Caliptra direct MCTP VDM command code.                                                                                                                                       |
| +7:N                   | N/A    | **Message Payload**         | Command-specific request or response payload.                                                                                                                                |
| Last bytes, if present | N/A    | **Msg Integrity Check**     | Optional MCTP message integrity check. If present, as indicated by the MCTP IC bit, the Message Integrity Check field is carried in the last bytes of the MCTP message body. |

The protocol header fields are to be included only in the first packet of a multiple-packet MCTP message. After reconstruction of the message body, the protocol header will be used to interpret the message contents. Reserved fields must be set to `0`.

## Command List and Definitions

This transport carries Caliptra common commands that do not require SPDM authorization, SPDM-defined semantics, or SPDM streaming/chunking. Command payload definitions are shared with the transport-agnostic [Caliptra Common Commands](caliptra_common_commands.md) specification.

| Command Code | Command Name       | Description                            |
| ------------ | ------------------ | -------------------------------------- |
| `0x01`       | FirmwareVersion    | Retrieve firmware version information. |
| `0x02`       | DeviceCapabilities | Retrieve device capabilities.          |
| `0x03`       | GetDebugLog        | Retrieve the MCU runtime debug log.    |
| `0x04`       | ClearDebugLog      | Clear the MCU runtime debug log.       |
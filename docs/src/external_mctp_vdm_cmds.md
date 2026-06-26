# External MCTP VDM Commands Spec

## Overview

This document specifies the external command protocol used by the Baseboard Management Controller (BMC) to communicate with the device integrating the Caliptra RoT subsystem. The protocol is based on the MCTP (Management Component Transport Protocol) over the I3C interface and uses a vendor-defined IANA message type (`0x7F`).

### Protocol

- **Transport Layer**: MCTP
- **Message Type**: The message type is `0x7F` as per the MCTP Base Specification. This message type supports Vendor Defined Messages, where the vendor is identified by an IANA enterprise number. The initial message header is specified in the MCTP Base Specification and detailed below for completeness:

| Field Name                  | Byte(s) | Description                                                             |
|-----------------------------|---------|-------------------------------------------------------------------------|
| **Request Data**            |         |                                                                         |
| IANA Enterprise ID          | 1:4     | The MCTP Vendor ID formatted per `01h` Vendor ID format offset.         |
| Vendor-Defined Message Body | 5:N     | Vendor-defined message body, 0 to N bytes.                              |
| **Response Data**           |         |                                                                         |
| IANA Enterprise ID          | 1:4     | The value is formatted per `01h` Vendor ID offset.                      |
| Vendor-Defined Message Body | 5:M     | Vendor-defined message body, 0 to M bytes.                              |

The IANA Enterprise ID is a 32-bit unsigned integer assigned by IANA. The message body and content are described in the sections below.

### Message Format

This section describes the MCTP message format used to support Caliptra subsystem external command protocol. The request/response message body encapsulates the Vendor Defined MCTP message within the MCTP transport. Details of MCTP message encapsulation can be found in the MCTP Base Specification. The MCTP Get Vendor Defined Message Support command allows discovery of the vendor-defined messages supported by an endpoint. This discovery process identifies the vendor organization and the supported message types. The format of this request is specified in the MCTP Base Specification.

For the Caliptra external command protocol, the following information is returned in response to the MCTP Get Vendor Defined Message Support request:
- **Vendor ID Format**: `1`
- **OCP Vendor ID**: `42623`
- **Command Set Version**: `4`

The following table provides detailed descriptions of the fields used in the Caliptra external command protocol:

| Field Name           | Description                                                                                                   |
|----------------------|---------------------------------------------------------------------------------------------------------------|
| **IC**               | (MCTP Integrity Check bit) Indicates whether the MCTP message is covered by an overall MCTP message payload integrity check. |
| **Message Type**     | Indicates an MCTP Vendor Defined Message.                                                                     |
| **MCTP IANA Enterprise ID** | IANA enterprise ID for the vendor. Caliptra messages use the OCP Vendor ID `42623`.                    |
| **Request Type**     | Distinguishes between request and response messages: set to `1` for requests, and `0` for responses. |
| **Crypt**            | Indicates whether the Message Payload and Command are encrypted.                                              |
| **Command Code**     | The command ID for the operation to execute.                                                                  |
| **Msg Integrity Check** | Represents the optional presence of a message type-specific integrity check over the contents of the message body. If present (indicated by the IC bit), the Message Integrity Check field is carried in the last bytes of the message body. |

The following table describes the MCTP message format used in the Caliptra external command protocol:

*Table: MCTP Vendor Defined Message Format*
<img src="images/mctp_vdm_format.svg" alt="Vendor defined message format" align="center" />

The protocol header fields are to be included only in the first packet of a multiple-packet MCTP message. After reconstruction of the message body, the protocol header will be used to interpret the message contents. Reserved fields must be set to `0`.

## Command List and Definitions
TBD
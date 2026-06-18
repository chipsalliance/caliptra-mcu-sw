# MCTP VDM Extension Framework

## Overview

This document describes how an integrator can define a vendor-specific protocol over MCTP Vendor Defined Messages (VDM). It is a framework for platform or vendor extensions, not a Caliptra standard command specification.

Caliptra vendor-neutral device-management commands are defined in [Caliptra Common Commands](caliptra_common_commands.md). Those commands are transported out-of-band through [Caliptra SPDM VDM Commands](caliptra_spdm_vdm_cmds.md) and in-band through [External Mailbox Commands](external_mailbox_cmds.md). They are not defined in this MCTP VDM extension document.

MCTP VDM is reserved for integrator-owned extensions that are outside the Caliptra common command set. The integrator owns the Vendor ID, command set version, command code allocation, payload formats, completion codes, discovery model, and security policy for those extensions.

## Scope

This document covers:

- MCTP VDM framing for message type `0x7E`.
- Use of the MCTP Get Vendor Defined Message Support command to advertise an integrator command set.
- A template for integrators to specify their own command protocol.

This document does not define:

- Caliptra common command payloads or completion codes.
- SPDM VDM command codes under the OCP IANA Vendor ID.
- MCI mailbox command IDs or mailbox request/response payloads.
- MCU SDK handlers for vendor-specific commands.

## Relationship to Caliptra Commands

| Area                              | Document                                                | Owner                  |
| --------------------------------- | ------------------------------------------------------- | ---------------------- |
| Caliptra common command semantics | [Caliptra Common Commands](caliptra_common_commands.md) | Caliptra Working Group |
| Standard out-of-band transport    | [Caliptra SPDM VDM Commands](caliptra_spdm_vdm_cmds.md) | Caliptra Working Group |
| In-band transport                 | [External Mailbox Commands](external_mailbox_cmds.md)   | Caliptra MCU SDK       |
| Vendor-specific MCTP extensions   | This document                                           | Integrator/vendor      |

## Protocol

- **Transport Layer**: MCTP
- **Message Type**: `0x7E` as defined by the MCTP Base Specification for Vendor Defined Messages.
- **Vendor Identification**: The vendor is identified by the Vendor ID field in the MCTP VDM payload. Integrators should use their own PCI Vendor ID or another Vendor ID format allowed by the MCTP Base Specification.

The MCTP VDM payload starts with a vendor identifier followed by a vendor-defined message body:

| Field Name                  | Byte(s) | Description                                                          |
| --------------------------- | ------- | -------------------------------------------------------------------- |
| **Request Data**            |         |                                                                      |
| Vendor ID                   | 1:2     | Vendor ID formatted according to the selected MCTP Vendor ID format. |
| Vendor-Defined Message Body | 3:N     | Integrator-defined request body.                                     |
| **Response Data**           |         |                                                                      |
| Vendor ID                   | 1:2     | Same Vendor ID format used by the request.                           |
| Vendor-Defined Message Body | 3:M     | Integrator-defined response body.                                    |

The Vendor ID identifies the organization that owns the command set. The message body is defined by that organization.

## Vendor Defined Message Support

The MCTP Get Vendor Defined Message Support command allows a requester to discover the vendor-defined message sets supported by an endpoint. Integrators should document the values returned for their extension protocol:

| Field               | Owner      | Description                                  |
| ------------------- | ---------- | -------------------------------------------- |
| Vendor ID Format    | Integrator | Vendor ID format advertised by the endpoint. |
| Vendor ID           | Integrator | Vendor ID that owns the extension protocol.  |
| Command Set Version | Integrator | Version of the vendor-defined command set.   |

These discovery values do not advertise Caliptra common commands. Standard Caliptra commands are discovered and invoked through their own transport-specific mechanisms.

## Message Format

The following table describes common fields an integrator-defined MCTP VDM protocol may carry after the MCTP common header. Field names and exact bit assignments must be specified by the integrator command-set definition.

| Field Name                  | Description                                                                                                                                                       |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **IC**                      | MCTP Integrity Check bit. Indicates whether the MCTP message includes an overall MCTP message payload integrity check.                                            |
| **Message Type**            | Indicates MCTP Vendor Defined Message type `0x7E`.                                                                                                                |
| **Vendor ID**               | Vendor identifier that owns the extension protocol.                                                                                                               |
| **Request Type**            | Distinguishes request messages from response messages.                                                                                                            |
| **Crypt**                   | Indicates whether the vendor-defined message body is encrypted, if the extension protocol defines encryption.                                                     |
| **Command Code**            | Integrator-defined command identifier.                                                                                                                            |
| **Message Integrity Check** | Optional message type-specific integrity check over the vendor-defined message body. If present, its format and placement are defined by the integrator protocol. |

*Table: MCTP Vendor Defined Message Format*
<img src="images/mctp_vdm_format.svg" alt="Vendor defined message format" align="center" />

The protocol header fields are included only in the first packet of a multi-packet MCTP message. After message reassembly, the protocol header is used to interpret the vendor-defined message body. Reserved fields must be set to `0` unless the integrator command-set definition assigns them.

## Vendor Extension Command Set Template

Integrators that expose MCTP VDM extensions should define their own command set. The command set definition should include at least the following information:

| Item                | Description                                                                        |
| ------------------- | ---------------------------------------------------------------------------------- |
| Vendor ID           | Vendor ID used by the extension protocol.                                          |
| Command Set Version | Version value returned by MCTP Get Vendor Defined Message Support.                 |
| Command List        | Command codes, names, required/optional status, and descriptions.                  |
| Request Payloads    | Byte layout, endianness, alignment, and validation rules for each command request. |
| Response Payloads   | Byte layout, completion code placement, and command-specific response data.        |
| Completion Codes    | Success and error code values.                                                     |
| Discovery           | How clients discover optional commands and feature flags.                          |
| Security            | Authorization, replay protection, encryption, and integrity requirements.          |
| Compatibility       | Versioning and backwards-compatibility rules.                                      |

No Caliptra common commands are assigned in this document.
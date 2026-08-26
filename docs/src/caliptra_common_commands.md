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

| Message Name                    | R/O | Transport(s)          | Description                                                                                                                          |
| ------------------------------- | --- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Firmware Version                | R   | MCTP VDM, MCI Mailbox | Retrieve firmware version information.                                                                                               |
| Device Capabilities             | R   | MCTP VDM, MCI Mailbox | Retrieve device capabilities.                                                                                                        |
| Get Debug Log                   | R   | MCTP VDM, MCI Mailbox | Retrieve debug log.                                                                                                                  |
| Clear Debug Log                 | R   | MCTP VDM, MCI Mailbox | Clear debug log.                                                                                                                     |
| Get Attestation                 | O   | SPDM VDM, MCI Mailbox | Retrieve signed attestation evidence in a requester-selected format.                                                                 |
| Request Debug Unlock            | O   | SPDM VDM, MCI Mailbox | Request debug unlock in production environment.                                                                                      |
| Authorize Debug Unlock Token    | O   | SPDM VDM, MCI Mailbox | Send debug unlock token to device for authorization.                                                                                 |
| Export Attested CSR             | O   | SPDM VDM, MCI Mailbox | Export attested CSR for a Caliptra device identity key (LDevID, FMC Alias, or RT Alias).                                             |
| Device Ownership Transfer       | O   | SPDM VDM, MCI Mailbox | Query and change the implemented DOT state.                                                                                          |
| Authorization-Gated Subcommands | O   | SPDM VDM, MCI Mailbox | Security-sensitive provisioning and fuse subcommands using a one-use challenge and hybrid signature.                                |

### Authorization-Gated Subcommands

The following subcommands are assigned to the SPDM VDM IANA authorization-gated path and are also available through the MCI mailbox path where implemented. Both paths use the same one-use challenge and hybrid-signature verification described in [Caliptra SPDM VDM Commands](caliptra_spdm_vdm_cmds.md#authorization-flow); only their outer framing differs.

| Subcommand Name                | Transport(s)               | Description                                        |
| ------------------------------ | -------------------------- | -------------------------------------------------- |
| Get Auth Challenge             | SPDM VDM IANA, MCI Mailbox | Challenge acquisition for authorization-gated use. |
| Provision Vendor PK Hash       | SPDM VDM IANA, MCI Mailbox | Provision vendor public key hash.                  |
| Fuse Increase Caliptra Min SVN | SPDM VDM IANA, MCI Mailbox | Increase Caliptra minimum SVN.                     |
| Program Field Entropy          | SPDM VDM IANA, MCI Mailbox | Program field entropy.                             |
| Fuse Revoke Vendor Public Key  | SPDM VDM IANA, MCI Mailbox | Revoke vendor public key.                          |
| Fuse Revoke Vendor PK Hash     | SPDM VDM IANA, MCI Mailbox | Revoke vendor public key hash.                     |
| Fuse Lock Partition            | SPDM VDM IANA, MCI Mailbox | Lock fuse partition.                               |
| Dot Lock                       | SPDM VDM IANA, MCI Mailbox | Lock the DOT after ownership validation.          |
| Dot Disable                    | SPDM VDM IANA, MCI Mailbox | Enter ODD state with no DOT-supplied CAK.          |
| Dot Rotate                     | SPDM VDM IANA, MCI Mailbox | Replace DOT key digests and advance the epoch.     |
| Get Dot Backup Blob            | SPDM VDM IANA, MCI Mailbox | Export the current DOT backup blob.               |

## Command Definitions

This section defines the request and response payloads for each command.

Common response payload tables describe command-specific response data only. They exclude transport-specific status and framing fields such as SPDM VDM completion codes, MCTP VDM completion codes, MCI mailbox `chksum`, MCI mailbox `fips_status`, and MCI mailbox variable-length `data_len` headers.

### Firmware Version

Retrieves the version of the target firmware.

**Request Payload**:

| Byte(s) | Name       | Type | Description                                                                                                                                                                                                   |
| ------- | ---------- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0:3     | area_index | u32  | Area Index: <br>- `00h` = Caliptra core firmware <br>- `01h` = MCU Runtime firmware <br>- `02h` = Optional integrator-defined aggregate SoC firmware-set version <br>Additional indexes are firmware-specific |

**Response Payload**:

| Byte(s) | Name    | Type   | Description                             |
| ------- | ------- | ------ | --------------------------------------- |
| 0:31    | version | u8[32] | Firmware Version Number in ASCII format |

Versions use `major.minor.patch` ASCII format. Index `02h` returns `UnsupportedOperation` when the integrator does not provide a single aggregate SoC firmware-set version. Individual SoC component versions may use firmware-specific additional indexes.

### Device Capabilities

**Request Payload**: Empty

**Response Payload**:

| Byte(s) | Name                   | Type  | Description                                                 |
| ------- | ---------------------- | ----- | ----------------------------------------------------------- |
| 0:7     | caliptra_rt            | u64   | Caliptra Runtime capabilities, copied from Core, big-endian |
| 8:11    | caliptra_fmc           | u32   | Caliptra FMC capabilities, copied from Core, big-endian     |
| 12:15   | caliptra_rom           | u32   | Caliptra ROM capabilities, copied from Core, big-endian     |
| 16:19   | mcu_rom                | u32   | MCU ROM capabilities, big-endian                            |
| 20:23   | mcu_rt                 | u32   | MCU Runtime feature capabilities, big-endian                |
| 24:27   | external_commands      | u32   | Supported top-level common commands, big-endian             |
| 28:31   | authorized_subcommands | u32   | Supported subcommands under `AuthorizedCommand`, big-endian |
| 32:35   | reserved               | u8[4] | Reserved; responders set to zero                            |

`external_commands` covers the OCP command codes `01h` through `20h`. Command code `N` maps to bitmap bit `N - 1`, allowing all 32 top-level codes to fit in this field. This is Caliptra common-command discovery carried by `DeviceCapabilities`; it is not MCTP Control Protocol command discovery.

**External Common-Command Capability Flags**:

| Bitmap Bit | Command Code | Command                     | Transport             |
| ---------- | ------------ | --------------------------- | --------------------- |
| 0          | `01h`        | `FirmwareVersion`           | MCTP VDM              |
| 1          | `02h`        | `DeviceCapabilities`        | MCTP VDM              |
| 2          | `03h`        | `GetDebugLog`               | MCTP VDM              |
| 3          | `04h`        | `ClearDebugLog`             | MCTP VDM              |
| 4          | `05h`        | `GetAttestation`            | SPDM VDM, MCU mailbox |
| 5          | `06h`        | `RequestDebugUnlock`        | SPDM VDM              |
| 6          | `07h`        | `AuthorizeDebugUnlockToken` | SPDM VDM              |
| 7          | `08h`        | `ExportAttestedCsr`         | SPDM VDM              |
| 16         | `11h`        | `DeviceOwnershipTransfer`   | SPDM VDM              |
| 17         | `12h`        | `AuthorizedCommand`         | SPDM VDM              |

This table defines the bit assignment for every allocated command code. A responder sets a bit only when the corresponding command is implemented. `GetAttestation` is set when a responder that carries it is built and the device can produce at least one evidence format. `AuthorizedCommand` is set when its wrapper and at least one authorized subcommand are implemented.

**Authorized-Subcommand Capability Flags**:

| Bitmap Bit | Subcommand                   | Status      |
| ---------- | ---------------------------- | ----------- |
| 0          | `GetAuthChallenge`           | Implemented |
| 1          | `ProvisionVendorPkHash`      | Implemented |
| 2          | `FuseIncreaseCaliptraMinSvn` | Implemented |
| 3          | `ProgramFieldEntropy`        | Implemented |
| 4          | `FuseRevokeVendorPublicKey`  | Implemented |
| 5          | `FuseRevokeVendorPkHash`     | Implemented |
| 6          | `FuseLockPartition`          | Implemented |
| 7          | `ProvisionOwnerPkHash`       | Implemented |
| 8          | `DotLock`                    | Implemented |
| 9          | `DotDisable`                 | Implemented |
| 10         | `DotRotate`                  | Implemented |
| 11         | `GetDotBackupBlob`           | Implemented |
| 12:31      | Reserved                     | —           |

The authorized-subcommand assignments are stable capability indexes; they are not transport command IDs. A responder sets a bit only when that subcommand is implemented under `AuthorizedCommand`. Authorization, lifecycle, or policy restrictions do not clear an implementation capability bit; execution can still return `AccessDenied`, `PolicyViolation`, or `InvalidState`.

**MCU Runtime Capability Flags**:

| Bit | Name                  | Description                                           |
| --- | --------------------- | ----------------------------------------------------- |
| 0   | `FLASH_BOOT`          | MCU Runtime supports flash-based image loading        |
| 1   | `STREAMING_BOOT`      | MCU Runtime supports streaming image loading          |
| 2   | `FIRMWARE_UPDATE`     | MCU Runtime supports firmware update                  |
| 3   | `SPDM_RESPONDER`      | MCU Runtime includes the SPDM responder               |
| 4   | `MCTP_VDM_RESPONDER`  | MCU Runtime includes the MCTP VDM responder           |
| 5   | `USERSPACE_DEBUG_LOG` | MCU Runtime includes userspace debug logging          |
| 6   | `MCI_MAILBOX_SERVICE` | MCU Runtime includes the external MCI mailbox service |
| 7   | `DOE`                 | MCU Runtime includes the DOE transport                |

The `mcu_rom` field is reserved and responders currently set it to zero.

### Get Debug Log

Retrieves the debug log for the MCU Runtime.

**Request Payload**: Empty

**Response Payload**:

| Byte(s) | Name      | Type          | Description                         |
| ------- | --------- | ------------- | ----------------------------------- |
| 0:3     | more_data | u32           | `1` if more log data remains        |
| 4:7     | data_size | u32           | Size of the valid log data in bytes |
| 8:N     | data      | u8[data_size] | Debug log contents                  |

For defmt-based debug logs, the device exposes a sequential drain interface rather than random access to individual log entries. Callers drain the debug log by repeating this command until `more_data` is `0`. Each response contains zero or more complete defmt frames. The host concatenates the returned data and decodes the resulting frame stream using the matching firmware ELF.

**Debug Log Format**:

The debug log payload is an opaque byte stream. For the MCU Runtime debug log, the current implementation uses the [defmt](https://crates.io/crates/defmt) crate. Each `defmt` log macro emits one complete rzCOBS-encoded frame, and the MCU runtime logging backend appends that complete frame as one flash log entry. `Get Debug Log` returns the concatenated raw frame bytes.

The device does not store human-readable log strings in the debug log. A host tool decodes the returned byte stream with `defmt-decoder` or `defmt-print` using the exact app's ELF that produced the log; the ELF `.defmt` section contains the interned format strings and metadata required to render readable messages.

### Clear Debug Log

Clears the debug log in the MCU Runtime. No authorization is required.

**Request Payload**: Empty

**Response Payload**: Empty. Command completion status is carried by the transport-specific response framing.

### Get Attestation

Retrieves signed attestation evidence bound to a requester-supplied nonce.

The requester selects the evidence format at runtime. The set of formats a
device can produce is fixed at build time by the evidence generators it links.
A requester discovers that set with the format-discovery query below.

All formats are signed with the device attestation key that terminates the
device's SPDM certificate chain. Evidence retrieved over the MCI mailbox
verifies against a certificate chain retrieved over SPDM, and the reverse.

#### Evidence Formats

| Value    | Name      | Description                                                                       |
| -------- | --------- | --------------------------------------------------------------------------------- |
| `0x0000` | (query)   | Reserved. Selects the format-discovery query.                                     |
| `0x0001` | OCP EAT   | Signed OCP Entity Attestation Token (COSE_Sign1) carrying OCP EAT profile claims. |
| `0x0002` | PCR Quote | Caliptra PCR quote.                                                               |

A device that supports a format need not support it under every algorithm. The
OCP EAT signer emits ES384 only; ML-DSA-87 EATs are not implemented yet. A
request naming an unsupported `(evidence_format, algorithm)` pair returns
`UNSUPPORTED_OPERATION` and no evidence is generated.

#### PKI Entity Slot

`pki_entity_slot` names the PKI entity whose hierarchy endorses the signing key.

| Value    | Name   | Description                    |
| -------- | ------ | ------------------------------ |
| `0x0000` | Vendor | Device manufacturer hierarchy. |
| `0x0001` | Owner  | Owner hierarchy. Reserved.     |

A value not listed above returns `INVALID_PARAMS`. `Owner` is reserved and
returns `UNSUPPORTED_OPERATION`; the current signer supports only the Vendor
entity.

#### Format Discovery

A request with `evidence_format` = `0x0000` is a query, not an evidence request.
The device returns a bitmap of the formats it can produce instead of evidence.
Bit *n* of the bitmap is set when the device supports the format whose wire
value is *n*; bit 0 is never set.

The supported set depends on which evidence generators the integrator built into
the device. A requester issues this query before requesting evidence rather than
inferring the set from `DeviceCapabilities`.

**Request Payload**:

| Byte(s) | Name            | Type   | Description                                                                                          |
| ------- | --------------- | ------ | ---------------------------------------------------------------------------------------------------- |
| 0:3     | evidence_format | u32    | Requested evidence format, or `0x0000` for the format-discovery query                                |
| 4:7     | algorithm       | u32    | Asymmetric Algorithm: <br>- `0x0001` = ECC P-384 <br>- `0x0002` = ML-DSA-87 <br>Ignored for the query request |
| 8:11    | pki_entity_slot | u32    | PKI entity: <br>- `0x0000` = Vendor <br>- `0x0001` = Owner <br>Ignored for the query request |
| 12:43   | nonce           | u8[32] | Nonce bound into the signed evidence for freshness. Ignored for the query request.                    |

For the query request, `algorithm`, `pki_entity_slot`, and `nonce` are ignored.
For an evidence request, a value outside the tables above returns
`INVALID_PARAMS`.

**Response Payload**:

| Byte(s) | Name            | Type          | Description                                                                                                    |
| ------- | --------------- | ------------- | -------------------------------------------------------------------------------------------------------------- |
| 0:3     | evidence_format | u32           | Echo of the requested `evidence_format`                                                                        |
| 4:N     | data            | u8[]          | For a format request: the signed evidence blob. For the query (`evidence_format` = `0x0000`): a `u32` bitmap of supported formats. |

The evidence blob is variable length, delimited by the transport's length field.
The transports scope that field differently:

| Transport   | Length field                          | Counts                                            |
| ----------- | ------------------------------------- | ------------------------------------------------- |
| SPDM VDM    | `data_len`, framed after `evidence_format` | The evidence bytes only                      |
| MCI Mailbox | `MailboxRespHeaderVarSize.data_len`   | The `evidence_format` field plus the evidence bytes |

For the MCI mailbox the evidence length is therefore `data_len - 4`.

Truncated evidence cannot pass signature verification, so a device that cannot
fit the evidence in the response buffer fails the command instead.

#### Transport Sizing

Attestation evidence is variable length, and its size depends on which evidence
generators the integrator builds into the device. Each transport sizes its
response buffer from those generators:

- **SPDM VDM** reserves the size the requested format needs. Evidence that does
  not fit in a single message is returned over the large-response (chunked)
  path. The advertised `MaxSPDMmsgSize` must cover the largest evidence the
  device can produce. See [SPDM VDM commands](caliptra_spdm_vdm_cmds.md).
- **MCI Mailbox** sizes the `GET_ATTESTATION` response buffer for the largest
  supported evidence. Other commands' response buffers are unaffected.

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
| 0:3     | length                   | u32    | Length of the message in DWORDs          |
| 4:35    | unique_device_identifier | u8[32] | Device identifier of the Caliptra device |
| 36:83   | challenge                | u8[48] | Random number challenge                  |

### Authorize Debug Unlock Token

Authorizes the debug unlock token. The request body is identical for MCI mailbox and SPDM VDM transports. The requester computes the leading `checksum` field as the Caliptra RT mailbox request checksum so the unified command handler can relay the complete request unchanged.

**Request Payload**:

| Byte(s)   | Name                     | Type      | Description                                                                           |
| --------- | ------------------------ | --------- | ------------------------------------------------------------------------------------- |
| 0:3       | checksum                 | u32       | Requester-computed Caliptra RT mailbox request checksum (`MailboxReqHeader.checksum`) |
| 4:7       | length                   | u32       | Length of the message in DWORDs                                                       |
| 8:39      | unique_device_identifier | u8[32]    | Device identifier of the Caliptra device                                              |
| 40        | unlock_level             | u8        | Debug unlock level (1-8)                                                              |
| 41:43     | reserved                 | u8[3]     | Reserved field                                                                        |
| 44:91     | challenge                | u8[48]    | Random number challenge                                                               |
| 92:187    | ecc_public_key           | u32[24]   | ECC public key in hardware format (little endian)                                     |
| 188:2779  | mldsa_public_key         | u32[648]  | MLDSA public key in hardware format (little endian)                                   |
| 2780:2875 | ecc_signature            | u32[24]   | ECC P-384 signature of the message hashed using SHA2-384 (R and S coordinates)        |
| 2876:7503 | mldsa_signature          | u32[1157] | MLDSA signature of the message hashed using SHA2-512 (4627 bytes + 1 reserved byte)   |

**Response Payload**: Empty. Command completion status is carried by the transport-specific response framing.

### Export Attested CSR

Exports an attested Certificate Signing Request (CSR) for a specified device key.

**Request Payload**:

| Byte(s) | Name          | Type   | Description                                                                                         |
| ------- | ------------- | ------ | --------------------------------------------------------------------------------------------------- |
| 0:3     | device_key_id | u32    | Device Key Identifier: <br>- `0x0001` = LDevID <br>- `0x0002` = FMC Alias <br>- `0x0003` = RT Alias |
| 4:7     | algorithm     | u32    | Asymmetric Algorithm: <br>- `0x0001` = ECC P-384 <br>- `0x0002` = ML-DSA-87                         |
| 8:39    | nonce         | u8[32] | 32-byte nonce for freshness                                                                         |

**Response Payload**:

| Byte(s) | Name      | Type          | Description                              |
| ------- | --------- | ------------- | ---------------------------------------- |
| 0:3     | data_size | u32           | Length in bytes of the attested CSR data |
| 4:N     | data      | u8[data_size] | Attested CSR data blob                   |

### Authorization-Gated Subcommand Wrapper

Security-sensitive provisioning and fuse subcommands are assigned to the SPDM
VDM IANA authorization-gated path and the MCI mailbox path. The SPDM VDM
transport uses an `Authorized Command` wrapper, while MCI uses each operation's
mailbox command ID directly. In both cases the requester first obtains a one-use
48-byte challenge and appends the common public-key and hybrid-signature trailer
over `command_id(BE) || command_payload || challenge`. See
[Caliptra SPDM VDM Commands](caliptra_spdm_vdm_cmds.md#authorization-flow) for
the byte-exact SPDM framing.

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

`DotLock`, `DotDisable`, `DotRotate`, and `GetDotBackupBlob` are the DOT-family subcommands that use this authorization wrapper. The remaining DOT commands (`DotUnlockChallenge`, `DotUnlock`, `DotStatus`, `DotRecovery`, `DotOverrideChallenge`, and `DotOverride`) are native device-ownership-transfer commands carried under top-level command `0x11` rather than via the `AuthorizedCommand` wrapper.

Subcommand-specific payloads are defined by the corresponding command specifications and contain no mailbox request header.

### Get Auth Challenge

Requests a one-use challenge for authorization-gated commands.

**Request Payload**: Empty

**Response Payload**:

| Byte(s) | Name      | Type   | Description                               |
| ------- | --------- | ------ | ----------------------------------------- |
| 0:47    | challenge | u8[48] | One-use command authorization challenge.  |

### Provision Vendor PK Hash

Provisions the vendor public key hash.

**Request Payload**: `slot:u32 | hash:u8[48] | HybridSignature`

**Response Payload**: Empty

### Fuse Increase Caliptra Min SVN

Increases the Caliptra minimum SVN.

**Request Payload**: `flags:u32 | svn:u32 | HybridSignature`

**Response Payload**: Empty

### Program Field Entropy

Programs field entropy.

**Request Payload**: `partition:u32 | HybridSignature`

**Response Payload**: Empty

### Fuse Revoke Vendor Public Key

Revokes a vendor public key.

**Request Payload**: `reserved:u32 | slot:u32 | key_type:u32 | key_index:u32 | HybridSignature`

**Response Payload**: Empty

### Fuse Revoke Vendor PK Hash

Revokes a vendor public key hash.

**Request Payload**: `reserved:u32 | slot:u32 | HybridSignature`

**Response Payload**: Empty

### Fuse Lock Partition

Locks a fuse partition.

**Request Payload**: `partition:u32 | HybridSignature`

**Response Payload**: Empty

### Device Ownership Transfer (DOT)

The device-ownership-transfer family is carried under the top-level `DeviceOwnershipTransfer` command (`0x11`). This family uses the DOT FourCC namespace and is split between authorization-gated and native commands:

- Authorization-gated: `MDLK` (`DotLock`), `MDDS` (`DotDisable`), `MDRT` (`DotRotate`), `MDBB` (`GetDotBackupBlob`)
- Native: `MDUC` (`DotUnlockChallenge`), `MDUL` (`DotUnlock`), `MDST` (`DotStatus`), `MDRC` (`DotRecovery`), `DOTW` (`DotOverrideChallenge`), `DOTX` (`DotOverride`)

The authorization-gated DOT commands are sent via the `AuthorizedCommand` wrapper and are rejected if delivered directly under `0x11`. The native DOT commands perform challenge-and-signature verification against the current ownership blob or the recovery-key hash, as appropriate for the command.

| FourCC | Command | Path | Description |
| ------ | ------- | ---- | ----------- |
| `MDLK` | `DotLock` | Authorized | Lock DOT with a nonzero CAK digest and LAK digest. |
| `MDDS` | `DotDisable` | Authorized | Enter ODD state with a zero CAK digest and a nonzero LAK digest. |
| `MDRT` | `DotRotate` | Authorized | Replace the CAK and LAK digests and advance the DOT epoch by two. |
| `MDBB` | `GetDotBackupBlob` | Authorized | Export a valid backup copy of the active DOT blob. |
| `MDUC` | `DotUnlockChallenge` | Native | Request the unlock challenge for a valid ODD DOT state. |
| `MDUL` | `DotUnlock` | Native | Complete ownership unlock using public keys matching the stored LAK digest and both challenge signatures. |
| `MDST` | `DotStatus` | Native/read-only | Return the current DOT status and fuse state. |
| `MDRC` | `DotRecovery` | Native | Restore DOT from a previously backed-up blob. |
| `DOTW` | `DotOverrideChallenge` | Native | Start DOT recovery using the recovery-key challenge flow. |
| `DOTX` | `DotOverride` | Native | Complete DOT recovery by verifying the hybrid recovery signature. |

See [DOT Commands](dot.md#runtime-commands) for the detailed state machine, validation rules, and command sequencing.

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

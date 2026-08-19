# External Mailbox (MCI Mailbox) Commands Spec

## Overview
This document outlines the external mailbox commands that enable SoC agents to interact with the MCU via [MCI mailbox](https://github.com/chipsalliance/caliptra-ss/blob/main/docs/CaliptraSSHardwareSpecification.md#mcu-mailbox).
These commands support common Caliptra management functions, including querying firmware information, retrieving debug and attestation logs, exporting attested CSRs, utilizing cryptographic services, secure debug unlock, and in-field fuse provisioning.

- **Device Identification and Capabilities**
    - Retrieve firmware versions and device capabilities to ensure compatibility and proper configuration.

- **Debugging and Diagnostics**
    - Retrieve debug logs to analyze device behavior, diagnose issues, and monitor runtime states.
    - Clear logs to reset diagnostic data and maintain storage efficiency.

- **Certificate Management**
    - Export attested Certificate Signing Requests (CSRs) for device keys to facilitate secure provisioning.

- **Cryptographic Services**
    - AES encryption and decryption
    - SHA hashing
    - Random number generation
    - Digital signing
    - Signature verification
    - Key exchange

- **Debug Unlock Mechanisms**
    - Facilitate secure debugging in production environments
    - Ensure controlled access to debugging features

- **In-Field Fuse Provisioning**
    - See [fuses spec](fuses.md) for details.

## Mailbox Commands List

| **Name**                      | **Command Code**     | **Description**                                                                       |
| ----------------------------- | -------------------- | ------------------------------------------------------------------------------------- |
| MC_FIRMWARE_VERSION           | 0x4D46_5756 ("MFWV") | Retrieves the version of the target firmware.                                         |
| MC_DEVICE_CAPABILITIES        | 0x4D43_4150 ("MCAP") | Retrieve the device capabilities.                                                     |
| MC_EXPORT_ATTESTED_CSR        | 0x4D45_4143 ("MEAC") | Discovers supported device keys or exports an attested CSR, wrapped in a CoseSign1 structure. |
| MC_GET_ATTESTATION            | 0x4D47_4154 ("MGAT") | Retrieves signed attestation evidence in a requester-selected format.                 |
| MC_GET_CERT_CHAIN             | 0x4D47_4343 ("MGCC") | Reserved for future certificate-chain retrieval; not implemented.                    |
| MC_SET_CERT_CHAIN             | 0x4D53_4343 ("MSCC") | Reserved for future certificate-chain updates; not implemented.                      |
| MC_GET_LOG                    | 0x4D47_4C47 ("MGLG") | Retrieves the debug log                                                               |
| MC_CLEAR_LOG                  | 0x4D43_4C47 ("MCLG") | Clears the debug log                                                                  |
| MC_FIPS_SELF_TEST_START       | 0x4D46_5354 ("MFST") | Starts the FIPS self-test to exercise the crypto engine.                              |
| MC_FIPS_SELF_TEST_GET_RESULTS | 0x4D46_4752 ("MFGR") | Retrieves the results of the FIPS self-test.                                          |
| MC_FIPS_PERIODIC_ENABLE       | 0x4D46_5045 ("MFPE") | Enables or disables periodic FIPS self-test.                                          |
| MC_FIPS_PERIODIC_STATUS       | 0x4D46_5053 ("MFPS") | Retrieves the status of periodic FIPS self-test.                                      |
| MC_SHA_INIT                   | 0x4D43_5349 ("MCSI") | Starts the computation of a SHA hash of data.                                         |
| MC_SHA_UPDATE                 | 0x4D43_5355 ("MCSU") | Continues a SHA computation started by `MC_SHA_INIT` or another `MC_SHA_UPDATE`.      |
| MC_SHA_FINAL                  | 0x4D43_5346 ("MCSF") | Finalizes the computation of a SHA and produces the hash of all the data.             |
| MC_HMAC                       | 0x4D43_484D ("MCHM") | Computes an HMAC according to RFC 2104.                                               |
| MC_HMAC_KDF_COUNTER           | 0x4D43_4B43 ("MCKC") | Computes HMAC KDF in Counter Mode as specified in NIST SP800-108.                     |
| MC_HKDF_EXTRACT               | 0x4D43_4B54 ("MCKT") | Implements HKDF-Extract as specified in RFC 5869.                                     |
| MC_HKDF_EXPAND                | 0x4D43_4B50 ("MCKP") | Implements HKDF-Expand as specified in RFC 5869.                                      |
| MC_AES_ENCRYPT_INIT           | 0x4D43_4349 ("MCCI") | Starts an AES encryption operation.                                                   |
| MC_AES_ENCRYPT_UPDATE         | 0x4D43_4355 ("MCCU") | Continues an AES encryption operation started by `MC_AES_ENCRYPT_INIT`.               |
| MC_AES_DECRYPT_INIT           | 0x4D43_414A ("MCAJ") | Starts an AES-256 decryption operation.                                               |
| MC_AES_DECRYPT_UPDATE         | 0x4D43_4155 ("MCAU") | Continues an AES decryption operation started by `MC_AES_DECRYPT_INIT`.               |
| MC_AES_GCM_ENCRYPT_INIT       | 0x4D43_4749 ("MCGI") | Starts an AES-256-GCM encryption operation.                                           |
| MC_AES_GCM_ENCRYPT_UPDATE     | 0x4D43_4755 ("MCGU") | Continues an AES-GCM encryption operation started by `MC_AES_GCM_ENCRYPT_INIT`.       |
| MC_AES_GCM_ENCRYPT_FINAL      | 0x4D43_4746 ("MCGF") | Finalizes the AES-GCM encryption operation and produces the final ciphertext and tag. |
| MC_AES_GCM_DECRYPT_INIT       | 0x4D43_4449 ("MCDI") | Starts an AES-256-GCM decryption operation.                                           |
| MC_AES_GCM_DECRYPT_UPDATE     | 0x4D43_4455 ("MCDU") | Continues an AES-GCM decryption operation started by `MC_AES_GCM_DECRYPT_INIT`.       |
| MC_AES_GCM_DECRYPT_FINAL      | 0x4D43_4446 ("MCDF") | Finalizes the AES-GCM decryption operation and verifies the tag.                      |
| MC_ECDH_GENERATE              | 0x4D43_4547 ("MCEG") | Computes the first half of an Elliptic Curve Diffie-Hellman exchange.                 |
| MC_ECDH_FINISH                | 0x4D43_4546 ("MCEF") | Computes the second half of an Elliptic Curve Diffie-Hellman exchange.                |
| MC_ECDSA_CMK_PUBLIC_KEY       | 0x4D43_4550 ("MCEP") | Generates an ECDSA public key from a CMK.                                             |
| MC_ECDSA_CMK_SIGN             | 0x4D43_4553 ("MCES") | Creates an ECDSA signature using a CMK.                                               |
| MC_ECDSA_CMK_VERIFY           | 0x4D43_4556 ("MCEV") | Validates an ECDSA signature using a CMK.                                             |
| MC_MLDSA_CMK_PUBLIC_KEY       | 0x4D4D_4C50 ("MMLP") | Generates an ML-DSA public key from a CMK.                                            |
| MC_MLDSA_CMK_SIGN             | 0x4D4D_4C53 ("MMLS") | Creates an ML-DSA signature using a CMK.                                              |
| MC_MLDSA_CMK_VERIFY           | 0x4D4D_4C56 ("MMLV") | Validates an ML-DSA signature using a CMK.                                            |
| MC_RANDOM_STIR                | 0x4D43_5253 ("MCRS") | Adds additional entropy to the internal deterministic random bit generator.           |
| MC_RANDOM_GENERATE            | 0x4D43_5247 ("MCRG") | Generates random bytes from the internal RNG.                                         |
| MC_IMPORT                     | 0x4D43_494D ("MCIM") | Imports a specified key and returns a CMK for it.                                     |
| MC_DELETE                     | 0x4D43_444C ("MCDL") | Deletes the object stored with the given mailbox ID.                                  |
| MC_CM_STATUS                  | 0x4D43_5354 ("MCST") | Reports cryptographic mailbox key-storage usage.                                      |
| MC_ECDSA384_SIG_VERIFY        | 0x4D45_4356 ("MECV") | Verifies an ECDSA P-384 signature.                                                    |
| MC_LMS_SIG_VERIFY             | 0x4D4C_4D56 ("MLMV") | Verifies an LMS signature.                                                            |
| MC_PROD_DEBUG_UNLOCK_REQ      | 0x4D50_5552 ("MPUR") | Requests debug unlock in a production environment.                                    |
| MC_PROD_DEBUG_UNLOCK_TOKEN    | 0x4D50_5554 ("MPUT") | Sends the debug unlock token.                                                         |
| MC_GET_AUTH_CMD_CHALLENGE     | 0x4D41_4343 ("MACC") | Requests a challenge for security-sensitive commands.                                 |
| MC_FUSE_INCREASE_CALIPTRA_MIN_SVN | 0x4D43_4D53 ("MCMS") | Increases the minimum bootable Caliptra firmware SVN.                             |
| MC_FUSE_READ                  | 0x4946_5052 ("IFPR") | See [fuses spec](fuses.md) for details                                                |
| MC_FUSE_WRITE                 | 0x4946_5057 ("IFPW") | See [fuses spec](fuses.md) for details                                                |
| MC_FUSE_LOCK_PARTITION        | 0x4946_504B ("IFPK") | See [fuses spec](fuses.md) for details                                                |
| MC_PROVISION_VENDOR_PK_HASH   | 0x5056_504b ("PVPK") | See [fuses spec](fuses.md) for details                                                |
| MC_PROVISION_OWNER_PK_HASH    | 0x504F_504B ("POPK") | See [fuses spec](fuses.md) for details                                                |
| MC_FE_PROG                    | 0x4D43_4650 ("MCFP") | See [fuses spec](fuses.md) for details                                                |
| MC_FUSE_REVOKE_VENDOR_PUB_KEY | 0x4D52_564B ("MRVK") | See [fuses spec](fuses.md) for details                                                |
| MC_FUSE_REVOKE_VENDOR_PK_HASH | 0x5256_4b48 ("RVKH") | See [fuses spec](fuses.md) for details                                                |
| MC_DEVICE_OWNERSHIP_TRANSFER  | 0x0000_0011          | Device Ownership Transfer family; subcommand is carried in mailbox SRAM                |

## Command Format

Common command payloads are defined in [Caliptra Common Commands](caliptra_common_commands.md#command-definitions). This section lists the MCI mailbox command code for each common command and keeps mailbox-only command definitions in this document. MCI mailbox checksum, `fips_status`, and variable-length `data_len` fields are transport-specific response framing and are not part of the common command payload tables.

### MC_DEVICE_OWNERSHIP_TRANSFER

All MCU Runtime DOT requests use MCI command register value `0x00000011`.
Mailbox SRAM begins with the normal checksum followed by a little-endian DOT
FourCC and its payload.

```text
Native:     checksum || DOT_FourCC || DOT_payload
Authorized: checksum || DOT_FourCC || DOT_payload || authorization_trailer
```

The authorized trailer is
`nonce[48] || ecc_pub_x[48] || ecc_pub_y[48] || mldsa_pub[2592] || HybridSignature`.
For authorized DOT commands the signed preimage is
`0x00000011(BE) || DOT_FourCC(LE) || DOT_payload || nonce`.

| FourCC | Command | Classification |
| ------ | ------- | -------------- |
| `MDLK` | Lock | Authorized |
| `MDDS` | Disable | Authorized |
| `MDRT` | Rotate | Authorized |
| `MDBB` | Get backup blob | Authorized |
| `MDUC` | Unlock challenge | Native |
| `MDUL` | Unlock | Native LAK signatures |
| `MDST` | Status | Native/read-only |
| `MDRC` | Restore backup blob | Native blob HMAC |
| `DOTW` | Override challenge | Native fused recovery key |
| `DOTX` | Override | Native recovery-key signatures |

Payload semantics match [Caliptra SPDM VDM DOT commands](caliptra_spdm_vdm_cmds.md#device-ownership-transfer-commands).

**For detailed command flows, state transitions, security properties, and use cases**, see [Device Ownership Transfer (DOT)](dot.md#runtime-commands)

### MC_FIRMWARE_VERSION

Retrieves the version of the target firmware.

Command Code: `0x4D46_5756` ("MFWV")

Payload semantics are defined by [Firmware Version](caliptra_common_commands.md#firmware-version).

MCI mailbox response payload:

| **Name**    | **Type**     | **Description**                            |
| ----------- | ------------ | ------------------------------------------ |
| chksum      | u32          | Response checksum.                         |
| fips_status | u32          | FIPS approved or an error.                 |
| data_len    | u32          | Length in bytes of the valid version data. |
| version     | u8[data_len] | Firmware Version Number in ASCII format.   |

### MC_DEVICE_CAPABILITIES

Retrieve the device capabilites.

Command Code: `0x4D43_4150` ("MCAP")

Payload semantics are defined by [Device Capabilities](caliptra_common_commands.md#device-capabilities).

### MC_EXPORT_ATTESTED_CSR

Discovers supported Caliptra identity keys or exports an attested Certificate
Signing Request (CSR) for a specified device key.

Command Code: `0x4D45_4143` ("MEAC")

Payload semantics are defined by [Export Attested CSR](caliptra_common_commands.md#export-attested-csr).

### MC_GET_ATTESTATION

Retrieves signed attestation evidence bound to a requester-supplied nonce.

Command Code: `0x4D47_4154` ("MGAT")

Payload semantics, the evidence format values, and the format-discovery query
are defined by [Get Attestation](caliptra_common_commands.md#get-attestation).

MCI mailbox response payload:

| **Name**        | **Type**       | **Description**                                                                       |
| --------------- | -------------- | ------------------------------------------------------------------------------------- |
| chksum          | u32            | Response checksum.                                                                    |
| fips_status     | u32            | FIPS approved or an error.                                                            |
| data_len        | u32            | Length in bytes of `evidence_format` plus `evidence`.                                 |
| evidence_format | u32            | Echo of the requested `evidence_format`.                                              |
| evidence        | u8[data_len-4] | Signed evidence blob, or a `u32` supported-format bitmap when responding to the query. |

### MC_GET_LOG

Retrieves the debug log for the MCU Runtime.

Command Code: `0x4D47_4C47` ("MGLG")

Payload semantics and debug log format are defined by [Get Debug Log](caliptra_common_commands.md#get-debug-log).

MCI mailbox request payload contains only the mailbox checksum header. The command always retrieves the MCU Runtime debug log.

MCI mailbox response payload:

| **Name**    | **Type**       | **Description**                                 |
| ----------- | -------------- | ----------------------------------------------- |
| chksum      | u32            | Response checksum.                              |
| fips_status | u32            | FIPS approved or an error.                      |
| data_len    | u32            | Length in bytes of `more_data` plus `log_data`. |
| more_data   | u32            | `1` if more log data remains, `0` otherwise.    |
| log_data    | u8[data_len-4] | Debug log contents.                             |

### MC_CLEAR_LOG

Clears the debug log in the MCU Runtime.

Command Code: `0x4D43_4C47` ("MCLG")

Payload semantics are defined by [Clear Debug Log](caliptra_common_commands.md#clear-debug-log).

### MC_FIPS_PERIODIC_ENABLE

Enables or disables periodic FIPS self-test. When enabled, the MCU runs FIPS self-tests in the background at a configurable interval (default: 60 seconds).

The periodic FIPS commands in this section are available only when MCU Runtime enables the
`periodic-fips-self-test` feature. Builds without that feature report both commands as unsupported.

Command Code: `0x4D46_5045` ("MFPE")

*Table: `MC_FIPS_PERIODIC_ENABLE` input arguments*
| **Name** | **Type** | **Description**                       |
| -------- | -------- | ------------------------------------- |
| chksum   | u32      | Checksum over input data              |
| enable   | u32      | 0 = disable, 1 = enable periodic test |

*Table: `MC_FIPS_PERIODIC_ENABLE` output arguments*
| **Name**    | **Type** | **Description**            |
| ----------- | -------- | -------------------------- |
| chksum      | u32      |                            |
| fips_status | u32      | FIPS approved or an error. |

### MC_FIPS_PERIODIC_STATUS

Retrieves the status of the periodic FIPS self-test, including whether it is enabled, the number of completed iterations, and the result of the last test.

Command Code: `0x4D46_5053` ("MFPS")

*Table: `MC_FIPS_PERIODIC_STATUS` input arguments*
| **Name** | **Type** | **Description**          |
| -------- | -------- | ------------------------ |
| chksum   | u32      | Checksum over input data |

*Table: `MC_FIPS_PERIODIC_STATUS` output arguments*
| **Name**    | **Type** | **Description**                                       |
| ----------- | -------- | ----------------------------------------------------- |
| chksum      | u32      |                                                       |
| fips_status | u32      | FIPS approved or an error.                            |
| enabled     | u32      | 0 = disabled, 1 = enabled                             |
| iterations  | u32      | Number of completed periodic test iterations          |
| last_result | u32      | Last test result: 0 = not run yet, 1 = pass, 2 = fail |

### MC_ECDSA384_SIG_VERIFY

Command Code: `0x4D45_4356` ("MECV")

Payload format and verification behavior are defined by Caliptra Core
[`ECDSA384_SIGNATURE_VERIFY`](https://github.com/chipsalliance/caliptra-sw/blob/main/runtime/README.md#ecdsa384_signature_verify).
MCU Runtime translates the MCI command code to the Caliptra Core command code and forwards the
request and response payloads unchanged apart from recalculating their transport checksums.

Successful verification returns `fips_status` `0x5553_5244` (`USRD`) because the digest is
caller-supplied. An invalid signature completes the MCI mailbox transaction with failure and no
response payload.

### MC_LMS_SIG_VERIFY

Command Code: `0x4D4C_4D56` ("MLMV")

Payload format, supported LMS parameters, and verification behavior are defined by Caliptra Core
[`LMS_SIGNATURE_VERIFY`](https://github.com/chipsalliance/caliptra-sw/blob/main/runtime/README.md#lms_signature_verify).

Successful verification returns `fips_status` `0x5553_5244` (`USRD`) because the digest is
caller-supplied.

### MC_PROD_DEBUG_UNLOCK_REQ

Requests debug unlock in production environment.

Command Code: `0x4D50_5552` ("MPUR")

Payload semantics are defined by [Request Debug Unlock](caliptra_common_commands.md#request-debug-unlock).

### MC_PROD_DEBUG_UNLOCK_TOKEN

Sends the debug unlock token.

Command Code: `0x4D50_5554` ("MPUT")

Payload semantics are defined by [Authorize Debug Unlock Token](caliptra_common_commands.md#authorize-debug-unlock-token).

### MC_GET_AUTH_CMD_CHALLENGE

Command Code: `0x4D41_4343` ("MACC")

Payload semantics are defined by [Get Auth Challenge](caliptra_common_commands.md#get-auth-challenge).
The MCI request appends `flags:u32` and `reserved:u32` after the mailbox checksum header; both
fields are reserved and must be zero. The MCI response inserts a zero `reserved:u32` between the
mailbox response header and the common 48-byte challenge payload.

### MC_FUSE_INCREASE_CALIPTRA_MIN_SVN

Increases the minimum bootable Caliptra firmware SVN.

Command Code: `0x4D43_4D53` ("MCMS")

Payload semantics are defined by [Fuse Increase Caliptra Min SVN](caliptra_common_commands.md#fuse-increase-caliptra-min-svn).

### MC_FE_PROG

Programs field entropy for the selected fuse partition.

Command Code: `0x4D43_4650` ("MCFP")

Payload semantics are defined by [Program Field Entropy](caliptra_common_commands.md#program-field-entropy).

{{#include fuse_api_cmd.md}}

### Cryptographic Command Format

The MCI mailbox cryptographic commands are mapped to their corresponding Caliptra Mailbox Cryptographic commands. The mapping is detailed in the table below. For the specific format of each command, refer to the [Mailbox Commands: Cryptographic Mailbox (2.0)](https://github.com/chipsalliance/caliptra-sw/blob/main/runtime/README.md#mailbox-commands-cryptographic-mailbox-20).

*Table: mapping MCI commands to Caliptra Core commands*
| **MCI Mailbox Command** | **Caliptra Core Mailbox Command** |
| ----------------------- | --------------------------------- |
| `MC_FIPS_SELF_TEST_START`       | `SELF_TEST_START`                    |
| `MC_FIPS_SELF_TEST_GET_RESULTS` | `SELF_TEST_GET_RESULTS`              |
| `MC_SHA_INIT`                   | `CM_SHA_INIT`                        |
| `MC_SHA_UPDATE`                 | `CM_SHA_UPDATE`                      |
| `MC_SHA_FINAL`                  | `CM_SHA_FINAL`                       |
| `MC_HMAC`                       | `CM_HMAC`                            |
| `MC_HMAC_KDF_COUNTER`           | `CM_HMAC_KDF_COUNTER`                |
| `MC_HKDF_EXTRACT`               | `CM_HKDF_EXTRACT`                    |
| `MC_HKDF_EXPAND`                | `CM_HKDF_EXPAND`                     |
| `MC_AES_ENCRYPT_INIT`           | `CM_AES_ENCRYPT_INIT`                |
| `MC_AES_ENCRYPT_UPDATE`         | `CM_AES_ENCRYPT_UPDATE`              |
| `MC_AES_DECRYPT_INIT`           | `CM_AES_DECRYPT_INIT`                |
| `MC_AES_DECRYPT_UPDATE`         | `CM_AES_DECRYPT_UPDATE`              |
| `MC_AES_GCM_ENCRYPT_INIT`       | `CM_AES_GCM_ENCRYPT_INIT`            |
| `MC_AES_GCM_ENCRYPT_UPDATE`     | `CM_AES_GCM_ENCRYPT_UPDATE`          |
| `MC_AES_GCM_ENCRYPT_FINAL`      | `CM_AES_GCM_ENCRYPT_FINAL`           |
| `MC_AES_GCM_DECRYPT_INIT`       | `CM_AES_GCM_DECRYPT_INIT`            |
| `MC_AES_GCM_DECRYPT_UPDATE`     | `CM_AES_GCM_DECRYPT_UPDATE`          |
| `MC_AES_GCM_DECRYPT_FINAL`      | `CM_AES_GCM_DECRYPT_FINAL`           |
| `MC_ECDH_GENERATE`              | `CM_ECDH_GENERATE`                   |
| `MC_ECDH_FINISH`                | `CM_ECDH_FINISH`                     |
| `MC_ECDSA_CMK_PUBLIC_KEY`       | `CM_ECDSA_PUBLIC_KEY`                |
| `MC_ECDSA_CMK_SIGN`             | `CM_ECDSA_SIGN`                      |
| `MC_ECDSA_CMK_VERIFY`           | `CM_ECDSA_VERIFY`                    |
| `MC_ECDSA384_SIG_VERIFY`        | `ECDSA384_SIGNATURE_VERIFY`          |
| `MC_LMS_SIG_VERIFY`             | `LMS_SIGNATURE_VERIFY`               |
| `MC_MLDSA_CMK_PUBLIC_KEY`       | `CM_MLDSA_PUBLIC_KEY`                |
| `MC_MLDSA_CMK_SIGN`             | `CM_MLDSA_SIGN`                      |
| `MC_MLDSA_CMK_VERIFY`           | `CM_MLDSA_VERIFY`                    |
| `MC_RANDOM_STIR`                | `CM_RANDOM_STIR`                     |
| `MC_RANDOM_GENERATE`            | `CM_RANDOM_GENERATE`                 |
| `MC_IMPORT`                     | `CM_IMPORT`                          |
| `MC_DELETE`                     | `CM_DELETE`                          |
| `MC_CM_STATUS`                  | `CM_STATUS`                          |

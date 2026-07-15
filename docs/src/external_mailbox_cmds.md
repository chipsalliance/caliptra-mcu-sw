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
| MC_EXPORT_ATTESTED_CSR        | 0x4D45_4143 ("MEAC") | Exports an attested CSR for a specified device key, wrapped in a CoseSign1 structure. |
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
| MC_RANDOM_STIR                | 0x4D43_5253 ("MCRS") | Adds additional entropy to the internal deterministic random bit generator.           |
| MC_RANDOM_GENERATE            | 0x4D43_5247 ("MCRG") | Generates random bytes from the internal RNG.                                         |
| MC_IMPORT                     | 0x4D43_494D ("MCIM") | Imports a specified key and returns a CMK for it.                                     |
| MC_DELETE                     | 0x4D43_444C ("MCDL") | Deletes the object stored with the given mailbox ID.                                  |
| MC_ECDSA384_SIG_VERIFY        | 0x4D45_4356 ("MECV") | Verifies an ECDSA P-384 signature.                                                    |
| MC_LMS_SIG_VERIFY             | 0x4D4C_4D56 ("MLMV") | Verifies an LMS signature.                                                            |
| MC_ECDSA384_SIGN              | 0x4D45_4353 ("MECS") | Requests to sign a SHA-384 digest with the DPE leaf certificate.                      |
| MC_MLDSA_SIGN                 | 0x4D4C_4D53 ("MLMS") | Requests to sign a SHA-384 digest with the DPE leaf certificate using MLDSA.          |
| MC_PROD_DEBUG_UNLOCK_REQ      | 0x4D50_5552 ("MPUR") | Requests debug unlock in a production environment.                                    |
| MC_PROD_DEBUG_UNLOCK_TOKEN    | 0x4D50_5554 ("MPUT") | Sends the debug unlock token.                                                         |
| MC_GET_AUTH_CMD_CHALLENGE     | 0x4D41_4343 ("MACC") | Requests a challenge for security-sensitive commands.                                 |
| MC_FUSE_READ                  | 0x4946_5052 ("IFPR") | See [fuses spec](fuses.md) for details                                                |
| MC_FUSE_WRITE                 | 0x4946_5057 ("IFPW") | See [fuses spec](fuses.md) for details                                                |
| MC_FUSE_LOCK_PARTITION        | 0x4946_504B ("IFPK") | See [fuses spec](fuses.md) for details                                                |
| MC_PROVISION_VENDOR_PK_HASH   | 0x5056_504b ("PVPK") | See [fuses spec](fuses.md) for details                                                |
| MC_FE_PROG                    | 0x4D43_4650 ("MCFP") | See [fuses spec](fuses.md) for details                                                |
| MC_FUSE_REVOKE_VENDOR_PUB_KEY | 0x4D52_564B ("MRVK") | See [fuses spec](fuses.md) for details                                                |
| MC_FUSE_REVOKE_VENDOR_PK_HASH | 0x5256_4b48 ("RVKH") | See [fuses spec](fuses.md) for details                                                |

## Command Format

Common command payloads are defined in [Caliptra Common Commands](caliptra_common_commands.md#command-definitions). This section lists the MCI mailbox command code for each common command and keeps mailbox-only command definitions in this document. MCI mailbox checksum and status fields are transport-specific framing and are not repeated in each common command section below.

### MC_FIRMWARE_VERSION

Retrieves the version of the target firmware.

Command Code: `0x4D46_5756` ("MFWV")

Payload semantics are defined by [Firmware Version](caliptra_common_commands.md#firmware-version).

### MC_DEVICE_CAPABILITIES

Retrieve the device capabilites.

Command Code: `0x4D43_4150` ("MCAP")

Payload semantics are defined by [Device Capabilities](caliptra_common_commands.md#device-capabilities).

### MC_EXPORT_ATTESTED_CSR

Exports an attested Certificate Signing Request (CSR) for a specified device key.

Command Code: `0x4D45_4143` ("MEAC")

Payload semantics are defined by [Export Attested CSR](caliptra_common_commands.md#export-attested-csr).

### MC_GET_LOG

Retrieves the debug log for the MCU Runtime.

Command Code: `0x4D47_4C47` ("MGLG")

Payload semantics and debug log format are defined by [Get Debug Log](caliptra_common_commands.md#get-debug-log).

### MC_CLEAR_LOG

Clears the debug log in the MCU Runtime.

Command Code: `0x4D43_4C47` ("MCLG")

Payload semantics are defined by [Clear Debug Log](caliptra_common_commands.md#clear-debug-log).

### MC_FIPS_PERIODIC_ENABLE

Enables or disables periodic FIPS self-test. When enabled, the MCU runs FIPS self-tests in the background at a configurable interval (default: 60 seconds).

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

Verifies an ECDSA P-384 signature. The hash to be verified is taken from the input.

Command Code: `0x4D45_4356` ("MECV")

*Table: `MC_ECDSA384_SIG_VERIFY` input arguments*
| **Name**    | **Type** | **Description**                                                             |
| ----------- | -------- | --------------------------------------------------------------------------- |
| chksum      | u32      | Checksum over other input arguments, computed by the caller. Little endian. |
| pub_key_x   | u8[48]   | X portion of the ECDSA verification key.                                    |
| pub_key_y   | u8[48]   | Y portion of the ECDSA verification key.                                    |
| signature_r | u8[48]   | R portion of the signature to verify.                                       |
| signature_s | u8[48]   | S portion of the signature to verify.                                       |
| hash        | u8[48]   | SHA-384 digest to verify.                                                   |

*Table: `MC_ECDSA384_SIG_VERIFY` output arguments*
| **Name**    | **Type** | **Description**                                                             |
| ----------- | -------- | --------------------------------------------------------------------------- |
| chksum      | u32      | Checksum over other output arguments, computed by responder. Little endian. |
| fips_status | u32      | Indicates if the command is FIPS approved or an error.                      |

### MC_LMS_SIG_VERIFY

Verifies an LMS signature. The hash to be verified is taken from the input.

Command Code: `0x4D4C_4D56` ("MLMV")

*Table: `MC_LMS_SIG_VERIFY` input arguments*
| **Name**            | **Type** | **Description**                                                                      |
| ------------------- | -------- | ------------------------------------------------------------------------------------ |
| chksum              | u32      | Checksum over other input arguments, computed by the caller. Little endian.          |
| pub_key_tree_type   | u8[4]    | LMS public key algorithm type. Must equal 12.                                        |
| pub_key_ots_type    | u8[4]    | LM-OTS algorithm type. Must equal 7.                                                 |
| pub_key_id          | u8[16]   | "I" Private key identifier                                                           |
| pub_key_digest      | u8[24]   | "T[1]" Public key hash value                                                         |
| signature_q         | u8[4]    | Leaf of the Merkle tree where the OTS public key appears                             |
| signature_ots       | u8[1252] | LM-OTS signature                                                                     |
| signature_tree_type | u8[4]    | LMS signature Algorithm type. Must equal 12.                                         |
| signature_tree_path | u8[360]  | Path through the tree from the leaf associated with the LM-OTS signature to the root |
| hash                | u8[48]   | SHA384 digest to verify.                                                             |

*Table: `MC_LMS_SIG_VERIFY` output arguments*
| **Name**    | **Type** | **Description**                                                       |
| ----------- | -------- | --------------------------------------------------------------------- |
| chksum      | u32      | Checksum over other output arguments, computed by MCU. Little endian. |
| fips_status | u32      | Indicates if the command is FIPS approved or an error.                |

### MC_ECDSA384_SIGN
Requests to sign SHA-384 digest with DPE leaf cert.

Command Code: `0x4D45_4353` ("MECS")

*Table: `MC_ECDSA384_SIGN` input arguments*
| **Name** | **Type** | **Description**                                                             |
| -------- | -------- | --------------------------------------------------------------------------- |
| chksum   | u32      | Checksum over other input arguments, computed by the caller. Little endian. |
| digest   | u8[48]   | SHA-384 digest to be signed.                                                |

*Table: `MC_ECDSA384_SIGN` output arguments*
| **Name**         | **Type** | **Description**                                                       |
| ---------------- | -------- | --------------------------------------------------------------------- |
| chksum           | u32      | Checksum over other output arguments, computed by MCU. Little endian. |
| fips_status      | u32      | Indicates if the command is FIPS approved or an error.                |
| derived_pubkey_x | u8[48]   | The X BigNum of the ECDSA public key associated with the signing key. |
| derived_pubkey_y | u8[48]   | The Y BigNum of the ECDSA public key associated with the signing key. |
| signature_r      | u8[48]   | The R BigNum of an ECDSA signature.                                   |
| signature_s      | u8[48]   | The S BigNum of an ECDSA signature.                                   |

### MC_MLDSA_SIGN

Request to sign the SHA-384 digest with DPE leaf cert.

Command Code: `0x4D4C_4D53` ("MMLS")

*Table: `MC_MLDSA_SIGN` input arguments*

| **Name** | **Type** | **Description**                                                             |
| -------- | -------- | --------------------------------------------------------------------------- |
| chksum   | u32      | Checksum over other input arguments, computed by the caller. Little endian. |
| digest   | u8[48]   | SHA-384 digest to be signed.                                                |

*Table: `MC_MLDSA_SIGN` output arguments*

| **Name**            | **Type** | **Description**                           |
| ------------------- | -------- | ----------------------------------------- |
| chksum              | u32      |                                           |
| fips_status         | u32      | FIPS approved or an error                 |
| pub_key_tree_type   | u8[4]    | LMS public key algorithm type.            |
| pub_key_ots_type    | u8[4]    | LM-OTS algorithm type.                    |
| pub_key_id          | u8[16]   | Private key identifier.                   |
| pub_key_digest      | u8[24]   | Public key hash value.                    |
| signature_q         | u8[4]    | Leaf of the Merkle tree for the OTS key.  |
| signature_ots       | u8[1252] | LM-OTS signature.                         |
| signature_tree_path | u8[360]  | Path through the Merkle tree to the root. |

### MC_PROD_DEBUG_UNLOCK_REQ

Requests debug unlock in production environment.

Command Code: `0x4D50_5552` ("MPUR")

Payload semantics are defined by [Request Debug Unlock](caliptra_common_commands.md#request-debug-unlock).

### MC_PROD_DEBUG_UNLOCK_TOKEN

Sends the debug unlock token.

Command Code: `0x4D50_5554` ("MPUT")

Payload semantics are defined by [Authorize Debug Unlock Token](caliptra_common_commands.md#authorize-debug-unlock-token).

{{#include fuse_api_cmd.md}}

### Cryptographic Command Format

The MCI mailbox cryptographic commands are mapped to their corresponding Caliptra Mailbox Cryptographic commands. The mapping is detailed in the table below. For the specific format of each command, refer to the [Mailbox Commands: Cryptographic Mailbox (2.0)](https://github.com/chipsalliance/caliptra-sw/blob/main/runtime/README.md#mailbox-commands-cryptographic-mailbox-20).

*Table: mapping MCI Mailbox Crypto Commands to Caliptra Crypto Mailbox Commands*
| **MCI Mailbox Crypto Commands** | **Caliptra Mailbox Crypto Commands** |
| ------------------------------- | ------------------------------------ |
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
| `MC_RANDOM_STIR`                | `CM_RANDOM_STIR`                     |
| `MC_RANDOM_GENERATE`            | `CM_RANDOM_GENERATE`                 |
| `MC_IMPORT`                     | `CM_IMPORT`                          |
| `MC_DELETE`                     | `CM_DELETE`                          |

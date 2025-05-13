# External Mailbox (MCI Mailbox) Commands Spec

## Overview
This document outlines the external mailbox commands that enable SoC agents to interact with the MCU via [MCI mailbox](https://github.com/chipsalliance/caliptra-ss/blob/main/docs/CaliptraSSHardwareSpecification.md#mcu-mailbox).
These commands support a wide range of functionalities, including querying device-specific information, retrieving debug and attestation logs, managing certificates, utilizing cryptographic services and secure debugging in production environment.

- **Device Identification and Capabilities**
    - Retrieve firmware versions, unique device identifiers, and device capabilities to ensure compatibility and proper configuration.
    - Query device-specific information such as chip identifiers or subsystem details.

- **Debugging and Diagnostics**
    - Retrieve debug logs to analyze device behavior, diagnose issues, and monitor runtime states.
    - Clear logs to reset diagnostic data and maintain storage efficiency.

- **Certificate Management**
    - Export Certificate Signing Requests (CSRs) for device keys to facilitate secure provisioning.
    - Import signed certificates to establish a trusted certificate chain for device authentication.

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

## Mailbox Commands List

| **Name**                          | **Command Code** | **Description**                                                                                     |
|-----------------------------------|------------------|-----------------------------------------------------------------------------------------------------|
| MC_FIRMWARE_VERSION               | 0x4D46_5756 ("MFWV") | Retrieves the version of the target firmware.                                                      |
| MC_DEVICE_CAPABILITIES            | 0x4D43_4150 ("MCAP") | Retrieve the device capabilities.                                                                  |
| MC_DEVICE_ID                      | 0x4D44_4944 ("MDID") | Retrieves the device ID.                                                                           |
| MC_DEVICE_INFO                    | 0x4D44_494E ("MDIN") | Retrieves information about the target device.                                                     |
| MC_EXPORT_IDEV_CSR                | 0x4D49_4352 ("MICR") | Exports the IDEVID Self-Signed Certificate Signing Request.                                        |
| MC_IMPORT_IDEV_CERT               | 0x4D49_4943 ("MIIC") | Allows SoC to import DER-encoded IDevId certificate on every boot.                                 |
| MC_GET_LOG                        | 0x4D47_4C47 ("MGLG") | Retrieves the internal log for the RoT.                                                            |
| MC_CLEAR_LOG                      | 0x4D43_4C47 ("MCLG") | Clears the log in the RoT subsystem.                                                               |
| MC_SHA_INIT                       | 0x4D43_5349 ("MCSI") | Starts the computation of a SHA hash of data.                                                      |
| MC_SHA_UPDATE                     | 0x4D43_5355 ("MCSU") | Continues a SHA computation started by `MC_SHA_INIT` or another `MC_SHA_UPDATE`.                   |
| MC_SHA_FINAL                      | 0x4D43_5346 ("MCSF") | Finalizes the computation of a SHA and produces the hash of all the data.                          |
| MC_AES_ENCRYPT_INIT               | 0x4D43_4349 ("MCCI") | Starts an AES encryption operation.                                                                |
| MC_AES_ENCRYPT_UPDATE             | 0x4D43_4355 ("MCMU") | Continues an AES encryption operation started by `MC_AES_ENCRYPT_INIT`.                            |
| MC_AES_DECRYPT_INIT               | 0x4D43_414A ("MCAJ") | Starts an AES-256 decryption operation.                                                            |
| MC_AES_DECRYPT_UPDATE             | 0x4D43_4155 ("MCAU") | Continues an AES decryption operation started by `MC_AES_DECRYPT_INIT`.                            |
| MC_AES_GCM_ENCRYPT_INIT           | 0x4D43_4749 ("MCGI") | Starts an AES-256-GCM encryption operation.                                                        |
| MC_AES_GCM_ENCRYPT_UPDATE         | 0x4D43_4755 ("MCGU") | Continues an AES-GCM encryption operation started by `MC_AES_GCM_ENCRYPT_INIT`.                    |
| MC_AES_GCM_ENCRYPT_FINAL          | 0x4D43_4746 ("MCGF") | Finalizes the AES-GCM encryption operation and produces the final ciphertext and tag.              |
| MC_AES_GCM_DECRYPT_INIT           | 0x4D43_4449 ("MCDI") | Starts an AES-256-GCM decryption operation.                                                        |
| MC_AES_GCM_DECRYPT_UPDATE         | 0x4D43_4455 ("MCDU") | Continues an AES-GCM decryption operation started by `MC_AES_GCM_DECRYPT_INIT`.                    |
| MC_AES_GCM_DECRYPT_FINAL          | 0x4D43_4446 ("MCDF") | Finalizes the AES-GCM decryption operation and verifies the tag.                                   |
| MC_ECDH_GENERATE                  | 0x4D43_4547 ("MCEG") | Computes the first half of an Elliptic Curve Diffie-Hellman exchange.                              |
| MC_ECDH_FINISH                    | 0x4D43_4546 ("MCEF") | Computes the second half of an Elliptic Curve Diffie-Hellman exchange.                             |
| MC_RANDOM_STIR                    | 0x4D43_5253 ("MCRS") | Adds additional entropy to the internal deterministic random bit generator.                        |
| MC_RANDOM_GENERATE                | 0x4D43_5247 ("MCRG") | Generates random bytes from the internal RNG.                                                      |
| MC_IMPORT                         | 0x4D43_494D ("MCIM") | Imports a specified key and returns a CMK for it.                                                  |
| MC_DELETE                         | 0x4D43_444C ("MCDL") | Deletes the object stored with the given mailbox ID.                                               |
| MC_ECDSA384_SIG_VERIFY            | 0x4D45_4356 ("MECV") | Verifies an ECDSA P-384 signature.                                                                 |
| MC_LMS_SIG_VERIFY                 | 0x4D4C_4D56 ("MLMV") | Verifies an LMS signature.                                                                         |
| MC_ECDSA_SIGN                     | 0x4D45_4353 ("MECS") | Requests to sign a SHA-384 digest with the DPE leaf certificate.                                   |
| MC_MLDSA_SIGN                     | 0x4D4C_4D53 ("MMLS") | Requests to sign a SHA-384 digest with the DPE leaf certificate using MLDSA.                       |
| MC_PRODUCTION_DEBUG_UNLOCK_REQ    | 0x4D44_5552 ("MDUR") | Requests debug unlock in a production environment.                                                 |
| MC_PRODUCTION_DEBUG_UNLOCK_TOKEN  | 0x4D44_5554 ("MDUT") | Sends the debug unlock token.                                                                      |

## Command Format

### MC_FIRMWARE_VERSION

Retrieves the version of the target firmware.

Command Code: `0x4D46_5756` ("MFWV")

*Table: `MC_FIRMWARE_VERSION` input arguments*
| **Name**   | **Type**       | **Description**                         |
| ---------- | -------------- | --------------------------------------- |
| chksum     |  u32           |                                         |
| index      |  u8            | - `00h` = Caliptra core firmware       |
|            |                | - `01h` = MCU runtime firmware         |
|            |                | - `02h` = SoC firmware                 |
|            |                |Additional indexes are firmware-specific |

*Table: `MC_FIRMWARE_VERSION` output arguments*
| **Name**   | **Type**       | **Description**                         |
| ---------- | -------------- | --------------------------------------- |
| chksum     |  u32           |                                         |
| fips_status|  u32           | FIPS approved or an error               |
| version    |  u8[32]        | Firmware Version Number in ASCII format |

### MC_DEVICE_CAPABILITIES

Retrieve the device capabilites.

Command Code: `0x4D43_4150` ("MCAP")

*Table: `MC_DEVICE_CAPABILITIES` input arguments*
| **Name**   | **Type**       | **Description**                         |
| ---------- | -------------- | --------------------------------------- |
| chksum     |  u32           |                                         |

*Table: `MC_DEVICE_CAPABILITIES` output arguments*
| **Name**   | **Type**       | **Description**                         |
| ---------- | -------------- | --------------------------------------- |
| chksum     | u32            |                                         |
| fips_status | u32            | FIPS approved or an error    |
| caps       | u8[32]         | - Bytes [0:7]: Reserved for Caliptra RT |
|            |                | - Bytes [8:11]: Reserved for Caliptra FMC |
|            |                | - Bytes [12:15]: Reserved for Caliptra ROM |
|            |                | - Bytes [16:23]: Reserved for MCU RT    |
|            |                | - Bytes [24:27]: Reserved for MCU ROM   |
|            |                | - Bytes [28:31]: Reserved               |

### MC_DEVICE_ID

Retrieves the device ID.

Command Code: `0x4D44_4944` ("MDID")

*Table: `MC_DEVICE_ID` input arguments*
| **Name**   | **Type**       | **Description**                         |
| ---------- | -------------- | --------------------------------------- |
| chksum     |  u32           |                                         |

*Table: `MC_DEVICE_ID` output arguments*
| **Name**               | **Type** | **Description**               |
|------------------------| -------- | ----------------------------- |
| chksum                 |  u32     |                               |
| fips_status            | u32      | FIPS approved or an error     |
| vendor_id              | u16      | Vendor ID; LSB                |
| device_id              | u16      | Device ID; LSB                |
| subsystem_vendor_id    | u16      | Subsystem Vendor ID; LSB      |
| subsystem_id           | u16      | Subsystem ID; LSB             |

### MC_DEVICE_INFO

Retrieves information about the target device.

Command Code: `0x4D44_494E` ("MDIN")

*Table: `MC_DEVICE_INFO` input arguments*
| **Name**   | **Type** | **Description**                         |
| ---------- | -------- | --------------------------------------- |
| chksum     | u32      |                                         |
| index      | u8       | Information Index:                     |
|            |          | - `00h` = Unique Chip Identifier       |
|            |          | Additional indexes are firmware-specific |

*Table: `MC_DEVICE_INFO` output arguments*
| **Name**    | **Type**       | **Description**                         |
| ----------- | -------------- | --------------------------------------- |
| chksum      | u32            |                                         |
| fips_status | u32            | FIPS approved or an error              |
| data_size   | u32            | Size of the requested data in bytes     |
| data        | u8[data_size]  | Requested information in binary format  |

### MC_EXPORT_IDEV_CSR

Exports the IDEVID Self-Signed Certificate Signing Request.

Command Code: `0x4D49_4352` ("MICR")

*Table: `MC_EXPORT_IDEV_CSR` input arguments*
| **Name**   | **Type** | **Description**                         |
| ---------- | -------- | --------------------------------------- |
| chksum     | u32      |                                         |
| index      | u8       | Information Index:                     |
|            |          | - `00h` = IDEVID ECC CSR               |
|            |          | - `01h` = IDEVID MLDSA CSR             |

*Table: `MC_EXPORT_IDEV_CSR` output arguments*
| **Name**    | **Type**       | **Description**                                           |
| ----------- | -------------- | --------------------------------------------------------- |
| chksum      | u32            |                                                           |
| fips_status | u32            | FIPS approved or an error                                 |
| data_size   | u32            | Length in bytes of the valid data in the data field.      |
| data        | u8[data_size]  | DER-encoded IDevID certificate signing request.           |

### MC_IMPORT_IDEV_CERT

Allows SoC to import DER-encoded IDevId certificate on every boot. The IDevId certificate is added to the start of the certificate chain.

Command Code: `0x4D49_4943` ("MIIC")

*Table: `MC_IMPORT_IDEV_CERT` input arguments*
| **Name**    | **Type**       | **Description**                              |
|-------------|----------------|----------------------------------------------|
| chksum      | u32            |                                              |
| cert_size   | u32            | Size of the DER-encoded IDevID certificate.  |
| cert        | u8[1024]       | DER-encoded IDevID certificate.              |

*Table: `MC_IMPORT_IDEV_CERT` output arguments*
| **Name**    | **Type**       | **Description**              |
|-------------|----------------|------------------------------|
| chksum      | u32            |                              |
| fips_status | u32            | FIPS approved or an error.   |

### MC_GET_LOG

Retrieves the internal log for the RoT. There are two types of logs available: the Debug Log, which contains RoT application information and machine state, and the Attestation Measurement Log, which is similar to the TCG log.

Command Code: `0x4D47_4C47` ("MGLG")

*Table: `MC_GET_LOG` input arguments*
| **Name**   | **Type** | **Description**          |
|------------|----------|--------------------------|
| chksum     | u32      | Checksum over input data |
| log type   | u8       | Type of log to retrieve: |
|            |          | - `0` = Debug Log        |
|            |          | - `1` = Attestation Log  |

*Table: `MC_GET_LOG` output arguments*
| **Name**    | **Type**       | **Description**              |
|-------------|----------------|------------------------------|
| chksum      | u32            |                              |
| fips_status | u32            | FIPS approved or an error.   |
| data_size   | u32            | Size of the log data in bytes |
| data        | u8[data_size]  | Log contents                 |

**Debug Log Format**:

The debug log reported by the device has no specified format, as this can vary between different devices and is not necessary for attestation. It is expected that diagnostic utilities for the device will be able to understand the exposed log information. A recommended entry format is provided here:

| Offset | Description                                       |
|--------|---------------------------------------------------|
| 1:7    | Log Entry Header                                 |
| 8:9    | Format of the entry (e.g., `1` for current format) |
| 10     | Severity of the entry                            |
| 11     | Identifier for the component that generated the message |
| 12     | Identifier for the entry message                 |
| 13:16  | Message-specific argument                        |
| 17:20  | Message-specific argument                        |

### MC_CLEAR_LOG

Clears the log in the RoT subsystem.

Command Code: `0x4D43_4C47` ("MCLG")

*Table: `MC_CLEAR_LOG` input arguments*
| **Name**   | **Type** | **Description**          |
|------------|----------|--------------------------|
| chksum     | u32      | Checksum over input data |
| log type   | u8       | Type of log to retrieve: |
|            |          | - `0` = Debug Log        |
|            |          | - `1` = Attestation Log  |

*Table: `MC_CLEAR_LOG` output arguments*
| **Name**    | **Type**       | **Description**            |
|-------------|----------------|----------------------------|
| chksum      | u32            |                            |
| fips_status | u32            | FIPS approved or an error. |

### MC_SHA_INIT

This starts the computation of a SHA hash of data, which may be larger than a single mailbox command allows. It also supports additional algorithms.

The sequence to use these are:
* 1 `MC_SHA_INIT` command
* 0 or more `MC_SHA_UPDATE` commands
* 1 `MC_SHA_FINAL` command

For each command, the context from the previous command's output must be passed as an input.
The maximum supported data size for the SHA commands is 4096 bytes.

Command Code: `0x4D43_5349` ("MCSI")

*Table: `MC_SHA_INIT` input arguments*
| **Name**       | **Type**      | **Description**    |
| -------------- | ------------- | ------------------ |
| chksum         | u32           |                    |
| hash algorithm | u32           | Enum.              |
|                |               | Value 0 = reserved |
|                |               | Value 1 = SHA2-384 |
|                |               | Value 2 = SHA2-512 |
| data size      | u32           |                    |
| data           | u8[data size] | Data to hash       |

*Table: `MC_SHA_INIT` output arguments*
| **Name**     | **Type**             | **Description**                            |
| ------------ | -------------------- | ------------------------------------------ |
| chksum       | u32                  |                                            |
| fips_status  | u32                  | FIPS approved or an error                  |
| context      | u8[SHA_CONTEXT_SIZE] | Passed to `MC_SHA_UPDATE` / `MC_SHA_FINAL` |

### MC_SHA_UPDATE

This continues a SHA computation started by `MC_SHA_INIT` or from another `MC_SHA_UPDATE`.

The context MUST be passed in from `MC_SHA_INIT` or `MC_SHA_UPDATE`.

Command Code: `0x4D43_5355` ("MCSU")

*Table: `MC_SHA_UPDATE` input arguments*
| **Name**     | **Type**             | **Description**                      |
| ------------ | -------------------- | ------------------------------------ |
| chksum       | u32                  |                                      |
| context      | u8[SHA_CONTEXT_SIZE] | From `MC_SHA_INIT` / `MC_SHA_UPDATE` |
| data size    | u32                  |                                      |
| data         | u8[data size]        | Data to hash                         |

*Table: `MC_SHA_UPDATE` output arguments*
| **Name**     | **Type**             | **Description**                            |
| ------------ | -------------------- | ------------------------------------------ |
| chksum       | u32                  |                                            |
| fips_status  | u32                  | FIPS approved or an error                  |
| context      | u8[SHA_CONTEXT_SIZE] | Passed to `MC_SHA_UPDATE` / `MC_SHA_FINAL` |

### MC_SHA_FINAL

This finalizes the computation of a SHA and produces the hash of all of the data.

The context MUST be passed in from `MC_SHA_INIT` or `MC_SHA_UPDATE`.

Command Code: `0x4D43_5346` ("MCSF")

*Table: `MC_SHA_FINAL` input arguments*
| **Name**     | **Type**             | **Description**                      |
| ------------ | -------------------- | ------------------------------------ |
| chksum       | u32                  |                                      |
| context      | u8[SHA_CONTEXT_SIZE] | From `MC_SHA_INIT` / `MC_SHA_UPDATE` |
| data size    | u32                  | May be 0                             |
| data         | u8[data size]        | Data to hash                         |

*Table: `MC_SHA_FINAL` output arguments*
| **Name**    | **Type**      | **Description**           |
| ----------- | ------------- | ------------------------- |
| chksum      | u32           |                           |
| fips_status | u32           | FIPS approved or an error |
| hash size   | u32           |                           |
| hash        | u8[hash size] |                           |

### MC_AES_ENCRYPT_INIT

Generic AES operation for unauthenticated AES operations. AES GCM operations use separate commands elsewhere.

Currently only supports AES-256-CBC with a random 128-bit IV. For block modes, such as CBC, the size must be a multiple of 16 bytes.
The CMK must have been created for AES usage.

Command Code: `0x4D43_4349` ("MCCI")

*Table: `MC_AES_ENCRYPT_INIT` input arguments*
| **Name**       | **Type**           | **Description**                       |
| -------------- | ------------------ | ------------------------------------- |
| chksum         | u32                |                                       |
| CMK            | CMK                | CMK of the key to use to encrypt      |
| mode/flags     | u32                | Requested mode and flags.             |
|                |                    | 0 = Reserved                          |
|                |                    | 1 = CBC                               |
| plaintext size | u32                | MUST be non-zero                      |
| plaintext      | u8[plaintext size] | Data to encrypt                       |

*Table: `MC_AES_ENCRYPT_INIT` output arguments*
| **Name**        | **Type**            | **Description**                  |
| --------------- | ------------------- | -------------------------------- |
| chksum          | u32                 |                                  |
| fips_status     | u32                 | FIPS approved or an error        |
| context         | AES_CONTEXT         |                                  |
| iv              | u8[16]              |                                  |
| ciphertext size | u32                 |                                  |
| ciphertext      | u8[ciphertext size] | Output encrypted data            |

### MC_AES_ENCRYPT_UPDATE

This continues (or finishes) an AES computation started by `MC_AES_ENCRYPT_INIT` or from another `MC_AES_ENCRYPT_UPDATE`.
There is no `MC_AES_ENCRYPT_FINISH` since unauthenticated AES modes do not output a final tag.
The context MUST be passed in from `MC_AES_ENCRYPT_INIT` or `MC_AES_ENCRYPT_UPDATE`.
For block modes, such as CBC, the size must be a multiple of 16 bytes.

Command Code: `0x4D43_4355` ("MCMU")

*Table: `MC_AES_ENCRYPT_UPDATE` input arguments*
| **Name**       | **Type**           | **Description**  |
| -------------- | ------------------ | ---------------- |
| chksum         | u32                |                  |
| context        | AES_CONTEXT        |                  |
| plaintext size | u32                | MUST be non-zero |
| plaintext      | u8[plaintext size] | Data to encrypt  |

*Table: `MC_AES_ENCRYPT_UPDATE` output arguments*
| **Name**       | **Type**            | **Description**           |
| -------------- | ------------------- | ------------------------- |
| chksum         | u32                 |                           |
| fips_status    | u32                 | FIPS approved or an error |
| context        | AES_CONTEXT         |                           |
| cipertext size | u32                 |                           |
| ciphertext     | u8[ciphertext size] |                           |

### MC_AES_DECRYPT_INIT

Starts an AES-256 unauthenaticed decryption computation.

The CMK must have been created for AES usage.

For block modes, such as CBC, the size must be a multiple of 16 bytes.

The IV must match what was passed and returned from the initial encryption operation.

Command Code: `0x4D43_414A` ("MCAJ")

*Table: `MC_AES_DECRYPT_INIT` input arguments*
| **Name**        | **Type**            | **Description**           |
| --------------- | ------------------- | ------------------------- |
| chksum          | u32                 |                           |
| CMK             | CMK                 | CMK to use for decryption |
| mode/flags      | u32                 | Requested mode and flags. |
|                 |                     | 0 = Reserved              |
|                 |                     | 1 = CBC                   |
| iv              | u8[16]              |                           |
| ciphertext size | u32                 | MUST be non-zero          |
| ciphertext      | u8[ciphertext size] | Data to decrypt           |

*Table: `MC_AES_DECRYPT_INIT` output arguments*
| **Name**       | **Type**           | **Description**           |
| -------------- | ------------------ | ------------------------- |
| chksum         | u32                |                           |
| fips_status    | u32                | FIPS approved or an error |
| context        | AES_CONTEXT        |                           |
| plaintext size | u32                |                           |
| plaintext      | u8[plaintext size] | Decrypted data            |

### MC_AES_DECRYPT_UPDATE

This continues an AES computation started by `MC_AES_DECRYPT_INIT` or from another `MC_AES_DECRYPT_UPDATE`.

There is no `MC_AES_DECRYPT_FINISH` since unauthenticated modes do not output a final tag.

The context MUST be passed in from `MC_AES_DECRYPT_INIT` or `MC_AES_DECRYPT_UPDATE`.

For block modes, such as CBC, the size must be a multiple of 16 bytes.

Command Code: `0x4D43_4155` ("MCAU")

*Table: `MC_AES_DECRYPT_UPDATE` input arguments*
| **Name**        | **Type**            | **Description**  |
| --------------- | ------------------- | ---------------- |
| chksum          | u32                 |                  |
| context         | AES_CONTEXT         |                  |
| ciphertext size | u32                 | MUST be non-zero |
| ciphertext      | u8[ciphertext size] | Data to decrypt  |

*Table: `MC_AES_DECRYPT_UPDATE` output arguments*
| **Name**       | **Type**           | **Description**           |
| -------------- | ------------------ | ------------------------- |
| chksum         | u32                |                           |
| fips_status    | u32                | FIPS approved or an error |
| context        | AES_CONTEXT        |                           |
| plaintext size | u32                |                           |
| plaintext      | u8[plaintext size] | Decrypted data            |

### MC_AES_GCM_ENCRYPT_INIT

Currently only supports AES-256-GCM with a random 96-bit IV.

The CMK must have been created for AES usage.

Additional authenticated data (AAD) can only be passed during the `INIT` command, so is limited to the maximum cryptographic mailbox data size (4096 bytes).

Command Code: `0x4D43_4749` ("MCGI")

*Table: `MC_AES_GCM_ENCRYPT_INIT` input arguments*
| **Name**       | **Type**           | **Description**                  |
| -------------- | ------------------ | -------------------------------- |
| chksum         | u32                |                                  |
| CMK            | CMK                | CMK of the key to use to encrypt |
| aad size       | u32                |                                  |
| aad            | u8[aad size]       | Additional authenticated data    |

*Table: `MC_AES_GCM_ENCRYPT_INIT` output arguments*
| **Name**       | **Type**            | **Description**                  |
| -------------- | ------------------- | -------------------------------- |
| chksum         | u32                 |                                  |
| fips_status    | u32                 | FIPS approved or an error        |
| context        | AES_GCM_CONTEXT     |                                  |
| iv             | u8[12]              |                                  |

### MC_AES_GCM_ENCRYPT_UPDATE

This continues an AES computation started by `MC_AES_GCM_ENCRYPT_INIT` or from another `MC_AES_GCM_ENCRYPT_UPDATE`.

The context MUST be passed in from `MC_AES_GCM_ENCRYPT_INIT` or `MC_AES_GCM_ENCRYPT_UPDATE`.

Command Code: `0x4D43_4755` ("MCGU")

*Table: `MC_AES_GCM_ENCRYPT_UPDATE` input arguments*
| **Name**       | **Type**           | **Description**  |
| -------------- | ------------------ | ---------------- |
| chksum         | u32                |                  |
| context        | AES_GCM_CONTEXT    |                  |
| plaintext size | u32                | MUST be non-zero |
| plaintext      | u8[plaintext size] | Data to encrypt  |

*Table: `MC_AES_GCM_ENCRYPT_UPDATE` output arguments*
| **Name**       | **Type**            | **Description**                 |
| -------------- | ------------------- | ------------------------------- |
| chksum         | u32                 |                                 |
| fips_status    | u32                 | FIPS approved or an error       |
| context        | AES_GCM_CONTEXT     |                                 |
| cipertext size | u32                 | could be greater than plaintext by 16 bytes |
| ciphertext     | u8[ciphertext size] |                                 |

### MC_AES_GCM_ENCRYPT_FINAL

This finalizes the computation of the AES GCM encryption and produces the final ciphertext and tag.

The context MUST be passed in from `MC_AES_GCM_ENCRYPT_INIT` or `MC_AES_GCM_ENCRYPT_UPDATE`.

Command Code: `0x4D43_4746` ("MCGF")

*Table: `MC_AES_GCM_ENCRYPT_FINAL` input arguments*
| **Name**       | **Type**           | **Description** |
| -------------- | ------------------ | --------------- |
| chksum         | u32                |                 |
| context        | AES_GCM_CONTEXT    |                  |
| plaintext size | u32                | MAY be 0        |
| plaintext      | u8[plaintext size] | Data to encrypt |

*Table: `MC_AES_GCM_ENCRYPT_FINAL` output arguments*
| **Name**       | **Type**            | **Description**                  |
| -------------- | ------------------- | -------------------------------- |
| chksum         | u32                 |                                  |
| fips_status    | u32                 | FIPS approved or an error        |
| tag            | u8[16]              |                                  |
| cipertext size | u32                 | could be greater than plaintext by 16 bytes |
| ciphertext     | u8[ciphertext size] |                                  |

The tag returned will always be 16 bytes. Shorter tags can be constructed by truncating.

### MC_AES_GCM_DECRYPT_INIT

Starts an AES-256-GCM decryption computation.

Currently only supports AES-256-GCM with a 96-bit IV.

The CMK must have been created for AES usage.

Additional authenticated data (AAD) can only be passed during the `INIT` command, so is limited to the maximum cryptographic mailbox data size (4096 bytes).

The AAD and IV must match what was passed and returned from the encryption operation.

Command Code: `0x4D43_4449` ("MCDI")

*Table: `MC_AES_GCM_DECRYPT_INIT` input arguments*
| **Name**        | **Type**            | **Description**               |
| --------------- | ------------------- | ----------------------------- |
| chksum          | u32                 |                               |
| CMK             | CMK                 | CMK to use for decryption     |
| iv              | u8[12]              |                               |
| aad size        | u32                 |                               |
| aad             | u8[aad size]        | Additional authenticated data |

*Table: `MC_AES_GCM_DECRYPT_INIT` output arguments*
| **Name**       | **Type**           | **Description**           |
| -------------- | ------------------ | ------------------------- |
| chksum         | u32                |                           |
| fips_status    | u32                | FIPS approved or an error |
| context        | AES_GCM_CONTEXT    |                           |

The encrypted and authenticated context's internal structure will be the same as for encryption.

### MC_AES_GCM_DECRYPT_UPDATE

This continues an AES computation started by `MC_AES_GCM_DECRYPT_INIT` or from another `MC_AES_GCM_DECRYPT_UPDATE`.

The context MUST be passed in from `MC_AES_GCM_DECRYPT_INIT` or `MC_AES_GCM_DECRYPT_UPDATE`.

Command Code: `0x4D43_4455` ("MCDU")

*Table: `MC_AES_GCM_DECRYPT_UPDATE` input arguments*
| **Name**        | **Type**            | **Description**  |
| --------------- | ------------------- | ---------------- |
| chksum          | u32                 |                  |
| context         | AES_GCM_CONTEXT     |                  |
| ciphertext size | u32                 | MUST be non-zero |
| ciphertext      | u8[ciphertext size] | Data to decrypt  |

*Table: `MC_AES_GCM_DECRYPT_UPDATE` output arguments*
| **Name**       | **Type**           | **Description**           |
| -------------- | ------------------ | ------------------------- |
| chksum         | u32                |                           |
| fips_status    | u32                | FIPS approved or an error |
| context        | AES_GCM_CONTEXT    |                           |
| plaintext size | u32                | MAY be 0                  |
| plaintext      | u8[plaintext size] |                           |

### MC_AES_GCM_DECRYPT_FINAL

This finalizes the computation of the AES GCM decryption and produces the final ciphertext.

The context MUST be passed in from `MC_AES_GCM_DECRYPT_INIT` or `MC_AES_GCM_DECRYPT_UPDATE`.

Tags between 0 and 16 bytes are supported but must be passed (on the right) with zeroes to 16 bytes.

The caller MUST verify that the tag verified field is set to 1 before using the result.

Command Code: `0x4D43_4446` ("MCDF")

*Table: `MC_AES_GCM_DECRYPT_FINAL` input arguments*
| **Name**        | **Type**            | **Description**                   |
| --------------- | ------------------- | --------------------------------- |
| chksum          | u32                 |                                   |
| context         | AES_GCM_CONTEXT     |                                   |
| tag size        | u32                 | Can be 0, 1, ..., 16              |
| tag             | u8[16]              | Right-padded with zeroes          |
| ciphertext size | u32                 | MAY be 0                          |
| ciphertext      | u8[ciphertext size] | Data to decrypt                   |

*Table: `MC_AES_GCM_DECRYPT_FINAL` output arguments*
| **Name**       | **Type**           | **Description**                      |
| -------------- | ------------------ | ------------------------------------ |
| chksum         | u32                |                                      |
| fips_status    | u32                | FIPS approved or an error            |
| tag verified   | u32                | 1 if tags matched, 0 if they did not |
| tag            | u8[16]             | Computed tag                         |
| plaintext size | u32                | MAY be 0                             |
| plaintext      | u8[plaintext size] |                                      |

### MC_ECDH_GENERATE

This computes the first half of an Elliptic Curve Diffie-Hellman exchange to compute an ephemeral shared key pair with another party.

Currently only supports the NIST P-384 curve.

The returned context must be passed to the `MC_ECDH_FINISH` command. The context contains the (encrypted) secret coefficient.

The returned exchange data format is the concatenation of the x- and y-coordinates of the public point encoded as big-endian integers, padded to 48 bytes each.

Command Code: `0x4D43_4547` ("MCEG")

*Table: `MC_ECDH_GENERATE` input arguments*
| **Name**    | **Type** | **Description**      |
| ----------- | -------- | -------------------- |
| chksum      | u32      |                      |

*Table: `MC_ECDH_GENERATE` output arguments*
| **Name**      | **Type** | **Description**                       |
| ------------- | -------- | ------------------------------------- |
| chksum        | u32      |                                       |
| fips_status   | u32      | FIPS approved or an error             |
| context       | u8[76]   | Used as the input to `MC_ECDH_FINISH` |
| exchange data | u8[96]   | i.e., the public point                |

### MC_ECDH_FINISH

This computes the second half of an Elliptic Curve Diffie-Hellman exchange.

Currently only supports the NIST P-384 curve.

The context must be passed from the `MC_ECDH_GENERATE` command.

The incoming exchange data MUST be the concatenation of the x- and y- coordinates of the other side's public point, encoded as big-endian integers, padded to 48 bytes each.

The produced shared secret is 384 bits.

Command Code: `0x4D43_4546` ("MCEF")

*Table: `MC_ECDH_FINISH` input arguments*
| **Name**               | **Type** | **Description**                                          |
| ---------------------- | -------- | -------------------------------------------------------- |
| chksum                 |          |                                                          |
| context                | u8[76]   | This MUST come from the output of the `MC_ECDH_GENERATE` |
| key usage              | u32      | usage tag of the kind of key that will be output         |
| incoming exchange data | u8[96]   | the other side's public point                            |

The context used as an input is the same as the output context from `MC_ECDH_GENERATE` above.

*Table: `MC_ECDH_FINISH` output arguments*
| **Name**    | **Type** | **Description**                 |
| ----------- | -------- | ------------------------------- |
| chksum      | u32      |                                 |
| fips_status | u32      | FIPS approved or an error       |
| output CMK  | CMK      | Output CMK of the shared secret |

### MC_RANDOM_STIR

This allows additional entropy to be added to the underlying deterministic random bit generator, if the hardware is using a CSRNG DRBG.

Command Code: `0x4D43_5253` ("MCRS")

*Table: `MC_RANDOM_STIR` input arguments*

| **Name**   | **Type**       | **Description** |
| ---------- | -------------- | --------------- |
| chksum     | u32            |                 |
| input size | u32            |                 |
| input      | u8[input size] |                 |

*Table: `MC_RANDOM_STIR` output arguments*
| **Name**    | **Type** | **Description**           |
| ----------- | -------- | ------------------------- |
| chksum      | u32      |                           |
| fips_status | u32      | FIPS approved or an error |

### MC_RANDOM_GENERATE

This generates random bytes that are returned from the internal RNG.

Command Code: `0x4D43_5247` ("MCRG")

*Table: `MC_RANDOM_GENERATE` input arguments*
| **Name**            | **Type** | **Description** |
| ------------------- | -------- | --------------- |
| chksum              | u32      |                 |
| data size to return | u32      |                 |


*Table: `MC_RANDOM_GENERATE` output arguments*
| **Name**    | **Type**        | **Description**           |
| ----------- | --------------- | ------------------------- |
| chksum      | u32             |                           |
| fips_status | u32             | FIPS approved or an error |
| output size | u32             | size of output            |
| output      | u8[output size] |                           |

### MC_IMPORT

Imports the specified key and returns a CMK for it.
Usage information is required so that the key can be verified and used appropriately.

Command Code: `0x4D43_494D` ("MCIM")

*Table: `MC_IMPORT` input arguments*
| **Name**   | **Type**       | **Description**                         |
| ---------- | -------------- | --------------------------------------- |
| chksum     | u32            |                                         |
| key usage  | u32            | Tag to specify how the data can be used |
| input size | u32            | This MUST agree with the key usage      |
| input      | u8[input size] |                                         |

*Table: `MC_IMPORT` output arguments*
| **Name**    | **Type** | **Description**             |
| ----------- | -------- | --------------------------- |
| chksum      | u32      |                             |
| fips_status | u32      | FIPS approved or an error   |
| CMK         | CMK      | CMK containing imported key |

### MC_DELETE

Deletes the object stored with the given mailbox ID.

Command Code: `0x4D43_444C` ("MCDL")

*Table: `MC_DELETE` input arguments*
| **Name** | **Type** | **Description** |
|----------|----------|-----------------|
| chksum   | u32      |                 |
| CMK      | CMK      | CMK to delete   |

*Table: `MC_DELETE` output arguments*
| **Name**     | **Type** | **Description**           |
|--------------|----------|---------------------------|
| chksum       | u32      |                           |
| fips_status  | u32      | FIPS approved or an error |

### MC_ECDSA384_SIG_VERIFY

Verifies an ECDSA P-384 signature. The hash to be verified is taken from the input.

Command Code: `0x4D45_4356` ("MECV")

*Table: `MC_ECDSA384_SIG_VERIFY` input arguments*
| **Name**      | **Type** | **Description**                                                                 |
|---------------|----------|-------------------------------------------------------------------------------|
| chksum        | u32      | Checksum over other input arguments, computed by the caller. Little endian.   |
| pub_key_x     | u8[48]   | X portion of the ECDSA verification key.                                      |
| pub_key_y     | u8[48]   | Y portion of the ECDSA verification key.                                      |
| signature_r   | u8[48]   | R portion of the signature to verify.                                         |
| signature_s   | u8[48]   | S portion of the signature to verify.                                         |
| hash          | u8[48]   | SHA-384 digest to verify.                                                    |

*Table: `MC_ECDSA384_SIG_VERIFY` output arguments*
| **Name**      | **Type** | **Description**                                                                 |
|---------------|----------|-------------------------------------------------------------------------------|
| chksum        | u32      | Checksum over other output arguments, computed by responder. Little endian.   |
| fips_status   | u32      | Indicates if the command is FIPS approved or an error.                        |

### MC_LMS_SIG_VERIFY

Verifies an LMS signature. The hash to be verified is taken from the input.

Command Code: `0x4D4C_4D56` ("MLMV")

*Table: `MC_LMS_SIG_VERIFY` input arguments*
| **Name**              | **Type** | **Description** |
| --------------------- | -------- | --------------- |
| chksum                | u32      | Checksum over other input arguments, computed by the caller. Little endian. |
| pub_key_tree_type     | u8[4]    | LMS public key algorithm type. Must equal 12. |
| pub_key_ots_type      | u8[4]    | LM-OTS algorithm type. Must equal 7. |
| pub_key_id            | u8[16]   | "I" Private key identifier |
| pub_key_digest        | u8[24]   | "T[1]" Public key hash value |
| signature_q           | u8[4]    | Leaf of the Merkle tree where the OTS public key appears |
| signature_ots         | u8[1252] | LM-OTS signature |
| signature_tree_type   | u8[4]    | LMS signature Algorithm type. Must equal 12. |
| signature_tree_path   | u8[360]  | Path through the tree from the leaf associated with the LM-OTS signature to the root |
| hash                  | u8[48]   | SHA384 digest to verify. |

*Table: `MC_LMS_SIG_VERIFY` output arguments*
| **Name**    | **Type** | **Description**
| --------    | -------- | ---------------
| chksum      | u32      | Checksum over other output arguments, computed by MCU. Little endian.
| fips_status | u32      | Indicates if the command is FIPS approved or an error.

### MC_ECDSA_SIGN
Requests to sign SHA-384 digest with DPE leaf cert.

Command Code: `0x4D45_4353` ("MECS")

*Table: `MC_ECDSA384_SIGN` input arguments*
| **Name**   | **Type** | **Description**                                                                 |
|------------|----------|-------------------------------------------------------------------------------|
| chksum     | u32      | Checksum over other input arguments, computed by the caller. Little endian.   |
| digest     | u8[48]   | SHA-384 digest to be signed.                                                  |

*Table: `MC_ECDSA384_SIGN` output arguments*
| **Name**          | **Type** | **Description**                                                                 |
|-------------------|----------|-------------------------------------------------------------------------------|
| chksum            | u32      | Checksum over other output arguments, computed by MCU. Little endian.         |
| fips_status       | u32      | Indicates if the command is FIPS approved or an error.                        |
| derived_pubkey_x  | u8[48]   | The X BigNum of the ECDSA public key associated with the signing key.         |
| derived_pubkey_y  | u8[48]   | The Y BigNum of the ECDSA public key associated with the signing key.         |
| signature_r       | u8[48]   | The R BigNum of an ECDSA signature.                                           |
| signature_s       | u8[48]   | The S BigNum of an ECDSA signature.                                           |

### MC_MLDSA_SIGN

Request to sign the SHA-384 digest with DPE leaf cert.

Command Code: `0x4D4C_4D53` ("MMLS")

*Table: `MC_MLDSA_SIGN` input arguments*

| **Name** | **Type** | **Description**                                                                 |
|----------|----------|-------------------------------------------------------------------------------|
| chksum   | u32      | Checksum over other input arguments, computed by the caller. Little endian.   |
| digest   | u8[48]   | SHA-384 digest to be signed.                                                  |

*Table: `MC_MLDSA_SIGN` output arguments*

| **Name**             | **Type**   | **Description**                           |
|----------------------|------------|-------------------------------------------|
| chksum               | u32        |                                           |
| fips_status          | u32        | FIPS approved or an error                 |
| pub_key_tree_type    | u8[4]      | LMS public key algorithm type.            |
| pub_key_ots_type     | u8[4]      | LM-OTS algorithm type.                    |
| pub_key_id           | u8[16]     | Private key identifier.                   |
| pub_key_digest       | u8[24]     | Public key hash value.                    |
| signature_q          | u8[4]      | Leaf of the Merkle tree for the OTS key.  |
| signature_ots        | u8[1252]   | LM-OTS signature.                         |
| signature_tree_path  | u8[360]    | Path through the Merkle tree to the root. |

### MC_PRODUCTION_DEBUG_UNLOCK_REQ

Requests debug unlock in production environment.

Command Code: `0x4D44_5552` ("MDUR")

*Table: `MC_PRODUCTION_DEBUG_UNLOCK_REQ` input arguments*
| **Name**       | **Type** | **Description**                 |
|-----------------|----------|---------------------------------|
| chksum          | u32      |                                 |
| length          | u32      | Length of the message in DWORDs |
| unlock_level    | u8       | Debug unlock Level (Number 1-8) |
| reserved        | u8[3]    | Reserved field                  |

*Table: `MC_PRODUCTION_DEBUG_UNLOCK_REQ` output arguments*
| **Name**                 | **Type**  | **Description**                     |
|--------------------------|-----------|-------------------------------------|
| chksum                   | u32       | Checksum over other output arguments. |
| fips_status              | u32       | FIPS approved or an error            |
| length                   | u32       | Length of the message in DWORDs.     |
| unique_device_identifier | u8[32]    | Device identifier of the Caliptra device. |
| challenge                | u8[48]    | Random number challenge.             |

### MC_PRODUCTION_DEBUG_UNLOCK_TOKEN

Sends the debug unlock token.

Command Code: `0x4D44_5554` ("MDUT")

*Table: `MC_PRODUCTION_DEBUG_UNLOCK_TOKEN` input arguments*
| **Name**                 | **Type**       | **Description**                                                                 |
|--------------------------|----------------|---------------------------------------------------------------------------------|
| chksum                   | u32            | Checksum over other input arguments.                                           |
| fips_status              | u32            | FIPS approved or an error                                                      |
| length                   | u32            | Length of the message in DWORDs.                                               |
| unique_device_identifier | u8[32]         | Device identifier of the Caliptra device.                                       |
| unlock_level             | u8             | Debug unlock level (1-8).                                                      |
| reserved                 | u8[3]          | Reserved field.                                                                |
| challenge                | u8[48]         | Random number challenge.                                                       |
| ecc_public_key           | u32[24]        | ECC public key in hardware format (little endian).                             |
| mldsa_public_key         | u32[648]       | MLDSA public key in hardware format (little endian).                           |
| ecc_signature            | u32[24]        | ECC P-384 signature of the message hashed using SHA2-384 (R and S coordinates).|
| mldsa_signature          | u32[1157]      | MLDSA signature of the message hashed using SHA2-512 (4627 bytes + 1 reserved byte). |

*Table: `MC_PRODUCTION_DEBUG_UNLOCK_TOKEN` output arguments*
| **Name**                 | **Type**       | **Description**                                                                 |
|--------------------------|----------------|---------------------------------------------------------------------------------|
| chksum                   | u32            |                                                                                 |
| fips_status              | u32            | FIPS approved or an error                                                      |

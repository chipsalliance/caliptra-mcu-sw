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

- **In-Field Fuse Provisioning**
    - See [fuses spec](fuses.md) for details.

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
| MC_FIPS_SELF_TEST_START           | 0x4D46_5354 ("MFST") | Starts the FIPS self-test to exercise the crypto engine.                                           |
| MC_FIPS_SELF_TEST_GET_RESULTS     | 0x4D46_4752 ("MFGR") | Retrieves the results of the FIPS self-test.                                                       |
| MC_FIPS_PERIODIC_ENABLE           | 0x4D46_5045 ("MFPE") | Enables or disables periodic FIPS self-test.                                                       |
| MC_FIPS_PERIODIC_STATUS           | 0x4D46_5053 ("MFPS") | Retrieves the status of periodic FIPS self-test.                                                   |
| MC_SHA_INIT                       | 0x4D43_5349 ("MCSI") | Starts the computation of a SHA hash of data.                                                      |
| MC_SHA_UPDATE                     | 0x4D43_5355 ("MCSU") | Continues a SHA computation started by `MC_SHA_INIT` or another `MC_SHA_UPDATE`.                   |
| MC_SHA_FINAL                      | 0x4D43_5346 ("MCSF") | Finalizes the computation of a SHA and produces the hash of all the data.                          |
| MC_HMAC                           | 0x4D43_484D ("MCHM") | Computes an HMAC according to RFC 2104.                                                            |
| MC_HMAC_KDF_COUNTER               | 0x4D43_4B43 ("MCKC") | Computes HMAC KDF in Counter Mode as specified in NIST SP800-108.                                  |
| MC_HKDF_EXTRACT                   | 0x4D43_4B54 ("MCKT") | Implements HKDF-Extract as specified in RFC 5869.                                                  |
| MC_HKDF_EXPAND                    | 0x4D43_4B50 ("MCKP") | Implements HKDF-Expand as specified in RFC 5869.                                                   |
| MC_AES_ENCRYPT_INIT               | 0x4D43_4349 ("MCCI") | Starts an AES encryption operation.                                                                |
| MC_AES_ENCRYPT_UPDATE             | 0x4D43_4355 ("MCCU") | Continues an AES encryption operation started by `MC_AES_ENCRYPT_INIT`.                            |
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
| MC_ECDSA_CMK_PUBLIC_KEY           | 0x4D43_4550 ("MCEP") | Generates an ECDSA public key from a CMK.                                                          |
| MC_ECDSA_CMK_SIGN                 | 0x4D43_4553 ("MCES") | Creates an ECDSA signature using a CMK.                                                            |
| MC_ECDSA_CMK_VERIFY               | 0x4D43_4556 ("MCEV") | Validates an ECDSA signature using a CMK.                                                          |
| MC_RANDOM_STIR                    | 0x4D43_5253 ("MCRS") | Adds additional entropy to the internal deterministic random bit generator.                        |
| MC_RANDOM_GENERATE                | 0x4D43_5247 ("MCRG") | Generates random bytes from the internal RNG.                                                      |
| MC_IMPORT                         | 0x4D43_494D ("MCIM") | Imports a specified key and returns a CMK for it.                                                  |
| MC_DELETE                         | 0x4D43_444C ("MCDL") | Deletes the object stored with the given mailbox ID.                                               |
| MC_ECDSA384_SIG_VERIFY            | 0x4D45_4356 ("MECV") | Verifies an ECDSA P-384 signature.                                                                 |
| MC_LMS_SIG_VERIFY                 | 0x4D4C_4D56 ("MLMV") | Verifies an LMS signature.                                                                         |
| MC_ECDSA384_SIGN                  | 0x4D45_4353 ("MECS") | Requests to sign a SHA-384 digest with the DPE leaf certificate.                                   |
| MC_MLDSA_SIGN                     | 0x4D4C_4D53 ("MLMS") | Requests to sign a SHA-384 digest with the DPE leaf certificate using MLDSA.                       |
| MC_PRODUCTION_DEBUG_UNLOCK_REQ    | 0x4D44_5552 ("MDUR") | Requests debug unlock in a production environment.                                                 |
| MC_PRODUCTION_DEBUG_UNLOCK_TOKEN  | 0x4D44_5554 ("MDUT") | Sends the debug unlock token.                                                                      |
| MC_FUSE_READ                      | 0x4946_5052 ("IFPR") | See [fuses spec](fuses.md) for details |
| MC_FUSE_WRITE                     | 0x4946_5057 ("IFPW") | See [fuses spec](fuses.md) for details |
| MC_FUSE_LOCK_PARTITION            | 0x4946_504B ("IFPK") | See [fuses spec](fuses.md) for details |

## Command Format

### MC_FIRMWARE_VERSION

Retrieves the version of the target firmware.

Command Code: `0x4D46_5756` ("MFWV")

*Table: `MC_FIRMWARE_VERSION` input arguments*
| **Name**   | **Type**       | **Description**                         |
| ---------- | -------------- | --------------------------------------- |
| chksum     |  u32           |                                         |
| index      |  u32           | - `00h` = Caliptra core firmware       |
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
| index      | u32      | Information Index:                     |
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
| index      | u32      | Information Index:                     |
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
| log type   | u32      | Type of log to retrieve: |
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
| log type   | u32      | Type of log to retrieve: |
|            |          | - `0` = Debug Log        |
|            |          | - `1` = Attestation Log  |

*Table: `MC_CLEAR_LOG` output arguments*
| **Name**    | **Type**       | **Description**            |
|-------------|----------------|----------------------------|
| chksum      | u32            |                            |
| fips_status | u32            | FIPS approved or an error. |

### MC_FIPS_PERIODIC_ENABLE

Enables or disables periodic FIPS self-test. When enabled, the MCU runs FIPS self-tests in the background at a configurable interval (default: 60 seconds).

Command Code: `0x4D46_5045` ("MFPE")

*Table: `MC_FIPS_PERIODIC_ENABLE` input arguments*
| **Name**   | **Type** | **Description**                         |
|------------|----------|-----------------------------------------|
| chksum     | u32      | Checksum over input data                |
| enable     | u32      | 0 = disable, 1 = enable periodic test   |

*Table: `MC_FIPS_PERIODIC_ENABLE` output arguments*
| **Name**    | **Type** | **Description**            |
|-------------|----------|----------------------------|
| chksum      | u32      |                            |
| fips_status | u32      | FIPS approved or an error. |

### MC_FIPS_PERIODIC_STATUS

Retrieves the status of the periodic FIPS self-test, including whether it is enabled, the number of completed iterations, and the result of the last test.

Command Code: `0x4D46_5053` ("MFPS")

*Table: `MC_FIPS_PERIODIC_STATUS` input arguments*
| **Name**   | **Type** | **Description**          |
|------------|----------|--------------------------|
| chksum     | u32      | Checksum over input data |

*Table: `MC_FIPS_PERIODIC_STATUS` output arguments*
| **Name**    | **Type** | **Description**                                           |
|-------------|----------|-----------------------------------------------------------|
| chksum      | u32      |                                                           |
| fips_status | u32      | FIPS approved or an error.                                |
| enabled     | u32      | 0 = disabled, 1 = enabled                                 |
| iterations  | u32      | Number of completed periodic test iterations              |
| last_result | u32      | Last test result: 0 = not run yet, 1 = pass, 2 = fail     |

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

### MC_ECDSA384_SIGN
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

{{#include fuse_api_cmd.md}}

### Cryptographic Command Format

The MCI mailbox cryptographic commands are mapped to their corresponding Caliptra Mailbox Cryptographic commands. The mapping is detailed in the table below. For the specific format of each command, refer to the [Mailbox Commands: Cryptographic Mailbox (2.0)](https://github.com/chipsalliance/caliptra-sw/blob/main/runtime/README.md#mailbox-commands-cryptographic-mailbox-20).

*Table: mapping MCI Mailbox Crypto Commands to Caliptra Crypto Mailbox Commands*
| **MCI Mailbox Crypto Commands** | **Caliptra Mailbox Crypto Commands**         |
|--------------------------------|---------------------------------------------|
| `MC_FIPS_SELF_TEST_START`     | `SELF_TEST_START`                           |
| `MC_FIPS_SELF_TEST_GET_RESULTS` | `SELF_TEST_GET_RESULTS`                   |
| `MC_SHA_INIT`                 | `CM_SHA_INIT`                               |
| `MC_SHA_UPDATE`               | `CM_SHA_UPDATE`                             |
| `MC_SHA_FINAL`                | `CM_SHA_FINAL`                              |
| `MC_HMAC`                     | `CM_HMAC`                                   |
| `MC_HMAC_KDF_COUNTER`         | `CM_HMAC_KDF_COUNTER`                       |
| `MC_HKDF_EXTRACT`             | `CM_HKDF_EXTRACT`                           |
| `MC_HKDF_EXPAND`              | `CM_HKDF_EXPAND`                            |
| `MC_AES_ENCRYPT_INIT`         | `CM_AES_ENCRYPT_INIT`                       |
| `MC_AES_ENCRYPT_UPDATE`       | `CM_AES_ENCRYPT_UPDATE`                     |
| `MC_AES_DECRYPT_INIT`         | `CM_AES_DECRYPT_INIT`                       |
| `MC_AES_DECRYPT_UPDATE`       | `CM_AES_DECRYPT_UPDATE`                     |
| `MC_AES_GCM_ENCRYPT_INIT`     | `CM_AES_GCM_ENCRYPT_INIT`                   |
| `MC_AES_GCM_ENCRYPT_UPDATE`   | `CM_AES_GCM_ENCRYPT_UPDATE`                 |
| `MC_AES_GCM_ENCRYPT_FINAL`    | `CM_AES_GCM_ENCRYPT_FINAL`                  |
| `MC_AES_GCM_DECRYPT_INIT`     | `CM_AES_GCM_DECRYPT_INIT`                   |
| `MC_AES_GCM_DECRYPT_UPDATE`   | `CM_AES_GCM_DECRYPT_UPDATE`                 |
| `MC_AES_GCM_DECRYPT_FINAL`    | `CM_AES_GCM_DECRYPT_FINAL`                  |
| `MC_ECDH_GENERATE`            | `CM_ECDH_GENERATE`                          |
| `MC_ECDH_FINISH`              | `CM_ECDH_FINISH`                            |
| `MC_ECDSA_CMK_PUBLIC_KEY`     | `CM_ECDSA_PUBLIC_KEY`                       |
| `MC_ECDSA_CMK_SIGN`           | `CM_ECDSA_SIGN`                             |
| `MC_ECDSA_CMK_VERIFY`         | `CM_ECDSA_VERIFY`                           |
| `MC_RANDOM_STIR`              | `CM_RANDOM_STIR`                            |
| `MC_RANDOM_GENERATE`          | `CM_RANDOM_GENERATE`                        |
| `MC_IMPORT`                   | `CM_IMPORT`                                 |
| `MC_DELETE`                   | `CM_DELETE`                                 |

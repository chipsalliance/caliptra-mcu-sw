



## MCI Mailbox Commands


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
| cmd status |  u32           | Success or error code                   |
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
| cmd status | u32            | Command status success or error code    |
| caps       | u8[32]         |                                         |
|            |                | - Bytes [0:7]: Reserved for Caliptra RT |
|            |                | - Bytes [8:11]: Reserved for Caliptra FMC |
|            |                | - Bytes [12:15]: Reserved for Caliptra ROM |
|            |                | - Bytes [16:23]: Reserved for MCU RT    |
|            |                | - Bytes [24:27]: Reserved for MCU ROM   |
|            |                | - Bytes [28:31]: Reserved               |

#### MC_DEVICE_ID

Retrieves the device ID.

Command Code: `0x4D44_4944` ("MDID")

*Table: `MC_DEVICE_ID` input arguments*
| **Name**   | **Type**       | **Description**                         |
| ---------- | -------------- | --------------------------------------- |
| chksum     |  u32           |                                         |

*Table: `MC_DEVICE_ID` output arguments*
| **Name**               | **Type** | **Description**               |
|------------------------| -------- | ----------------------------- |
| vendor_id              | u16      | Vendor ID; LSB                |
| device_id              | u16      | Device ID; LSB                |
| subsystem_vendor_id    | u16      | Subsystem Vendor ID; LSB      |
| subsystem_id           | u16      | Subsystem ID; LSB             |


#### MC_DEVICE_INFO

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
| **Name**   | **Type**       | **Description**                         |
| ---------- | -------------- | --------------------------------------- |
| chksum     | u32            |                                         |
| cmd status | u32            | Success or error code                   |
| data_size  | u32            | Size of the requested data in bytes     |
| data       | u8[data_size]  | Requested information in binary format  |

// TODO: Cleaning up this part
### Export CSR

Exports the IDEVID Self-Signed Certificate Signing Request.

**Request Payload**:

| Byte Offset | Description                          |
|-------------|--------------------------------------|
| 1           | Index: Default = `0`                |

**Response Payload**:

| Byte Offset | Description                          |
|-------------|--------------------------------------|
| 1:N         | Certificate in DER format           |

### Import Certificate

The Import Certificate command allows the device to receive and store a signed Device Identification certificate chain. Each command sends a single certificate in the chain to the device. The order of certificate imports is not enforced, meaning certificates can be sent in any sequence.

Once the device verifies that the complete certificate chain has been received and is valid, the device is sealed. After sealing, no further certificate imports are allowed unless the firmware is updated.

A response message is returned immediately after the device processes the new certificate. This response only indicates whether the certificate was accepted by the device; it does not confirm the validity of the entire certificate chain. The full state of the certificate provisioning process can be queried using the Get Certificate State command.

**Request Payload**:

| Byte Offset | Description                          |
|-------------|--------------------------------------|
| 1           | Index:                              |
|             | - `0` = Device Identification Certificate |
|             | - `1` = Root CA Certificate         |
|             | - `2` = Intermediate CA Certificate |
|             | Additional indices are implementation-specific |
| 2:3         | Certificate Length                  |
| 4:N         | Certificate in DER format           |

#### Get Certificate State

Determines the state of the certificate chain for signed certificates that have been sent to the device. The request for this command contains no additional payload.

**Request Payload**: Empty

| Byte Offset | Description                          |
|-------------|--------------------------------------|

**Response Payload**:

| Byte Offset | Description                          |
|-------------|--------------------------------------|
| 1           | State:                              |
|             | - `0` = A valid chain has been provisioned. |
|             | - `1` = A valid chain has not been provisioned. |
|             | - `2` = The stored chain is being validated. |
| 2:4         | Error details if chain validation has failed. |

#### Get Log

Retrieves the internal log for the RoT. There are three types of logs available: the Debug Log, which contains RoT application information and machine state, and the Attestation Measurement Log, which is similar to the TCG log.

**Log Types**:

| Log Type | Description          |
|----------|----------------------|
| 1        | Debug Log            |
| 2        | Attestation Log      |

**Request Payload**:

| Byte Offset | Description          |
|-------------|----------------------|
| 1           | Log Type             |
| 2:5         | Offset               |

**Response Payload**:

| Byte Offset | Description          |
|-------------|----------------------|
| 1:N         | The contents of the log |

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

#### Clear Log

Clears the log in the RoT subsystem.

**Request Payload**:

| Byte Offset | Description          |
|-------------|----------------------|
| 1           | Log Type:            |
|             | - `01h` = Debug Log  |
|             | - `02h` = Attestation Log |

/// TODO: Clean up Above 


### MC_SHA_INIT

This starts the computation of a SHA hash of data, which may be larger than a single mailbox command allows. It also supports additional algorithms.

The sequence to use these are:
* 1 `MC_SHA_INIT` command
* 0 or more `MC_SHA_UPDATE` commands
* 1 `MC_SHA_FINAL` command

For each command, the context from the previous command's output must be passed as an input.

The `SHA_CONTEXT_SIZE` is always exactly 200 bytes long.

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

Generic AES operation for unauthenticated AES operations.
AES GCM operations use separate commands elsewhere.

Currently only supports AES-256-CBC with a random 128-bit IV.

For block modes, such as CBC, the size must be a multiple of 16 bytes.

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
| context        | AES_CONTEXT     |                               |
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
| **Name**     | **Type** | **Description**
| --------     | -------- | ---------------
| chksum       | u32      | Checksum over other input arguments, computed by the caller. Little endian. |
| pub_key_x  | u8[48]   | X portion of ECDSA verification key.
| pub_key_y  | u8[48]   | Y portion of ECDSA verification key.
| signature_r | u8[48]   | R portion of signature to verify.
| signature_s | u8[48]   | S portion of signature to verify.
| hash         | u8[48]   | SHA384 digest to verify.

*Table: `MC_ECDSA384_SIG_VERIFY` output arguments*
| **Name**      | **Type** | **Description**
| --------      | -------- | ---------------
| chksum        | u32      |                                        |
| fips_status  | u32      | Indicates if the command is FIPS approved or an error. |

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
| **Name**       | **Type** | **Description**                                   |
| -------------- | -------- | ------------------------------------------------- |
| chksum         | u32      | Checksum over other input arguments, computed by the caller. Little endian. |
| digest         | u8[48]   | SHA-384 digest to be signed.                      |
*Table: `MC_ECDSA384_SIGN` output arguments*

| **Name**           | **Type** | **Description**                                                                 |
|--------------------|----------|---------------------------------------------------------------------------------|
| chksum            | u32      | Checksum over other output arguments, computed by MCU. Little endian.           |
| fips_status       | u32      | Indicates if the command is FIPS approved or an error.                          |
| derived_pubkey_x  | u8[48]   | The X BigNum of the ECDSA public key associated with the signing key.           |
| derived_pubkey_y  | u8[48]   | The Y BigNum of the ECDSA public key associated with the signing key.           |
| signature_r       | u8[48]   | The R BigNum of an ECDSA signature.                                             |
| signature_s       | u8[48]   | The S BigNum of an ECDSA signature.                                             |

### MC_MLDSA_SIGN

Request to sign the SHA-384 digest with DPE leaf cert.

Command Code: `0x4D4C_4D53` "MMLS"

*Table: `MC_MLDSA_SIGN` input arguments*
| **Name**       | **Type** | **Description**                                   |
| -------------- | -------- | ------------------------------------------------- |
| chksum         | u32      | Checksum over other input arguments, computed by the caller. Little endian. |
| digest         | u8[48]   | SHA-384 digest to be signed.                      |

*Table: `MC_MLDSA_SIGN` output arguments*

| **Name**             | **Type**  | **Description**                           |
|----------------------|-----------|-------------------------------------------|
| pub_key_tree_type    | u8[4]     | LMS public key algorithm type.            |
| pub_key_ots_type     | u8[4]     | LM-OTS algorithm type.                    |
| pub_key_id           | u8[16]    | Private key identifier.                   |
| pub_key_digest       | u8[24]    | Public key hash value.                    |
| signature_q          | u8[4]     | Leaf of the Merkle tree for the OTS key.  |
| signature_ots        | u8[1252]  | LM-OTS signature.                         |
| signature_tree_path  | u8[360]   | Path through the Merkle tree to the root. |

### MC_PRODUCTION_DEBUG_UNLOCK_REQ

Requests debug unlock in production environment.

Command Code: `0x4D44_5552`("MDUR")

*Table: `MC_PRODUCTION_DEBUG_UNLOCK_REQ` input arguments*
| **Name**       | **Type** | **Description**                  |
|-----------------|----------|----------------------------------|
| chksum          | u32      |                                  |
| length          | u32      | Length of the message in DWORDs  |
| unlock_level    | u8       | Debug unlock Level (Number 1-8)  |
| reserved        | u8[3]    | Reserved field                   |

*Table: `MC_PRODUCTION_DEBUG_UNLOCK_REQ` output arguments*
| **Name**                 | **Type**  | **Description**                     |
|--------------------------|-----------|-------------------------------------|
| chksum                   | u32       | Checksum over other output arguments. |
| fips_status              | u32      | FIPS approved or an error   |
| length                   | u32       | Length of the message in DWORDs.    |
| unique_device_identifier | u8[32]    | Device identifier of the Caliptra device. |
| challenge                | u8[48]    | Random number challenge.            |

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
| chksum                   | u32            | Checksum over other input arguments.                                           |
| fips_status              | u32            | FIPS approved or an error                                                      |
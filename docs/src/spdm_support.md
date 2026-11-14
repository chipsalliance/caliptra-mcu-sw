# SPDM Responder Support

This page lists what the SPDM responder in
[`runtime/userspace/api/spdm-lib`](../../runtime/userspace/api/spdm-lib)
supports. For the supported requests, see
[Supported Requests](./spdm.md#supported-requests). For the design, see
[SPDM](./spdm.md).

The responder's local policy is set in `ConnectionState::caliptra()` in
[`stack/src/stack.rs`](../../runtime/userspace/api/spdm-lib/stack/src/stack.rs).

## Versions

| Item                    | Supported                 | Source                                                                                     |
| ----------------------- | ------------------------- | ------------------------------------------------------------------------------------------ |
| SPDM version (DSP0274)  | 1.2, 1.3, 1.4             | `SUPPORTED_VERSIONS` in [`stack/src/version.rs`](../../runtime/userspace/api/spdm-lib/stack/src/version.rs) |
| Secured message version (DSP0277) | 1.1             | `select_version` in [`codec/src/opaque.rs`](../../runtime/userspace/api/spdm-lib/codec/src/opaque.rs) |

- SPDM 1.0 and 1.1 are not supported. `GET_VERSION` itself must still use
  version 1.0 in its header, as the specification requires.
- The secured message version is selected in `KEY_EXCHANGE` from the
  requester's supported-version list (opaque data, `OpaqueDataFmt1`). Only
  major and minor version are compared. If the list does not contain 1.1,
  `KEY_EXCHANGE` fails with `InvalidRequest`. If the requester sends no
  opaque data, `KEY_EXCHANGE` is accepted and no version selection is
  returned.

## Capabilities

`CAPABILITIES` response flags. A flag is only sent if the negotiated SPDM
version defines it.

| Flag (bit)                    | Advertised | Condition                                                                 |
| ----------------------------- | ---------- | ------------------------------------------------------------------------- |
| `CERT_CAP` (1)                | Yes        |                                                                           |
| `CHAL_CAP` (2)                | Yes        |                                                                           |
| `MEAS_CAP` (3-4)              | Yes        | Value `10b`: measurements with signature                                  |
| `ENCRYPT_CAP` (6)             | Yes        | Only if the transport supports secured messages [^sm]                     |
| `MAC_CAP` (7)                 | Yes        | Only if the transport supports secured messages [^sm]                     |
| `KEY_EX_CAP` (9)              | Yes        | Only if the transport supports secured messages [^sm]                     |
| `CHUNK_CAP` (17)              | Yes        | Only if the PAL can buffer at least one transport MTU                     |
| `ALIAS_CERT_CAP` (18)         | Yes        |                                                                           |
| `SET_CERT_CAP` (19)           | Optional   | `set-certificate` feature                                                 |
| `MULTI_KEY_CAP` (26-27)       | Optional   | `set-certificate` feature, value `10b` (`MultiKeyConnRsp`), SPDM 1.3+     |
| `GET_KEY_PAIR_INFO_CAP` (28)  | Optional   | `set-certificate` feature, SPDM 1.3+                                      |
| `LARGE_RESP_CAP` (31)         | Yes        | SPDM 1.4 only                                                             |

All other flags are not advertised. These include `CACHE_CAP`,
`MEAS_FRESH_CAP`, `MUT_AUTH_CAP`, `PSK_CAP`, `ENCAP_CAP`, `HBEAT_CAP`,
`KEY_UPD_CAP`, `HANDSHAKE_IN_THE_CLEAR_CAP`, `PUB_KEY_ID_CAP`, `CSR_CAP`,
`CERT_INSTALL_RESET_CAP`, `EP_INFO_CAP`, `MEL_CAP`, `EVENT_CAP`,
`SET_KEY_PAIR_INFO_CAP` and `SET_KEY_PAIR_RESET_CAP`.

Other `CAPABILITIES` fields:

| Field              | Value                                                                    |
| ------------------ | ------------------------------------------------------------------------ |
| `CTExponent`       | 20 (2^20 µs, about 1 s)                                                  |
| `DataTransferSize` | Transport MTU                                                            |
| `MaxSPDMmsgSize`   | PAL maximum inbound request size with `CHUNK_CAP`, otherwise the MTU     |
| Extended flags     | None                                                                     |

[^sm]: Currently only DOE. See
    [Transport Support](./spdm.md#transport-support).

## Algorithms

The responder supports exactly one algorithm per family. In `ALGORITHMS`
it selects that algorithm if the requester offers it, and selects nothing
otherwise.

| Family                          | Algorithm            | Condition                                                         |
| ------------------------------- | -------------------- | ----------------------------------------------------------------- |
| `MeasurementSpecification`      | DMTF                 |                                                                   |
| `MeasurementHashAlgo`           | SHA-384              | Always selected; the requester does not negotiate it              |
| `BaseHashAlgo`                  | SHA-384              |                                                                   |
| `BaseAsymAlgo`                  | ECDSA NIST P-384     | Used if ML-DSA-87 is not selected                                 |
| `PqcAsymAlgo`                   | ML-DSA-87            | SPDM 1.4 only; preferred over ECDSA if the requester offers both  |
| DHE                             | SECP384R1            | Secured-message transports only [^sm]                             |
| KEM                             | ML-KEM-1024          | SPDM 1.4 only, secured-message transports only; preferred over DHE |
| AEAD                            | AES-256-GCM          | Secured-message transports only [^sm]                             |
| `KeySchedule`                   | SPDM key schedule    | Secured-message transports only [^sm]                             |
| `OtherParamsSupport`            | `OpaqueDataFmt1`     |                                                                   |
| `OtherParamsSupport`            | `MULTI_KEY_CONN`     | `set-certificate` feature, SPDM 1.3+                              |

Extended algorithms (`ExtAsym`, `ExtHash`, extended `AlgStruct` entries)
are not supported.

## Limitations

- **No mutual authentication**: the responder never authenticates the
  requester (`MUT_AUTH_CAP`, encapsulated requests).
- **No pre-shared keys**: sessions are only created with `KEY_EXCHANGE`,
  not `PSK_EXCHANGE`.
- **No `HEARTBEAT` or `KEY_UPDATE`**: session keys are not updated during a
  session.
- **`FINISH` is always encrypted**: `HANDSHAKE_IN_THE_CLEAR_CAP` is not
  supported.
- **Secure sessions only over DOE**: see
  [Transport Support](./spdm.md#transport-support).
- **Number of sessions**: limited by the `MAX_SESSIONS` parameter of
  `SpdmStack` (default 1).
- **`KEY_EXCHANGE` opaque data size**: SPDM allows up to 1024 bytes of
  `OpaqueData` in `KEY_EXCHANGE`. This implementation only guarantees
  support for opaque data containing a single _secured message
  supported-version list_ with up to 8 versions (or a total of 28 bytes of opaque data).
  Buffer allocation for large `KEY_EXCHANGE` requests (e.g. when using _ML-KEM_) with
  more than 28 bytes of opaque data might fail.

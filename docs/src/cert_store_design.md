# SPDM Certificate Store Design

This document describes the certificate store architecture used by the Caliptra
MCU SPDM responder. The store exposes SPDM certificate slots while keeping the
slot backing data, DPE device chain, and DPE leaf certificate as separate data
sources.

For the provisioning workflow, see [In-field Provisioning and Management of SPDM Certificate Slots](./cert_slot_mgmt.md).

## Overview

The PAL cert store supports three logical certificate slots by default:

| SPDM slot | PKI entity | Endorsement source | Writable |
| --- | --- | --- | --- |
| 0 | Vendor | Static MCU runtime data | No |
| 2 | Owner | Flash-backed managed store | Yes, with `set-certificate` |
| 3 | Tenant | Flash-backed managed store | Yes, with `set-certificate` |

The SPDM requester sees a complete certificate chain for each provisioned slot.
Internally, however, the PAL composes that chain from three independently owned
sources:

```text
SPDM certificate chain returned by GET_CERTIFICATE

+----------------------+----------------------+----------------------+
| 1. Endorsement       | 2. DPE device chain  | 3. DPE leaf cert    |
| Root CA -> device    | Caliptra Core DPE    | Caliptra Core DPE   |
| endorsement cert     | certificate chain    | CertifyKey cert     |
+----------------------+----------------------+----------------------+
```

Only the endorsement portion is stored in the MCU cert store. The DPE device
chain and DPE leaf certificate are retrieved from Caliptra Core at read time.
The DPE device chain is read in chunks, and the DPE leaf certificate is read
on demand using the `CERTIFY_KEY_CHUNKS` mailbox command.

## Certificate Store Model

The implementation keeps certificate-slot backing state shared while each SPDM
transport task owns its PAL/transport/allocator state. The shared model captures
the three OCP PKI roles exposed through SPDM: Vendor, Owner, and Tenant.

```text
                         +-----------------------+
                         |    SharedCertStore    |
                         |-----------------------|
                         | cert_slots[3]         |
                         |  - slot 0: Vendor     |
                         |  - slot 2: Owner      |
                         |  - slot 3: Tenant     |
                         +-----------+-----------+
                                     |
            shared reference         |        shared reference
      +------------------------------+------------------------------+
      |                                                             |
+-----v------------------+                              +-----------v--------+
|    MCTP task storage   |                              |   DOE task storage |
|------------------------|                              |--------------------|
| shared: SharedCertStore|                              | shared: Shared...  |
| SlotCache[3]           |                              | SlotCache[3]       |
|  - chain_len           |                              |  - chain_len       |
|  - leaf_len            |                              |  - leaf_len        |
|  - chain_digest        |                              |  - chain_digest    |
+------------------------+                              +--------------------+

SharedCertStore slot backing:

  +----------------------+----------------------+----------------------+
  | slot 0: Vendor       | slot 2: Owner        | slot 3: Tenant       |
  |----------------------|----------------------|----------------------|
  | ReadOnlyEndorsement  | ManagedEndorsement   | ManagedEndorsement   |
  | MCU runtime image    | SPI flash            | SPI flash            |
  | read-only            | set-certificate      | set-certificate      |
  +----------------------+----------------------+----------------------+

Full chain returned to a requester:

  endorsement/root portion  +  Caliptra Core DPE chain  +  DPE leaf cert
  (from slot backing)          (chunked read)              (CERTIFY_KEY_CHUNKS)
```

### SharedCertStore

`SharedCertStore` is a single static store referenced by every SPDM PAL instance
for transports such as MCTP and DOE. It owns the `CertSlot` array and the slot
backing definitions.

`CertSlot` is shared between tasks and contains only slot metadata, the slot
endorsement backing, and synchronization state for managed-slot updates.

### TaskCertStore

Each SPDM transport task owns a `TaskCertStore`. It wraps a reference to the
global `SharedCertStore` and keeps task-local cached values:

- composed certificate chain length,
- DPE leaf certificate length,
- composed certificate chain digest.

Each cached value is tagged with the shared slot's provisioning-state version.
When `SET_CERTIFICATE` writes or erases a managed slot, that slot's version is
bumped and stale task-local cache entries no longer match.

## Certificate Chain Composition

### Vendor slot

Slot 0 uses a read-only endorsement chain built into the MCU runtime image. The
complete chain returned to the requester is:

```text
static vendor endorsement
+ Caliptra Core DPE device chain
+ Caliptra Core DPE leaf certificate
```

`SET_CERTIFICATE` is rejected for slot 0.

### Managed slots

Managed slots use a flash-backed endorsement store. `SET_CERTIFICATE` writes the
endorsement/root DER bytes and associated metadata to flash. The full SPDM
certificate chain is still composed at read time:

```text
flash-backed managed endorsement
+ Caliptra Core DPE device chain
+ Caliptra Core DPE leaf certificate
```

The managed flash record stores the root hash from the SPDM certificate-chain
wrapper. The root hash is loaded from flash at boot and updated in memory after a
successful provisioning write.

## GET_CERTIFICATE Size Queries

SPDM 1.3 defines two different size queries in `GET_CERTIFICATE`:

| Request | Meaning | PAL path |
| --- | --- | --- |
| `Length = 0`, `SlotSizeRequested = 0` | Actual current composed certificate chain size | `cert_chain_len()` |
| `SlotSizeRequested = 1` | Bytes available for certificate slot storage | `cert_chain_slot_size()` |

`cert_chain_len()` computes the current full composed chain length:

```text
endorsement length + DPE device chain length + DPE leaf length
```

`cert_chain_slot_size()` returns the endorsement backing capacity only. It does
not walk the DPE chain and does not probe the leaf certificate. For slot 0 this
is the read-only endorsement length; for managed slots this is the flash-backed
DER capacity.

The SPDM stack adds the 52-byte SPDM certificate-chain header when forming the
wire response.

## GET_CERTIFICATE Read Flow

`GET_CERTIFICATE` can be requested in multiple portions. For each portion, the
PAL splices bytes from the composed chain layout:

```text
offset range requested by SPDM
        |
        v
+----------------------+----------------------+----------------------+
| endorsement backing  | DPE device chain     | DPE leaf cert       |
| static or flash      | chunked reads        | chunked CertifyKey  |
+----------------------+----------------------+----------------------+
```

The PAL reads only the bytes needed for the requested range. DPE device-chain
and leaf-certificate bytes are fetched in bounded chunks.

## GET_DIGESTS, CHALLENGE, and KEY_EXCHANGE

The composed certificate-chain digest is computed by streaming the same SPDM
certificate-chain wire bytes used by `GET_CERTIFICATE`:

```text
Length(2) | Reserved(2) | RootHash(48) | composed DER chain
```

`GET_DIGESTS`, `CHALLENGE`, and `KEY_EXCHANGE` use a task-local digest cache only
when the cached digest is tagged with the current shared slot provisioning-state
version. Otherwise, the digest is recomputed from the current composed chain and
stored with the current version.

## Synchronization

The cert store uses a slot-granular write gate:

```text
CertSlot.write_in_progress: AtomicBool
```

During a managed slot write or erase:

1. The writer sets `write_in_progress = true`.
2. Readers see the slot as not provisioned and fail or skip the slot.
3. The writer erases/writes flash and commits the managed record.
4. The writer updates in-memory slot metadata.
5. The writer clears `write_in_progress`.
6. The writer bumps the slot's provisioning-state version.

Length and digest caches are tagged with the slot provisioning-state version.
If a managed-slot update changes the version while cert-derived data is being
computed, the operation returns an error rather than returning a mixed or stale
value.

This is intentionally simple. The requester may retry after an SPDM error or
failed certificate validation. Slot-backed signing checks the provisioning-state
version before and after signing so a managed-slot update cannot complete in the
middle of a signature operation unnoticed. If this check fails, the responder
returns `RequestResynch`; any partially updated local transcript or session state
is discarded by the required restart from `GET_VERSION`.

## SET_CERTIFICATE Notes

`SET_CERTIFICATE` provisions only the endorsement/root portion for managed
slots. It does not persist the Caliptra Core DPE device chain or DPE leaf
certificate.

The incoming SPDM certificate-chain wrapper contains:

```text
Length(2) | Reserved(2) | RootHash(48) | DER endorsement chain
```

The stack validates the wrapper and passes the root hash and DER bytes to the
PAL. The managed store persists:

- DER endorsement bytes,
- root hash,
- key pair ID,
- certificate info,
- key usage mask,
- integrity metadata.

The managed record is committed after the DER bytes are written so an interrupted
write is treated as empty or invalid at the next boot.
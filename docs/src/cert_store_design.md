# Caliptra MCU Certificate Store Design

## Status and scope

This document defines the certificate-store architecture shared by Caliptra MCU
certificate transports. It is the design authority for the common store,
certificate-chain composition boundary, durable-update semantics, and
transport-adapter responsibilities.

The current implementation has a working shared P-384 store used by the MCTP
and DOE SPDM responders. It also has algorithm-and-role keying in the common
store. ML-DSA-87 is represented by that keying, but end-to-end ML-DSA-87
certificate service is not implemented yet. The MCI certificate-chain wire
contract is documented in [External Mailbox Commands](./external_mailbox_cmds.md);
its runtime implementation is intentionally deferred until the common service
and SPDM ML-DSA-87 path are ready.

This document does not define an integrator's flash layout, partition names,
record locations, or other backing-store implementation details. Those are
platform configuration choices, not certificate-service or transport contract
details.

## Design principles

1. The common store is protocol-neutral. It accepts a certificate algorithm
   and a certificate role; it does not accept SPDM slot IDs, SPDM BankIDs, MCI
   command IDs, or transport framing.
2. A protocol adapter maps its own address to the common-store key before
   accessing certificate data.
3. The store owns only the mutable or static endorsement portion of a chain.
   A certificate service composes that portion with device-generated
   certificates when a complete chain is requested.
4. A reader observes one committed generation of a chain. It never observes a
   mixture of an old chain and a new chain, and it does not observe staged
   bytes.
5. A write is durable before it becomes visible. Interruption, failed
   validation, and an abandoned write leave the previously committed chain
   readable.
6. Authorization, wire parsing, and protocol-specific validation remain above
   the common store.

## Certificate identity

The common-store key is:

```text
CertificateKey = (CertificateAlgorithm, CertificateRole)
```

`CertificateAlgorithm` selects the public-key certificate-chain family:

| Value | Meaning | Current status |
| --- | --- | --- |
| `EccP384` | ECDSA P-384 certificate chain | Implemented for the current SPDM path |
| `MlDsa87` | ML-DSA-87 certificate chain | Key space is implemented; complete chain service is pending |

`CertificateRole` identifies the PKI entity without inheriting a transport's
slot-numbering scheme:

| Value | Meaning |
| --- | --- |
| `Vendor` | Vendor-provisioned, normally read-only identity chain |
| `Owner` | Owner-provisioned identity chain |
| `Tenant` | Tenant-provisioned identity chain |

The existence of a role in the common model does not require every platform or
transport to expose it. In particular, the initial MCI certificate interface
does not support Tenant even though the common store can represent a Tenant
key.

### Adapter-owned addresses

SPDM and MCI use different address forms. They are adapter concerns, not
common-store identifiers:

| Adapter | Incoming address | Adapter action |
| --- | --- | --- |
| SPDM | Negotiated asymmetric algorithm and SPDM SlotID | Convert the negotiated algorithm to `CertificateAlgorithm` and the SPDM SlotID to `CertificateRole` |
| SPDM 1.4 slot management | BankID and SlotID | Resolve BankID to the selected algorithm, then map SlotID to `CertificateRole` |
| MCI mailbox | BankID, `asym_algo`, and SlotID | Require the BankID and `asym_algo` to agree, convert the algorithm and role, then call the common service |

A BankID is not a common-store concept and is not synonymous with an algorithm
inside the store. A bank is a protocol-level way to select an algorithm and
address a slot. The generic store needs only the resulting algorithm and role.

The reference mappings used by the current contracts are:

| Protocol address | Common role |
| --- | --- |
| SlotID 0 | `Vendor` |
| SlotID 2 | `Owner` |
| SlotID 3 | `Tenant` |

An integrator may choose a different adapter mapping without changing the
common-store model.

## Architecture

The certificate service has three layers:

```text
  SPDM over MCTP       SPDM over DOE          MCI mailbox
         |                    |                    |
         +--------------------+--------------------+
                              |
                    transport adapter
          wire framing, authorization, address mapping,
          protocol errors, negotiated-algorithm handling
                              |
                    certificate-chain service
          complete-chain composition, snapshot validation,
          generic metadata and streaming update operations
                              |
                     protocol-neutral store
       CertificateKey -> static or managed endorsement backing
                              |
              integrator-selected durable backing store
```

Today, the P-384 SPDM PAL contains the certificate-chain-composition logic
directly and uses `SharedCertStore` as the protocol-neutral storage layer. The
explicit certificate-chain service shown above is the next extraction boundary:
it will make the same complete-chain and update semantics available to SPDM and
MCI without placing SPDM types in the store or MCI types in the SPDM PAL.

### Store layer

`SharedCertStore` is shared by all transports. Its conceptual state is:

```text
SharedCertStore {
    slots[CertificateAlgorithm][CertificateRole]: CertSlot,
    writer_gates[CertificateAlgorithm][CertificateRole],
}

CertSlot {
    endorsement: Empty | ReadOnly | Managed,
    attributes: opaque certificate metadata,
    provisioning_state_version: generation counter,
    write-session state for managed slots,
}
```

The store provides the following properties:

- isolation between P-384 and ML-DSA-87 chains for the same role;
- isolation between Vendor, Owner, and Tenant chains for the same algorithm;
- static read-only and managed durable backings;
- per-key writer serialization;
- generation tracking for readers and derived-data caches; and
- opaque attributes such as key-pair ID and certificate type.

An opaque persistent `storage_id` may identify a configured managed backing.
It is local to the backing-store implementation and is never exposed through
SPDM or MCI.

### Certificate-chain service layer

The common certificate-chain service is responsible for the operations that
must be identical across transports:

- resolve a `CertificateKey`;
- report complete-chain metadata and capacity;
- read a complete DER-concatenated chain by offset;
- begin, write, validate, finish, abandon, or erase a mutable endorsement
  update;
- publish a new generation only after durable validation; and
- expose a generation snapshot suitable for cache and signed-object checks.

It must be parameterized by generic algorithm and role types. It must not
depend on `SpdmPalAsymAlgo`, SPDM headers, SPDM SlotIDs, BankIDs, MCI mailbox
messages, or an integrator's storage layout.

### Transport adapters

Each adapter owns:

- parsing and emitting its wire format;
- mapping wire addresses to `CertificateKey`;
- authorization and key-binding policy;
- protocol-specific request ordering and errors;
- selecting the negotiated or requested hash and asymmetric algorithms; and
- mapping common-service errors to transport errors.

The SPDM adapter additionally owns SPDM certificate-chain headers, digest
construction, challenge/session semantics, and `RequestResynch` handling. The
MCI adapter will own mailbox framing and its per-operation authorization
trailer. Neither adapter owns a second copy of certificate bytes or a separate
durable store.

## Certificate-chain ownership and composition

The store does not persist every certificate returned by a transport. It stores
the endorsement portion that is static or provisioned by a caller. The
certificate service adds the device-generated portion when serving a read:

```text
complete chain returned to a caller

+----------------------------+------------------------+-----------------------+
| stored endorsement portion | device/DPE chain       | device leaf chain     |
| static or managed backing  | generated by Caliptra  | generated by Caliptra |
+----------------------------+------------------------+-----------------------+
```

For a managed Owner or Tenant role, a caller writes only the mutable
endorsement portion. It must not write Caliptra-generated DPE or leaf
certificates. A later read returns the complete composed chain.

This rule applies to all transports:

| Operation | Data visible to or supplied by the caller |
| --- | --- |
| Read complete chain | Stored endorsement plus generated device and leaf portions |
| Write chain | Only the mutable endorsement portion and its metadata |
| Erase chain | Removes only the mutable endorsement portion; no generated device certificate is erased |

The current P-384 SPDM PAL composes the chain from a stored endorsement, a
Caliptra DPE device chain, and a `CertifyKey` leaf certificate. ML-DSA-87 needs
an equivalent algorithm-specific device-chain composer and signer before it
can be exposed through any transport.

## Slot states

Each `CertificateKey` is in one of these logical states:

| State | Meaning | Read behavior | Write behavior |
| --- | --- | --- | --- |
| Unsupported | No backing is configured | Report unsupported | Reject |
| Read-only active | A static endorsement chain is configured | Return the composed chain | Reject replacement and erase |
| Managed unprovisioned | Durable backing is configured but has no valid active record | Report unprovisioned | Allow authorized begin/write/finish |
| Managed active | A valid committed record is selected | Return the composed chain | Allow authorized replacement or erase |
| Managed staging | A replacement is being assembled | Continue to return the prior active chain | Serialize concurrent writers; do not expose staged bytes |

Staging is an internal state. It is not represented as a transport-visible
certificate slot state, and it never changes the data returned by a read.

## Managed update and recovery

A managed update is transactional at the certificate-key granularity:

```text
1. Adapter authorizes the operation and resolves CertificateKey.
2. A writer obtains the per-key asynchronous writer gate.
3. BEGIN establishes a new local write-session epoch and selects staging.
4. WRITE appends ordered endorsement bytes to staging.
5. FINISH validates DER structure, metadata, and root-certificate digest.
6. The implementation durably writes a new record and its commit marker.
7. The new record is published as the active in-memory view.
8. The slot generation advances and derived caches become stale.
```

The reference managed backing uses separate active and staging durable records.
It writes the payload before committing the record metadata, and uses integrity
metadata plus a commit marker to identify complete records. At startup it
selects the newest valid record. This is an implementation of the required
semantics, not a wire-contract requirement; an integrator can use another
durable mechanism if it preserves the same behavior.

The resulting failure behavior is:

| Event | Visible result |
| --- | --- |
| Invalid DER or root digest | Update fails; prior active chain remains visible |
| Interrupted staging write | Prior active chain remains visible after recovery |
| Interrupted record publication | Recovery selects the newest valid committed record |
| Erase commit | The role becomes unprovisioned only after the erase record is committed |
| Newer BEGIN for the same key | The older local write session becomes stale and later operations fail |

`CertWriteSession` is local responder state, not a portable wire transaction
token. It binds a session epoch to a `CertificateKey`. SPDM retains the opaque
session internally while reassembling a streaming request. The planned MCI
interface deliberately exposes no host session token: a newer `BEGIN` wins and
supersedes a previous staged update.

## Synchronization and snapshots

The store deliberately uses per-key writer serialization plus generation
snapshots rather than a reader-writer lock.

Readers do not need to block a flash-backed write because staging does not
alter the active record. A reader copies the active backing state and its
generation before an asynchronous operation, performs bounded flash or
Caliptra reads, then confirms that the generation still matches. It returns a
result only if the check succeeds.

Writers serialize only with writers for the same `CertificateKey`. The
reference implementation uses an asynchronous per-key gate. A writer may hold
that gate while awaiting durable I/O, but it never retains a mutable
`CertSlot` reference across an `await`, and readers do not acquire the gate.
Writes to different algorithms or roles proceed independently.

`provisioning_state_version` is the volatile generation counter for one
certificate key. It is not certificate content, a persistent record
generation, a BankID, or a protocol-visible version. It advances when a
committed endorsement state becomes visible or is erased. It does not advance
while bytes are merely staged.

A cache or signed-object operation uses this rule:

```text
capture (CertificateKey, provisioning_state_version)
perform asynchronous reads, hashing, or signing
accept result only if the key is still provisioned and generation is unchanged
```

This prevents a caller from receiving a root hash, chain length, digest, or
signature assembled from two committed generations.

The current P-384 `TaskCertStore` cache is indexed by SPDM slot because the
current SPDM adapter supports only P-384. Before ML-DSA-87 is enabled, all
adapter caches and snapshot identities must be keyed by algorithm and role as
well as generation.

For focused implementation detail, see
[Certificate Store Synchronization](./cert_store_synchronization.md).

## Certificate metadata and hash agility

The common service must retain the root-certificate digest and the metadata
needed to validate a managed endorsement. The digest is a property of the
selected hash algorithm, not of the storage backend.

The current implementation stores a fixed 48-byte SHA-384 root hash in
read-only and managed records. That is sufficient for the present P-384 /
SHA-384 SPDM path, but it is not a complete multi-algorithm metadata model.
SPDM defines the certificate-chain `RootHash` size as the output size of the
hash selected during algorithm negotiation. A future selected hash can have a
different size, such as 64 bytes for SHA-512.

Before enabling ML-DSA-87 end to end, the common service must introduce
hash-agile certificate metadata:

- carry the hash algorithm and exact digest length with the root digest;
- preserve exact-length digest comparison rather than padding a shorter digest;
- make chain-header construction use the selected hash size;
- key derived digest caches by both asymmetric and hash algorithms where
  required; and
- evolve the durable managed-record format compatibly, while continuing to
  recover existing P-384 records.

The MCI certificate contract currently documents the available P-384 bank with
a 48-byte SHA-384 root hash. Its Bank 1 behavior remains unavailable until the
hash-agile ML-DSA-87 service is complete; the Bank 1 response metadata must be
finalized consistently with the selected SPDM hash profile before that bank is
enabled.

## Algorithm and platform configuration

Algorithm-and-role keying prevents accidental P-384/ML-DSA or
Vendor/Owner/Tenant aliasing in memory, sessions, locks, and managed-record
identity. It does not allocate storage automatically.

Every configured managed key needs independent durable capacity for its active
and staging state. Platform configuration must therefore:

1. assign non-overlapping backing regions to each enabled
   `(algorithm, role)` key;
2. size each region for that algorithm's maximum mutable endorsement chain and
   metadata;
3. configure the same key identity during boot recovery; and
4. test interrupted updates and reboot recovery for every enabled key.

The current emulator configuration provisions P-384 managed Owner and Tenant
slots only under its test feature. It has no ML-DSA-87 managed backing
configuration yet. How a production integrator supplies those regions is
intentionally outside the transport contract.

## SPDM integration

SPDM is an adapter over the certificate service, not the definition of the
common store.

For the current P-384 path, the adapter:

- maps SPDM SlotIDs 0, 2, and 3 to Vendor, Owner, and Tenant;
- composes a complete chain from the endorsement and generated DPE/leaf
  portions;
- forms the SPDM certificate-chain header;
- calculates `GET_DIGESTS` over that header and the composed DER chain;
- checks slot generations across asynchronous composition and signing; and
- accepts `SET_CERTIFICATE` only for configured managed roles.

SPDM 1.4 ML-DSA-87 support requires work above and beside the storage core:

1. codec and stack support for SPDM 1.4 PQC algorithm negotiation and selected
   hash handling;
2. bank-aware SPDM slot operations that resolve the selected bank to an
   algorithm before querying support, provisioning, capacity, or caches;
3. an algorithm-aware PAL and cache model;
4. ML-DSA-87 device/DPE chain generation, leaf-certificate retrieval, and
   signing; and
5. hash-agile managed metadata, validation, and durable recovery.

The common-store keying is the foundation for this work, but it does not by
itself make an ML-DSA-87 SPDM certificate chain available.

## MCI integration

The MCI contract uses `MC_GET_CERT_CHAIN` and `MC_SET_CERT_CHAIN`; see
[External Mailbox Commands](./external_mailbox_cmds.md) for the wire format and
authorization requirements.

When implemented, the MCI adapter will:

1. validate BankID and `asym_algo` as a consistent algorithm selection;
2. map MCI SlotID to `CertificateRole`;
3. call the common certificate-chain service with the resulting
   `CertificateKey`;
4. return only a committed complete chain for reads; and
5. apply its fresh authorization requirement to every mutable operation.

MCI does not expose a flash partition, a backing record, a storage ID, a
generation, or any other integrator-selected storage detail. It also must not
implement a parallel certificate store. Bank 0 P-384 can be enabled only when
it uses the same service as SPDM; Bank 1 remains unavailable until the complete
ML-DSA-87 service exists. Tenant is deliberately not supported by the initial
MCI implementation.

## Security and validation boundaries

The common store provides consistency and durability; it does not decide who
may provision a certificate. The layer above it must:

- authorize every mutable operation;
- bind an authorized requester to the permitted role and key pair;
- validate DER sequence structure and chain-specific requirements;
- calculate and validate the root-certificate digest using the selected hash;
- reject writes that exceed the configured key capacity; and
- map stale-generation results to the transport's retry/resynchronization
  behavior.

The store must reject a mismatched `CertificateAlgorithm`, role, session, or
metadata shape. It must not silently coerce algorithms, truncate a digest, or
fall back to a different key.

## Required invariants

1. One `CertificateKey` never reads, writes, locks, caches, or recovers data
   belonging to another key.
2. No transport-visible address is stored as a generic certificate identity.
3. A read returns data from exactly one committed generation.
4. Staged bytes and incomplete durable records are never visible as active.
5. A successful write or erase changes the active state and increments the
   corresponding volatile provisioning generation.
6. A stale local write session cannot publish or alter a newer staged update.
7. Persistent recovery accepts only records that match the configured local
   key, capacity, and integrity requirements.
8. Complete-chain composition never persists generated DPE or leaf
   certificates as if they were caller-provisioned endorsements.
9. The common API remains independent of SPDM and MCI types.
10. Enabling a new algorithm requires its metadata, backing configuration,
    cache identity, composer, signer, and transport negotiation to be complete.

## Delivery sequence

The following order keeps the shared service correct before additional
transports consume it:

1. Extract the common certificate-chain service boundary from the P-384 SPDM
   PAL.
2. Make root-digest metadata, chain headers, caches, validation, and durable
   records hash-agile while preserving P-384 recovery compatibility.
3. Configure and test isolated persistent backing for each enabled algorithm
   and role.
4. Add SPDM 1.4 bank-aware negotiation, ML-DSA-87 composition/signing, and
   `GET_CERTIFICATE` / `SET_CERTIFICATE` coverage.
5. Implement the already documented MCI certificate-chain adapter over the
   same service.
6. Add MCI transport, cross-transport concurrency/recovery, and MCI
   attestation integration tests.

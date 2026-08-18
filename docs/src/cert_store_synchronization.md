# Certificate Store Synchronization

This document records the concurrency rules for the transport-neutral
certificate store. The full architecture is in
[Caliptra MCU Certificate Store Design](./cert_store_design.md).

## Synchronization model

The synchronization unit is one:

```text
CertificateKey = (CertificateAlgorithm, CertificateRole)
```

The common store has a separate writer gate, write-session epoch, active
backing state, and provisioning generation for every key. P-384 Vendor,
P-384 Owner, ML-DSA-87 Vendor, and ML-DSA-87 Owner are therefore independent
even when they are served by the same process.

The design intentionally does not use a reader-writer lock:

- readers need not wait for a writer because a managed update stages a
  replacement without changing the active view;
- writers for the same key must serialize;
- readers validate a generation snapshot after asynchronous work; and
- writers for different keys can proceed independently.

The reference implementation uses an asynchronous per-key writer gate. A
writer can retain the gate while awaiting durable I/O, but no mutable slot
reference or critical section is retained across an `await`. Readers do not
take that gate.

## Generation snapshots

`provisioning_state_version` is an in-memory generation counter. It is not
certificate data, a durable-record generation, a BankID, or a
transport-visible field.

It changes only when a managed update or erase has committed and been
published. It does not change when a writer starts staging, writes a chunk, or
abandons an update.

The required read pattern is:

```text
1. Resolve CertificateKey.
2. Copy the active backing state and capture its generation.
3. Perform asynchronous flash, DPE, hashing, or signing work.
4. Confirm that the key is still provisioned and its generation is unchanged.
5. Return the result only when the confirmation succeeds.
```

If step 4 fails, the result is stale. A transport must retry or return its
resynchronization error rather than return a mixed result.

This check applies to complete-chain reads, chain-length calculation, root
digest calculation, `GET_DIGESTS`, signing, and derived-data cache fills.

## Managed write sessions

A managed update has an internal `CertWriteSession` with:

```text
scope = CertificateKey
epoch = monotonically advancing local session identity
```

`BEGIN` creates a new epoch and marks the slot as having a staging owner.
`WRITE`, `FINISH`, and `ABORT` must match both the key and epoch. A later
`BEGIN` for the same key supersedes an unfinished session, so operations from
the older session fail as stale.

The session is responder-local state. It is not a durable transaction ID and
is not exposed as an MCI mailbox token.

## Publication and recovery

The visible state is always one of:

- the prior committed record;
- a newly committed record; or
- no active record after a committed erase.

The reference managed backing stages bytes separately, validates them, writes
durable metadata and a final commit marker, then publishes the new in-memory
active view and advances `provisioning_state_version`.

Consequently:

| Race or failure | Required behavior |
| --- | --- |
| Reader overlaps staging | Reader continues from the prior active record |
| Reader overlaps publication | Generation check rejects a stale result |
| Two writers target one key | The writer gate serializes them; a newer begin supersedes the older session |
| Writer targets another key | It does not block the first key |
| Reset during staging | Recovery retains the newest valid prior record |
| Reset during publication | Recovery chooses the newest valid committed record |

`write_in_progress` identifies the current local staging owner. It does not
make a valid active record disappear from readers.

## Cache rule

Any derived value must be tagged with the generation that produced it. A cache
hit is valid only when the current key has the same generation:

```text
CacheEntry<T> {
    provisioning_state_version,
    value,
}
```

The current P-384 SPDM PAL uses slot-indexed task-local caches. That is safe
only while P-384 is the sole SPDM algorithm. Before ML-DSA-87 is enabled, cache
and snapshot identities must include the algorithm and role, not only the
SPDM SlotID.

## Invariants

1. A reader never returns staged bytes.
2. A reader never combines metadata or DER bytes from different committed
   generations.
3. A stale writer cannot change a newer staged update.
4. A failed or interrupted write leaves the prior committed data visible.
5. Every cache entry is invalid once its key's generation changes.
6. No synchronization state is shared between different certificate keys.

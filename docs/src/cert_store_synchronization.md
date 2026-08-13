# SPDM Certificate Store Synchronization Design

This note documents the synchronization model for the shared cert store used by the SPDM responder. The objective is to keep the backing cert-slot state consistent across multiple asynchronous consumers while allowing the cert store to live in a common shared location, without yet exposing it through the MCI mailbox API.

This design intentionally scopes the initial integration to the SPDM consumers that are already active today:

- MCTP-SPDM
- DOE-SPDM

The MCI mailbox interface is intentionally left out of the first phase. The cert store remains protocol-independent at the storage layer, while the SPDM PAL and stack remain the protocol-facing adapter layer.

## Goals

- Keep the cert-store backing state shared and consistent.
- Allow multiple SPDM tasks to read the same slot concurrently without returning mixed or stale results.
- Serialize managed-slot writes so a write cannot race with a read or a digest/signature operation.
- Preserve the invariant that a slot is never treated as valid while it is mid-update.
- Make stale results detectable via versioned snapshots instead of assuming a lock is sufficient.
- Keep the design compatible with cooperative-thread execution, where blocking locks across async awaits are undesirable.

## Scope and non-goals

### In scope

- Shared cert-slot metadata for managed slots
- Per-slot write gate and generation counter
- Versioned cache entries for chain length, leaf length, and digest
- Snapshot validation after async work
- Common shared backing state for MCTP and DOE

### Out of scope for now

- MCI mailbox commands that directly read or write cert slots
- Protocol-specific mailbox framing or SPDM header encoding
- New external management interfaces

## Architecture

The store has three layers:

1. Shared storage layer
   - owns the actual per-slot state
   - shared across SPDM consumers
   - stores slot metadata, backing endorsement state, and generation counters

2. Task-local cache layer
   - stores per-task derived values such as chain length, leaf length, and digest
   - caches are keyed by slot generation so stale values do not survive a slot mutation

3. SPDM adapter layer
   - calls into the shared store to compose cert-chain data
   - packages values into SPDM-specific messages
   - performs request resynchronization when a slot changed mid-operation

The cert store is therefore protocol-independent. The SPDM stack is responsible for SPDM framing, signing, and request restart handling.

## Slot state model

Each cert slot has the following state:

```text
CertSlot {
    endorsement: SlotEndorsement,
    key_pair_id: Option<u8>,
    cert_info: Option<u8>,
    write_in_progress: AtomicBool,
    provisioning_state_version: AtomicU32,
}
```

The important pieces are:

- `write_in_progress` serializes managed-slot mutation.
- `provisioning_state_version` acts as a generation counter for the slot.
- the version changes only after a successful managed-slot update or erase commit.

## Why generation/version is needed

The cert slot is not static. A managed slot can be updated by `SET_CERTIFICATE`, which may rewrite endorsement bytes, root hash metadata, or slot provisioning state. A read or signature operation may start before the update and finish after it. Without a generation check, the responder can mix:

- a new root hash with an old DER chain,
- a new leaf cert with old cached metadata,
- a newly signed object over a slot that changed in the middle of the operation.

The generation counter provides a way to detect that a slot changed while the operation was in flight.

## Snapshot-based synchronization

The synchronization pattern is:

1. Capture a snapshot before async work begins.
2. Perform asynchronous work such as hash computation, flash reads, DPE reads, or signing.
3. After the async work, validate the slot still matches the captured snapshot.
4. If the slot changed, reject the result instead of returning stale or mixed data.

Snapshot format:

```text
CertSlotSnapshot {
    slot: u8,
    provisioning_state_version: u32,
}
```

The validation rule is:

```text
slot is provisioned
AND slot.provisioning_state_version == snapshot.provisioning_state_version
```

If either check fails, the operation is treated as stale and must be restarted or returned as a resynchronization error.

This matches the SPDM responder requirement: a slot update during an in-flight operation must not silently produce a valid signed object over a mutated slot.

## Read/write flow

### Reader flow

1. Lookup the slot.
2. If the slot is not provisioned or `write_in_progress` is true, fail early.
3. Read `snapshot = slot.provisioning_state_version`.
4. Perform async cert-chain hash, cert read, or signing work.
5. After the await, confirm the slot is still provisioned and version still matches the snapshot.
6. If version changed, fail with stale-data / resync semantics.
7. Otherwise accept the result.

### Writer flow

1. Acquire exclusive ownership of the slot with atomic compare-and-swap on `write_in_progress`.
2. If another writer is active, fail or retry.
3. Update the managed flash backing and metadata.
4. Validate the final slot contents.
5. Commit new metadata.
6. Bump `provisioning_state_version`.
7. Clear `write_in_progress`.
8. Invalidate task-local cert caches for that slot.

The key rule is that a slot never becomes valid in the middle of a write. Readers must always see either:

- old valid state, or
- write-in-progress (temporarily invalid), or
- new valid state

Never a partially committed state.

## Cache model

Each task has a task-local cache for cert-derived values. The per-slot cache entry is tagged with the generation that produced it:

```text
CacheEntry<T> {
    provisioning_state_version: u32,
    value: T,
}
```

Examples:

- `chain_len`
- `leaf_len`
- `chain_digest`

The cache hit rule is:

- if the cached entry's generation matches the current slot generation, reuse it
- otherwise discard it and recompute

This prevents stale digest or length values from being reused after a managed-slot update.

## Why this design works in cooperative async tasks

This code runs in a cooperative-thread environment, not a fully preemptive multi-threaded OS. That is important because:

- blocking RW locks are not the ideal mechanism for async paths
- holds across `await` are dangerous and can lead to reentrancy or deadlock-like behavior
- the main requirement is not general-purpose locking; it is stale-state detection

A versioned slot model fits cooperative async well:

- writes are exclusive via atomic write gate
- reads validate generation after potentially long async work
- no long lock is held across awaits
- the design is simple to reason about and easy to document

## Race conditions and how they are handled

### Race 1: read starts, write completes before read finishes

- Reader captures version V
- Writer updates slot and bumps generation to V+1
- Reader resumes and sees slot.version != V
- Result is rejected

This is the primary stale-read protection.

### Race 2: two writers try to mutate the same slot

- Writer A sets `write_in_progress = true`
- Writer B attempts to acquire the same gate
- Writer B fails or retries

This prevents two managed-slot updates from interleaving.

### Race 3: stale cache reused after update

- Task-local cache was created under generation V
- Slot is updated to V+1
- Cache lookup sees mismatch and recomputes

This prevents old digest and length values from surviving across a re-provisioning event.

### Race 4: partial flash state is exposed as valid

- Writer must set `write_in_progress` before mutating flash
- The slot remains invalid until metadata commit completes
- Only after successful commit does generation bump and the slot become valid again

This avoids exposing a partially written or partially erased certificate chain as provisioned.

### Race 5: MCTP and DOE access the same slot concurrently

- Both tasks may read or write the same slot
- reads are version-checked after async work
- writes are serialized by the atomic write gate
- each SPDM consumer still sees a consistent slot state and either succeeds or resynchronizes

## Required invariants

The implementation must maintain the following invariants:

1. `write_in_progress == true` means the slot is temporarily invalid for readers.
2. A managed slot is only considered provisioned if the slot is not in write progress and the backing endorsement is valid.
3. `provisioning_state_version` must change exactly when the slot backing changes.
4. All task-local caches for a slot must be generation-tagged.
5. Any async operation that touches slot state must validate generation on exit.
6. A write or erase cannot expose a partially committed state as provisioned.

## Common-location plan

For the current phase, the cert store will live in the shared certificate-store layer that is common to the SPDM PAL implementations used by MCTP and DOE. The design remains:

- shared store owns slot backing state
- task-local store owns per-task derived caches
- SPDM PAL is the adapter for stack calls

The common cert-store layer is the right home for:

- `CertSlot`
- slot version counter
- write gate
- cache generation tagging
- snapshot helpers
- invalidation hooks

The SPDM stack still remains responsible for:

- cert-chain assembly
- SPDM request / response semantics
- `RequestResynch` handling
- signing over the final slot snapshot

This separation keeps the store independent of SPDM protocol semantics while making the synchronization logic common and reusable.

## Release-plan guidance

This synchronization model should be included before any broader commonization of the cert-store API. The immediate release-safe change is to centralize the slot state and synchronization primitives while preserving the existing SPDM behavior. MCI mailbox integration should remain deferred until after the release, so the protocol-facing behavior stays stable while the common cert slot model matures.

## Summary

The cert-store synchronization model is intentionally simple:

- one atomic write gate per managed slot
- one generation counter per slot
- one snapshot token captured before async work
- one validation after async work
- generation-tagged caches
- strong invalidation on writes and erases

This is the minimal model that prevents stale reads, mixed cert chains, and partially updated flash state without requiring a heavy blocking lock.

# Integrator's Guide

This guide provides recommendations for platform integrators building on
Caliptra MCU.

## DOT Fuse Recommendations

### DOT fuse array sizing

The `dot_fuse_array` field in the vendor non-secret OTP partition tracks Device
Ownership Transfer (DOT) state transitions. Each state change (lock, unlock,
disable) burns one bit, using a `OneHot` encoding. The total number of bits
determines the maximum number of ownership state transitions over the lifetime
of the part.

A full ownership transfer cycle (install → lock → unlock) consumes **2 fuse
bits**: one for the lock transition (EVEN → ODD) and one for the unlock
transition (ODD → EVEN). Therefore:

| Logical fuse bits | Lock/unlock cycles | Notes |
|:---------:|:------------------:|-------|
| 64        | 32                 | Recommended minimum. |
| 256       | 128                | Default in the reference `hw/fuses.hjson`. |

The right size depends on how many ownership transfers the part is expected to
undergo in its lifetime. There is no way to reclaim burned fuse bits — once the
array is exhausted, mutable locking DOT transitions are no longer possible and
the device can only operate in Volatile DOT mode (ownership lost on power
cycle).

### Vendor recovery PK hash

The `vendor_recovery_pk_hash` fuse stores the SHA-384 hash of the vendor recovery
public key (VendorKey) used for `DOT_OVERRIDE` — a catastrophic recovery
command that force-unlocks the DOT state when no backup DOT blob is available
(e.g., RMA scenarios). This fuse is **optional**: if your deployment does not
require vendor-level catastrophic recovery, it can be left unprovisioned.

If provisioned, the hash is stored in the `VENDOR_SECRET_PROD_PARTITION` and
occupies **48 bytes** (384 bits). Because it is write-once and ECC-protected,
no redundant encoding is needed.

### Fuse storage cost summary

| Fuse field | Partition | Size | Encoding | Notes |
|---|---|:---:|---|---|
| `dot_initialized` | `VENDOR_NON_SECRET_PROD_PARTITION` | 1 bit (3 bytes with 3× majority vote) | `LinearMajorityVote` | Gates the DOT flow. |
| `dot_fuse_array` | `VENDOR_NON_SECRET_PROD_PARTITION` | 256 bits (32 bytes) | `OneHot` | State counter. Scales linearly with desired lock/unlock cycles. |
| `vendor_recovery_pk_hash` | `VENDOR_SECRET_PROD_PARTITION` | 384 bits (48 bytes) | `Single` | Optional. For `DOT_OVERRIDE` catastrophic recovery. |

If OTP space is constrained, the `dot_fuse_array` can be made smaller — the
minimum useful size is 2 bits, but this only allows a single lock/unlock cycle
with no margin. If redundant encoding (`OneHotLinearMajorityVote`) is used,
multiply the raw bit count by the duplication factor (e.g., 3×).

A different partition can also be used if there is one specifically allocated in
the integration-specific fuse map.

## Owner Public Key Hash Provisioning

- If you are using DOT for ownership management, provisioning
  `CPTRA_SS_OWNER_PK_HASH` is optional. See the
  [cold boot flow](./rom.md#cold-boot-flow) for details on how the ROM
  determines the owner PK hash.
- If you are **not** using DOT, then `CPTRA_SS_OWNER_PK_HASH` is the sole
  source of the owner PK hash and must be provisioned or another integrator-
  specific mechanism must be used.

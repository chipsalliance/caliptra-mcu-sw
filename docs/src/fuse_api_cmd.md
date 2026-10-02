The identifiers in this section are MCU Runtime `AuthorizedCommand` target
IDs, not top-level Runtime mailbox command-register values. Runtime requests
use:

```text
MBOX_CMD = 0x00000012
SRAM = checksum || target_id(LE) || operation_payload
       || nonce[48] || ecc_pub_x[48] || ecc_pub_y[48]
       || mldsa_pub[2592] || HybridSignature
```

The request tables below describe `operation_payload`; the common checksum,
target ID, and authorization trailer are shown once above.

MCU ROM has a separate boot-time direct fuse API for `IFPR`, `IFPW`, and
`IFPK`. ROM places that identifier directly in the mailbox command register
and uses `checksum || operation_payload` without the Runtime target field or
authorization trailer.

### MC_FUSE_READ

Reads fuse values.

Runtime target ID / ROM direct command code: `0x4946_5052` ("IFPR")

*Table: `MC_FUSE_READ` operation payload*
| **Name**   | **Type**       | **Description**               |
| ---------- | -------------- | ----------------------------- |
| partition  |  u32           | Partition number to read from |
| entry      |  u32           | Entry to read                 |

*Table: `MC_FUSE_READ` output arguments*
| **Name**      | **Type**       | **Description**                         |
| ------------- | -------------- | --------------------------------------- |
| chksum        |  u32           |                                         |
| fips_status   |  u32           | FIPS approved or an error               |
| length (bits) |  u32           | Number of bits that are valid           |
| data          |  u8[...]       | Fuse data (length/8)                    |

### MC_FUSE_WRITE

Write fuse values.

Runtime target ID / ROM direct command code: `0x4946_5057` ("IFPW")

*Table: `MC_FUSE_WRITE` operation payload*
| **Name**   | **Type**       | **Description**                       |
| ---------- | -------------- | ------------------------------------- |
| word_addr  |  u32           | Entry to write (word offset)          |
| data       |  u32           | Word to write                         |
| mask       |  u32           | Bit-Mask to only write specified bits |


*Table: `MC_FUSE_WRITE` output arguments*
| **Name**      | **Type**       | **Description**                         |
| ------------- | -------------- | --------------------------------------- |
| chksum        |  u32           |                                         |
| fips_status   |  u32           | FIPS approved or an error               |


Caveats:
* This command is **idempotent**, so that identical writes will have no effect.
* Will fail if any of the existing data is 1 but is set to 0 in the input data.
* Bits cleared in `mask` are ignored
* Writes to buffered partitions will not take effect until the next reset.

### MC_FUSE_LOCK_PARTITION

Lock a partition.

Runtime target ID / ROM direct command code: `0x4946_504B` ("IFPK")

*Table: `MC_FUSE_LOCK_PARTITION` operation payload*
| **Name**   | **Type**       | **Description**               |
| ---------- | -------------- | ----------------------------- |
| partition  |  u32           | Partition number to lock      |


*Table: `MC_FUSE_LOCK_PARTITION` output arguments*
| **Name**      | **Type**       | **Description**                         |
| ------------- | -------------- | --------------------------------------- |
| chksum        |  u32           |                                         |
| fips_status   |  u32           | FIPS approved or an error               |

Caveats:
* This command is **idempotent**, so that locking a partition twice has no effect.
* Locking a partition causes subsequent writes to it to fail.
* Locking does not fully take effect until the next reset.

### MC_PROVISION_VENDOR_PK_HASH

Provision a new vendor PK hash.

Runtime authorized target ID: `0x5056_504b` ("PVPK")

*Table: `MC_PROVISION_VENDOR_PK_HASH` operation payload*
| **Name**   | **Type**       | **Description**                |
| ---------- | -------------- | ------------------------------ |
| slot       |  u32           | The vendor PK hash slot to use |
| hash       |  \[u8; 48\]    | New vendor PK hash             |


*Table: `MC_PROVISION_VENDOR_PK_HASH` output arguments*
| **Name**      | **Type**       | **Description**                         |
| ------------- | -------------- | --------------------------------------- |
| chksum        |  u32           |                                         |
| fips_status   |  u32           | FIPS approved or an error               |

Caveats:
* Fails if the slot already contains data

### MC_PROVISION_OWNER_PK_HASH

Provision `CPTRA_SS_OWNER_PK_HASH` using its 48-byte dword-reversed OTP
representation.

Runtime authorized target ID: `0x504F_504B` ("POPK")

*Table: `MC_PROVISION_OWNER_PK_HASH` operation payload*
| **Name** | **Type**    | **Description**              |
| -------- | ----------- | ---------------------------- |
| hash     | \[u8; 48\] | New owner public-key hash    |

*Table: `MC_PROVISION_OWNER_PK_HASH` output arguments*
| **Name**    | **Type** | **Description**           |
| ----------- | -------- | ------------------------- |
| chksum      | u32      |                           |
| fips_status | u32      | FIPS approved or an error |

Caveats:
* The all-zero hash is rejected.
* Reprovisioning the identical hash is idempotent.
* Provisioning a different hash after any owner-hash data has been burned is rejected.
* After verifying the hash, the command burns and verifies bit 0 of `CPTRA_SS_OWNER_PK_HASH_VALID` for use as a commit marker by ROM versions that enforce it.
* Current MCU ROM does not check `CPTRA_SS_OWNER_PK_HASH_VALID` before consuming the hash. Provisioning must not be interrupted by reset or power loss; an interruption can cause ROM to consume a partial hash and prevent retrying the intended hash.
* The newly provisioned owner hash is consumed by MCU ROM on the next reset.

### MC_FUSE_REVOKE_VENDOR_PUB_KEY

Revoke one vendor firmware verification key within a vendor PK hash slot.

Runtime authorized target ID: `0x4D52_564B` ("MRVK")

*Table: `MC_FUSE_REVOKE_VENDOR_PUB_KEY` operation payload*
| **Name**             | **Type**       | **Description**                                      |
| -------------------- | -------------- | ---------------------------------------------------- |
| reserved             |  u32           | Reserved; must be zero                               |
| vendor_pk_hash_slot  |  u32           | Vendor PK hash slot containing the key to revoke     |
| key_type             |  u32           | `0` = ECDSA P-384, `1` = LMS, `2` = MLDSA-87         |
| key_index            |  u32           | Key index within the selected key type's revocation field |

*Table: `MC_FUSE_REVOKE_VENDOR_PUB_KEY` output arguments*
| **Name**      | **Type**       | **Description**                         |
| ------------- | -------------- | --------------------------------------- |
| chksum        |  u32           |                                         |
| fips_status   |  u32           | FIPS approved or an error               |

Caveats:
* This command must be authorized.
* The selected PK hash slot must be provisioned and valid.
* The command fails if it targets the key used to boot the currently running
  firmware.
* The last key index for a key type cannot be revoked.

### MC_FUSE_REVOKE_VENDOR_PK_HASH

Revoke a vendor PK hash.
Marks a vendor PK hash as invalid, revoking all of the associated keys.

Runtime authorized target ID: `0x5256_4b48` ("RVKH")

*Table: `MC_FUSE_REVOKE_VENDOR_PK_HASH` operation payload*
| **Name**             | **Type**       | **Description**               |
| -------------------- | -------------- | ----------------------------- |
| reserved             |  u32           | Reserved; must be zero        |
| vendor_pk_hash_slot  |  u32           | Vendor PK hash slot to revoke |


*Table: `MC_FUSE_REVOKE_VENDOR_PK_HASH` output arguments*
| **Name**      | **Type**       | **Description**                         |
| ------------- | -------------- | --------------------------------------- |
| chksum        |  u32           |                                         |
| fips_status   |  u32           | FIPS approved or an error               |

Caveats:
* This command must be authorized.
* This command is **idempotent**, so that revoking a slot twice has no effect.
* Trying to revoke an empty slot will result in an error
* Trying to revoke the PK hash slot used to boot the currently running firmware
  will result in an error

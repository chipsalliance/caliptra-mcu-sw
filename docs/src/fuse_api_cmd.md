### MC_FUSE_READ

Reads fuse values.

Command Code: `0x4946_5052` ("IFPR")

*Table: `MC_FUSE_READ` input arguments*
| **Name**   | **Type**       | **Description**               |
| ---------- | -------------- | ----------------------------- |
| chksum     |  u32           |                               |
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

Command Code: `0x4946_5057` ("IFPW")

*Table: `MC_FUSE_WRITE` input arguments*
<<<<<<< HEAD
| **Name**   | **Type**       | **Description**               |
| ---------- | -------------- | ----------------------------- |
| chksum     |  u32           |                               |
| partition  |  u32           | Partition number to write to  |
| entry      |  u32           | Entry to write                |
| start bit  |  u32           | Starting bit to write to (least significant bit in entry is 0). |
| length     | u32            | in bits                       |
| data       | u8[...]        | length/8
=======
| **Name**   | **Type**       | **Description**                       |
| ---------- | -------------- | ------------------------------------- |
| chksum     |  u32           |                                       |
| word_addr  |  u32           | Entry to write (word offset)          |
| data       |  u32           | Word to write                         |
| mask       |  u32           | Bit-Mask to only write specified bits |

>>>>>>> 56fcd2fa ([mcu-mbox] fuse read write lock commands (#1380))


*Table: `MC_FUSE_WRITE` output arguments*
| **Name**      | **Type**       | **Description**                         |
| ------------- | -------------- | --------------------------------------- |
| chksum        |  u32           |                                         |
| fips_status   |  u32           | FIPS approved or an error               |


Caveats:
* This command is **idempotent**, so that identical writes will have no effect.
* Will fail if any of the existing data is 1 but is set to 0 in the input data.
* Bits masked with `mask` will be ignored
* Writes to buffered partitions will not take effect until the next reset.

### MC_FUSE_LOCK_PARTITION

Lock a partition.

Command Code: `0x4946_504B` ("IFPK")

*Table: `MC_FUSE_LOCK_PARTITION` input arguments*
| **Name**   | **Type**       | **Description**               |
| ---------- | -------------- | ----------------------------- |
| chksum     |  u32           |                               |
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

Command Code: `0x5056_504b` ("PVPK")

*Table: `MC_PROVISION_VENDOR_PK_HASH` input arguments*
| **Name**   | **Type**       | **Description**                |
| ---------- | -------------- | ------------------------------ |
| chksum     |  u32           |                                |
| slot       |  u32           | The vendor PK hash slot to use |
| hash       |  \[u8; 48\]    | New vendor PK hash             |


*Table: `MC_PROVISION_VENDOR_PK_HASH` output arguments*
| **Name**      | **Type**       | **Description**                         |
| ------------- | -------------- | --------------------------------------- |
| chksum        |  u32           |                                         |
| fips_status   |  u32           | FIPS approved or an error               |

Caveats:
* Fails if the slot already contains data

### MC_FUSE_REVOKE_VENDOR_PUB_KEY

Revoke one vendor firmware verification key within a vendor PK hash slot.

Command Code: `0x4D52_564B` ("MRVK")

*Table: `MC_FUSE_REVOKE_VENDOR_PUB_KEY` input arguments*
| **Name**             | **Type**       | **Description**                                      |
| -------------------- | -------------- | ---------------------------------------------------- |
| chksum               |  u32           |                                                      |
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

Command Code: `0x5256_4b48` ("RVKH")

*Table: `MC_FUSE_REVOKE_VENDOR_PK_HASH` input arguments*
| **Name**             | **Type**       | **Description**               |
| -------------------- | -------------- | ----------------------------- |
| chksum               |  u32           |                               |
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

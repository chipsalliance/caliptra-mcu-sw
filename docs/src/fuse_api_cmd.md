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

Start bit is counting from the least significant bit.

Command Code: `0x4946_5057` ("IFPW")

*Table: `MC_FUSE_WRITE` input arguments*
| **Name**   | **Type**       | **Description**               |
| ---------- | -------------- | ----------------------------- |
| chksum     |  u32           |                               |
| partition  |  u32           | Partition number to write to  |
| entry      |  u32           | Entry to write                |
| start bit  |  u32           | Starting bit to write to (least significant bit in entry is 0). |
| length     | u32            | in bits                       |
| data       | u8[...]        | length/8


*Table: `MC_FUSE_WRITE` output arguments*
| **Name**      | **Type**       | **Description**                         |
| ------------- | -------------- | --------------------------------------- |
| chksum        |  u32           |                                         |
| fips_status   |  u32           | FIPS approved or an error               |


Caveats:
* This command is **idempotent**, so that identical writes will have no effect.
* Will fail if any of the existing data is 1 but is set to 0 in the input data. Existing data that is 0 but set to 1 will be burned to a 1.
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
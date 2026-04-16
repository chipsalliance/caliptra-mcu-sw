# ROM Fuses

## Fuse Field Reference

Every OTP field read or written by the reference MCU ROM, with the target register and the net
transformation from raw OTP bytes to written value. ✓ = Caliptra core fuse register or strap.

- **`CPTRA_CORE_VENDOR_PK_HASH`** (selected slot) ✓ → `FUSE_VENDOR_PK_HASH[0..11]`
  Each 4-byte group is byte-reversed in OTP from the standard SHA-384 format.
  _Example: SHA-384 `b17ca877666657ccd100e6926c7206b60c995cb68992c6c9baefce728af05441dee1ff415adfc187e1e4edb4d3b2d909`
  → OTP bytes `77 a8 7c b1 cc 57 66 66 …` → `FUSE_VENDOR_PK_HASH[0] = 0xb17ca877`_

- **`CPTRA_CORE_PQC_KEY_TYPE`** (selected slot) ✓ → `FUSE_PQC_KEY_TYPE`
  `OneHotLinearOr{bits:2, dupe:3}` decoded to logical value, then mapped to a Caliptra
  constant: MLDSA → 1, LMS → 3.
  _Example: LMS → OTP bytes `3f 00 00 00` → `FUSE_PQC_KEY_TYPE = 3`_

- **`CPTRA_CORE_FMC_KEY_MANIFEST_SVN`** ✓ → `FUSE_FMC_KEY_MANIFEST_SVN`: raw u32

- **`CPTRA_CORE_RUNTIME_SVN`** ✓ → `FUSE_RUNTIME_SVN[0..3]`: raw u32 × 4

- **`CPTRA_CORE_SOC_MANIFEST_SVN`** ✓ → `FUSE_SOC_MANIFEST_SVN[0..3]`: raw u32 × 4

- **`CPTRA_CORE_SOC_MANIFEST_MAX_SVN`** ✓ → `FUSE_SOC_MANIFEST_MAX_SVN`: raw u32

- **`CPTRA_CORE_ECC_REVOCATION`** (selected slot) ✓ → `FUSE_ECC_REVOCATION`:
  `LinearOr{bits:4, dupe:3}` → decoded u4

- **`CPTRA_CORE_LMS_REVOCATION`** (selected slot) ✓ → `FUSE_LMS_REVOCATION`:
  `LinearOr{bits:16, dupe:2}` → decoded u16

- **`CPTRA_CORE_MLDSA_REVOCATION`** (selected slot) ✓ → `FUSE_MLDSA_REVOCATION`:
  `LinearOr{bits:4, dupe:3}` → decoded u4

- **`CPTRA_CORE_SOC_STEPPING_ID`** ✓ → `FUSE_SOC_STEPPING_ID`: raw u32, bits\[15:0\] only

- **`CPTRA_CORE_ANTI_ROLLBACK_DISABLE`** ✓ → `FUSE_ANTI_ROLLBACK_DISABLE`: raw u32

- **`CPTRA_CORE_IDEVID_CERT_IDEVID_ATTR`** ✓ → `FUSE_IDEVID_CERT_ATTR[0..23]`: raw u32 × 24

- **`CPTRA_CORE_IDEVID_MANUF_HSM_IDENTIFIER`** ✓ → `FUSE_IDEVID_MANUF_HSM_ID[0..3]`: raw u32 × 4

- **`CPTRA_SS_MANUF_DEBUG_UNLOCK_TOKEN`** ✓ → `FUSE_MANUF_DBG_UNLOCK_TOKEN[0..15]`: raw u32 × 16 (512 bits)

- **`CPTRA_SS_OWNER_PK_HASH`** ✓ → `CPTRA_OWNER_PK_HASH[0..11]`
  Raw bytes `transmute`d to `[u32; 12]` (LE); same LE-dword format as vendor PK hash.

- **`CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_{0..7}`** ✓ → `MCI_PROD_DEBUG_UNLOCK_PK_HASH_REG[0..95]`:
  raw u32 × 12 per hash (8 hashes)

- **`cptra_itrng_health_test_window_size`** ✓ → `SS_STRAP_GENERIC[2]` bits\[15:0\]. `Single{bits:16}` raw u16. Bit\[31\] of the same word is
  the bypass mode flag (from ROM parameters, not OTP).

- **`cptra_itrng_entropy_config_0`** ✓ →
  `CPTRA_I_TRNG_ENTROPY_CONFIG_0`: `Single{bits:32}` raw u32.

- **`cptra_itrng_entropy_config_1`** ✓ →
  `CPTRA_I_TRNG_ENTROPY_CONFIG_1`: `Single{bits:32}` raw u32.

- **`CPTRA_CORE_VENDOR_PK_HASH_VALID`** (all slots) — slot selection only, not written to any
  register. `LinearOr{bits:16, dupe:3}` → decoded u16 bitmask.

- **`dot_initialized`** — MCU
  internal use only, not written to any register. `LinearOr{bits:1, dupe:3}` → logical
  0 or 1, used as the DOT flow gate.

- **`dot_fuse_array`** — MCU internal
  use only, not written to any register. `OneHot{bits:256}` → count of burned bits, used to track
  the DOT state counter. Also written (next bit burned) during DOT state transitions.

- **`perma_hek_en`** (2.1+) — MCU internal use only, not written to any register.
  `LinearOr{bits:1, dupe:3}` → logical 0 or 1, indicates whether the
  HEK is permanently set. Used by OCP LOCK logic to determine HEK slot state.

- **`CPTRA_SS_LOCK_HEK_PROD_{0..7}`** ✓ → `FUSE_HEK_SEED[0..7]` (2.1+): 8 OTP
  partitions. Contains HEK seeds for OCP LOCK. The
  active slot's seed is written to `FUSE_HEK_SEED[0..7]` (raw u32 × 8)
  by the OCP LOCK fuse logic. Inactive exhausted/sanitized slots write
  all-zeros or all-ones to the register. The active slot is determined by the
  OCP LOCK `RomConfig` platform logic.

- **`ss_key_release_base_addr_l`**, **`ss_key_release_base_addr_h`**,
  **`ss_key_release_size`** ✓ (2.1+) — OCP LOCK key release configuration. Set from
  `RomConfig` parameters (not from OTP). `ss_key_release_size` is the MEK size;
  `ss_key_release_base_addr_l/h` is the 64-bit key release base address.

### OTP Encoding Recommendations

OTP ECC protects against read and write errors, but **must not** be used on
monotonically-increasing fields (SVNs, the DOT state counter) or revocation
bitmasks, as ECC integrity checks will most likely fail after two bits are
burned. For those fields, either HW or SW redundant encoding provides
fault tolerance without causing ECC integrity issues.

| OTP field | ECC | Recommended layout |
|---|:---:|---|
| `CPTRA_CORE_VENDOR_PK_HASH_{0..N}` | ✅ | `Single{bits:384}` |
| `CPTRA_CORE_PQC_KEY_TYPE_{0..N}` | ✅ | `OneHotLinearOr{bits:2, dupe:3}` |
| `CPTRA_CORE_FMC_KEY_MANIFEST_SVN` | ❌ | `LinearOr{bits:32, dupe:3}` |
| `CPTRA_CORE_RUNTIME_SVN` | ❌ | `LinearOr{bits:128, dupe:3}` |
| `CPTRA_CORE_SOC_MANIFEST_SVN` | ❌ | `LinearOr{bits:128, dupe:3}` |
| `CPTRA_CORE_SOC_MANIFEST_MAX_SVN` | ❌ | `LinearOr{bits:32, dupe:3}` |
| `CPTRA_CORE_ECC_REVOCATION_{0..N}` | ❌ | `LinearOr{bits:4, dupe:3}` |
| `CPTRA_CORE_LMS_REVOCATION_{0..N}` | ❌ | `LinearOr{bits:16, dupe:2}` |
| `CPTRA_CORE_MLDSA_REVOCATION_{0..N}` | ❌ | `LinearOr{bits:4, dupe:3}` |
| `CPTRA_CORE_VENDOR_PK_HASH_VALID` | ❌ | `LinearOr{bits:16, dupe:3}` |
| `CPTRA_CORE_SOC_STEPPING_ID` | ✅ | `Single{bits:16}` |
| `CPTRA_CORE_ANTI_ROLLBACK_DISABLE` | ✅ | `Single{bits:1}` |
| `CPTRA_CORE_IDEVID_CERT_IDEVID_ATTR` | ✅ | `Single{bits:768}` |
| `CPTRA_CORE_IDEVID_MANUF_HSM_IDENTIFIER` | ✅ | `Single{bits:128}` |
| `CPTRA_SS_MANUF_DEBUG_UNLOCK_TOKEN` | ✅ | `Single{bits:512}` |
| `CPTRA_SS_OWNER_PK_HASH` | ✅ | `Single{bits:384}` |
| `CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_{0..7}` | ✅ | `Single{bits:384}` each |
| `dot_initialized` | ✅ | `Single{bits:1}` or if no ECC, `LinearOr{bits:1, dupe:3}` |
| `dot_fuse_array` | ❌ | `OneHot{bits:256}` or `OneHotLinearOr{bits:256, dupe: 3}` |
| `cptra_itrng_health_test_window_size` | ✅ | `Single{bits:16}` |
| `cptra_itrng_entropy_config_0` | ✅ | `Single{bits:32}` |
| `cptra_itrng_entropy_config_1` | ✅ | `Single{bits:32}` |
| `perma_hek_en` (2.1 only) | ✅ | `Single{bits:1}` or if no ECC, `LinearOr{bits:1, dupe:3}` |
| `CPTRA_SS_LOCK_HEK_PROD_{0..7}` (2.1 only) | ✅ | `Single{bits:384}` each |

TODO: there are only 32 LMS revocation bits specificed in the reference fuse map, but with redundant encoding, we would get 16 or fewer bits, unless  they are backed with HW redundancy.



## Vendor PK Hash Fuse Encoding Example

This section walks through how a vendor public key hash (48 bytes / 384 bits) is represented at
each layer of the system: from raw bytes in OTP physical memory, through the 16-bit backdoor
vmem interface, the OTP Direct Access Interface (DAI), MCU ROM, and finally the Caliptra fuse
register.

Note that the exact OTP offsets (0x3f8 and 0x428) may differ between integrators and Caliptra versions. The examples below are for the reference fuse map for Caliptra Subsystem 2.0.

### Overview

The OTP reference implementation has a physical memory with 16-bit data bus (plus optional 6 bits ECC). The vendor hash partitions
(`VENDOR_HASHES_MANUF_PARTITION` and `VENDOR_HASHES_PROD_PARTITION`) use 32-bit DAI access
granularity, so MCU ROM reads one 32-bit word at a time.

The vendor PK hash is stored in OTP in **reversed-dword format**: the 48 bytes are stored as
12 little-endian 32-bit words, meaning each 4-byte group has its bytes reversed relative to the
standard big-endian SHA-384 output.

### Example: CPTRA_CORE_VENDOR_PK_HASH_0

For this example, the vendor PK hash in standard (FIPS SHA-384) byte order is:
`b17ca877666657ccd100e6926c7206b60c995cb68992c6c9baefce728af05441dee1ff415adfc187e1e4edb4d3b2d909`.

#### Layer 1: OTP Raw Bytes

MCU expects these to be stored in OTP with each dword **byte-reversed**, e.g.,
the bytes in memory should be:

```
77 a8 7c b1 cc 57 66 66 92 e6 00 d1 b6 06 72 6c
b6 5c 99 0c c9 c6 92 89 72 ce ef ba 41 54 f0 8a
41 ff e1 de 87 c1 df 5a b4 ed e4 e1 09 d9 b2 d3
```

(This is because they are essentially passed through to Caliptra core's fuse
registers as-is, without any byte swapping, and this is the byte order Caliptra
ROM expects them to be in.)

This is often represented in `vmem` format.
For the reference MCU implementation (using the backdoor OTP memory or the `prim_generic_otp`), the `.vmem` file addresses each 16-bit OTP word at `@addr` where `byte_offset = addr × 2`.
Each 16-bit word stores its low byte at the lower byte address (little-endian). Each vmem entry is
6 hex digits, with the 16-bit data in bits \[15:0\] and ECC in bits \[21:16\].

Two consecutive vmem entries cover each 4-byte u32 group. For example, `@0001fc` data
`a877` holds the bytes `[0x77, 0xa8]` at OTP offsets `0x3F8`–`0x3F9`, and `@0001fd` data
`b17c` holds `[0x7c, 0xb1]` at `0x3FA`–`0x3FB` — exactly matching the the first dword above, with an additional 6 bits of ECC:

```
@0001fc 1fa877
@0001fd 10b17c
@0001fe 2c57cc
@0001ff 246666
@000200 33e692
@000201 1ed100
@000202 0d06b6
@000203 146c72
@000204 345cb6
@000205 3f0c99
@000206 03c6c9
@000207 098992
@000208 1cce72
@000209 21baef
@00020a 015441
@00020b 0e8af0
@00020c 35ff41
@00020d 2ddee1
@00020e 20c187
@00020f 105adf
@000210 28edb4
@000211 14e1e4
@000212 0bd909
```

#### Layer 2: OTP DAI Read

MCU ROM calls `otp.read_word(word_addr)`, which writes `direct_access_address = word_addr × 4`
and reads `dai_rdata_0`. The DAI assembles two consecutive 16-bit OTP words into a 32-bit result:
the first 16-bit word occupies bits \[15:0\] and the second occupies bits \[31:16\].

| `word_addr` | DAI byte addr | Low 16-bit word | High 16-bit word | `dai_rdata_0` |
|:---:|:---:|:---:|:---:|:---:|
| `0xFE` | `0x3F8` | `0xa877` | `0xb17c` | `0xb17ca877` |
| `0xFF` | `0x3FC` | `0x57cc` | `0x6666` | `0x666657cc` |
| `0x100` | `0x400` | `0xe692` | `0xd100` | `0xd100e692` |
| `0x101` | `0x404` | `0x06b6` | `0x6c72` | `0x6c7206b6` |
| `0x102` | `0x408` | `0x5cb6` | `0x0c99` | `0x0c995cb6` |
| `0x103` | `0x40C` | `0xc6c9` | `0x8992` | `0x8992c6c9` |
| `0x104` | `0x410` | `0xce72` | `0xbaef` | `0xbaefce72` |
| `0x105` | `0x414` | `0x5441` | `0x8af0` | `0x8af05441` |
| `0x106` | `0x418` | `0xff41` | `0xdee1` | `0xdee1ff41` |
| `0x107` | `0x41C` | `0xc187` | `0x5adf` | `0x5adfc187` |
| `0x108` | `0x420` | `0xedb4` | `0xe1e4` | `0xe1e4edb4` |
| `0x109` | `0x424` | `0xd909` | `0xd3b2` | `0xd3b2d909` |

MCU ROM `read_data` calls `word.to_le_bytes()` on each `dai_rdata_0` to unpack the u32 back
into 4 bytes, filling `hash_buf` in memory order — i.e. the same byte order as the OTP
physical memory (Layer 1):

```text
77 a8 7c b1  cc 57 66 66  92 e6 00 d1  b6 06 72 6c
b6 5c 99 0c  c9 c6 92 89  72 ce ef ba  41 54 f0 8a
41 ff e1 de  87 c1 df 5a  b4 ed e4 e1  09 d9 b2 d3
```

#### Layer 3: MCU ROM Writes to Caliptra

`populate_fuses` reassembles `hash_buf` back into u32 words via `u32::from_le_bytes` and
writes them to the Caliptra fuse registers:

```rust
// hash_buf after reading 48 bytes from OTP at 0x3F8 (OTP memory order):
// [0x77, 0xa8, 0x7c, 0xb1, 0xcc, 0x57, 0x66, 0x66, ...]
for (i, word_bytes) in hash_buf.chunks_exact(4).enumerate() {
    let word = u32::from_le_bytes(word_bytes.try_into().unwrap());
    // u32::from_le_bytes([0x77, 0xa8, 0x7c, 0xb1]) == 0xb17ca877
    self.registers.fuse_vendor_pk_hash[i].set(word);
}
```

The `to_le_bytes` → `from_le_bytes` round-trip is a no-op: the resulting Caliptra register
values are exactly the same u32 words returned by the DAI, representing the raw OTP memory byte-for-byte.

The resulting Caliptra `FUSE_VENDOR_PK_HASH` register values are written as:

| Register | Value |
|---|:---:|
| `FUSE_VENDOR_PK_HASH[0]` | `0xb17ca877` |
| `FUSE_VENDOR_PK_HASH[1]` | `0x666657cc` |
| `FUSE_VENDOR_PK_HASH[2]` | `0xd100e692` |
| `FUSE_VENDOR_PK_HASH[3]` | `0x6c7206b6` |
| `FUSE_VENDOR_PK_HASH[4]` | `0x0c995cb6` |
| `FUSE_VENDOR_PK_HASH[5]` | `0x8992c6c9` |
| `FUSE_VENDOR_PK_HASH[6]` | `0xbaefce72` |
| `FUSE_VENDOR_PK_HASH[7]` | `0x8af05441` |
| `FUSE_VENDOR_PK_HASH[8]` | `0xdee1ff41` |
| `FUSE_VENDOR_PK_HASH[9]` | `0x5adfc187` |
| `FUSE_VENDOR_PK_HASH[10]` | `0xe1e4edb4` |
| `FUSE_VENDOR_PK_HASH[11]` | `0xd3b2d909` |

These register values match what Caliptra ROM expects.
Note that Caliptra interprets each fuse register as a big-endian u32 word, so
writing `0xb17ca877` to `FUSE_VENDOR_PK_HASH[0]` corresponds to the leading 4
bytes `b1 7c a8 77` of the SHA-384 hash value (in standard format) of
`b17ca877666657ccd100e6926c7206b60c995cb68992c6c9baefce728af05441dee1ff415adfc187e1e4edb4d3b2d909`.

## Vendor PQC Key Type Fuse Encoding Example

This section traces the `vendor_pqc_key_type_0` field — a small encoded integer — through the
same layers: raw bytes in OTP physical memory, the 16-bit backdoor vmem interface, the OTP DAI,
MCU ROM decode, and the final Caliptra `FUSE_PQC_KEY_TYPE` register value.

| Property | Value |
|---|---|
| OTP item | `vendor_pqc_key_type_0` |
| Partition | `VENDOR_HASHES_MANUF_PARTITION` (partition 10) |
| OTP byte offset | `0x428` |
| Size | 4 bytes (only 6 bits are used) |
| Layout | `OneHotLinearOr { bits: 2, duplication: 3 }` |

Unlike the PK hash, this field uses the `OneHotLinearOr` layout for
fault tolerance. The `OneHotLinearOr { bits: 2, duplication: 3 }`
layout encodes a logical integer using two stages:

1. **OneHot**: the logical value `n` is encoded as `n` consecutive 1-bits: `onehot = (1 << n) - 1`
2. **LinearOr**: each bit of the OneHot value is replicated `duplication` (3) times in
   consecutive bit positions. The 2 logical bits × 3 replications = 6 physical bits, packed into
   the low 6 bits of the 4-byte field.

| Key type | Logical value | OneHot bits | OTP raw u32 | OTP bytes @ `0x428` |
|---|:---:|:---:|:---:|:---:|
| MLDSA | 1 | `0b01` | `0x00000007` | `07 00 00 00` |
| LMS | 2 | `0b11` | `0x0000003F` | `3f 00 00 00` |

In this example, we assume that MCU ROM is implementing this replication layout in software.
**An integrator may choose to have this replication implemented at a
lower level in the hardware's fuse macro layer**.
If that is the case, then the duplication and OR reduction in this example can be ignored.

### Example: CPTRA_CORE_PQC_KEY_TYPE_0 (LMS)

We trace `vendor_pqc_key_type_0` provisioned for LMS, i.e., the one-hot encoded value of 0b11 (logical value 2, one-hot encoded as 3), expected by Caliptra core ROM for LMS.

#### Layer 1: OTP Raw Bytes

The LMS logical value 2 encodes to raw u32 `0x0000003F`. The bytes in memory at `0x428` are:

```
3f 00 00 00
```

This is often represented in `vmem` format. The `.vmem` file addresses each
16-bit OTP word at `@addr` where `byte_offset = addr × 2`. Each vmem entry is 6
hex digits, with the 16-bit data in bits \[15:0\] and ECC in bits \[21:16\]:

```
@000214 24003f
@000215 000000
```

The data portion `0x003f` holds the raw byte `0x3F` in bits \[7:0\].

#### Layer 2: OTP DAI Read

MCU ROM calls `otp.read_word(word_addr)` with `word_addr = 0x428 / 4 = 0x10A`,
which sets `direct_access_address = 0x428` and reads `dai_rdata_0`:

| `word_addr` | DAI byte addr | `dai_rdata_0` |
|:---:|:---:|:---:|
| `0x10A` | `0x428` | `0x0000003F` |

#### Layer 3: MCU ROM Decode

`read_entry` applies `extract_single_fuse_value(OneHotLinearOr{bits:2, dupe:3}, 0x3F)`:

```
extract_or_u32(bits=2, dupe=3, raw=0x3F):
  bit 0: copies = (0x3F & 0x07) = 0x07, any set → bit 0 = 1
  bit 1: copies = (0x3F & 0x38) = 0x38, any set → bit 1 = 1
  OR result = 0b11

count_ones(0b11) = 2  →  2 ≠ 1  →  PqcKeyType::LMS
```

MCU ROM writes `FUSE_PQC_KEY_TYPE = 3` (the Caliptra LMS constant) to Caliptra.
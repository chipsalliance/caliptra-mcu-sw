# ROM Fuses

## Fuse Categories

This section is the authoritative summary of every OTP fuse the reference MCU
ROM consumes today or is specified to consume shortly. Scope is limited to
**Caliptra core and Caliptra MCU fuses**; broader SoC-level provisioning
(PLL/clock trim, analog/AST configuration, entropy-source conditioning
beyond the iTRNG thresholds, pinmux defaults, watchdog defaults, SKU
metadata, etc.) is integrator-defined and is not covered here. OpenTitan's
[`CREATOR_SW_CFG`](https://github.com/lowRISC/opentitan/blob/master/hw/top_earlgrey/data/otp/otp_ctrl_mmap.hjson)
partition is a useful prior-art reference for that broader set.

Fuses are grouped by how essential they are to a working production part:

- **Mandatory** — required for a production MCU/Caliptra subsystem to boot
  and run securely. These must be provisioned and routed through OTP (or, for
  fields where Caliptra Core requires real entropy on every cold boot, through
  OTP-backed straps).
- **Optional** — fuses MCU ROM will consume if present, but which an
  integrator may legitimately replace with constants, RTL straps, or
  feature-gate out entirely (e.g., debug-only flows, owner-set policies that
  default to zero).
- **Recommended but not required** — fuses that back specific MCU features
  (Device Ownership Transfer, MCU-side SVN anti-rollback, OCP LOCK). MCU only
  reads them when the corresponding feature is enabled by the integrator.

Sizes given are the logical (decoded) bit width. Physical OTP cost is larger
when the field uses a redundancy layout (e.g., `LinearOr{bits:N, dupe:3}` takes
`N×3` physical bits). See [OTP Encoding Recommendations](#otp-encoding-recommendations)
for the recommended layout and physical footprint of each fuse.

### Mandatory fuses

Caliptra Core fuse registers and iTRNG straps that MCU ROM must populate on
every cold boot. These are read by MCU ROM from OTP, transformed if needed,
and written to Caliptra's `FUSE_*` registers or `SS_STRAP_GENERIC[*]` /
`CPTRA_I_TRNG_*` registers.

| Fuse | Logical size | Notes |
|---|---|---|
| `CPTRA_CORE_VENDOR_PK_HASH_{0..N}` | 384 bits each | One slot active per boot; reference map has 16 slots |
| `CPTRA_CORE_VENDOR_PK_HASH_VALID` | 16 bits | Slot validity bitmask used to pick the active slot |
| `CPTRA_CORE_PQC_KEY_TYPE_{0..N}` | 2 bits each | Per-slot; selects MLDSA vs LMS for that vendor PK |
| `CPTRA_CORE_RUNTIME_SVN` | 128 bits | Caliptra Runtime SVN |
| `CPTRA_CORE_SOC_MANIFEST_SVN` | 128 bits | SoC manifest SVN (also drives MCU Runtime SVN) |
| `CPTRA_CORE_SOC_MANIFEST_MAX_SVN` | 32 bits | Max allowed SoC manifest SVN |
| `CPTRA_CORE_ECC_REVOCATION_{0..N}` | 4 bits each | Per-slot ECC key revocation bitmask |
| `CPTRA_CORE_LMS_REVOCATION_{0..N}` | 16 bits each | Per-slot LMS key revocation bitmask |
| `CPTRA_CORE_MLDSA_REVOCATION_{0..N}` | 4 bits each | Per-slot MLDSA key revocation bitmask |
| `CPTRA_SS_MANUF_DEBUG_UNLOCK_TOKEN` | 512 bits | Manufacturing debug unlock token (provision to all-zeros if unused) |
| `CPTRA_CORE_IDEVID_CERT_IDEVID_ATTR` | 512 bits used (768 bits allocated) | IDevID certificate attributes. The Caliptra register array is 24×u32 (96 B), but Caliptra ROM only consumes the first 16 entries (64 B): `Flags` (1), ECC `SubjectKeyId` (5), MLDSA `SubjectKeyId` (5), `UeidType` (1), `ManufacturerSerialNumber` (4). The remaining 8 u32 are reserved |
| `cptra_itrng_health_test_window_size` | 16 bits | Written to `SS_STRAP_GENERIC[2]` bits\[15:0\] |
| `cptra_itrng_entropy_config_0` | 32 bits | Written to `CPTRA_I_TRNG_ENTROPY_CONFIG_0` |
| `cptra_itrng_entropy_config_1` | 32 bits | Written to `CPTRA_I_TRNG_ENTROPY_CONFIG_1` |
| `CPTRA_CORE_OWNER_MANIFEST_MIN_SVN` | 8 bits | Owner manifest min SVN floor (upcoming Caliptra requirement). Written to `SS_STRAP_GENERIC[3]` bits\[7:0\]. **Upcoming:** the existing PK-hash skip-lock and PK-hash rotation straps on `SS_STRAP_GENERIC[3]` bits\[1:0\] are moving to MCI generic input wires (`mci_reg_generic_input_wires[*]`), so the full low byte will be available for this fuse value once that change lands. |

### Optional fuses

Fuses MCU ROM will read if provisioned, but which an integrator may replace
with hardcoded constants, RTL straps, or omit when the corresponding policy
is unused. The reference MCU ROM still reads every entry below; "optional"
here means an integrator-built MCU ROM may legitimately skip provisioning
or remove the read path.

| Fuse | Logical size | Notes |
|---|---|---|
| `CPTRA_CORE_FMC_KEY_MANIFEST_SVN` | 32 bits | Reserved; neither MCU nor Caliptra Core currently checks the value |
| `CPTRA_CORE_SOC_STEPPING_ID` | 16 bits | Lives in a 32-bit field; could be RTL-tied or strapped |
| `CPTRA_CORE_ANTI_ROLLBACK_DISABLE` | 1 bit | Lives in a 32-bit field; defaults to 0 (enforcement on). Should only be set on dev/manuf parts |
| `CPTRA_CORE_IDEVID_MANUF_HSM_IDENTIFIER` | 128 bits (16 B) | Manufacturing HSM identifier |
| `CPTRA_SS_OWNER_PK_HASH` | 384 bits | Only needed when owner PK comes from OTP; DOT can provide it instead |
| `CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_{0..7}` | 384 bits each | Only required if prod debug unlock is enabled |
| `fw_encryption_key` | 256 bits (recommended; 128/192/256 supported) | Only required if firmware images are encrypted at rest. Global AES key; lives in a secret partition (e.g., `VENDOR_SECRET_PROD_PARTITION`) |
| `ss_key_release_base_addr_l` / `ss_key_release_base_addr_h` / `ss_key_release_size` | 64+16 bits | Usually sourced from `RomConfig` but may be from OTP; OCP LOCK key release (2.1+) |

### Recommended but not required fuses

Feature-specific fuses. MCU ROM reads them only when the corresponding
feature is enabled by the integrator; with the feature off, the OTP space
can be reclaimed.

| Fuse | Logical size | Feature | Notes |
|---|---|---|---|
| `dot_initialized` | 1 bit | DOT | Gate flag indicating DOT flow is active for this part |
| `dot_fuse_array` | 256 bits | DOT | Monotonic bit-count DOT state counter; supports 128 lock/unlock cycles; more or less can be allocated depending on use cases |
| `vendor_recovery_pk_hash` | 384 bits | DOT | Vendor master key for `DOT_OVERRIDE` catastrophic recovery (lives in `VENDOR_SECRET_PROD_PARTITION`). One slot today; integrators that need rotation should add `vendor_recovery_pk_hash_{0..N}` + a `vendor_recovery_pk_hash_valid` bitmask and/or revocation bits |
| `MCU_COMPONENT_SVN_MANIFEST_MIN_SVN` | 32 bits (recommended) | MCU SVN anti-rollback | Min SVN for the MCU Component SVN Manifest itself |
| `SOC_IMAGE_MIN_SVN[0..M]` | 32 bits each (recommended) | MCU SVN anti-rollback | Per-slot SoC image min SVN; `M` is integrator-defined |
| `perma_hek_en` | 1 bit | OCP LOCK (2.1+) | Permanent HEK enable flag |
| `CPTRA_SS_LOCK_HEK_PROD_{0..7}` | 256 bits each | OCP LOCK (2.1+) | 8 HEK seed slots (`CPTRA_SS_LOCK_HEK_PROD_N_RATCHET_SEED`, 32 B each); one active at a time |

The MCU SVN fuse sizes above are the recommended logical widths from
[`docs/src/svn.md`](svn.md); integrators choose the actual bit-count width and
number of `SOC_IMAGE_MIN_SVN` slots based on their release cadence and
component count.

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

- **`CPTRA_CORE_IDEVID_CERT_IDEVID_ATTR`** ✓ → `FUSE_IDEVID_CERT_ATTR[0..23]`: raw u32 × 24.
  The Caliptra register array is 24 u32 wide (96 bytes), but Caliptra ROM
  only reads the first **16 entries (64 bytes)**, defined by the
  [`IdevidCertAttr`](https://github.com/chipsalliance/caliptra-sw/blob/main/drivers/src/fuse_bank.rs)
  enum: index 0 = `Flags` (ECC and MLDSA X.509 key-id algorithm selection,
  bits \[2:0\] = ECC, bits \[5:3\] = MLDSA); indexes 1..5 = ECC `SubjectKeyId`
  (20 bytes); indexes 6..10 = MLDSA `SubjectKeyId` (20 bytes); index 11 =
  `UeidType` (low byte only); indexes 12..15 = `ManufacturerSerialNumber`
  (16 bytes, little-endian, forming the 17-byte UEID together with
  `UeidType`). Indexes 16..23 are reserved — integrators only need to
  provision the first 64 bytes in OTP.

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

- **`CPTRA_CORE_OWNER_MANIFEST_MIN_SVN`** ✓ → `SS_STRAP_GENERIC[3]` bits\[7:0\].
  `Single{bits:8}` raw u8 (recommended `LinearOr{bits:8, dupe:3}` since this is
  a monotonically increasing anti-rollback value — see encoding table below).
  Required by an upcoming Caliptra ROM change that reads the owner manifest min
  SVN floor from this strap during owner manifest verification. **Upcoming:**
  bits\[1:0\] of `SS_STRAP_GENERIC[3]` are currently used as platform hardware
  straps (PK-hash skip-lock and PK-hash rotation); both are moving to MCI
  generic input wires (`mci_reg_generic_input_wires[*]`) so the full low byte
  of `SS_STRAP_GENERIC[3]` will be available for this fuse value. MCU ROM
  consumers of the PK-hash straps (see `PK_HASH_SKIP_LOCK_STRAPPING_MASK` and
  `PK_HASH_ROTATION_STRAPPING_MASK` in `rom/src/rom.rs`) will need to be
  retargeted to the new MCI input-wire bits when that change lands.

- **OTP status register offset** — hard-coded in MCU ROM (not from OTP).
  Written to `SS_STRAP_GENERIC[0]` bits\[15:0\]; Caliptra ROM reads this strap
  and uses it as the OTP controller status-register byte offset when polling
  for DAI idle during UDS/FE programming. Integrators select the value from
  their OTP controller's register map. See
  [caliptra-sw#3723](https://github.com/chipsalliance/caliptra-sw/pull/3723).

- **`CPTRA_CORE_VENDOR_PK_HASH_VALID`** (all slots) — slot selection only, not written to any
  register. `LinearOr{bits:16, dupe:3}` → decoded u16 bitmask.

- **`dot_initialized`** — MCU
  internal use only, not written to any register. `LinearOr{bits:1, dupe:3}` → logical
  0 or 1, used as the DOT flow gate.

- **`dot_fuse_array`** — MCU internal
  use only, not written to any register. `OneHot{bits:256}` is the current
  layout name for bit-count encoding: count burned bits to track
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

- **`fw_encryption_key`** — MCU internal use only, not written to any Caliptra
  register. `Single{bits:K}` raw key bytes, where `K ∈ {128, 192, 256}`
  (256 recommended). Global AES key used to decrypt firmware images at rest;
  only required when the integrator deploys encrypted firmware. Should live
  in a secret partition (e.g., `VENDOR_SECRET_PROD_PARTITION`) so the key is
  not accessible to non-MCU bus masters.

- **`vendor_recovery_pk_hash`** — MCU internal use only, not written to any
  Caliptra register. `Single{bits:384}` raw 48 bytes. Vendor master key used by
  the `DOT_OVERRIDE` catastrophic recovery flow; lives in
  `VENDOR_SECRET_PROD_PARTITION` (`CPTRA_SS_VENDOR_SPECIFIC_SECRET_FUSE_0`).
  The stored value is `SHA-384(ECC P-384 pubkey X ‖ Y ‖ MLDSA-87 pubkey)`
  — see [Vendor Recovery PK Hash Format](dot.md#vendor-recovery-pk-hash-format)
  in the DOT spec for the exact byte layout. The current reference design
  provisions exactly one recovery PK hash and has no revocation mechanism;
  integrators that need to rotate the vendor recovery key in the field should
  allocate additional slots (`vendor_recovery_pk_hash_{0..N}`, 48 B each) plus
  a `vendor_recovery_pk_hash_valid` bitmask (`LinearOr{bits:N, dupe:3}`)
  analogous to `CPTRA_CORE_VENDOR_PK_HASH_VALID`.

- **`MCU_COMPONENT_SVN_MANIFEST_MIN_SVN`** — MCU internal use only, not written
  to any Caliptra register. Recommended `OneHotLinearOr{bits:N, dupe:3}`
  (logical width up to 32 bits). MCU ROM compares this against the MCU
  Component SVN Manifest header to enforce its own anti-rollback floor.

- **`SOC_IMAGE_MIN_SVN[0..M]`** — MCU internal use only, not written to any
  Caliptra register. Recommended `OneHotLinearOr{bits:N, dupe:3}` per slot
  (logical width up to 32 bits). Optional per-SoC-component min SVN floor;
  the number of slots `M` and the `component_id → slot` mapping are
  integrator-defined.

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
| `CPTRA_CORE_IDEVID_CERT_IDEVID_ATTR` | ✅ | `Single{bits:512}` for the 16 used entries (or `Single{bits:768}` to match the full Caliptra register array) |
| `CPTRA_CORE_IDEVID_MANUF_HSM_IDENTIFIER` | ✅ | `Single{bits:128}` |
| `CPTRA_SS_MANUF_DEBUG_UNLOCK_TOKEN` | ✅ | `Single{bits:512}` |
| `CPTRA_SS_OWNER_PK_HASH` | ✅ | `Single{bits:384}` |
| `CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_{0..7}` | ✅ | `Single{bits:384}` each |
| `dot_initialized` | ✅ | `Single{bits:1}` or if no ECC, `LinearOr{bits:1, dupe:3}` |
| `dot_fuse_array` | ❌ | `OneHot{bits:256}` or `OneHotLinearOr{bits:256, dupe: 3}` |
| `cptra_itrng_health_test_window_size` | ✅ | `Single{bits:16}` |
| `cptra_itrng_entropy_config_0` | ✅ | `Single{bits:32}` |
| `cptra_itrng_entropy_config_1` | ✅ | `Single{bits:32}` |
| `CPTRA_CORE_OWNER_MANIFEST_MIN_SVN` | ❌ | `LinearOr{bits:8, dupe:3}` |
| `perma_hek_en` (2.1 only) | ✅ | `Single{bits:1}` or if no ECC, `LinearOr{bits:1, dupe:3}` |
| `CPTRA_SS_LOCK_HEK_PROD_{0..7}` (2.1 only) | ✅ | `Single{bits:256}` each (per-slot `CPTRA_SS_LOCK_HEK_PROD_N_RATCHET_SEED`) |
| `vendor_recovery_pk_hash` | ✅ | `Single{bits:384}` |
| `vendor_recovery_pk_hash_valid` (optional, if multiple slots) | ❌ | `LinearOr{bits:N, dupe:3}` |
| `fw_encryption_key` | ✅ | `Single{bits:256}` (or 128/192 to match the chosen AES key length) |
| `MCU_COMPONENT_SVN_MANIFEST_MIN_SVN` | ❌ | `OneHotLinearOr{bits:N, dupe:3}` (N up to 32) |
| `SOC_IMAGE_MIN_SVN_{0..M}` | ❌ | `OneHotLinearOr{bits:N, dupe:3}` (N up to 32) each |

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
layout name means bit-count encoding with OR redundancy, not true one-hot
encoding. It encodes a logical integer using two stages:

1. **Bit-count**: the logical value `n` is encoded as `n` consecutive 1-bits: `bits = (1 << n) - 1`
2. **LinearOr**: each bit of the bit-count value is replicated `duplication` (3) times in
   consecutive bit positions. The 2 logical bits × 3 replications = 6 physical bits, packed into
   the low 6 bits of the 4-byte field.

| Key type | Logical value | Bit-count pattern | OTP raw u32 | OTP bytes @ `0x428` |
|---|:---:|:---:|:---:|:---:|
| MLDSA | 1 | `0b01` | `0x00000007` | `07 00 00 00` |
| LMS | 2 | `0b11` | `0x0000003F` | `3f 00 00 00` |

In this example, we assume that MCU ROM is implementing this replication layout in software.
**An integrator may choose to have this replication implemented at a
lower level in the hardware's fuse macro layer**.
If that is the case, then the duplication and OR reduction in this example can be ignored.

### Example: CPTRA_CORE_PQC_KEY_TYPE_0 (LMS)

We trace `vendor_pqc_key_type_0` provisioned for LMS, i.e., the bit-count
pattern `0b11` (logical value 2, raw encoded value 3), expected by Caliptra
core ROM for LMS.

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

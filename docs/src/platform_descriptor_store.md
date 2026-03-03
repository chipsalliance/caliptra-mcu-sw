# Platform Descriptor Store (PDS)

The Platform Descriptor Store (PDS) is an extensible, self-describing binary region within the flash layout that stores platform-level data as a linked list of UUID-typed descriptors with variable-size payloads.

## Purpose

The PDS provides a generic mechanism for embedding non-firmware data in the IFWI without modifying the flash layout specification. This enables late-in-the-program additions such as:

- Device identity binding
- Build provenance tracking (e.g., build origin, tool versions)
- Platform compatibility information (e.g., flavor, SKU)
- Impactless update version lists
- Configuration attributes or debug policy flags

## Identifier

The PDS uses a Caliptra-defined Identifier:

| Identifier | Name |
|-----------|------|
| `0x00000003` | Platform Descriptor Store |

The PDS is stored as a standard image within each slot, with its own Image Information entry in the flash layout.

## Verification

The PDS is included in the Caliptra verification flow:

1. An Image Metadata Entry (IME) in the SoC Manifest contains the SHA-384 hash of the PDS binary
2. During boot, Caliptra RT verifies the PDS hash against the SoC Manifest digest via `authorize_and_stash`
3. After verification, firmware can parse the PDS content with confidence that it has not been tampered with

The PDS is a build-time artifact. It is written during IFWI generation and is read-only at runtime. Any change to the PDS content requires re-signing the SoC Manifest.

## Binary Format

All integer fields are little-endian byte-ordered.

### Alignment Requirements

**Flash alignment:**

- The PDS image must be aligned to flash erase block boundaries within the slot, consistent with other images in the flash layout

**Binary alignment:**

- Descriptor headers must start at 4-byte aligned offsets within the PDS binary. Generation tools must insert 0-3 padding bytes after a payload if needed to align the next descriptor header
- Payload data has no alignment requirement since payloads are accessed as byte arrays
- The PDS header size (148 bytes) and descriptor header size (32 bytes) are both multiples of 4 bytes

**Parser requirements:**

- Parsers must copy headers from the source buffer into a local aligned struct before accessing fields. This ensures correct behavior on architectures that do not support unaligned memory access (e.g., RISC-V). The recommended pattern is:
  1. Read the raw bytes from flash (or from an in-memory copy of flash) into a local struct-sized buffer
  2. Interpret the local copy as the header struct
  3. Access fields from the local copy, which is guaranteed to be aligned on the stack
- This is equivalent to the C pattern: read from flash into a local variable, then access fields directly from that local copy
- Parsers must not cast arbitrary buffer offsets to struct pointers, as the source buffer may not be aligned

**Physical layout:**

- Descriptor headers and payloads may appear at arbitrary (aligned) offsets within the PDS, not necessarily in sequential order
- Parsers must follow the offset chain (`first_descriptor_offset`, `next_descriptor_offset`, `payload_offset`) to discover locations rather than assuming sequential layout
- Multiple descriptors may reference the same payload offset (shared data)

### PDS Header

The PDS begins with a header:

```c
typedef struct __attribute__((packed)) {
    uint32_t magic;                       // Must be 0x50445331 ("PDS1")
    uint32_t header_size;                 // Size of this header (currently 148 bytes)
    uint32_t header_crc;                  // CRC-32 over bytes from offset 12 to header_size
    uint32_t version;                     // Header version (currently 1)
    uint32_t first_descriptor_offset;     // Byte offset from PDS start to first descriptor, or 0
    uint8_t  pds_version_string[128];     // Null-terminated UTF-8 version string
} PdsHeaderV1;
```

| Field | Size (bytes) | Description |
|-------|-------------|-------------|
| magic | 4 | Must be `0x50445331` ("PDS1" in little-endian ASCII) |
| header_size | 4 | Size of this header structure in bytes. Currently 148 |
| header_crc | 4 | CRC-32 (CRC-32/CKSUM polynomial) computed over bytes from offset 12 (`version` field) through `header_size` |
| version | 4 | Header format version. Currently `1` |
| first_descriptor_offset | 4 | Byte offset from the start of the PDS to the first descriptor header. `0` if no descriptors are present |
| pds_version_string | 128 | Null-terminated UTF-8 string. Optional version identifier for the PDS content. Unused bytes must be zero |

### PDS Descriptor Header

Each descriptor in the chain begins with a descriptor header:

```c
typedef struct __attribute__((packed)) {
    uint32_t header_size;              // Size of this descriptor header (currently 32 bytes)
    uint32_t payload_offset;           // Byte offset from PDS start to payload data
    uint32_t payload_size;             // Size of payload in bytes
    uint32_t next_descriptor_offset;   // Byte offset from PDS start to next descriptor, or 0
    uint8_t  descriptor_type[16];      // UUID (RFC 4122) identifying descriptor type
} PdsDescriptorHeaderV1;
```

| Field | Size (bytes) | Description |
|-------|-------------|-------------|
| header_size | 4 | Size of this descriptor header in bytes. Currently 32 |
| payload_offset | 4 | Byte offset from the start of the PDS to the payload data for this descriptor |
| payload_size | 4 | Size of the payload data in bytes |
| next_descriptor_offset | 4 | Byte offset from the start of the PDS to the next descriptor header. `0` if this is the last descriptor in the chain |
| descriptor_type | 16 | UUID (RFC 4122) identifying the type of this descriptor. Used by parsers to match descriptors to known types |

## Descriptor Chain Rules

1. Descriptors form a singly linked list via `next_descriptor_offset`
2. Each `next_descriptor_offset` must point to a location strictly greater than the current descriptor's offset (forward-only, prevents loops)
3. A `next_descriptor_offset` of `0` indicates the last descriptor
4. Headers and payloads may appear at arbitrary offsets within the PDS (not necessarily contiguous). Parsers must follow offset fields to discover locations
5. Multiple descriptors of the same type (same UUID) are permitted
6. Multiple descriptors may reference the same payload offset (shared payload data)
7. Parsers must enforce a maximum descriptor count to bound traversal time. Recommended default: 32

## Versioning and Extension Rules

These rules apply to both the PDS Header and PDS Descriptor Header:

1. Future versions may append additional fields at the end while keeping existing fields intact. The `header_size` field will increase to reflect the new size
2. Parsers encountering a `header_size` larger than expected must ignore additional bytes beyond the fields they understand
3. Parsers encountering a `header_size` smaller than expected must use appropriate default values for the missing fields
4. Breaking changes that are not backwards compatible require both a new `version` value and a new `magic` number

## Descriptor Types

Descriptor type UUIDs and their payload formats are vendor-defined. The Caliptra specification defines only the PDS container format (header, descriptor chain, CRC, versioning rules).

Each vendor defines their own descriptor types by:

1. Assigning a UUID (RFC 4122) for the descriptor type
2. Defining the payload binary format
3. Implementing serialization in their IFWI generation tooling
4. Implementing deserialization in their firmware

This separation ensures that no vendor-specific data types or business logic are required in the Caliptra open-source codebase.

## Backwards Compatibility

The PDS is backwards compatible along three dimensions:

- **Old firmware, new IFWI:** Firmware that does not know about the PDS skips the Image Information entry with Identifier `0x00000003` because it does not match any known Identifier. The PDS image is never loaded.
- **New firmware, old IFWI:** Firmware that expects a PDS searches for Identifier `0x00000003`, does not find it, and handles the absence gracefully (e.g., skips descriptor-dependent operations).
- **Unknown descriptors:** Firmware walks the descriptor chain comparing each UUID against known types. Unrecognized UUIDs are skipped without error.

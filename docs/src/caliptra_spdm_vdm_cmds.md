# Caliptra SPDM VDM Commands

## Overview

This document describes how Caliptra common commands are transported over SPDM Vendor Defined Messages (VDM) via MCTP. This is the **out-of-band (OOB)** path for standard, vendor-neutral Caliptra device management commands that require SPDM-defined semantics, SPDM authorization, or SPDM streaming/chunking.

For command definitions (categories, payloads, and completion codes), see [Caliptra Common Commands](caliptra_common_commands.md).

For the unified software architecture shared between OOB (SPDM VDM) and in-band (MCI Mailbox) paths, see [Unified Caliptra Command Handling](unified_caliptra_command_handling.md).

## Transport Stack

```text
┌─────────────────────────────────────────┐
│        Caliptra VDM Commands            │
│ (FirmwareVersion, ExportAttestedCsr, …) │
├─────────────────────────────────────────┤
│      Caliptra Command Header            │
│     (Command Version, Command Code)     │
├─────────────────────────────────────────┤
│        OCP SPDM VDM Framing             │
│     (IANA Registry ID, Vendor ID)       │
├─────────────────────────────────────────┤
│              SPDM                       │
│     (VENDOR_DEFINED_REQUEST/RESPONSE)   │
├─────────────────────────────────────────┤
│              MCTP                       │
│        (Message Type 0x05)              │
├─────────────────────────────────────────┤
│         Physical Layer                  │
│              (I3C)                      │
└─────────────────────────────────────────┘
```

## SPDM VDM Encapsulation

Caliptra commands assigned to SPDM VDM are carried within SPDM `VENDOR_DEFINED_REQUEST` and `VENDOR_DEFINED_RESPONSE` messages using the OCP-assigned Vendor ID (`42623`). The command range `0x01`-`0x20` is [reserved in the OCP registry](https://github.com/opencomputeproject/ocp-registry/blob/main/command-registry.md) and defined by the Caliptra Working Group.

### OCP VDM Header

The SPDM VDM standard header identifies the vendor organization:

| Field            | Size    | Value        | Description                                       |
| ---------------- | ------- | ------------ | ------------------------------------------------- |
| Standard ID      | 2 bytes | `0x0004`     | IANA Enterprise ID format                         |
| Vendor ID Length | 1 byte  | `0x04`       | Length of the Vendor ID field (4 bytes)           |
| Vendor ID (IANA) | 4 bytes | `0x0000A67F` | OCP Caliptra Working Group IANA Enterprise Number |

### Caliptra VDM Message Header

Following the OCP VDM standard header, the Caliptra-specific message header appears:

| Field           | Size   | Description                                                                           |
| --------------- | ------ | ------------------------------------------------------------------------------------- |
| Command Version | 1 byte | Protocol version. Current value: `0x01`                                               |
| Command Code    | 1 byte | Identifies the command (see [Command List](caliptra_common_commands.md#command-list)) |

### Response Format

Responses follow the same header structure. The Command Code in the response mirrors the request. The response payload begins with a `CaliptraCompletionCode` (1 byte) indicating success or failure. Command-specific response data, if any, follows the completion code:

| Field           | Size    | Description                            |
| --------------- | ------- | -------------------------------------- |
| Command Version | 1 byte  | `0x01`                                 |
| Command Code    | 1 byte  | Same as request command code           |
| Completion Code | 1 byte  | OCP completion code (`0x00` = Success) |
| Payload         | N bytes | Command-specific response data         |

See [Completion Codes](caliptra_common_commands.md#completion-codes) for the full list of error codes.

The SPDM VDM completion code is transport-specific response status and is not included in the transport-agnostic common response payload tables.

## Command Codes

The following table maps SPDM VDM command codes to Caliptra common commands. For command payload definitions, see [Caliptra Common Commands](caliptra_common_commands.md#command-definitions).

These command codes are assigned from the Caliptra range reserved in the [OCP command registry](https://github.com/opencomputeproject/ocp-registry/blob/main/command-registry.md).

| Command Code | Command Name              | R/O | Description                                                                |
| ------------ | ------------------------- | --- | -------------------------------------------------------------------------- |
| `0x05`       | GetAttestation            | O   | Retrieve signed attestation evidence in a requester-selected format.       |
| `0x06`       | RequestDebugUnlock        | O   | Request debug unlock in production environment.                            |
| `0x07`       | AuthorizeDebugUnlockToken | O   | Send debug unlock token to device for authorization.                       |
| `0x08`       | ExportAttestedCsr         | O   | Discover device identity keys or export an attested CSR.                   |
| `0x11`       | DeviceOwnershipTransfer   | O   | Carry DOT commands with native authentication.                             |
| `0x12`       | AuthorizedCommand         | O   | Carry manifest-authorized provisioning and fuse subcommands.               |
| `0x13`       | OcpLock                   | O   | Carry OCP LOCK commands.                                                   |

R = Required, O = Optional

Implemented commands are advertised in the `external_commands` field returned by `DeviceCapabilities`. Implemented operations under `AuthorizedCommand` are advertised individually in `authorized_subcommands`. Recognized but unimplemented commands are not advertised. See [Device Capabilities](caliptra_common_commands.md#device-capabilities).

## Authorization-Gated Subcommands

The following subcommands are assigned to the SPDM VDM IANA authorization-gated path and are carried under `AuthorizedCommand`. Multi-byte payload integers and the subcommand ID are encoded little-endian on the wire.

| Subcommand ID          | Name                       | Status        | Description                                         |
| ---------------------- | -------------------------- | ------------- | --------------------------------------------------- |
| `0x4D41_4343` (`MACC`) | GetAuthChallenge           | Supported     | Acquire a one-use 48-byte authorization challenge.  |
| `0x5056_504B` (`PVPK`) | ProvisionVendorPkHash      | Supported     | Provision vendor public key hash.                   |
| `0x504F_504B` (`POPK`) | ProvisionOwnerPkHash       | Supported     | Provision owner public key hash.                    |
| `0x4D43_4D53` (`MCMS`) | FuseIncreaseMinSvn         | Supported     | Increase the Caliptra Runtime, SoC Manifest, or Owner SoC Manifest minimum SVN. |
| `0x4D43_4650` (`MCFP`) | ProgramFieldEntropy        | Supported     | Program field entropy.                              |
| `0x4D52_564B` (`MRVK`) | FuseRevokeVendorPubKey     | Supported     | Revoke vendor public key.                           |
| `0x5256_4B48` (`RVKH`) | FuseRevokeVendorPkHash     | Supported     | Revoke vendor public key hash.                      |
| `0x4946_504B` (`IFPK`) | FuseLockPartition          | Supported     | Lock fuse partition.                                |
| `0x4D5A_524D` (`MZRM`) | ZeroizeUdsFeAndEnterRma    | Supported     | Zeroize UDS and field entropy, then enter RMA.      |
| `0x4F4C_5048` (`OLPH`) | OcpLockProgramHek          | Supported     | Program an unused HEK slot.                         |
| `0x4F4C_5A48` (`OLZH`) | OcpLockZeroHek             | Supported     | Permanently sanitize an unused HEK slot.            |
| `0x0000_0011`          | DeviceOwnershipTransfer    | Supported     | Carry authorization-gated DOT subcommands.          |
| `0x0000_0013`          | OcpLock                    | Supported     | Carry authorization-gated OCP LOCK subcommands.     |
| `VU00`-`VUFF`           | VendorUnique               | Reserved      | Vendor-unique innermost commands; unsupported by the reference MCU. |

`VU00` through `VUFF` represent exactly 256 IDs of the form `VUxy`, where both
suffix characters are uppercase ASCII hexadecimal digits. They are encoded in
the little-endian `sub_cmd_id` field like the other FourCC subcommands. Numeric
values in the ASCII gaps between `9` and `A` are not reserved. The reference
implementation returns `UnsupportedOperation` for these recognized but
unimplemented IDs.

### Authorization Modes and Targets

The signer selects the authorization mode independently for each request using
the signed nonce. An all-zero nonce selects Offline authorization; a nonzero
nonce selects Challenge-bound authorization and must match a live device
challenge. Runtime accepts either form for any otherwise-authorized command.
There is no firmware-wide mode switch or mode-discovery command.

| Scope | Mode | Signed SoC UEID | Nonce |
| ----- | ---- | --------------- | ----- |
| Device | Challenge-bound | Target manufacturer serial number | Live nonzero device challenge |
| Device | Offline | Target manufacturer serial number | 48 zero bytes |
| Fleet | Challenge-bound | 16 zero bytes | Live nonzero device challenge |
| Fleet | Offline | 16 zero bytes | 48 zero bytes |

A nonzero UEID must match the 16-byte manufacturer serial number in local OTP.
This is the serial-number portion of the UEID, without its type byte. Zero
UEID selects Fleet scope. Fleet challenge-bound requests still require a
separate challenge and signature for each target device; a nonce is not
fleet-wide.

Offline authorization intentionally permits replay on every matching device
whose key and command-policy checks succeed. An operation's lifecycle and
state checks can still reject a repeated operation.

### Authorization Block

Both MCI mailbox and SPDM VDM carry:

```text
subcommand_id(LE) || command_payload || AuthorizationBlock
```

The fixed-size Authorization Block is **7,484 bytes**. Offsets below are relative
to its beginning, immediately after the command payload.

| Bytes | Field | Encoding |
| ----- | ----- | -------- |
| 0:3 | `version` | u32 little-endian; must be `1` |
| 4:7 | `authority` | u32 little-endian; `1` = Vendor+Owner, `2` = Owner-only |
| 8:23 | `soc_ueid` | 16 opaque bytes |
| 24:71 | `nonce` | 48 opaque bytes |
| 72:119 | `ecc_pub_x` | Standard 48-byte big-endian coordinate |
| 120:167 | `ecc_pub_y` | Standard 48-byte big-endian coordinate |
| 168:2759 | `mldsa_pub` | Standard 2,592-byte ML-DSA-87 public key |
| 2760:2807 | `ecc_sig_r` | Standard 48-byte big-endian scalar |
| 2808:2855 | `ecc_sig_s` | Standard 48-byte big-endian scalar |
| 2856:7483 | `mldsa_sig` | Standard 4,627-byte signature followed by one zero padding byte |

These are Core's byte-array cryptographic encodings; do not word-swap the ECC
key or signature fields on the wire. Unknown authorization versions and
authorities, and nonzero ML-DSA padding, are rejected.

The signed Authority selects an existing, fixed IME firmware ID and manifest:

| Authority | IME `fw_id` | Manifest |
| --------- | ----------- | -------- |
| Vendor+Owner (`1`) | `0x0000_0004` (`V_AUTH_KEY_ID`) | Original/base SoC Manifest |
| Owner-only (`2`) | `0x0000_0006` (`O_AUTH_KEY_ID`) | Owner-only SoC Manifest |

The request does not carry an IME selector. There is no cross-manifest fallback
or separate command-key installation command. The applicable manifest must
already be authenticated and active in Core. In particular, Owner commands
cannot use the original manifest as a fallback when the Owner manifest is
unavailable. The reference original-manifest generator requires vendor IMC
signatures as well as owner authentication.

The initial Runtime command policy permits **Owner-only** authorization for all
currently implemented protected commands. Vendor+Owner permissions must be
enabled explicitly for individual commands or targets through
`CommandAuthorizer::permits_authority`. A trusted key alone does not grant
permission.

These IME IDs are not new flash images or DPE identities. Existing measurement
logic is unchanged. The optional Core UEID-binding IME at `0x0000_0FFF` is
separate from the command's signed 16-byte target UEID.

### Signed Transcript and Key Digest

Both signatures bind the following bytes in order:

```text
subcommand_id(BE) || command_payload ||
version(LE) || authority(LE) || soc_ueid[16] || nonce[48]
```

The signed command ID retains the existing big-endian signing convention,
although its transport field is little-endian. ECDSA P-384 signs
`SHA384(transcript)`. The ML-DSA-87 leg uses pure ML-DSA with an empty context
and `SHA512(transcript)` as its 64-byte message; this is not direct signing of
the transcript or the standardized HashML-DSA encoding.

For ordinary subcommands, the signed ID is the FourCC above. For DOT
(`0x00000011`) and OCP LOCK (`0x00000013`), it is the outer family ID and the
signed payload includes `FourCC(LE) || operation_payload`. Transport headers
and checksums, supplied public keys, and signatures are not in the signed
transcript.

The supplied keys are authenticated separately against the selected IME's
48-byte digest:

```text
key_digest = SHA384(
    CoreWordEncode(ecc_pub_x) ||
    CoreWordEncode(ecc_pub_y) ||
    mldsa_pub
)
```

`CoreWordEncode` reverses bytes within each four-byte ECC word, preserving word
and coordinate order. ML-DSA bytes are unchanged. This matches Core's owner
firmware key-pair hash in ML-DSA mode and production debug-unlock key hash.
Store the resulting standard digest bytes directly in the IME; do not apply
the additional word-storage conversion used for fuse/register buffers.

### Authorization Flow

1. Select Challenge-bound or Offline authorization for this request.
2. Select the permitted authority and Device or Fleet target.
3. In Challenge-bound mode, request a live, nonzero 48-byte nonce through
   `GetAuthChallenge`. In Offline mode, use 48 zero bytes without requesting
   a challenge.
4. Sign the canonical transcript with both authorized keys.
5. Append the Authorization Block and submit through `AuthorizedCommand`.
6. Runtime checks format, authority policy, target, key digest, both signatures,
   and live-challenge freshness when requested, before executing the operation.

After format, policy, and target checks succeed, a Challenge-bound
verification attempt consumes the stored challenge before key/signature
verification. A mismatched live nonce or failed signature therefore requires
a fresh challenge. A successful new challenge request replaces the old one.
An all-zero RNG result is rejected without replacing the outstanding challenge.
MCI and SPDM share challenge state, so a challenge cannot be replayed through
the other transport. Offline requests do not consume a pending challenge.
Changing a signed nonce to switch modes invalidates both signatures.

Requests must have the exact size. Missing, truncated, oversized, and legacy
nonce-only trailers are rejected with `InvalidPayloadSize`. Authorization
mismatches return `AccessDenied`; operational and resource failures retain
their normal completion codes. Version 1 requires coordinated host, Runtime,
and manifest-key-digest updates; there is no legacy hash or trailer fallback.

`ZeroizeUdsFeAndEnterRma` reports `ZeroizeFailed` if the zeroization command
fails or the kernel cannot confirm by OTP readback that UDS and all field
entropy partitions are zeroized. In that case, RMA is not attempted. It reports
`RmaTransitionFailed` if zeroization is confirmed but the lifecycle-controller
transition to RMA fails.

### Implemented Subcommand Payloads

These operation payloads exclude the Authorization Block, which is appended
immediately afterwards. All payload integers are little-endian. Family
operations additionally prefix their FourCC as described above.

| Subcommand | Operation payload | Payload bytes |
| ---------- | ----------------- | ------------- |
| PVPK | `slot:u32 || hash:u8[48]` | 52 |
| POPK | `hash:u8[48]`, existing dword-reversed OTP representation | 48 |
| MCMS | `flags:u32 || target:u32 || svn:u32`; flags must be zero | 12 |
| MCFP | `partition:u32` | 4 |
| MRVK | `reserved:u32 || slot:u32 || key_type:u32 || key_index:u32`; reserved must be zero | 16 |
| RVKH | `reserved:u32 || slot:u32`; reserved must be zero | 8 |
| IFPK | `partition:u32` | 4 |
| MZRM | `rma_token:u8[16]` | 16 |
| OLPH | `hek_slot:u32`, slot 0 through 7 | 4 |
| OLZH | `hek_slot:u32`, slot 0 through 7 | 4 |

## Device Ownership Transfer Commands

Runtime DOT commands use a common four-byte subcommand namespace under family
ID `0x11`. Multi-byte fields are little-endian.

Authorization-gated DOT request:

```text
[version=1][command=0x12][family=0x11:u32][DOT FourCC:u32]
[DOT payload][authorization trailer]
```

Native-authenticated/read-only DOT request:

```text
[version=1][command=0x11][DOT FourCC:u32][DOT payload]
```

| FourCC | Command | Path | DOT payload | Validation |
| ------ | ------- | ---- | ----------- | ---------- |
| `MDEN` (`0x4D44_454E`) | Enable | Authorized | Empty | Initialization gate clear and zero epoch bits; programs all three redundant gate bits |
| `MDLK` | Lock | Authorized | `cak_digest[48] || lak_digest[48]` | Nonzero digests; EVEN state |
| `MDDS` | Disable | Authorized | `lak_digest[48]` | Nonzero LAK digest; EVEN state |
| `MDRT` | Rotate | Authorized | `min_fuse_count:u32 || cak_digest[48] || lak_digest[48]` | Runs when burned count is below the minimum |
| `MDBB` | Get backup blob | Authorized | Empty | ODD state and valid blob HMAC |
| `MDUC` | Unlock challenge | Native | Empty | ODD state and valid current blob |
| `MDUL` | Unlock | Native | LAK ECC key, ML-DSA key, hybrid signature | Existing LAK digest and challenge signatures |
| `MDST` | Status | Native/read-only | Empty | Returns `enabled:u8 || locked:u8 || burned:u16` |
| `MDRC` | Recovery | Native | `DOT_BLOB[168]` | ODD state and current-epoch blob HMAC |
| `DOTW` | Override challenge | Native | Recovery ECC key and ML-DSA key | Keys match fused recovery-key hash |
| `DOTX` | Override | Native | Recovery keys and hybrid signature | Fused key hash and challenge signatures |

`MDEN`, `MDLK`, `MDDS`, `MDRT`, and `MDBB` are rejected with `AccessDenied` when sent
directly under top-level command `0x11`. `MDRC`, `DOTW`, and `DOTX` are not
gated by a ROM recovery-mode signal; their native cryptographic and state checks
are always enforced.

**For detailed command flows, state transitions, security properties, and use cases**, see [Device Ownership Transfer (DOT)](dot.md#runtime-commands).

## OCP LOCK Commands

Runtime OCP LOCK commands over SPDM VDM use a common four-byte subcommand
namespace under family ID `0x13` (gated by the `ocp-lock` feature flag).
Multi-byte fields are little-endian.

Authorization-gated OCP LOCK request:

```text
[version=1][command=0x12][family=0x13:u32][OCP LOCK FourCC:u32]
[OCP LOCK payload][authorization trailer]
```

| FourCC | Command | Path | OCP LOCK payload | Description |
| ------ | ------- | ---- | ---------------- | ----------- |
| `OLRH` | Rotate HEK | Authorized | `slot:u32` | Sanitize active HEK and program next slot |
| `OLSP` | Set Perma HEK | Authorized | Empty | Program permanent HEK lock fuse (`PERMA_HEK_EN`) |

`OLRH` and `OLSP` are rejected with `AccessDenied` when sent directly under
top-level command `0x13`.

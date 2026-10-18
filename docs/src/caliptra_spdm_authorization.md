# Caliptra SPDM Authorization Implementation

## Introduction

This document defines the Caliptra MCU implementation binding for the SPDM Authorization specification (DSP0289). The SPDM Authorization specification provides a standardized framework for controlling access to protected resources through credential-based authorization and policy enforcement. This binding document specifies how Caliptra implements DSP0289 requirements, including which optional features are supported, how implementation-specific choices are made, and how the specification maps to Caliptra's hardware capabilities and operational constraints. Example use cases include certificate provisioning for multi-entity PKI hierarchies (Vendor, Owner, Tenant), secure command authorization, and lifecycle-aware privilege management for device transfer scenarios.

## Implementation Details

### Credential Storage and Persistence

Caliptra uses both OTP and flash storage for SPDM authorization credentials:

**Recovery Credential (Credential ID 0)**:
- Used exclusively for emergency recovery via factory reset. Since operational credentials (IDs 1-3) are stored in flash as a [CRED_BLOB](#cred-blob-structure), this recovery credential enables wiping the flash credential blob when it becomes corrupted or needs to be reset. The recovery credential can only execute `AUTH_RESET_TO_DEFAULT` to return the device to default state, allowing reprovisioning from scratch.
- **Production Lifecycle**: Vendor-controlled key provisioned in OTP during manufacturing
  - Only vendor public key hash stored in OTP (48 bytes for SHA-384 hash in `VENDOR_NON_SECRET_PROD_PARTITION`)
  - Full vendor public key carried in firmware flash and verified against OTP hash at boot
  - Locked and immutable (cannot be modified after manufacturing)
- **Non-Production Lifecycle** (TestUnlocked, TestLocked, Manufacturing, RMA, Scrap): Well-known credential stored in flash [CRED_BLOB](#cred-blob-structure)
  - Firmware maintains an in-memory slot for Credential ID 0
  - At boot, Credential ID 0 is populated from [CRED_BLOB](#cred-blob-structure) if present
  - If no Credential ID 0 exists in CRED_BLOB, authorization operations requiring it will fail
  - Enables testing of authorization recovery flows without production PKI
  - **Note**: "Well-known" refers to publicly documented test keys for non-production use only. These credentials are disabled and unusable in Production lifecycle - Production uses vendor-specific keys in OTP instead.
  - **Note**: Integrator may choose to bypass authorization checks entirely in these lifecycles
- Metadata (algorithms, attributes, policies) is implicit and recreated at boot:
  - BaseAsymAlgo: ECDSA P-384 (fixed)
  - BaseHashAlgo: SHA-384 (fixed)
  - Recovery privilege only:
    - `ResetToDefaultsPrivilege` - can execute `AUTH_RESET_TO_DEFAULT` to factory reset and wipe flash CRED_BLOB

**Operational Credentials - Flash Storage with HMAC Authentication**:
- **Production Lifecycle** (Production, Prod[End], ProdDebugUnlock): Credential IDs 1-3 stored in flash [CRED_BLOB](#cred-blob-structure)
  - Credential ID 1: Vendor (maps to SPDM Certificate Slot 0)
  - Credential ID 2: Owner (maps to SPDM Certificate Slot 2)
  - Credential ID 3: Tenant (maps to SPDM Certificate Slot 3)
  - Credential ID 0 stored separately in OTP
- **Non-Production Lifecycle** (TestUnlocked, TestLocked, Manufacturing, RMA, Scrap): Credential IDs 0-3 stored in flash [CRED_BLOB](#cred-blob-structure)
  - Credential ID 0: Recovery/Admin (well-known - publicly documented test key)
  - Credential ID 1: Vendor (well-known - publicly documented test key, maps to SPDM Certificate Slot 0)
  - Credential ID 2: Owner (well-known - publicly documented test key, maps to SPDM Certificate Slot 2)
  - Credential ID 3: Tenant (well-known - publicly documented test key, maps to SPDM Certificate Slot 3)
  - **Note**: Well-known credentials are only used in non-production lifecycles and are disabled in Production
  - Integrator may bypass authorization checks in non-production lifecycles

**Initial Provisioning (Before TAKE_OWNERSHIP)**:
- In default state (before `TAKE_OWNERSHIP` is sent), authorization is not enforced for unlocked credentials per DSP0289
- Credential IDs 1, 2, 3 can be provisioned via `SET_CRED_ID_PARAMS` with any authorization privileges they require (e.g., `SetCertPrivilege`, `ModifyOtherCredentialParamPrivilege`, `SetAuthPolicyPrivilege`, etc.)
- Authorization policies for each credential can be configured via `SET_AUTH_POLICY` without authorization checks
- Once `TAKE_OWNERSHIP` is sent, authorization is fully enforced and credentials can only perform operations granted by their provisioned policies

Credentials are stored in SPI flash with HMAC-based cryptographic authentication, similar to the DOT (Device Ownership Transfer) BLOB scheme.

#### CRED_BLOB Structure

The CRED_BLOB is an HMAC-authenticated data structure stored in flash that contains authorization credentials along with their policies and a cryptographic seal to prevent tampering.

```
CRED_BLOB = {
    version: u8,
    credential_count: u8,     // Production: Count = 3 (IDs 1-3)
                              // Non-Production: Count = 4 (IDs 0-3)
    reserved: [u8; 2],
    credentials: [CredentialStructure],  // Variable length based on credential_count
    policy: AuthorizationPolicy,         // See definition below
    hmac_tag: [u8; 64]  // HMAC-SHA-512 tag (see BLOB Sealing below)
}
```

Note: In Production lifecycle, Credential ID 0 (recovery) is stored in OTP and not included in CRED_BLOB. In Non-Production lifecycle, Credential ID 0 is included in CRED_BLOB and loaded into an in-memory slot at boot.

#### CredentialStructure

A CredentialStructure contains the public key and algorithm identifiers for a single authorization credential.

```
CredentialStructure = {
    credential_id: u16,       // 1=Vendor, 2=Owner, 3=Tenant
    credential_type: u8,      // 0x01 = Asymmetric Key
    base_asym_algo: [u8; N],  // Algorithm bitmask (ECDSA P-384)
    base_hash_algo: [u8; N],  // Hash algorithm bitmask (SHA-384)
    credential_data_size: u32,
    credential_data: [u8],    // Public key in SubjectPublicKeyInfo DER format
}
```

#### AuthorizationPolicy

An AuthorizationPolicy defines the privilege bits for each credential, controlling which operations (certificate provisioning, policy modification, etc.) the credential is authorized to perform.

```
AuthorizationPolicy = {
    dsp274_policy: [u8; 1],   // Privilege bits (SetCertPrivilege, etc.)
    // Separate policy for each credential ID
}
```

*Authentication Scheme* (Based on DOT):

#### Key Derivation

**CRED_ROOT_KEY**: The root cryptographic key derived from the device's DICE layer (LDevID CDI), used as input for deriving the credential effective key.

**CRED_EFFECTIVE_KEY**: The effective key derived from CRED_ROOT_KEY and the anti-rollback fuse counter, used to compute the HMAC authentication tag that seals the CRED_BLOB.

```
CRED_ROOT_KEY = KDF(
    LDevID_CDI,           // Derived from UDS + Field Entropy by Caliptra Core (DICE layer)
    "SPDM_AUTH_CRED"      // Domain separation constant
)

CRED_EFFECTIVE_KEY = KDF(
    CRED_ROOT_KEY,        // Derived from LDevID CDI (no OTP storage needed)
    CRED_FUSE_ARRAY_VALUE // Fuse-based counter for anti-rollback (same as DOT)
)
```

#### BLOB Sealing

**HMAC_TAG**: The HMAC-SHA-512 authentication tag computed over the CRED_BLOB contents (excluding the tag itself) using the CRED_EFFECTIVE_KEY, providing cryptographic integrity protection and binding the BLOB to the device and its fuse state.

```
HMAC_TAG = HMAC-SHA-512(
    CRED_EFFECTIVE_KEY,
    CRED_BLOB[0:size-64]   // All fields except HMAC tag
)
```

**Differences from DOT BLOB HMAC Scheme**: The credential blob authentication scheme is identical to DOT's approach. Both use a fuse-based counter (CRED_FUSE_ARRAY for credentials, DOT_FUSE_ARRAY for DOT) in [effective key derivation](#key-derivation), HMAC-SHA-512 for sealing, and derive their [root keys](#key-derivation) from Caliptra's DICE CDI (IDevID or LDevID) with different domain separation labels. Similarly, the CRED_BLOB is authenticated with [CRED_EFFECTIVE_KEY](#key-derivation) before first use of authorization credentials.

**Notes**: OTP storage is minimal (48 bytes for vendor key hash), with full public key carried in firmware flash and verified at boot. Flash wear from credential updates can be mitigated through rate limiting of `SET_CRED_ID_PARAMS` operations. If [HMAC](#blob-sealing) verification fails (credentials tampered or corrupted), the OTP recovery credential (Cred ID 0) provides a vendor-controlled recovery path via `AUTH_RESET_TO_DEFAULT` to factory reset the device, eliminating the need for external backup mechanisms. Flash bit rot risk can be minimized by storing redundant credential BLOBs in flash. Fuse consumption for the anti-rollback counter (CRED_FUSE_ARRAY) limits the total number of credential updates over device lifetime (1 bit per update). If using LDevID CDI for [CRED_ROOT_KEY](#key-derivation) derivation, updating field entropy (4 slots: CPTRA_CORE_FIELD_ENTROPY_0-3 in SECRET_PROD_PARTITION_0-3) requires re-sealing the credential BLOB with the new LDevID CDI value, similar to DOT's field entropy recovery flow.

**Recovery Flow Using Recovery Credential**:

When flash [CRED_BLOB](#cred-blob-structure) is corrupted, lost, or needs factory reset:

1. **Detection**: [HMAC](#blob-sealing) verification of CRED_BLOB fails at boot, or explicit recovery request
2. **Recovery Mode**:
   - Production: Device boots with Credential ID 0 from OTP, Credential IDs 1-3 unavailable
   - Non-Production: Device boots without any credentials if CRED_BLOB is invalid (Credential ID 0 in-memory slot empty)
3. **Vendor Authentication**:
   - Production: Vendor uses recovery credential (Credential ID 0) from OTP to authenticate
   - Non-Production: If CRED_BLOB is completely corrupted, recovery requires re-provisioning CRED_BLOB with well-known credentials via out-of-band mechanism
4. **Factory Reset**: Vendor issues `AUTH_RESET_TO_DEFAULT` command with:
   - `DataType.CredIDParams = 1` (reset credential parameters)
   - `DataType.AuthPolicy = 1` (reset authorization policies)
   - `CredentialID = 0xFFFF` (all unlocked credentials)
5. **Result**: Flash CRED_BLOB wiped, OTP preserved, device returns to default state
   - Production: Credential ID 0 in OTP unchanged, flash CRED_BLOB cleared (only IDs 1-3 were in CRED_BLOB)
   - Non-Production: Flash CRED_BLOB completely cleared (IDs 0-3 removed), Credential ID 0 in-memory slot becomes empty
6. **Reprovisioning**:
   - Production: Owner/Tenant can provision new credentials (IDs 1-3) via normal flow using recovery credential (ID 0)
   - Non-Production: Well-known credentials (IDs 0-3) must be re-provisioned to CRED_BLOB

This recovery mechanism is **pure DSP0289** - leveraging locked credentials with `ResetToDefaultsPrivilege` as defined by the specification, requiring no custom recovery commands. Optionally, custom commands can be implemented to read out the current [credential BLOB](#cred-blob-structure) and provision it back, allowing an off-device entity to maintain backup credentials and recover without resetting to default and reprovisioning; this would be exactly like the DOT recovery flow in terms of security (BMC maintains backup DOT_BLOB externally and uses DOT_RECOVERY command to restore it when the flash copy is corrupted, authenticating with [DOT_EFFECTIVE_KEY](#key-derivation) - analogous to CRED_EFFECTIVE_KEY for credentials).

#### Default/Initial Values for Reset Operations Detailed Analysis

DSP0289 defines a "default state" (before `TAKE_OWNERSHIP`) where authorization is not enforced for unlocked credentials, and `AUTH_RESET_TO_DEFAULT` can return the device to this state or selectively reset specific credentials/policies.

**Caliptra Default State Definition**

Caliptra's default state is lifecycle-aware, with different behavior for Production and Non-Production lifecycles:

*Production Lifecycle (Production, Prod[End], ProdDebugUnlock)*:
- **Credential ID 0 (Recovery)**: Stored in OTP, locked and immutable
  - Hash stored in OTP, full public key in firmware flash
  - Recovery privilege only (immutable):
    - `ResetToDefaultsPrivilege = 1`
- **Credential IDs 1-3 (Vendor, Owner, Tenant)**: Not provisioned in flash [CRED_BLOB](#cred-blob-structure) (empty/cleared)
- **Authorization Policies**: All operational credential policies cleared (all privilege bits = 0)
- **Authorization Enforcement**: Not enforced until `TAKE_OWNERSHIP`

*Non-Production Lifecycle (TestUnlocked, TestLocked, Manufacturing, RMA, Scrap)*:
- **Credential ID 0 (Recovery)**: Well-known credential in flash [CRED_BLOB](#cred-blob-structure), loaded into in-memory slot at boot
  - If not present in CRED_BLOB, authorization operations requiring it fail
  - Recovery privilege only (same as production)
- **Credential IDs 1-3 (Vendor, Owner, Tenant)**: Well-known test credentials in flash [CRED_BLOB](#cred-blob-structure)
- **Authorization Policies**: All credential policies cleared (all privilege bits = 0)
- **Authorization Enforcement**: Not enforced (default state)
- **Note**: Integrator may choose to bypass authorization checks entirely in non-production lifecycles

**AUTH_RESET_TO_DEFAULT Behavior**

`AUTH_RESET_TO_DEFAULT` operates uniformly across all lifecycles:
- **Flash Operation**: Wipes out the [CRED_BLOB](#cred-blob-structure) in flash
  - Production: Clears Credential IDs 1-3 and their policies (CRED_BLOB becomes empty)
  - Non-Production: Clears Credential IDs 0-3 and their policies (CRED_BLOB becomes empty)
- **Fuse/OTP Preservation**: Leaves OTP untouched
  - Production: Credential ID 0 hash in OTP is preserved
  - Non-Production: OTP is preserved (typically empty or contains test data)
- **Result**: Device returns to default state
  - Production: Empty flash CRED_BLOB, Credential ID 0 hash remains in OTP, firmware can still use recovery credential
  - Non-Production: Empty flash CRED_BLOB, Credential ID 0 in-memory slot becomes empty (authorization requiring it will fail until re-provisioned)
- **Selective Reset**: Can selectively reset specific data types (credentials, policies) for specific Credential IDs while remaining in Owned state


#### Authorization Session Handling

**Note**: Caliptra implements only USAP (User-Specific Authorization Process), not SEAP (SPDM Endpoint Authorization Process).

#### Credential Algorithm Support

Caliptra supports ECDSA P-384 for asymmetric signatures and SHA-384/SHA-512 for hashing, all of which have hardware acceleration support. Post-quantum cryptography (PQC) support is not yet available in the SPDM Authorization specification.

#### Rate Limiting for Credential Operations Detailed Analysis

Rate limiting is implicitly provided by the `CRED_FUSE_ARRAY` anti-rollback mechanism, which burns one fuse bit per credential BLOB update. The finite size of the fuse array provides a hardware-enforced lifetime limit on the total number of credential updates, similar to DOT's approach with `DOT_FUSE_ARRAY`.


#### Credential Locking Attributes

Caliptra implements the following credential locking support per DSP0289:

- **Credential ID 0** (Recovery): `Lockable=1`, `Unlockable=0`
  - Stored in OTP (Production) or flash (Non-Production)
  - Locked and immutable after provisioning
  - Cannot be unlocked via `SET_CRED_ID_PARAMS` Unlock operation

- **Credential IDs 1-3** (Vendor, Owner, Tenant): `Lockable=0`, `Unlockable=0`
  - Stored in flash CRED_BLOB
  - Cannot be locked via `SET_CRED_ID_PARAMS` Lock operation
  - Always remain modifiable (with proper authorization privileges)

#### Recovery from Misconfigured Privilege Restrictions

DSP0289 acknowledges that Owners can misconfigure authorization policies, but states "recovery from such a state is outside the scope of this specification."

Caliptra's design minimizes this risk:
- **Prevention**: Credentials 1-3 are not lockable (`Lockable=0`), so misconfigurations can be corrected with proper authorization
- **Expected Usage**: Owner provisions Credential ID 2 with full administrative privileges (SetAuthPolicyPrivilege, ModifyOtherCredentialParamPrivilege, SetCertPrivilege), enabling self-recovery from most misconfigurations
- **Recovery**: If Owner loses all administrative privileges across all credentials, Vendor can use Credential ID 0 (OTP) with `AUTH_RESET_TO_DEFAULT` to factory reset and return to default state for reprovisioning

**Best Practice**: Before sending `TAKE_OWNERSHIP`, verify that at least one credential (typically Credential ID 2 - Owner) has `SetAuthPolicyPrivilege` to enable policy corrections after ownership is taken.

## Optional Enhancements

### Audit Logging

Audit logging for SPDM authorization operations can be implemented using Caliptra's existing logging infrastructure to track security-relevant events such as authorization session establishment (`START_AUTH`/`END_AUTH`), credential provisioning operations (`SET_CRED_ID_PARAMS`, `SET_CERTIFICATE`), policy changes (`SET_AUTH_POLICY`, `TAKE_OWNERSHIP`, `AUTH_RESET_TO_DEFAULT`), and authorization failures (authentication failures, privilege denials, rate limit exceeded, fuse exhaustion). Logs would be stored in a dedicated flash partition using the generic log entry format defined in `docs/src/logging.md`, with entries containing event type, credential ID, result status, and timestamp. Access to audit logs can be provided via SPDM vendor-defined commands or out-of-band interfaces (UART, JTAG in debug lifecycles), with appropriate access controls to ensure only authorized entities can retrieve log data.


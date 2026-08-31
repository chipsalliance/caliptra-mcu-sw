# rt-sdk-2.0.0

## Caliptra MCU Runtime SDK 2.0.0 Release Notes

This is the initial release of the MCU Runtime SDK for Caliptra 2.0. It provides
a Rust-based reference Root of Trust runtime built on Tock, including reusable
capsules, hardware-abstraction interfaces, reference drivers, userspace APIs,
protocol stacks, reference applications, and host tooling.

The SDK includes emulator and FPGA reference platforms that integrators can
adapt to their SoC-specific hardware and security policies.

### Features

- **Tock-based runtime architecture**:
  - Separates privileged machine-mode boards and hardware drivers from reusable
    capsules and isolated userspace applications.
  - Provides hardware-abstraction interfaces and reference platform drivers for
    I3C, DOE, DMA, flash, external OTP, and mailbox-backed transports.
  - Provides reusable capsules for MCTP, DOE, mailbox access, OTP, external OTP,
    logging, and flash partitions and storage. Integrators can bind these
    capsules to vendor-specific drivers.
  - Provides synchronous and asynchronous Rust APIs for Caliptra services.
- **Caliptra command services**:
  - Provides common Caliptra command handling over the MCI mailbox and SPDM VDM,
    with SPDM transported over MCTP or DOE.
  - Provides direct MCTP VDM services for supported vendor-defined commands.
  - Supports firmware version, device capabilities, attestation, debug logging,
    production debug unlock, Caliptra CSR retrieval, IDevID certificate
    population, and cryptographic operations.
  - Supports chunked and streaming requests for commands larger than the
    transport buffer.
- **Authenticated provisioning and ownership**:
  - Provides challenge-response authorization using ECDSA P-384/SHA-384 and
    ML-DSA-87/SHA-512.
  - Supports Field Entropy provisioning, minimum SVN updates, fuse locking,
    owner and vendor public-key hash provisioning, rotation, and revocation.
  - Exposes Device Ownership Transfer commands through the MCI mailbox and SPDM
    VDM.
  - Supports external OTP storage for ECDSA and ML-DSA IDevID certificates.
  - Zeroizes sensitive key material after use.
- **Attestation and measurements**:
  - Supports integrator-owned attestation manifests describing platform
    identity and SoC firmware measurements.
  - Provides DPE-backed TCB measurements and software-PCR-backed non-TCB
    measurements.
  - Provides production OCP EAT evidence through first-class SPDM measurements
    and the Caliptra `GET_ATTESTATION` command over the MCI mailbox and SPDM VDM.
  - Supports optional PCR Quote evidence through the same evidence framework.
  - Preserves and validates measurement state across cold boot and hitless
    firmware updates.
- **SPDM, MCTP, DOE, and certificates**:
  - Provides a feature-gated SPDM runtime stack with certificate-slot
    management, algorithm negotiation, secured sessions, large-message
    handling, and MCTP and DOE transports.
  - Reuses the Caliptra VDM command implementation in the SPDM stack and
    supports streaming production debug unlock.
  - Supports read-only vendor and managed flash-backed owner and tenant
    endorsement certificate slots.
  - Includes feature-gated `SET_CERTIFICATE` support. The tagged reference
    applications enable it only for testing; production integrations must
    provide authorization and key-binding policy.
  - Adds MCTP endpoint UUID and vendor-defined message support discovery,
    advertises the MCTP DCR on I3C targets, and validates MCTP operation after
    warm reset.
  - Provides a platform-neutral DOE transport HIL and capsule plus an emulator
    DOE-mailbox reference driver. Integrators supply their platform-specific
    PCIe DOE hardware integration.
- **Firmware update and image loading**:
  - Provides PLDM Type 5 firmware update with a single combined flash-image
    component containing embedded Caliptra FMC and Runtime, MCU Runtime, and
    optional SoC firmware subcomponents.
  - Supports flash boot, streaming boot, update restart, and hitless activation.
  - Authenticates SoC images through Caliptra Core against the SoC manifest.
  - Provides platform hooks for authorization, component loading, activation,
    and flash-wear protection.
- **Logging and diagnostics**:
  - Provides `defmt`-based userspace logging with release-build support.
  - Supports persistent flash and volatile RAM backends with multiple log
    instances.
  - Supports log retrieval and clearing through the MCI mailbox and MCTP VDM.
  - Tracks image, stack, and SRAM sizes for runtime configurations.
- **Build and signing tools**:
  - Supports offline authorization-manifest generation, signing, and signature
    attachment.
  - Supports ECDSA P-384, LMS, and ML-DSA-87 signing with optional OpenSSL
    provider and HSM integration.
  - Provides firmware-bundle vendor and owner public-key hash inspection and
    verification.
  - Provides development and release build profiles with feature-selected
    runtime images.

### Notes for integrators

This is a source-oriented SDK release. Integrators select the required
production features and provide platform-specific boards, drivers, storage
layouts, authorization policies, and security configuration.

**Full Changelog**:
[rom-sdk-2.0.0...rt-sdk-2.0.0](https://github.com/chipsalliance/caliptra-mcu-sw/compare/rom-sdk-2.0.0...rt-sdk-2.0.0)

# rom-sdk-2.0.1

## Caliptra MCU ROM SDK 2.0.1 Release Notes

Release notes for changes introduced since ROM SDK 2.0.0 (`af221b7`) through
`7cb0e55` on the `main` branch.

This is a reference source release. No prebuilt binaries are included.

### Features

- **SVN anti-rollback**:
  - Adds MCU-side anti-rollback fuse support and the MCU Component SVN Manifest
    format (#1476).
  - Adds optional ROM parsing and enforcement of the MCU Component SVN Manifest
    (#1521).
  - Supports burning Caliptra-owned SVN floors from the authenticated MCU
    Runtime SVN header (#1612).
- **Device Ownership Transfer**:
  - Processes the DOT header during firmware-update flows (#1292).
  - Installs the owner public-key hash through the Caliptra mailbox and adds a
    policy for forcing the fused owner (#1584).
  - Adds DOT recovery-reset coordination (#1695).
- **Fuse and OTP integration**:
  - Moves public-key-hash provisioning straps to MCI generic input wires
    (#1459).
  - Adds the OTP status-register offset to `SS_STRAP_GENERIC[0]` (#1622).
  - Uses RTL-provided DAI granules for generic OTP reads (#1657).
  - Moves monotonic bit-count anti-rollback fuses using `OneHot*` layout names
    to the `VENDOR_TEST` partition (#1745).
- **ROM and platform integration**:
  - Adds configurable primary and secondary I3C timing parameters to
    `RomParameters` (#1598).
  - Adds development and release build profiles (#1442).
  - Adds ROM size reporting and enforces ROM size budgets during precheckin
    (#1473).
  - Allows builds to override the Caliptra Core ROM source reference (#1735).

### Fixes

- Align the DOT recovery public-key hash with the Caliptra fuse layout (#1448).
- Correctly acknowledge mailbox status after DOT override (#1659).
- Program the FIPS zeroization mask before locking MCI configuration (#1635).
- Correct the default `FW_SRAM_EXEC_REGION_SIZE` calculation (#1428).
- Remove additional panic paths from the ROM implementation (#1484).

### Notes for integrators

`RomParameters` adds the following integration controls:

- `owner_pk_hash_policy`
- `svn_manifest_enabled`
- `svn_fuse_map`
- `dot_recovery_reset_flow`
- `fips_zeroization_mask`
- `i3c_timings`
- `i3c1_timings`

Integrators constructing `RomParameters` directly should review these additions.
Defaults preserve opt-in behavior where applicable.

Integrators should also review the updated fuse layout, particularly the
relocation of monotonic bit-count fuses to the `VENDOR_TEST` partition.

The Caliptra Core Rust dependencies are pinned to commit `852385c`. CI uses
Caliptra Core ROM reference `rom-2.0.3-1`.

### Validation

The release commit passed the ROM SDK build, emulator tests, release-profile
tests, reproducible-build check, and FPGA tests.

**Full Changelog**:
[rom-sdk-2.0.0...rom-sdk-2.0.1](https://github.com/chipsalliance/caliptra-mcu-sw/compare/rom-sdk-2.0.0...rom-sdk-2.0.1)

# rom-sdk-2.0.0

## Caliptra MCU ROM SDK 2.0.0 Release Notes

This is the initial release of the MCU ROM SDK for Caliptra 2.0. It provides a
platform-independent, `no_std` RISC-V ROM library
(`caliptra-mcu-rom-common`) that integrators use to build their platform ROM.
Integrators call `rom_start(params)` with a `RomParameters` structure to
customize ROM behavior for their SoC.

The ROM targets `riscv32imc-unknown-none-elf`. The SDK checks that the ROM is
panic-free when compiled for the reference emulator and FPGA platforms.

### Features

- **Reset-driven boot dispatcher**:
  - `rom_start` reads the MCI `RESET_REASON` and dispatches to cold boot, warm
    boot, firmware boot, or firmware hitless update.
  - Each reset-selected path implements the common `BootFlow` interface.
- **Caliptra Core orchestration**:
  - Waits for boot-FSM, ready-for-fuses, ready-for-Runtime, and firmware-ready
    signaling.
  - Programs Caliptra fuses from OTP, including vendor public-key hashes, PQC
    key type, FMC and Runtime SVNs, SoC-manifest SVN, anti-rollback settings,
    stepping ID, IDevID attributes, manufacturing debug-unlock token, and ECC,
    LMS, and ML-DSA revocation.
  - Configures the iTRNG entropy source and Caliptra watchdog timers.
  - Sets and locks valid AXI users for Caliptra mailbox, fuse, TRNG, and DMA
    interfaces.
- **Security lifecycle and debug unlock**:
  - Supports lifecycle transitions and lifecycle-token burning assistance.
  - Programs the production debug-unlock public-key hash into MCI and verifies
    it against OTP after locking.
  - Programs `SS_NUM_OF_PROD_DEBUG_UNLOCK_AUTH_PK_HASHES`.
  - Provides a pluggable `VendorKeyPolicy` interface for vendor public-key slot
    selection and rotation.
- **Device Ownership Transfer**:
  - Provides the DOT flow with stable-key derivation using IDevID or LDevID and
    owner public-key-hash programming and locking.
  - Supports backup-blob recovery for corrupted DOT blobs through
    `DotRecoveryPolicy` and ordered integrator-supplied locked-state recovery
    handlers through `DotLockedRecoveryEntry`.
  - Supports DOT override challenge and response over MCI mailbox 0 using ECC
    P-384 or ML-DSA-87.
  - Optionally processes a firmware-manifest DOT section during firmware boot.
- **I3C services mailbox**:
  - Provides packetized I3C transport with IBI-driven notifications.
  - Supports `PING`, `DOT_STATUS`, `DOT_RECOVERY`, `DOT_UNLOCK_CHALLENGE`, and
    `DOT_OVERRIDE` commands.
  - Enters the service on demand or unconditionally through
    `force_i3c_services`.
- **Image verification**:
  - Provides the `ImageVerifier` interface so integrators can enforce
    header-format-specific authenticity and OTP policy checks.
- **OTP services**:
  - Integrates the OTP driver with optional integrity and consistency checks.
  - Provides software-digest calculation and write-and-lock helpers using an
    integrator-supplied digest IV and constant.
  - Supports volatile vendor public-key-slot locking.
- **Integrator extension points**:
  - Provides `RomHooks` callbacks around cold, warm, firmware, and hitless boot,
    Caliptra boot-go, fuse population, and firmware loading.
  - Exposes AXI users, watchdog timeouts, SRAM executable-region size, Field
    Entropy programming, and other settings through `RomParameters`.
  - Provides a `FatalErrorHandler` interface and reports fatal errors through
    the MCI fatal-error register.
  - Reports flow checkpoints and boot milestones through MCI.

### Feature flags

- `fw-manifest-dot` enables firmware-manifest DOT command processing during
  firmware boot.
- `core_test` enables internal test hooks.

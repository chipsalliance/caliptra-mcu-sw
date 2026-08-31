# rt-sdk-2.1.0

## Caliptra MCU Runtime SDK 2.1.0 Release Notes

This is the initial release of the MCU Runtime SDK for Caliptra 2.1. It provides
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
  - Adds configurable MCTP endpoint UUID and vendor-defined message support
    discovery, advertises the MCTP DCR on I3C targets, and validates MCTP
    operation after warm reset.
  - Provides a platform-neutral DOE transport HIL and capsule plus an emulator
    DOE-mailbox reference driver. Integrators supply their platform-specific
    PCIe DOE hardware integration.
- **Firmware update and image loading**:
  - Provides PLDM Type 5 firmware update for the combined flash image containing
    Caliptra FMC and Runtime, MCU Runtime, and optional SoC firmware images.
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
- **OCP LOCK and epoch-key services**:
  - Uses the HEK slot state discovered by ROM and handed off to Runtime.
  - Generates X.509 HPKE endorsement certificates for ECDH P-384, ML-KEM-1024,
    and hybrid ML-KEM-1024/ECDH P-384 keys.
  - Provides commands for retrieving HPKE endorsement certificates, DPE signer
    context certificates, and nonce-bound epoch-key attestation reports.
  - Uses an exported CDI context for DPE-backed signing and retains its opaque
    handle in reserved SRAM.
  - Supports authorized HEK rotation and permanent-HEK state operations.
- **Runtime APIs and platform support**:
  - Adds the consolidated `caliptra-libapi` for certificate, cryptographic,
    evidence, signing, and OCP LOCK operations.
  - Adds a reusable DMA capsule HIL for integration with platform-specific DMA
    engines.
  - Adds a manufacturing fuse-provisioning firmware image.
  - Adds production feature gating and reduces all-features FPGA SRAM usage.
  - Expands sensitive-material zeroization and scratch-backed Runtime APIs.

### Notes for integrators

This is a source-oriented SDK release. Integrators select the required
production features and provide platform-specific boards, drivers, storage
layouts, authorization policies, and security configuration.

OCP LOCK requires the corresponding Caliptra 2.1 hardware and firmware support,
platform KMB policy, certificates, OTP layout, and key-release integration.

**Full Changelog**:
[rom-sdk-2.1.0...rt-sdk-2.1.0](https://github.com/chipsalliance/caliptra-mcu-sw/compare/rom-sdk-2.1.0...rt-sdk-2.1.0)

# rom-sdk-2.1.0

## Caliptra MCU ROM SDK 2.1.0 Release Notes

Release notes for changes introduced since ROM SDK 2.0.0 (`af221b7`) through
`da45122` on the `main-2.1` branch. This section consolidates the capabilities
first published in `rom-sdk-2.1.0rc1` with the changes included in the final
2.1.0 release.

The MCU ROM SDK is a platform-independent, `no_std` RISC-V ROM library
(`caliptra-mcu-rom-common`) that integrators can use to build their platform ROM.
Integrators call `rom_start(params)` with a `RomParameters` structure to
customize ROM behavior for their SoC.

### Features

- **OCP LOCK**:
  - Adds ROM-side support for OCP LOCK key release, including programming and
    masking the Caliptra HEK seed slots, configuring the key-release destination,
    and tracking the HEK permanent-state bit through OTP.
  - Adds `RomConfig::get_active_slot` so integrators can implement an HEK
    slot-selection policy using the reported permanent, programmed, sanitized,
    corrupted, pending, and unused slot states.
  - Issues `REPORT_HEK_METADATA` after fuse programming so Caliptra Runtime can
    report HEK availability to firmware.
  - Enables the flow through the `ocp-lock` feature on
    `caliptra-mcu-rom-common`.
- **Stable owner-key derivation**:
  - Adds the `stable-owner-key` feature to derive a deterministic stable owner
    key from the OTP personalization seed during cold boot.
  - The `stable-owner-key` and `ocp-lock` features are mutually exclusive.
- **Encrypted firmware boot**:
  - Adds an encrypted cold-boot flow using
    `RI_DOWNLOAD_ENCRYPTED_FIRMWARE`, `GET_MCU_FW_SIZE`, `CM_IMPORT`, and
    `CM_AES_GCM_DECRYPT_DMA` to authenticate and decrypt MCU firmware in place.
  - Uses `ACTIVATE_FIRMWARE` with `INITIAL_ACTIVATE` to publish the MCU firmware
    execution state without a hitless-update sequence.
- **FIPS zeroization**:
  - Detects the platform PPD signal during cold boot and programs the FIPS
    zeroization mask before locking MCI configuration.
  - Requests zeroization of UDS and all Field Entropy partitions, transitions
    the lifecycle controller to SCRAP, and waits for cold reset.
  - Reports zeroization checkpoints through MCI for integrator observability.
- **Recovery and image loading**:
  - Adds the `ImageProvider` interface and `ImageProviderManager` so integrators
    can register multiple firmware sources, including flash, USB, or custom
    providers.
  - Supports `Continue`, bounded `Retry(n)`, and `RetryForever` error policies
    for image providers.
- **Device Ownership Transfer and owner-key handling**:
  - Adds DOT recovery-reset coordination and force-fused-owner recovery policy
    support.
  - Installs the selected owner public-key hash through the Caliptra mailbox
    after fuse write completion.
  - Aligns the DOT recovery public-key hash with the Caliptra fuse layout and
    documents ownership RAM and DOT handoff guidance.
- **Fuse and Field Entropy handling**:
  - Adds vendor-fuse tracking for Field Entropy partition state and moves that
    state to a non-ECC-protected partition.
  - Reserves FPGA fuse fields for UDS and Field Entropy programming.
  - Moves monotonic bit-count fuses using `OneHot*` layout names to the
    `VENDOR_TEST` partition where appropriate.
  - Clarifies that these layouts use thermometer-style encoding, while
    revocation and validity fields are bitmasks rather than counters.
- **SVN anti-rollback**:
  - Adds MCU Component SVN Manifest parsing and validation, MCU-owned SVN fuse
    floors, and per-component SoC image SVN floor mapping through `SVN_FUSE_MAP`.
  - Supports burning the Caliptra Runtime and SoC-manifest SVN floors from the
    authenticated MCU Runtime SVN header.
  - Documents that Caliptra fuse registers are latched during cold-boot fuse
    transfer, so later OTP burns affect Caliptra authentication on the next cold
    boot.
- **ROM hardening and boot observability**:
  - Adds preliminary control-flow-integrity hardening.
  - Adds ROM milestone hooks, unique ROM error codes, and expanded boot and
    status reporting.
  - Removes panic paths from the reference ROM implementation.
- **Build and reference-platform support**:
  - Adds development and release build profiles for ROM consumers.
  - Adds `xtask sizes`, broader ROM-variant size reporting, and ROM size-budget
    checks.
  - Adds configurable primary and secondary I3C timing parameters and improves
    FPGA ROM build and test integration.
  - Adds a TestUnlocked provisioning binary for ROM and platform validation
    flows.
- **Documentation**:
  - Expands integrator guidance for DOT recovery and storage, SVN anti-rollback,
    fuse partition planning, management-command transports, vendor-key rotation
    and revocation, and ROM milestone hooks.
  - Adds OCP LOCK integration guidance and updates ROM fuse documentation,
    including the recovery public-key hash format and bit-count fuse behavior.

### Fixes

- Fix HEK OTP digest handling and zeroization-entry reads.
- Correctly acknowledge mailbox status after DOT override.
- Program the FIPS zeroization mask before MCI configuration is locked.
- Correct the default MCU firmware SRAM executable-region size calculation.
- Remove additional panic paths and resolve ROM lint issues.

### Notes for integrators

- This is a source-oriented SDK release. Integrators build their platform ROM
  from the SDK using platform-specific `RomParameters`.
- Caliptra Core fuse registers are latched during the cold-boot fuse-write phase.
  Fuse burns performed after that point affect Caliptra authentication on the
  next cold boot.
- Several flows require platform policy, including DOT recovery, vendor-key
  rotation, OCP LOCK HEK slot selection, Field Entropy provisioning, and
  persistent SRAM and attestation-storage sizing.
- Integrators constructing `RomParameters` directly should review the new 2.1
  controls and the updated fuse layout.

**Full Changelog**:
[rom-sdk-2.0.0...rom-sdk-2.1.0](https://github.com/chipsalliance/caliptra-mcu-sw/compare/rom-sdk-2.0.0...rom-sdk-2.1.0)

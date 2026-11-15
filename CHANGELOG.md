# rt-sdk-2.1.1

## Caliptra MCU Runtime SDK 2.1.1 Release Notes

Release notes for changes introduced since Runtime SDK 2.1.0.

### Features

- **SPDM**:
  - Add SPDM 1.4 `VERSION`, `CAPABILITIES`, and `ALGORITHMS` support (#1857)
  - Support SPDM 1.4 VDM and `LARGE_RESP`, including large VDM fields in the codec (#2094)
  - Support large offset/length in `CERTIFICATE` responses (#2019)
  - Support ML-DSA-87 asymmetric algorithm in spdm-lib; cache cert chain digests and DPE skip lengths (#2061)
  - Add ML-DSA cert-store signing and separate streamed vs. buffered message limits (#2064)
  - Support ML-DSA-87 signing for `CHALLENGE_AUTH` and `MEASUREMENTS` (#2113)
  - Install the ML-DSA-87 IDevID certificate into Caliptra (#2009)
  - Serve per-algorithm certificate chains from managed cert slots (#2100)
  - Add `set_dpe_only_slot()` for DPE-only certificate chains (#2011)
  - Support ML-KEM in SPDM 1.4 `KEY_EXCHANGE` (#2080)
  - Allow multiple opaque data elements in `KEY_EXCHANGE` requests (#2207)
- **Attestation & Certificates**:
  - Support ML-DSA-87 signed OCP EAT tokens (#2139)
  - Provision IDevID certificates during boot (#2016)
  - Support attested CSR keypair inventory discovery and ML-DSA-87 buffer sizing (#2123)
  - Gate attested CSR export behind an opt-in `attested-csr` feature (#2186)
- **Ownership, Authorization & Manifests**:
  - Add Owner Authorization Manifest support: mailbox commands (#2097), flash layout (#2107), builder (#2110), and installation during image loading (#2119)
  - Add Owner Attestation Manifest and policy packaging; measure Owner artifacts and Vendor Authorization Key on cold boot and hitless update (#2160)
  - Persist Owner SoC Manifest minimum SVN (#2175)
  - Make minimum SVN command target-aware (#2124)
  - Unify MCI and SPDM authorized command envelope (#2189)
  - Add SPDM-VDM support for OCP LOCK authorized commands (#2101)
  - Add DOT enable command support (#2109)
- **OCP LOCK**:
  - Support ML-DSA keys from DPE for endorsement certificates (#2005)
  - Support and verify ML-DSA signatures from DPE for EKP reports (#2063)
  - Nest OCP LOCK command codes (#2118)
- **Caliptra API & Commands**:
  - Add `DpeProfile` support to DPE commands (#2061)
  - Add ML-DSA signing primitives (#2064) and ML-KEM (#2067)
  - Add `AxiDmaTarget` abstraction and `mcu_sram_to_axi_dma` helper (#2065)
  - Extend device capabilities to 64 bytes (#2127)
  - Reserve `VUxx` vendor-unique command namespace (#2184)
  - Consolidate Caliptra userspace API (#2210)
- **ROM, Boot & Network Boot**:
  - Backport network boot support: lwIP integration, MCU-to-Network CoP mailbox, boot-source protocol, TFTP TOC images, stateful DHCPv6, and MCU ROM network recovery path (#2036)
  - Package prebuilt network ROM variants (#2150); remove boot flags from initiate request (#2131)
  - Hand over firmware boot type and ROM capabilities to Runtime (#2021)
  - Advertise additional MCU ROM capabilities (#2095)
  - Update ROM start message (#2086)
- **Host Tooling (`caliptra-util-host`)**:
  - Add version API (#2104)
  - Task changes (#2149)
  - Add OCP DIP keypair discovery and attested CSR export (#2147)
- **Memory & Code Size**:
  - Reduce overall memory usage (#2174)
  - Reduce SPDM attestation and secured-session footprint; reuse task scratch for transient buffers (#2164)
  - Unify user app on a single scratch allocator (#2179)
  - Stage `mcu_mbox` request metadata instead of copying the payload (#2105)
  - Reduce user app grant reserve (#2142) and adjust SRAM sizing split to 10/16 (#2111)
  - Reduce SPDM responder code size (#2185)
- **Toolchain & Build**:
  - Update Rust toolchain to 1.95 (#2087) and 1.96.1 with caliptra-sw dependency update (#2111)
  - Update bindgen to support newer clang versions (#2040)
  - Remove `no_default_features` flag (#2051)
  - Stop forcing rebuilds of unchanged firmware (#2192); skip unused ROM work in firmware-bundler (#2194)
  - Build ROM explicitly in `xtask size-history` (#2208)

### Fixes

- **SPDM, MCTP & I3C**:
  - Fix SPDM 1.4 chunking and `KEY_EXCHANGE` handling (#2185)
  - Reject `LargeCertChain` `GET_CERTIFICATE` without `LARGE_RESP_CAP` (#2089)
  - Prevent stalled MCTP transfers and surface SPDM failures (#2115)
  - Synchronize I3C private-read completion (#2185)
- **Boot, Update & Kernel**:
  - Fix recovery boot hanging on hardware (#2172)
  - Fix hitless firmware update rejecting packages with owner artifacts (#2168)
  - Wait for PLDM responder readiness instead of a fixed delay (#2193)
  - Fix partial-word truncation in kernel mailbox response copying (#2050)
- **CI & Infrastructure**:
  - Add Mjolnir GitHub workflow and config (#2048)
  - Gate `main` and `main-2.1` PRs on SPDM suites (#2009)
  - Fix bitstream-build job (#2206)
  - Fix `caliptra-util-host` validator precheckin failures (#2105)
- **Documentation**:
  - Define protocol-neutral certificate store design (#2008)
  - Update OCP LOCK integrator guide (#2015)
  - Align DOT documentation with implementation (#2023)
  - Correct 2.1 key revocation flows (#2037)
  - Fix Caliptra 2.1 PLDM package layout (#2022)
  - Correct vendor PK hash strap documentation (#2129)
  - Reserve firmware ID for device UEID (#2167)

**Full Changelog**: https://github.com/chipsalliance/caliptra-mcu-sw/compare/rt-sdk-2.1.0...rt-sdk-2.1.1

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
  - Adds the consolidated `mcu-caliptra-api` for Caliptra mailbox,
    cryptographic, signing, and OCP LOCK operations.
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

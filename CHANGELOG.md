# rt-sdk-2.0.1

## Caliptra MCU Runtime SDK 2.0.1 Release Notes

Release notes for changes introduced since Runtime SDK 2.0.0.

### Features

- **Certificate Store & Provisioning**:
  - Provision IDevID certificates during boot (#2016, #2046) and install the ML-DSA-87 IDevID certificate into Caliptra (#1933, #2054)
  - Move common certificate store ownership and initialization into `cert-store` (#2257)
  - Enforce certificate provisioning policy and endorsement key binding (#2233)
  - Add two-bank (A/B) atomic updates and generation-consistent reads (#2265)
  - Add `EndorsementStorage` trait and verify streamed write checksums (#2287)
  - Implement MCI certificate chain commands and all-role attestation (#2296, #2306)
  - Support out-of-band Vendor endorsement and IDevID certificates (#2311)
  - Add `MC_PROVISION_IDEV_CERT` and SPDM VDM `ProvisionIdevCert` (#2315)
  - Add `MC_AUTH_SET_CERT_CHAIN` authorized certificate provisioning (#2325)
  - Support attested CSR keypair inventory discovery and ML-DSA-87 buffer sizing (#2123, #2147); gate attested CSR export behind an opt-in `attested-csr` feature (#2186)
- **SPDM**:
  - Add SPDM 1.4 `VERSION`, `CAPABILITIES`, and `ALGORITHMS` support (#1857)
  - Support SPDM 1.4 VDM and `LARGE_RESP`, including large VDM fields in the codec (#2094) and large offset/length in `CERTIFICATE` responses (#2019)
  - Support ML-DSA-87 asymmetric algorithm in `spdm-lib`; cache certificate chain digests and DPE skip lengths (#2061)
  - Add ML-DSA cert-store signing and separate streamed vs. buffered message limits (#2064)
  - Support ML-DSA-87 signing for `CHALLENGE_AUTH` and `MEASUREMENTS` on Caliptra 2.0 (#2113)
  - Serve per-algorithm certificate chains from managed cert slots (#2100)
  - Add `HEARTBEAT` / `HEARTBEAT_ACK` with watchdog support (#1927)
- **Attestation & Measurements**:
  - Support ML-DSA-87 signed OCP EAT tokens on Caliptra 2.0 (#2139)
  - Add Owner Attestation Manifest and policy packaging; measure Owner artifacts and Vendor Authorization Key on cold boot and hitless update (#2160)
  - Encode Owner components in OCP EAT evidence (#2285)
  - Add Owner CoRIM generation and matrix component support (#2300)
  - Make DPE Exported-CDI platform-configurable (`DpeHandleStore` v2 `fw_id`-keyed slots, `ATTESTATION_FLAG_EXPORT_CDI_TARGET`, signing/revocation APIs, and separate `vendor_owner` vs. `owner` DPE branches) (#2314)
  - Add opt-in Field Entropy status in the hardware configuration class and omit `mkey` from keyless evidence/CoRIMs (#2344)
- **Ownership, Authorization, Mailbox & Security**:
  - Add Owner Authorization Manifest support: mailbox commands (#2097), flash layout (#2107), builder (#2110), installation during image loading (#2119), and native offline signing over `owner_signed_data` (#2344)
  - Persist Owner SoC Manifest minimum SVN (#2175) and make the minimum SVN command target-aware (#2135)
  - Unify MCI and SPDM authorized command envelope (#2189)
  - Implement manifest-backed MCU command authorization (#2281) and add platform extension hooks for authorized vendor MCU commands (#2316)
  - Restrict privileged MCI mailbox commands to PL0 AXI users (#2336)
  - Add DOT enable command support (#2187)
  - Add vendor public-key hash status (#2126), DPE signer certificate/chain mailbox commands (#1850), `DpeProfile` support (#2061), 64-byte device capabilities (#2134), and `VUxx` vendor-unique command namespace (#2188)
  - Expose native and packed live Field Entropy provisioning status in Runtime (#2344) and remove unsupported UDS/FE zeroization command (#2335)
- **Firmware Update, Boot & Transports**:
  - Enforce physical SVN floors during PLDM updates (#2143)
  - Load and activate Owner SoC images after the Vendor load list (#2230)
  - Allow platform activation method changes in PLDM `ApplyComplete` (#2267)
  - Validate SoC image load ranges before DMA (#2344)
  - Add opt-in MDB-only pending-read notifications in I3C (#2328)
- **Memory & Code Size**:
  - Reduce runtime panic paths and SRAM footprint (#2164, #2174, #2337)
  - Unify user app on a single scratch allocator (#2179), stage `mcu_mbox` request metadata (#2105), reduce user app grant reserve (#2142), and adjust SRAM sizing split to 10/16 (#2111)
  - Simplify `cert-store` and SPDM PAL API surface (#2287)

### Fixes

- **Boot, DMA, Update & Transports**:
  - Prevent streaming boot hangs after DMA errors (#2343)
  - Align Caliptra DMA AXI USER with MCU SRAM configuration (#2259)
  - Fix hitless firmware update rejecting packages with owner artifacts (#2168)
  - Fix partial-word truncation in kernel mailbox response copying (#2050)
  - Harden I3C target RX/TX handling, synchronize private-read completion, and avoid cloning recovery images on every FIFO read (#1360, #2030, #2185, #2213)
  - Wait for IBI completion before advancing MCTP TX (#2115)
- **TDISP & SPDM**:
  - Store `START_INTERFACE` nonce on accepted `LOCK` and free interface slots on `STOP_INTERFACE` (#2320)
  - Fix SPDM 1.4 chunking and `KEY_EXCHANGE` handling (#2185), reject `LargeCertChain` `GET_CERTIFICATE` without `LARGE_RESP_CAP` (#2089), and align SPDM debug unlock with common format (#2014)
  - Remove `SPDM-Lite` naming and raw DSP0274 section references in comments (#2287)
- **ROM & Compatibility**:
  - Support ROM mapped at address zero (#2231)
  - Support legacy flash images with ROM compatibility checks (#2266)
  - Fix release ROM handoff reads and emulator layout (#2319)
  - Retire ROM Field Entropy provisioning and bookkeeping (#2321)
- **Testing, CI & Documentation**:
  - Add released ROM/runtime compatibility matrix testing (#2282)
  - Add `stack-guard` (#1883) and Mjolnir security audit workflow (#2047)
  - Expand MCU mailbox runtime-command test coverage (#2195, #2221, #2226), offline manifest signing tests (#2056), PLDM error coverage (#2234), and MCTP/DOE SPDM coverage (#2235, #2253)
  - Move SPDM validator tests to nightly (#2222) and fix nightly task (#2262)
  - Add Caliptra Subsystem Attestation documentation (#1662), protocol-neutral certificate store design (#2008), vendor key revocation recovery guidance (#2038, #2275), DOT documentation alignment (#2023), SPDM documentation updates (#2252), command authorization clarifications (#2308), and ROM fuse reference updates (#2129, #2167, #2317)

**Full Changelog**: https://github.com/chipsalliance/caliptra-mcu-sw/compare/rt-sdk-2.0.0...rt-sdk-2.0.1

# rom-sdk-2.0.2

## Caliptra MCU ROM SDK 2.0.2 Release Notes

Release notes for ROM and `romtime` changes introduced since ROM SDK 2.0.1 (`7cb0e55`).

### Features

- **Boot Handoff, Capabilities & Compatibility**:
  - Add ROM-to-Runtime handoff table (#1262) and hand over firmware boot type and ROM capabilities to Runtime (#2021)
  - Advertise additional MCU ROM capabilities (#2095)
  - Support legacy flash images with ROM compatibility checks (#2266)
  - Fix release ROM handoff reads and emulator layout (#2319)
- **Ownership, Provisioning & Fuse Handling**:
  - Implement Device Ownership Transfer commands and recover locked DOT blob from backup before reset (#1840, #1930)
  - Provision IDevID certificates during boot (#2016, #2046)
  - Zeroize sensitive key material after use (#1919)
  - Persist Owner SoC Manifest minimum SVN (#2175)
  - Retire ROM-side Field Entropy provisioning and bookkeeping (#2321)
  - Add `on_fw_update_request` hook to prevent flash wear-out attacks (#1773)

### Fixes

- Fix recovery boot hanging on hardware (#2172)
- Wait for PLDM responder readiness instead of a fixed delay (#2193)
- Reset `start_cycle` and `next_print_offset` between image transfers (#1591)
- Support ROM mapped at address zero (#2231)
- Align Caliptra DMA AXI USER with MCU SRAM configuration (#2259)
- Harden I3C target RX/TX handling (#2213), advertise MCTP DCR on I3C targets (#1808), and verify MCTP after warm reset (#1876)
- Add MCTP Get Endpoint UUID support (#1907)
- Align ROM fuse reference documentation with SDK layouts (#2317)

**Full Changelog**: https://github.com/chipsalliance/caliptra-mcu-sw/compare/rom-sdk-2.0.1...rom-sdk-2.0.2

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

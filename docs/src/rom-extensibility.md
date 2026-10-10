# MCU ROM Extensibility

The common MCU ROM provides integration interfaces for platform behavior that
cannot be implemented generically. This document catalogs those interfaces,
how each one is supplied, and what behavior it provides. It also distinguishes
behavior supplied as Rust code from static platform bindings and declarative
ROM configuration.

Implementations are selected at build time and statically linked into the ROM
image. The ROM does not load extensions or plug-ins at run time.

## Behavior Interfaces

The following interfaces execute integrator-provided behavior. `RomParameters`
fields not listed here are configuration values rather than callbacks.

| Interface | Injection point | What it provides | Availability |
|---|---|---|---|
| `RomHooks` | `RomParameters::hooks` | Observes boot milestones. It has no return value, but its code still runs with full ROM privilege. | Optional |
| `ImageVerifier` | `RomParameters::mcu_image_verifier` with `mcu_image_header_size` | Parses the integrator-defined MCU image header and enforces header, fuse, and rollback policy. Returning `false` causes a fatal boot error. | Optional; no custom header verification occurs when absent |
| `ImageProvider` | `ImageProviderEntry` and `ImageProviderManager`, passed as `RomParameters::image_provider_manager` | Supplies recovery images. The manager applies the configured continue or retry policy across an ordered provider list. | Optional recovery boot path |
| `FlashStorage` | `RomParameters::dot_flash` | Reads, writes, and erases persistent DOT state. Storage correctness and power-failure behavior are security critical. | Required for configured DOT storage flows |
| `RecoveryTransport` | `RomParameters::dot_recovery_transport` | Carries DOT override requests, challenges, responses, completion status, and transport-owned sensitive data. The common ROM performs cryptographic verification. | Optional DOT override path |
| `DotRecoveryHandler` | `RomParameters::dot_recovery_handler` or a locked-state recovery adapter | Obtains a backup DOT blob. The common ROM authenticates the blob before writing it. | Optional DOT recovery path |
| `DotLockedRecoveryHandler` | `DotLockedRecoveryEntry` list in `RomParameters::dot_locked_recovery_handlers` | Implements one locked-state recovery strategy. Handlers are tried in integrator-defined order with per-entry error policy and receive mutable ROM context. | Optional DOT recovery path |
| `VendorKeyPolicy` | `RomParameters::vendor_key_policy` | Selects the vendor public-key hash slot populated into Caliptra. The implementation reads OTP and is responsible for its selection policy. | Optional override; the common ROM supplies a default policy |
| `CfiEntropySource` | `RomParameters::cfi_entropy_source` | Supplies early entropy for CFI counters before the Caliptra mailbox is available. | Required when the `cfi` feature is enabled |
| `ocp_lock::Platform` | `ocp_lock::RomConfig::platform`, carried by `RomParameters::ocp_lock_config` | Interprets HEK slot and permanent-bit state and selects the active HEK slot. | Required when the `ocp-lock` feature is enabled |

Definitions for these interfaces live in `caliptra-mcu-rom-common`, except for
`ocp_lock::Platform`, which lives in `caliptra-mcu-romtime`. The emulator and
FPGA ROM crates provide reference wiring examples. Protocol-specific guidance
is available in [Device Ownership Transfer](./dot.md),
[OCP LOCK Integration](./ocp_lock_integrator_guide.md), and
[OCP Recovery Integration](./ocp_recovery_integrator_guide.md).

## Platform Runtime Backends

The platform ROM installs several process-wide backends before entering the
common ROM:

| Backend | Installation | Contract |
|---|---|---|
| Fatal error handling | Implement `FatalErrorHandler` and call `set_fatal_error_handler` | Publish the fatal code using the platform mechanism, then halt or terminate without returning. If absent, the common ROM writes the MCI fatal-error register and loops. |
| Diagnostic output | Implement `core::fmt::Write` and call `caliptra_mcu_romtime::set_printer` | Provide bounded output suitable for ROM execution. Output is externally observable and must never contain secrets. The `no-print` feature removes normal printing. |
| Controlled exit | Implement `caliptra_mcu_romtime::Exit` and call `set_exiter` | Supports `test_exit` and controlled simulation/test termination. It is not a replacement for production fatal-error handling. |

The platform also owns reset entry, early machine setup, trap-vector setup,
linker placement, and installation of these backends before calling
`rom_start`. These startup responsibilities are outside `RomParameters`.

## Static Platform Bindings

The common ROM imports two platform-defined symbols:

- `MCU_MEMORY_MAP`: addresses, sizes, and memory properties for ROM, SRAM,
  persistent storage, DCCM, handoff memory, I3C, MCI, mailbox, SoC, OTP,
  lifecycle, and staging SRAM regions.
- `MCU_STRAPS`: I3C controller selection and addresses plus Caliptra and MCU
  watchdog settings for production, manufacturing, and debug states.

The platform ROM exports these symbols using values from its platform
configuration. They are compile-time bindings, not mutable run-time discovery.

### `MCU_MEMORY_MAP`

`MCU_MEMORY_MAP` has type `McuMemoryMap`. It describes the address ranges and
layout values shared by the ROM, runtime, linker generation, and platform
protection setup. Fields ending in `_offset` are base addresses, fields ending
in `_size` are byte lengths, and fields ending in `_properties` classify the
range for memory-attribute and protection configuration.

| Region | Fields | What the fields describe |
|---|---|---|
| MCU ROM | `rom_offset`, `rom_size`, `rom_properties` | ROM base, extent, and memory type. ROM uses the range for its code and digest measurement; `rom_offset` is also installed as the MCU NMI vector base. |
| ROM stacks | `rom_stack_size`, `rom_estack_size` | Space reserved by the platform ROM linker/startup code for the normal ROM stack and the exception stack. These are sizes, not separate address regions. |
| MCU SRAM | `sram_offset`, `sram_size`, `sram_properties` | Base and extent of SRAM used to receive the authenticated MCU firmware. ROM derives the firmware header and entry addresses from `sram_offset`. |
| Reset-retained SRAM storage | `storage_size` | Bytes reserved from the MCU data-memory range and excluded from kernel and application allocation. The linker emits it as `NOLOAD`, allowing contents to survive supported warm-reset and hitless-update flows when the platform retains that SRAM. It is volatile and is not preserved across a power cycle or SRAM-clearing cold reset. It has no separate base field. |
| DCCM | `dccm_offset`, `dccm_size`, `dccm_properties` | Closely coupled data-memory range used by the MCU software and linker layout. |
| Firmware handoff | `handoff_offset`, `handoff_size` | Shared handoff-data area used to pass ROM-selected boot information to later MCU firmware. |
| PIC | `pic_offset`, `pic_properties` | Base and memory type of the MCU programmable interrupt controller. Its extent is platform-defined rather than represented by a `pic_size` field. |
| Primary I3C | `i3c_offset`, `i3c_size`, `i3c_properties` | Register range for the primary I3C controller and recovery interface. |
| Secondary I3C | `i3c1_offset`, `i3c1_size`, `i3c1_properties` | Register range for the optional secondary I3C controller. `MCU_STRAPS.active_i3c` selects which controller ROM uses for recovery. |
| MCI | `mci_offset`, `mci_size`, `mci_properties` | Register range for the MCU Control Interface, including reset reason, boot status, watchdog, configuration locks, and MCU mailbox control. |
| Caliptra mailbox | `mbox_offset`, `mbox_size`, `mbox_properties` | Register range for the Caliptra mailbox used by MCU ROM to issue commands to Caliptra firmware. |
| Caliptra SoC interface | `soc_offset`, `soc_size`, `soc_properties` | Register range for Caliptra boot control, fuse population, status, AXI-user configuration, and related SoC-interface operations. |
| OTP controller | `otp_offset`, `otp_size`, `otp_properties` | Register range through which ROM reads and programs platform OTP fields. |
| Lifecycle controller | `lc_offset`, `lc_size`, `lc_properties` | Register range for lifecycle-state reads and transitions. |
| Staging SRAM | `staging_sram_offset`, `staging_sram_size` | External staging-memory window used by platform recovery/update and DMA paths. It does not have a `MemoryRegionType` field in `McuMemoryMap`. |

`MemoryRegionType` contains two attributes: `side_effect` and `cacheable`.
Normal memory uses `MEMORY` (`side_effect = false`, `cacheable = true`), while
register ranges use `MMIO` (`side_effect = true`, `cacheable = false`). The
platform configuration uses these properties when deriving memory-region
attributes and protection entries.

All MCU SRAM is physically retained across a warm reset while `powergood`
remains asserted. The reserved region is not a different kind of SRAM; it adds
a software-preservation contract. Outside that region, retained bytes can be
overwritten when Caliptra loads a new MCU image, when runtime startup relocates
`.data` and clears `.bss`, or when stacks, heaps, and application memory are
reused.

`storage_size` excludes a page-aligned range at the end of the data-memory
allocation from those normal uses. The firmware bundler marks its linker
section `NOLOAD` and exports `_sstorage` and `_estorage`, so a newly loaded
runtime neither initializes nor allocates the range. The kernel maps it
separately from application RAM. The reference runtime uses these
software-preserved bytes for the DPE Handle Store and Software PCR Store. The
contents remain volatile and are lost when `powergood` cycles or SRAM is
otherwise explicitly cleared.

The default values in `caliptra-mcu-config` are reference values. Each platform
exports its own `MCU_MEMORY_MAP`; for example, the emulator and FPGA provide
different ROM, SRAM, stack, persistent-storage, and staging-SRAM sizes.

## Declarative Configuration

`RomParameters` is the central composition structure. In addition to the
behavior interfaces above, it carries declarative choices in these groups:

| Group | Representative fields and tables |
|---|---|
| Lifecycle and provisioning | `lifecycle_transition`, `burn_lifecycle_tokens`, `program_field_entropy` |
| OTP checks and constants | Integrity and consistency enables, timeout override, digest IV, and digest finalization constant |
| Security locks and access control | Caliptra and MCI mailbox AXI users, fuse/TRNG/DMA AXI users, FIPS zeroization mask, executable SRAM region size, and production-debug hash count |
| Image and recovery selection | Recovery and network boot requests, recovery-status handling, image header size, and image-provider ordering |
| DOT policy | Stable-key type, owner-PK-hash policy, recovery policy, watchdog timeout, reset flow, firmware-manifest enable, and ordered locked-state handlers |
| SVN policy | Component SVN manifest enable and `svn_fuse_map`, which maps SoC component IDs to integrator-selected `SOC_IMAGE_MIN_SVN` fuse slots |
| I3C services | Enabled service modes, forced service entry, and timing values for each controller |
| Measurements and entropy | ROM-digest stashing and Caliptra entropy-bypass selection |

Detailed configuration guidance is available in
[ROM I3C Services](./rom_i3c_services.md), [ROM Fuses](./rom-fuses.md),
[SVN Anti-Rollback](./svn.md), and the [Integrator's Guide](./integrator-guide.md).

## Compile-time Selection

The common ROM also uses Cargo features to include optional security and boot
flows:

| Feature | Effect |
|---|---|
| `cfi` | Enables control-flow-integrity counter initialization and requires an early `CfiEntropySource`. |
| `network-boot` | Includes network recovery boot support. |
| `fw-manifest-dot` | Enables processing of the firmware-manifest DOT section. |
| `svn-manifest` | Enables parsing and enforcement of the MCU Component SVN Manifest. |
| `ocp-lock` | Includes OCP LOCK HEK handling and requires `ocp_lock::Platform`. |
| `stable-owner-key` | Includes stable owner-key derivation; it is mutually exclusive with OCP LOCK as an HEK consumer. |

Features prefixed with `test-`, and `core_test`, are verification mechanisms
rather than additional extensibility points.

## ROM Milestone Hooks

`RomHooks` lets integrators observe major boot milestones without forking the
common ROM. Typical uses are bounded logging, phase-latency measurements, and
integration-test event traces. It is an observation interface, not a policy,
recovery, or hardware-abstraction interface.

### Attaching hooks

Implement `caliptra_mcu_rom_common::RomHooks` and pass a reference through
`RomParameters::hooks`:

```rust
use caliptra_mcu_rom_common::{RomHooks, RomParameters};

struct LoggingRomHooks;

impl RomHooks for LoggingRomHooks {
    fn pre_cold_boot(&self) {
        caliptra_mcu_romtime::println!("[rom-hook] pre_cold_boot");
    }

    fn post_cold_boot(&self) {
        caliptra_mcu_romtime::println!("[rom-hook] post_cold_boot");
    }
}

let hooks = LoggingRomHooks;
caliptra_mcu_rom_common::rom_start(RomParameters {
    hooks: Some(&hooks),
    ..Default::default()
});
```

All methods have no-op defaults, and the field defaults to `None`. Methods take
`&self`; local counters or timestamps can use interior mutability.

### Invocation contract

A `post_*` hook runs only after the operation in its row has completed
successfully up to that point.

| Hooks | Invocation point | Paths and conditions |
|---|---|---|
| `pre_cold_boot` / `post_cold_boot` | First action in cold boot / after the flow-complete milestone and immediately before the warm-reset request | Cold boot only |
| `pre_warm_boot` / `post_warm_boot` | Entry to warm boot / after the flow-complete milestone and immediately before the next warm-reset request | Warm boot only |
| `pre_fw_boot` / `post_fw_boot` | Entry to firmware boot / immediately before the jump to mutable firmware | Firmware-boot reset only |
| `pre_fw_hitless_update` / `post_fw_hitless_update` | Entry to hitless update / immediately before the jump to mutable firmware | Firmware hitless-update reset only |
| `pre_caliptra_boot` / `post_caliptra_boot` | Immediately before boot-go / after `BOOT_DONE`; cold boot also waits for mailbox readiness | Cold and warm boot |
| `pre_populate_fuses_to_caliptra` / `post_populate_fuses_to_caliptra` | Before the fuse phase / after `fuse_write_done` is acknowledged | Cold boot populates fuse registers; warm boot performs the required handshake only |
| `pre_load_firmware` / `post_load_firmware` | Before `RI_DOWNLOAD_FIRMWARE` or its encrypted variant / after successful normal-path validation or encrypted-path activation | Cold boot only |
| `pre_set_ocp_lock_fuses` / `post_set_ocp_lock_fuses` | Around OCP LOCK HEK fuse setup inside the fuse phase | Cold boot with `ocp-lock` only |
| `pre_stable_owner_key_derivation` / `post_stable_owner_key_derivation` | Around derivation and handoff of the stable owner key | Cold boot with `stable-owner-key` only |
| `pre_encrypted_firmware_decrypt` / `post_encrypted_firmware_decrypt` | Around `CM_AES_GCM_DECRYPT_DMA` | Encrypted `core_test` path only |

### Hook behavior and limitations

Hooks run synchronously and have no return value, so they observe rather than
select common-ROM behavior. A `pre_*` call does not guarantee its `post_*`
call: validation failure, hardware failure, fatal error, or reset can end the
flow first. Hooks are path- and feature-dependent, and resets can execute a
flow more than once. They therefore provide neither a liveness signal nor an
exactly-once event.

The emulator and FPGA reference ROMs contain a `LoggingRomHooks`
implementation gated by the `test-rom-hooks` feature. The integration test
`test_rom_hooks_fire_in_order` verifies its event sequence. Do not enable this
test implementation in a production ROM.
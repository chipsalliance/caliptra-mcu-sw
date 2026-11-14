# VCK190 internal-ULPI recovery test

## Verification-branch Core workaround

This local verification branch pins latest Core to
`4d451b367974d6e17fd57ee6f5fabdae676929e0`, based on upstream `1a5ed709`.
The Core ROM sets VeeR `MFDC[3]` before startup to disable branch prediction
and prints the CSR readback. This applies to Core ROMs built from this latest
pin, not only to the MCU `htg940` feature. The 2.1 pin and subsystem RTL pin
are unchanged.

On HTG, the matched predictor-enabled control reproduced `HW_FATAL=0x10`
and an ML-KEM startup stall. The predictor-disabled ROM passed ML-KEM and
completed host recovery of all three images with Production/debug-lock,
the MCU ROM, recovery images, and base BIT/MMI unchanged. This is a temporary
bring-up workaround, not a confirmed permanent RTL fix. The final MCU runtime
Hello marker was not captured, so full MCU runtime boot is still unconfirmed.

The debug Core revision currently exists only in the local Core repository.
Before sharing this MCU branch, publish that Core revision to a repository
from which the configured Core submodule URL can fetch it. Do not silently
substitute the upstream pin or reuse old bundles: rebuild the complete
five-image HTG bundle after this pin change.

## Opt-in HTG940 bring-up build

For HTG gateware rebuilt from the same linked subsystem revision as this
firmware, use:

```bash
CALIPTRA_HW_REV=latest cargo xtask rom-build --platform fpga \
  --features htg940
```

Use the resulting `latest-caliptra-mcu-rom-fpga-htg940.bin`
instead of the default VCK190 recovery ROM. Selecting the feature does not
change the pins. Both boards
use the normal generated fuse map from the linked subsystem, and DAI access
widths follow that map's partition metadata. FMC key-manifest SVN forwarding
is retained only on 2.1; the latest map no longer contains that field. Active
Core firmware and SoC SVN checks are unchanged.

`htg940` is disabled by default and includes the USB recovery test feature.
It selects development vendor-hash RAM initialization and absence of a DOT
flash backend. Normal VCK190 recovery builds use
`test-lpcip-usb-ocp-recovery`, the linked subsystem's generated fuse map,
host-side OTP provisioning, and the normal DOT flash backend.
Regenerate fuse definitions from the linked hardware using the normal
`CALIPTRA_HW_REV=latest cargo xtask registers-autogen` workflow when changing
the pin. The fuse-only `--fuses-output-dir` option is also available for
generation/comparison without overwriting the checked-in definitions.

The old `test-htg940-otp-164dfbd6` feature and separate legacy fuse module
have been removed. The complete `otp_ctrl_mmap.hjson` in the earlier HTG source
pin `164dfbd6` is byte-for-byte identical to the linked `743d5f7e` map:
SHA-256 `ab78f3f8a14de43693af8267fc0f021e037fff0b35ce281e2cfd03a447ea1328`.
The common generated map therefore covers that known HTG OTP layout without
an alternate fuse module. This comparison does not verify the actual loaded
image or compatibility of other RTL interfaces; use matching hardware for full
qualification. Board flash/provisioning policy remains development-only.

Temporary HTG development provisioning: only the `htg940` FPGA ROM
checks vendor hash slot 0 through OTP backing RAM at `0xB0080000` plus the
generated slot offset (`0x430` with the current pin). A zero slot is filled with the fixed test-key
digest verified against this bundle; a matching slot is left unchanged, and a
different slot or failed readback is fatal. This is RAM-backdoor initialization,
not physical OTP programming. It must not be used for production provisioning
or firmware signed with other vendor keys. The slot's PQC selection and other
OTP policy fields are not changed. Remove this temporary initialization when
the HTG OTP image is supplied through the board's provisioning flow.

On USB recovery device-error, boot-failure, fatal-error, or a Core firmware
or hardware fatal error, MCU ROM prints a one-time raw recovery-status and Core
error register snapshot while polling. It includes Core boot/flow status and
the MCU cycle count. Hardware-only faults are reported even when firmware
fatal/nonfatal status remains zero; `HW_FATAL=00000010` is the key-vault error
bit, whose RTL sources include boot-flow monitoring and key-vault monitoring.
The snapshot only reads status and does not clear errors or reset the target.
Error snapshots are independent of
`UsbParams::enable_logs`. Preserve the target state and continue console
capture after host failure; do not automatically reset before collecting it.

Temporary USB recovery fuse diagnostics also print all 12 selected vendor-hash
words read through OTP DAI alongside Core fuse-register readback immediately
after writing them. Three lines cover words 0-3, 4-7, and 8-11. These are public
trust-anchor digest values, not secret fuse contents.

FPGA Device 0 advertises bring-up VID:PID `0424:0007`. These match the
USB3320 PHY identification values but are not a production device allocation.
Select `0424:0007` in the host recovery tool; the hub identity is unchanged.
Emulator fixtures retain their existing identity.

For temporary standalone HTG USB recovery bring-up, `htg940`
supplies no DOT flash backend. This skips DOT blob processing and uses the
common ROM's fuse-owner fallback rather than issuing host-serviced secondary
flash reads on standalone HTG-940. Other FPGA ROM features retain DOT flash.

Both VCK190 and HTG FPGA USB recovery ROMs enable the MCU watchdog with
3,600,000,000 cycles for debug, manufacturing, and production states. This is
60 seconds at the intended 60 MHz MCU clock, or 200 seconds at 18 MHz.
The watchdog starts during cold-boot setup, not when the host clicks recovery;
there is no temporary watchdog disable or periodic petting. Other FPGA ROM
features retain their original watchdog straps. Core watchdog settings are
unchanged. `test-rom-hooks` retains its usual milestone logging on either board.

FPGA MCU ROM prints the live wrapper `FPGA_VERSION` register (`0xA4010004`)
at startup, for example `[mcu-rom] FPGA version: 0xA22B0005`. This identifies
the loaded image's version tag, not its SHA-256 or the underlying base image.

This test reuses `RecoveryAgent` from `caliptra-mcu-usb-recovery`. Its transport
uses Carl's `caliptra_fpga_ulpi_host` MMIO engine at wrapper offset `0x4000`
(physical address `0xA4014000`), rather than libusb. The ARM PS drives USB
enumeration explicitly; Linux USB enumeration and the PS USB controller are
not involved.

FPGA ROM enables the hardware-serviced internal two-port hub by default,
connects Device 0 on port 1, and leaves Device 1 in its reset-disabled state.
The host enumerates the hub at address 127 (126 if needed to avoid an address
collision), validates its descriptors, powers/resets port 1, then enumerates
Device 0 at address 7. The test requires the hub path, not direct-device
fallback. Physical HTG hosts perform this enumeration through their OS USB
stack. Emulator ROM fixtures keep their existing direct-Device-0 topology.

The hub uses its RTL reset descriptors and request table, with configuration
power fields updated to the platform's `UsbParams` policy; these are bring-up
identities, not production USB identities. Hub connection requires real
VBUS, and LPM remains disabled.

`UsbParams::enable_logs` controls verbose USB initialization and state-change
diagnostics. FPGA ROM sets it to `true`; set it to `false` in the platform's
USB parameters for quiet operation. Emulator fixtures default to `false`.
PHY identity, hub connection, VBUS, reset, address and configuration are logged;
firmware payloads and idle polls are not. Error diagnostics remain enabled.

The FPGA ROM uses VCK190 AXI addresses `0xA4200000` for USB registers and
`0xA4300000` for Device 0 packet SRAM. The generated subsystem-local bases
(`0x20000000` and `0x30000000`) must not be used by this FPGA ROM.

## Requirements

- Latest (Caliptra 2.2) hardware and Carl's Architecture B bitstream with host
  magic `0x55534248`. A compatible segmented base image is required.
- ARM Linux with the normal FPGA UIO mappings and permissions.
- A **fresh bundle from this branch**, built for `CALIPTRA_HW_REV=latest` and
  `--platform fpga`. It must contain the
  `test-lpcip-usb-ocp-recovery` feature ROM and matching signed Caliptra firmware,
  SoC manifest, and MCU runtime. The builder's latest FPGA ROM list already
  includes this feature. Do not reuse Carl's older firmware bundle.
- Exclusive use of the FPGA; no concurrent recovery tools or test processes.

### Current development-branch compatibility

This branch follows the `caliptra-mcu-dev-2.2` baseline with the temporary
Core workaround described above and subsystem
`743d5f7eaa9a946f405b9087c7ffd2fbb38e1543`. Core's upstream OTP tooling
accepts the selected map through `CALIPTRA_MCU_OTP_MMAP_HJSON`; no local Core
OTP patch or alternate board-specific fuse map is required.

The generated map allocates 56 bytes to the SVN partition, places vendor hash
slot 0 at `0x430`, and places lifecycle at `0xE40`. MCU DAI access widths come
from the linked partition metadata, keeping the preceding digest's 64-bit
accesses separate from the public hash's 32-bit accesses.

Use an Architecture B bitstream built with the same subsystem pin. Carl's
older `a22b0001`/`a22b0005` images use `cadc77b6` and are not the matching
baseline. Rebuild the firmware bundle and ARM archive before testing; do not
reuse artifacts from the old pin.

For example, build the bundle locally:

```bash
CALIPTRA_HW_REV=latest cargo xtask-fpga all-build \
  --platform fpga --output all-fw.zip \
  --mcu_cfg mcu,0x0,0xB00C0000,2,2,2,none --separate-runtimes
```

Cross-build the integration executable/archive on the workstation:

```bash
CALIPTRA_HW_REV=latest \
CALIPTRA_MCU_FUSES_HJSON="$PWD/hw/latest/fuses.hjson" \
CALIPTRA_MCU_OTP_MMAP_HJSON="$PWD/hw/latest/caliptra-ss/src/fuse_ctrl/data/otp_ctrl_mmap.hjson" \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
cargo nextest archive \
  -p caliptra-mcu-tests-integration --lib --features fpga_realtime \
  --target aarch64-unknown-linux-gnu --release \
  --archive-file caliptra-test-binaries.tar.zst --target-dir cross-target
```

Deploy the bundle and unpacked archive using your FPGA deployment workflow.
Run the prebuilt executable on the board as a user with UIO access:

```bash
CALIPTRA_HW_REV=latest \
CPTRA_FIRMWARE_BUNDLE=/tmp/caliptra-binaries/all-fw.zip \
  /tmp/caliptra-test-binaries/target/aarch64-unknown-linux-gnu/release/deps/caliptra_mcu_tests_integration-* \
  test_fpga_usb_arch_b --nocapture --test-threads=1
```

Alternatively, nextest's `usb-fpga` profile selects this test and disables
automatic retries. Supply the usual archive/metadata remapping options when
running without a source checkout.

## Behavior and limits

The test loads the USB recovery feature ROM and supplies no firmware through
the model's automatic I3C path. The ROM selects USB recovery itself. The MMIO
host enumerates the hub and downstream Device 0, then the shared recovery agent discovers capabilities
and streams all three requested images using 64-byte control transfers.
Success requires `RecoveryOutcome::Confirmed`, MCU firmware-boot completion,
and no MCU fatal error.

Transport errors propagate with stage diagnostics. An ambiguously completed
write is not restarted as a new control transfer. NAK handshakes may be retried
within the original transfer deadline.

This does not change lifecycle initialization or work around its previously
observed stall. A ROM that stops before asserting Device 0 connect will fail
the bounded enumeration wait with host status and diagnostics.

This validates the digital recovery path, not libusb, a physical USB PHY,
electrical compliance, or independent USB-host interoperability.

The internal HS device may return NYET after accepting an OUT packet, including
the status OUT zero-length packet. The MMIO adapter treats ACK and NYET as
accepted, retries only NAK, and does not replay accepted OUT payloads.

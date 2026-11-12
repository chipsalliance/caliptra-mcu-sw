# VCK190 internal-ULPI recovery test

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

This branch follows `caliptra-mcu-dev-2.2` with Core
`1a5ed709808ab5bd77372dd9cee66f8833936901` and subsystem
`743d5f7eaa9a946f405b9087c7ffd2fbb38e1543`. Core's upstream OTP tooling now
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

# USB recovery agent

This crate provides the Caliptra 2.2 OCP recovery protocol driver, a libusb
transport, and a supported CLI. Linux performs standard USB enumeration and
configuration. The transport-independent library has no default libusb dependency;
other transports implement `RecoveryTransport` without duplicating sequencing.

Build the CLI on a host with libusb development files and pkg-config:

```sh
cargo build --locked -p caliptra-mcu-usb-recovery --features libusb
```

Select an explicitly provisioned device identity; there is no release VID/PID
default. `--bus` and `--address` disambiguate multiple matching devices. The agent
does not detach kernel drivers, reset devices, or change their configuration.
The user must have access to the selected `/dev/bus/usb` node.

```sh
target/debug/caliptra-mcu-usb-recovery --vid 0x1234 --pid 0x5678 probe
target/debug/caliptra-mcu-usb-recovery --vid 0x1234 --pid 0x5678 recover \
  --caliptra-fmc-rt caliptra-fw.bin \
  --soc-manifest soc-manifest.bin \
  --mcu-runtime mcu-runtime.bin
```

The identities above are placeholders, not approved device IDs. `probe` validates
the OCP interface, functional descriptor, protocol capabilities, and device
status without changing recovery state. Recovery follows the image indices
requested by the device: 0 is Caliptra FMC/runtime, 1 is the SoC manifest, and 2 is
MCU runtime. Empty, unrepresentable, or unsupported image inputs are errors.

## Transfer and failure contract

OCP class reads request 64 bytes on the selected LPCIP hardware; response lengths
remain command-specific. FIFO sizes, limits, and indices are DWORD quantities.
Image chunks never exceed 64 bytes, the reported transfer limit, or available
FIFO capacity. Image size rounds up to DWORDs; only the final word is zero-padded.
Original payload byte order is preserved. Modulo FIFO indices are not total image
progress.

Defaults bound individual transfers to 2 seconds, lack of progress to 30 seconds,
and the overall operation to 180 seconds. CLI timeout options override these
bounds. FIFO backpressure/status waits are bounded. libusb handles NAKs within
each transfer deadline. STALL, disconnect, malformed responses, unsupported
capabilities, and protocol errors terminate with context. Ambiguously completed
writes are never replayed automatically; callers must explicitly restart a failed
recovery under an appropriate device/reset policy.

Final image activation alone is **not** success: the agent waits for the device
to report healthy/running after all supplied images were activated. A device
already running recovery is reported separately, without claiming any transfer.
The complete ROM tests below independently check the MCU firmware-boot milestone
and exact DMA-delivered image bytes; the CLI does not expose MCU registers.

## Linux USB/IP enumeration smoke test

The [build/test workflow](../../../.github/workflows/build-test.yml) runs USB
setup and the host tests once, on emulator shard 1 for `latest`. It installs
libusb, a USB/IP userspace binary, matching-kernel `vhci_hcd` support, and `acl`,
with passwordless narrowly scoped test setup.
Installing userspace tools alone does not provide kernel support.

The firmware build prebuilds both USB enumeration ROMs into the firmware bundle;
`test-lpcip-usb-host` is emulator-only. The emulator build also prebuilds the
libusb CLI, and the test build covers its optional libusb adapter tests.
The emulator test worker consumes these artifacts and its existing nextest
archive without compiling firmware or the CLI.

The opt-in test runs the real shared-driver enumeration ROM in its explicitly
test-only `test-lpcip-usb-host` mode, which continues serving EP0 after Linux
configuration. A loopback-only USB/IP server translates URBs into LPCIP
transactions. Linux owns enumeration; the CLI then probes the same device through
libusb. The test verifies exact device/configuration descriptors, OCP discovery,
and cleanup. It does not stream the full firmware set or implement production
recovery boot.

After preparing prerequisites (`sudo modprobe vhci_hcd`), run:

```sh
export USBIP=/absolute/path/to/the/real/usbip
export USB_RECOVERY_CLI="$PWD/target/debug/caliptra-mcu-usb-recovery"
cargo test --locked -p caliptra-mcu-tests-integration --lib \
  usb::usbip_tests::usbip_linux_enumerates_and_probes_shared_rom \
  -- --exact --ignored --nocapture --test-threads=1
```

Set `CPTRA_FIRMWARE_BUNDLE` to reuse a prebuilt firmware bundle locally; missing
or empty required USB ROMs fail rather than falling back to a generic ROM or a
rebuild. Without that variable, local tests build their fixture ROMs.

Missing prerequisites fail this explicitly selected test; ordinary nonprivileged
tests do not run it. CI uses the `usb-host` nextest profile, runs ignored tests
explicitly, and fails if the required host selection is empty. Its separate
JUnit report is uploaded with the emulator shard results.
Only the fixture's exact loopback remote URL is eligible for detach; unrelated
VHCI attachments are never touched. CI records that URL in `USBIP_STATE_FILE`
for cleanup after process interruption.

## Linux USB/IP complete ROM recovery tests

The same `usb-host` profile also exercises the common
`test-lpcip-usb-ocp-recovery` ROM, prebuilt in the latest firmware bundle.
Linux VHCI retrieves the device and configuration descriptors through ROM EP0
and configures the OCP interface. The external CLI then transfers Caliptra
FMC/runtime, the SoC manifest, and MCU runtime through libusb and USB/IP.
No test writes image bytes directly to OCP registers or SRAM.

Both the hardware-model executor and the standalone emulator implementation are
covered. The standalone case constructs `Emulator` from its supported arguments
and steps it in-process; the recovery CLI is a separate executable in both
cases. An opt-in peripheral observer records requests, activations, and FIFO DMA
responses, not merely accepted host packets. Tests compare exact delivered bytes,
including zero-padding of a partial final DWORD, and require the actual MCI
`FIRMWARE_BOOT_FLOW_COMPLETE` milestone. CPUs stop at that milestone or a fatal
ROM error while the bridge continues serving status and teardown requests.

The required profile includes enumeration/probe, both complete boot paths,
a corrupt partial-word manifest, missing and empty MCU images, detach and VBUS disconnect
during a real FIFO transfer, and stalled-ROM timeout handling. Failure cases
require a nonzero CLI exit with a diagnostic and must not reach the boot
milestone. Nonprivileged peripheral tests separately verify delivered versus
accepted bytes, partial-word padding, reset-invalidated DMA exclusion, and
observer preservation across resets.

With the same Linux prerequisites and environment variables as above:

```sh
CALIPTRA_HW_REV=latest cargo nextest run \
  -p caliptra-mcu-tests-integration --locked --profile usb-host \
  --run-ignored only --no-tests fail --test-threads 1
```

These privileged tests are ignored in ordinary local/nonprivileged runs. Once
explicitly selected, missing tools, permissions, kernel support, firmware or
CLI binaries fail; there is no successful prerequisite-skip fallback.
`USBIP` must name a real executable, not a kernel-version wrapper that cannot
find its tools. Every child has a deadline and is killed/reaped if necessary;
each attachment is detached using its exact owned remote URL. Tests run
serially and remove their optional CI ownership file after successful cleanup.

### Exporting the standalone emulator

On latest hardware, add these options to the normal emulator command with a
common USB recovery ROM and the matching firmware arguments:

```sh
--usb-recovery --usbip-listen 127.0.0.1:3240
```

Keep the firmware's matching memory-map and vendor-key-hash options, as supplied
by `cargo xtask rom-run`; the ROM must run at its linked address, not the
standalone executable's generic default address.

The emulator prints the bound address and exports bus ID `1-1`. The bridge
supplies VBUS, but ROM must initialize USB and answer enumeration; firmware
arguments configure the emulator and do not inject images into the USB FIFO.
Only loopback listeners are accepted. `--usbip-listen` requires
`--usb-recovery` and cannot be combined with GDB. Bridge failures are reported
and terminate the emulator with an error. This validates OS/protocol behavior,
not physical USB signaling or hub electrical operation.

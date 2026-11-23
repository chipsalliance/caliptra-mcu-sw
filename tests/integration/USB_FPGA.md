# VCK190 USB recovery integration

The latest-only `test_fpga_usb_arch_b_ocp_recovery_boot` test uses the internal
ULPI host in the subsystem bitstream. No external USB cable or Linux USB/IP
driver is needed. It enumerates the hardware hub and downstream Device 0,
verifies high-speed operation, transfers all three recovery images, and requires
confirmed OCP recovery plus the MCU firmware-boot completion milestone.

Use a compatible subsystem parent image and the latest manifest-selected
segmented runtime PDI. The wrapper UIO mapping must cover at least 64 KiB and
include the host at wrapper offset `0x4000`. Missing host identity or firmware
inputs fail explicitly. The test ROM maps USB CSRs at `0xA4200000` and packet
memory at `0xA4300000`; these are FPGA AXI addresses, not subsystem-local ones.
Its `0424:0007` device identity is a test fixture, not a production allocation.

Select matching latest Core source with `cargo xtask switch-version latest`.
Build the FPGA firmware bundle including the
`test-lpcip-usb-ocp-recovery` ROM and compile the integration package with
`--features fpga_realtime` for `aarch64-unknown-linux-gnu`.

On the board, use the normal FPGA bootstrap flow, mount/extract the prebuilt
test archive, and run nextest with `--profile usb-fpga --no-tests fail`.
Set `CALIPTRA_HW_REV=latest`, `CPTRA_FIRMWARE_BUNDLE` to the FPGA bundle, and
provide the matching source workspace and fuse/OTP inputs as in general FPGA
CI. Run serially: the test owns the shared FPGA through `TEST_LOCK` and rewrites
ROM, SRAM and OTP test contents.

The test remains outside the general `nightly-ci` selection. Host diagnostics
include bounded SETUP handshake samples and an OTP/lifecycle snapshot when
enumeration fails. They do not replace physical USB electrical validation.

# Testing

The Caliptra MCU software uses integration tests that run on the MCU emulator to verify functionality. These tests are orchestrated using `cargo nextest` and can be run locally or in CI.

## Running Tests

The primary way to run tests is using the `xtask` test command:

```shell
cargo xtask test
```

This command runs all integration tests using `cargo nextest`. It automatically excludes certain packages that do not contain tests or are not relevant for the main test suite.

### Test Environment Variables

Integration tests often require pre-built firmware and emulator binary bundles. These can be provided via command-line arguments:

*   `--firmware-bundle <PATH>`: Path to a ZIP file containing Caliptra Core ROM, Core firmware, MCU ROM, and MCU runtime binaries. This is built with `cargo xtask all-build`.
*   `--emulator-bundle <PATH>`: Path to a ZIP file containing the pre-built emulator binary. This is built with `cargo xtask emulator-build`.

Example of running tests with pre-built bundles:

```shell
cargo xtask test --firmware-bundle target/all-fw.zip --emulator-bundle target/emulators.zip
```

(Note: These can also be provided via `CPTRA_FIRMWARE_BUNDLE` and `CPTRA_EMULATOR_BUNDLE` environment variables.)

### Advanced Test Options

The `xtask test` command supports several advanced options to aid CI flows:

*   `--archive <PATH>`: Instead of running tests, archives the test binaries to a file. This is used in CI to separate the build and test execution phases.
*   `--shard <SHARD>`: Runs a specific shard of tests (e.g., `hash:1/4`) to enable splitting tests across CI machines.
*   `--workspace-remap <PATH>`: Remaps the workspace path when running archived tests.

## Adding a New Integration Test

Integration tests usually involve a specific feature in the MCU runtime and potentially matching behavior in the emulator. Follow these steps to add a new test:

### 1. Define Feature Flags

Add a new feature flag (e.g., `test-my-feature`) to the following files:

*   `platforms/emulator/runtime/Cargo.toml`: The MCU runtime feature.
*   `emulator/app/Cargo.toml`: (If needed) The emulator feature.
*   `emulator/periph/Cargo.toml`: (If needed) The peripheral emulation feature.

### 2. Implement Runtime Logic

In the runtime (or application) code, use the feature flag to enable your test logic. For example, in `platforms/emulator/runtime/userspace/apps/example/src/main.rs`:

```rust
#[cfg(feature = "test-my-feature")]
{
    // Run your test logic here
    test_my_feature::run().await;
    System::exit(0);
}
```

### 3. Implement Emulator Logic

If your test requires specific emulator behavior (e.g., simulating a hardware event or responding to a mailbox command), implement it in the emulator under the corresponding feature flag.

### 4. Register the Integration Test

In `tests/integration/src/lib.rs`, register your test using the `run_test!` macro:

```rust
run_test!(test_my_feature, example_app);
```

The second argument (`example_app`) indicates that the test uses the example application.

### 5. Add to xtask Feature Lists

To ensure your test is built by default and included in CI, add the feature name to the constants in `builder/src/features.rs`:

*   `RUNTIME_TEST_FEATURES`: Add to this list if the feature should be included in the MCU runtime build.

## Continuous Integration (CI)

### VCK190 Device 0 kernel USB stress (latest only)

The `test-usb-stress-dev0` runtime exposes the CST1 stress personality from
the kernel, without loading userspace processes. A 100-microsecond kernel alarm
services the USB driver; it does not replace the kernel loop with a busy loop.
The short polling interval allows deferred EP0 status actions to complete
within the host's SET_ADDRESS recovery window.
Each ARM-side Rust test first boots the USB OCP recovery ROM and transfers Core
firmware, the stress-specific SoC manifest, and the stress-enabled MCU runtime
through the internal ULPI host. Automatic I3C firmware recovery is disabled.
After confirmed USB recovery and MCU runtime boot, the host signals the kernel
through MCI generic input wire 0. Generic output wire 1 reports readiness or
failure. The kernel takes Device 0 out of OCP recovery and initializes CST1;
the host resets and re-enumerates USB before running stress transfers.
Device 0 owns the shared hub/PHY and its private USB SRAM.

```shell
CALIPTRA_HW_REV=latest cargo xtask all-build --platform fpga \
  --rom-features core_test --separate-runtimes \
  --runtime-features test-usb-stress-dev0 --output target/usb-stress-fw.zip
```

Run the ARM test archive on VCK190 with `CPTRA_FIRMWARE_BUNDLE` pointing to
that bundle and nextest profile `usb-stress-fpga`.
Alternatively, build the standalone Rust test executable:

```shell
CALIPTRA_HW_REV=latest \
  CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  cargo test -p caliptra-mcu-tests-integration --features fpga_realtime \
  --target aarch64-unknown-linux-gnu --no-run
```

Copy the executable reported by Cargo and the firmware bundle to VCK190, then
run the executable there with `CPTRA_FIRMWARE_BUNDLE` set to the bundle's
absolute path and arguments
`--nocapture --test-threads=1 test_fpga_usb_stress_dev0`.
This runner does not require Python, Cargo, or nextest on the board.

The tests verify the CST1 handshake, control echo, and bulk loopback packets
from 0 through 64 bytes with DATA0/DATA1 progression.
The device retains legal 512-byte HS endpoint descriptors, but the current
internal FPGA host has only 64-byte packet buffers. These tests do not claim
full HS source/sink, asynchronous queues, physical port cycling, or Device 1
coverage. They require no Python application and remain opt-in.

The CI workflow in `.github/workflows/build-test.yml` uses the same `xtask` commands to build and run tests. By maintaining the runtime feature list in `builder/src/features.rs`, you ensure that CI always tests the same set of features as your local default build. The emulator itself no longer uses feature flags; all test features are enabled at runtime using the `--test-feature` flag.

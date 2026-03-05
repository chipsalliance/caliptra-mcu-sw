# Testing

The Caliptra MCU software uses integration tests that run on the MCU emulator to verify functionality. These tests are orchestrated using `cargo nextest` and can be run locally or in CI.

## Running Tests

The primary way to run tests is using the `xtask` test command:

```shell
cargo xtask test
```

This command runs all integration tests using `cargo nextest`. It automatically excludes certain packages that do not contain tests or are not relevant for the main test suite.

### Test Environment Variables

Integration tests often require pre-built firmware and emulator binary bundles. These are provided via environment variables:

*   `CPTRA_FIRMWARE_BUNDLE`: Path to a ZIP file containing Caliptra Core ROM, Core firmware, MCU ROM, and MCU runtime binaries. This is built with `cargo xtask all-build`.
*   `CPTRA_EMULATOR_BUNDLE`: Path to a ZIP file containing pre-built emulator binaries with different test features. This is built with `cargo xtask emulator-build`.

Example of running tests with pre-built bundles:

```shell
CPTRA_FIRMWARE_BUNDLE=target/all-fw.zip CPTRA_EMULATOR_BUNDLE=target/emulators.zip cargo xtask test
```

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
*   `EMULATOR_TEST_FEATURES`: Add to this list if the feature should be included in the emulator build.

## Continuous Integration (CI)

The CI workflow in `.github/workflows/build-test.yml` uses the same `xtask` commands to build and run tests. By maintaining the feature lists in `builder/src/features.rs`, you ensure that CI always tests the same set of features as your local default build.

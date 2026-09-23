# Component Configuration

The component configuration is the TOML source of truth for SoC authorization,
MCU component SVN, attestation, and firmware ID metadata. See
`builder/component-config.example.toml` for the complete schema.

Image paths are resolved relative to the configuration file. A matching entry
under `[features."name"]` overrides the manifest SVN and MCU fields, and replaces
the base `soc_images` list for that feature. A combined runtime build may select
at most one configured feature override.

Pass the same file to each builder:

```console
cargo xtask runtime-build --component-config component-config.toml
cargo xtask all-build --component-config component-config.toml
cargo xtask auth-manifest create --component-config component-config.toml --output soc-manifest.bin
cargo xtask --features fpga_realtime -- fpga build --component-config component-config.toml
```

When `--component-config` is present, it is authoritative. Commands reject
overlapping legacy metadata such as `--soc-image`, `--mcu-cfg`, `--mcu-image`,
`--svn`, `--vendor`, and `--model`. The build writes these resolved files under
`target/generated` before compiling the runtime:

- `attestation_manifest.toml`
- `soc_image_descriptors.toml`
- `component_svn_manifest.toml`
- `component_svn_manifest.bin`

`auth-manifest create` also writes `mcu_runtime_with_component_svn.bin` when the
configured MCU runtime does not already contain the generated SVN manifest. The
SoC authorization manifest authenticates this final prefixed runtime.

Standalone `auth-manifest create` and `auth-manifest verify` default to the
emulator component defaults. Pass `--platform fpga` to resolve FPGA defaults.

Verify an authorization manifest against the same metadata with:

```console
cargo xtask auth-manifest verify \
  --manifest soc-manifest.bin \
  --component-config component-config.toml
```

The command prints `valid` on success and returns an error describing the first
metadata mismatch otherwise. Use `--feature NAME` with `auth-manifest create` or
`verify` to select a feature override.

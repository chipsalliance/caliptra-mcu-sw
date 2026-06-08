// Licensed under the Apache-2.0 license

//! A collection of useful utilities for xtask operations.

use std::path::PathBuf;

use anyhow::{bail, Result};

use caliptra_mcu_firmware_bundler::utils::find_workspace_directory;

// Default emulator manifests use the constrained 512 KB SRAM layout (matches
// the real device).  Built by the default `release` cargo profile.
const EMU_USER_APP_MANIFEST: &str = "firmware-bundler/reference/emulator/user-app.toml";
const EMU_EXAMPLE_APP_MANIFEST: &str = "firmware-bundler/reference/emulator/example-app.toml";
// `devel` profile mirrors the dev-time layout with 1 MB SRAM so the debug-only
// Tock components (Console / DebugWriter / LowLevelDebug / ProcessConsole) fit
// alongside the kernel and apps.  Only emulator gets a `*-devel.toml` for now —
// FPGA SRAM is fixed by the FPGA fabric and always uses the single layout.
const EMU_USER_APP_MANIFEST_DEVEL: &str = "firmware-bundler/reference/emulator/user-app-devel.toml";
const EMU_EXAMPLE_APP_MANIFEST_DEVEL: &str =
    "firmware-bundler/reference/emulator/example-app-devel.toml";
const FPGA_USER_APP_MANIFEST: &str = "firmware-bundler/reference/fpga/user-app.toml";
const FPGA_EXAMPLE_APP_MANIFEST: &str = "firmware-bundler/reference/fpga/example-app.toml";

pub fn manifest_file(platform: Option<&str>, example_app: bool) -> Result<PathBuf> {
    manifest_file_for_profile(platform, example_app, None)
}

/// Resolve the bundler platform manifest for `platform`, optionally swapping
/// to the shipping `*.toml` variant when `profile == Some("release")`.  All
/// other profile names — including `None`, `"devel"`, and any custom name —
/// fall through to the dev-time `*-devel.toml` manifest with the 1 MB SRAM
/// layout.  This matches `xtask`'s default-profile semantics: `runtime-build`
/// uses `devel` unless the caller explicitly opts into `--profile release`.
pub fn manifest_file_for_profile(
    platform: Option<&str>,
    example_app: bool,
    profile: Option<&str>,
) -> Result<PathBuf> {
    let release = matches!(profile, Some("release"));
    let manifest = match platform {
        Some("emulator") | None => match (example_app, release) {
            (true, true) => EMU_EXAMPLE_APP_MANIFEST,
            (true, false) => EMU_EXAMPLE_APP_MANIFEST_DEVEL,
            (false, true) => EMU_USER_APP_MANIFEST,
            (false, false) => EMU_USER_APP_MANIFEST_DEVEL,
        },
        Some("fpga") => {
            // FPGA SRAM is hardware-constrained; no `*-devel.toml` variant.
            if example_app {
                FPGA_EXAMPLE_APP_MANIFEST
            } else {
                FPGA_USER_APP_MANIFEST
            }
        }
        _ => bail!("Invalid platform {platform:?}, supported options are 'emulator' or 'fpga'"),
    };

    find_workspace_directory().map(|w| w.join(manifest))
}

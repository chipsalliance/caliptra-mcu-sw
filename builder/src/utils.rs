// Licensed under the Apache-2.0 license

//! A collection of useful utilities for xtask operations.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use caliptra_mcu_firmware_bundler::utils::find_workspace_directory;

/// Write `contents` to `path` only if the file is missing or differs.
///
/// Firmware build scripts track generated inputs (e.g. the files under
/// `target/generated/`) with `cargo:rerun-if-changed`, which compares mtimes.
/// Rewriting identical bytes would bump the mtime and force cargo to rebuild
/// the firmware, so leave unchanged files untouched. Returns whether the file
/// was written.
pub(crate) fn write_if_changed(path: &Path, contents: impl AsRef<[u8]>) -> std::io::Result<bool> {
    let contents = contents.as_ref();
    if std::fs::read(path).is_ok_and(|existing| existing == contents) {
        return Ok(false);
    }
    std::fs::write(path, contents)?;
    Ok(true)
}

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
const EMU_BARE_METAL_MANIFEST: &str = "firmware-bundler/reference/emulator/bare-metal.toml";
const FPGA_BARE_METAL_MANIFEST: &str = "firmware-bundler/reference/fpga/bare-metal.toml";

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

pub fn bare_metal_manifest_file(platform: Option<&str>) -> Result<PathBuf> {
    let manifest = match platform {
        Some("emulator") | None => EMU_BARE_METAL_MANIFEST,
        Some("fpga") => FPGA_BARE_METAL_MANIFEST,
        _ => bail!("Invalid platform {platform:?}, supported options are 'emulator' or 'fpga'"),
    };

    find_workspace_directory().map(|w| w.join(manifest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP;

    #[test]
    fn emulator_rom_and_runtime_share_handoff_layout() {
        for example_app in [false, true] {
            for profile in [None, Some("devel"), Some("release")] {
                let path = match profile {
                    None => manifest_file(Some("emulator"), example_app),
                    Some(_) => manifest_file_for_profile(Some("emulator"), example_app, profile),
                }
                .unwrap();
                let manifest: toml::Value =
                    toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
                let dccm = &manifest["platform"]["dccm"];
                let handoff = &manifest["platform"]["handoff"];
                let offset = handoff["offset"].as_integer().unwrap();
                let size = handoff["size"].as_integer().unwrap();

                assert_eq!(
                    offset,
                    i64::from(EMULATOR_MEMORY_MAP.handoff_offset),
                    "{}",
                    path.display()
                );
                assert_eq!(size, i64::from(EMULATOR_MEMORY_MAP.handoff_size));
                assert_eq!(
                    dccm["offset"].as_integer().unwrap() + dccm["size"].as_integer().unwrap(),
                    offset
                );
                assert_eq!(
                    offset + size,
                    i64::from(EMULATOR_MEMORY_MAP.dccm_offset)
                        + i64::from(EMULATOR_MEMORY_MAP.dccm_size)
                );
                assert_eq!(
                    manifest["platform"]["runtime_memory"]["sram"]["size"].as_integer(),
                    Some(if profile == Some("release") {
                        0x8_0000
                    } else {
                        0x10_0000
                    })
                );
            }
        }
    }
}

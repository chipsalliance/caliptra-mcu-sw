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

    #[test]
    fn handoff_layout_matches_profile_for_rom_and_runtime() {
        for platform in ["emulator", "fpga"] {
            for example_app in [false, true] {
                for profile in [None, Some("devel"), Some("release")] {
                    let path =
                        manifest_file_for_profile(Some(platform), example_app, profile).unwrap();
                    let manifest: toml::Value =
                        toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
                    let handoff = &manifest["platform"]["handoff"];
                    let dccm = &manifest["platform"]["dccm"];
                    let release_layout = platform == "fpga" || profile == Some("release");
                    assert_eq!(
                        handoff["offset"].as_integer(),
                        Some(if release_layout {
                            0x5000_3c00
                        } else {
                            0x5000_3800
                        }),
                        "{platform}, example_app={example_app}, profile={profile:?}"
                    );
                    assert_eq!(
                        handoff["size"].as_integer(),
                        Some(if release_layout { 1024 } else { 2048 })
                    );
                    assert_eq!(
                        dccm["offset"].as_integer().unwrap() + dccm["size"].as_integer().unwrap(),
                        handoff["offset"].as_integer().unwrap()
                    );
                }
            }
        }
    }

    #[test]
    fn invalid_platform_has_no_handoff_layout() {
        assert!(manifest_file_for_profile(Some("invalid"), false, Some("release")).is_err());
    }

    #[test]
    fn handoff_release_features_match_kernel_and_userspace() {
        for (platform, features) in [
            ("emulator", crate::features::RELEASE_RUNTIME_TEST_FEATURES),
            ("fpga", crate::features::FPGA_RELEASE_RUNTIME_TEST_FEATURES),
        ] {
            for path in [
                format!("platforms/{platform}/runtime/Cargo.toml"),
                "platforms/emulator/runtime/userspace/apps/user/Cargo.toml".to_string(),
            ] {
                let manifest: toml::Value = toml::from_str(
                    &std::fs::read_to_string(crate::PROJECT_ROOT.join(&path)).unwrap(),
                )
                .unwrap();
                for feature in features {
                    assert!(
                        manifest["features"].get(*feature).is_some(),
                        "{platform} release feature {feature} is missing from {path}"
                    );
                }
            }
        }
    }

    #[test]
    fn handoff_syscall_regression_cannot_enable_address_observing_hooks() {
        let manifest: toml::Value = toml::from_str(
            &std::fs::read_to_string(
                crate::PROJECT_ROOT.join("platforms/emulator/runtime/Cargo.toml"),
            )
            .unwrap(),
        )
        .unwrap();
        let features = manifest["features"].as_table().unwrap();
        let mut pending = vec!["test-handoff-syscalls"];
        let mut visited = std::collections::BTreeSet::new();
        while let Some(feature) = pending.pop() {
            if !visited.insert(feature) {
                continue;
            }
            assert!(
                !["test-handoff", "test-exit-immediately", "debug"].contains(&feature),
                "The production-path handoff regression must not enable {feature}"
            );
            for dependency in features[feature].as_array().unwrap() {
                let dependency = dependency.as_str().unwrap();
                if features.contains_key(dependency) {
                    pending.push(dependency);
                }
            }
        }
        assert!(visited.contains("release"));
        assert!(visited.contains("ocp-lock"));
    }
}

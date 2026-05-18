// Licensed under the Apache-2.0 license

//! A collection of useful utilities for xtask operations.

use std::path::PathBuf;

use anyhow::{bail, Result};

use caliptra_mcu_firmware_bundler::utils::find_workspace_directory;

const EMU_USER_APP_MANIFEST: &str = "firmware-bundler/reference/emulator/user-app.toml";
const EMU_EXAMPLE_APP_MANIFEST: &str = "firmware-bundler/reference/emulator/example-app.toml";
const FPGA_USER_APP_MANIFEST: &str = "firmware-bundler/reference/fpga/user-app.toml";
const FPGA_EXAMPLE_APP_MANIFEST: &str = "firmware-bundler/reference/fpga/example-app.toml";
const EMU_BARE_METAL_MANIFEST: &str = "firmware-bundler/reference/emulator/bare-metal.toml";
const FPGA_BARE_METAL_MANIFEST: &str = "firmware-bundler/reference/fpga/bare-metal.toml";

pub fn manifest_file(platform: Option<&str>, example_app: bool) -> Result<PathBuf> {
    let manifest = match platform {
        Some("emulator") | None => {
            if example_app {
                EMU_EXAMPLE_APP_MANIFEST
            } else {
                EMU_USER_APP_MANIFEST
            }
        }
        Some("fpga") => {
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

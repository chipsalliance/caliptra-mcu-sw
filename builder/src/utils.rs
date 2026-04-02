// Licensed under the Apache-2.0 license

//! A collection of useful utilities for xtask operations.

use std::path::PathBuf;

use anyhow::Result;

use crate::Platform;
use mcu_firmware_bundler::utils::find_workspace_directory;

const EMU_USER_APP_MANIFEST: &str = "firmware-bundler/reference/emulator/user-app.toml";
const EMU_EXAMPLE_APP_MANIFEST: &str = "firmware-bundler/reference/emulator/example-app.toml";
const FPGA_USER_APP_MANIFEST: &str = "firmware-bundler/reference/fpga/user-app.toml";
const FPGA_EXAMPLE_APP_MANIFEST: &str = "firmware-bundler/reference/fpga/example-app.toml";

pub fn manifest_file(platform: Platform, example_app: bool) -> Result<PathBuf> {
    let manifest = match platform {
        Platform::Emulator => {
            if example_app {
                EMU_EXAMPLE_APP_MANIFEST
            } else {
                EMU_USER_APP_MANIFEST
            }
        }
        Platform::Fpga => {
            if example_app {
                FPGA_EXAMPLE_APP_MANIFEST
            } else {
                FPGA_USER_APP_MANIFEST
            }
        }
    };

    find_workspace_directory().map(|w| w.join(manifest))
}

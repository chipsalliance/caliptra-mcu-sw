// Licensed under the Apache-2.0 license

//! Build the Runtime Tock kernel image for VeeR RISC-V.
// Based on the tock board Makefile.common.
// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(dead_code)]

use crate::utils::manifest_file;
use crate::{objcopy, target_binary, target_dir, OBJCOPY_FLAGS, PROJECT_ROOT, SYSROOT, TARGET};
use anyhow::{anyhow, bail, Result};
use elf::endian::AnyEndian;
use elf::ElfBytes;
use mcu_config::McuMemoryMap;
use mcu_config_emulator::flash::LoggingFlashConfig;
use mcu_firmware_bundler::args::{
    BuildArgs, BundleArgs, Commands as BundleCommands, Common, LdArgs,
};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;

pub fn runtime_build_with_apps(
    features: &[&str],
    output_name: Option<String>,
    example_app: bool,
    platform: Option<&str>,
    svn: Option<u16>,
) -> Result<PathBuf> {
    let manifest = manifest_file(platform, example_app)?;
    let platform = platform.unwrap_or("emulator");
    let output_name = output_name.unwrap_or_else(|| format!("runtime-{}.bin", platform));

    let common = Common {
        manifest,
        svn,
        ..Default::default()
    };
    let runtime_bin = common.release_dir()?.join(&output_name);

    let runtime_features = if features.is_empty() {
        None
    } else {
        Some(features.join(","))
    };
    let bundle_cmd = BundleCommands::Bundle {
        common,
        ld: LdArgs::default(),
        build: BuildArgs {
            runtime_features,
            ..Default::default()
        },
        bundle: BundleArgs {
            bundle_name: Some(output_name),
        },
    };

    mcu_firmware_bundler::execute(bundle_cmd)?;
    Ok(runtime_bin)
}

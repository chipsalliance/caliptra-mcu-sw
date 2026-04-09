// Licensed under the Apache-2.0 license

//! Build the Runtime Tock kernel image for VeeR RISC-V.
// Based on the tock board Makefile.common.
// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

use crate::utils::manifest_file;
use crate::{CaliptraBuildArgs, PROJECT_ROOT};
use anyhow::Result;
use caliptra_mcu_firmware_bundler::args::{
    BuildArgs, BundleArgs, Commands as BundleCommands, Common, LdArgs,
};
use std::path::PathBuf;

pub fn runtime_build_with_apps(args: &CaliptraBuildArgs) -> Result<PathBuf> {
    let features = args.features;
    let output_name = args.output_name.clone();
    let example_app = args.example_app;
    let platform = args.platform;
    let svn = args.svn;
    let target_dir = args.target_dir.clone();

    let manifest = manifest_file(platform, example_app)?;
    let platform_str = platform.unwrap_or("emulator");
    let output_name = output_name.unwrap_or_else(|| format!("runtime-{}.bin", platform_str));

    let common = Common {
        manifest,
        svn,
        target_dir,
        ..Default::default()
    };
    let release_dir = common.release_dir()?;
    let runtime_bin = release_dir.join(&output_name);

    let runtime_features = features.filter(|s| !s.is_empty()).map(|f| f.to_string());
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

    caliptra_mcu_firmware_bundler::execute(bundle_cmd)?;

    // The bundle step rebuilds the ROM via objcopy, which strips the SHA-384
    // digest appended by rom_build(). Re-apply the digest so the ROM binary
    // stays valid regardless of build order.
    let rom_binary = release_dir.join(format!("mcu-rom-{platform_str}.bin"));
    if rom_binary.exists() {
        let rom_size = crate::rom::rom_size_for_platform(platform_str);
        crate::rom::append_rom_digest(&rom_binary, rom_size)?;
    }

    Ok(runtime_bin)
}

pub fn bare_metal_build() -> Result<PathBuf> {
    let manifest = PROJECT_ROOT.join("runtime/bare-metal/manifest.toml");
    let output_name = "runtime-bare-metal.bin".to_string();

    let common = Common {
        manifest,
        ..Default::default()
    };
    let runtime_bin = common.release_dir()?.join(&output_name);

    let bundle_cmd = BundleCommands::Bundle {
        common,
        ld: LdArgs::default(),
        build: BuildArgs::default(),
        bundle: BundleArgs {
            bundle_name: Some(output_name),
        },
    };

    caliptra_mcu_firmware_bundler::execute(bundle_cmd)?;
    Ok(runtime_bin)
}

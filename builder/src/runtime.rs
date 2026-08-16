// Licensed under the Apache-2.0 license

//! Build the Runtime Tock kernel image for VeeR RISC-V.
// Based on the tock board Makefile.common.
// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

use crate::utils::manifest_file_for_profile;
use crate::{CaliptraBuildArgs, PROJECT_ROOT};
use anyhow::Result;
use caliptra_mcu_firmware_bundler::args::{
    BuildArgs, BundleArgs, Commands as BundleCommands, Common, LdArgs,
};
use std::path::PathBuf;

fn runtime_features(
    features: Option<&str>,
    platform: &str,
    no_default_features: bool,
    example_app: bool,
) -> Option<String> {
    let mut runtime_features = features.filter(|s| !s.is_empty()).map(str::to_string);

    // The user app is shared by emulator and FPGA, but DOT Runtime storage is
    // currently implemented only by the emulator kernel. Keep DOT out of the
    // app's platform-neutral default feature set and add it for emulator builds.
    if platform == "emulator" && !no_default_features && !example_app {
        for feature in ["dot-mci-mailbox", "dot-spdm-vdm"] {
            let features = runtime_features.get_or_insert_with(String::new);
            if !features.split(',').any(|enabled| enabled == feature) {
                if !features.is_empty() {
                    features.push(',');
                }
                features.push_str(feature);
            }
        }
    }

    if platform == "fpga" {
        let features = runtime_features.get_or_insert_with(String::new);
        if !features
            .split(',')
            .any(|feature| feature == "disable-lms-sig-verify")
        {
            if !features.is_empty() {
                features.push(',');
            }
            features.push_str("disable-lms-sig-verify");
        }
    }

    runtime_features
}

pub fn runtime_build_with_apps(args: &CaliptraBuildArgs) -> Result<PathBuf> {
    let features = args.features;
    let output_name = args.output_name.clone();
    let example_app = args.example_app;
    let platform = args.platform;
    let svn = args.svn;
    let target_dir = args.target_dir.clone();
    let profile = args.profile.unwrap_or("devel").to_string();

    let manifest = manifest_file_for_profile(platform, example_app, args.profile)?;
    let platform_str = platform.unwrap_or("emulator");
    let output_name = output_name.unwrap_or_else(|| format!("runtime-{}.bin", platform_str));

    let common = Common {
        manifest,
        svn,
        target_dir,
        profile,
        ..Default::default()
    };
    let release_dir = common.release_dir()?;
    let runtime_bin = release_dir.join(&output_name);

    let runtime_features = runtime_features(
        features,
        platform_str,
        args.no_default_features,
        example_app,
    );
    let bundle_cmd = BundleCommands::Bundle {
        common,
        ld: LdArgs::default(),
        build: BuildArgs {
            runtime_features,
            no_default_features: args.no_default_features,
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

#[cfg(test)]
mod tests {
    use super::runtime_features;

    #[test]
    fn emulator_defaults_enable_dot() {
        assert_eq!(
            runtime_features(Some("release,all-features"), "emulator", false, false).as_deref(),
            Some("release,all-features,dot-mci-mailbox,dot-spdm-vdm")
        );
    }

    #[test]
    fn emulator_example_app_does_not_receive_user_app_dot_features() {
        assert_eq!(
            runtime_features(Some("test-mcu-svn-gt-fuse"), "emulator", false, true).as_deref(),
            Some("test-mcu-svn-gt-fuse")
        );
    }

    #[test]
    fn explicit_emulator_features_are_unchanged_without_defaults() {
        assert_eq!(
            runtime_features(
                Some("test-caliptra-util-host-spdm-vdm-validator"),
                "emulator",
                true,
                false,
            )
            .as_deref(),
            Some("test-caliptra-util-host-spdm-vdm-validator")
        );
    }

    #[test]
    fn fpga_defaults_exclude_dot() {
        assert_eq!(
            runtime_features(Some("release,all-features"), "fpga", false, false).as_deref(),
            Some("release,all-features,disable-lms-sig-verify")
        );
    }
}

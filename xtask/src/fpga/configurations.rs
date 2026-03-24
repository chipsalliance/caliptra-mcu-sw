// Licensed under the Apache-2.0 license

use anyhow::{bail, Context, Result};
use caliptra_mcu_builder::{AllBuildArgs, ImageCfg, PROJECT_ROOT};
use clap::ValueEnum;

use super::{
    run_command, run_command_with_output,
    utils::{
        build_base_container_command, build_caliptra_firmware, caliptra_sw_workspace_root,
        check_ssh_access, download_bitstream, load_bitstream, rsync_file, run_test_suite,
        NextestArchiveCommand,
    },
    ActionHandler, BootstrapArgs, BuildArgs, BuildTestArgs, TestArgs,
};

/// The FPGA configuration mode
#[derive(Copy, Clone, ValueEnum, Debug)]
pub enum Configuration {
    /// Testing FPGA in Subsystem mode. For example running tests in caliptra-mcu-sw.
    Subsystem,
    /// Running Core tests on a subsystem FPGA. The tests are sourced from caliptra-sw.
    CoreOnSubsystem,
    /// Testing `caliptra-sw` in `core` mode.
    Core,
}

impl Configuration {
    pub fn default_test_profile(&self) -> &str {
        match self {
            Self::Subsystem => "nightly-ci",
            // Test profiles defined in caliptra-sw
            Self::CoreOnSubsystem => "fpga-subsystem",
            Self::Core => "fpga-core",
        }
    }
}

pub enum CommandExecutor {
    /// Runs commands for a subsystem FPGA.
    Subsystem(Subsystem),
    /// Runs commands for a core on subsystem FPGA.
    CoreOnSubsystem(CoreOnSubsystem),
    /// Runs commands for a FPGA.
    Core(Core),
}

impl From<Configuration> for CommandExecutor {
    fn from(value: Configuration) -> Self {
        match value {
            Configuration::Subsystem => CommandExecutor::Subsystem(Subsystem::default()),
            Configuration::CoreOnSubsystem => {
                CommandExecutor::CoreOnSubsystem(CoreOnSubsystem::default())
            }
            Configuration::Core => CommandExecutor::Core(Core::default()),
        }
    }
}

impl<'a> Configuration {
    pub fn cache(&'a self, cache_function: impl FnOnce(&'a str) -> Result<()>) -> Result<()> {
        match self {
            Self::Subsystem => cache_function("subsystem")?,
            Self::CoreOnSubsystem => cache_function("core-on-subsystem")?,
            Self::Core => cache_function("core")?,
        }
        Ok(())
    }

    pub fn from_cache(cache_contents: &'a str) -> Result<Self> {
        match cache_contents {
            "subsystem" => Ok(Configuration::Subsystem),
            "core-on-subsystem" => Ok(Configuration::CoreOnSubsystem),
            "core" => Ok(Configuration::Core),
            _ => bail!("FPGA is not bootstrapped. Need to run `xtask fpga bootstrap`"),
        }
    }

    pub fn from_cmd(target_host: Option<&str>) -> Result<Self> {
        check_ssh_access(target_host)?;
        let cache_contents = run_command_with_output(target_host, "cat /dev/shm/fpga-config")?;
        let cache_contents = cache_contents.trim_end();
        Self::from_cache(cache_contents)
    }

    pub fn executor(self) -> CommandExecutor {
        self.into()
    }
}

impl<'a> ActionHandler<'a> for CommandExecutor {
    fn bootstrap(&self, args: &'a BootstrapArgs<'a>) -> Result<()> {
        match self {
            Self::Subsystem(sub) => sub.bootstrap(args),
            Self::CoreOnSubsystem(core) => core.bootstrap(args),
            Self::Core(core) => core.bootstrap(args),
        }
    }

    fn download_bitstream(&self) -> Result<()> {
        match self {
            Self::Subsystem(sub) => sub.download_bitstream(),
            Self::CoreOnSubsystem(core) => core.download_bitstream(),
            Self::Core(core) => core.download_bitstream(),
        }
    }

    fn build(&self, args: &'a BuildArgs<'a>) -> Result<()> {
        match self {
            Self::Subsystem(sub) => sub.build(args),
            Self::CoreOnSubsystem(core) => core.build(args),
            Self::Core(core) => core.build(args),
        }
    }

    fn build_test(&self, args: &'a BuildTestArgs<'a>) -> Result<()> {
        // Delete the file if it exists. Sometimes the docker build fails silently. This will force
        // the rsync to fail in those cases.
        let _ = std::fs::remove_file("caliptra-test-binaries.tar.zst");
        match self {
            Self::Subsystem(sub) => sub.build_test(args),
            Self::CoreOnSubsystem(core) => core.build_test(args),
            Self::Core(core) => core.build_test(args),
        }
    }

    fn test(&self, args: &'a TestArgs) -> Result<()> {
        match self {
            Self::Subsystem(sub) => sub.test(args)?,
            Self::CoreOnSubsystem(core) => core.test(args)?,
            Self::Core(core) => core.test(args)?,
        }
        Ok(())
    }
}

impl CommandExecutor {
    pub fn set_target_host(&mut self, target_host: Option<&str>) -> &mut Self {
        match self {
            Self::Subsystem(sub) => sub.set_target_host(target_host),
            Self::CoreOnSubsystem(core) => core.set_target_host(target_host),
            Self::Core(core) => core.set_target_host(target_host),
        };
        self
    }
    pub fn set_caliptra_fpga(&mut self, caliptra_fpga: bool) -> &mut Self {
        match self {
            Self::Subsystem(sub) => sub.set_caliptra_fpga(caliptra_fpga),
            Self::CoreOnSubsystem(core) => core.set_caliptra_fpga(caliptra_fpga),
            Self::Core(core) => core.set_caliptra_fpga(caliptra_fpga),
        };
        self
    }
}

#[derive(Clone, Default, Debug)]
/// Implements FPGA actions for a Subsystem FPGA.
pub struct Subsystem {
    target_host: Option<String>,
    caliptra_fpga: bool,
}

impl Subsystem {
    fn set_target_host(&mut self, target_host: Option<&str>) {
        self.target_host = target_host.map(|f| f.to_owned());
    }
    fn set_caliptra_fpga(&mut self, caliptra_fpga: bool) {
        self.caliptra_fpga = caliptra_fpga;
    }
}

impl<'a> ActionHandler<'a> for Subsystem {
    fn bootstrap(&self, args: &'a BootstrapArgs<'a>) -> Result<()> {
        let bootstrap_cmd= "[ -d caliptra-mcu-sw ] || git clone https://github.com/chipsalliance/caliptra-mcu-sw --branch=main --depth=1";
        let target_host = self.target_host.as_deref();
        run_command(target_host, bootstrap_cmd).context("failed to clone caliptra-mcu-sw repo")?;

        // Only Petalinux images (similar to the Caliptra CI image) support segmented bitstreams.
        if !self.caliptra_fpga {
            return Ok(());
        }

        handle_bitstream_bootstrap(
            target_host,
            args.bitstream.as_deref(),
            &bitstream_manifest_path(&PROJECT_ROOT, "subsystem.toml"),
        )?;
        Ok(())
    }

    fn download_bitstream(&self) -> Result<()> {
        download_bitstream(
            None,
            &bitstream_manifest_path(&PROJECT_ROOT, "subsystem.toml"),
        )?;
        Ok(())
    }

    fn build(&self, _: &'a BuildArgs<'a>) -> Result<()> {
        // TODO(clundin): Modify `caliptra_mcu_builder::all_build` to return the zip instead of writing it?
        // TODO(clundin): Place FPGA xtask artifacts in a specific folder?
        let mcu_cfgs = Some(vec![ImageCfg {
            path: "mcu".into(),
            load_addr: 0x0,
            staging_addr: 0xB00C0000,
            image_id: 2,
            exec_bit: 2,
            component_id: 2,
            feature: "test-fpga-flash-ctrl".to_string(),
        }]);
        let args = AllBuildArgs {
            output: Some("all-fw.zip"),
            platform: Some("fpga"),
            mcu_cfgs: mcu_cfgs,
            separate_runtimes: true,
            ..Default::default()
        };
        caliptra_mcu_builder::all_build(args)?;
        if let Some(target_host) = &self.target_host {
            rsync_file(target_host, "all-fw.zip", ".", false)?;
        }
        Ok(())
    }

    fn build_test(&self, args: &'a BuildTestArgs<'a>) -> Result<()> {
        let mut container = build_base_container_command()?;
        let cmd = NextestArchiveCommand::new("/work-dir")
            .feature("fpga_realtime")
            .package_filter(args.package_filter.as_deref())
            .build();

        container.arg(&cmd);
        container
            .status()
            .context("failed to cross compile tests")?;
        if let Some(target_host) = &self.target_host {
            rsync_file(target_host, "caliptra-test-binaries.tar.zst", ".", false)
                .context("failed to copy tests to fpga")?;
        }
        Ok(())
    }

    fn test(&self, args: &'a TestArgs) -> Result<()> {
        let test_filters = args
            .test_filter
            .as_ref()
            .map(|filter_str| filter_str.split(',').collect());
        let to = if *args.test_output {
            "--no-capture"
        } else {
            "--test-threads=1"
        };

        let bundle = std::env::var("CPTRA_FIRMWARE_BUNDLE")
            .unwrap_or_else(|_| "$HOME/all-fw.zip".to_string());
        let prelude = format!("CPTRA_FIRMWARE_BUNDLE={bundle}");
        run_test_suite(
            "caliptra-mcu-sw",
            &prelude,
            test_filters,
            to,
            self.target_host.as_deref(),
            args.default_test_profile,
        )?;
        Ok(())
    }
}

#[derive(Clone, Default, Debug)]
/// Implements FPGA actions for a Core on Subsystem FPGA.
pub struct CoreOnSubsystem {
    target_host: Option<String>,
    caliptra_fpga: bool,
}

impl CoreOnSubsystem {
    fn set_target_host(&mut self, target_host: Option<&str>) {
        self.target_host = target_host.map(|f| f.to_owned());
    }
    fn set_caliptra_fpga(&mut self, caliptra_fpga: bool) {
        self.caliptra_fpga = caliptra_fpga;
    }
}

impl<'a> ActionHandler<'a> for CoreOnSubsystem {
    fn bootstrap(&self, args: &'a BootstrapArgs<'a>) -> Result<()> {
        let bootstrap_cmd= "[ -d caliptra-sw ] || git clone https://github.com/chipsalliance/caliptra-sw --branch=caliptra-2.0 --depth=1";
        let target_host = self.target_host.as_deref();
        run_command(target_host, bootstrap_cmd).context("failed to clone caliptra-sw repo")?;

        // Only Petalinux images (similar to the Caliptra CI image) support segmented bitstreams.
        if !self.caliptra_fpga {
            return Ok(());
        }

        handle_bitstream_bootstrap(
            target_host,
            args.bitstream.as_deref(),
            &bitstream_manifest_path(&caliptra_sw_workspace_root(), "subsystem.toml"),
        )?;
        Ok(())
    }

    fn download_bitstream(&self) -> Result<()> {
        download_bitstream(
            None,
            &bitstream_manifest_path(&caliptra_sw_workspace_root(), "subsystem.toml"),
        )?;
        Ok(())
    }
    fn build(&self, args: &'a BuildArgs<'a>) -> Result<()> {
        let caliptra_sw = caliptra_sw_workspace_root();
        let rom_path = caliptra_mcu_builder::rom_build(&caliptra_mcu_builder::CaliptraBuildArgs {
            platform: Some("fpga"),
            features: Some("core_test"),
            ..Default::default()
        })?;
        if !args.mcu {
            build_caliptra_firmware(&caliptra_sw, args.fw_id.as_deref())?;
        }
        if let Some(target_host) = &self.target_host {
            rsync_file(
                target_host,
                "/tmp/caliptra-test-firmware",
                "/tmp/caliptra-test-firmware",
                false,
            )?;
            rsync_file(
                target_host,
                &rom_path.to_string_lossy(),
                "mcu-rom-fpga.bin",
                false,
            )?;
        }
        Ok(())
    }

    fn build_test(&self, args: &'a BuildTestArgs<'a>) -> Result<()> {
        let caliptra_sw = caliptra_sw_workspace_root();
        let base_name = caliptra_sw.file_name().unwrap().to_str().unwrap();

        let mut container = build_base_container_command()?;
        let cmd = NextestArchiveCommand::new(&format!("/{base_name}"))
            .features(&["fpga_subsystem", "itrng"])
            .package_filter(args.package_filter.as_deref())
            .build();

        container.arg(&cmd);
        container
            .status()
            .context("failed to cross compile tests")?;
        if let Some(target_host) = &self.target_host {
            rsync_file(target_host, "caliptra-test-binaries.tar.zst", ".", false)
                .context("failed to copy tests to fpga")?;
        }
        Ok(())
    }

    fn test(&self, args: &'a TestArgs) -> Result<()> {
        let test_filters = args
            .test_filter
            .as_ref()
            .map(|filter_str| filter_str.split(',').collect());

        let to = if *args.test_output {
            "--no-capture"
        } else {
            "--test-threads=1"
        };

        let mcu_rom = std::env::var("CPTRA_MCU_ROM")
            .unwrap_or_else(|_| "/home/runner/mcu-rom-fpga.bin".to_string());
        let uio_num = std::env::var("CPTRA_UIO_NUM").unwrap_or_else(|_| "0".to_string());
        let fw_dir = std::env::var("CALIPTRA_PREBUILT_FW_DIR")
            .unwrap_or_else(|_| "/tmp/caliptra-test-firmware/caliptra-test-firmware".to_string());
        let prelude = format!("CPTRA_MCU_ROM={mcu_rom} CPTRA_UIO_NUM={uio_num} CALIPTRA_PREBUILT_FW_DIR={fw_dir} CALIPTRA_IMAGE_NO_GIT_REVISION=1");
        run_test_suite(
            "caliptra-sw",
            &prelude,
            test_filters,
            to,
            self.target_host.as_deref(),
            args.default_test_profile,
        )?;
        Ok(())
    }
}

#[derive(Clone, Default, Debug)]
/// Implements FPGA actions for a Core FPGA.
pub struct Core {
    target_host: Option<String>,
    caliptra_fpga: bool,
}

impl Core {
    fn set_target_host(&mut self, target_host: Option<&str>) {
        self.target_host = target_host.map(|f| f.to_owned());
    }
    fn set_caliptra_fpga(&mut self, caliptra_fpga: bool) {
        self.caliptra_fpga = caliptra_fpga;
    }
}

impl<'a> ActionHandler<'a> for Core {
    fn bootstrap(&self, args: &'a BootstrapArgs<'a>) -> Result<()> {
        let bootstrap_cmd= "[ -d caliptra-sw ] || git clone https://github.com/chipsalliance/caliptra-sw --branch=caliptra-2.0 --depth=1";
        let target_host = self.target_host.as_deref();
        run_command(target_host, bootstrap_cmd).context("failed to clone caliptra-sw repo")?;

        // Only Petalinux images (similar to the Caliptra CI image) support segmented bitstreams.
        if !self.caliptra_fpga {
            return Ok(());
        }

        handle_bitstream_bootstrap(
            target_host,
            args.bitstream.as_deref(),
            &bitstream_manifest_path(&caliptra_sw_workspace_root(), "core.toml"),
        )?;
        Ok(())
    }

    fn download_bitstream(&self) -> Result<()> {
        download_bitstream(
            None,
            &bitstream_manifest_path(&caliptra_sw_workspace_root(), "core.toml"),
        )?;
        Ok(())
    }
    fn build(&self, args: &'a BuildArgs<'a>) -> Result<()> {
        let caliptra_sw = caliptra_sw_workspace_root();
        if !args.mcu {
            build_caliptra_firmware(&caliptra_sw, args.fw_id.as_deref())?;
        }
        if let Some(target_host) = &self.target_host {
            rsync_file(
                target_host,
                "/tmp/caliptra-test-firmware",
                "/tmp/caliptra-test-firmware",
                false,
            )?;
        }
        Ok(())
    }

    fn build_test(&self, args: &'a BuildTestArgs<'a>) -> Result<()> {
        let caliptra_sw = caliptra_sw_workspace_root();
        let base_name = caliptra_sw.file_name().unwrap().to_str().unwrap();

        let mut container = build_base_container_command()?;
        let cmd = NextestArchiveCommand::new(&format!("/{base_name}"))
            .features(&["fpga_realtime", "itrng"])
            .package_filter(args.package_filter.as_deref())
            .build();

        container.arg(&cmd);
        container
            .status()
            .context("failed to cross compile tests")?;
        if let Some(target_host) = &self.target_host {
            rsync_file(target_host, "caliptra-test-binaries.tar.zst", ".", false)
                .context("failed to copy tests to fpga")?;
        }
        Ok(())
    }

    fn test(&self, args: &'a TestArgs) -> Result<()> {
        let test_filters = args
            .test_filter
            .as_ref()
            .map(|filter_str| filter_str.split(',').collect());

        let to = if *args.test_output {
            "--no-capture"
        } else {
            "--test-threads=1"
        };

        let uio_num = std::env::var("CPTRA_UIO_NUM").unwrap_or_else(|_| "0".to_string());
        let fw_dir = std::env::var("CALIPTRA_PREBUILT_FW_DIR")
            .unwrap_or_else(|_| "/tmp/caliptra-test-firmware/caliptra-test-firmware".to_string());
        let prelude = format!("CPTRA_UIO_NUM={uio_num} CALIPTRA_PREBUILT_FW_DIR={fw_dir} CALIPTRA_IMAGE_NO_GIT_REVISION=1");
        run_test_suite(
            "caliptra-sw",
            &prelude,
            test_filters,
            to,
            self.target_host.as_deref(),
            args.default_test_profile,
        )?;
        Ok(())
    }
}

fn bitstream_manifest_path(root: &std::path::Path, toml_name: &str) -> std::path::PathBuf {
    root.join("hw")
        .join("fpga")
        .join("bitstream_manifests")
        .join(toml_name)
}

fn handle_bitstream_bootstrap(
    target_host: Option<&str>,
    bitstream_arg: Option<&std::path::Path>,
    manifest_path: &std::path::Path,
) -> Result<()> {
    if let Some(bitstream) = bitstream_arg {
        if let Some(target_host) = target_host {
            rsync_file(
                target_host,
                &bitstream.display().to_string(),
                "caliptra-bitstream.pdi",
                false,
            )
            .context("failed to copy bitstream to fpga")?;
        } else {
            std::fs::copy(bitstream, "caliptra-bitstream.pdi").context("copy bitstream pdi")?;
        }
    } else {
        download_bitstream(target_host, manifest_path)?;
    }
    load_bitstream(target_host)?;
    Ok(())
}

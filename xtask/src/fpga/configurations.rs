// Licensed under the Apache-2.0 license

use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use mcu_builder::{AllBuildArgs, ImageCfg, PROJECT_ROOT};

use super::{
    run_command, run_command_with_output,
    utils::{
        build_base_docker_command, caliptra_sw_workspace_root, download_bitstream_pdi, rsync_file,
        run_test_suite,
    },
    ActionHandler, BuildArgs, BuildTestArgs, TestArgs,
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
        let cache_contents = run_command_with_output(target_host, "cat /dev/shm/fpga-config")?;
        let cache_contents = cache_contents.trim_end();
        Self::from_cache(cache_contents)
    }

    pub fn executor(self) -> CommandExecutor {
        self.into()
    }
}

impl<'a> ActionHandler<'a> for CommandExecutor {
    fn bootstrap(&self) -> Result<()> {
        match self {
            Self::Subsystem(sub) => sub.bootstrap(),
            Self::CoreOnSubsystem(core) => core.bootstrap(),
            Self::Core(core) => core.bootstrap(),
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
    fn bootstrap(&self) -> Result<()> {
        let bootstrap_cmd= "[ -d caliptra-mcu-sw ] || git clone https://github.com/chipsalliance/caliptra-mcu-sw --branch=main --depth=1";
        let target_host = self.target_host.as_deref();
        run_command(target_host, bootstrap_cmd).context("failed to clone caliptra-mcu-sw repo")?;

        // Only Petalinux images (similar to the Caliptra CI image) support segmented bitstreams.
        if !self.caliptra_fpga {
            return Ok(());
        }

        let subsystem_bitstream = PROJECT_ROOT
            .join("hw")
            .join("fpga")
            .join("bitstream_manifests")
            .join("subsystem.toml");
        download_bitstream_pdi(self.target_host.as_deref(), &subsystem_bitstream)?;
        Ok(())
    }

    fn build(&self, _: &'a BuildArgs<'a>) -> Result<()> {
        // TODO(clundin): Modify `mcu_builder::all_build` to return the zip instead of writing it?
        // TODO(clundin): Place FPGA xtask artifacts in a specific folder?
        let mcu_cfgs = Some(vec![ImageCfg {
            path: "mcu".into(),
            load_addr: 0x0,
            staging_addr: 0xB00C0000,
            image_id: 2,
            exec_bit: 2,
            feature: "test-fpga-flash-ctrl".to_string(),
        }]);
        let args = AllBuildArgs {
            output: Some("all-fw.zip"),
            platform: Some("fpga"),
            runtime_features: Some("test-mctp-capsule-loopback,test-fpga-flash-ctrl,test-pldm-fw-update-e2e,test-firmware-update-streaming"),
            mcu_cfgs: mcu_cfgs,
            separate_runtimes: true,
            ..Default::default()
        };
        mcu_builder::all_build(args)?;
        if let Some(target_host) = &self.target_host {
            rsync_file(target_host, "all-fw.zip", ".", false)?;
        }
        Ok(())
    }

    fn build_test(&self, _args: &'a BuildTestArgs<'a>) -> Result<()> {
        let mut base_cmd = build_base_docker_command()?;
        base_cmd.arg(
                "(cd /work-dir && CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc cargo nextest archive --features=fpga_realtime --target=aarch64-unknown-linux-gnu --archive-file=/work-dir/caliptra-test-binaries.tar.zst --target-dir cross-target/)"
            );
        base_cmd.status().context("failed to cross compile tests")?;
        if let Some(target_host) = &self.target_host {
            rsync_file(target_host, "caliptra-test-binaries.tar.zst", ".", false)
                .context("failed to copy tests to fpga")?;
        }
        Ok(())
    }

    fn test(&self, args: &'a TestArgs) -> Result<()> {
        let default_test_filter_string = String::from(
            "package(mcu-hw-model) and test(test_mailbox_execute),\
            package(mcu-hw-model) and test(test_mailbox_execute),\
            package(tests-integration) and test(test_jtag_taps),\
            package(tests-integration) and test(test_lc_transitions),\
            package(tests-integration) and test(test_manuf_debug_unlock),\
            package(tests-integration) and test(test_prod_debug_unlock),\
            package(tests-integration) and test(test_uds),\
            package(tests-integration) and test(test_imaginary_flash_controller),\
            package(tests-integration) and test(test_fw_update_e2e),\
            package(tests-integration) and test(test_firmware_update_streaming)",
        );
        let test_filter_string = args
            .test_filter
            .as_ref()
            .unwrap_or(&default_test_filter_string);
        let test_filters: Vec<&str> = test_filter_string.split(',').collect();
        let to = if *args.test_output {
            "--no-capture"
        } else {
            "--test-threads=1"
        };

        let prelude = "CPTRA_FIRMWARE_BUNDLE=$HOME/all-fw.zip";
        run_test_suite(
            "caliptra-mcu-sw",
            prelude,
            test_filters,
            to,
            self.target_host.as_deref(),
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
    fn bootstrap(&self) -> Result<()> {
        // TODO(clundin): Consider overriding branch command
        let bootstrap_cmd= "[ -d caliptra-sw ] || git clone https://github.com/chipsalliance/caliptra-sw --branch=main-2.x --depth=1";
        let target_host = self.target_host.as_deref();
        run_command(target_host, bootstrap_cmd).context("failed to clone caliptra-sw repo")?;

        // Only Petalinux images (similar to the Caliptra CI image) support segmented bitstreams.
        if !self.caliptra_fpga {
            return Ok(());
        }

        let caliptra_sw = caliptra_sw_workspace_root();
        let subsystem_bitstream = caliptra_sw
            .join("hw")
            .join("fpga")
            .join("bitstream_manifests")
            .join("subsystem.toml");
        download_bitstream_pdi(self.target_host.as_deref(), &subsystem_bitstream)?;
        Ok(())
    }
    fn build(&self, args: &'a BuildArgs<'a>) -> Result<()> {
        run_command(
            None,
            "mkdir -p /tmp/caliptra-test-firmware/caliptra-test-firmware",
        )?;
        let caliptra_sw = caliptra_sw_workspace_root();
        // Skip building Caliptra binaries when the MCU flag is set.
        if !args.mcu {
            run_command(
                        None,
                        &format!("(cd {} && cargo run --release -p caliptra-builder -- --all_elfs /tmp/caliptra-test-firmware)", caliptra_sw.display()),
                    )?;
        }
        let rom_path = mcu_builder::rom_build(Some("fpga"), "core_test")?;
        if let Some(target_host) = &self.target_host {
            rsync_file(
                target_host,
                "/tmp/caliptra-test-firmware",
                "/tmp/caliptra-test-firmware",
                false,
            )?;
            rsync_file(target_host, &rom_path, "mcu-rom-fpga.bin", false)?;
        }
        Ok(())
    }

    fn build_test(&self, _args: &'a BuildTestArgs<'a>) -> Result<()> {
        let caliptra_sw = caliptra_sw_workspace_root();
        let base_name = caliptra_sw.file_name().unwrap().to_str().unwrap();
        let mut base_cmd = build_base_docker_command()?;
        base_cmd.arg(
                format!("(cd /{} && CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc cargo nextest archive --features=fpga_subsystem,itrng --target=aarch64-unknown-linux-gnu --archive-file=/work-dir/caliptra-test-binaries.tar.zst --target-dir cross-target/)"
            , base_name));
        base_cmd.status().context("failed to cross compile tests")?;
        if let Some(target_host) = &self.target_host {
            rsync_file(target_host, "caliptra-test-binaries.tar.zst", ".", false)
                .context("failed to copy tests to fpga")?;
        }
        Ok(())
    }

    fn test(&self, args: &'a TestArgs) -> Result<()> {
        let default_test_filter = String::from("package(caliptra-drivers)");
        let test_filters = vec![args
            .test_filter
            .as_ref()
            .unwrap_or(&default_test_filter)
            .as_str()];

        let to = if *args.test_output {
            "--no-capture"
        } else {
            "--test-threads=1"
        };

        let prelude = "CPTRA_MCU_ROM=/home/runner/mcu-rom-fpga.bin CPTRA_UIO_NUM=0 CALIPTRA_PREBUILT_FW_DIR=/tmp/caliptra-test-firmware/caliptra-test-firmware CALIPTRA_IMAGE_NO_GIT_REVISION=1";
        run_test_suite(
            "caliptra-sw",
            prelude,
            test_filters,
            to,
            self.target_host.as_deref(),
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
    fn bootstrap(&self) -> Result<()> {
        let bootstrap_cmd= "[ -d caliptra-sw ] || git clone https://github.com/chipsalliance/caliptra-sw --branch=main-2.x --depth=1";
        let target_host = self.target_host.as_deref();
        run_command(target_host, bootstrap_cmd).context("failed to clone caliptra-sw repo")?;

        // Only Petalinux images (similar to the Caliptra CI image) support segmented bitstreams.
        if !self.caliptra_fpga {
            return Ok(());
        }

        let caliptra_sw = caliptra_sw_workspace_root();
        let core_bitstream = caliptra_sw
            .join("hw")
            .join("fpga")
            .join("bitstream_manifests")
            .join("core.toml");
        download_bitstream_pdi(self.target_host.as_deref(), &core_bitstream)?;
        Ok(())
    }
    fn build(&self, _args: &'a BuildArgs<'a>) -> Result<()> {
        run_command(
            None,
            "mkdir -p /tmp/caliptra-test-firmware/caliptra-test-firmware",
        )?;
        let caliptra_sw = caliptra_sw_workspace_root();
        run_command(
                        None,
                        &format!("(cd {} && cargo run --release -p caliptra-builder -- --all_elfs /tmp/caliptra-test-firmware)", caliptra_sw.display()),
                    )?;
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

    fn build_test(&self, _args: &'a BuildTestArgs<'a>) -> Result<()> {
        let caliptra_sw = caliptra_sw_workspace_root();
        let base_name = caliptra_sw.file_name().unwrap().to_str().unwrap();

        let mut base_cmd = build_base_docker_command()?;
        base_cmd.arg(
                format!("(cd /{} && CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc cargo nextest archive --features=fpga_realtime,itrng --target=aarch64-unknown-linux-gnu --archive-file=/work-dir/caliptra-test-binaries.tar.zst --target-dir cross-target/)"
            , base_name));
        base_cmd.status().context("failed to cross compile tests")?;
        if let Some(target_host) = &self.target_host {
            rsync_file(target_host, "caliptra-test-binaries.tar.zst", ".", false)
                .context("failed to copy tests to fpga")?;
        }
        Ok(())
    }

    fn test(&self, args: &'a TestArgs) -> Result<()> {
        let default_test_filter = String::from("package(caliptra-drivers)");
        let test_filters = vec![args
            .test_filter
            .as_ref()
            .unwrap_or(&default_test_filter)
            .as_str()];

        let to = if *args.test_output {
            "--no-capture"
        } else {
            "--test-threads=1"
        };

        let prelude = "CPTRA_UIO_NUM=0 CALIPTRA_PREBUILT_FW_DIR=/tmp/caliptra-test-firmware/caliptra-test-firmware CALIPTRA_IMAGE_NO_GIT_REVISION=1";
        run_test_suite(
            "caliptra-sw",
            prelude,
            test_filters,
            to,
            self.target_host.as_deref(),
        )?;
        Ok(())
    }
}

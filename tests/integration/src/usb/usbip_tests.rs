// Licensed under the Apache-2.0 license

//! Opt-in OS-stack coverage. Unlike normal USB tests, this test requires a
//! prepared Linux VHCI host. Missing prerequisites are errors, never success.

use anyhow::{ensure, Context, Result};
use caliptra_emu_bus::Bus;
use caliptra_emu_cpu::StepAction;
use caliptra_emu_types::RvSize;
use caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP;
use caliptra_mcu_emulator::{Emulator, EmulatorArgs};
use caliptra_mcu_emulator_periph::{LpcipUsbHostController, LpcipUsbRecoveryEvent, UsbIpServer};
use caliptra_mcu_hw_model::{InitParams, McuHwModel, ModelEmulated};
use caliptra_mcu_romtime::McuBootMilestones;
use clap::Parser;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Process(Option<Child>);

impl Process {
    fn spawn(command: &mut Command) -> Result<Self> {
        Ok(Self(Some(
            command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .with_context(|| format!("spawn {command:?}"))?,
        )))
    }

    fn ready(&mut self) -> Result<bool> {
        Ok(self
            .0
            .as_mut()
            .context("process already reaped")?
            .try_wait()?
            .is_some())
    }

    fn output(mut self) -> Result<Output> {
        Ok(self
            .0
            .take()
            .context("process already reaped")?
            .wait_with_output()?)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            match child.try_wait() {
                Ok(None) => {
                    if let Err(error) = child.kill() {
                        eprintln!("USB test helper kill failed: {error}");
                    }
                }
                Ok(Some(_)) => {}
                Err(error) => eprintln!("USB test helper status failed: {error}"),
            }
            if let Err(error) = child.wait() {
                eprintln!("USB test helper reap failed: {error}");
            }
        }
    }
}

fn check_output(output: Output) -> Result<Output> {
    ensure!(
        output.status.success(),
        "helper failed ({}): stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

fn bounded_output(command: &mut Command) -> Result<Output> {
    let mut child = Process::spawn(command)?;
    let start = Instant::now();
    loop {
        if child.ready()? {
            return child.output();
        }
        ensure!(
            start.elapsed() < Duration::from_secs(10),
            "helper timed out: {command:?}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn bounded(command: &mut Command) -> Result<Output> {
    check_output(bounded_output(command)?)
}

fn owned_attachment(text: &str, remote: &str) -> Result<Option<(String, String)>> {
    let mut port = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Port ") {
            let value = value
                .split(':')
                .next()
                .context("invalid usbip port output")?;
            ensure!(
                !value.is_empty() && value.chars().all(|ch| ch.is_ascii_digit()),
                "invalid VHCI port"
            );
            port = Some(value.to_owned());
        }
        if let Some((bus, url)) = line.trim().split_once(" -> ") {
            if url == remote {
                ensure!(
                    !bus.is_empty()
                        && bus
                            .chars()
                            .all(|ch| ch.is_ascii_digit() || ch == '-' || ch == '.'),
                    "invalid local USB bus ID"
                );
                return Ok(Some((port.context("missing VHCI port")?, bus.to_owned())));
            }
        }
    }
    Ok(None)
}

struct Attachment {
    tool: PathBuf,
    remote: String,
    cleaned: bool,
    fixture: Fixture,
    state_file: Option<PathBuf>,
}

impl Attachment {
    fn locate(&mut self, enumerating: bool) -> Result<Option<(String, String)>> {
        let output = self
            .fixture
            .wait_output(Command::new("sudo").arg("-n").arg(&self.tool).arg("port"))?;
        if enumerating
            && !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("open vhci_driver")
        {
            // Some usbip versions cannot resolve the local bus ID until Linux
            // finishes enumeration. The caller's enumeration deadline bounds retries.
            eprintln!("VHCI local bus ID is not yet available during enumeration");
            return Ok(None);
        }
        let output = check_output(output)?;
        owned_attachment(std::str::from_utf8(&output.stdout)?, &self.remote)
    }

    fn cleanup(&mut self) -> Result<()> {
        if let Some((port, _)) = self.locate(false)? {
            self.fixture.wait(
                Command::new("sudo")
                    .arg("-n")
                    .arg(&self.tool)
                    .args(["detach", "-p", &port]),
            )?;
        }
        if let Some(path) = &self.state_file {
            ensure!(
                std::fs::read_to_string(path)?.trim() == self.remote,
                "USB/IP ownership file changed"
            );
            std::fs::remove_file(path)?;
            self.state_file = None;
        }
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for Attachment {
    fn drop(&mut self) {
        if !self.cleaned {
            if let Err(error) = self.cleanup() {
                eprintln!("USB/IP test attachment cleanup failed: {error:#}");
            }
        }
    }
}

enum Executor {
    Model {
        model: Box<ModelEmulated>,
        server: Box<UsbIpServer>,
    },
    Standalone(Box<Emulator>),
}

struct Fixture {
    executor: Executor,
    paused: bool,
    fatal: Option<u32>,
}

impl Fixture {
    fn model(mut model: ModelEmulated) -> Result<Self> {
        let server = UsbIpServer::bind(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            model.lpcip_usb_host_controller.clone(),
        )?;
        model.boot()?;
        Ok(Self {
            executor: Executor::Model {
                model: Box::new(model),
                server: Box::new(server),
            },
            paused: false,
            fatal: None,
        })
    }

    fn host(&self) -> &LpcipUsbHostController {
        match &self.executor {
            Executor::Model { model, .. } => &model.lpcip_usb_host_controller,
            Executor::Standalone(emulator) => &emulator.lpcip_usb_host_controller,
        }
    }

    fn address(&self) -> Result<SocketAddr> {
        Ok(match &self.executor {
            Executor::Model { server, .. } => server.local_addr()?,
            Executor::Standalone(emulator) => emulator
                .usbip_server
                .as_ref()
                .context("standalone USB/IP server")?
                .local_addr()?,
        })
    }

    fn log(&mut self) -> String {
        match &mut self.executor {
            Executor::Model { model, .. } => model.output().peek().to_string(),
            Executor::Standalone(emulator) => {
                let output = emulator
                    .uart_output
                    .as_ref()
                    .expect("UART capture enabled")
                    .borrow();
                format!(
                    "MCU PC={:#x}, Caliptra boot-go={}, ticks={}: {}",
                    emulator.mcu_cpu.read_pc(),
                    emulator.cptra_boot_go.get(),
                    emulator.mcu_cpu.clock.now(),
                    String::from_utf8_lossy(&output)
                )
            }
        }
    }

    fn milestones(&mut self) -> McuBootMilestones {
        match &mut self.executor {
            Executor::Model { model, .. } => model.mci_boot_milestones(),
            Executor::Standalone(emulator) => emulator.mcu_boot_milestones(),
        }
    }

    fn step(&mut self) -> Result<()> {
        match &mut self.executor {
            Executor::Model { server, .. } => server.poll().context("USB/IP bridge")?,
            Executor::Standalone(emulator) if self.paused => emulator
                .usbip_server
                .as_mut()
                .context("standalone USB/IP server")?
                .poll()?,
            Executor::Standalone(_) => {}
        }
        for _ in 0..1000 {
            if self.paused {
                break;
            }
            let fatal = match &mut self.executor {
                Executor::Model { model, .. } => {
                    model.step();
                    model
                        .mcu_bus_for_test()
                        .read(RvSize::Word, EMULATOR_MEMORY_MAP.mci_offset + 0x60)
                }
                Executor::Standalone(emulator) => {
                    ensure!(
                        emulator.step() == StepAction::Continue,
                        "standalone emulator halted"
                    );
                    emulator
                        .mcu_cpu
                        .bus
                        .read(RvSize::Word, EMULATOR_MEMORY_MAP.mci_offset + 0x60)
                }
            }
            .map_err(|error| anyhow::anyhow!("read MCU fatal error: {error:?}"))?;
            if fatal != 0 {
                eprintln!("USB ROM fatal error: {fatal:#x}; {}", self.log());
                self.fatal = Some(fatal);
                self.paused = true;
            } else if self
                .milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
            {
                // Keep serving the host after the real ROM milestone, without
                // executing a test runtime that may exit the entire process.
                self.paused = true;
            }
        }
        Ok(())
    }

    fn wait(&mut self, command: &mut Command) -> Result<Output> {
        check_output(self.wait_output(command)?)
    }

    fn wait_output(&mut self, command: &mut Command) -> Result<Output> {
        self.wait_output_timeout(command, Duration::from_secs(30))
    }

    fn wait_output_timeout(&mut self, command: &mut Command, timeout: Duration) -> Result<Output> {
        let mut child = Process::spawn(command)?;
        self.wait_child(&mut child, timeout)?;
        child.output()
    }

    fn wait_child(&mut self, child: &mut Process, timeout: Duration) -> Result<()> {
        let start = Instant::now();
        loop {
            self.step()?;
            if child.ready()? {
                return Ok(());
            }
            ensure!(
                start.elapsed() < timeout,
                "USB helper timed out; ROM log: {}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Executor::Standalone(emulator) = &self.executor {
            emulator
                .state
                .running
                .store(false, std::sync::atomic::Ordering::Relaxed);
            emulator.state.tick_cond.notify_all();
        }
    }
}

fn required_file(name: &str) -> Result<PathBuf> {
    let path = PathBuf::from(
        std::env::var_os(name).with_context(|| format!("{name} must name an executable"))?,
    );
    ensure!(
        path.is_absolute() && path.is_file(),
        "{name} must be an absolute executable path"
    );
    Ok(path)
}

fn attach_fixture(mut fixture: Fixture) -> Result<(Attachment, Vec<String>, PathBuf)> {
    let tool = required_file("USBIP")?;
    let cli = required_file("USB_RECOVERY_CLI")?;
    bounded(Command::new(&tool).arg("version"))?;
    bounded(Command::new("sudo").args(["-n", "true"]))?;
    ensure!(
        Path::new("/sys/module/vhci_hcd").is_dir(),
        "load vhci_hcd before running this test"
    );
    bounded(Command::new("sudo").arg("-n").arg(&tool).arg("port"))?;

    let started = Instant::now();
    while !fixture.host().connected() {
        fixture.step()?;
        ensure!(
            started.elapsed() < Duration::from_secs(30) && fixture.fatal.is_none(),
            "ROM did not connect USB: {}",
            fixture.log()
        );
    }
    let port = fixture.address()?.port().to_string();
    let remote = format!("usbip://127.0.0.1:{port}/{}", UsbIpServer::BUS_ID);
    eprintln!("Attaching test-owned {remote}");
    let state_file = std::env::var_os("USBIP_STATE_FILE").map(PathBuf::from);
    if let Some(path) = &state_file {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        writeln!(file, "{remote}")?;
    }
    let mut attachment = Attachment {
        tool,
        remote,
        cleaned: false,
        fixture,
        state_file,
    };
    attachment
        .fixture
        .wait(Command::new("sudo").arg("-n").arg(&attachment.tool).args([
            "--tcp-port",
            &port,
            "attach",
            "-r",
            "127.0.0.1",
            "-b",
            UsbIpServer::BUS_ID,
        ]))?;
    let started = Instant::now();
    let sysfs = loop {
        attachment.fixture.step()?;
        if let Some((_, bus)) = attachment.locate(true)? {
            let path = Path::new("/sys/bus/usb/devices").join(bus);
            if path.join("bConfigurationValue").exists()
                && std::fs::read_to_string(path.join("bConfigurationValue"))?.trim() == "1"
            {
                break path;
            }
        }
        ensure!(
            started.elapsed() < Duration::from_secs(30),
            "Linux did not configure the attached device"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    let descriptors = std::fs::read(sysfs.join("descriptors"))?;
    let expected_device = [
        18, 1, 0, 2, 0, 0, 0, 64, 255, 255, 255, 255, 0, 1, 0, 0, 0, 1,
    ];
    let expected_config = [
        9, 2, 28, 0, 1, 1, 0, 0xc0, 0, 9, 4, 0, 0, 0, 0xef, 8, 1, 1, 10, 0x24, 1, 0, 64, 0, 64, 0,
        1, 1,
    ];
    ensure!(
        descriptors.get(..18) == Some(expected_device.as_slice()),
        "unexpected device descriptor"
    );
    ensure!(
        descriptors.get(18..46) == Some(expected_config.as_slice()),
        "unexpected configuration tree"
    );
    let bus = std::fs::read_to_string(sysfs.join("busnum"))?
        .trim()
        .parse::<u8>()?;
    let address = std::fs::read_to_string(sysfs.join("devnum"))?
        .trim()
        .parse::<u8>()?;
    let node = format!("/dev/bus/usb/{bus:03}/{address:03}");
    let uid = unsafe { libc::getuid() };
    bounded(Command::new("sudo").args(["-n", "setfacl", "-m", &format!("u:{uid}:rw"), &node]))?;
    let selector = vec![
        "--vid".into(),
        "0xffff".into(),
        "--pid".into(),
        "0xffff".into(),
        "--bus".into(),
        bus.to_string(),
        "--address".into(),
        address.to_string(),
    ];
    Ok((attachment, selector, cli))
}

#[test]
#[ignore = "requires Linux vhci_hcd, USBIP and USB_RECOVERY_CLI paths, sudo and setfacl"]
fn usbip_linux_enumerates_and_probes_shared_rom() -> Result<()> {
    let rom = super::test_rom("test-lpcip-usb-host")?;
    let model = ModelEmulated::new_unbooted(InitParams {
        mcu_rom: &rom,
        check_booted_to_runtime: false,
        ..Default::default()
    })?;
    let (mut attachment, selector, cli) = attach_fixture(Fixture::model(model)?)?;
    let output = attachment
        .fixture
        .wait(
            Command::new(cli)
                .args(&selector)
                .args(["--overall-timeout-ms", "10000", "probe"]),
        )?;
    ensure!(
        std::str::from_utf8(&output.stdout)?
            .contains("OCP Recovery 1.1; CMS regions: 1; device status: StatusPending"),
        "unexpected CLI discovery response: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    ensure!(
        attachment
            .fixture
            .log()
            .contains("[usb-enumeration-test] configured"),
        "Linux configuration did not traverse shared ROM driver"
    );
    attachment.cleanup()?;
    ensure!(
        attachment.locate(false)?.is_none(),
        "test-owned VHCI attachment leaked"
    );
    Ok(())
}

struct RecoveryFiles {
    _directory: tempfile::TempDir,
    images: [Vec<u8>; 3],
    paths: [PathBuf; 3],
    rom: PathBuf,
    core_rom: PathBuf,
}

impl RecoveryFiles {
    fn new() -> Result<Self> {
        let binaries = super::usb_rom_recovery_tests::binaries();
        let directory = tempfile::tempdir()?;
        let paths =
            ["caliptra.bin", "manifest.bin", "mcu.bin"].map(|name| directory.path().join(name));
        let images = [
            binaries.caliptra_fw.clone(),
            binaries.soc_manifest.clone(),
            binaries.mcu_runtime.clone(),
        ];
        for (path, image) in paths.iter().zip(&images) {
            std::fs::write(path, image)?;
        }
        let rom = directory.path().join("rom.bin");
        let core_rom = directory.path().join("core-rom.bin");
        std::fs::write(&rom, &binaries.mcu_rom)?;
        std::fs::write(&core_rom, &binaries.caliptra_rom)?;
        Ok(Self {
            _directory: directory,
            images,
            paths,
            rom,
            core_rom,
        })
    }

    fn command(
        &self,
        cli: &Path,
        selector: &[String],
        overall_timeout_ms: u64,
        progress_timeout_ms: u64,
    ) -> Command {
        let mut command = Command::new(cli);
        command
            .args(selector)
            .arg("--overall-timeout-ms")
            .arg(overall_timeout_ms.to_string())
            .arg("--progress-timeout-ms")
            .arg(progress_timeout_ms.to_string())
            .args(["recover", "--caliptra-fmc-rt"])
            .arg(&self.paths[0])
            .arg("--soc-manifest")
            .arg(&self.paths[1])
            .arg("--mcu-runtime")
            .arg(&self.paths[2]);
        command
    }
}

#[derive(Default)]
struct Capture {
    requests: Vec<(u8, u32)>,
    consumed: [Vec<u8>; 3],
    activations: Vec<u8>,
}

fn recovery_fixture(
    files: &RecoveryFiles,
    standalone: bool,
) -> Result<(Fixture, Arc<Mutex<Capture>>)> {
    let binaries = super::usb_rom_recovery_tests::binaries();
    let mut fixture = if standalone {
        let mut args = vec![
            "emulator".to_owned(),
            "--usb-recovery".into(),
            "--usbip-listen".into(),
            "127.0.0.1:0".into(),
        ];
        for (name, path) in [
            ("--rom", &files.rom),
            ("--firmware", &files.paths[2]),
            ("--caliptra-rom", &files.core_rom),
            ("--caliptra-firmware", &files.paths[0]),
            ("--soc-manifest", &files.paths[1]),
        ] {
            args.push(name.into());
            args.push(path.to_str().context("fixture path is not UTF-8")?.into());
        }
        for (name, value) in [
            ("--rom-offset", EMULATOR_MEMORY_MAP.rom_offset),
            ("--rom-size", EMULATOR_MEMORY_MAP.rom_size),
            ("--dccm-offset", EMULATOR_MEMORY_MAP.dccm_offset),
            ("--dccm-size", EMULATOR_MEMORY_MAP.dccm_size),
            ("--sram-offset", EMULATOR_MEMORY_MAP.sram_offset),
            ("--sram-size", EMULATOR_MEMORY_MAP.sram_size),
            ("--pic-offset", EMULATOR_MEMORY_MAP.pic_offset),
            ("--i3c-offset", EMULATOR_MEMORY_MAP.i3c_offset),
            ("--i3c-size", EMULATOR_MEMORY_MAP.i3c_size),
            ("--mci-offset", EMULATOR_MEMORY_MAP.mci_offset),
            ("--mci-size", EMULATOR_MEMORY_MAP.mci_size),
            ("--mbox-offset", EMULATOR_MEMORY_MAP.mbox_offset),
            ("--mbox-size", EMULATOR_MEMORY_MAP.mbox_size),
            ("--soc-offset", EMULATOR_MEMORY_MAP.soc_offset),
            ("--soc-size", EMULATOR_MEMORY_MAP.soc_size),
            ("--otp-offset", EMULATOR_MEMORY_MAP.otp_offset),
            ("--otp-size", EMULATOR_MEMORY_MAP.otp_size),
            ("--lc-offset", EMULATOR_MEMORY_MAP.lc_offset),
            ("--lc-size", EMULATOR_MEMORY_MAP.lc_size),
        ] {
            args.extend([name.to_owned(), format!("0x{value:x}")]);
        }
        args.extend([
            "--vendor-pk-hash".to_owned(),
            binaries
                .vendor_pk_hash_u8
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        ]);
        let emulator = Emulator::from_args(EmulatorArgs::try_parse_from(args)?, true)?;
        Fixture {
            executor: Executor::Standalone(Box::new(emulator)),
            paused: false,
            fatal: None,
        }
    } else {
        Fixture::model(ModelEmulated::new_unbooted(InitParams {
            caliptra_rom: &binaries.caliptra_rom,
            mcu_rom: &binaries.mcu_rom,
            vendor_pk_hash: Some(binaries.vendor_pk_hash_u8.as_slice().try_into()?),
            usb_recovery: true,
            check_booted_to_runtime: false,
            ..Default::default()
        })?)?
    };
    let capture = Arc::new(Mutex::new(Capture::default()));
    let captured = capture.clone();
    let limits = files
        .images
        .each_ref()
        .map(|image| image.len().next_multiple_of(4));
    fixture.host().observe_recovery(move |event| {
        let mut capture = captured.lock().unwrap();
        match event {
            LpcipUsbRecoveryEvent::Requested { image, words } => {
                capture.requests.push((image, words))
            }
            LpcipUsbRecoveryEvent::Activated { image } => capture.activations.push(image),
            LpcipUsbRecoveryEvent::Consumed { image, data } => {
                let index = usize::from(image);
                let bytes = capture
                    .consumed
                    .get_mut(index)
                    .expect("supported recovery image index");
                assert!(
                    bytes.len() + data.len() <= limits[index],
                    "unexpected extra FIFO DMA bytes"
                );
                bytes.extend(data);
            }
        }
    })?;
    ensure!(
        !fixture
            .milestones()
            .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE),
        "fixture already booted"
    );
    Ok((fixture, capture))
}

fn assert_payloads(capture: &Capture, files: &RecoveryFiles, count: usize) {
    assert_eq!(capture.requests.len(), count, "requested image count");
    for index in 0..count {
        let mut expected = files.images[index].clone();
        expected.resize(expected.len().next_multiple_of(4), 0);
        assert_eq!(
            capture.consumed[index], expected,
            "exact DMA bytes for image {index}"
        );
        assert_eq!(
            capture.requests[index],
            (index as u8, (expected.len() / 4) as u32)
        );
    }
}

fn complete_boot(standalone: bool) -> Result<()> {
    let files = RecoveryFiles::new()?;
    let (fixture, capture) = recovery_fixture(&files, standalone)?;
    let (mut attachment, selector, cli) = attach_fixture(fixture)?;
    let output = check_output(attachment.fixture.wait_output_timeout(
        &mut files.command(&cli, &selector, 180000, 30000),
        Duration::from_secs(240),
    )?)?;
    ensure!(
        String::from_utf8_lossy(&output.stdout)
            .contains("Recovery success confirmed by device status"),
        "CLI did not confirm recovery"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while !attachment
        .fixture
        .milestones()
        .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
    {
        attachment.fixture.step()?;
        ensure!(
            Instant::now() < deadline && attachment.fixture.fatal.is_none(),
            "MCU did not boot: {}",
            attachment.fixture.log()
        );
    }
    let capture = capture.lock().unwrap();
    assert_eq!(capture.activations, [0, 1, 2]);
    assert_eq!(capture.requests.len(), 3);
    assert_payloads(&capture, &files, 3);
    drop(capture);
    attachment.cleanup()?;
    ensure!(
        attachment.locate(false)?.is_none(),
        "VHCI attachment leaked"
    );
    Ok(())
}

#[test]
#[ignore = "requires Linux VHCI, USBIP, USB_RECOVERY_CLI, sudo and setfacl"]
fn usbip_linux_recovers_common_rom_through_libusb() -> Result<()> {
    complete_boot(false)
}

#[test]
#[ignore = "requires Linux VHCI, USBIP, USB_RECOVERY_CLI, sudo and setfacl"]
fn usbip_linux_recovers_standalone_emulator_through_libusb() -> Result<()> {
    complete_boot(true)
}

#[test]
#[ignore = "requires Linux VHCI, USBIP, USB_RECOVERY_CLI, sudo and setfacl"]
fn usbip_linux_rejects_partial_word_corrupt_manifest() -> Result<()> {
    let mut files = RecoveryFiles::new()?;
    files.images[1].pop();
    files.images[1][0] ^= 0xff;
    std::fs::write(&files.paths[1], &files.images[1])?;
    let (fixture, capture) = recovery_fixture(&files, false)?;
    let (mut attachment, selector, cli) = attach_fixture(fixture)?;
    let output = attachment.fixture.wait_output_timeout(
        &mut files.command(&cli, &selector, 180000, 30000),
        Duration::from_secs(240),
    )?;
    ensure!(!output.status.success(), "corrupt manifest succeeded");
    ensure!(
        !output.stderr.is_empty(),
        "CLI did not explain recovery failure"
    );
    assert_payloads(&capture.lock().unwrap(), &files, 2);
    assert!(!capture.lock().unwrap().activations.contains(&2));
    ensure!(
        !attachment
            .fixture
            .milestones()
            .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE),
        "invalid firmware booted"
    );
    attachment.cleanup()?;
    Ok(())
}

fn invalid_mcu_input(missing: bool) -> Result<()> {
    let mut files = RecoveryFiles::new()?;
    files.images[2].clear();
    if missing {
        std::fs::remove_file(&files.paths[2])?;
    } else {
        std::fs::write(&files.paths[2], [])?;
    }
    let (fixture, capture) = recovery_fixture(&files, false)?;
    let (mut attachment, selector, cli) = attach_fixture(fixture)?;
    let output = attachment.fixture.wait_output_timeout(
        &mut files.command(&cli, &selector, 120000, 30000),
        Duration::from_secs(180),
    )?;
    ensure!(!output.status.success(), "missing MCU image succeeded");
    ensure!(
        String::from_utf8_lossy(&output.stderr).contains(&if missing {
            format!("read {}", files.paths[2].display())
        } else {
            "empty recovery image".to_owned()
        }),
        "unexpected missing-image error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let capture = capture.lock().unwrap();
    assert_payloads(&capture, &files, 0);
    assert!(
        capture.activations.is_empty(),
        "invalid inputs must not mutate recovery"
    );
    assert!(capture.consumed.iter().all(Vec::is_empty));
    drop(capture);
    ensure!(
        !attachment
            .fixture
            .milestones()
            .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE),
        "missing firmware booted"
    );
    attachment.cleanup()?;
    Ok(())
}

#[test]
#[ignore = "requires Linux VHCI, USBIP, USB_RECOVERY_CLI, sudo and setfacl"]
fn usbip_linux_missing_mcu_image_fails_and_cleans_up() -> Result<()> {
    invalid_mcu_input(true)
}

#[test]
#[ignore = "requires Linux VHCI, USBIP, USB_RECOVERY_CLI, sudo and setfacl"]
fn usbip_linux_empty_mcu_image_fails_without_mutation() -> Result<()> {
    invalid_mcu_input(false)
}

fn interrupted_recovery(disconnect: bool) -> Result<()> {
    let files = RecoveryFiles::new()?;
    let (fixture, capture) = recovery_fixture(&files, false)?;
    let (mut attachment, selector, cli) = attach_fixture(fixture)?;
    let mut child = Process::spawn(&mut files.command(&cli, &selector, 120000, 30000))?;
    eprintln!("Waiting for the first completed FIFO DMA before interruption");
    let deadline = Instant::now() + Duration::from_secs(120);
    while capture.lock().unwrap().consumed[0].is_empty() {
        attachment.fixture.step()?;
        ensure!(
            !child.ready()? && Instant::now() < deadline,
            "CLI did not start recovery"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    eprintln!("Interrupting the active recovery transfer");
    if disconnect {
        attachment.fixture.host().set_vbus(false);
    } else {
        attachment.cleanup()?;
    }
    eprintln!("Waiting for the interrupted recovery CLI");
    if let Err(error) = attachment
        .fixture
        .wait_child(&mut child, Duration::from_secs(10))
    {
        ensure!(
            disconnect
                && error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotConnected),
            "unexpected interruption error: {error:#}"
        );
        eprintln!("USB/IP reported the expected device disconnect: {error:#}");
        attachment
            .fixture
            .wait_child(&mut child, Duration::from_secs(10))?;
    }
    let output = child.output()?;
    eprintln!("Interrupted recovery CLI exited with {}", output.status);
    ensure!(
        !output.status.success() && !output.stderr.is_empty(),
        "interrupted CLI transfer did not fail"
    );
    ensure!(
        !attachment
            .fixture
            .milestones()
            .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE),
        "interrupted firmware booted"
    );
    if !attachment.cleaned {
        attachment.cleanup()?;
    }
    ensure!(
        attachment.locate(false)?.is_none(),
        "interrupted VHCI attachment leaked"
    );
    Ok(())
}

#[test]
#[ignore = "requires Linux VHCI, USBIP, USB_RECOVERY_CLI, sudo and setfacl"]
fn usbip_linux_detaches_during_real_recovery() -> Result<()> {
    interrupted_recovery(false)
}

#[test]
#[ignore = "requires Linux VHCI, USBIP, USB_RECOVERY_CLI, sudo and setfacl"]
fn usbip_linux_disconnects_during_real_recovery() -> Result<()> {
    interrupted_recovery(true)
}

#[test]
#[ignore = "requires Linux VHCI, USBIP, USB_RECOVERY_CLI, sudo and setfacl"]
fn usbip_linux_stalled_recovery_times_out() -> Result<()> {
    let files = RecoveryFiles::new()?;
    let (fixture, _) = recovery_fixture(&files, false)?;
    let (mut attachment, selector, cli) = attach_fixture(fixture)?;
    attachment.fixture.paused = true;
    let output = attachment.fixture.wait_output_timeout(
        &mut files.command(&cli, &selector, 1000, 250),
        Duration::from_secs(5),
    )?;
    ensure!(!output.status.success(), "stalled recovery succeeded");
    ensure!(
        String::from_utf8_lossy(&output.stderr).contains("timeout")
            || String::from_utf8_lossy(&output.stderr).contains("timed out"),
        "CLI did not report a bounded timeout: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    attachment.cleanup()?;
    Ok(())
}

#[test]
fn attachment_parser_matches_exact_remote_and_rejects_bad_identifiers() {
    let ports = "Port 00: <Port in Use>\n  1-1 -> usbip://127.0.0.1:1234/1-1\nPort 01: <Port in Use>\n  2-1 -> usbip://127.0.0.1:1235/1-1\n";
    assert_eq!(
        owned_attachment(ports, "usbip://127.0.0.1:1235/1-1").unwrap(),
        Some(("01".into(), "2-1".into()))
    );
    assert!(owned_attachment(ports, "usbip://127.0.0.1:123/1-1")
        .unwrap()
        .is_none());
    assert!(owned_attachment("Port ../x: invalid\n", "anything").is_err());
    assert!(owned_attachment(
        "Port 01: active\n../x -> usbip://host/device",
        "usbip://host/device"
    )
    .is_err());
}

// Licensed under the Apache-2.0 license

//! Opt-in OS-stack coverage. Unlike normal USB tests, this test requires a
//! prepared Linux VHCI host. Missing prerequisites are errors, never success.

use anyhow::{ensure, Context, Result};
use caliptra_mcu_emulator_periph::UsbIpServer;
use caliptra_mcu_hw_model::{InitParams, McuHwModel, ModelEmulated};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
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

struct Fixture {
    model: ModelEmulated,
    server: UsbIpServer,
}

impl Fixture {
    fn step(&mut self) -> Result<()> {
        self.server.poll().context("USB/IP bridge")?;
        for _ in 0..1000 {
            self.model.step();
            let log = self.model.output().peek();
            ensure!(
                !log.contains("initialization failed") && !log.contains("service failed"),
                "enumeration fixture failed: {log}"
            );
        }
        Ok(())
    }

    fn wait(&mut self, command: &mut Command) -> Result<Output> {
        check_output(self.wait_output(command)?)
    }

    fn wait_output(&mut self, command: &mut Command) -> Result<Output> {
        let mut child = Process::spawn(command)?;
        let start = Instant::now();
        loop {
            self.step()?;
            if child.ready()? {
                return child.output();
            }
            ensure!(
                start.elapsed() < Duration::from_secs(30),
                "USB helper timed out: {command:?}; ROM log: {}",
                self.model.output().peek()
            );
            std::thread::sleep(Duration::from_millis(1));
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

#[test]
#[ignore = "requires Linux vhci_hcd, USBIP and USB_RECOVERY_CLI paths, sudo and setfacl"]
fn usbip_linux_enumerates_and_probes_shared_rom() -> Result<()> {
    let tool = required_file("USBIP")?;
    let cli = required_file("USB_RECOVERY_CLI")?;
    bounded(Command::new(&tool).arg("version"))?;
    bounded(Command::new("sudo").args(["-n", "true"]))?;
    ensure!(
        Path::new("/sys/module/vhci_hcd").is_dir(),
        "load vhci_hcd before running this test"
    );
    bounded(Command::new("sudo").arg("-n").arg(&tool).arg("port"))?;

    let rom = super::test_rom("test-lpcip-usb-host")?;
    let mut model = ModelEmulated::new_unbooted(InitParams {
        mcu_rom: &rom,
        check_booted_to_runtime: false,
        ..Default::default()
    })?;
    model.boot()?;
    let server = UsbIpServer::bind(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        model.lpcip_usb_host_controller.clone(),
    )?;
    let mut fixture = Fixture { model, server };
    let started = Instant::now();
    while !fixture.model.lpcip_usb_host_controller.connected() {
        fixture.step()?;
        ensure!(
            started.elapsed() < Duration::from_secs(30),
            "ROM did not connect USB"
        );
    }
    let port = fixture.server.local_addr()?.port().to_string();
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
    let output = attachment.fixture.wait(Command::new(cli).args([
        "--vid",
        "0xffff",
        "--pid",
        "0xffff",
        "--bus",
        &bus.to_string(),
        "--address",
        &address.to_string(),
        "--overall-timeout-ms",
        "10000",
        "probe",
    ]))?;
    ensure!(
        std::str::from_utf8(&output.stdout)?
            .contains("OCP Recovery 1.1; CMS regions: 1; device status: StatusPending"),
        "unexpected CLI discovery response: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    ensure!(
        attachment
            .fixture
            .model
            .output()
            .peek()
            .contains("[usb-enumeration-test] configured"),
        "Linux configuration did not traverse shared ROM driver"
    );
    attachment.cleanup()?;
    ensure!(
        attachment.locate(false)?.is_none(),
        "test-owned VHCI attachment leaked"
    );
    if let Some(path) = state_file {
        std::fs::remove_file(path)?;
    }
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

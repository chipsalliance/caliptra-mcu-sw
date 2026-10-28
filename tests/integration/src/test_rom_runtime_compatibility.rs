// Licensed under the Apache-2.0 license

//! Selected-image tests for the six pairs in rom-runtime-compatibility-matrix-2.md.
//! The workflow builds images and prepares fixtures before running these ignored tests.

mod fixtures;
mod spdm;

use crate::test::{CustomCaliptraFw, TestParams};
use anyhow::{bail, ensure, Context, Result};
use caliptra_api::{calc_checksum, SocManager};
use caliptra_mcu_hw_model::{DefaultHwModel, Fuses, InitParams, McuHwModel, McuManager};
use caliptra_mcu_mbox_common::messages::{MailboxRespHeader, MailboxRespHeaderVarSize};
use caliptra_mcu_romtime::McuBootMilestones;
use caliptra_ureg::Mmio;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    mem::size_of,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};
use zerocopy::FromBytes;

const CORE: &str = "e5d1f27b15ba02e4e0a57b942bbde39b74cab2eb";
const ROMS: [(&str, &str); 2] = [
    ("rom-sdk-2.1.0", "da451221542758758f1c4ce35efbe48da9935dd8"),
    (
        "rom-sdk-2.1.0rc1",
        "12b6dc3f760767a17e931db3b4a4aa5dca47b95f",
    ),
];
const RUNTIMES: [&str; 3] = ["rt-sdk-2.1.0", "rt-sdk-2.1.1", "main-2.1"];
const PLDM_TID: u8 = 1;

fn runtime_source(label: &str) -> Result<String> {
    Ok(match label {
        "rt-sdk-2.1.0" => "24ea8b90bb56c0aed5512232dfbbca3dd2e39716".into(),
        "rt-sdk-2.1.1" => "8c9c8ff27de1babf63c0be74e973185837439040".into(),
        "main-2.1" => std::env::var("MCU_COMPAT_CURRENT_RUNTIME_SHA")?,
        _ => bail!("Unknown runtime {label}"),
    })
}

fn artifact_root() -> Result<PathBuf> {
    let path = std::env::var_os("MCU_COMPAT_ARTIFACT_DIR")
        .context("BLOCKED: MCU_COMPAT_ARTIFACT_DIR is required")?;
    Ok(fs::canonicalize(path)?)
}

fn require_agreement() -> Result<()> {
    ensure!(
        !std::env::var("MCU_COMPAT_AGREEMENT").unwrap_or_default().trim().is_empty(),
        "BLOCKED: owner agreement on the 2.1 Core, OTP/signing and release build configurations is required"
    );
    Ok(())
}

#[derive(Deserialize, Serialize)]
struct Artifact {
    path: PathBuf,
    sha256: String,
}

impl Artifact {
    fn read(&self, root: &Path) -> Result<Vec<u8>> {
        ensure!(
            !self.path.is_absolute()
                && !self
                    .path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir)),
            "Artifact must stay inside the downloaded inputs"
        );
        let bytes = fs::read(root.join(&self.path))
            .with_context(|| format!("Missing artifact {}", self.path.display()))?;
        ensure!(
            !bytes.is_empty() && hex::encode(Sha256::digest(&bytes)) == self.sha256,
            "Artifact hash mismatch: {}",
            self.path.display()
        );
        Ok(bytes)
    }
}

#[derive(Deserialize)]
struct Build {
    source: String,
    toolchain: String,
    version: Option<String>,
    images: BTreeMap<String, String>,
    #[serde(default)]
    command_ids: BTreeMap<String, u32>,
    mcu_error: Option<u32>,
    handoff_address: Option<u32>,
}

fn image(root: &Path, label: &str, mode: &str) -> Result<(Build, Vec<u8>)> {
    let directory = root.join("images").join(label);
    let build: Build = serde_json::from_slice(&fs::read(directory.join("metadata.json"))?)?;
    let source = if let Some((_, source)) = ROMS.iter().find(|(name, _)| *name == label) {
        source.to_string()
    } else {
        runtime_source(label)?
    };
    let toolchain = if label.starts_with("rom-") || label == "rt-sdk-2.1.0" {
        "1.85"
    } else {
        "1.96.1"
    };
    ensure!(
        build.source == source && build.toolchain == toolchain,
        "Image source/toolchain does not match {label}"
    );
    let file = if label.starts_with("rom-") {
        "image.bin".to_string()
    } else {
        format!("{mode}.bin")
    };
    let artifact = Artifact {
        path: PathBuf::from("images").join(label).join(&file),
        sha256: build
            .images
            .get(&file)
            .context("Missing selected image hash")?
            .clone(),
    };
    Ok((build, artifact.read(root)?))
}

#[derive(Deserialize)]
struct MemoryCheck {
    address: u32,
    execution_bit: u8,
    image: Artifact,
}

#[derive(Deserialize)]
struct NegativeCase {
    expected_mcu_error: u32,
    expected_core_error: u32,
    soc_manifest: Option<Artifact>,
    otp: Option<Artifact>,
    corrupt_offset: Option<usize>,
    runtime_flash: Option<Artifact>,
}

#[derive(Deserialize)]
struct PairConfig {
    rom: String,
    runtime: String,
    mode: String,
    caliptra_rom: Artifact,
    caliptra_firmware: Artifact,
    soc_manifest: Artifact,
    otp: Artifact,
    vendor_pk_hash: String,
    primary_flash: Artifact,
    runtime_flash: Artifact,
    pldm_package: Artifact,
    expected_capabilities: String,
    handoff_address: u32,
    soc_images: Vec<MemoryCheck>,
    negative_cases: BTreeMap<String, NegativeCase>,
}

struct SelectedPair {
    config: PairConfig,
    root: PathBuf,
    rom: Vec<u8>,
    runtime: Vec<u8>,
    version: String,
    commands: BTreeMap<String, u32>,
}

impl SelectedPair {
    fn load() -> Result<Self> {
        require_agreement()?;
        let root = artifact_root()?;
        let rom = std::env::var("MCU_COMPAT_ROM")?;
        let runtime = std::env::var("MCU_COMPAT_RUNTIME")?;
        let mode = std::env::var("MCU_COMPAT_MODE")?;
        ensure!(
            matches!(mode.as_str(), "flash" | "streaming"),
            "Unknown runtime configuration"
        );
        let (_, rom_bytes) = image(&root, &rom, &mode)?;
        let (build, runtime_bytes) = image(&root, &runtime, &mode)?;
        let config_path = PathBuf::from("pairs")
            .join(&rom)
            .join(&runtime)
            .join(&mode)
            .join("config.json");
        let manifest: BTreeMap<String, String> =
            serde_json::from_slice(&fs::read(root.join("fixture-hashes.json"))?)?;
        let config_artifact = Artifact {
            sha256: manifest
                .get(config_path.to_str().context("Non-UTF-8 config path")?)
                .context("Missing configuration hash")?
                .clone(),
            path: config_path,
        };
        let config: PairConfig = serde_json::from_slice(&config_artifact.read(&root)?)?;
        ensure!(
            config.rom == rom && config.runtime == runtime && config.mode == mode,
            "Configuration does not describe the selected pair"
        );
        let core: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("fixtures/core.json"))?)?;
        ensure!(
            core["source"] == CORE && core["hardware"] == "2.1.0",
            "Fixtures are not the agreed 2.1 Core"
        );
        Ok(Self {
            config,
            root,
            rom: rom_bytes,
            runtime: runtime_bytes,
            version: build.version.context("Missing selected runtime version")?,
            commands: build.command_ids,
        })
    }

    fn command(&self, name: &str) -> Result<u32> {
        self.commands
            .get(name)
            .copied()
            .with_context(|| format!("BLOCKED: selected release lacks {name}"))
    }

    fn streaming(&self) -> bool {
        self.config.mode == "streaming"
    }

    fn boot(
        &self,
        flash: bool,
        negative: Option<(&str, &NegativeCase)>,
        preserved: Option<(Vec<u8>, Vec<u8>)>,
        transport: bool,
    ) -> Result<DefaultHwModel> {
        let core_rom = self.config.caliptra_rom.read(&self.root)?;
        let mut core_fw = CustomCaliptraFw {
            fw_bytes: self.config.caliptra_firmware.read(&self.root)?,
            vendor_pk_hash: hex::decode(&self.config.vendor_pk_hash)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Expected a 48-byte vendor hash"))?,
            soc_manifest: self.config.soc_manifest.read(&self.root)?,
        };
        let mut runtime = self.runtime.clone();
        let mut otp = self.config.otp.read(&self.root)?;
        let mut runtime_flash = &self.config.runtime_flash;
        if let Some((name, case)) = negative {
            if let Some(value) = &case.soc_manifest {
                core_fw.soc_manifest = value.read(&self.root)?;
            }
            if let Some(value) = &case.otp {
                otp = value.read(&self.root)?;
            }
            if let Some(value) = &case.runtime_flash {
                runtime_flash = value;
            }
            if let Some(offset) = case.corrupt_offset {
                let bytes = match name {
                    "corrupted_runtime" => &mut runtime,
                    "corrupted_manifest" => &mut core_fw.soc_manifest,
                    _ => bail!("SVN cases must not corrupt images"),
                };
                *bytes
                    .get_mut(offset)
                    .context("Corruption offset outside selected image")? ^= 1;
            }
        }
        let (otp, primary_flash) = if let Some(value) = preserved {
            value
        } else {
            (
                otp,
                if flash {
                    self.config.primary_flash.read(&self.root)?
                } else {
                    runtime_flash.read(&self.root)?
                },
            )
        };
        let params = TestParams {
            custom_mcu_rom: Some(self.rom.clone()),
            custom_mcu_runtime: Some(runtime),
            custom_caliptra_fw: Some(core_fw),
            otp_memory: Some(otp),
            flash_boot: flash,
            primary_flash_image: Some(primary_flash),
            i3c_port: if transport {
                Some(
                    random_port::PortPicker::new()
                        .random(true)
                        .pick()
                        .context("No free I3C port")?,
                )
            } else {
                None
            },
            rom_only: true,
            ..Default::default()
        };
        // Instantiate only the supplied images; the shared helper may compile fallback firmware.
        let rom = params.custom_mcu_rom.context("Missing selected ROM")?;
        let runtime = params
            .custom_mcu_runtime
            .context("Missing selected runtime")?;
        let core = params.custom_caliptra_fw.context("Missing Core fixtures")?;
        let vendor_hash = std::array::from_fn(|index| {
            u32::from_be_bytes(
                core.vendor_pk_hash[index * 4..index * 4 + 4]
                    .try_into()
                    .unwrap(),
            )
        });
        Ok(caliptra_mcu_hw_model::new(InitParams {
            hw_revision: Some("2.1.0".parse()?),
            capture_mcu_exit: true,
            fuses: Fuses {
                vendor_pk_hash: vendor_hash,
                fuse_pqc_key_type: 1,
                ..Default::default()
            },
            caliptra_rom: &core_rom,
            mcu_rom: &rom,
            caliptra_firmware: if flash { &[] } else { &core.fw_bytes },
            soc_manifest: if flash { &[] } else { &core.soc_manifest },
            mcu_firmware: if flash { &[] } else { &runtime },
            vendor_pk_hash: Some(core.vendor_pk_hash),
            vendor_pqc_type: Some(caliptra_image_types::FwVerificationPqcKeyType::LMS),
            active_mode: true,
            i3c_port: params.i3c_port,
            enable_mcu_uart_log: true,
            check_booted_to_runtime: false,
            otp_memory: params.otp_memory.as_deref(),
            primary_flash_initial_contents: params.primary_flash_image,
            flash_boot: flash,
            ..Default::default()
        })?)
    }
}

fn check_version_response(response: &[u8], expected_version: &str) -> Result<()> {
    let (header, version) = MailboxRespHeaderVarSize::ref_from_prefix(response)
        .map_err(|e| anyhow::anyhow!("Invalid firmware-version response: {e}"))?;
    ensure!(
        response.len() == size_of::<MailboxRespHeaderVarSize>() + header.data_len as usize,
        "Firmware-version response length mismatch"
    );
    ensure!(
        header.hdr.chksum == calc_checksum(0, &response[size_of::<u32>()..]),
        "Firmware-version response checksum mismatch"
    );
    ensure!(
        header.hdr.fips_status == MailboxRespHeader::FIPS_STATUS_APPROVED,
        "Firmware-version command returned status {}",
        header.hdr.fips_status
    );
    ensure!(
        version == expected_version.as_bytes(),
        "Expected runtime version {expected_version}, got {version:?}"
    );
    Ok(())
}

fn check_no_fatal(hw: &mut impl McuHwModel) -> Result<()> {
    if let Some(status) = hw.mcu_exit_status() {
        ensure!(
            status == 0,
            "MCU firmware requested exit {status}; Core nonfatal error={:#x}",
            hw.caliptra_soc_manager()
                .soc_ifc()
                .cptra_fw_error_non_fatal()
                .read()
        );
    }
    ensure!(
        hw.mci_fw_fatal_error().is_none(),
        "Fatal MCU error: {:?}",
        hw.mci_fw_fatal_error()
    );
    let fatal = hw
        .caliptra_soc_manager()
        .soc_ifc()
        .cptra_fw_error_fatal()
        .read();
    ensure!(fatal == 0, "Fatal Core error: {fatal:#x}");
    Ok(())
}

fn verify_svn_boundary(manifest: &[u8], otp: &[u8], runtime: &[u8]) -> Result<u32> {
    use caliptra_auth_man_types::AuthorizationManifest;
    use sha2::Sha384;
    ensure!(otp.len() == 0xe88, "Wrong SVN OTP size");
    let signed = AuthorizationManifest::ref_from_bytes(manifest)
        .map_err(|error| anyhow::anyhow!("Invalid boundary manifest: {error}"))?;
    let floor: u32 = otp[0x3cc..0x3dc].iter().map(|byte| byte.count_ones()).sum();
    let ceiling = u32::from_le_bytes(otp[0x3dc..0x3e0].try_into()?);
    ensure!(
        floor > 0 && signed.preamble.svn == floor && floor <= ceiling,
        "Not an exact signed SVN boundary"
    );
    let entries = signed
        .image_metadata_col
        .image_metadata_list
        .get(..usize::try_from(signed.image_metadata_col.entry_count)?)
        .context("Invalid manifest entry count")?;
    let mut mcu = entries.iter().filter(|entry| entry.fw_id == 2);
    let entry = mcu.next().context("Missing boundary MCU entry")?;
    ensure!(
        mcu.next().is_none() && entry.digest[..] == Sha384::digest(runtime)[..],
        "Boundary does not bind the unchanged selected runtime"
    );
    println!("Verified signed SVN {floor} equals OTP minimum; OTP maximum={ceiling}");
    Ok(floor)
}

fn streaming_package(pair: &SelectedPair) -> Result<caliptra_mcu_pldm_fw_pkg::FirmwareManifest> {
    pair.config.pldm_package.read(&pair.root)?;
    let path = pair.root.join(&pair.config.pldm_package.path);
    let path = path.to_str().context("Non-UTF-8 PLDM path")?.to_owned();
    let package = caliptra_mcu_pldm_fw_pkg::FirmwareManifest::decode_firmware_package(&path, None)?;
    ensure!(
        package.component_image_information.len() == 1
            && package.component_image_information[0].identifier == 0xffff,
        "Wrong selected PLDM component"
    );
    Ok(package)
}

struct DiscoveryObserver(Arc<AtomicBool>);

impl caliptra_mcu_pldm_ua::discovery_sm::StateMachineActions for DiscoveryObserver {
    fn on_set_tid_response(
        &self,
        ctx: &mut caliptra_mcu_pldm_ua::discovery_sm::InnerContext<
            impl caliptra_mcu_pldm_ua::transport::PldmSocket + Send + 'static,
        >,
        response: caliptra_mcu_pldm_common::message::control::SetTidResponse,
    ) -> std::result::Result<(), ()> {
        if response.hdr.instance_id() != ctx.instance_id || response.completion_code != 0 {
            eprintln!("Invalid PLDM SetTID response: {response:?}");
            return Err(());
        }
        caliptra_mcu_pldm_ua::discovery_sm::DefaultActions {}.on_set_tid_response(ctx, response)
    }

    fn on_get_tid_response(
        &self,
        ctx: &mut caliptra_mcu_pldm_ua::discovery_sm::InnerContext<
            impl caliptra_mcu_pldm_ua::transport::PldmSocket + Send + 'static,
        >,
        response: caliptra_mcu_pldm_common::message::control::GetTidResponse,
    ) -> std::result::Result<(), ()> {
        if response.hdr.instance_id() != ctx.instance_id
            || response.completion_code != 0
            || response.tid != PLDM_TID
        {
            eprintln!("Invalid PLDM GetTID response: {response:?}");
            return Err(());
        }
        caliptra_mcu_pldm_ua::discovery_sm::DefaultActions {}.on_get_tid_response(ctx, response)
    }

    fn on_pldm_commands_response_type5(
        &self,
        ctx: &mut caliptra_mcu_pldm_ua::discovery_sm::InnerContext<
            impl caliptra_mcu_pldm_ua::transport::PldmSocket + Send + 'static,
        >,
        response: caliptra_mcu_pldm_common::message::control::GetPldmCommandsResponse,
    ) -> std::result::Result<(), ()> {
        use caliptra_mcu_pldm_ua::discovery_sm::DefaultActions;
        DefaultActions {}.on_pldm_commands_response_type5(ctx, response)?;
        self.0.store(true, Ordering::Release);
        Ok(())
    }
}

struct UpdateObserver(Arc<AtomicU8>);

impl caliptra_mcu_pldm_ua::update_sm::StateMachineActions for UpdateObserver {
    fn on_verify_complete_request(
        &mut self,
        ctx: &mut caliptra_mcu_pldm_ua::update_sm::InnerContext<
            impl caliptra_mcu_pldm_ua::transport::PldmSocket + Send + 'static,
        >,
        request: caliptra_mcu_pldm_common::message::firmware_update::verify_complete::VerifyCompleteRequest,
    ) -> std::result::Result<(), ()> {
        let result = request.verify_result;
        caliptra_mcu_pldm_ua::update_sm::DefaultActions {}
            .on_verify_complete_request(ctx, request)?;
        self.0.store(result, Ordering::Release);
        Ok(())
    }
}

struct TransportSession {
    daemon: caliptra_mcu_pldm_ua::daemon::PldmDaemon<
        caliptra_mcu_testing_common::mctp_transport::MctpPldmSocket,
        DiscoveryObserver,
        UpdateObserver,
    >,
    socket: caliptra_mcu_testing_common::mctp_transport::MctpPldmSocket,
    discovered: Arc<AtomicBool>,
    verification_error: Arc<AtomicU8>,
}

impl TransportSession {
    fn finish(&mut self, hw: &mut impl McuHwModel, pair: &SelectedPair) -> Result<()> {
        use caliptra_mcu_pldm_ua::{transport::PldmSocket, update_sm::States};
        let start = Instant::now();
        let cycles = hw.cycle_count();
        while !matches!(self.daemon.get_update_sm_state(), States::Done) {
            check_no_fatal(hw)?;
            let verification_error = self.verification_error.load(Ordering::Acquire);
            ensure!(
                verification_error == 0,
                "PLDM verification failed: result={verification_error:#x}, Core nonfatal error={:#x}",
                hw.caliptra_soc_manager().soc_ifc().cptra_fw_error_non_fatal().read()
            );
            ensure!(
                hw.mcu_exit_status().is_none(),
                "MCU exited before PLDM completion"
            );
            ensure!(
                hw.cycle_count() - cycles < 200_000_000
                    && start.elapsed() < Duration::from_secs(180),
                "PLDM transport timed out: discovered={}, state={:?}",
                self.discovered.load(Ordering::Acquire),
                self.daemon.get_update_sm_state()
            );
            hw.step();
        }
        ensure!(
            self.discovered.load(Ordering::Acquire),
            "PLDM discovery did not complete"
        );
        let device = self
            .daemon
            .get_device_id()
            .context("PLDM device identification did not complete")?;
        ensure!(
            device.initial_descriptor.descriptor_data == (1..=16).collect::<Vec<u8>>(),
            "Discovered wrong PLDM device"
        );
        check_soc_images(hw, pair)?;
        self.daemon.stop();
        self.socket.disconnect();
        check_no_fatal(hw)?;
        println!("MCTP/PLDM discovery, update completion, SoC payloads and activation verified");
        Ok(())
    }
}

fn check_mctp_discovery(port: u16, address: u8) -> Result<()> {
    use caliptra_mcu_testing_common::{
        i3c_socket::BufferedStream,
        mctp_util::{
            common::MctpUtil,
            ctrl_protocol::{MCTPCtrlCmd, MCTPCtrlMsgHdr},
        },
    };
    let mut stream = BufferedStream::new(std::net::TcpStream::connect(("127.0.0.1", port))?);
    let mut protocol = MctpUtil::new();
    protocol.set_boot_delay_ticks(0);
    for cmd in [
        MCTPCtrlCmd::GetEID,
        MCTPCtrlCmd::GetEndpointUUID,
        MCTPCtrlCmd::GetMsgTypeSupport,
    ] {
        let command = cmd as u8;
        let mut header = MCTPCtrlMsgHdr::new();
        header.set_rq(1);
        header.set_instance_id(command);
        header.set_cmd(command);
        let mut request = vec![0];
        request.extend_from_slice(&header.0);
        let response = protocol
            .wait_for_responder(0, &request, &mut stream, address)
            .context("No MCTP discovery response")?;
        check_mctp_response(command, header.0[0], &response)?;
        println!(
            "MCTP discovery command {command}: {}",
            hex::encode(response)
        );
    }
    Ok(())
}

fn check_mctp_response(command: u8, request_header: u8, response: &[u8]) -> Result<()> {
    use caliptra_mcu_testing_common::mctp_util::base_protocol::MctpMsgType;
    ensure!(
        response.len() >= 4 && response[..4] == [0, request_header & 0x7f, command, 0],
        "Invalid MCTP discovery response: {}",
        hex::encode(response)
    );
    match command {
        2 => ensure!(
            response.len() == 7 && response[4] != 255,
            "Invalid MCTP endpoint ID response"
        ),
        3 => ensure!(response.len() == 20, "Invalid MCTP UUID response"),
        5 => ensure!(
            response.len() >= 5
                && response.len() == 5 + usize::from(response[4])
                && [
                    MctpMsgType::Ctrl,
                    MctpMsgType::Pldm,
                    MctpMsgType::Spdm,
                    MctpMsgType::Caliptra
                ]
                .iter()
                .all(|kind| response[5..].contains(&(*kind as u8))),
            "Missing configured MCTP message types"
        ),
        _ => bail!("Unexpected MCTP discovery command {command}"),
    }
    Ok(())
}

fn start_transport(hw: &mut impl McuHwModel, pair: &SelectedPair) -> Result<TransportSession> {
    use caliptra_mcu_pldm_ua::{
        daemon::{Options, PldmDaemon},
        transport::{EndpointId, PldmSocket, PldmTransport},
    };
    use caliptra_mcu_testing_common::{mctp_transport::MctpTransport, spawn_with_emulator_state};
    let manifest = streaming_package(pair)?;
    let port = hw.i3c_port().context("Missing selected-image I3C port")?;
    let address = hw.i3c_address().context("Missing dynamic I3C address")?;
    hw.start_i3c_controller();
    let discovered = Arc::new(AtomicBool::new(false));
    let observer = discovered.clone();
    let verification_error = Arc::new(AtomicU8::new(0));
    let update_observer = verification_error.clone();
    let (tx, rx) = mpsc::channel();
    spawn_with_emulator_state(move || {
        let result = (|| -> Result<TransportSession> {
            check_mctp_discovery(port, address)?;
            let socket = MctpTransport::new(port, address.into())
                .create_socket(EndpointId(8), EndpointId(0))
                .map_err(|error| anyhow::anyhow!("I3C PLDM socket failed: {error:?}"))?;
            let daemon = PldmDaemon::run(
                socket.clone(),
                Options {
                    caliptra_mcu_pldm_fw_pkg: Some(manifest),
                    discovery_sm_actions: DiscoveryObserver(observer),
                    update_sm_actions: UpdateObserver(update_observer),
                    fd_tid: PLDM_TID,
                    rerun_count: 0,
                },
            )
            .map_err(|()| anyhow::anyhow!("Cannot start selected-image PLDM daemon"))?;
            Ok(TransportSession {
                daemon,
                socket,
                discovered,
                verification_error,
            })
        })();
        if tx.send(result).is_err() {
            eprintln!("Selected-image transport receiver exited");
        }
    });
    let start = Instant::now();
    let cycles = hw.cycle_count();
    loop {
        match rx.try_recv() {
            Ok(result) => return result,
            Err(mpsc::TryRecvError::Disconnected) => {
                bail!("Selected-image transport worker terminated")
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        check_no_fatal(hw)?;
        ensure!(
            hw.mcu_exit_status().is_none(),
            "MCU exited during MCTP discovery"
        );
        ensure!(
            hw.cycle_count() - cycles < 100_000_000 && start.elapsed() < Duration::from_secs(120),
            "MCTP discovery timed out"
        );
        hw.step();
    }
}

fn wait_ready(hw: &mut impl McuHwModel) -> Result<()> {
    let start = Instant::now();
    let initial_cycles = hw.cycle_count();
    loop {
        check_no_fatal(hw)?;
        let milestones = hw.mci_boot_milestones();
        if milestones.contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
            && milestones.contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
        {
            return Ok(());
        }
        ensure!(
            hw.mcu_exit_status().is_none(),
            "MCU exited before service readiness"
        );
        ensure!(
            hw.cycle_count() - initial_cycles < 100_000_000
                && start.elapsed() < Duration::from_secs(180),
            "Boot/mailbox readiness timed out; milestones={:#x}",
            milestones.bits()
        );
        hw.step();
    }
}

fn mailbox(hw: &mut impl McuHwModel, command: u32, payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        hw.mcu_exit_status().is_none(),
        "MCU exited before mailbox command {command:#x}"
    );
    let mut request = calc_checksum(command, payload).to_le_bytes().to_vec();
    request.extend_from_slice(payload);
    hw.start_mailbox_execute(command, &request)?;
    let start = Instant::now();
    let cycles = hw.cycle_count();
    while hw.cmd_status().cmd_busy() {
        check_no_fatal(hw)?;
        ensure!(
            hw.mcu_exit_status().is_none(),
            "MCU exited during mailbox command {command:#x}"
        );
        ensure!(
            hw.cycle_count() - cycles < 40_000_000 && start.elapsed() < Duration::from_secs(60),
            "Mailbox command timed out"
        );
        hw.step();
    }
    hw.finish_mailbox_execute()?
        .context("Mailbox command returned no response")
}

fn check_version(hw: &mut impl McuHwModel, pair: &SelectedPair) -> Result<()> {
    check_version_response(
        &mailbox(
            hw,
            pair.command("MC_FIRMWARE_VERSION")?,
            &1u32.to_le_bytes(),
        )?,
        &pair.version,
    )?;
    check_no_fatal(hw)
}

fn read_memory<M: McuManager>(manager: &mut M, address: u32, length: usize) -> Result<Vec<u8>> {
    read_memory_mmio(&manager.mmio_mut(), M::MBOX_1_ADDR, address, length)
}

fn read_memory_mmio(
    mmio: &impl Mmio,
    mailbox1_base: u32,
    address: u32,
    length: usize,
) -> Result<Vec<u8>> {
    const SOC_MAILBOX1_BASE: u32 = 0xa880_0000;
    let map = &caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP;
    let end = u64::from(address)
        .checked_add(u64::try_from(length)?)
        .context("Memory check address overflow")?;
    let regions = [
        (map.sram_offset, map.sram_size),
        (map.dccm_offset, map.dccm_size),
        (
            SOC_MAILBOX1_BASE,
            caliptra_mcu_emulator_consts::MCU_MAILBOX1_SRAM_SIZE,
        ),
    ];
    ensure!(
        length > 0
            && regions
                .iter()
                .any(|&(base, size)| u64::from(address) >= base as u64
                    && end <= (base + size) as u64),
        "Memory check is outside emulator RAM"
    );
    let address = if address >= SOC_MAILBOX1_BASE {
        mailbox1_base
            .checked_add(address - SOC_MAILBOX1_BASE)
            .context("Mailbox SRAM address overflow")?
    } else {
        address
    };
    let byte_offset = address as usize % size_of::<u32>();
    let aligned_address = address as usize - byte_offset;
    Ok((0..(length + byte_offset).div_ceil(size_of::<u32>()))
        .flat_map(|index| {
            // Mailbox SRAM is a word-only CSR aperture, unlike ordinary MCU RAM.
            unsafe {
                mmio.read_volatile((aligned_address + index * size_of::<u32>()) as *const u32)
            }
            .to_le_bytes()
        })
        .skip(byte_offset)
        .take(length)
        .collect())
}

fn check_soc_images(hw: &mut impl McuHwModel, pair: &SelectedPair) -> Result<()> {
    ensure!(
        !pair.config.soc_images.is_empty(),
        "BLOCKED: no expected SoC images supplied"
    );
    let start = Instant::now();
    let initial_cycles = hw.cycle_count();
    let images = pair
        .config
        .soc_images
        .iter()
        .map(|check| Ok((check.address, check.image.read(&pair.root)?)))
        .collect::<Result<Vec<_>>>()?;
    loop {
        check_no_fatal(hw)?;
        let mut complete = true;
        for (address, expected) in &images {
            complete &= read_memory(&mut hw.mcu_manager(), *address, expected.len())? == *expected;
        }
        if complete {
            let mut required = [0u32; 4];
            for image in &pair.config.soc_images {
                ensure!(image.execution_bit < 128, "Invalid SoC execution bit");
                required[usize::from(image.execution_bit / 32)] |= 1 << (image.execution_bit % 32);
            }
            if required.iter().enumerate().all(|(index, bits)| {
                hw.caliptra_soc_manager()
                    .soc_ifc()
                    .ss_generic_fw_exec_ctrl()
                    .at(index)
                    .read()
                    & bits
                    == *bits
            }) {
                return Ok(());
            }
        }
        ensure!(
            hw.mcu_exit_status().is_none(),
            "MCU exited before SoC loading and activation completed"
        );
        ensure!(
            hw.cycle_count() - initial_cycles < 100_000_000
                && start.elapsed() < Duration::from_secs(180),
            "SoC loading/activation timed out; payloads_match={complete}"
        );
        hw.step();
    }
}

fn check_capabilities(response: &[u8], expected: &[u8]) -> Result<()> {
    let (header, payload) = MailboxRespHeader::ref_from_prefix(response)
        .map_err(|error| anyhow::anyhow!("Invalid capabilities response: {error}"))?;
    ensure!(
        matches!(expected.len(), 36 | 64),
        "Expected capabilities must use the selected release's 36- or 64-byte layout"
    );
    ensure!(
        response.len() == size_of::<MailboxRespHeader>() + expected.len(),
        "Capabilities length mismatch"
    );
    ensure!(
        header.fips_status == MailboxRespHeader::FIPS_STATUS_APPROVED,
        "Capabilities status mismatch"
    );
    ensure!(
        header.chksum == calc_checksum(0, &response[4..]),
        "Capabilities checksum mismatch"
    );
    ensure!(
        payload == expected,
        "Capabilities differ from selected release metadata"
    );
    Ok(())
}

fn rejection_complete(mcu_error: u32, core_error: u32, expected: &NegativeCase) -> Result<bool> {
    ensure!(
        expected.expected_mcu_error != 0 || expected.expected_core_error != 0,
        "Rejection requires an exact nonzero error"
    );
    ensure!(
        (mcu_error == 0 || mcu_error == expected.expected_mcu_error)
            && (core_error == 0 || core_error == expected.expected_core_error),
        "Wrong rejection: MCU={mcu_error:#x}, Core={core_error:#x}"
    );
    Ok(mcu_error == expected.expected_mcu_error && core_error == expected.expected_core_error)
}

fn boot_check(pair: &SelectedPair, scenario: &str) -> Result<Option<String>> {
    if scenario == "warm_reset" {
        bail!("BLOCKED: a validated FPGA warm-reset lane or emulator implementation is required");
    }
    if matches!(scenario, "streaming_boot" | "discovery") && !pair.streaming() {
        return Ok(Some(
            "Covered by the separate streaming configuration".into(),
        ));
    }
    if matches!(scenario, "flash_cold_boot" | "cold_reboot") && pair.streaming() {
        return Ok(Some(
            "Covered by the separate flash-only configuration".into(),
        ));
    }
    let negative = pair.config.negative_cases.get(scenario);
    let reject = matches!(
        scenario,
        "corrupted_runtime" | "corrupted_manifest" | "svn_rollback"
    );
    if reject {
        ensure!(
            negative.is_some(),
            "BLOCKED: missing rejection expectations"
        );
    }
    if scenario == "svn_boundary" {
        let case = negative.context("Missing signed SVN boundary")?;
        verify_svn_boundary(
            &case
                .soc_manifest
                .as_ref()
                .context("Missing boundary manifest")?
                .read(&pair.root)?,
            &case
                .otp
                .as_ref()
                .context("Missing boundary OTP")?
                .read(&pair.root)?,
            &pair.runtime,
        )?;
    }
    let flash = matches!(scenario, "flash_cold_boot" | "cold_reboot");
    let mut hw = pair.boot(
        flash,
        negative.map(|value| (scenario, value)),
        None,
        pair.streaming() && !reject,
    )?;
    if reject {
        let expected = negative.context("Missing rejection")?;
        let started = Instant::now();
        let cycles = hw.cycle_count();
        loop {
            ensure!(
                hw.mcu_exit_status().is_none(),
                "MCU exited without the expected rejection"
            );
            let mcu = hw.mci_fw_fatal_error().unwrap_or(0);
            let core = hw
                .caliptra_soc_manager()
                .soc_ifc()
                .cptra_fw_error_fatal()
                .read();
            if rejection_complete(mcu, core, expected)? {
                return Ok(None);
            }
            ensure!(
                !hw.mci_boot_milestones()
                    .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY),
                "Invalid firmware reached runtime readiness"
            );
            ensure!(
                hw.cycle_count() - cycles < 100_000_000
                    && started.elapsed() < Duration::from_secs(180),
                "Timed out without expected rejection: MCU={mcu:#x}, Core={core:#x}"
            );
            hw.step();
        }
    }
    wait_ready(&mut hw)?;
    check_version(&mut hw, pair)?;
    match scenario {
        "runtime_commands" => check_capabilities(
            &mailbox(&mut hw, pair.command("MC_DEVICE_CAPABILITIES")?, &[])?,
            &hex::decode(&pair.config.expected_capabilities)?,
        )?,
        "handoff" => {
            let bytes = read_memory(&mut hw.mcu_manager(), pair.config.handoff_address, 8)?;
            ensure!(
                &bytes[..4] == b"MCUH" && bytes[4..8] == [1, 0, 0, 0],
                "Released ROM handoff is not version 1.0"
            );
            // Both selected ROMs predate boot-source/capability fields. Successful
            // mailbox commands prove the real runtime accepts this older layout.
        }
        "flash_cold_boot" | "cold_reboot" => {
            // Never provide PLDM payloads here: flash must work without streaming fallback.
            check_soc_images(&mut hw, pair)?;
            if scenario == "cold_reboot" {
                let otp = hw.read_otp_memory();
                drop(hw);
                let flash = fs::read("primary_flash").context("Cannot preserve primary flash")?;
                hw = pair.boot(true, None, Some((otp.clone(), flash)), false)?;
                ensure!(
                    hw.read_otp_memory() == otp,
                    "OTP changed across cold reboot"
                );
                wait_ready(&mut hw)?;
                check_version(&mut hw, pair)?;
                check_soc_images(&mut hw, pair)?;
            }
        }
        "streaming_boot" | "discovery" => start_transport(&mut hw, pair)?.finish(&mut hw, pair)?,
        _ => {}
    }
    check_no_fatal(&mut hw)?;
    Ok(None)
}

fn provisioning(pair: &SelectedPair, hw: &mut DefaultHwModel) -> Result<()> {
    let challenge = pair.command("MC_GET_AUTH_CMD_CHALLENGE")?;
    let (command, payload) = if pair.commands.contains_key("MC_AUTHORIZED_COMMAND") {
        (
            pair.command("MC_AUTHORIZED_COMMAND")?,
            challenge.to_le_bytes().to_vec(),
        )
    } else {
        (challenge, vec![0; 8])
    };
    let mut previous = None;
    for _ in 0..2 {
        let response = mailbox(hw, command, &payload)?;
        ensure!(
            response.len() == 60,
            "Authorization challenge response length"
        );
        let (header, bytes) = MailboxRespHeader::ref_from_prefix(&response)
            .map_err(|error| anyhow::anyhow!("Invalid challenge: {error}"))?;
        ensure!(
            header.fips_status == MailboxRespHeader::FIPS_STATUS_APPROVED
                && header.chksum == calc_checksum(0, &response[4..])
                && bytes[..4] == [0; 4]
                && bytes[4..].iter().any(|byte| *byte != 0),
            "Invalid authorization challenge status/checksum/nonce"
        );
        ensure!(
            previous.as_deref() != Some(&bytes[4..]),
            "Authorization nonce was reused"
        );
        previous = Some(bytes[4..].to_vec());
    }
    // Non-mutating checks only: authenticated fuse writes require another lifecycle fixture.
    for name in ["MC_FE_STATUS", "MC_VENDOR_PK_HASH_STATUS"] {
        if let Some(&command) = pair.commands.get(name) {
            let response = mailbox(hw, command, &[])?;
            let (header, bytes) = MailboxRespHeader::ref_from_prefix(&response)
                .map_err(|error| anyhow::anyhow!("Invalid provisioning status: {error}"))?;
            ensure!(
                header.fips_status == MailboxRespHeader::FIPS_STATUS_APPROVED
                    && header.chksum == calc_checksum(0, &response[4..]),
                "Invalid provisioning status"
            );
            if name == "MC_FE_STATUS" {
                ensure!(bytes == [0; 4], "Unexpected field-entropy provisioning");
            } else {
                ensure!(
                    bytes.len() == 20
                        && bytes[..4] == 1u32.to_le_bytes()
                        && bytes[4] == 1
                        && bytes[5..].iter().all(|byte| *byte == 0),
                    "Unexpected vendor key slots/types"
                );
            }
        } else {
            println!("NOT APPLICABLE: selected source has no {name}");
        }
    }
    Ok(())
}

fn suite_check(pair: &SelectedPair, scenario: &str) -> Result<Option<String>> {
    match scenario {
        "suite_spdm_mctp" if pair.streaming() =>
            bail!("BLOCKED: full MCTP SPDM conformance requires same-model PLDM loading, verified SoC measurement completion and a live responder after loading; separate boot tests do not establish these prerequisites"),
        "suite_attestation_ocp_eat_non_tcb" | "suite_attestation_ocp_eat_tcb" |
        "suite_attestation_ocp_eat_mixed" if pair.streaming() =>
            bail!("BLOCKED: production EAT fixtures need verified embedded component policy, initial measurement completion and matching appraisal inputs"),
        "suite_attestation_ocp_eat_non_tcb" | "suite_attestation_ocp_eat_tcb" |
        "suite_attestation_ocp_eat_mixed" | "suite_spdm_mctp" if !pair.streaming() =>
            return Ok(Some("The flash configuration does not enable SPDM".into())),
        "suite_attestation_pcr_quote" =>
            return Ok(Some("The selected production configuration uses OCP EAT, not the test-only PCR provider".into())),
        "suite_spdm_doe" | "suite_spdm_rs" =>
            return Ok(Some("The selected service configuration enables MCTP, not DOE/TDISP/IDE".into())),
        "suite_ownership_dot" | "suite_owner_stable_key" =>
            return Ok(Some("The selected ROM/OTP do not enable DOT or stable-owner-key".into())),
        "suite_network_boot" => return Ok(Some("No network ROM/configuration is selected".into())),
        "suite_usb_recovery" => return Ok(Some("USB recovery is outside the selected 2.1 I3C configuration".into())),
        "suite_ownership_handoff" => return boot_check(pair, "handoff"),
        "suite_mailbox" => return boot_check(pair, "runtime_commands"),
        _ => {}
    }
    let mut hw = pair.boot(false, None, None, pair.streaming())?;
    wait_ready(&mut hw)?;
    check_version(&mut hw, pair)?;
    match scenario {
        "suite_spdm_mctp" => {
            hw.start_i3c_controller();
            spdm::run_compatibility_conformance(&mut hw)?;
        }
        "suite_provisioning" => provisioning(pair, &mut hw)?,
        _ => bail!("BLOCKED: no selected-image implementation for {scenario}"),
    }
    check_no_fatal(&mut hw)?;
    Ok(None)
}

fn run_case(scenario: &str) -> Result<()> {
    let result = SelectedPair::load().and_then(|pair| {
        if scenario.starts_with("suite_") {
            suite_check(&pair, scenario)
        } else {
            boot_check(&pair, scenario)
        }
    });
    let (status, reason) = match &result {
        Ok(None) => ("PASS", String::new()),
        Ok(Some(reason)) => ("NOT APPLICABLE", reason.clone()),
        Err(error) => {
            let reason = format!("{error:#}");
            (
                if reason.contains("BLOCKED:") {
                    "BLOCKED"
                } else {
                    "FAIL"
                },
                reason,
            )
        }
    };
    let directory =
        PathBuf::from(std::env::var_os("MCU_COMPAT_RESULTS").context("Missing result directory")?);
    fs::create_dir_all(&directory)?;
    fs::write(
        directory.join(format!("{scenario}.json")),
        serde_json::to_vec_pretty(
            &serde_json::json!({"scenario": scenario, "result": status, "reason": reason}),
        )?,
    )?;
    println!("{status}: {scenario}: {reason}");
    result.map(|_| ())
}

macro_rules! compatibility_test {
    ($name:ident, $scenario:literal) => {
        #[test]
        #[ignore = "requires released images and agreed fixtures; run the compatibility workflow"]
        fn $name() -> Result<()> {
            run_case($scenario)
        }
    };
}

compatibility_test!(test_recovery_cold_boot, "recovery_cold_boot");
compatibility_test!(test_flash_cold_boot, "flash_cold_boot");
compatibility_test!(test_streaming_boot, "streaming_boot");
compatibility_test!(test_handoff, "handoff");
compatibility_test!(test_runtime_commands, "runtime_commands");
compatibility_test!(test_discovery, "discovery");
compatibility_test!(test_cold_reboot, "cold_reboot");
compatibility_test!(test_corrupted_runtime, "corrupted_runtime");
compatibility_test!(test_corrupted_manifest, "corrupted_manifest");
compatibility_test!(test_svn_rollback, "svn_rollback");
compatibility_test!(test_svn_boundary, "svn_boundary");
compatibility_test!(test_warm_reset, "warm_reset");
compatibility_test!(
    test_suite_attestation_ocp_eat_non_tcb,
    "suite_attestation_ocp_eat_non_tcb"
);
compatibility_test!(
    test_suite_attestation_ocp_eat_tcb,
    "suite_attestation_ocp_eat_tcb"
);
compatibility_test!(
    test_suite_attestation_ocp_eat_mixed,
    "suite_attestation_ocp_eat_mixed"
);
compatibility_test!(
    test_suite_attestation_pcr_quote,
    "suite_attestation_pcr_quote"
);
compatibility_test!(test_suite_spdm_mctp, "suite_spdm_mctp");
compatibility_test!(test_suite_spdm_doe, "suite_spdm_doe");
compatibility_test!(test_suite_spdm_rs, "suite_spdm_rs");
compatibility_test!(test_suite_mailbox, "suite_mailbox");
compatibility_test!(test_suite_provisioning, "suite_provisioning");
compatibility_test!(test_suite_ownership_dot, "suite_ownership_dot");
compatibility_test!(test_suite_owner_stable_key, "suite_owner_stable_key");
compatibility_test!(test_suite_ownership_handoff, "suite_ownership_handoff");
compatibility_test!(test_suite_network_boot, "suite_network_boot");
compatibility_test!(test_suite_usb_recovery, "suite_usb_recovery");

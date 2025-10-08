// Licensed under the Apache-2.0 license

#![allow(unused_imports)]

use anyhow::{anyhow, Result};
use caliptra_hw_model::BootParams;
use caliptra_image_gen::to_hw_format;
use caliptra_image_types::FwVerificationPqcKeyType;
use chrono::{TimeZone, Utc};
use crossterm::event::{self, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use log::{error, LevelFilter};
use mcu_builder::{FirmwareBinaries, PROJECT_ROOT};
use mcu_hw_model::{InitParams, McuHwModel, ModelEmulated, ModelFpgaRealtime};
use mcu_rom_common::LifecycleControllerState;
use mcu_testing_common::i3c_socket::BufferedStream;
use mcu_testing_common::mctp_transport::{MctpPldmSocket, MctpTransport};
use ml_kem::{kem, MlKem1024Params};
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    EncodedSizeUser, KemCore,
};
use nix::sched::CpuSet;
use nix::unistd::Pid;
use pldm_common::protocol::firmware_update::ComponentClassification;
use pldm_fw_pkg::manifest::{
    ComponentImageInformation, Descriptor, DescriptorType, FirmwareDeviceIdRecord,
    PackageHeaderInformation, StringType,
};
use pldm_fw_pkg::FirmwareManifest;
use pldm_ua::daemon::{Options, PldmDaemon};
use pldm_ua::transport::EndpointId;
use pldm_ua::transport::PldmSocket;
use pldm_ua::transport::PldmTransport;
use pldm_ua::{discovery_sm, update_sm};
use rand::thread_rng;
use ratatui::backend::CrosstermBackend;
use ratatui::buffer::Buffer;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::palette::tailwind;
use ratatui::style::Color;
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Gauge, Padding, Paragraph, Widget};
use ratatui::Frame;
use ratatui::Terminal;
use simplelog::{Config, WriteLogger};
use std::cell::{RefCell, RefMut};
use std::collections::VecDeque;
use std::io::{Read, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use uuid::Uuid;

const GAUGE1_COLOR: Color = tailwind::RED.c800;
const CUSTOM_LABEL_COLOR: Color = tailwind::SLATE.c200;

const TERMINAL_LINES: usize = 30;

const FPGA: bool = true;
type Model = ModelFpgaRealtime;
// type Model = ModelEmulated;

const DECODE_PY: &str = include_str!("decode.py");
const SIGNATURE_ANALYSIS_PY: &str = include_str!("signature_analysis.py");
const SIGNATURE_VALIDATION_PY: &str = include_str!("signature_validation.py");

const PLDM_DEMO_ZIP: &'static str = "pldm-demo-fpga.zip";
const SPDM_DEMO_ZIP: &'static str = "spdm-demo-fpga-2.1.zip";
const MLKEM_DEMO_ZIP: &'static str = "mlkem-demo-fpga.zip";
const OCPLOCK_DEMO_ZIP: &'static str = "ocplock-demo-fpga.zip";

const PAUSE_START_DEMO: Duration = Duration::from_secs(5);
const PAUSE_BETWEEN_DEMOS: Duration = Duration::from_secs(10);

const SPDM_BOOT_CYCLES: u64 = 700_000_000;

const I3C_PORTS: [u16; 5] = [65530, 65531, 65532, 65533, 65534];

pub const DEVICE_UUID: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
];

#[derive(Clone, Copy, Debug)]
enum DemoType {
    Pldm,
    Spdm,
    Mlkem,
    OcpLock,
}

impl DemoType {
    fn zip(self) -> &'static str {
        match self {
            DemoType::Pldm => PLDM_DEMO_ZIP,
            DemoType::Spdm => SPDM_DEMO_ZIP,
            DemoType::Mlkem => MLKEM_DEMO_ZIP,
            DemoType::OcpLock => OCPLOCK_DEMO_ZIP,
        }
    }

    fn max_cycles(self) -> u64 {
        match self {
            DemoType::Pldm => {
                if FPGA {
                    100_000_000_000
                } else {
                    100_000_000_000
                }
            }
            DemoType::Spdm => {
                if FPGA {
                    1_800_000_000
                } else {
                    200_000_000
                }
            }
            DemoType::Mlkem => {
                if FPGA {
                    100_000_000
                } else {
                    100_000_000
                }
            }
            DemoType::OcpLock => {
                if FPGA {
                    100_000_000
                } else {
                    100_000_000
                }
            }
        }
    }

    fn title(self) -> &'static str {
        match self {
            DemoType::Pldm => "Caliptra FPGA Demos: PLDM",
            DemoType::Spdm => "Caliptra FPGA Demos: SPDM",
            DemoType::Mlkem => "Caliptra FPGA Demos: MLKEM",
            DemoType::OcpLock => "Caliptra FPGA Demos: OCP LOCK",
        }
    }

    fn needs_i3c(self) -> bool {
        match self {
            DemoType::Pldm => true,
            DemoType::Spdm => true,
            DemoType::Mlkem => false,
            DemoType::OcpLock => false,
        }
    }
}

impl std::fmt::Display for DemoType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DemoType::Pldm => write!(f, "PLDM"),
            DemoType::Spdm => write!(f, "SPDM"),
            DemoType::Mlkem => write!(f, "MLKEM"),
            DemoType::OcpLock => write!(f, "OCP LOCK"),
        }
    }
}

pub(crate) fn demo() -> Result<()> {
    if FPGA {
        if !std::path::Path::new("/dev/uio0").exists() {
            crate::fpga::fpga_install_kernel_modules(None)?;
        }
    }

    std::fs::write("/tmp/decode.py", DECODE_PY)?;
    std::fs::write("/tmp/signature_analysis.py", SIGNATURE_ANALYSIS_PY)?;
    std::fs::write("/tmp/signature_validation.py", SIGNATURE_VALIDATION_PY)?;

    // Define the PLDM Firmware Package that the Update Agent will use
    let pldm_fw_pkg = FirmwareManifest {
        package_header_information: PackageHeaderInformation {
            package_header_identifier: Uuid::parse_str("7B291C996DB64208801B02026E463C78").unwrap(),
            package_header_format_revision: 1,
            package_release_date_time: Utc.with_ymd_and_hms(2025, 3, 1, 0, 0, 0).unwrap(),
            package_version_string_type: StringType::Utf8,
            package_version_string: Some("1.2.0-release".to_string()),
            package_header_size: 0, // This will be computed during encoding
        },

        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            firmware_device_package_data: None,
            device_update_option_flags: 0x0,
            component_image_set_version_string_type: StringType::Utf8,
            component_image_set_version_string: Some("1.2.0".to_string()),
            applicable_components: Some(vec![0]),
            // The descriptor should match the device's ID record found in runtime/apps/pldm/pldm-lib/src/config.rs
            initial_descriptor: Descriptor {
                descriptor_type: DescriptorType::Uuid,
                descriptor_data: DEVICE_UUID.to_vec(),
            },
            additional_descriptors: None,
            reference_manifest_data: None,
        }],
        downstream_device_id_records: None,
        component_image_information: vec![ComponentImageInformation {
            // Classification and identifier should match the device's component image information found in runtime/apps/pldm/pldm-lib/src/config.rs
            classification: ComponentClassification::Firmware as u16,
            identifier: 0x0001,

            // Comparison stamp should be greater than the device's comparison stamp
            comparison_stamp: Some(0x12345679),
            options: 0x0,
            requested_activation_method: 0x0002,
            version_string_type: StringType::Utf8,
            version_string: Some("soc-fw-1.2".to_string()),

            // Define the firmware image binary data of size 256 bytes
            // First 128 bytes are 0x55, next 128 bytes are 0xAA
            size: 256,
            image_data: {
                let mut data = vec![0x55u8; 128];
                data.extend(vec![0xAAu8; 128]);
                Some(data)
            },
            ..Default::default()
        }],
    };

    // Pin to CPU 0 for stability.
    let mut cpu_set = CpuSet::new();
    cpu_set.set(0)?;
    nix::sched::sched_setaffinity(Pid::this(), &cpu_set)?;

    // setup terminal
    let stdout = std::io::stdout();
    enable_raw_mode()?;

    let app_result = {
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        //terminal.clear()?;
        crossterm::execute!(std::io::stdout(), crossterm::terminal::EnterAlternateScreen)?;

        // create app and run it
        let tick_rate = Duration::from_micros(1_000_000 / 60);
        let mut app = Demo::new(pldm_fw_pkg);
        let app_result = app.run(&mut terminal, tick_rate);
        if app_result.is_err() {
            std::thread::sleep(Duration::from_millis(10000));
            println!("Error: {:?}", app_result);
        }

        // restore terminal
        //crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen)?;
        //terminal.clear()?;
        terminal.show_cursor()?;
        app_result
    };
    disable_raw_mode()?;

    if let Err(err) = app_result {
        println!("{err:?}");
    }

    Ok(())
}

struct Console {
    buffer: Arc<RwLock<VecDeque<String>>>,
    last_line_terminated: bool,
}

impl Console {
    fn clear(&mut self) {
        self.buffer.write().unwrap().clear();
        self.last_line_terminated = true;
    }
}

impl std::io::Write for Console {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut buffer = self.buffer.write().unwrap();
        for line in String::from_utf8_lossy(buf).lines() {
            if buffer.is_empty() || self.last_line_terminated {
                buffer.push_back(line.to_string());
            } else {
                buffer.push_back(line.to_string());
            }
            self.last_line_terminated = false;
        }
        let last = *buf.last().unwrap();
        self.last_line_terminated = last == 10 || last == 13;
        while buffer.len() > TERMINAL_LINES {
            buffer.pop_front();
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpdmDemoState {
    SentGetVersion,
    SentGetCapabilities,
    SentNegotiateAlgorithms,
    SentGetDigests,
    SentGetMeasurements,
    Done,
}

const GET_VERSION: [u8; 4] = [0x10, 0x84, 0x00, 0x00];
const GET_CAPABILITIES: [u8; 20] = [
    0x13, 0xE1, 0x00, 0x00, 0x00, // header
    0,    // ct exponent
    0, 0, // ext flags
    0xC6, 0x73, 0, 0, // flags
    0, 0x12, 0, 0, // data transfer size
    0, 0x12, 0, 0, // max SPDM msg size,
];
const GET_DIGESTS: [u8; 4] = [0x13, 0x81, 00, 00];
// const NEGOTIATE_ALGORITHMS: [u8; _] = [0x13, 0xe3,
// 1, // number of structs
// 0,
// 16, 0, // length of entire request message
// 0, // measurement spec bit mask
// 0, // other params bit mask
// 0x80, 0, 0, 0, // P-384
// 0x01, 0, 0, 0, // SHA-384
// 0, 0, 0, 0, // PQC
// 0, 0, 0, 0, 0, 0, 0, 0, // reserved
// 0, // ext asym count
// 0, // ext hash count
// 0, // reserved
// 0, // measurement extension log bit mask
// 4, // ReqBaseAsymAlg
// 0x
// ]
const NEGOTIATE_ALGORITMS: [u8; 48] = [
    0x13, 0xE3, 0x04, 0x00, 0x30, 0x00, 0x01, 0x02, 0xFF, 0x0F, 0x00, 0x00, 0x7F, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x20, 0x7F, 0x00, 0x03, 0x20, 0x0F, 0x00, 0x04, 0x20, 0xFF, 0x0F, 0x05, 0x20, 0x01, 0x00,
];
const GET_MEASUREMENTS_HEADER: [u8; 4] = [0x13, 0xe0, 1, 0xff];
const GET_MEASUREMENTS_FOOTER: [u8; 9] = [0u8; 9];

const MCTP_HEADER: [u8; 5] = [
    1,    // version 1
    0,    // destination eid
    8,    // source eid
    0xc8, // som + eom + sequence + tag owner
    5,    // message type = SPDM
];

struct Demo {
    console_buffer: Arc<RwLock<VecDeque<String>>>,
    host_console: RefCell<Console>,
    progress: u16,
    should_quit: bool,
    model: Option<RefCell<Model>>,
    model_started: bool,
    next_demo: bool,
    i3c_socket: Option<BufferedStream>,
    demos: Vec<DemoType>,
    current_demo_idx: usize,
    i3c_port_idx: usize,
    wait_for_next_demo_until: Option<Instant>,
    pause: bool,
    ticks: u64,
    spdm_demo_state: Option<SpdmDemoState>,
    expect_packets: usize,
    got_packets: usize,
    buffered_packets: Vec<Vec<u8>>,
    encaps_key: Vec<u8>,
    write_msg_fifo: VecDeque<u8>,
    ocplock_key_printed: bool,
    socket: Option<MctpPldmSocket>,
    daemon:
        Option<PldmDaemon<MctpPldmSocket, discovery_sm::DefaultActions, update_sm::DefaultActions>>,
    pldm_fw_pkg: FirmwareManifest,
}

impl Demo {
    fn new(pldm_fw_pkg: FirmwareManifest) -> Self {
        Self {
            console_buffer: Arc::new(RwLock::new(VecDeque::new())),
            host_console: RefCell::new(Console {
                buffer: Arc::new(RwLock::new(VecDeque::new())),
                last_line_terminated: true,
            }),
            should_quit: false,
            progress: 0,
            model: None,
            model_started: false,
            next_demo: false,
            i3c_socket: None,
            demos: vec![
                DemoType::Pldm,
                DemoType::OcpLock,
                DemoType::Mlkem,
                DemoType::Spdm,
            ],
            current_demo_idx: 0,
            i3c_port_idx: 0,
            wait_for_next_demo_until: None,
            pause: false,
            ticks: 0,
            spdm_demo_state: None,
            expect_packets: 0,
            got_packets: 0,
            buffered_packets: vec![],
            encaps_key: vec![],
            write_msg_fifo: VecDeque::new(),
            ocplock_key_printed: false,
            pldm_fw_pkg,
            daemon: None,
            socket: None,
        }
    }

    fn host_console(&self) -> RefMut<'_, Console> {
        self.host_console.borrow_mut()
    }

    fn run(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
        tick_rate: Duration,
    ) -> Result<()> {
        let mut last_tick = Instant::now();
        {
            let current_demo = self.current_demo();
            writeln!(
                self.host_console(),
                "{}",
                format!("Starting demo: {}", current_demo)
            )?;
        }

        loop {
            terminal.draw(|frame| self.render(frame))?;

            let timeout = tick_rate.saturating_sub(last_tick.elapsed());
            if !event::poll(timeout)? {
                self.on_tick()?;
                last_tick = Instant::now();
                continue;
            }
            if let Some(key) = event::read()?.as_key_event() {
                match key.code {
                    KeyCode::Char(c) => self.on_key(c),
                    _ => {}
                }
            }
            if self.should_quit {
                return Ok(());
            }
        }
    }

    fn i3c_port(&self) -> u16 {
        I3C_PORTS[self.i3c_port_idx % I3C_PORTS.len()]
    }

    pub fn on_key(&mut self, c: char) {
        match c {
            'q' => {
                self.should_quit = true;
            }
            'n' => {
                self.next_demo = true;
                self.wait_for_next_demo_until = Some(Instant::now() + PAUSE_START_DEMO);
            }
            ' ' => {
                self.pause = !self.pause;
            }
            _ => {}
        }
    }

    fn current_demo(&self) -> DemoType {
        self.demos[self.current_demo_idx]
    }

    fn on_tick(&mut self) -> Result<()> {
        self.ticks += 1;
        if self.pause {
            return Ok(());
        }
        if let Some(wait_for_next_demo_until) = self.wait_for_next_demo_until {
            if Instant::now() < wait_for_next_demo_until {
                return Ok(());
            }
            self.wait_for_next_demo_until = None;
        }

        if self.next_demo {
            // TODO: drop current hw model
            // TODO: start next
            self.model_stop()?;
            self.spdm_demo_state = None;
            self.next_demo = false;
            self.model_started = false;
            self.encaps_key.clear();
            self.write_msg_fifo.clear();
            self.current_demo_idx = (self.current_demo_idx + 1) % self.demos.len();
            self.i3c_port_idx = (self.i3c_port_idx + 1) % I3C_PORTS.len();
            self.console_buffer.write().unwrap().clear();
            self.host_console().clear();
            let current_demo = self.current_demo();
            writeln!(
                self.host_console(),
                "{}",
                format!("Starting demo: {}", current_demo)
            )?;
        }

        if !self.model_started {
            self.model_started = true;
            self.model_start()?;
        }

        if self.model.is_none() {
            self.progress = 0;
            return Ok(());
        }

        let mut model = self.model.as_ref().unwrap().borrow_mut();

        // The FPGA keeps running in real-time, so we don't need to step a bunch of times just to run the model.
        let steps = if FPGA { 100 } else { 10_000 };

        if self.pause && !FPGA {
            return Ok(());
        }

        // we still step for FPGA so that the log FIFO doesn't overflow
        for _ in 0..steps {
            model.maybe_step()?;
        }

        if self.pause {
            return Ok(());
        }

        let mut output_sink = &model.output().sink().clone();
        //if matches!(self.current_demo(), DemoType::Mlkem) && model.cycle_count() < 500_000 {
        // if self.ticks % 2 == 0 {
        //     output_sink.write(b"\n")?;
        // }
        //}
        // if !model.output().peek().is_empty() {
        //     output_sink.write_all(model.output().take(usize::MAX).as_bytes())?;
        //     output_sink.flush()?;
        // }

        let s = caliptra_emu_periph::output().take();
        if !s.is_empty() {
            output_sink.write_all(s.as_bytes())?;
            output_sink.flush()?;
        }

        let s = mcu_hw_model::model_fpga_realtime::side_output().take();
        if !s.is_empty() {
            self.host_console().write_all(s.as_bytes())?;
        }

        let max_cycles = self.current_demo().max_cycles();
        self.progress = (((model.cycle_count() * 100) / max_cycles) as u16)
            .min(100)
            .max(0);
        if model.cycle_count() >= max_cycles {
            self.next_demo = true;
            self.wait_for_next_demo_until = Some(Instant::now() + PAUSE_BETWEEN_DEMOS);
        }

        drop(model);

        self.demo_tick()?;

        Ok(())
    }

    fn demo_tick(&mut self) -> Result<()> {
        match self.current_demo() {
            DemoType::Pldm => self.pldm_demo_tick()?,
            DemoType::Spdm => self.spdm_demo_tick()?,
            DemoType::Mlkem => self.mlkem_demo_tick()?,
            DemoType::OcpLock => self.ocplock_demo_tick()?,
        }
        Ok(())
    }

    fn pldm_demo_tick(&mut self) -> Result<()> {
        let mut model = self.model.as_ref().unwrap().borrow_mut();

        // Wait until we have an I3C address.
        let Some(addr) = model.i3c_address() else {
            return Ok(());
        };

        let flow_status = model.mci_flow_status();
        if flow_status & 0xffff < 386 {
            // don't even try if we have not booted to runtime
            return Ok(());
        }

        if model.cycle_count() > SPDM_BOOT_CYCLES && self.i3c_socket.is_none() {
            writeln!(
                model.output().logger(),
                "Connecting to I3C socket: {}",
                flow_status
            )?;
            let addr = SocketAddr::from(([127, 0, 0, 1], self.i3c_port()));
            let stream = TcpStream::connect(addr).unwrap();
            let stream = BufferedStream::new(stream);
            self.i3c_socket = Some(stream);
        }
        if model.cycle_count() < SPDM_BOOT_CYCLES + 1_000_000 {
            return Ok(());
        }
        let i3c_socket = self.i3c_socket.as_mut().unwrap();

        let pldm_transport = MctpTransport::new(self.i3c_port(), addr.into());
        let pldm_socket = pldm_transport
            .create_socket(EndpointId(8), EndpointId(0))
            .unwrap();
        // PldmFwUpdateTest::run(pldm_socket, debug_level);
        Ok(())
    }

    fn ocplock_demo_tick(&mut self) -> Result<()> {
        if self.ocplock_key_printed {
            return Ok(());
        }
        let mut model = self.model.as_ref().unwrap().borrow_mut();
        if model.ocp_lock_released_key().iter().all(|x| *x == 0) {
            return Ok(());
        }
        self.ocplock_key_printed = true;
        // ensure that the key has been full written
        std::thread::sleep(Duration::from_micros(1));
        let key = model.ocp_lock_released_key();
        writeln!(
            self.host_console.borrow_mut(),
            "{}",
            format!("OCP LOCK released MEK: {:02x?}...", &key[..16])
        )?;
        let mut expected = [0u8; 64];
        for i in 0..64 {
            expected[i] = i as u8;
        }
        let result = if key == expected { "✅" } else { "❌" };
        writeln!(
            self.host_console.borrow_mut(),
            "{}",
            format!("OCP LOCK result: {}", result)
        )?;
        Ok(())
    }

    fn mlkem_demo_tick(&mut self) -> Result<()> {
        let mut model = self.model.as_ref().unwrap().borrow_mut();
        while self.encaps_key.len() < 1568 {
            if let Some(b) = model.read_msg_fifo() {
                self.encaps_key.push(b);
            } else {
                break;
            }
        }
        if self.encaps_key.len() == 1568 {
            writeln!(
                self.host_console.borrow_mut(),
                "{}",
                format!("Received encaps key: {:02x?}...", &self.encaps_key[..16])
            )?;

            let encaps_key: [u8; 1568] = self.encaps_key.as_slice().try_into().unwrap();

            let encaps_key =
                EncapsulationKey::<MlKem1024Params>::from_bytes((&encaps_key).try_into().unwrap());

            writeln!(self.host_console.borrow_mut(), "Encapsulating")?;
            let mut rng = thread_rng();
            let (ciphertext, shared_key) = encaps_key.encapsulate(&mut rng).unwrap();
            writeln!(
                self.host_console.borrow_mut(),
                "{}",
                format!("Ciphertext: {:02x?}...", &ciphertext[..16])
            )?;
            writeln!(
                self.host_console.borrow_mut(),
                "{}",
                format!("Shared key: {:02x?}...", &shared_key[..16])
            )?;

            writeln!(self.host_console.borrow_mut(), "Sending to Caliptra")?;
            self.write_msg_fifo.extend(&ciphertext);
            self.encaps_key.push(0); // prevent re-entry
        }

        if !self.write_msg_fifo.is_empty() && model.msg_fifo_is_empty() {
            for _ in 0..(self.write_msg_fifo.len().min(512)) {
                model.write_msg_fifo(self.write_msg_fifo.pop_front().unwrap());
            }
        }
        Ok(())
    }

    fn spdm_demo_tick(&mut self) -> Result<()> {
        let mut model = self.model.as_ref().unwrap().borrow_mut();

        // Wait until we have an I3C address.
        let Some(addr) = model.i3c_address() else {
            return Ok(());
        };

        let flow_status = model.mci_flow_status();
        if flow_status & 0xffff < 386 {
            // don't even try if we have not booted to runtime
            return Ok(());
        }

        if model.cycle_count() > SPDM_BOOT_CYCLES && self.i3c_socket.is_none() {
            writeln!(
                model.output().logger(),
                "Connecting to I3C socket: {}",
                flow_status
            )?;
            let addr = SocketAddr::from(([127, 0, 0, 1], self.i3c_port()));
            let stream = TcpStream::connect(addr).unwrap();
            let stream = BufferedStream::new(stream);
            self.i3c_socket = Some(stream);
        }
        if model.cycle_count() < SPDM_BOOT_CYCLES + 1_000_000 {
            return Ok(());
        }
        let i3c_socket = self.i3c_socket.as_mut().unwrap();

        if self.spdm_demo_state.is_none() {
            // send a version
            let cycle = model.cycle_count();
            writeln!(
                self.host_console.borrow_mut(),
                "{}",
                format!("Requesting EAT at cycle {}", cycle)
            )?;
            let mut packet = vec![];
            packet.extend_from_slice(&MCTP_HEADER);
            packet.extend_from_slice(&GET_VERSION);
            i3c_socket.send_private_write(addr, packet);
            writeln!(
                model.output().logger(),
                "HOST: I3C send to MCU: GET_VERSION"
            )?;
            self.spdm_demo_state = Some(SpdmDemoState::SentGetVersion);
            self.expect_packets = 1;
            self.got_packets = 0;
            self.buffered_packets.clear();
            return Ok(());
        }

        // handle I3C for SPDM
        let Some(recv) = i3c_socket.receive_private_read(addr) else {
            return Ok(());
        };

        self.got_packets += 1;

        // writeln!(
        //     model.output().logger(),
        //     "HOST: I3C recv from Caliptra (got={}/{}) (len={}): {:02x?}",
        //     self.got_packets,
        //     self.expect_packets,
        //     recv.len(),
        //     recv
        // )?;

        self.buffered_packets.push(recv.clone());

        if self.got_packets < self.expect_packets {
            return Ok(());
        }

        self.expect_packets = 1;
        self.got_packets = 0;

        match self.spdm_demo_state.unwrap() {
            SpdmDemoState::SentGetVersion => {
                // got a version response, send capabilities
                let mut packet = vec![];
                packet.extend_from_slice(&MCTP_HEADER);
                packet.extend_from_slice(&GET_CAPABILITIES);
                i3c_socket.send_private_write(addr, packet);
                writeln!(
                    model.output().logger(),
                    "HOST: I3C send to MCU: GET_CAPABILITIES"
                )?;
                self.spdm_demo_state = Some(SpdmDemoState::SentGetCapabilities);
            }
            SpdmDemoState::SentGetCapabilities => {
                // got capabilities, send negotiate algorithms
                let mut packet = vec![];
                packet.extend_from_slice(&MCTP_HEADER);
                packet.extend_from_slice(&NEGOTIATE_ALGORITMS);
                i3c_socket.send_private_write(addr, packet);
                writeln!(
                    model.output().logger(),
                    "HOST: I3C send to MCU: NEGOTIATE_ALGORITHMS"
                )?;
                self.spdm_demo_state = Some(SpdmDemoState::SentNegotiateAlgorithms);
            }
            SpdmDemoState::SentNegotiateAlgorithms => {
                // got algorithms response, send get digests
                let mut packet = vec![];
                packet.extend_from_slice(&MCTP_HEADER);
                packet.extend_from_slice(&GET_DIGESTS);
                i3c_socket.send_private_write(addr, packet);
                writeln!(
                    model.output().logger(),
                    "HOST: I3C send to MCU: GET_DIGESTS"
                )?;
                self.spdm_demo_state = Some(SpdmDemoState::SentGetDigests);
            }
            SpdmDemoState::SentGetDigests => {
                // got a digests response, send get measurements
                let mut packet = vec![];
                packet.extend_from_slice(&MCTP_HEADER);
                packet.extend_from_slice(&GET_MEASUREMENTS_HEADER);
                let mut nonce = [0u8; 32];
                nonce[..8].copy_from_slice(&model.cycle_count().to_le_bytes());
                packet.extend_from_slice(&nonce);
                packet.extend_from_slice(&GET_MEASUREMENTS_FOOTER);
                i3c_socket.send_private_write(addr, packet);
                self.spdm_demo_state = Some(SpdmDemoState::SentGetMeasurements);
                writeln!(
                    model.output().logger(),
                    "HOST: I3C send to MCU: GET_MEASUREMENTS"
                )?;
                self.expect_packets = 32;
            }
            SpdmDemoState::SentGetMeasurements => {
                let mut measurements = vec![];
                self.buffered_packets.reverse();
                let initial = self.buffered_packets.pop().unwrap();
                // remove MCTP + SPDM header
                measurements.extend_from_slice(&initial[5 + 8..]);
                while let Some(pkt) = self.buffered_packets.pop() {
                    // remove MCTP header
                    measurements.extend_from_slice(&pkt[4..]);
                }
                writeln!(
                    model.output().logger(),
                    "Measurements packets: {:02x?}",
                    measurements
                )?;
                let measurement_len =
                    u16::from_le_bytes(initial[5 + 5..5 + 5 + 2].try_into().unwrap()) as usize;

                let record_len =
                    u16::from_le_bytes(measurements[2..4].try_into().unwrap()) as usize;
                writeln!(
                    model.output().logger(),
                    "Measurement length = {}, expected length = {}, record len = {}",
                    measurements.len(),
                    measurement_len,
                    record_len
                )?;

                std::fs::write("/tmp/measurements.bin", &measurements)?;

                let mut host_console = self.host_console.borrow_mut();

                let measurement_record = measurements[4..4 + record_len].to_vec();
                // remove DMTF header
                let eat_token = measurement_record[3..].to_vec();

                // validate the nonce
                let returned_nonce = measurements[4 + record_len..4 + record_len + 32].to_vec();
                writeln!(
                    host_console,
                    "{}",
                    format!("Nonce: {:02x?}", &returned_nonce),
                )?;

                std::fs::write("/tmp/eat_token.cbor", &eat_token)?;
                writeln!(
                    host_console,
                    "{}",
                    format!("Raw EAT token: {:02x?}...", &eat_token[..16])
                )?;

                // Decode the EAT token using Python
                let output = std::process::Command::new("venv/bin/python")
                    .arg("/tmp/decode.py")
                    .arg("/tmp/eat_token.cbor")
                    .output();

                match output {
                    Ok(output) => {
                        if output.status.success() {
                            let decoded = String::from_utf8_lossy(&output.stdout);
                            writeln!(host_console, "{}", format!("Decoded EAT: {}", decoded))?;
                        } else {
                            let error = String::from_utf8_lossy(&output.stderr);
                            writeln!(host_console, "Decode error: {}", error)?;
                        }
                    }
                    Err(e) => {
                        writeln!(host_console, "Failed to run decoder: {}", e)?;
                    }
                }

                self.spdm_demo_state = Some(SpdmDemoState::Done);
            }
            SpdmDemoState::Done => {
                writeln!(model.output().logger(), "SPDM demo complete!")?;
            }
        }
        self.buffered_packets.clear();
        Ok(())
    }

    fn model_start(&mut self) -> Result<()> {
        let zip = Some(PROJECT_ROOT.join(self.current_demo().zip()));
        let binaries = FirmwareBinaries::read_from_zip(zip.as_ref().unwrap()).map_err(|err| {
            anyhow!(
                "Could not find demo zip {:?}: {:?}",
                zip.as_ref().unwrap().display(),
                err
            )
        })?;
        let otp_memory = vec![];

        let mut console = Console {
            buffer: self.console_buffer.clone(),
            last_line_terminated: true,
        };
        writeln!(
            console,
            "{}",
            format!("Starting demo: {}", self.current_demo())
        )?;

        let init_params = InitParams {
            caliptra_rom: &binaries.caliptra_rom,
            caliptra_firmware: &binaries.caliptra_fw,
            mcu_rom: &binaries.mcu_rom,
            mcu_firmware: &binaries.mcu_runtime,
            soc_manifest: &binaries.soc_manifest,
            active_mode: true,
            lifecycle_controller_state: Some(LifecycleControllerState::Prod),
            otp_memory: Some(&otp_memory),
            vendor_pk_hash: binaries.vendor_pk_hash(),
            enable_mcu_uart_log: true,
            log_writer: Box::new(console),
            i3c_port: if self.current_demo().needs_i3c() {
                Some(self.i3c_port())
            } else {
                None
            },
            ..Default::default()
        };
        let mut model = Model::new_unbooted(init_params)?;
        model.boot(BootParams {
            fuses: caliptra_api_types::Fuses {
                vendor_pk_hash: binaries
                    .vendor_pk_hash()
                    .map(|h| to_hw_format(&h))
                    .unwrap_or([0u32; 12]),
                fuse_pqc_key_type: u8::from(FwVerificationPqcKeyType::LMS).into(),
                ..Default::default()
            },
            fw_image: Some(binaries.caliptra_fw.as_slice()),
            soc_manifest: Some(binaries.soc_manifest.as_slice()),
            mcu_fw_image: Some(binaries.mcu_runtime.as_slice()),
            ..Default::default()
        })?;
        model.start_i3c_controller();
        self.model = Some(RefCell::new(model));

        Ok(())
    }

    #[allow(clippy::result_unit_err)]
    pub fn pldm_wait_for_state_transition(
        &self,
        expected_state: update_sm::States,
    ) -> Result<(), ()> {
        let timeout = Duration::from_secs(500);
        let start_time = std::time::Instant::now();

        while start_time.elapsed() < timeout {
            if let Some(daemon) = &self.daemon {
                if daemon.get_update_sm_state() == expected_state {
                    return Ok(());
                }
            } else {
                error!("Daemon is not initialized");
                return Err(());
            }

            std::thread::sleep(Duration::from_millis(100));
        }
        if let Some(daemon) = &self.daemon {
            if daemon.get_update_sm_state() != expected_state {
                error!("Timed out waiting for state transition");
                Err(())
            } else {
                Ok(())
            }
        } else {
            error!("Daemon is not initialized");
            Err(())
        }
    }

    #[allow(clippy::result_unit_err)]
    pub fn test_fw_update(&mut self, debug_level: LevelFilter) -> Result<(), ()> {
        // Initialize log level to info (only once)
        WriteLogger::init(
            debug_level,
            Config::default(),
            // TODO: make the console itself synchronize the newline
            Console {
                buffer: self.console_buffer.clone(),
                last_line_terminated: true,
            },
        )
        .unwrap();

        let pldm_fw_pkg = self.pldm_fw_pkg.clone();

        // Run the PLDM daemon
        self.daemon = Some(
            PldmDaemon::run(
                self.socket.as_mut().unwrap().clone(),
                Options {
                    pldm_fw_pkg: Some(pldm_fw_pkg),
                    discovery_sm_actions: discovery_sm::DefaultActions {},
                    update_sm_actions: update_sm::DefaultActions {},
                    fd_tid: 0x01,
                },
            )
            .map_err(|_| ())?,
        );

        // Modify the expected state to the one that the test will reach.
        // Note that the UA state machine will not progress if it receives an unexpected response from the device.
        let res = self.pldm_wait_for_state_transition(update_sm::States::Done);

        self.daemon.as_mut().unwrap().stop();

        res
    }

    pub fn run_pldm_test(&mut self, socket: MctpPldmSocket, debug_level: LevelFilter) {
        // TODO: start this once
        print!("Emulator: Running PLDM Loopback Test: ",);

        self.socket = Some(socket);
        if self.test_fw_update(debug_level).is_err() {
            println!("Failed");
        } else {
            println!("Passed");
        }
    }

    fn render(&mut self, frame: &mut Frame) {
        frame.render_widget(self, frame.area());
    }

    fn render_gauge1(&self, area: Rect, buf: &mut Buffer) {
        let title = title_block("Demo Progress");
        Gauge::default()
            .block(title)
            .gauge_style(GAUGE1_COLOR)
            .percent(self.progress)
            .render(area, buf);
    }

    fn model_stop(&mut self) -> Result<()> {
        drop(self.model.take());
        caliptra_emu_periph::output().take();
        Ok(())
    }
}

impl Widget for &mut Demo {
    #[expect(clippy::similar_names)]
    fn render(self, area: Rect, buf: &mut Buffer) {
        use Constraint::Length;
        let layout = Layout::vertical([
            Length(2),
            Length(4),
            Length(TERMINAL_LINES as u16 + 4),
            Length(2),
        ]);
        let [header_area, gauge_area, consoles_area, footer_area] = layout.areas(area);

        let [console_area, host_console_area] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(consoles_area);

        render_header(self.current_demo().title(), header_area, buf);
        render_console(console_area, &*self.console_buffer.read().unwrap(), buf);
        render_host_console(
            host_console_area,
            &*(self.host_console().buffer.read().unwrap()),
            buf,
        );

        let footer = if self.pause {
            "Paused - Press Space to resume"
        } else if self.next_demo {
            "Starting next demo in a few seconds..."
        } else {
            "Press Space to pause, N for next demo, Q to quit"
        };

        render_footer(footer, footer_area, buf);

        self.render_gauge1(gauge_area, buf);
    }
}

fn render_host_console(area: Rect, lines: &VecDeque<String>, buf: &mut Buffer) {
    let console_border = Block::bordered().padding(Padding::uniform(1));
    let (a, b) = lines.as_slices();
    let mut text: Vec<String> = vec![];
    text.extend(a.iter().cloned());
    text.extend(b.iter().cloned());
    Paragraph::new(text.join("\n"))
        .block(console_border)
        .render(area, buf);
}

fn render_console(area: Rect, lines: &VecDeque<String>, buf: &mut Buffer) {
    let console_border = Block::bordered().padding(Padding::uniform(1));
    let (a, b) = lines.as_slices();
    let mut text: Vec<String> = vec![];
    text.extend(a.iter().cloned());
    text.extend(b.iter().cloned());
    Paragraph::new(text.join("\n"))
        .block(console_border)
        .render(area, buf);
}

fn title_block(title: &str) -> Block<'_> {
    let title = Line::from(title).centered();
    Block::new()
        .borders(Borders::NONE)
        .padding(Padding::vertical(1))
        .title(title)
        .fg(CUSTOM_LABEL_COLOR)
}

fn render_header(title: &str, area: Rect, buf: &mut Buffer) {
    Paragraph::new(title)
        .bold()
        .alignment(Alignment::Center)
        .fg(CUSTOM_LABEL_COLOR)
        .render(area, buf);
}

fn render_footer(text: &str, area: Rect, buf: &mut Buffer) {
    Paragraph::new(text)
        .alignment(Alignment::Center)
        .fg(CUSTOM_LABEL_COLOR)
        .bold()
        .render(area, buf);
}

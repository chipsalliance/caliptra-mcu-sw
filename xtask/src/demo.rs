// Licensed under the Apache-2.0 license

#![allow(unused_imports)]

use anyhow::{anyhow, Result};
use caliptra_hw_model::BootParams;
use caliptra_image_gen::to_hw_format;
use caliptra_image_types::FwVerificationPqcKeyType;
use crossterm::event::{self, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use mcu_builder::{FirmwareBinaries, PROJECT_ROOT};
use mcu_hw_model::{InitParams, McuHwModel, ModelEmulated, ModelFpgaRealtime};
use mcu_rom_common::LifecycleControllerState;
use mcu_testing_common::i3c_socket::BufferedStream;
use nix::sched::CpuSet;
use nix::unistd::Pid;
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
use std::cell::{RefCell, RefMut};
use std::collections::VecDeque;
use std::io::Write as _;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

const GAUGE1_COLOR: Color = tailwind::RED.c800;
const CUSTOM_LABEL_COLOR: Color = tailwind::SLATE.c200;

const TERMINAL_LINES: usize = 30;

const FPGA: bool = true;
type Model = ModelFpgaRealtime;
// type Model = ModelEmulated;

const SPDM_DEMO_ZIP: &'static str = "spdm-demo-fpga.zip";
const MLKEM_DEMO_ZIP: &'static str = "mlkem-demo-fpga.zip";
//const MLKEM_DEMO_ZIP: &'static str = "ocplock-demo-fpga.zip";
const OCPLOCK_DEMO_ZIP: &'static str = "ocplock-demo-fpga.zip";

const PAUSE_START_DEMO: Duration = Duration::from_secs(5);
const PAUSE_BETWEEN_DEMOS: Duration = Duration::from_secs(10);

const SPDM_BOOT_CYCLES: u64 = 400_000_000;

const I3C_PORTS: [u16; 5] = [65530, 65531, 65532, 65533, 65534];

#[derive(Clone, Copy, Debug)]
enum DemoType {
    Spdm,
    Mlkem,
    // OcpLock
}

impl DemoType {
    fn zip(self) -> &'static str {
        match self {
            DemoType::Spdm => OCPLOCK_DEMO_ZIP, // SPDM_DEMO_ZIP,
            DemoType::Mlkem => MLKEM_DEMO_ZIP,
        }
    }

    fn max_cycles(self) -> u64 {
        match self {
            DemoType::Spdm => {
                if FPGA {
                    500_000_000
                } else {
                    20_000_000
                }
            }
            DemoType::Mlkem => {
                if FPGA {
                    20_000_000
                } else {
                    1_000_000
                }
            }
        }
    }

    fn title(self) -> &'static str {
        match self {
            DemoType::Spdm => "Caliptra FPGA Demos: SPDM",
            DemoType::Mlkem => "Caliptra FPGA Demos: MLKEM",
        }
    }

    fn needs_i3c(self) -> bool {
        match self {
            DemoType::Spdm => true,
            DemoType::Mlkem => false,
        }
    }
}

impl std::fmt::Display for DemoType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DemoType::Spdm => write!(f, "SPDM"),
            DemoType::Mlkem => write!(f, "MLKEM"),
        }
    }
}

pub(crate) fn demo() -> Result<()> {
    if FPGA {
        if !std::path::Path::new("/dev/uio0").exists() {
            crate::fpga::fpga_install_kernel_modules(None)?;
        }
    }

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
        let mut app = Demo::new();
        let app_result = app.run(&mut terminal, tick_rate);

        // restore terminal
        crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen)?;
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

struct Demo {
    console_buffer: Arc<RwLock<VecDeque<String>>>,
    host_console: RefCell<Console>,
    progress: u16,
    should_quit: bool,
    model: Option<RefCell<Model>>,
    model_started: bool,
    next_demo: bool,
    i3c_socket: Option<BufferedStream>,
    sent_vca: bool,
    demos: Vec<DemoType>,
    current_demo_idx: usize,
    i3c_port_idx: usize,
    wait_for_next_demo_until: Option<Instant>,
    pause: bool,
    ticks: u64,
}

impl Demo {
    fn new() -> Self {
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
            sent_vca: false,
            demos: vec![DemoType::Spdm, DemoType::Mlkem],
            current_demo_idx: 0,
            i3c_port_idx: 0,
            wait_for_next_demo_until: None,
            pause: false,
            ticks: 0,
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
            writeln!(self.host_console(), "Starting demo: {}", current_demo)?;
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
            self.next_demo = false;
            self.model_started = false;
            self.current_demo_idx = (self.current_demo_idx + 1) % self.demos.len();
            self.i3c_port_idx = (self.i3c_port_idx + 1) % I3C_PORTS.len();
            self.console_buffer.write().unwrap().clear();
            self.host_console().clear();
            let current_demo = self.current_demo();
            writeln!(self.host_console(), "Starting demo: {}", current_demo)?;
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
            DemoType::Spdm => self.spdm_demo_tick()?,
            DemoType::Mlkem => {}
        }
        Ok(())
    }

    fn spdm_demo_tick(&mut self) -> Result<()> {
        let mut model = self.model.as_ref().unwrap().borrow_mut();

        // Wait until we have an I3C address.
        let Some(addr) = model.i3c_address() else {
            return Ok(());
        };

        if model.cycle_count() > SPDM_BOOT_CYCLES && self.i3c_socket.is_none() {
            writeln!(model.output().logger(), "Connecting to I3C socket")?;
            let addr = SocketAddr::from(([127, 0, 0, 1], self.i3c_port()));
            let stream = TcpStream::connect(addr).unwrap();
            let stream = BufferedStream::new(stream);
            self.i3c_socket = Some(stream);
        }

        // handle I3C for SPDM
        // TODO: move to state machine for SPDM test
        if let Some(i3c_socket) = self.i3c_socket.as_mut() {
            if model.cycle_count() >= SPDM_BOOT_CYCLES + 1_000_000 {
                if !self.sent_vca {
                    self.sent_vca = true;
                    writeln!(model.output().logger(), "HOST: I3C send to MCU: VCA")?;
                    i3c_socket.send_private_write(
                        addr,
                        vec![0x01, 0x00, 0x08, 0xc8, 0x05, 0x10, 0x84, 0x00, 0x00, 0xfe],
                    );
                }
                // I3C send to MCU: [01, 00, 08, c8, 05, 10, 84, 00, 00, fe]
                //
                //
                //                         [01, 08, 00, c0, 05, 10, 04, 00, 00, 00, 02, 00, 12, 00, 13]
                if let Some(recv) = i3c_socket.receive_private_read(addr) {
                    writeln!(
                        model.output().logger(),
                        "HOST: I3C recv from Caliptra: {:02x?}",
                        recv
                    )?;
                }
            }
        }
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
        writeln!(console, "Starting demo: {}", self.current_demo())?;

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
            Layout::horizontal([Constraint::Percentage(70), Constraint::Percentage(30)])
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

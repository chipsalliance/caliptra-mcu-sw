// Licensed under the Apache-2.0 license

use anyhow::{anyhow, Result};
use caliptra_hw_model::BootParams;
use caliptra_image_gen::to_hw_format;
use caliptra_image_types::FwVerificationPqcKeyType;
use crossterm::event::{self, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use mcu_builder::{FirmwareBinaries, PROJECT_ROOT};
use mcu_hw_model::{InitParams, McuHwModel, ModelEmulated, ModelFpgaRealtime};
use mcu_testing_common::i3c_socket::BufferedStream;
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
use std::collections::VecDeque;
use std::io::Write as _;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

const GAUGE1_COLOR: Color = tailwind::RED.c800;
const CUSTOM_LABEL_COLOR: Color = tailwind::SLATE.c200;

const FPGA: bool = false;
type Model = ModelEmulated; //ModelFpgaRealtime;

pub(crate) fn demo() -> Result<()> {
    if FPGA {
        if !std::path::Path::new("/dev/uio0").exists() {
            crate::fpga::fpga_install_kernel_modules(None)?;
        }
    }

    // setup terminal
    enable_raw_mode()?;
    let stdout = std::io::stdout();

    let app_result = {
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.clear()?;

        // create app and run it
        let tick_rate = Duration::from_micros(1_000_000 / 60);
        let mut app = Demo::new();
        let app_result = app.run(&mut terminal, tick_rate);
        // restore terminal
        disable_raw_mode()?;
        terminal.show_cursor()?;
        app_result
    };

    if let Err(err) = app_result {
        println!("{err:?}");
    }

    Ok(())
}

struct Console {
    buffer: Arc<RwLock<VecDeque<String>>>,
    last_line_terminated: bool,
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
        while buffer.len() > 50 {
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
    progress: u16,
    should_quit: bool,
    model: Option<Model>,
    spdm_started: bool,
    next_demo: bool,
    i3c_socket: Option<BufferedStream>,
    sent_vca: bool,
}

impl Demo {
    fn new() -> Self {
        Self {
            console_buffer: Arc::new(RwLock::new(VecDeque::new())),
            should_quit: false,
            progress: 0,
            model: None,
            spdm_started: false,
            next_demo: false,
            i3c_socket: None,
            sent_vca: false,
        }
    }

    fn run(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
        tick_rate: Duration,
    ) -> Result<()> {
        let mut last_tick = Instant::now();
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

    pub fn on_key(&mut self, c: char) {
        match c {
            'q' => {
                self.should_quit = true;
            }
            'n' => {
                self.next_demo = true;
            }
            _ => {}
        }
    }

    fn on_tick(&mut self) -> Result<()> {
        if !self.spdm_started {
            self.spdm_started = true;
            self.spdm_start()?;
        }
        if let Some(model) = self.model.as_mut() {
            let addr = model.i3c_address().unwrap();
            for _ in 0..1000 {
                model.step();
            }

            let mut output_sink = &model.output().sink().clone();
            if !model.output().peek().is_empty() {
                output_sink
                    .write_all(model.output().take(usize::MAX).as_bytes())
                    .unwrap();
            }
            const MAX_CYCLES: u64 = 20_000_000;
            // TODO: why is there no ouput from cycle 50,000 to 1,000,000 or so?
            self.progress = (((model.cycle_count() * 100) / MAX_CYCLES) as u16)
                .min(100)
                .max(0);
            if model.cycle_count() >= MAX_CYCLES {
                self.next_demo = true;
            }

            if model.cycle_count() > 1_000_000 && self.i3c_socket.is_none() {
                let addr = SocketAddr::from(([127, 0, 0, 1], 65534));
                let stream = TcpStream::connect(addr).unwrap();
                let stream = BufferedStream::new(stream);
                self.i3c_socket = Some(stream);
            }

            // handle I3C for SPDM
            // TODO: move to state machine for SPDM test
            if let Some(i3c_socket) = self.i3c_socket.as_mut() {
                if model.cycle_count() >= 10_000_000 {
                    if !self.sent_vca {
                        self.sent_vca = true;
                        i3c_socket.send_private_write(
                            addr,
                            vec![0x01, 0x00, 0x08, 0xc8, 0x05, 0x10, 0x84, 0x00, 0x00, 0xfe],
                        );
                    }
                    // I3C send to MCU: [01, 00, 08, c8, 05, 10, 84, 00, 00, fe]
                    // I3C recv from Caliptra: [01, 08, 00, c0, 05, 10, 04, 00, 00, 00, 02, 00, 12, 00, 13, 1e]
                    if let Some(recv) = i3c_socket.receive_private_read(addr) {
                        writeln!(
                            model.output().logger(),
                            "I3C recv from Caliptra: {:02x?}",
                            recv
                        )
                        .unwrap();
                    }
                }
            }
        } else {
            self.progress = 0;
        }
        Ok(())
    }

    fn spdm_start(&mut self) -> Result<()> {
        let zip = Some(PROJECT_ROOT.join("spdm-demo.zip"));
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
        writeln!(console, "Starting SPDM Demo...")?;

        let init_params = InitParams {
            //let mut model = ModelFpgaRealtime::new_unbooted(InitParams {
            caliptra_rom: &binaries.caliptra_rom,
            caliptra_firmware: &binaries.caliptra_fw,
            mcu_rom: &binaries.mcu_rom,
            mcu_firmware: &binaries.mcu_runtime,
            soc_manifest: &binaries.soc_manifest,
            active_mode: true,
            otp_memory: Some(&otp_memory),
            vendor_pk_hash: binaries.vendor_pk_hash(),
            enable_mcu_uart_log: true,
            log_writer: Box::new(console),
            i3c_port: Some(65534),
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
        let port = model.i3c_port().unwrap();
        self.model = Some(model);

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
}

impl Widget for &mut Demo {
    #[expect(clippy::similar_names)]
    fn render(self, area: Rect, buf: &mut Buffer) {
        use Constraint::Length;
        let layout = Layout::vertical([Length(2), Length(4), Length(30), Length(2)]);
        let [header_area, gauge_area, console_area, footer_area] = layout.areas(area);

        render_header(header_area, buf);
        render_console(console_area, &*self.console_buffer.read().unwrap(), buf);
        render_footer(footer_area, buf);

        self.render_gauge1(gauge_area, buf);
    }
}

fn render_console(area: Rect, lines: &VecDeque<String>, buf: &mut Buffer) {
    let (a, b) = lines.as_slices();
    let mut text: Vec<String> = vec![];
    text.extend(a.iter().cloned());
    text.extend(b.iter().cloned());
    Paragraph::new(text.join("\n")).render(area, buf);
}

fn title_block(title: &str) -> Block<'_> {
    let title = Line::from(title).centered();
    Block::new()
        .borders(Borders::NONE)
        .padding(Padding::vertical(1))
        .title(title)
        .fg(CUSTOM_LABEL_COLOR)
}

fn render_header(area: Rect, buf: &mut Buffer) {
    Paragraph::new("Caliptra FPGA Demos")
        .bold()
        .alignment(Alignment::Center)
        .fg(CUSTOM_LABEL_COLOR)
        .render(area, buf);
}

fn render_footer(area: Rect, buf: &mut Buffer) {
    Paragraph::new("Press N for next demo, Q to quit")
        .alignment(Alignment::Center)
        .fg(CUSTOM_LABEL_COLOR)
        .bold()
        .render(area, buf);
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    emulator.rs

Abstract:

    File contains the Emulator struct implementation.

--*/

use crate::dis;
use crate::doe_mbox_fsm;
use crate::elf;
use crate::i3c_socket;
use crate::i3c_socket::start_i3c_socket;
use crate::mctp_transport::MctpTransport;
use crate::tests;
use crate::{EMULATOR_RUNNING, EMULATOR_TICKS, MCU_RUNTIME_STARTED, TICK_COND};
use caliptra_emu_bus::{Bus, Clock, Timer};
use caliptra_emu_cpu::{Cpu, Pic, RvInstr, StepAction};
use caliptra_emu_cpu::{Cpu as CaliptraMainCpu, StepAction as CaliptraMainStepAction};
use caliptra_emu_periph::CaliptraRootBus as CaliptraMainRootBus;
use caliptra_image_types::FwVerificationPqcKeyType;
use clap::{ArgAction, Parser};
use clap_num::maybe_hex;
use crossterm::event::{Event, KeyCode, KeyEvent};
use emulator_bmc::Bmc;
use emulator_caliptra::{start_caliptra, StartCaliptraArgs};
use emulator_consts::{DEFAULT_CPU_ARGS, RAM_ORG, ROM_SIZE};
#[allow(unused_imports)]
use emulator_periph::MciMailboxRequester;
use emulator_periph::{
    CaliptraToExtBus, DoeMboxPeriph, DummyDoeMbox, DummyFlashCtrl, I3c, I3cController, LcCtrl, Mci,
    McuMailbox0Internal, McuRootBus, McuRootBusArgs, McuRootBusOffsets, Otp, OtpArgs,
};
use emulator_registers_generated::dma::DmaPeripheral;
use emulator_registers_generated::root_bus::{AutoRootBus, AutoRootBusOffsets};
use pldm_fw_pkg::FirmwareManifest;
use pldm_ua::daemon::PldmDaemon;
use pldm_ua::transport::{EndpointId, PldmTransport};
use std::cell::RefCell;
use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use tests::mctp_util::base_protocol::LOCAL_TEST_ENDPOINT_EID;
use tests::pldm_request_response_test::PldmRequestResponseTest;

// Type aliases for external shim callbacks
pub type ExternalReadCallback =
    Box<dyn Fn(caliptra_emu_types::RvSize, caliptra_emu_types::RvAddr, &mut u32) -> bool>;
pub type ExternalWriteCallback = Box<
    dyn Fn(
        caliptra_emu_types::RvSize,
        caliptra_emu_types::RvAddr,
        caliptra_emu_types::RvData,
    ) -> bool,
>;

fn parse_vendor_pqc_type(s: &str) -> Result<FwVerificationPqcKeyType, String> {
    match s.to_lowercase().trim() {
        "mldsa" => Ok(FwVerificationPqcKeyType::MLDSA),
        "lms" => Ok(FwVerificationPqcKeyType::LMS),
        _ => Err(format!(
            "Invalid vendor PQC type: {}. Supported types are 'mldsa' and 'lms'.",
            s
        )),
    }
}

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None, name = "Caliptra MCU Emulator")]
pub struct EmulatorArgs {
    /// ROM binary path
    #[arg(short, long)]
    pub rom: PathBuf,

    #[arg(short, long)]
    pub firmware: PathBuf,

    /// Optional file to store OTP / fuses between runs.
    #[arg(short, long)]
    pub otp: Option<PathBuf>,

    /// GDB Debugger Port
    #[arg(short, long)]
    pub gdb_port: Option<u16>,

    /// Directory in which to log execution artifacts.
    #[arg(short, long)]
    pub log_dir: Option<PathBuf>,

    /// Trace instructions.
    #[arg(short, long, default_value_t = false)]
    pub trace_instr: bool,

    // These look backwards, but this is necessary so that the default is to capture stdin.
    /// Pass stdin to the MCU UART Rx.
    #[arg(long = "no-stdin-uart", action = ArgAction::SetFalse)]
    pub stdin_uart: bool,

    // this is used only to set stdin_uart to false
    #[arg(long = "stdin-uart", overrides_with = "stdin_uart")]
    pub _no_stdin_uart: bool,

    /// The ROM path for the Caliptra CPU.
    #[arg(long)]
    pub caliptra_rom: PathBuf,

    /// The Firmware path for the Caliptra CPU.
    #[arg(long)]
    pub caliptra_firmware: PathBuf,

    #[arg(long)]
    pub soc_manifest: PathBuf,

    #[arg(long)]
    pub i3c_port: Option<u16>,

    /// This is only needed if the IDevID CSR needed to be generated in the Caliptra Core.
    #[arg(long)]
    pub manufacturing_mode: bool,

    #[arg(long)]
    pub vendor_pk_hash: Option<String>,

    #[arg(long)]
    pub owner_pk_hash: Option<String>,

    /// mldsa or lms (default)
    #[arg(long, value_parser = parse_vendor_pqc_type, default_value = "lms")]
    pub vendor_pqc_type: FwVerificationPqcKeyType,

    /// Path to the streaming boot PLDM firmware package
    #[arg(long)]
    pub streaming_boot: Option<PathBuf>,

    #[arg(long)]
    pub primary_flash_image: Option<PathBuf>,

    #[arg(long)]
    pub secondary_flash_image: Option<PathBuf>,

    /// HW revision in semver format (e.g., "2.0.0")
    #[arg(long, value_parser = semver::Version::parse, default_value = "2.0.0")]
    pub hw_revision: semver::Version,

    /// Override ROM offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub rom_offset: Option<u32>,
    /// Override ROM size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub rom_size: Option<u32>,
    /// Override UART offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub uart_offset: Option<u32>,
    /// Override UART size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub uart_size: Option<u32>,
    /// Override emulator control offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub ctrl_offset: Option<u32>,
    /// Override emulator control size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub ctrl_size: Option<u32>,
    /// Override SPI offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub spi_offset: Option<u32>,
    /// Override SPI size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub spi_size: Option<u32>,
    /// Override SRAM offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub sram_offset: Option<u32>,
    /// Override SRAM size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub sram_size: Option<u32>,
    /// Override PIC offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub pic_offset: Option<u32>,
    /// Override external test SRAM offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub external_test_sram_offset: Option<u32>,
    /// Override external test SRAM size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub external_test_sram_size: Option<u32>,
    /// Override DCCM offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub dccm_offset: Option<u32>,
    /// Override DCCM size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub dccm_size: Option<u32>,
    /// Override I3C offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub i3c_offset: Option<u32>,
    /// Override I3C size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub i3c_size: Option<u32>,
    /// Override primary flash offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub primary_flash_offset: Option<u32>,
    /// Override primary flash size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub primary_flash_size: Option<u32>,
    /// Override secondary flash offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub secondary_flash_offset: Option<u32>,
    /// Override secondary flash size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub secondary_flash_size: Option<u32>,
    /// Override MCI offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub mci_offset: Option<u32>,
    /// Override MCI size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub mci_size: Option<u32>,
    /// Override DMA offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub dma_offset: Option<u32>,
    /// Override DMA size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub dma_size: Option<u32>,
    /// Override Caliptra mailbox offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub mbox_offset: Option<u32>,
    /// Override Caliptra mailbox size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub mbox_size: Option<u32>,
    /// Override Caliptra SoC interface offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub soc_offset: Option<u32>,
    /// Override Caliptra SoC interface size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub soc_size: Option<u32>,
    /// Override OTP offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub otp_offset: Option<u32>,
    /// Override OTP size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub otp_size: Option<u32>,
    /// Override LC offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub lc_offset: Option<u32>,
    /// Override LC size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub lc_size: Option<u32>,
    /// SoC Manifest SVN Fuse Value
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pub fuse_soc_manifest_svn: Option<u32>,
    #[arg(long, value_parser=maybe_hex::<u32>)]
    /// Soc Manifest Max SVN Fuse Value
    pub fuse_soc_manifest_max_svn: Option<u32>,
    #[arg(long)]
    pub fuse_vendor_hashes_prod_partition: Option<String>,
}

pub struct Emulator {
    pub mcu_cpu: Cpu<AutoRootBus>,
    pub caliptra_cpu: CaliptraMainCpu<CaliptraMainRootBus>,
    pub bmc: Option<Bmc>,
    pub timer: Timer,
    pub trace_file: Option<File>,
    pub stdin_uart: Option<Arc<Mutex<Option<u8>>>>,
    pub sram_range: Range<u32>,
    #[allow(dead_code)]
    pub clock: Rc<Clock>,
    #[allow(dead_code)]
    pub pic: Rc<Pic>,
    #[allow(dead_code)]
    pub uart_output: Option<Rc<RefCell<Vec<u8>>>>,
    #[allow(dead_code)]
    pub i3c_controller: I3cController,
    #[allow(dead_code)]
    pub doe_mbox_fsm: doe_mbox_fsm::DoeMboxFsm,
}

impl Emulator {
    /// Create an Emulator from command line arguments without external callbacks
    pub fn from_args(cli: EmulatorArgs, capture_uart_output: bool) -> std::io::Result<Self> {
        Self::from_args_with_callbacks(cli, capture_uart_output, None, None)
    }

    /// Create an Emulator from command line arguments with optional external callbacks
    pub fn from_args_with_callbacks(
        cli: EmulatorArgs,
        capture_uart_output: bool,
        external_read_callback: Option<ExternalReadCallback>,
        external_write_callback: Option<ExternalWriteCallback>,
    ) -> std::io::Result<Self> {
        let args_rom = &cli.rom;
        let args_log_dir = &cli.log_dir.unwrap_or_else(|| PathBuf::from("/tmp"));

        if !Path::new(&args_rom).exists() {
            println!("ROM File {:?} does not exist", args_rom);
            exit(-1);
        }

        let device_lifecycle: Option<String> = if cli.manufacturing_mode {
            Some("manufacturing".into())
        } else {
            Some("production".into())
        };

        let req_idevid_csr: Option<bool> = if cli.manufacturing_mode {
            Some(true)
        } else {
            None
        };

        let use_mcu_recovery_interface;
        #[cfg(feature = "test-flash-based-boot")]
        {
            use_mcu_recovery_interface = true;
        }
        #[cfg(not(feature = "test-flash-based-boot"))]
        {
            use_mcu_recovery_interface = false;
        }

        let (mut caliptra_cpu, soc_to_caliptra, ext_mci) = start_caliptra(&StartCaliptraArgs {
            rom: cli.caliptra_rom,
            device_lifecycle,
            req_idevid_csr,
            use_mcu_recovery_interface,
        })
        .expect("Failed to start Caliptra CPU");

        let rom_buffer = read_binary(args_rom, 0)?;
        if rom_buffer.len() > ROM_SIZE as usize {
            println!("ROM File Size must not exceed {} bytes", ROM_SIZE);
            exit(-1);
        }
        println!(
            "Loaded ROM File {:?} of size {}",
            args_rom,
            rom_buffer.len(),
        );

        let mcu_firmware = read_binary(&cli.firmware, 0x4000_0000)?;

        let clock = Rc::new(Clock::new());

        let uart_output = if capture_uart_output {
            Some(Rc::new(RefCell::new(Vec::new())))
        } else {
            None
        };

        let stdin_uart = if cli.stdin_uart && std::io::stdin().is_terminal() {
            Some(Arc::new(Mutex::new(None)))
        } else {
            None
        };
        let pic = Rc::new(Pic::new());

        let mut mcu_root_bus_offsets = McuRootBusOffsets::default();
        let mut auto_root_bus_offsets = AutoRootBusOffsets::default();

        // Apply all the CLI offset overrides
        if let Some(rom_offset) = cli.rom_offset {
            mcu_root_bus_offsets.rom_offset = rom_offset;
        }
        if let Some(rom_size) = cli.rom_size {
            mcu_root_bus_offsets.rom_size = rom_size;
        }
        if let Some(sram_offset) = cli.sram_offset {
            mcu_root_bus_offsets.ram_offset = sram_offset;
        }
        if let Some(uart_offset) = cli.uart_offset {
            mcu_root_bus_offsets.uart_offset = uart_offset;
        }
        if let Some(uart_size) = cli.uart_size {
            mcu_root_bus_offsets.uart_size = uart_size;
        }
        if let Some(ctrl_offset) = cli.ctrl_offset {
            mcu_root_bus_offsets.ctrl_offset = ctrl_offset;
        }
        if let Some(ctrl_size) = cli.ctrl_size {
            mcu_root_bus_offsets.ctrl_size = ctrl_size;
        }
        if let Some(spi_offset) = cli.spi_offset {
            mcu_root_bus_offsets.spi_offset = spi_offset;
        }
        if let Some(spi_size) = cli.spi_size {
            mcu_root_bus_offsets.spi_size = spi_size;
        }
        if let Some(pic_offset) = cli.pic_offset {
            mcu_root_bus_offsets.pic_offset = pic_offset;
            auto_root_bus_offsets.el2_pic_offset = pic_offset;
        }
        if let Some(external_test_sram_offset) = cli.external_test_sram_offset {
            mcu_root_bus_offsets.external_test_sram_offset = external_test_sram_offset;
        }
        if let Some(external_test_sram_size) = cli.external_test_sram_size {
            mcu_root_bus_offsets.external_test_sram_size = external_test_sram_size;
        }
        if let Some(sram_size) = cli.sram_size {
            mcu_root_bus_offsets.ram_size = sram_size;
        }
        if let Some(dccm_offset) = cli.dccm_offset {
            mcu_root_bus_offsets.rom_dedicated_ram_offset = dccm_offset;
        }
        if let Some(dccm_size) = cli.dccm_size {
            mcu_root_bus_offsets.rom_dedicated_ram_size = dccm_size;
        }
        if let Some(i3c_offset) = cli.i3c_offset {
            auto_root_bus_offsets.i3c_offset = i3c_offset;
        }
        if let Some(i3c_size) = cli.i3c_size {
            auto_root_bus_offsets.i3c_size = i3c_size;
        }
        if let Some(primary_flash_offset) = cli.primary_flash_offset {
            auto_root_bus_offsets.primary_flash_offset = primary_flash_offset;
        }
        if let Some(primary_flash_size) = cli.primary_flash_size {
            auto_root_bus_offsets.primary_flash_size = primary_flash_size;
        }
        if let Some(secondary_flash_offset) = cli.secondary_flash_offset {
            auto_root_bus_offsets.secondary_flash_offset = secondary_flash_offset;
        }
        if let Some(secondary_flash_size) = cli.secondary_flash_size {
            auto_root_bus_offsets.secondary_flash_size = secondary_flash_size;
        }
        if let Some(mci_offset) = cli.mci_offset {
            auto_root_bus_offsets.mci_offset = mci_offset;
        }
        if let Some(mci_size) = cli.mci_size {
            auto_root_bus_offsets.mci_size = mci_size;
        }
        if let Some(dma_offset) = cli.dma_offset {
            auto_root_bus_offsets.dma_offset = dma_offset;
        }
        if let Some(dma_size) = cli.dma_size {
            auto_root_bus_offsets.dma_size = dma_size;
        }
        if let Some(mbox_offset) = cli.mbox_offset {
            auto_root_bus_offsets.mbox_offset = mbox_offset;
        }
        if let Some(mbox_size) = cli.mbox_size {
            auto_root_bus_offsets.mbox_size = mbox_size;
        }
        if let Some(soc_offset) = cli.soc_offset {
            auto_root_bus_offsets.soc_offset = soc_offset;
        }
        if let Some(soc_size) = cli.soc_size {
            auto_root_bus_offsets.soc_size = soc_size;
        }
        if let Some(otp_offset) = cli.otp_offset {
            auto_root_bus_offsets.otp_offset = otp_offset;
        }
        if let Some(otp_size) = cli.otp_size {
            auto_root_bus_offsets.otp_size = otp_size;
        }
        if let Some(lc_offset) = cli.lc_offset {
            auto_root_bus_offsets.lc_offset = lc_offset;
        }
        if let Some(lc_size) = cli.lc_size {
            auto_root_bus_offsets.lc_size = lc_size;
        }

        let bus_args = McuRootBusArgs {
            offsets: mcu_root_bus_offsets.clone(),
            rom: rom_buffer,
            log_dir: args_log_dir.clone(),
            uart_output: uart_output.clone(),
            uart_rx: stdin_uart.clone(),
            pic: pic.clone(),
            clock: clock.clone(),
        };
        let root_bus = McuRootBus::new(bus_args).unwrap();

        // Create external communication bus
        let mut caliptra_to_ext = CaliptraToExtBus::new();

        // Set external callbacks if provided
        if let Some(read_callback) = external_read_callback {
            caliptra_to_ext.set_read_callback(read_callback);
        }
        if let Some(write_callback) = external_write_callback {
            caliptra_to_ext.set_write_callback(write_callback);
        }

        let dma_ram = root_bus.ram.clone();
        let dma_rom_sram = root_bus.rom_sram.clone();
        let direct_read_flash = root_bus.direct_read_flash.clone();

        let i3c_irq = pic.register_irq(McuRootBus::I3C_IRQ);

        println!("Starting I3C Socket, port {}", cli.i3c_port.unwrap_or(0));

        let mut i3c_controller = if let Some(i3c_port) = cli.i3c_port {
            let (rx, tx) = start_i3c_socket(i3c_port);
            I3cController::new(rx, tx)
        } else {
            I3cController::default()
        };
        let i3c = I3c::new(
            &clock.clone(),
            &mut i3c_controller,
            i3c_irq,
            cli.hw_revision.clone(),
        );
        let i3c_dynamic_address = i3c.get_dynamic_address().unwrap();

        let doe_event_irq = pic.register_irq(McuRootBus::DOE_MBOX_EVENT_IRQ);
        let doe_mbox_periph = DoeMboxPeriph::default();

        let mut doe_mbox_fsm = doe_mbox_fsm::DoeMboxFsm::new(doe_mbox_periph.clone());

        let doe_mbox = DummyDoeMbox::new(&clock.clone(), doe_event_irq, doe_mbox_periph);

        println!("Starting DOE mailbox transport thread");

        // Feature flag based test setup
        if cfg!(feature = "test-doe-transport-loopback") {
            let (test_rx, test_tx) = doe_mbox_fsm.start();
            println!("Starting DOE transport loopback test thread");
            let tests = tests::doe_transport_loopback::generate_tests();
            doe_mbox_fsm::run_doe_transport_tests(test_tx, test_rx, tests);
        } else if cfg!(feature = "test-doe-discovery") {
            let (test_rx, test_tx) = doe_mbox_fsm.start();
            println!("Starting DOE discovery test thread");
            let tests = tests::doe_discovery::DoeDiscoveryTest::generate_tests();
            doe_mbox_fsm::run_doe_transport_tests(test_tx, test_rx, tests);
        } else if cfg!(feature = "test-doe-user-loopback") {
            let (test_rx, test_tx) = doe_mbox_fsm.start();
            println!("Starting DOE user loopback test thread");
            let tests = tests::doe_user_loopback::generate_tests();
            doe_mbox_fsm::run_doe_transport_tests(test_tx, test_rx, tests);
        } else if cfg!(feature = "test-mctp-ctrl-cmds") {
            i3c_controller.start();
            println!(
                "Starting test-mctp-ctrl-cmds test thread for testing target {:?}",
                i3c.get_dynamic_address().unwrap()
            );

            let tests = tests::mctp_ctrl_cmd::MCTPCtrlCmdTests::generate_tests();
            i3c_socket::run_tests(
                cli.i3c_port.unwrap(),
                i3c.get_dynamic_address().unwrap(),
                tests,
                None,
            );
        } else if cfg!(feature = "test-mctp-capsule-loopback") {
            i3c_controller.start();
            println!(
                "Starting loopback test thread for testing target {:?}",
                i3c.get_dynamic_address().unwrap()
            );

            let tests = tests::mctp_loopback::generate_tests();
            i3c_socket::run_tests(
                cli.i3c_port.unwrap(),
                i3c.get_dynamic_address().unwrap(),
                tests,
                None,
            );
        } else if cfg!(feature = "test-mctp-user-loopback") {
            i3c_controller.start();
            println!(
                "Starting loopback test thread for testing target {:?}",
                i3c.get_dynamic_address().unwrap()
            );

            let spdm_loopback_tests = tests::mctp_user_loopback::MctpUserAppTests::generate_tests(
                tests::mctp_util::base_protocol::MctpMsgType::Caliptra as u8,
            );

            i3c_socket::run_tests(
                cli.i3c_port.unwrap(),
                i3c.get_dynamic_address().unwrap(),
                spdm_loopback_tests,
                None,
            );
        } else if cfg!(feature = "test-mctp-spdm-responder-conformance") {
            if std::env::var("SPDM_VALIDATOR_DIR").is_err() {
                println!("SPDM_VALIDATOR_DIR environment variable is not set. Skipping test");
                exit(0);
            }
            i3c_controller.start();
            crate::tests::spdm_responder_validator::mctp::run_mctp_spdm_conformance_test(
                cli.i3c_port.unwrap(),
                i3c.get_dynamic_address().unwrap(),
                std::time::Duration::from_secs(9000), // timeout in seconds
            );
        } else if cfg!(feature = "test-doe-spdm-responder-conformance") {
            if std::env::var("SPDM_VALIDATOR_DIR").is_err() {
                println!("SPDM_VALIDATOR_DIR environment variable is not set. Skipping test");
                exit(0);
            }
            let (test_rx, test_tx) = doe_mbox_fsm.start();
            crate::tests::spdm_responder_validator::doe::run_doe_spdm_conformance_test(
                test_tx,
                test_rx,
                std::time::Duration::from_secs(9000), // timeout in seconds
            );
        }

        if cfg!(any(
            feature = "test-pldm-request-response",
            feature = "test-pldm-discovery",
            feature = "test-pldm-fw-update",
        )) {
            i3c_controller.start();
            let pldm_transport =
                MctpTransport::new(cli.i3c_port.unwrap(), i3c.get_dynamic_address().unwrap());
            let pldm_socket = pldm_transport
                .create_socket(EndpointId(0), EndpointId(1))
                .unwrap();
            PldmRequestResponseTest::run(pldm_socket);
        }

        if cfg!(feature = "test-pldm-fw-update-e2e") {
            i3c_controller.start();
            let pldm_transport =
                MctpTransport::new(cli.i3c_port.unwrap(), i3c.get_dynamic_address().unwrap());
            let pldm_socket = pldm_transport
                .create_socket(EndpointId(8), EndpointId(0))
                .unwrap();
            tests::pldm_fw_update_test::PldmFwUpdateTest::run(pldm_socket);
        }

        let create_flash_controller =
            |default_path: &str,
             error_irq: u8,
             event_irq: u8,
             initial_content: Option<&[u8]>,
             direct_read_region: Option<Rc<RefCell<caliptra_emu_bus::Ram>>>| {
                // Use a temporary file for flash storage if we're running a test
                let flash_file = if cfg!(any(
                    feature = "test-flash-ctrl-init",
                    feature = "test-flash-ctrl-read-write-page",
                    feature = "test-flash-ctrl-erase-page",
                    feature = "test-flash-storage-read-write",
                    feature = "test-flash-storage-erase",
                    feature = "test-flash-usermode",
                    feature = "test-mcu-rom-flash-access",
                    feature = "test-log-flash-linear",
                    feature = "test-log-flash-circular",
                    feature = "test-log-flash-usermode",
                )) {
                    Some(
                        tempfile::NamedTempFile::new()
                            .unwrap()
                            .into_temp_path()
                            .to_path_buf(),
                    )
                } else {
                    Some(PathBuf::from(default_path))
                };

                DummyFlashCtrl::new(
                    &clock.clone(),
                    direct_read_region,
                    flash_file,
                    pic.register_irq(error_irq),
                    pic.register_irq(event_irq),
                    initial_content,
                )
                .unwrap()
            };

        let primary_flash_initial_content = if cli.primary_flash_image.is_some() {
            let flash_image_path = cli.primary_flash_image.as_ref().unwrap();
            println!("Loading flash image from {}", flash_image_path.display());
            const FLASH_SIZE: usize =
                DummyFlashCtrl::PAGE_SIZE * DummyFlashCtrl::MAX_PAGES as usize;
            let mut flash_image = vec![0; FLASH_SIZE];
            let mut file = File::open(flash_image_path)?;
            let bytes_read = file.read(&mut flash_image)?;
            if bytes_read > FLASH_SIZE {
                println!("Flash image size exceeds {} bytes", FLASH_SIZE);
                exit(-1);
            }

            Some(flash_image[..bytes_read].to_vec())
        } else {
            None
        };

        let primary_flash_controller = create_flash_controller(
            "primary_flash",
            McuRootBus::PRIMARY_FLASH_CTRL_ERROR_IRQ,
            McuRootBus::PRIMARY_FLASH_CTRL_EVENT_IRQ,
            primary_flash_initial_content.as_deref(),
            Some(direct_read_flash.clone()),
        );

        let secondary_flash_initial_content = if cli.secondary_flash_image.is_some() {
            let flash_image_path = cli.secondary_flash_image.as_ref().unwrap();
            const FLASH_SIZE: usize =
                DummyFlashCtrl::PAGE_SIZE * DummyFlashCtrl::MAX_PAGES as usize;
            let mut flash_image = vec![0; FLASH_SIZE];
            let mut file = File::open(flash_image_path)?;
            let bytes_read = file.read(&mut flash_image)?;
            if bytes_read > FLASH_SIZE {
                println!("Flash image size exceeds {} bytes", FLASH_SIZE);
                exit(-1);
            }

            Some(flash_image[..bytes_read].to_vec())
        } else {
            None
        };

        let secondary_flash_controller = create_flash_controller(
            "secondary_flash",
            McuRootBus::SECONDARY_FLASH_CTRL_ERROR_IRQ,
            McuRootBus::SECONDARY_FLASH_CTRL_EVENT_IRQ,
            secondary_flash_initial_content.as_deref(),
            None,
        );

        let mut dma_ctrl = emulator_periph::DummyDmaCtrl::new(
            &clock.clone(),
            pic.register_irq(McuRootBus::DMA_ERROR_IRQ),
            pic.register_irq(McuRootBus::DMA_EVENT_IRQ),
            Some(root_bus.external_test_sram.clone()),
        )
        .unwrap();

        emulator_periph::DummyDmaCtrl::set_dma_ram(&mut dma_ctrl, dma_ram.clone());
        let mci_irq = root_bus.mci_irq.clone();

        let delegates: Vec<Box<dyn Bus>> = vec![
            Box::new(root_bus),
            Box::new(soc_to_caliptra),
            Box::new(caliptra_to_ext),
        ];

        let vendor_pk_hash = cli.vendor_pk_hash.map(|hash| {
            let v = hex::decode(hash).unwrap();
            v.try_into().unwrap()
        });
        let owner_pk_hash = cli.owner_pk_hash.map(|hash| {
            let v = hex::decode(hash).unwrap();
            v.try_into().unwrap()
        });
        let fuse_vendor_hashes_prod_partition = cli
            .fuse_vendor_hashes_prod_partition
            .map(|fuse| hex::decode(fuse).expect("Invalid hex in vendor_hashes_prod_partition"));

        let lc = LcCtrl::new();

        let mcu_mailbox0 = McuMailbox0Internal::new(&clock.clone());

        let otp = Otp::new(
            &clock.clone(),
            OtpArgs {
                file_name: cli.otp,
                owner_pk_hash,
                vendor_pk_hash,
                vendor_pqc_type: cli.vendor_pqc_type,
                soc_manifest_svn: cli.fuse_soc_manifest_svn.map(|v| v as u8),
                soc_manifest_max_svn: cli.fuse_soc_manifest_max_svn.map(|v| v as u8),
                vendor_hashes_prod_partition: fuse_vendor_hashes_prod_partition,
                ..Default::default()
            },
        )?;
        let mci = Mci::new(&clock.clone(), ext_mci, mci_irq, Some(mcu_mailbox0.clone()));

        let mut auto_root_bus = AutoRootBus::new(
            delegates,
            Some(auto_root_bus_offsets),
            Some(Box::new(i3c)),
            Some(Box::new(primary_flash_controller)),
            Some(Box::new(secondary_flash_controller)),
            Some(Box::new(mci)),
            Some(Box::new(doe_mbox)),
            Some(Box::new(dma_ctrl)),
            None,
            Some(Box::new(otp)),
            Some(Box::new(lc)),
            None,
            None,
            None,
        );

        // Set the DMA RAM for Primary Flash Controller
        auto_root_bus
            .primary_flash_periph
            .as_mut()
            .unwrap()
            .periph
            .set_dma_ram(dma_ram.clone());

        // Set DMA RAM for ROM access to Primary Flash Controller
        auto_root_bus
            .primary_flash_periph
            .as_mut()
            .unwrap()
            .periph
            .set_dma_rom_sram(dma_rom_sram.clone());

        // Set the DMA RAM for Secondary Flash Controller
        auto_root_bus
            .secondary_flash_periph
            .as_mut()
            .unwrap()
            .periph
            .set_dma_ram(dma_ram);

        // Set the DMA RAM for ROM access to Secondary Flash Controller
        auto_root_bus
            .secondary_flash_periph
            .as_mut()
            .unwrap()
            .periph
            .set_dma_rom_sram(dma_rom_sram.clone());

        let cpu_args = DEFAULT_CPU_ARGS;

        let mut cpu = Cpu::new(auto_root_bus, clock.clone(), pic.clone(), cpu_args);
        cpu.write_pc(mcu_root_bus_offsets.rom_offset);
        cpu.register_events();

        let mut bmc;
        #[cfg(feature = "test-flash-based-boot")]
        {
            println!("Emulator is using MCU recovery interface");
            bmc = None;
            let (caliptra_event_sender, caliptra_event_receiver) = caliptra_cpu.register_events();
            let (mcu_event_sender, mcu_event_receiver) = cpu.register_events();
            cpu.bus
                .i3c_periph
                .as_mut()
                .unwrap()
                .periph
                .register_event_channels(
                    caliptra_event_sender,
                    caliptra_event_receiver,
                    mcu_event_sender,
                    mcu_event_receiver,
                );
        }
        #[cfg(not(feature = "test-flash-based-boot"))]
        {
            let (caliptra_event_sender, caliptra_event_receiver) = caliptra_cpu.register_events();
            let (mcu_event_sender, mcu_event_reciever) = cpu.register_events();
            // prepare the BMC recovery interface emulator
            bmc = Some(Bmc::new(
                caliptra_event_sender,
                caliptra_event_receiver,
                mcu_event_sender,
                mcu_event_reciever,
            ));

            // load the firmware images and SoC manifest into the recovery interface emulator
            let caliptra_firmware = read_binary(&cli.caliptra_firmware, RAM_ORG).unwrap();
            let soc_manifest = read_binary(&cli.soc_manifest, 0).unwrap();
            let bmc = bmc.as_mut().unwrap();
            bmc.push_recovery_image(caliptra_firmware);
            bmc.push_recovery_image(soc_manifest);
            bmc.push_recovery_image(mcu_firmware);
            println!("Active mode enabled with 3 recovery images");
        }

        #[cfg(any(
            feature = "test-mcu-mbox-soc-requester-loopback",
            feature = "test-mcu-mbox-usermode"
        ))]
        {
            const SOC_AGENT_ID: u32 = 0x1;
            use emulator_mcu_mbox::mcu_mailbox_transport::McuMailboxTransport;
            let transport = McuMailboxTransport::new(
                mcu_mailbox0.as_external(MciMailboxRequester::SocAgent(SOC_AGENT_ID)),
            );
            let test = crate::tests::emulator_mcu_mailbox_test::RequestResponseTest::new(transport);
            test.run();
        }

        if cli.streaming_boot.is_some() {
            let _ = simple_logger::SimpleLogger::new()
                .with_level(log::LevelFilter::Info)
                .init();
            let pldm_fw_pkg_path = cli.streaming_boot.as_ref().unwrap();
            println!(
                "Starting streaming boot using PLDM package {}",
                pldm_fw_pkg_path.display()
            );

            // Parse PLDM Firmware Package
            let pldm_fw_pkg = FirmwareManifest::decode_firmware_package(
                &pldm_fw_pkg_path.to_str().unwrap().to_string(),
                None,
            );
            if pldm_fw_pkg.is_err() {
                println!("Failed to parse PLDM firmware package");
                exit(-1);
            }

            // Start the PLDM Daemon
            i3c_controller.start();
            let pldm_transport = MctpTransport::new(cli.i3c_port.unwrap(), i3c_dynamic_address);
            let pldm_socket = pldm_transport
                .create_socket(EndpointId(LOCAL_TEST_ENDPOINT_EID), EndpointId(1))
                .unwrap();
            if cfg!(feature = "test-pldm-streaming-boot") {
                // If we are running the PLDM daemon from an integration test,
                // we need to set the update state machine to exit on error
                let _ = PldmDaemon::run(
                    pldm_socket,
                    pldm_ua::daemon::Options {
                        pldm_fw_pkg: Some(pldm_fw_pkg.unwrap()),
                        discovery_sm_actions: pldm_ua::discovery_sm::DefaultActions {},
                        update_sm_actions: pldm_ua::update_sm::DefaultActionsExitOnError {},
                        fd_tid: 0x01,
                    },
                );
            } else {
                let _ = PldmDaemon::run(
                    pldm_socket,
                    pldm_ua::daemon::Options {
                        pldm_fw_pkg: Some(pldm_fw_pkg.unwrap()),
                        discovery_sm_actions: pldm_ua::discovery_sm::DefaultActions {},
                        update_sm_actions: pldm_ua::update_sm::DefaultActions {},
                        fd_tid: 0x01,
                    },
                );
            };
        }

        let instr_trace = if cli.trace_instr {
            Some(args_log_dir.join("caliptra_instr_trace.txt"))
        } else {
            None
        };

        let sram_range = mcu_root_bus_offsets.ram_offset
            ..mcu_root_bus_offsets.ram_offset + mcu_root_bus_offsets.ram_size;

        // Create the emulator instance
        Ok(Self::new(
            cpu,
            caliptra_cpu,
            instr_trace,
            stdin_uart,
            bmc,
            sram_range,
            clock,
            pic,
            uart_output,
            i3c_controller,
            doe_mbox_fsm,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mcu_cpu: Cpu<AutoRootBus>,
        caliptra_cpu: CaliptraMainCpu<CaliptraMainRootBus>,
        trace_path: Option<PathBuf>,
        stdin_uart: Option<Arc<Mutex<Option<u8>>>>,
        bmc: Option<Bmc>,
        sram_range: Range<u32>,
        clock: Rc<Clock>,
        pic: Rc<Pic>,
        uart_output: Option<Rc<RefCell<Vec<u8>>>>,
        i3c_controller: I3cController,
        doe_mbox_fsm: doe_mbox_fsm::DoeMboxFsm,
    ) -> Self {
        // read from the console in a separate thread to prevent blocking
        let stdin_uart_clone = stdin_uart.clone();
        std::thread::spawn(move || read_console(stdin_uart_clone));

        let timer = Timer::new(&mcu_cpu.clock.clone());
        let trace_file = trace_path.map(|path| File::create(path).unwrap());

        Self {
            mcu_cpu,
            caliptra_cpu,
            bmc,
            timer,
            trace_file,
            stdin_uart,
            sram_range,
            clock,
            pic,
            uart_output,
            i3c_controller,
            doe_mbox_fsm,
        }
    }

    pub fn step(&mut self) -> StepAction {
        if !EMULATOR_RUNNING.load(Ordering::Relaxed) {
            return StepAction::Break;
        }

        let now = self.mcu_cpu.clock.now();
        EMULATOR_TICKS.store(now, Ordering::Relaxed);
        if now % 1000 == 0 {
            TICK_COND.notify_all();
        }

        if let Some(ref stdin_uart) = self.stdin_uart {
            if stdin_uart.lock().unwrap().is_some() {
                self.timer.schedule_poll_in(1);
            }
        }

        let action = if let Some(ref mut trace_file) = self.trace_file {
            let trace_fn: &mut dyn FnMut(u32, RvInstr) = &mut |pc, instr| match instr {
                RvInstr::Instr32(instr32) => {
                    let _ = writeln!(trace_file, "{}", disassemble(pc, instr32));
                    println!("{{mcu cpu}}      {}", disassemble(pc, instr32));
                }
                RvInstr::Instr16(instr16) => {
                    let _ = writeln!(trace_file, "{}", disassemble(pc, instr16 as u32));
                    println!("{{mcu cpu}}      {}", disassemble(pc, instr16 as u32));
                }
            };
            self.mcu_cpu.step(Some(trace_fn))
        } else {
            self.mcu_cpu.step(None)
        };

        if action != StepAction::Continue {
            return action;
        }

        if self.sram_range.contains(&self.mcu_cpu.read_pc()) {
            MCU_RUNTIME_STARTED.store(true, Ordering::Relaxed);
        }

        let caliptra_action = if self.trace_file.is_some() {
            let caliptra_trace_fn: &mut dyn FnMut(u32, caliptra_emu_cpu::RvInstr) =
                &mut |pc, instr| match instr {
                    caliptra_emu_cpu::RvInstr::Instr32(instr32) => {
                        println!("{{caliptra cpu}} {}", disassemble(pc, instr32));
                    }
                    caliptra_emu_cpu::RvInstr::Instr16(instr16) => {
                        println!("{{caliptra cpu}} {}", disassemble(pc, instr16 as u32));
                    }
                };
            self.caliptra_cpu.step(Some(caliptra_trace_fn))
        } else {
            self.caliptra_cpu.step(None)
        };

        match caliptra_action {
            CaliptraMainStepAction::Continue => {}
            _ => {
                println!("Caliptra CPU Halted");
            }
        }

        if let Some(bmc) = self.bmc.as_mut() {
            bmc.step();
        }

        action
    }

    /// Get the current program counter (PC) of the MCU CPU
    pub fn get_pc(&self) -> u32 {
        self.mcu_cpu.read_pc()
    }
}

fn disassemble(pc: u32, instr: u32) -> String {
    let mut out = vec![];
    // TODO: we should replace this with something more efficient.
    let dis = dis::disasm_inst(dis::RvIsa::Rv32, pc as u64, instr as u64);
    write!(&mut out, "0x{:08x}   {}", pc, dis).unwrap();

    String::from_utf8(out).unwrap()
}

fn read_console(stdin_uart: Option<Arc<Mutex<Option<u8>>>>) {
    let mut buffer = vec![];
    if let Some(ref stdin_uart) = stdin_uart {
        while EMULATOR_RUNNING.load(std::sync::atomic::Ordering::Relaxed) {
            if buffer.is_empty() {
                match crossterm::event::read() {
                    Ok(Event::Key(KeyEvent {
                        code: KeyCode::Char(ch),
                        ..
                    })) => {
                        buffer.extend_from_slice(ch.to_string().as_bytes());
                    }
                    Ok(Event::Key(KeyEvent {
                        code: KeyCode::Enter,
                        ..
                    })) => {
                        buffer.push(b'\n');
                    }
                    Ok(Event::Key(KeyEvent {
                        code: KeyCode::Backspace,
                        ..
                    })) => {
                        if !buffer.is_empty() {
                            buffer.pop();
                        } else {
                            buffer.push(8);
                        }
                    }
                    _ => {} // ignore other keys
                }
            } else {
                let mut stdin_uart = stdin_uart.lock().unwrap();
                if stdin_uart.is_none() {
                    *stdin_uart = Some(buffer.remove(0));
                }
            }
            std::thread::yield_now();
        }
    }
}

fn read_binary(path: &PathBuf, expect_load_addr: u32) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Check if this is an ELF
    if buffer.starts_with(&[0x7f, 0x45, 0x4c, 0x46]) {
        println!("Loading ELF executable {}", path.display());
        let elf = elf::ElfExecutable::new(&buffer).unwrap();
        if elf.load_addr() != expect_load_addr {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "ELF executable has non-0x{:x} load address, which is not supported (got 0x{:x})",
                    expect_load_addr, elf.load_addr()
                ),
            ))?;
        }
        // TBF files have an entry point offset by 0x20
        if elf.entry_point() != expect_load_addr && elf.entry_point() != elf.load_addr() + 0x20 {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("ELF executable has non-0x{:x} entry point, which is not supported (got 0x{:x})", expect_load_addr, elf.entry_point()),
            ))?;
        }
        buffer = elf.content().clone();
    }

    Ok(buffer)
}

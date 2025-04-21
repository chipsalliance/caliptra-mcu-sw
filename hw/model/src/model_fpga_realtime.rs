// Licensed under the Apache-2.0 license

use crate::xi3c;
use crate::EtrngResponse;
use crate::ModelError;
use crate::Output;
use crate::{McuHwModel, SecurityState, SocManager, TrngMode};
use bitfield::bitfield;
use caliptra_emu_bus::{Bus, BusError, BusMmio, Event};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::io::{BufRead, BufReader, Write};
use std::marker::PhantomData;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
use std::{env, str::FromStr};
use uio::{UioDevice, UioError};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum OpenOcdError {
    Closed,
    CaliptraNotAccessible,
    VeerNotAccessible,
    WrongVersion,
}

// UIO mapping indices
const FPGA_WRAPPER_MAPPING: usize = 0;
const CALIPTRA_MAPPING: usize = 1;
const I3C_MAPPING: usize = 2; // TODO: get the correct value for this

// Set to core_clk cycles per ITRNG sample.
const ITRNG_DIVISOR: u32 = 400;
const DEFAULT_AXI_PAUSER: u32 = 0x1;

fn fmt_uio_error(err: UioError) -> String {
    format!("{err:?}")
}

// ITRNG FIFO stores 1024 DW and outputs 4 bits at a time to Caliptra.
const FPGA_ITRNG_FIFO_SIZE: usize = 1024;

// FPGA wrapper register offsets
const FPGA_WRAPPER_MAGIC_OFFSET: isize = 0x0000 / 4;
const FPGA_WRAPPER_VERSION_OFFSET: isize = 0x0004 / 4;
const FPGA_WRAPPER_CONTROL_OFFSET: isize = 0x0008 / 4;
const FPGA_WRAPPER_STATUS_OFFSET: isize = 0x000C / 4;
const FPGA_WRAPPER_PAUSER_OFFSET: isize = 0x0010 / 4;
const FPGA_WRAPPER_ITRNG_DIV_OFFSET: isize = 0x0014 / 4;
const FPGA_WRAPPER_CYCLE_COUNT_OFFSET: isize = 0x0018 / 4;
const _FPGA_WRAPPER_GENERIC_INPUT_OFFSET: isize = 0x0030 / 4;
const _FPGA_WRAPPER_GENERIC_OUTPUT_OFFSET: isize = 0x0038 / 4;
const FPGA_WRAPPER_DEOBF_KEY_OFFSET: isize = 0x0040 / 4;
const FPGA_WRAPPER_CSR_HMAC_KEY_OFFSET: isize = 0x0060 / 4;

const _FPGA_WRAPPER_LSU_USER_OFFSET: isize = 0x0100 / 4;
const _FPGA_WRAPPER_IFU_USER_OFFSET: isize = 0x0104 / 4;
const _FPGA_WRAPPER_CLP_USER_OFFSET: isize = 0x0108 / 4;
const _FPGA_WRAPPER_SOC_CFG_USER_OFFSET: isize = 0x010C / 4;
const _FPGA_WRAPPER_SRAM_CFG_USER_OFFSET: isize = 0x0110 / 4;
const FPGA_WRAPPER_MCU_RESET_VECTOR_OFFSET: isize = 0x0114 / 4;
const _FPGA_WRAPPER_MCI_ERROR: isize = 0x0118 / 4;
const _FPGA_WRAPPER_MCU_CONFIG: isize = 0x011C / 4;
const _FPGA_WRAPPER_MCI_GENERIC_INPUT_WIRES_0_OFFSET: isize = 0x0120 / 4;
const _FPGA_WRAPPER_MCI_GENERIC_INPUT_WIRES_1_OFFSET: isize = 0x0124 / 4;
const FPGA_WRAPPER_MCI_GENERIC_OUTPUT_WIRES_0_OFFSET: isize = 0x0128 / 4;
const FPGA_WRAPPER_MCI_GENERIC_OUTPUT_WIRES_1_OFFSET: isize = 0x012C / 4;
const FPGA_WRAPPER_LOG_FIFO_DATA_OFFSET: isize = 0x1000 / 4;
const FPGA_WRAPPER_LOG_FIFO_STATUS_OFFSET: isize = 0x1004 / 4;
const FPGA_WRAPPER_ITRNG_FIFO_DATA_OFFSET: isize = 0x1008 / 4;
const FPGA_WRAPPER_ITRNG_FIFO_STATUS_OFFSET: isize = 0x100C / 4;

bitfield! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    /// Wrapper wires -> Caliptra
    pub struct GpioOutput(u32);
    cptra_pwrgood, set_cptra_pwrgood: 0, 0;
    cptra_rst_b, set_cptra_rst_b: 1, 1;
    debug_locked, set_debug_locked: 2, 2;
    device_lifecycle, set_device_lifecycle: 4, 3;
}

bitfield! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    /// Wrapper wires <- Caliptra
    pub struct GpioInput(u32);
    cptra_error_fatal, _: 0, 0;
    cptra_error_non_fatal, _: 1, 1;
    ready_for_fuses, _: 2, 2;
    ready_for_fw, _: 3, 3;
    ready_for_runtime, _: 4, 4;
}

bitfield! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    /// Log FIFO data
    pub struct FifoData(u32);
    log_fifo_char, _: 7, 0;
    log_fifo_valid, _: 8, 8;
}

bitfield! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    /// Log FIFO status
    pub struct FifoStatus(u32);
    log_fifo_empty, _: 0, 0;
    log_fifo_full, _: 1, 1;
}

bitfield! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    /// ITRNG FIFO status
    pub struct TrngFifoStatus(u32);
    trng_fifo_empty, _: 0, 0;
    trng_fifo_full, _: 1, 1;
    trng_fifo_reset, set_trng_fifo_reset: 2, 2;
}

pub struct ModelFpgaRealtime {
    dev: UioDevice,
    wrapper: *mut u32,
    mmio: *mut u32,
    output: Output,

    realtime_thread: Option<thread::JoinHandle<()>>,
    realtime_thread_exit_flag: Arc<AtomicBool>,

    trng_mode: TrngMode,
    openocd: Option<Child>,

    #[allow(dead_code)]
    i3c_mmio: *mut u32,
    recovery_images: Arc<Mutex<Vec<Vec<u8>>>>,
    i3c_controller: xi3c::Controller,
}

impl ModelFpgaRealtime {
    fn realtime_thread_itrng_fn(
        wrapper: *mut u32,
        i3c: *mut u32,
        recovery_images: Arc<Mutex<Vec<Vec<u8>>>>,
        exit: Arc<AtomicBool>,
        mut itrng_nibbles: Box<dyn Iterator<Item = u8> + Send>,
    ) {
        let mut recovery = RecoveryFlow {
            i3c_mmio: i3c,
            images: recovery_images,
            image_index: 0,
            image_offset: 0,
        };
        // Reset ITRNG FIFO to clear out old data
        unsafe {
            let mut trngfifosts = TrngFifoStatus(0);
            trngfifosts.set_trng_fifo_reset(1);
            wrapper
                .offset(FPGA_WRAPPER_ITRNG_FIFO_STATUS_OFFSET)
                .write_volatile(trngfifosts.0);
            trngfifosts.set_trng_fifo_reset(0);
            wrapper
                .offset(FPGA_WRAPPER_ITRNG_FIFO_STATUS_OFFSET)
                .write_volatile(trngfifosts.0);
        };
        // Small delay to allow reset to complete
        thread::sleep(Duration::from_millis(1));

        while !exit.load(Ordering::Relaxed) {
            // Once TRNG data is requested the FIFO will continously empty. Load at max one FIFO load at a time.
            // FPGA ITRNG FIFO is 1024 DW deep.
            for _i in 0..FPGA_ITRNG_FIFO_SIZE {
                let trngfifosts = unsafe {
                    TrngFifoStatus(
                        wrapper
                            .offset(FPGA_WRAPPER_ITRNG_FIFO_STATUS_OFFSET)
                            .read_volatile(),
                    )
                };
                if trngfifosts.trng_fifo_full() == 0 {
                    let mut itrng_dw = 0;
                    for i in (0..8).rev() {
                        match itrng_nibbles.next() {
                            Some(nibble) => itrng_dw += u32::from(nibble) << (4 * i),
                            None => return,
                        }
                    }
                    unsafe {
                        wrapper
                            .offset(FPGA_WRAPPER_ITRNG_FIFO_DATA_OFFSET)
                            .write_volatile(itrng_dw);
                    }
                } else {
                    break;
                }
            }
            recovery.step();
            // 1 second * (20 MHz / (2^13 throttling counter)) / 8 nibbles per DW: 305 DW of data consumed in 1 second.
            let end_time = Instant::now() + Duration::from_millis(1000);
            while !exit.load(Ordering::Relaxed) && Instant::now() < end_time {
                recovery.step();
                thread::sleep(Duration::from_millis(1));
            }
        }
    }

    fn realtime_thread_etrng_fn(
        mmio: *mut u32,
        i3c: *mut u32,
        recovery_images: Arc<Mutex<Vec<Vec<u8>>>>,
        exit: Arc<AtomicBool>,
        mut etrng_responses: Box<dyn Iterator<Item = EtrngResponse>>,
    ) {
        let mut recovery = RecoveryFlow {
            i3c_mmio: i3c,
            images: recovery_images,
            image_index: 0,
            image_offset: 0,
        };
        let soc_ifc_trng = unsafe {
            caliptra_registers::soc_ifc_trng::RegisterBlock::new_with_mmio(
                0x3003_0000 as *mut u32,
                BusMmio::new(FpgaRealtimeBus {
                    mmio,
                    phantom: Default::default(),
                }),
            )
        };

        while !exit.load(Ordering::Relaxed) {
            let trng_status = soc_ifc_trng.cptra_trng_status().read();
            if trng_status.data_req() {
                if let Some(resp) = etrng_responses.next() {
                    soc_ifc_trng.cptra_trng_data().write(&resp.data);
                    soc_ifc_trng
                        .cptra_trng_status()
                        .write(|w| w.data_wr_done(true));
                }
            }
            recovery.step();
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn is_ready_for_fuses(&self) -> bool {
        unsafe {
            GpioInput(
                self.wrapper
                    .offset(FPGA_WRAPPER_STATUS_OFFSET)
                    .read_volatile(),
            )
            .ready_for_fuses()
                != 0
        }
    }
    fn set_cptra_pwrgood(&mut self, value: bool) {
        unsafe {
            let mut val = GpioOutput(
                self.wrapper
                    .offset(FPGA_WRAPPER_CONTROL_OFFSET)
                    .read_volatile(),
            );
            val.set_cptra_pwrgood(value as u32);
            self.wrapper
                .offset(FPGA_WRAPPER_CONTROL_OFFSET)
                .write_volatile(val.0);
        }
    }
    fn set_cptra_rst_b(&mut self, value: bool) {
        unsafe {
            let mut val = GpioOutput(
                self.wrapper
                    .offset(FPGA_WRAPPER_CONTROL_OFFSET)
                    .read_volatile(),
            );
            val.set_cptra_rst_b(value as u32);
            self.wrapper
                .offset(FPGA_WRAPPER_CONTROL_OFFSET)
                .write_volatile(val.0);
        }
    }
    fn set_security_state(&mut self, value: SecurityState) {
        unsafe {
            let mut val = GpioOutput(
                self.wrapper
                    .offset(FPGA_WRAPPER_CONTROL_OFFSET)
                    .read_volatile(),
            );
            val.set_debug_locked(u32::from(value.debug_locked()));
            val.set_device_lifecycle(u32::from(value.device_lifecycle()));
            self.wrapper
                .offset(FPGA_WRAPPER_CONTROL_OFFSET)
                .write_volatile(val.0);
        }
    }

    fn clear_log_fifo(&mut self) {
        loop {
            let fifodata = unsafe {
                FifoData(
                    self.wrapper
                        .offset(FPGA_WRAPPER_LOG_FIFO_DATA_OFFSET)
                        .read_volatile(),
                )
            };
            if fifodata.log_fifo_valid() == 0 {
                break;
            }
        }
    }

    fn handle_log(&mut self) {
        // Check if the FIFO is full (which probably means there was an overrun)
        let fifosts = unsafe {
            FifoStatus(
                self.wrapper
                    .offset(FPGA_WRAPPER_LOG_FIFO_STATUS_OFFSET)
                    .read_volatile(),
            )
        };
        if fifosts.log_fifo_full() != 0 {
            panic!("FPGA log FIFO overran");
        }
        // Check and empty log FIFO
        loop {
            let fifodata = unsafe {
                FifoData(
                    self.wrapper
                        .offset(FPGA_WRAPPER_LOG_FIFO_DATA_OFFSET)
                        .read_volatile(),
                )
            };
            // Add byte to log if it is valid
            if fifodata.log_fifo_valid() != 0 {
                self.output()
                    .sink()
                    .push_uart_char(fifodata.log_fifo_char().try_into().unwrap());
            } else {
                break;
            }
        }
    }
    // UIO crate doesn't provide a way to unmap memory.
    fn unmap_mapping(&self, addr: *mut u32, mapping: usize) {
        let map_size = self.dev.map_size(mapping).unwrap();

        unsafe {
            nix::sys::mman::munmap(addr as *mut libc::c_void, map_size).unwrap();
        }
    }

    fn set_itrng_divider(&mut self, divider: u32) {
        unsafe {
            self.wrapper
                .offset(FPGA_WRAPPER_ITRNG_DIV_OFFSET)
                .write_volatile(divider - 1);
        }
    }
}

// simple recovery flow implementation
#[allow(dead_code)]
struct RecoveryFlow {
    i3c_mmio: *mut u32,
    images: Arc<Mutex<Vec<Vec<u8>>>>,
    image_index: usize,
    image_offset: usize,
}

impl RecoveryFlow {
    fn step(&mut self) {}
}

// Hack to pass *mut u32 between threads
struct SendPtr(*mut u32);
unsafe impl Send for SendPtr {}

impl SocManager for ModelFpgaRealtime {
    const SOC_IFC_ADDR: u32 = 0x3003_0000;
    const SOC_IFC_TRNG_ADDR: u32 = 0x3003_0000;
    const SOC_SHA512_ACC_ADDR: u32 = 0x3002_1000;
    const SOC_MBOX_ADDR: u32 = 0x3002_0000;

    const MAX_WAIT_CYCLES: u32 = 20_000_000;

    type TMmio<'a> = BusMmio<FpgaRealtimeBus<'a>>;

    fn mmio_mut(&mut self) -> Self::TMmio<'_> {
        BusMmio::new(self.apb_bus())
    }

    fn delay(&mut self) {
        self.step();
    }
}
impl McuHwModel for ModelFpgaRealtime {
    type TBus<'a> = FpgaRealtimeBus<'a>;

    fn apb_bus(&mut self) -> Self::TBus<'_> {
        FpgaRealtimeBus {
            mmio: self.mmio,
            phantom: Default::default(),
        }
    }

    fn step(&mut self) {
        self.handle_log();
    }

    fn new_unbooted(params: crate::InitParams) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized,
    {
        let output = Output::new(params.log_writer);
        let uio_num = usize::from_str(&env::var("CPTRA_UIO_NUM")?)?;
        let dev = UioDevice::blocking_new(uio_num)?;

        let wrapper = dev
            .map_mapping(FPGA_WRAPPER_MAPPING)
            .map_err(fmt_uio_error)? as *mut u32;
        let caliptra_mmio = dev.map_mapping(CALIPTRA_MAPPING).map_err(fmt_uio_error)? as *mut u32;
        let i3c_mmio = dev.map_mapping(I3C_MAPPING).map_err(fmt_uio_error)? as *mut u32;
        let recovery_images = Arc::new(Mutex::new(vec![]));
        let i3c_controller_ptr = dev.map_mapping(3).map_err(fmt_uio_error)? as *mut u32;
        let mut i3c_controller = xi3c::Controller::new(i3c_controller_ptr);

        let xi3c_config = xi3c::Config {
            device_id: 0,
            base_address: i3c_controller_ptr,
            input_clock_hz: 199_999_000,
            rw_fifo_depth: 16,
            wr_threshold: 12,
            device_count: 1,
            ibi_capable: true,
            hj_capable: false,
            entdaa_enable: true,
            known_static_addrs: vec![],
        };

        i3c_controller.set_s_clk(199_999_000, 12_500_000, 1);
        i3c_controller
            .cfg_initialize(&xi3c_config, i3c_controller_ptr as usize)
            .unwrap();
        i3c_controller.bus_init().unwrap();

        let realtime_thread_exit_flag = Arc::new(AtomicBool::new(false));
        let realtime_thread_exit_flag2 = realtime_thread_exit_flag.clone();

        let desired_trng_mode = TrngMode::resolve(params.trng_mode);
        let realtime_thread = match desired_trng_mode {
            TrngMode::Internal => {
                let realtime_thread_wrapper = SendPtr(wrapper);
                let realtime_i3c_wrapper = SendPtr(i3c_mmio);
                let images = recovery_images.clone();
                Some(thread::spawn(move || {
                    let wrapper = realtime_thread_wrapper;
                    let i3c_wrapper = realtime_i3c_wrapper;
                    Self::realtime_thread_itrng_fn(
                        wrapper.0,
                        i3c_wrapper.0,
                        images,
                        realtime_thread_exit_flag2,
                        params.itrng_nibbles,
                    )
                }))
            }
            TrngMode::External => {
                let realtime_thread_mmio = SendPtr(caliptra_mmio);
                let realtime_i3c_wrapper = SendPtr(i3c_mmio);
                let images = recovery_images.clone();
                Some(thread::spawn(move || {
                    let mmio = realtime_thread_mmio;
                    let i3c_wrapper = realtime_i3c_wrapper;
                    Self::realtime_thread_etrng_fn(
                        mmio.0,
                        i3c_wrapper.0,
                        images,
                        realtime_thread_exit_flag2,
                        params.etrng_responses,
                    )
                }))
            }
        };

        let mut m = Self {
            dev,
            wrapper,
            mmio: caliptra_mmio,
            output,

            realtime_thread,
            realtime_thread_exit_flag,

            trng_mode: desired_trng_mode,

            openocd: None,
            i3c_mmio,
            recovery_images,
            i3c_controller,
        };
        writeln!(m.output().logger(), "breadcrumb {}", line!())?;
        // Check if the FPGA image is valid
        if 0x52545043 == unsafe { wrapper.offset(FPGA_WRAPPER_MAGIC_OFFSET).read_volatile() } {
            writeln!(m.output().logger(), "breadcrumb {}", line!())?;
            let fpga_version = unsafe {
                m.wrapper
                    .offset(FPGA_WRAPPER_VERSION_OFFSET)
                    .read_volatile()
            };
            writeln!(m.output().logger(), "FPGA built from {fpga_version:x}")?;
        } else {
            panic!("FPGA image invalid");
        }
        writeln!(m.output().logger(), "breadcrumb {}", line!())?;

        // Set pwrgood and rst_b to 0 to boot from scratch
        m.set_cptra_pwrgood(false);
        m.set_cptra_rst_b(false);

        writeln!(m.output().logger(), "new_unbooted")?;

        // Set Security State signal wires
        m.set_security_state(params.security_state);

        // Set initial PAUSER
        m.set_axi_user(DEFAULT_AXI_PAUSER);

        // Set divisor for ITRNG throttling
        m.set_itrng_divider(ITRNG_DIVISOR);

        // Set deobfuscation key
        for i in 0..8 {
            unsafe {
                m.wrapper
                    .offset(FPGA_WRAPPER_DEOBF_KEY_OFFSET + i)
                    .write_volatile(params.cptra_obf_key[i as usize])
            };
        }

        // Write ROM images over backdoors
        let mut rom_driver = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/caliptra-rom-backdoor")
            .unwrap();
        rom_driver.write_all(params.caliptra_rom)?;
        rom_driver.sync_all()?;

        let mut mcu_rom_driver = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/caliptra-mcu-rom-backdoor") // TODO: get correct ROM backdoor name
            .unwrap();
        mcu_rom_driver.write_all(params.mcu_rom)?;
        mcu_rom_driver.sync_all()?;

        // Sometimes there's garbage in here; clean it out
        m.clear_log_fifo();

        // Bring Caliptra out of reset and wait for ready_for_fuses
        m.set_cptra_pwrgood(true);
        m.set_cptra_rst_b(true);
        while !m.is_ready_for_fuses() {}
        writeln!(m.output().logger(), "ready_for_fuses is high")?;

        // Checking the FPGA model needs to happen after Caliptra's registers are available.
        let fpga_trng_mode = if m.soc_ifc().cptra_hw_config().read().i_trng_en() {
            TrngMode::Internal
        } else {
            TrngMode::External
        };
        if desired_trng_mode != fpga_trng_mode {
            return Err(format!(
                "HwModel InitParams asked for trng_mode={desired_trng_mode:?}, \
                    but the FPGA was compiled with trng_mode={fpga_trng_mode:?}; \
                    try matching the test and the FPGA image."
            )
            .into());
        }

        Ok(m)
    }

    fn type_name(&self) -> &'static str {
        "ModelFpgaRealtime"
    }

    fn trng_mode(&self) -> TrngMode {
        self.trng_mode
    }

    fn output(&mut self) -> &mut crate::Output {
        let cycle = unsafe {
            self.wrapper
                .offset(FPGA_WRAPPER_CYCLE_COUNT_OFFSET)
                .read_volatile()
        };
        self.output.sink().set_now(u64::from(cycle));
        &mut self.output
    }

    fn warm_reset(&mut self) {
        // Toggle reset pin
        self.set_cptra_rst_b(false);
        self.set_cptra_rst_b(true);
        // Wait for ready_for_fuses
        while !self.is_ready_for_fuses() {}
    }

    fn cold_reset(&mut self) {
        // Toggle reset and pwrgood
        self.set_cptra_rst_b(false);
        self.set_cptra_pwrgood(false);
        self.set_cptra_pwrgood(true);
        self.set_cptra_rst_b(true);
        self.i3c_controller.reset();
        self.i3c_controller.reset_fifos();
        // Wait for ready_for_fuses
        while !self.is_ready_for_fuses() {}
    }

    fn ready_for_fw(&self) -> bool {
        unsafe {
            GpioInput(
                self.wrapper
                    .offset(FPGA_WRAPPER_STATUS_OFFSET)
                    .read_volatile(),
            )
            .ready_for_fw()
                != 0
        }
    }

    fn tracing_hint(&mut self, _enable: bool) {
        // Do nothing; we don't support tracing yet
    }

    fn set_axi_user(&mut self, pauser: u32) {
        unsafe {
            self.wrapper
                .offset(FPGA_WRAPPER_PAUSER_OFFSET)
                .write_volatile(pauser);
        }
    }

    fn put_firmware_in_rri(
        &mut self,
        firmware: &[u8],
        soc_manifest: Option<&[u8]>,
        mcu_firmware: Option<&[u8]>,
    ) -> Result<(), ModelError> {
        let mut images = self.recovery_images.lock().unwrap();
        images.push(firmware.to_vec());
        if let Some(soc_manifest) = soc_manifest {
            images.push(soc_manifest.to_vec());
        }
        if let Some(mcu_firmware) = mcu_firmware {
            images.push(mcu_firmware.to_vec());
        }
        // TODO: need to start recovery sequence in registers
        Ok(())
    }

    fn events_from_caliptra(&mut self) -> Vec<Event> {
        todo!()
    }

    fn events_to_caliptra(&mut self) -> mpsc::Sender<Event> {
        todo!()
    }
}

impl ModelFpgaRealtime {
    pub fn launch_openocd(&mut self) -> Result<(), OpenOcdError> {
        let _ = Command::new("sudo")
            .arg("pkill")
            .arg("openocd")
            .spawn()
            .unwrap()
            .wait();

        let mut openocd = Command::new("sudo")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .arg("openocd")
            .arg("--command")
            .arg(include_str!("../../fpga/openocd_caliptra.txt"))
            .spawn()
            .unwrap();

        let mut child_err = BufReader::new(openocd.stderr.as_mut().unwrap());
        let mut output = String::new();
        loop {
            if 0 == child_err.read_line(&mut output).unwrap() {
                println!("openocd log returned EOF. Log: {output}");
                return Err(OpenOcdError::Closed);
            }
            if output.contains("OpenOCD setup finished") {
                break;
            }
        }
        if !output.contains("Open On-Chip Debugger 0.12.0") {
            return Err(OpenOcdError::WrongVersion);
        }
        if output.contains("Caliptra not accessible") {
            return Err(OpenOcdError::CaliptraNotAccessible);
        }
        if output.contains("Core not accessible") {
            return Err(OpenOcdError::VeerNotAccessible);
        }
        self.openocd = Some(openocd);
        Ok(())
    }
}

impl Drop for ModelFpgaRealtime {
    fn drop(&mut self) {
        // Ask the realtime thread to exit and wait for it to finish
        // SAFETY: The thread is using the UIO mappings below, so it must be
        // dead before we unmap.
        // TODO: Find a safer abstraction for UIO mappings.
        self.realtime_thread_exit_flag
            .store(true, Ordering::Relaxed);
        self.realtime_thread.take().unwrap().join().unwrap();

        // Unmap UIO memory space so that the file lock is released
        self.unmap_mapping(self.wrapper, FPGA_WRAPPER_MAPPING);
        self.unmap_mapping(self.mmio, CALIPTRA_MAPPING);

        // Close openocd
        if let Some(ref mut cmd) = &mut self.openocd {
            cmd.kill().expect("Failed to close openocd")
        }
    }
}

pub struct FpgaRealtimeBus<'a> {
    mmio: *mut u32,
    phantom: PhantomData<&'a mut ()>,
}
impl<'a> FpgaRealtimeBus<'a> {
    fn ptr_for_addr(&mut self, addr: RvAddr) -> Option<*mut u32> {
        let addr = addr as usize;
        unsafe {
            match addr {
                0x3002_0000..=0x3003_ffff => Some(self.mmio.add((addr - 0x3002_0000) / 4)),
                _ => None,
            }
        }
    }
}
impl<'a> Bus for FpgaRealtimeBus<'a> {
    fn read(&mut self, _size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        if let Some(ptr) = self.ptr_for_addr(addr) {
            Ok(unsafe { ptr.read_volatile() })
        } else {
            println!("Error LoadAccessFault");
            Err(BusError::LoadAccessFault)
        }
    }

    fn write(
        &mut self,
        _size: RvSize,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), caliptra_emu_bus::BusError> {
        if let Some(ptr) = self.ptr_for_addr(addr) {
            // TODO: support 16-bit and 8-bit writes
            unsafe { ptr.write_volatile(val) };
            Ok(())
        } else {
            Err(BusError::StoreAccessFault)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::model_fpga_realtime::{FifoData, FPGA_WRAPPER_CONTROL_OFFSET, FPGA_WRAPPER_STATUS_OFFSET, FPGA_WRAPPER_CYCLE_COUNT_OFFSET, FPGA_WRAPPER_MCI_GENERIC_OUTPUT_WIRES_0_OFFSET, FPGA_WRAPPER_MCI_GENERIC_OUTPUT_WIRES_1_OFFSET, FPGA_WRAPPER_MCU_RESET_VECTOR_OFFSET, FPGA_WRAPPER_PAUSER_OFFSET, FPGA_WRAPPER_VERSION_OFFSET};
    use crate::xi3c::{self, Ccc};
    use bitfield::bitfield;
    use caliptra_emu_bus::{Device, Event, EventData, RecoveryCommandCode};
    use emulator_bmc::Bmc;
    use registers_generated::i3c::bits::HcControl::{BusEnable, ModeSelector};
    use registers_generated::i3c::bits::{
        DeviceStatus0, IndirectFifoStatus0, ProtCap2, ProtCap3, QueueThldCtrl, RecoveryStatus,
        RingHeadersSectionOffset, StbyCrCapabilities, StbyCrControl, StbyCrDeviceAddr,
        StbyCrVirtDeviceAddr, TtiQueueThldCtrl,
    };
    use registers_generated::i3c::regs::I3c;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};
    use std::thread::{self, sleep};
    use std::time::Duration;
    use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
    use uio::UioDevice;
    use zerocopy::{FromBytes, IntoBytes};

    bitfield! {
        #[derive(Clone, FromBytes, IntoBytes)]
        pub struct RxDescriptor(u32);
        impl Debug;
        pub u16, data_length, set_data_length: 15, 0;
    }

    fn configure_i3c_target(regs: &I3c, addr: u8, recovery_enabled: bool) {
        println!("I3C HCI version: {:x}", regs.i3c_base_hci_version.get());

        println!("Set TTI RESET_CONTROL");
        regs.tti_tti_reset_control.set(0x3f);
        println!("TTI RESET_CONTROL: {:x}", regs.tti_tti_reset_control.get());

        // Evaluate RING_HEADERS_SECTION_OFFSET, the SECTION_OFFSET should read 0x0 as this controller doesn’t support the DMA mode
        println!("Check ring headers section offset");
        let rhso = regs
            .i3c_base_ring_headers_section_offset
            .read(RingHeadersSectionOffset::SectionOffset);
        if rhso != 0 {
            panic!("RING_HEADERS_SECTION_OFFSET is not 0");
        }

        println!("TTI QUEUE_SIZE: {:x}", regs.tti_tti_queue_size.get());

        // initialize timing registers
        println!("Initialize timing registers");

        // AXI clock is ~200 MHz, I3C clock is 12.5 MHz
        // values of all of these set to 0-5 seem to work for receiving data correctly
        // 6-7 gets corrupted data but will ACK
        // 8+ will fail to ACK
        regs.soc_mgmt_if_t_r_reg.set(1); // rise time of both SDA and SCL in clock units
        regs.soc_mgmt_if_t_f_reg.set(1); // rise time of both SDA and SCL in clock units

        // if this is set to 6+ then ACKs start failing
        regs.soc_mgmt_if_t_hd_dat_reg.set(1); // data hold time in clock units
        regs.soc_mgmt_if_t_su_dat_reg.set(1); // data setup time in clock units

        regs.soc_mgmt_if_t_high_reg.set(1); // High period of the SCL in clock units
        regs.soc_mgmt_if_t_low_reg.set(1); // Low period of the SCL in clock units
        regs.soc_mgmt_if_t_hd_sta_reg.set(1); // Hold time for (repeated) START in clock units
        regs.soc_mgmt_if_t_su_sta_reg.set(1); // Setup time for repeated START in clock units
        regs.soc_mgmt_if_t_su_sto_reg.set(1); // Setup time for STOP in clock units

        println!(
            "Timing register t_r: {}, t_f: {}, t_hd_dat: {}, t_su_dat: {}, t_high: {}, t_low: {}, t_hd_sta: {}, t_su_sta: {}, t_su_sto: {}",
            regs.soc_mgmt_if_t_r_reg.get(),
            regs.soc_mgmt_if_t_f_reg.get(),
            regs.soc_mgmt_if_t_hd_dat_reg.get(),
            regs.soc_mgmt_if_t_su_dat_reg.get(),
            regs.soc_mgmt_if_t_high_reg.get(),
            regs.soc_mgmt_if_t_low_reg.get(),
            regs.soc_mgmt_if_t_hd_sta_reg.get(),
            regs.soc_mgmt_if_t_su_sta_reg.get(),
            regs.soc_mgmt_if_t_su_sto_reg.get()
        );

        // Setup the threshold for the HCI queues (in the internal/private software data structures):
        println!("Setup HCI queue thresholds");
        regs.piocontrol_queue_thld_ctrl.modify(
            QueueThldCtrl::CmdEmptyBufThld.val(0)
                + QueueThldCtrl::RespBufThld.val(1)
                + QueueThldCtrl::IbiStatusThld.val(1),
        );

        println!("Enable the target transaction interface");
        regs.stdby_ctrl_mode_stby_cr_control.modify(
            StbyCrControl::StbyCrEnableInit.val(2) // enable the standby controller
                + StbyCrControl::TargetXactEnable::SET // enable Target Transaction Interface
                + StbyCrControl::DaaEntdaaEnable::SET // enable ENTDAA dynamic address assignment
                + StbyCrControl::DaaSetdasaEnable::SET // enable SETDASA dynamic address assignment
                + StbyCrControl::BastCccIbiRing.val(0) // Set the IBI to use ring buffer 0
                + StbyCrControl::PrimeAcceptGetacccr::CLEAR // // don't auto-accept primary controller role
                + StbyCrControl::AcrFsmOpSelect::CLEAR, // don't become the active controller and set us as not the bus owner
        );

        println!(
            "STBY_CR_CONTROL: {:x}",
            regs.stdby_ctrl_mode_stby_cr_control.get()
        );

        regs.stdby_ctrl_mode_stby_cr_capabilities
            .write(StbyCrCapabilities::TargetXactSupport::SET);
        println!(
            "STBY_CR_CAPABILITIES: {:x}",
            regs.stdby_ctrl_mode_stby_cr_capabilities.get()
        );
        if !regs
            .stdby_ctrl_mode_stby_cr_capabilities
            .is_set(StbyCrCapabilities::TargetXactSupport)
        {
            panic!("I3C target transaction support is not enabled");
        }

        // program a static address
        println!("Setting static address to {:x}", addr);
        regs.stdby_ctrl_mode_stby_cr_device_addr.write(
            StbyCrDeviceAddr::StaticAddrValid::SET + StbyCrDeviceAddr::StaticAddr.val(addr as u32),
        );
        if recovery_enabled {
            println!("Setting virtual device static address to {:x}", addr + 1);
            regs.stdby_ctrl_mode_stby_cr_virt_device_addr.write(
                StbyCrVirtDeviceAddr::VirtStaticAddrValid::SET
                    + StbyCrVirtDeviceAddr::VirtStaticAddr.val((addr + 1) as u32),
            );
        }

        println!("Set TTI queue thresholds");
        // set TTI queue thresholds
        regs.tti_tti_queue_thld_ctrl.modify(
            TtiQueueThldCtrl::IbiThld.val(1)
                + TtiQueueThldCtrl::RxDescThld.val(1)
                + TtiQueueThldCtrl::TxDescThld.val(1),
        );
        println!(
            "TTI queue thresholds: {:x}",
            regs.tti_tti_queue_thld_ctrl.get()
        );

        println!(
            "TTI data buffer thresholds ctrl: {:x}",
            regs.tti_tti_data_buffer_thld_ctrl.get()
        );

        println!("Enable PHY to the bus");
        // enable the PHY connection to the bus
        regs.i3c_base_hc_control
            .modify(ModeSelector::SET + BusEnable::CLEAR); // clear is enabled, set is suspended

        println!("Enabling interrupts");
        // regs.tti_interrupt_enable.modify(
        //     InterruptEnable::IbiThldStatEn::SET
        //         + InterruptEnable::RxDescThldStatEn::SET
        //         + InterruptEnable::TxDescThldStatEn::SET
        //         + InterruptEnable::RxDataThldStatEn::SET
        //         + InterruptEnable::TxDataThldStatEn::SET,
        // );
        regs.tti_interrupt_enable.set(0xffff_ffff);
        println!(
            "I3C target interrupt enable {:x}",
            regs.tti_interrupt_enable.get()
        );

        println!(
            "I3C target status {:x}, interrupt status {:x}",
            regs.tti_status.get(),
            regs.tti_interrupt_status.get()
        );

        if recovery_enabled {
            println!("Enabling recovery interface");
            regs.sec_fw_recovery_if_prot_cap_2.write(
                ProtCap2::RecProtVersion.val(0x101)
                    + ProtCap2::AgentCaps.val(
                        (1 << 0) | // device id
                (1 << 4) | // device status
                (1 << 5) | // indirect ctrl
                (1 << 7), // push c-image support
                    ),
            );
            regs.sec_fw_recovery_if_prot_cap_3.write(
                ProtCap3::NumOfCmsRegions.val(1) + ProtCap3::MaxRespTime.val(20), // 1.048576 second maximum response time
            );
            regs.sec_fw_recovery_if_device_status_0
                .write(DeviceStatus0::DevStatus.val(0x3)); // ready to accept recovery image
        }

        println!(
            "I3C recovery prot_cap 2 and 3: {:08x} {:08x}",
            regs.sec_fw_recovery_if_prot_cap_2.get(),
            regs.sec_fw_recovery_if_prot_cap_3.get(),
        );
        println!(
            "I3C recovery device status: {:x}",
            regs.sec_fw_recovery_if_device_status_0
                .read(DeviceStatus0::DevStatus)
        );
    }

    fn empty_rx_queue(i3c: &I3c) {
        while i3c.tti_interrupt_status.get() & 0x801 != 0 {
            let packet = read_packet(i3c);
            println!("Emptying I3C RX queue: {:x?}", packet);
        }
    }

    fn read_packet(i3c: &I3c) -> Vec<u8> {
        assert!(
            i3c.tti_interrupt_status.get() & 0x801 != 0,
            "Expected I3C target to have an RX descriptor waiting"
        );
        let desc0 = RxDescriptor(i3c.tti_rx_desc_queue_port.get());
        println!("Read a descriptor: {:08x}", desc0.0,);
        let mut len = desc0.data_length() as usize;
        let mut data = vec![];
        while len > 0 {
            let dword = i3c.tti_rx_data_port.get();
            let slice = dword.to_le_bytes();
            let valid = len.min(4);
            data.extend(&slice[0..valid]);
            len -= valid;
        }
        data
    }

    fn send_packet(i3c: &I3c, mut data: &[u8]) {
        let mut desc = RxDescriptor(0);
        desc.set_data_length(data.len() as u16);
        i3c.tti_tx_desc_queue_port.set(desc.0);
        while data.len() > 0 {
            let next = &data[..4.min(data.len())];
            let mut word = [0, 0, 0, 0];
            word[..next.len()].copy_from_slice(next);
            let word = u32::from_le_bytes(word);
            i3c.tti_tx_data_port.set(word);
            data = &data[next.len()..];
        }
    }

    // tests writes
    #[test]
    fn test_xi3c() {
        const AXI_CLOCK_HZ: u32 = 199_999_000;
        const I3C_CLOCK_HZ: u32 = 12_500_000;
        let dev0 = UioDevice::blocking_new(0).unwrap();
        let dev1 = UioDevice::blocking_new(1).unwrap();
        let wrapper = dev0.map_mapping(0).unwrap() as *mut u32;
        let i3c_target_raw = dev1.map_mapping(2).unwrap();
        let i3c_target: &I3c = unsafe { &*(i3c_target_raw as *const I3c) };
        const I3C_TARGET_ADDR: u8 = 0x5a;
        let repeat = 1; // repeat messages this many times when sending

        let empty_wait_time = Some(Duration::from_millis(1)); // sleep this much before emptying the rx queue
        let use_dynamic_addr = false;

        let fpga_version = unsafe { core::ptr::read_volatile(wrapper.offset(FPGA_WRAPPER_VERSION_OFFSET)) };
        println!("FPGA version: {:08x}", fpga_version);

        println!("Bring SS out of reset");
        unsafe {
            core::ptr::write_volatile(wrapper.offset(FPGA_WRAPPER_CONTROL_OFFSET), 0);
            core::ptr::write_volatile(wrapper.offset(FPGA_WRAPPER_CONTROL_OFFSET), 0x3);
        }
        println!("Configuring I3C target");
        configure_i3c_target(i3c_target, I3C_TARGET_ADDR, false);

        let xi3c_controller_ptr = dev0.map_mapping(3).unwrap() as *mut u32;
        let xi3c: &xi3c::XI3c = unsafe { &*(xi3c_controller_ptr as *const xi3c::XI3c) };
        println!("XI3C HW version = {:x}", xi3c.version.get());

        let mut i3c_controller = xi3c::Controller::new(xi3c_controller_ptr);
        let xi3c_config = xi3c::Config {
            device_id: 0,
            base_address: xi3c_controller_ptr,
            input_clock_hz: AXI_CLOCK_HZ,
            rw_fifo_depth: 16,
            wr_threshold: 12,
            device_count: 1,
            ibi_capable: use_dynamic_addr, // this needs to be true for dynamic addressing
            hj_capable: false,
            entdaa_enable: false,
            known_static_addrs: vec![I3C_TARGET_ADDR],
        };

        i3c_controller.set_s_clk(AXI_CLOCK_HZ, I3C_CLOCK_HZ, 1);
        i3c_controller
            .cfg_initialize(&xi3c_config, xi3c_controller_ptr as usize)
            .unwrap();
        println!("I3C controller timing registers:");
        println!(
            "  od scl high: {}",
            i3c_controller.regs().od_scl_high_time.get()
        );
        println!(
            "  od scl low: {}",
            i3c_controller.regs().od_scl_low_time.get()
        );
        println!("  scl high: {}", i3c_controller.regs().scl_high_time.get());
        println!("  scl low: {}", i3c_controller.regs().scl_low_time.get());
        println!("  sda hold: {}", i3c_controller.regs().sda_hold_time.get());
        println!("  tsu start: {}", i3c_controller.regs().tsu_start.get());
        println!("  tsu stop: {}", i3c_controller.regs().tsu_stop.get());
        println!("  bus free time: {}", i3c_controller.regs().bus_idle.get());
        println!("  thld start: {}", i3c_controller.regs().thd_start.get());

        // check I3C target address
        let mut target_addr = I3C_TARGET_ADDR;
        if i3c_target
            .stdby_ctrl_mode_stby_cr_device_addr
            .read(StbyCrDeviceAddr::DynamicAddrValid)
            == 1
        {
            let addr = i3c_target
                .stdby_ctrl_mode_stby_cr_device_addr
                .read(StbyCrDeviceAddr::DynamicAddr);
            println!("I3C target dynamic address: {:x}", addr,);
            if use_dynamic_addr {
                target_addr = addr as u8;
            }
        }
        if i3c_target
            .stdby_ctrl_mode_stby_cr_device_addr
            .read(StbyCrDeviceAddr::StaticAddrValid)
            == 1
        {
            println!(
                "I3C target static address: {:x}",
                i3c_target
                    .stdby_ctrl_mode_stby_cr_device_addr
                    .read(StbyCrDeviceAddr::StaticAddr) as u8,
            );
        }
        println!("Using {:x} as target address", target_addr);

        const I3C_DATALEN: u16 = 50;
        let max_len = I3C_DATALEN.to_be_bytes();

        // sequence from xi3c_polled_example.c
        let mut cmd = xi3c::Command {
            cmd_type: 1,
            no_repeated_start: 1,
            ..Default::default()
        };
        if !use_dynamic_addr {
            const XI3C_CCC_BRDCAST_SETAASA: u8 = 0x29;
            println!("Broadcast CCC SETAASA");
            let result =
                i3c_controller.send_transfer_cmd(&mut cmd, Ccc::Byte(XI3C_CCC_BRDCAST_SETAASA));
            assert!(result.is_ok(), "Failed to ack broadcast CCC SETAASA");
            println!("Acknowledge received");
        }

        cmd.no_repeated_start = 1;
        cmd.tid = 0;
        cmd.pec = 0;
        cmd.rw = 0;
        cmd.cmd_type = 1;
        const XI3C_CCC_SETMWL: u8 = 0x9;
        println!("Broadcast CCC SETMWL");
        assert!(
            i3c_controller
                .send_transfer_cmd(
                    &mut cmd,
                    Ccc::Data(vec![XI3C_CCC_SETMWL, 0, I3C_DATALEN as u8])
                )
                .is_ok(),
            "Failed to ack broadcast CCC SETMWL message"
        );
        println!("Acknowledge received");

        for _ in 0..repeat {
            cmd.target_addr = target_addr;
            cmd.no_repeated_start = 1;
            cmd.tid = 0;
            cmd.pec = 0;
            cmd.cmd_type = 1; // SDR mode
            println!("Sending 2-byte message to target");
            assert!(
                i3c_controller
                    .master_send_polled(&mut cmd, &max_len, 2)
                    .is_ok(),
                "Failed to ack first message sent to the target"
            );
            println!("Acknowledge received");
        }

        println!(
            "I3C target status {:x}, interrupt status {:x}",
            i3c_target.tti_status.get(),
            i3c_target.tti_interrupt_status.get()
        );

        // let's try reading the message now
        let data = read_packet(i3c_target);
        println!("Read bytes: {:x?}", data);

        empty_wait_time.map(sleep);
        empty_rx_queue(i3c_target);

        assert_eq!(
            &I3C_DATALEN.to_be_bytes()[..],
            &data,
            "Data read from I3C target did not match what controller sent"
        );

        println!(
            "I3C target status {:x}, interrupt status {:x}",
            i3c_target.tti_status.get(),
            i3c_target.tti_interrupt_status.get()
        );

        /*
         * Set Max read length
         */
        cmd.no_repeated_start = 1;
        cmd.tid = 0;
        cmd.pec = 0;
        cmd.rw = 0;
        cmd.cmd_type = 1;
        const XI3C_CCC_SETMRL: u8 = 0xa;
        println!("Broadcast CCC SETMRL");
        assert!(
            i3c_controller
                .send_transfer_cmd(
                    &mut cmd,
                    Ccc::Data(vec![XI3C_CCC_SETMRL, 0, I3C_DATALEN as u8])
                )
                .is_ok(),
            "Failed to ack broadcast CCC SETMRL"
        );

        for _ in 0..repeat {
            cmd.target_addr = target_addr;
            cmd.no_repeated_start = 1;
            cmd.tid = 0;
            cmd.pec = 0;
            cmd.cmd_type = 1;
            println!("Sending second message to target");
            assert!(
                i3c_controller
                    .master_send_polled(&mut cmd, &max_len, 2)
                    .is_ok(),
                "Failed to ack second message to target"
            );
            println!("Acknowledge received");
        }

        let data = read_packet(i3c_target);
        println!("Read bytes: {:x?}", data);

        assert_eq!(
            &I3C_DATALEN.to_be_bytes()[..],
            &data,
            "Data read from I3C target did not match what controller sent"
        );

        empty_wait_time.map(sleep);
        empty_rx_queue(i3c_target);

        // println!(
        //     "I3C target status {:x}, interrupt status {:x}",
        //     i3c_target.tti_status.get(),
        //     i3c_target.tti_interrupt_status.get()
        // );

        // // Fill data to buffer
        // for i in 0..I3C_DATALEN as usize {
        //     tx_data[i] = i as u8; // Test data
        // }

        // // Send
        // for _ in 0..repeat {
        //     cmd.target_addr = target_addr;
        //     cmd.no_repeated_start = 1;
        //     cmd.tid = 0;
        //     cmd.pec = 0;
        //     cmd.cmd_type = 1;
        //     println!("Sending third message to target");
        //     assert!(
        //         i3c_controller
        //             .master_send_polled(&mut cmd, &tx_data, I3C_DATALEN)
        //             .is_ok(),
        //         "Failed to ack third message sent to target"
        //     );
        //     println!("Acknowledge received");
        // }

        // let data = read_packet(i3c_target);
        // println!("Read bytes: {:x?}", data);

        // assert_eq!(
        //     &tx_data, &*data,
        //     "Data read from I3C target did not match what controller sent"
        // );

        // empty_wait_time.map(sleep);
        // empty_rx_queue(i3c_target);

        // println!(
        //     "I3C target status {:x}, interrupt status {:x}",
        //     i3c_target.tti_status.get(),
        //     i3c_target.tti_interrupt_status.get()
        // );

        // let mut s = String::new();
        // println!("Waiting on user to hit enter");
        // std::io::stdin().read_line(&mut s).unwrap();
    }

    #[test]
    fn test_xi3c_write() {
        const AXI_CLOCK_HZ: u32 = 199_999_000;
        const I3C_CLOCK_HZ: u32 = 12_500_000;
        let dev0 = UioDevice::blocking_new(0).unwrap();
        let dev1 = UioDevice::blocking_new(1).unwrap();
        let wrapper = dev0.map_mapping(0).unwrap() as *mut u32;
        let i3c_target_raw = dev1.map_mapping(2).unwrap();
        let i3c_target: &I3c = unsafe { &*(i3c_target_raw as *const I3c) };
        const I3C_TARGET_ADDR: u8 = 0x5a;
        let use_dynamic_addr = false;

        let fpga_version = unsafe { core::ptr::read_volatile(wrapper.offset(FPGA_WRAPPER_VERSION_OFFSET)) };
        println!("FPGA version: {:08x}", fpga_version);

        println!("Bring SS out of reset");
        unsafe {
            core::ptr::write_volatile(wrapper.offset(FPGA_WRAPPER_CONTROL_OFFSET), 0);
            core::ptr::write_volatile(wrapper.offset(FPGA_WRAPPER_CONTROL_OFFSET), 0x3);
        }
        println!("Configuring I3C target");
        configure_i3c_target(i3c_target, I3C_TARGET_ADDR, false);

        let xi3c_controller_ptr = dev0.map_mapping(3).unwrap() as *mut u32;
        let xi3c: &xi3c::XI3c = unsafe { &*(xi3c_controller_ptr as *const xi3c::XI3c) };
        println!("XI3C HW version = {:x}", xi3c.version.get());

        let mut i3c_controller = xi3c::Controller::new(xi3c_controller_ptr);
        let xi3c_config = xi3c::Config {
            device_id: 0,
            base_address: xi3c_controller_ptr,
            input_clock_hz: AXI_CLOCK_HZ,
            rw_fifo_depth: 16,
            wr_threshold: 12,
            device_count: 1,
            ibi_capable: use_dynamic_addr, // this needs to be true for dynamic addressing
            hj_capable: false,
            entdaa_enable: false,
            known_static_addrs: vec![I3C_TARGET_ADDR],
        };

        i3c_controller.set_s_clk(AXI_CLOCK_HZ, I3C_CLOCK_HZ, 1);
        i3c_controller
            .cfg_initialize(&xi3c_config, xi3c_controller_ptr as usize)
            .unwrap();
        println!("I3C controller timing registers:");
        println!(
            "  od scl high: {}",
            i3c_controller.regs().od_scl_high_time.get()
        );
        println!(
            "  od scl low: {}",
            i3c_controller.regs().od_scl_low_time.get()
        );
        println!("  scl high: {}", i3c_controller.regs().scl_high_time.get());
        println!("  scl low: {}", i3c_controller.regs().scl_low_time.get());
        println!("  sda hold: {}", i3c_controller.regs().sda_hold_time.get());
        println!("  tsu start: {}", i3c_controller.regs().tsu_start.get());
        println!("  tsu stop: {}", i3c_controller.regs().tsu_stop.get());
        println!("  bus free time: {}", i3c_controller.regs().bus_idle.get());
        println!("  thld start: {}", i3c_controller.regs().thd_start.get());

        // check I3C target address
        let mut target_addr = I3C_TARGET_ADDR;
        if i3c_target
            .stdby_ctrl_mode_stby_cr_device_addr
            .read(StbyCrDeviceAddr::DynamicAddrValid)
            == 1
        {
            let addr = i3c_target
                .stdby_ctrl_mode_stby_cr_device_addr
                .read(StbyCrDeviceAddr::DynamicAddr);
            println!("I3C target dynamic address: {:x}", addr,);
            if use_dynamic_addr {
                target_addr = addr as u8;
            }
        }
        if i3c_target
            .stdby_ctrl_mode_stby_cr_device_addr
            .read(StbyCrDeviceAddr::StaticAddrValid)
            == 1
        {
            println!(
                "I3C target static address: {:x}",
                i3c_target
                    .stdby_ctrl_mode_stby_cr_device_addr
                    .read(StbyCrDeviceAddr::StaticAddr) as u8,
            );
        }
        println!("Using {:x} as target address", target_addr);

        const I3C_DATALEN: u16 = 50;
        let mut tx_data = [0u8; I3C_DATALEN as usize];

        let mut cmd = xi3c::Command {
            cmd_type: 1,
            no_repeated_start: 1,
            ..Default::default()
        };
        if !use_dynamic_addr {
            const XI3C_CCC_BRDCAST_SETAASA: u8 = 0x29;
            println!("Broadcast CCC SETAASA");
            let result =
                i3c_controller.send_transfer_cmd(&mut cmd, Ccc::Byte(XI3C_CCC_BRDCAST_SETAASA));
            assert!(result.is_ok(), "Failed to ack broadcast CCC SETAASA");
            println!("Acknowledge received");
        }

        // Fill data to buffer
        for i in 0..I3C_DATALEN as usize {
            tx_data[i] = i as u8; // Test data
        }

        // let's send a message back
        println!("Writing data back to controller: {:x?}", tx_data);
        send_packet(i3c_target, &tx_data);

        // Recv
        println!("Sending a read request to the target");
        cmd.target_addr = target_addr;
        cmd.no_repeated_start = 1;
        cmd.tid = 0;
        cmd.pec = 0;
        cmd.cmd_type = 1;
        i3c_controller
            .master_recv(&mut cmd, I3C_DATALEN)
            .expect("Failed to start receive from target");

        println!(
            "I3C target status {:x}, interrupt status {:x}",
            i3c_target.tti_status.get(),
            i3c_target.tti_interrupt_status.get()
        );

        // assert!(
        //     i3c_target.tti_interrupt_status.get() & 0x402 != 0,
        //     "Expected TX_DESC interrupt"
        // );

        let rx_data: Vec<u8> = i3c_controller
            .master_recv_finish(None, &cmd, I3C_DATALEN)
            .expect("Failed to finish receiving data from target");

        assert_eq!(tx_data, *rx_data);

        println!(
            "I3C target status {:x}, interrupt status {:x}",
            i3c_target.tti_status.get(),
            i3c_target.tti_interrupt_status.get()
        );
    }

    #[test]
    fn test_recovery_flow() {
        const AXI_CLOCK_HZ: u32 = 199_999_000;
        const I3C_CLOCK_HZ: u32 = 12_500_000;
        let dev0 = UioDevice::blocking_new(0).unwrap();
        let dev1 = UioDevice::blocking_new(1).unwrap();
        let wrapper = dev0.map_mapping(0).unwrap() as *mut u32;
        let i3c_target_raw = dev1.map_mapping(2).unwrap();
        let i3c_target: &I3c = unsafe { &*(i3c_target_raw as *const I3c) };
        const I3C_TARGET_ADDR: u8 = 0x5a;

        let fpga_version = unsafe { core::ptr::read_volatile(wrapper.offset(FPGA_WRAPPER_VERSION_OFFSET)) };
        println!("FPGA version: {:08x}", fpga_version);

        println!("Bring SS out of reset");
        unsafe {
            core::ptr::write_volatile(wrapper.offset(FPGA_WRAPPER_CONTROL_OFFSET), 0);
            core::ptr::write_volatile(wrapper.offset(FPGA_WRAPPER_CONTROL_OFFSET), 0x3);
        }
        println!("Configuring I3C target");
        configure_i3c_target(i3c_target, I3C_TARGET_ADDR, true);

        let mut recovery_target_addr = I3C_TARGET_ADDR;

        let xi3c_controller_ptr = dev0.map_mapping(3).unwrap() as *mut u32;
        let xi3c: &xi3c::XI3c = unsafe { &*(xi3c_controller_ptr as *const xi3c::XI3c) };
        println!("XI3C HW version = {:x}", xi3c.version.get());

        let mut i3c_controller = xi3c::Controller::new(xi3c_controller_ptr);
        let xi3c_config = xi3c::Config {
            device_id: 0,
            base_address: xi3c_controller_ptr,
            input_clock_hz: AXI_CLOCK_HZ,
            rw_fifo_depth: 16,
            wr_threshold: 12,
            device_count: 2,
            ibi_capable: false, // temporarily disable dynamic addresses
            hj_capable: false,
            entdaa_enable: false,
            known_static_addrs: vec![I3C_TARGET_ADDR, I3C_TARGET_ADDR + 1],
        };

        i3c_controller.set_s_clk(AXI_CLOCK_HZ, I3C_CLOCK_HZ, 1);
        i3c_controller
            .cfg_initialize(&xi3c_config, xi3c_controller_ptr as usize)
            .unwrap();
        println!("I3C controller timing registers:");
        println!(
            "  od scl high: {}",
            i3c_controller.regs().od_scl_high_time.get()
        );
        println!(
            "  od scl low: {}",
            i3c_controller.regs().od_scl_low_time.get()
        );
        println!("  scl high: {}", i3c_controller.regs().scl_high_time.get());
        println!("  scl low: {}", i3c_controller.regs().scl_low_time.get());
        println!("  sda hold: {}", i3c_controller.regs().sda_hold_time.get());
        println!("  tsu start: {}", i3c_controller.regs().tsu_start.get());
        println!("  tsu stop: {}", i3c_controller.regs().tsu_stop.get());
        println!("  bus free time: {}", i3c_controller.regs().bus_idle.get());
        println!("  thld start: {}", i3c_controller.regs().thd_start.get());

        // check I3C target address
        if i3c_target
            .stdby_ctrl_mode_stby_cr_device_addr
            .read(StbyCrDeviceAddr::DynamicAddrValid)
            == 1
        {
            let addr = i3c_target
                .stdby_ctrl_mode_stby_cr_device_addr
                .read(StbyCrDeviceAddr::DynamicAddr);
            println!("I3C target dynamic address: {:x}", addr);
            //recovery_target_addr = addr as u8;
        }
        if i3c_target
            .stdby_ctrl_mode_stby_cr_device_addr
            .read(StbyCrDeviceAddr::StaticAddrValid)
            == 1
        {
            println!(
                "I3C target static address: {:x}",
                i3c_target
                    .stdby_ctrl_mode_stby_cr_device_addr
                    .read(StbyCrDeviceAddr::StaticAddr) as u8,
            );
        }

        if i3c_target
            .stdby_ctrl_mode_stby_cr_virt_device_addr
            .read(StbyCrVirtDeviceAddr::VirtStaticAddrValid)
            == 1
        {
            let addr = i3c_target
                .stdby_ctrl_mode_stby_cr_virt_device_addr
                .read(StbyCrVirtDeviceAddr::VirtStaticAddr);
            println!("I3C virtual target static address: {:x}", addr,);
            recovery_target_addr = addr as u8;
        }
        if i3c_target
            .stdby_ctrl_mode_stby_cr_virt_device_addr
            .read(StbyCrVirtDeviceAddr::VirtDynamicAddrValid)
            == 1
        {
            let addr = i3c_target
                .stdby_ctrl_mode_stby_cr_virt_device_addr
                .read(StbyCrVirtDeviceAddr::VirtDynamicAddr);

            println!("I3C virtual target dynamic address: {:x}", addr);
            recovery_target_addr = addr as u8;
        }

        // Run the recovery flow.
        println!(
            "Starting recovery flow for target address {:x}",
            recovery_target_addr
        );

        let (caliptra_cpu_event_sender, from_bmc) = mpsc::channel();
        let (to_bmc, caliptra_cpu_event_recv) = mpsc::channel();

        // these aren't used
        let (mcu_cpu_event_sender, mcu_cpu_event_recv) = mpsc::channel();

        // This is a fake BMC that runs the recovery flow as a series of events for recovery block reads and writes.
        let mut bmc = Bmc::new(
            caliptra_cpu_event_sender,
            caliptra_cpu_event_recv,
            mcu_cpu_event_sender,
            mcu_cpu_event_recv,
        );

        bmc.push_recovery_image(vec![1, 2, 3, 4]);

        let running = Arc::new(AtomicBool::new(true));
        let running_timer = running.clone();

        // stop running the test after a while
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(30));
            running_timer.store(false, Ordering::Relaxed);
        });

        i3c_target.sec_fw_recovery_if_recovery_ctrl.set(0xffffffff);

        let mut set_to_running = false;

        let mut fifo_blocks = vec![];

        while running.load(Ordering::Relaxed) {
            bmc.step();

            if i3c_target.sec_fw_recovery_if_recovery_ctrl.get() & 0xff == 0 {
                // we've been told to start recovery
                // set to awaiting recovery image
                i3c_target
                    .sec_fw_recovery_if_recovery_status
                    .write(RecoveryStatus::DevRecStatus.val(1));
                i3c_target.sec_fw_recovery_if_recovery_ctrl.set(0xffffffff);
            }

            if !fifo_blocks.is_empty() {
                // do the indirect fifo thing
                println!("Starting indirect fifo writes");

                let len = ((fifo_blocks.len() / 4) as u32).to_le_bytes();
                let mut ctrl = vec![0, 1];
                ctrl.extend_from_slice(&len);

                println!(
                    "Device status0: {:x}",
                    i3c_target.sec_fw_recovery_if_device_status_0.get(),
                );
                println!("Writing Indirect fifo ctrl: {:x?}", ctrl);
                recovery_block_write_request(
                    &mut i3c_controller,
                    recovery_target_addr,
                    RecoveryCommandCode::IndirectFifoCtrl,
                    &ctrl,
                );
                // ensure that we read the fifo ctrl
                println!(
                    "Val: {:x} {:x}",
                    i3c_target.sec_fw_recovery_if_indirect_fifo_ctrl_0.get(),
                    i3c_target.sec_fw_recovery_if_indirect_fifo_ctrl_1.get(),
                );

                println!(
                    "Indirect fifo status0: {:x?}",
                    i3c_target.sec_fw_recovery_if_indirect_fifo_status_0.get()
                );
                println!(
                    "Indirect fifo status1: {:x?}",
                    i3c_target.sec_fw_recovery_if_indirect_fifo_status_1.get()
                );
                println!(
                    "Indirect fifo status2: {:x?}",
                    i3c_target.sec_fw_recovery_if_indirect_fifo_status_2.get()
                );
                println!(
                    "Indirect fifo status3: {:x?}",
                    i3c_target.sec_fw_recovery_if_indirect_fifo_status_3.get()
                );
                println!(
                    "Indirect fifo status4: {:x?}",
                    i3c_target.sec_fw_recovery_if_indirect_fifo_status_4.get()
                );

                // now write and read bytes
                for chunk in fifo_blocks.chunks(128) {
                    recovery_block_write_request(
                        &mut i3c_controller,
                        recovery_target_addr,
                        RecoveryCommandCode::IndirectFifoData,
                        chunk,
                    );

                    let mut i = 0;

                    while !i3c_target
                        .sec_fw_recovery_if_indirect_fifo_status_0
                        .is_set(IndirectFifoStatus0::Empty)
                    {
                        let word = i3c_target.sec_fw_recovery_if_indirect_fifo_data.get();
                        println!("chunk {:x?} word {:x}", &chunk[i * 4..i * 4 + 4], word);
                        i += 4;
                    }
                    println!("FIFO empty");
                    if i < chunk.len() {
                        panic!("FIFO empty but we should have more data");
                    }
                }

                println!("Setting recovery status to pending");
                i3c_target
                    .sec_fw_recovery_if_device_status_0
                    .write(DeviceStatus0::DevStatus.val(0x4));
                // recovery success
                i3c_target
                    .sec_fw_recovery_if_recovery_status
                    .write(RecoveryStatus::DevRecStatus.val(3));
                set_to_running = true;
                fifo_blocks.clear();
            }

            if let Ok(event) = from_bmc.try_recv() {
                if !matches!(event.dest, Device::CaliptraCore) {
                    continue;
                }
                match event.event {
                    EventData::RecoveryBlockReadRequest {
                        source_addr,
                        target_addr,
                        command_code,
                    } => {
                        println!("Recovery block read request {:?}", command_code);

                        let payload = recovery_block_read_request(
                            running.clone(),
                            &mut i3c_controller,
                            recovery_target_addr,
                            command_code,
                        );

                        to_bmc
                            .send(Event {
                                src: Device::CaliptraCore,
                                dest: Device::BMC,
                                event: EventData::RecoveryBlockReadResponse {
                                    source_addr: target_addr,
                                    target_addr: source_addr,
                                    command_code,
                                    payload,
                                },
                            })
                            .unwrap();

                        if set_to_running {
                            i3c_target
                                .sec_fw_recovery_if_device_status_0
                                .write(DeviceStatus0::DevStatus.val(0x5));
                            // test passed
                            return;
                        }
                    }
                    EventData::RecoveryBlockReadResponse {
                        source_addr: _,
                        target_addr: _,
                        command_code: _,
                        payload: _,
                    } => todo!(),
                    EventData::RecoveryBlockWrite {
                        source_addr: _,
                        target_addr: _,
                        command_code,
                        payload,
                    } => {
                        println!("Recovery block write request: {:?}", command_code);

                        recovery_block_write_request(
                            &mut i3c_controller,
                            recovery_target_addr,
                            command_code,
                            &payload,
                        );
                    }
                    EventData::RecoveryImageAvailable { image_id: _, image } => {
                        println!("Recovery image available; writing blocks");
                        fifo_blocks = image;
                    }
                    _ => todo!(),
                }
            }
        }
    }

    fn command_code_to_u8(command: RecoveryCommandCode) -> u8 {
        match command {
            RecoveryCommandCode::ProtCap => 34,
            RecoveryCommandCode::DeviceId => 35,
            RecoveryCommandCode::DeviceStatus => 36,
            RecoveryCommandCode::DeviceReset => 37,
            RecoveryCommandCode::RecoveryCtrl => 38,
            RecoveryCommandCode::RecoveryStatus => 39,
            RecoveryCommandCode::HwStatus => 40,
            RecoveryCommandCode::IndirectCtrl => 41,
            RecoveryCommandCode::IndirectStatus => 42,
            RecoveryCommandCode::IndirectData => 43,
            RecoveryCommandCode::Vendor => 44,
            RecoveryCommandCode::IndirectFifoCtrl => 45,
            RecoveryCommandCode::IndirectFifoStatus => 46,
            RecoveryCommandCode::IndirectFifoData => 47,
        }
    }

    fn command_code_to_len(command: RecoveryCommandCode) -> (u16, u16) {
        match command {
            RecoveryCommandCode::ProtCap => (15, 15),
            RecoveryCommandCode::DeviceId => (24, 255),
            RecoveryCommandCode::DeviceStatus => (7, 255),
            RecoveryCommandCode::DeviceReset => (3, 3),
            RecoveryCommandCode::RecoveryCtrl => (3, 3),
            RecoveryCommandCode::RecoveryStatus => (2, 2),
            RecoveryCommandCode::HwStatus => (4, 255),
            RecoveryCommandCode::IndirectCtrl => (6, 6),
            RecoveryCommandCode::IndirectStatus => (6, 6),
            RecoveryCommandCode::IndirectData => (1, 252),
            RecoveryCommandCode::Vendor => (1, 255),
            RecoveryCommandCode::IndirectFifoCtrl => (6, 6),
            RecoveryCommandCode::IndirectFifoStatus => (20, 20),
            RecoveryCommandCode::IndirectFifoData => (1, 4095),
        }
    }

    // send a recovery block read request to the I3C target
    fn recovery_block_read_request(
        running: Arc<AtomicBool>,
        xi3c: &mut xi3c::Controller,
        target_addr: u8,
        command: RecoveryCommandCode,
    ) -> Vec<u8> {
        // per the recovery spec, this maps to a private write and private read

        // First we write the recovery command code for the block we want
        let mut cmd = xi3c::Command {
            cmd_type: 1,
            no_repeated_start: 0, // we want the next command (read) to be Sr
            pec: 1,
            target_addr,
            ..Default::default()
        };

        let recovery_command_code = command_code_to_u8(command);

        println!(
            "Sending write to target: 0x{:x} to start recovery block read (with no termination)",
            recovery_command_code
        );
        assert!(
            xi3c.master_send_polled(&mut cmd, &[recovery_command_code], 1)
                .is_ok(),
            "Failed to ack write message sent to target"
        );
        println!("Acknowledge received");

        // then we send a private read for the minimum length
        let len_range = command_code_to_len(command);
        cmd.target_addr = target_addr;
        cmd.no_repeated_start = 0;
        cmd.tid = 0;
        cmd.pec = 0;
        cmd.cmd_type = 1;
        println!(
            "Starting private read from target for {} bytes with repeated start",
            len_range.0
        );
        xi3c.master_recv(&mut cmd, len_range.0 + 2)
            .expect("Failed to receive ack from target");
        println!("Acknowledge received");

        // read in the length, lsb then msb
        println!(
            "Reading the minimum block length ({}+ bytes expected)",
            len_range.0
        );
        let resp = xi3c
            .master_recv_finish(Some(running.clone()), &cmd, len_range.0 + 2)
            .expect(&format!("Expected to read {}+ bytes", len_range.0 + 2));

        if resp.len() < 2 {
            panic!("Expected to read at least 2 bytes from target for recovery block length");
        }
        println!("Read from target {:02x?}", resp);
        let len = u16::from_le_bytes([resp[0], resp[1]]);
        if len < len_range.0 || len > len_range.1 {
            panic!(
                "Expected to read between {} and {} bytes from target, got {}",
                len_range.0, len_range.1, len
            );
        }
        let len = len as usize;
        let left = len - (resp.len() - 2);
        println!("Expect to read {} bytes from target ({} more)", len, left);
        // read the rest of the bytes
        if left > 0 {
            // TODO: if the length is more than the minimum we need to abort and restart with the correct value
            // because the xi3c controller does not support variable reads.
            todo!()
        }
        println!("Got block read back from target: {:x?}", &resp[2..]);
        resp[2..].to_vec()
    }

    // send a recovery block write request to the I3C target
    fn recovery_block_write_request(
        xi3c: &mut xi3c::Controller,
        target_addr: u8,
        command: RecoveryCommandCode,
        payload: &[u8],
    ) {
        // per the recovery spec, this maps to a private write

        let mut cmd = xi3c::Command {
            cmd_type: 1,
            no_repeated_start: 1,
            pec: 1,
            target_addr,
            ..Default::default()
        };

        let recovery_command_code = command_code_to_u8(command);

        println!(
            "Sending write to target: 0x{:x} + 2 bytes length + {} bytes payload",
            recovery_command_code,
            payload.len(),
        );

        let mut data = vec![recovery_command_code];
        data.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        data.extend_from_slice(&payload);

        assert!(
            xi3c.master_send_polled(&mut cmd, &data, data.len() as u16)
                .is_ok(),
            "Failed to ack write message sent to target"
        );
        println!("Acknowledge received");
    }

    #[test]
    fn test_rom_backdoor() {
        let dev0 = UioDevice::blocking_new(0).unwrap();
        let dev1 = UioDevice::blocking_new(1).unwrap();
        let wrapper = dev0.map_mapping(0).unwrap() as *mut u32;

        println!("Check FPGA version");
        println!("FPGA version: {:x}", unsafe {
            core::ptr::read_volatile(wrapper.offset(FPGA_WRAPPER_VERSION_OFFSET))
        });
        let rom_backdoor = dev1.map_mapping(1).unwrap() as *mut u8;
        let rom_frontdoor = dev1.map_mapping(4).unwrap() as *mut u8;
        println!("Reset");
        unsafe {
            core::ptr::write_volatile(wrapper.offset(FPGA_WRAPPER_CONTROL_OFFSET), 0x0);
        }

        let mut rom_data =
            std::fs::read("../../target/riscv32imc-unknown-none-elf/release/rom.bin").unwrap();
        while rom_data.len() % 8 != 0 {
            rom_data.push(0);
        }
        println!("Writing ROM {}", rom_data.len());

        let rom_slice = unsafe { core::slice::from_raw_parts_mut(rom_backdoor, rom_data.len()) };
        rom_slice.copy_from_slice(&rom_data);

        println!("Written to ROM");

        println!(
            "ROM bytes from backdoor {:x?}",
            rom_slice[0..8].iter().collect::<Vec<_>>()
        );

        let mci = dev1.map_mapping(3).unwrap() as *mut u32;
        unsafe {
            println!("Write reset vector");
            core::ptr::write_volatile(wrapper.offset(FPGA_WRAPPER_MCU_RESET_VECTOR_OFFSET), 0xB002_0000); // address of ROM backdoor in AXI
                                                                              // bring out of reset
            println!("Bring SS out of reset");
            core::ptr::write_volatile(wrapper.offset(FPGA_WRAPPER_CONTROL_OFFSET), 0x3);
            println!("Write PAUSER");
            // write pauser that is used for all accesses (this behavior will need to change in the future)
            core::ptr::write_volatile(wrapper.offset(FPGA_WRAPPER_PAUSER_OFFSET), 0xAAAAAAAA);
            println!("Write SOC user");
            // echo write soc user so that the MCI sees we have elevated permissions
            // core::ptr::write_volatile(wrapper.offset(0x54 / 4), 0xAAAAAAAA);
            println!("Read HW_REG_ID");
            // Read MCI HW_REG_ID, expect 0x1000
            let x = core::ptr::read_volatile(mci.offset(0xC / 4));
            println!("HW_REG_ID: {:x}", x);
        }

        println!("SS is out of reset");

        let rom_frontdoor_slice =
            unsafe { core::slice::from_raw_parts_mut(rom_frontdoor, rom_data.len()) };

        println!(
            "ROM bytes from frontdoor {:x?}",
            rom_frontdoor_slice[0..8].iter().collect::<Vec<_>>()
        );

        let fsm = unsafe { core::ptr::read_volatile(mci.offset(0x24 / 4)) };
        println!("Checking fsm: {:x}", fsm);

        const FPGA_WRAPPER_MCU_LOG_FIFO_DATA_OFFSET: isize = 0x1010 / 4;
        const FPGA_WRAPPER_MCU_LOG_FIFO_PUSH_OFFSET: isize = 0x1014 / 4;
        const FPGA_WRAPPER_MCU_LOG_FIFO_STATUS_OFFSET: isize = 0x1018 / 4;
        let fifo_status = unsafe {
            wrapper
                .offset(FPGA_WRAPPER_MCU_LOG_FIFO_STATUS_OFFSET)
                .read_volatile()
        };
        println!("FIFO status: {:x}", fifo_status);
        println!("Writing to FIFO: 0x34");
        unsafe {
            core::ptr::write_volatile(
                wrapper.offset(FPGA_WRAPPER_MCU_LOG_FIFO_PUSH_OFFSET),
                0x34 | 0x100,
            );
        }
        std::thread::sleep(Duration::from_secs_f64(0.001));
        println!("Writing to FIFO: 0x35");
        unsafe {
            core::ptr::write_volatile(
                wrapper.offset(FPGA_WRAPPER_MCU_LOG_FIFO_PUSH_OFFSET),
                0x35 | 0x100,
            );
        }
        std::thread::sleep(Duration::from_secs(1));
        let fifo_status = unsafe {
            wrapper
                .offset(FPGA_WRAPPER_MCU_LOG_FIFO_STATUS_OFFSET)
                .read_volatile()
        };
        println!("FIFO status: {:x}", fifo_status);

        std::thread::sleep(Duration::from_secs(1));

        println!("Reading fifo data");
        loop {
            let fifo_status = unsafe {
                wrapper
                    .offset(FPGA_WRAPPER_MCU_LOG_FIFO_STATUS_OFFSET)
                    .read_volatile()
            };
            println!("FIFO status: {:x}", fifo_status);
            let fifodata = unsafe {
                FifoData(
                    wrapper
                        .offset(FPGA_WRAPPER_MCU_LOG_FIFO_DATA_OFFSET)
                        .read_volatile(),
                )
            };
            if fifo_status == 1 {
                break;
            }
            std::thread::sleep(Duration::from_secs_f64(0.001));
            println!(
                "Got fifo data {:x}, valid {}",
                fifodata.0,
                fifodata.log_fifo_valid()
            );
            let fifodata = unsafe {
                FifoData(
                    wrapper
                        .offset(FPGA_WRAPPER_MCU_LOG_FIFO_DATA_OFFSET)
                        .read_volatile(),
                )
            };
            println!(
                "Got fifo data {:x}, valid {}",
                fifodata.0,
                fifodata.log_fifo_valid()
            );
            if fifodata.log_fifo_valid() == 0 {
                break;
            }
        }

        let status = unsafe { core::ptr::read_volatile(wrapper.offset(FPGA_WRAPPER_STATUS_OFFSET)) };
        println!("Checking status: {:x}", status);
        let start = std::time::Instant::now();
        let cycle_count0 = unsafe { core::ptr::read_volatile(wrapper.offset(FPGA_WRAPPER_CYCLE_COUNT_OFFSET)) };
        println!("Checking cycle count: {}", cycle_count0);
        std::thread::sleep(Duration::from_secs(1));
        let end = std::time::Instant::now();
        let cycle_count1 = unsafe { core::ptr::read_volatile(wrapper.offset(FPGA_WRAPPER_CYCLE_COUNT_OFFSET)) };
        let dur = end - start;
        let cycles = (cycle_count1 - cycle_count0) as f64;
        let seconds = dur.as_secs_f64();
        println!("Checking cycle count 1: {}", cycle_count1);
        println!(
            "MCU RISC-V Frequency: {:.6} MHz",
            cycles / seconds / 1000000.0
        );
        let output0 = unsafe { core::ptr::read_volatile(wrapper.offset(FPGA_WRAPPER_MCI_GENERIC_OUTPUT_WIRES_0_OFFSET)) };
        println!("Checking generic output wire 0: {:x}", output0);
        let output1 = unsafe { core::ptr::read_volatile(wrapper.offset(FPGA_WRAPPER_MCI_GENERIC_OUTPUT_WIRES_1_OFFSET)) };
        println!("Checking generic output wire 1: {:x}", output1);

        let fsm = unsafe { core::ptr::read_volatile(mci.offset(0x24 / 4)) };
        println!("Checking fsm: {:x}", fsm);
        println!("Writing to FIFO: 0x36");
        unsafe {
            core::ptr::write_volatile(
                wrapper.offset(FPGA_WRAPPER_MCU_LOG_FIFO_PUSH_OFFSET),
                0x36 | 0x100,
            );
        }

        println!("Reading fifo data");
        loop {
            let fifo_status = unsafe {
                wrapper
                    .offset(FPGA_WRAPPER_MCU_LOG_FIFO_STATUS_OFFSET)
                    .read_volatile()
            };
            println!("FIFO status: {:x}", fifo_status);
            if fifo_status == 1 {
                break;
            }
            let fifodata = unsafe {
                FifoData(
                    wrapper
                        .offset(FPGA_WRAPPER_MCU_LOG_FIFO_DATA_OFFSET)
                        .read_volatile(),
                )
            };
            println!(
                "Got fifo data {:x}, valid {}",
                fifodata.0,
                fifodata.log_fifo_valid()
            );
            if fifodata.log_fifo_valid() == 0 {
                break;
            }
        }
    }
}

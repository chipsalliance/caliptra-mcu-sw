// Licensed under the Apache-2.0 license

use crate::fpga_regs::{Control, FifoData, FifoRegs, FifoStatus, ItrngFifoStatus, WrapperRegs};
use crate::{InitParams, McuHwModel, Output, SecurityState};
use anyhow::{anyhow, Error, Result};
use caliptra_emu_bus::Event;
use caliptra_hw_model_types::{DEFAULT_FIELD_ENTROPY, DEFAULT_UDS_SEED};
use registers_generated::mci::bits::Go::Go;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use uio::{UioDevice, UioError};

// UIO mapping indices
const FPGA_WRAPPER_MAPPING: (usize, usize) = (0, 0);
const CALIPTRA_MAPPING: (usize, usize) = (0, 1);
const CALIPTRA_ROM_MAPPING: (usize, usize) = (0, 2);
const I3C_CONTROLLER_MAPPING: (usize, usize) = (0, 3);
const MCU_SRAM_MAPPING: (usize, usize) = (0, 4);
const LC_MAPPING: (usize, usize) = (1, 0);
const MCU_ROM_MAPPING: (usize, usize) = (1, 1);
const I3C_TARGET_MAPPING: (usize, usize) = (1, 2);
const MCI_MAPPING: (usize, usize) = (1, 3);
const OTP_MAPPING: (usize, usize) = (1, 4);

// Set to core_clk cycles per ITRNG sample.
const ITRNG_DIVISOR: u32 = 400;
const DEFAULT_AXI_PAUSER: u32 = 0x1;

// ITRNG FIFO stores 1024 DW and outputs 4 bits at a time to Caliptra.
const FPGA_ITRNG_FIFO_SIZE: usize = 1024;

fn fmt_uio_error(err: UioError) -> Error {
    anyhow!("{err:?}")
}

struct Wrapper {
    ptr: *mut u32,
}

impl Wrapper {
    fn regs(&self) -> &mut WrapperRegs {
        unsafe { &mut *(self.ptr as *mut WrapperRegs) }
    }
    fn fifo_regs(&self) -> &mut FifoRegs {
        unsafe { &mut *(self.ptr.offset(0x1000 / 4) as *mut FifoRegs) }
    }
}
unsafe impl Send for Wrapper {}
unsafe impl Sync for Wrapper {}

struct Mci {
    ptr: *mut u32,
}

impl Mci {
    fn regs(&self) -> &mut registers_generated::mci::regs::Mci {
        unsafe { &mut *(self.ptr as *mut registers_generated::mci::regs::Mci) }
    }
}

struct CaliptraMmio {
    ptr: *mut u32,
}

impl CaliptraMmio {
    #[allow(unused)]
    fn mbox(&self) -> &mut registers_generated::mbox::regs::Mbox {
        unsafe {
            &mut *(self.ptr.offset(0x2_0000 / 4) as *mut registers_generated::mbox::regs::Mbox)
        }
    }
    #[allow(unused)]
    fn soc(&self) -> &mut registers_generated::soc::regs::Soc {
        unsafe { &mut *(self.ptr.offset(0x3_0000 / 4) as *mut registers_generated::soc::regs::Soc) }
    }
}

pub struct ModelFpgaRealtime {
    devs: [UioDevice; 2],
    // mmio uio pointers
    wrapper: Arc<Wrapper>,
    caliptra_mmio: CaliptraMmio,
    caliptra_rom_backdoor: *mut u8,
    mcu_rom_backdoor: *mut u8,
    mcu_sram_backdoor: *mut u8,
    mci: Mci,
    i3c_mmio: *mut u32,
    i3c_controller_mmio: *mut u32,

    realtime_thread: Option<thread::JoinHandle<()>>,
    realtime_thread_exit_flag: Arc<AtomicBool>,

    output: Output,
}

impl ModelFpgaRealtime {
    fn set_subsystem_reset(&mut self, reset: bool) {
        self.wrapper.regs().control.modify(
            Control::CptraSsRstB.val(!(reset) as u32)
                + Control::CptraPwrgood.val((!reset) as u32)
                + Control::SsDebugIntent::SET,
        );
    }

    fn set_secrets_valid(&mut self, value: bool) {
        self.wrapper.regs().control.modify(
            Control::CptraObfUdsSeedVld.val(value as u32)
                + Control::CptraObfFieldEntropyVld.val(value as u32),
        )
    }

    fn clear_logs(&mut self) {
        println!("Clearing Caliptra logs");
        loop {
            if self
                .wrapper
                .fifo_regs()
                .log_fifo_status
                .is_set(FifoStatus::Empty)
            {
                break;
            }
            if !self
                .wrapper
                .fifo_regs()
                .log_fifo_data
                .is_set(FifoData::CharValid)
            {
                break;
            }
        }

        println!("Clearing MCU logs");
        loop {
            if self
                .wrapper
                .fifo_regs()
                .dbg_fifo_status
                .is_set(FifoStatus::Empty)
            {
                break;
            }
            if !self
                .wrapper
                .fifo_regs()
                .dbg_fifo_data_pop
                .is_set(FifoData::CharValid)
            {
                break;
            }
        }
    }

    fn handle_log(&mut self) {
        loop {
            // Check if the FIFO is full (which probably means there was an overrun)
            if self
                .wrapper
                .fifo_regs()
                .log_fifo_status
                .is_set(FifoStatus::Full)
            {
                panic!("FPGA log FIFO overran");
            }
            if self
                .wrapper
                .fifo_regs()
                .log_fifo_status
                .is_set(FifoStatus::Empty)
            {
                break;
            }
            let data = self.wrapper.fifo_regs().log_fifo_data.extract();
            // Add byte to log if it is valid
            if data.is_set(FifoData::CharValid) {
                self.output()
                    .sink()
                    .push_uart_char(data.read(FifoData::NextChar) as u8);
            }
        }

        loop {
            // Check if the FIFO is full (which probably means there was an overrun)
            if self
                .wrapper
                .fifo_regs()
                .dbg_fifo_status
                .is_set(FifoStatus::Full)
            {
                panic!("FPGA log FIFO overran");
            }
            if self
                .wrapper
                .fifo_regs()
                .dbg_fifo_status
                .is_set(FifoStatus::Empty)
            {
                break;
            }
            let data = self.wrapper.fifo_regs().dbg_fifo_data_pop.extract();
            // Add byte to log if it is valid
            if data.is_set(FifoData::CharValid) {
                self.output()
                    .sink()
                    .push_uart_char(data.read(FifoData::NextChar) as u8);
            }
        }
    }

    // UIO crate doesn't provide a way to unmap memory.
    fn unmap_mapping(&self, addr: *mut u32, mapping: (usize, usize)) {
        let map_size = self.devs[mapping.0].map_size(mapping.1).unwrap();

        unsafe {
            nix::sys::mman::munmap(addr as *mut libc::c_void, map_size).unwrap();
        }
    }

    fn realtime_thread_itrng_fn(
        wrapper: Arc<Wrapper>,
        exit: Arc<AtomicBool>,
        mut itrng_nibbles: Box<dyn Iterator<Item = u8> + Send>,
    ) {
        // Reset ITRNG FIFO to clear out old data

        wrapper
            .fifo_regs()
            .itrng_fifo_status
            .write(ItrngFifoStatus::Reset::SET);
        wrapper
            .fifo_regs()
            .itrng_fifo_status
            .write(ItrngFifoStatus::Reset::CLEAR);

        // Small delay to allow reset to complete
        thread::sleep(Duration::from_millis(1));

        while !exit.load(Ordering::Relaxed) {
            // Once TRNG data is requested the FIFO will continously empty. Load at max one FIFO load at a time.
            // FPGA ITRNG FIFO is 1024 DW deep.
            for _ in 0..FPGA_ITRNG_FIFO_SIZE {
                if !wrapper
                    .fifo_regs()
                    .itrng_fifo_status
                    .is_set(ItrngFifoStatus::Full)
                {
                    let mut itrng_dw = 0;
                    for i in 0..8 {
                        match itrng_nibbles.next() {
                            Some(nibble) => itrng_dw += u32::from(nibble) << (4 * i),
                            None => return,
                        }
                    }
                    wrapper.fifo_regs().itrng_fifo_data.set(itrng_dw);
                } else {
                    break;
                }
            }
            // 1 second * (20 MHz / (2^13 throttling counter)) / 8 nibbles per DW: 305 DW of data consumed in 1 second.
            let end_time = Instant::now() + Duration::from_millis(1000);
            while !exit.load(Ordering::Relaxed) && Instant::now() < end_time {
                thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

impl McuHwModel for ModelFpgaRealtime {
    fn step(&mut self) {
        self.handle_log();
    }

    fn new_unbooted(params: InitParams) -> Result<Self>
    where
        Self: Sized,
    {
        let output = Output::new(params.log_writer);
        let dev0 = UioDevice::blocking_new(0)?;
        let dev1 = UioDevice::blocking_new(1)?;
        let devs = [dev0, dev1];

        let wrapper = Arc::new(Wrapper {
            ptr: devs[FPGA_WRAPPER_MAPPING.0]
                .map_mapping(FPGA_WRAPPER_MAPPING.1)
                .map_err(fmt_uio_error)? as *mut u32,
        });
        let caliptra_rom_backdoor = devs[CALIPTRA_ROM_MAPPING.0]
            .map_mapping(CALIPTRA_ROM_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u8;
        let mcu_sram_backdoor = devs[MCU_SRAM_MAPPING.0]
            .map_mapping(MCU_SRAM_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u8;
        let mcu_rom_backdoor = devs[MCU_ROM_MAPPING.0]
            .map_mapping(MCU_ROM_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u8;
        let mci_ptr = devs[MCI_MAPPING.0]
            .map_mapping(MCI_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u32;
        let caliptra_mmio = devs[CALIPTRA_MAPPING.0]
            .map_mapping(CALIPTRA_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u32;
        let i3c_mmio = devs[I3C_TARGET_MAPPING.0]
            .map_mapping(I3C_TARGET_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u32;
        let i3c_controller_mmio = devs[I3C_CONTROLLER_MAPPING.0]
            .map_mapping(I3C_CONTROLLER_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u32;
        let _lc_mmio = devs[LC_MAPPING.0]
            .map_mapping(LC_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u32;
        let _otp_mmio = devs[OTP_MAPPING.0]
            .map_mapping(OTP_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u32;

        let realtime_thread_exit_flag = Arc::new(AtomicBool::new(false));
        let realtime_thread_exit_flag2 = realtime_thread_exit_flag.clone();
        let realtime_wrapper = wrapper.clone();

        let realtime_thread = Some(std::thread::spawn(move || {
            Self::realtime_thread_itrng_fn(
                realtime_wrapper,
                realtime_thread_exit_flag2,
                params.itrng_nibbles,
            )
        }));

        // TODO: initialize this after the I3C target is configured.
        // let i3c_controller = xi3c::Controller::new(i3c_controller_mmio);

        let mut m = Self {
            devs,
            wrapper,
            caliptra_mmio: CaliptraMmio { ptr: caliptra_mmio },
            caliptra_rom_backdoor,
            mcu_rom_backdoor,
            mcu_sram_backdoor,
            mci: Mci { ptr: mci_ptr },
            i3c_mmio,
            i3c_controller_mmio,

            realtime_thread,
            realtime_thread_exit_flag,

            output,
        };

        // Set generic input wires.
        let input_wires = [(!params.uds_granularity_64 as u32) << 31, 0];
        m.set_generic_input_wires(&input_wires);

        // Set Security State signal wires
        println!("Set security state");
        m.set_security_state(params.security_state);

        println!("Set itrng divider");
        // Set divisor for ITRNG throttling
        m.set_itrng_divider(ITRNG_DIVISOR);

        println!("Set deobf key");
        // Set deobfuscation key
        for i in 0..8 {
            m.wrapper.regs().cptra_obf_key[i].set(params.cptra_obf_key[i]);
        }

        // Set the CSR HMAC key
        for i in 0..16 {
            m.wrapper.regs().cptra_csr_hmac_key[i].set(params.csr_hmac_key[i]);
        }

        // Set the UDS Seed
        for i in 0..16 {
            m.wrapper.regs().cptra_obf_uds_seed[i].set(DEFAULT_UDS_SEED[i]);
        }

        // Set the FE Seed
        for i in 0..8 {
            m.wrapper.regs().cptra_obf_field_entropy[i].set(DEFAULT_FIELD_ENTROPY[i]);
        }

        // Currently not using strap UDS and FE
        m.set_secrets_valid(false);

        println!("Clearing fifo");
        // Sometimes there's garbage in here; clean it out
        m.clear_logs();

        println!("Putting subsystem into reset");
        m.set_subsystem_reset(true);

        println!("new_unbooted");

        // Set initial PAUSER
        m.set_axi_user(DEFAULT_AXI_PAUSER);

        println!("AXI user written");

        // Write ROM images over backdoors
        // ensure that they are 8-byte aligned to write to AXI
        let mut caliptra_rom_data = params.caliptra_rom.to_vec();
        while caliptra_rom_data.len() % 8 != 0 {
            caliptra_rom_data.push(0);
        }
        let mut mcu_rom_data = params.mcu_rom.to_vec();
        while mcu_rom_data.len() % 8 != 0 {
            mcu_rom_data.push(0);
        }

        // copy the ROM data
        let caliptra_rom_slice = unsafe {
            core::slice::from_raw_parts_mut(m.caliptra_rom_backdoor, caliptra_rom_data.len())
        };
        println!("Writing Caliptra ROM ({} bytes)", caliptra_rom_data.len());
        caliptra_rom_slice.copy_from_slice(&caliptra_rom_data);
        println!("Writing MCU ROM");
        let mcu_rom_slice =
            unsafe { core::slice::from_raw_parts_mut(m.mcu_rom_backdoor, mcu_rom_data.len()) };
        mcu_rom_slice.copy_from_slice(&mcu_rom_data);

        // set the reset vector to point to the ROM backdoor
        println!("Writing MCU reset vector");
        m.wrapper
            .regs()
            .mcu_reset_vector
            .set(mcu_config_fpga::FPGA_MEMORY_MAP.rom_offset);

        println!("Taking subsystem out of reset");
        m.set_subsystem_reset(false);

        // TODO: remove this when we can finish subsystem/active mode
        println!("Writing MCU firmware to SRAM");
        // For now, we copy the runtime directly into the SRAM
        let mut fw_data = params.mcu_firmware.to_vec();
        while fw_data.len() % 8 != 0 {
            fw_data.push(0);
        }
        // TODO: remove this offset 0x80 and add 128 bytes of padding to the beginning of the firmware
        // as this is going to fail when we use the DMA controller
        let sram_slice = unsafe {
            core::slice::from_raw_parts_mut(m.mcu_sram_backdoor.offset(0x80), fw_data.len())
        };
        sram_slice.copy_from_slice(&fw_data);

        println!("Done starting MCU");
        Ok(m)
    }

    fn type_name(&self) -> &'static str {
        "ModelFpgaRealtime"
    }

    fn output(&mut self) -> &mut crate::Output {
        let cycle = self.wrapper.regs().cycle_count.get();
        self.output.sink().set_now(u64::from(cycle));
        &mut self.output
    }

    fn ready_for_fw(&self) -> bool {
        true
    }

    fn tracing_hint(&mut self, _enable: bool) {
        // Do nothing; we don't support tracing yet
    }

    fn set_axi_user(&mut self, pauser: u32) {
        self.wrapper.regs().pauser.set(pauser);
    }

    fn set_caliptra_boot_go(&mut self, go: bool) {
        self.mci
            .regs()
            .mci_reg_cptra_boot_go
            .write(Go.val(go as u32));
    }

    fn set_itrng_divider(&mut self, divider: u32) {
        self.wrapper.regs().itrng_divisor.set(divider - 1);
    }

    fn set_security_state(&mut self, _value: SecurityState) {
        // todo!() // this is no yet supported in FPGA
    }

    fn set_generic_input_wires(&mut self, value: &[u32; 2]) {
        for i in 0..2 {
            self.wrapper.regs().generic_input_wires[i].set(value[i]);
        }
    }

    fn events_from_caliptra(&mut self) -> Vec<Event> {
        todo!()
    }

    fn events_to_caliptra(&mut self) -> mpsc::Sender<Event> {
        todo!()
    }
}

impl Drop for ModelFpgaRealtime {
    fn drop(&mut self) {
        self.realtime_thread_exit_flag
            .store(true, Ordering::Relaxed);
        self.realtime_thread.take().unwrap().join().unwrap();

        // Unmap UIO memory space so that the file lock is released
        self.unmap_mapping(self.wrapper.ptr, FPGA_WRAPPER_MAPPING);
        self.unmap_mapping(self.caliptra_mmio.ptr, CALIPTRA_MAPPING);
        self.unmap_mapping(self.caliptra_rom_backdoor as *mut u32, CALIPTRA_ROM_MAPPING);
        self.unmap_mapping(self.mcu_rom_backdoor as *mut u32, MCU_ROM_MAPPING);
        self.unmap_mapping(self.mcu_sram_backdoor as *mut u32, MCU_SRAM_MAPPING);
        self.unmap_mapping(self.mci.ptr, MCI_MAPPING);
        self.unmap_mapping(self.i3c_mmio, I3C_TARGET_MAPPING);
        self.unmap_mapping(self.i3c_controller_mmio, I3C_CONTROLLER_MAPPING);
    }
}

#[cfg(test)]
mod test {
    use crate::{DefaultHwModel, InitParams, McuHwModel};

    #[test]
    fn test_new_unbooted() {
        let mcu_rom = mcu_builder::rom_build(Some("fpga"), "").expect("Could not build MCU ROM");
        let mcu_runtime = &mcu_builder::runtime_build_with_apps_cached(
            &[],
            Some("fpga-runtime.bin"),
            false,
            Some("fpga"),
            Some(&mcu_config_fpga::FPGA_MEMORY_MAP),
            false,
            None,
            None,
        )
        .expect("Could not build MCU runtime");
        let mut caliptra_builder =
            mcu_builder::CaliptraBuilder::new(true, None, None, None, None, None, None);
        let caliptra_rom = caliptra_builder
            .get_caliptra_rom()
            .expect("Could not build Caliptra ROM");
        let caliptra_fw = caliptra_builder
            .get_caliptra_fw()
            .expect("Could not build Caliptra FW bundle");
        let _vendor_pk_hash = caliptra_builder
            .get_vendor_pk_hash()
            .expect("Could not get vendor PK hash");

        let caliptra_rom = std::fs::read(caliptra_rom).unwrap();
        let caliptra_fw = std::fs::read(caliptra_fw).unwrap();
        let mcu_rom = std::fs::read(mcu_rom).unwrap();
        let mcu_runtime = std::fs::read(mcu_runtime).unwrap();

        let mut model = DefaultHwModel::new_unbooted(InitParams {
            caliptra_rom: &caliptra_rom,
            caliptra_firmware: &caliptra_fw,
            mcu_rom: &mcu_rom,
            mcu_firmware: &mcu_runtime,
            active_mode: true,
            ..Default::default()
        })
        .unwrap();
        for _ in 0..5_000_000 {
            model.step();
        }
    }
}

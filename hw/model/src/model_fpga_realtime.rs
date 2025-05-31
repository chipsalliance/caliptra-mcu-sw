// Licensed under the Apache-2.0 license

use crate::InitParams;
use crate::McuHwModel;
use crate::Output;
use anyhow::{anyhow, Error, Result};
use bitfield::bitfield;
use caliptra_emu_bus::Event;
use std::sync::mpsc;
use uio::{UioDevice, UioError};

// UIO mapping indices
const FPGA_WRAPPER_MAPPING: (usize, usize) = (0, 0);
const CALIPTRA_MAPPING: (usize, usize) = (0, 1);
const CALIPTRA_ROM_MAPPING: (usize, usize) = (0, 2);
const I3C_CONTROLLER_MAPPING: (usize, usize) = (0, 3);
const MCU_SRAM_MAPPING: (usize, usize) = (0, 4);
const _SS_MAPPING: (usize, usize) = (1, 0);
const MCU_ROM_MAPPING: (usize, usize) = (1, 1);
const I3C_TARGET_MAPPING: (usize, usize) = (1, 2);
const MCI_MAPPING: (usize, usize) = (1, 3);

const DEFAULT_AXI_PAUSER: u32 = 0x1;

fn fmt_uio_error(err: UioError) -> Error {
    anyhow!("{err:?}")
}

// FPGA wrapper register offsets
const _FPGA_WRAPPER_MAGIC_OFFSET: isize = 0x0000 / 4;
const _FPGA_WRAPPER_VERSION_OFFSET: isize = 0x0004 / 4;
const FPGA_WRAPPER_CONTROL_OFFSET: isize = 0x0008 / 4;
const _FPGA_WRAPPER_STATUS_OFFSET: isize = 0x000C / 4;
const FPGA_WRAPPER_PAUSER_OFFSET: isize = 0x0010 / 4;
const _FPGA_WRAPPER_ITRNG_DIV_OFFSET: isize = 0x0014 / 4;
const FPGA_WRAPPER_CYCLE_COUNT_OFFSET: isize = 0x0018 / 4;
const _FPGA_WRAPPER_GENERIC_INPUT_OFFSET: isize = 0x0030 / 4;
const _FPGA_WRAPPER_GENERIC_OUTPUT_OFFSET: isize = 0x0038 / 4;
const _FPGA_WRAPPER_DEOBF_KEY_OFFSET: isize = 0x0040 / 4;
const _FPGA_WRAPPER_CSR_HMAC_KEY_OFFSET: isize = 0x0060 / 4;

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
const _FPGA_WRAPPER_MCI_GENERIC_OUTPUT_WIRES_0_OFFSET: isize = 0x0128 / 4;
const _FPGA_WRAPPER_MCI_GENERIC_OUTPUT_WIRES_1_OFFSET: isize = 0x012C / 4;
const _FPGA_WRAPPER_LOG_FIFO_DATA_OFFSET: isize = 0x1000 / 4;
const _FPGA_WRAPPER_LOG_FIFO_STATUS_OFFSET: isize = 0x1004 / 4;
const _FPGA_WRAPPER_ITRNG_FIFO_DATA_OFFSET: isize = 0x1008 / 4;
const _FPGA_WRAPPER_ITRNG_FIFO_STATUS_OFFSET: isize = 0x100C / 4;
const FPGA_WRAPPER_MCU_LOG_FIFO_DATA_OFFSET: isize = 0x1010 / 4;
const FPGA_WRAPPER_MCU_LOG_FIFO_STATUS_OFFSET: isize = 0x1018 / 4;

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
    devs: [UioDevice; 2],
    // mmio uio pointers
    wrapper: *mut u32,
    caliptra_mmio: *mut u32,
    caliptra_rom_backdoor: *mut u8,
    mcu_rom_backdoor: *mut u8,
    mcu_sram_backdoor: *mut u8,
    mci: *mut u32,
    i3c_mmio: *mut u32,
    i3c_controller_mmio: *mut u32,

    output: Output,
}

impl ModelFpgaRealtime {
    fn set_subsystem_reset(&mut self, reset: bool) {
        let value = if reset { 0 } else { 3 };
        unsafe {
            core::ptr::write_volatile(self.wrapper.offset(FPGA_WRAPPER_CONTROL_OFFSET), value);
        }
    }

    fn clear_log_fifo(&mut self) {
        // clear Caliptra log FIFO
        // loop {
        //     let fifodata = unsafe {
        //         FifoData(
        //             self.wrapper
        //                 .offset(FPGA_WRAPPER_LOG_FIFO_DATA_OFFSET)
        //                 .read_volatile(),
        //         )
        //     };
        //     if fifodata.log_fifo_valid() == 0 {
        //         break;
        //     }
        // }
        // clear MCU log FIFO
        loop {
            let fifosts = unsafe {
                FifoStatus(
                    self.wrapper
                        .offset(FPGA_WRAPPER_MCU_LOG_FIFO_STATUS_OFFSET)
                        .read_volatile(),
                )
            };
            if fifosts.log_fifo_empty() == 1 {
                break;
            }
            let fifodata = unsafe {
                FifoData(
                    self.wrapper
                        .offset(FPGA_WRAPPER_MCU_LOG_FIFO_DATA_OFFSET)
                        .read_volatile(),
                )
            };
            if fifodata.log_fifo_valid() == 0 {
                return;
            }
        }
    }

    fn handle_log(&mut self) {
        // Check if the FIFO is full (which probably means there was an overrun)
        // let fifosts = unsafe {
        //     FifoStatus(
        //         self.wrapper
        //             .offset(FPGA_WRAPPER_LOG_FIFO_STATUS_OFFSET)
        //             .read_volatile(),
        //     )
        // };
        // if fifosts.log_fifo_full() != 0 {
        //     panic!("FPGA log Caliptra FIFO overran");
        // }
        // // Check and empty log Caliptra FIFO
        // loop {
        //     let fifodata = unsafe {
        //         FifoData(
        //             self.wrapper
        //                 .offset(FPGA_WRAPPER_LOG_FIFO_DATA_OFFSET)
        //                 .read_volatile(),
        //         )
        //     };
        //     // Add byte to log if it is valid
        //     if fifodata.log_fifo_valid() != 0 {
        //         self.output()
        //             .sink()
        //             .push_uart_char(fifodata.log_fifo_char().try_into().unwrap());
        //     } else {
        //         break;
        //     }
        // }
        // Check if the FIFO is full (which probably means there was an overrun)
        loop {
            let fifosts = unsafe {
                FifoStatus(
                    self.wrapper
                        .offset(FPGA_WRAPPER_MCU_LOG_FIFO_STATUS_OFFSET)
                        .read_volatile(),
                )
            };
            if fifosts.log_fifo_full() != 0 {
                panic!("FPGA log MCU FIFO overran");
            }
            if fifosts.log_fifo_empty() == 1 {
                break;
            }
            let fifodata = unsafe {
                FifoData(
                    self.wrapper
                        .offset(FPGA_WRAPPER_MCU_LOG_FIFO_DATA_OFFSET)
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
    fn unmap_mapping(&self, addr: *mut u32, mapping: (usize, usize)) {
        let map_size = self.devs[mapping.0].map_size(mapping.1).unwrap();

        unsafe {
            nix::sys::mman::munmap(addr as *mut libc::c_void, map_size).unwrap();
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

        let wrapper = devs[FPGA_WRAPPER_MAPPING.0]
            .map_mapping(FPGA_WRAPPER_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u32;
        let caliptra_rom_backdoor = devs[CALIPTRA_ROM_MAPPING.0]
            .map_mapping(CALIPTRA_ROM_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u8;
        let mcu_sram_backdoor = devs[MCU_SRAM_MAPPING.0]
            .map_mapping(MCU_SRAM_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u8;
        let mcu_rom_backdoor = devs[MCU_ROM_MAPPING.0]
            .map_mapping(MCU_ROM_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u8;
        let mci = devs[MCI_MAPPING.0]
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

        // TODO: initialize this after the I3C target is configured.
        // let i3c_controller = xi3c::Controller::new(i3c_controller_mmio);

        let mut m = Self {
            devs,
            wrapper,
            caliptra_mmio,
            caliptra_rom_backdoor,
            mcu_rom_backdoor,
            mcu_sram_backdoor,
            mci,
            i3c_mmio,
            i3c_controller_mmio,

            output,
        };

        println!("Clearing fifo");
        // Sometimes there's garbage in here; clean it out
        m.clear_log_fifo();

        println!("Putting subsystem into reset");
        m.set_subsystem_reset(true);

        println!("new_unbooted");

        // Set initial PAUSER
        m.set_axi_user(DEFAULT_AXI_PAUSER);

        println!("AXI user written");

        // Write ROM images over backdoors
        // ensure that they are 8-byte aligned to write to AXI
        // let mut caliptra_rom_data = params.caliptra_rom.to_vec();
        // while caliptra_rom_data.len() % 8 != 0 {
        //     caliptra_rom_data.push(0);
        // }
        let mut mcu_rom_data = params.mcu_rom.to_vec();
        while mcu_rom_data.len() % 8 != 0 {
            mcu_rom_data.push(0);
        }

        // copy the ROM data
        // let caliptra_rom_slice = unsafe {
        //     core::slice::from_raw_parts_mut(m.caliptra_rom_backdoor, caliptra_rom_data.len())
        // };
        // println!("Writing Caliptra ROM");
        // TODO: this crashes the FPGA
        // caliptra_rom_slice.copy_from_slice(&caliptra_rom_data);
        println!("Writing MCU ROM");
        let mcu_rom_slice =
            unsafe { core::slice::from_raw_parts_mut(m.mcu_rom_backdoor, mcu_rom_data.len()) };
        mcu_rom_slice.copy_from_slice(&mcu_rom_data);

        // set the reset vector to point to the ROM backdoor
        println!("Writing MCU reset vector");
        unsafe {
            core::ptr::write_volatile(
                m.wrapper.offset(FPGA_WRAPPER_MCU_RESET_VECTOR_OFFSET),
                mcu_config_fpga::FPGA_MEMORY_MAP.rom_offset,
            )
        };

        println!("Taking subsystem out of reset");
        m.set_subsystem_reset(false);

        // TODO: finish testing active mode
        println!("Writing MCU firmware to SRAM");
        // For now, we copy the runtime directly into the SRAM
        let mut fw_data = params.mcu_firmware.to_vec();
        while fw_data.len() % 8 != 0 {
            fw_data.push(0);
        }
        // TODO: remove this offset 0x80 and add 128 bytes of padding to the beginning of the firmware
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
        let cycle = unsafe {
            self.wrapper
                .offset(FPGA_WRAPPER_CYCLE_COUNT_OFFSET)
                .read_volatile()
        };
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
        unsafe {
            self.wrapper
                .offset(FPGA_WRAPPER_PAUSER_OFFSET)
                .write_volatile(pauser);
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
        // Unmap UIO memory space so that the file lock is released
        self.unmap_mapping(self.wrapper, FPGA_WRAPPER_MAPPING);
        self.unmap_mapping(self.caliptra_mmio, CALIPTRA_MAPPING);
        self.unmap_mapping(self.caliptra_rom_backdoor as *mut u32, CALIPTRA_ROM_MAPPING);
        self.unmap_mapping(self.mcu_rom_backdoor as *mut u32, MCU_ROM_MAPPING);
        self.unmap_mapping(self.mcu_sram_backdoor as *mut u32, MCU_SRAM_MAPPING);
        self.unmap_mapping(self.mci, MCI_MAPPING);
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
        let mcu_runtime = &mcu_builder::runtime_build_with_apps(
            &[],
            Some("fpga-runtime.bin"),
            false,
            Some("fpga"),
            Some(&mcu_config_fpga::FPGA_MEMORY_MAP),
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
            ..Default::default()
        })
        .unwrap();
        for _ in 0..1_000_000 {
            model.step();
        }
    }
}

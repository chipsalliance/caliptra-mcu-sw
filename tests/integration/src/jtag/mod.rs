// Licensed under the Apache-2.0 license

mod test_jtag_taps;
mod test_lc_transitions;
mod test_manuf_debug_unlock;
mod test_prod_debug_unlock;
mod test_uds;

#[cfg(test)]
mod test {

    use caliptra_hw_model::jtag::DmReg;
    use caliptra_hw_model::openocd::openocd_jtag_tap::OpenOcdJtagTap;
    use caliptra_hw_model::Fuses;
    use mcu_builder::FirmwareBinaries;
    use mcu_config_fpga::FPGA_MEMORY_MAP;
    use mcu_hw_model::{DefaultHwModel, InitParams, McuHwModel};
    use mcu_rom_common::LifecycleControllerState;

    use anyhow::Result;

    pub fn ss_setup(
        initial_lc_state: Option<LifecycleControllerState>,
        rma_or_scrap_ppd: bool,
        debug_intent: bool,
        bootfsm_break: bool,
        enable_mcu_uart_log: bool,
    ) -> DefaultHwModel {
        let firmware_bundle = FirmwareBinaries::from_env().unwrap();

        let init_params = InitParams {
            fuses: Fuses::default(),
            caliptra_rom: &firmware_bundle.caliptra_rom,
            mcu_rom: &firmware_bundle.mcu_rom,
            lifecycle_controller_state: initial_lc_state,
            rma_or_scrap_ppd,
            debug_intent,
            bootfsm_break,
            enable_mcu_uart_log,
            ..Default::default()
        };
        let mut m = DefaultHwModel::new_unbooted(init_params).unwrap();
        // tell the ROM to boot by setting bits 30 and 31
        m.set_mcu_generic_input_wires(&[0, 0xc000_0000]);
        m
    }

    /// Write/Read words to SRAM over the system bus.
    fn sysbus_write_read(tap: &mut OpenOcdJtagTap, sram_base_addr: u32) -> Result<bool> {
        const NUM_WORDS: u32 = 4;
        for i in 0..NUM_WORDS {
            let addr = sram_base_addr + i * 4;
            let value = 0xa5a5a5a5;
            tap.write_memory_32(addr, value)?;
            let read_value = tap.read_memory_32(addr)?;
            println!(
                "Wrote 0x{:x} to 0x{:x}; Read 0x{:x}",
                value, addr, read_value
            );
            if value != read_value {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Check if a debug module is active.
    fn check_debug_module_active(tap: &mut OpenOcdJtagTap) -> Result<bool> {
        // Check dmstatus.allrunning and dmstatus.anyrunning bits to see if
        // debug access has been unlocked.
        let dmstatus = tap.read_reg(&DmReg::DmStatus)?;
        if (dmstatus & 0x00000c00) == 0 {
            println!("Debug is not unlocked: dmstatus = 0x{:08x}", dmstatus);
            return Ok(false);
        }
        Ok(true)
    }

    pub fn debug_is_unlocked(
        core_tap: &mut OpenOcdJtagTap,
        mcu_tap: &mut OpenOcdJtagTap,
    ) -> Result<bool> {
        // Check both TAPs are active.
        if !check_debug_module_active(core_tap)? {
            return Ok(false);
        }
        if !check_debug_module_active(mcu_tap)? {
            return Ok(false);
        }

        // Test writes to Caliptra MCU SRAM.
        if !sysbus_write_read(mcu_tap, FPGA_MEMORY_MAP.sram_offset)? {
            return Ok(false);
        }

        Ok(true)
    }
}

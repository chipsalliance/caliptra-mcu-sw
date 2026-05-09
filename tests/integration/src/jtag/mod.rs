// Licensed under the Apache-2.0 license

mod test_jtag_taps;
mod test_lc_transitions;
mod test_manuf_debug_unlock;
mod test_prod_debug_unlock;
mod test_uds;

#[cfg(test)]
mod test {
    use caliptra_hw_model::jtag::{CsrReg, DmReg};
    use caliptra_hw_model::openocd::openocd_jtag_tap::OpenOcdJtagTap;
    use caliptra_hw_model::Fuses;
    use mcu_builder::FirmwareBinaries;
    use mcu_config_fpga::FPGA_MEMORY_MAP;
    use mcu_hw_model::{DefaultHwModel, InitParams, McuHwModel};
    use romtime::LifecycleControllerState;

    use anyhow::{bail, Result};

    use std::time::Duration;

    pub const ALLHALTED_MASK: u32 = 1 << 9;
    const DCSR_SET_EBREAKM: u32 = 0x8003; // to enable debug mode on an ebreak

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
    pub fn sysbus_write_read(
        tap: &mut OpenOcdJtagTap,
        sram_base_addr: u32,
        data: &[u32],
    ) -> Result<bool> {
        for i in 0..data.len() {
            let addr = sram_base_addr + u32::try_from(i)? * 4;
            tap.write_memory_32(addr, data[i])?;
            let read_value = tap.read_memory_32(addr)?;
            println!(
                "Wrote 0x{:x} to 0x{:x}; Read 0x{:x}",
                data[i], addr, read_value
            );
            if data[i] != read_value {
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
        if !sysbus_write_read(mcu_tap, FPGA_MEMORY_MAP.sram_offset, &[0xa5a5a5a5])? {
            return Ok(false);
        }

        Ok(true)
    }

    /// Write to and execute from SRAM a tiny assembly program that performs a sum
    /// and writes it memory, then verify it executed properly
    pub fn verify_execute_from_sram(tap: &mut OpenOcdJtagTap) -> Result<()> {
        const SW_OFFSET: u32 = 0x100;
        const SW_ADDRESS: u32 = FPGA_MEMORY_MAP.sram_offset | SW_OFFSET;
        const RV32_INSTS: &[u32] = &[
            0x00100513,                                                           // addi x10, x0, 1
            0x00200593,                                                           // addi x11, x0, 2
            0x00b50533,                                              // add x10, x10, x11
            0x00000637 | (FPGA_MEMORY_MAP.sram_offset & 0xFFFFF000), // lui x12 0xa8c00 (sram base addr)
            0x00a62023 | (SW_OFFSET & 0x1F) << 7 | (SW_OFFSET >> 5 & 0x7F) << 25, // sw x10, 0x100(x12)
            0x00100073,                                                           // ebreak
        ];

        tap.halt()?;

        // Write program to SRAM
        if !sysbus_write_read(&mut *tap, FPGA_MEMORY_MAP.sram_offset, RV32_INSTS)? {
            bail!("Readback incorrect on writing program to SRAM")
        }

        // set PC to start of SRAM
        tap.write_csr_reg(CsrReg::Dpc, FPGA_MEMORY_MAP.sram_offset)?;

        // Write DCSR to enable ebreakm (bit 15) so ebreak enters debug mode
        tap.write_csr_reg(CsrReg::Dcsr, DCSR_SET_EBREAKM)?;

        tap.resume()?;
        tap.wait_status(ALLHALTED_MASK, Duration::from_secs(3))?;

        let readback = tap.read_memory_32(SW_ADDRESS)?;
        if readback != 3 {
            bail!(
                "Readback from MCU SRAM incorrect; got 0x{:x}, wanted 0x3",
                readback
            )
        }
        Ok(())
    }
}

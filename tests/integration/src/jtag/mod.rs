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
    use mcu_hw_model::{DefaultHwModel, InitParams, McuHwModel};
    use romtime::LifecycleControllerState;

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
        DefaultHwModel::new_unbooted(init_params).unwrap()
    }

    pub fn debug_is_unlocked(tap: &mut OpenOcdJtagTap) -> Result<bool> {
        // Check dmstatus.allrunning and dmstatus.anyrunning bits to see if
        // debug access has been unlocked.
        let dmstatus = tap.read_reg(&DmReg::DmStatus)?;
        if (dmstatus & 0x00000c00) == 0 {
            println!("Debug is not unlocked: dmstatus = 0x{:08x}", dmstatus);
            return Ok(false);
        }
        Ok(true)
    }
}

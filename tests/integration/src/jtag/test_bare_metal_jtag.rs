// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use caliptra_hw_model::jtag::CsrReg;
    use caliptra_hw_model::openocd::openocd_jtag_tap::{JtagParams, JtagTap, OpenOcdJtagTap};
    use caliptra_mcu_builder::FirmwareBinaries;
    use caliptra_mcu_config_fpga::FPGA_MEMORY_MAP;
    use caliptra_mcu_hw_model::{McuHwModel, McuManager};
    use caliptra_mcu_romtime::LifecycleControllerState;

    use crate::jtag::test::{ss_setup, sysbus_write_read};
    use crate::test::finish_runtime_hw_model;

    use anyhow::{bail, Result};

    const DCSR_SET_EBREAKM: u32 = 0x8003; // to enable debug mode on an ebreak

    fn sideload_bare_metal(tap: &mut OpenOcdJtagTap, bytes: &[u8]) -> Result<()> {
        // SRAM base offset
        let sram_base = FPGA_MEMORY_MAP.sram_offset;

        // Convert u8 slice to u32 words (little endian)
        let mut words = Vec::with_capacity((bytes.len() + 3) / 4);
        for chunk in bytes.chunks(4) {
            let mut word_bytes = [0u8; 4];
            word_bytes[..chunk.len()].copy_from_slice(chunk);
            words.push(u32::from_le_bytes(word_bytes));
        }
        if !sysbus_write_read(&mut *tap, sram_base, &words)? {
            bail!("Readback incorrect on writing program to SRAM")
        }

        // Set PC (Dpc CSR) to start of SRAM (sram_base)
        tap.write_csr_reg(CsrReg::Dpc, sram_base)?;

        // Write DCSR to enable ebreakm
        tap.write_csr_reg(CsrReg::Dcsr, DCSR_SET_EBREAKM)?;

        Ok(())
    }

    #[test]
    fn test_bare_metal_jtag_sideload() {
        let mut model = ss_setup(
            Some(LifecycleControllerState::TestUnlocked0),
            /*rma_or_scrap_ppd=*/ false,
            /*debug_intent=*/ true,
            /*bootfsm_break=*/ true,
            /*enable_mcu_uart_log=*/ true,
        );
        model.set_axi_user(2);

        // Connect to Caliptra Core and MCU JTAG TAPs via OpenOCD.
        let jtag_params = JtagParams {
            openocd: PathBuf::from("openocd"),
            adapter_speed_khz: 1000,
            log_stdio: true,
        };
        println!("Connecting to MCU TAP ...");
        let mut mcu_tap = model
            .jtag_tap_connect(&jtag_params, JtagTap::CaliptraMcuTap)
            .expect("Failed to connect to the Caliptra MCU JTAG TAP.");

        mcu_tap.halt().expect("Failed to halt hart");

        // Pull bare-metal bytes from prebuilt bundle environment.
        let binaries = FirmwareBinaries::from_env().expect("Firmware bundle not found");
        let bare_metal_bytes = &binaries.mcu_bare_metal;
        assert!(
            !bare_metal_bytes.is_empty(),
            "mcu_bare_metal binary is empty"
        );

        // Sideload and execute bare metal binary
        sideload_bare_metal(&mut *mcu_tap, bare_metal_bytes)
            .expect("Failed to sideload and execute bare metal binary");

        // the ROM throws an error and the sim attempts to exit due to the lack
        // of MCU runtime firmware. This is not relevant to us, as we are about
        // to jump to our sideloaded binary, so clear the error and exit status
        model
            .mcu_manager()
            .with_mci(|mci| mci.fw_error_fatal().write(|_| 0x0));
        model.output().clear_exit_status();

        // Resume MCU
        mcu_tap.resume().expect("Failed to resume hart");

        // Verify that the sideloaded binary actually ran by checking UART
        model
            .step_until_output_contains("Hello from Bare Metal Runtime!")
            .expect("Failed to find expected UART output from bare metal binary");

        // Let simulation advance and verify clean execution exit
        let status = finish_runtime_hw_model(&mut model);
        assert_eq!(status, 0);
    }
}

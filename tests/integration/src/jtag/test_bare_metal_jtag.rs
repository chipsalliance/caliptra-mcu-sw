// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use caliptra_mcu_builder::FirmwareBinaries;
    use caliptra_mcu_config_fpga::FPGA_MEMORY_MAP;
    use caliptra_mcu_hw_model::{jtag::sideload_binary, McuHwModel};
    use caliptra_mcu_romtime::LifecycleControllerState;

    use crate::jtag::test::{connect_mcu_tap, ss_setup};
    use crate::test::finish_runtime_hw_model;

    #[test]
    fn test_bare_metal_jtag_sideload() {
        let mut model = ss_setup(
            Some(LifecycleControllerState::TestUnlocked0),
            /*rma_or_scrap_ppd=*/ false,
            /*debug_intent=*/ true,
            /*bootfsm_break=*/ true,
            /*enable_mcu_uart_log=*/ true,
        );

        let mut mcu_tap =
            connect_mcu_tap(&mut model).expect("Failed to connect to the Caliptra MCU JTAG TAP.");
        mcu_tap.halt().expect("Failed to halt hart");

        // Pull bare-metal bytes from prebuilt bundle environment.
        let binaries = FirmwareBinaries::from_env().expect("Firmware bundle not found");
        let target = &caliptra_mcu_builder::firmware::targets::BARE_METAL;
        let bare_metal_bytes = &binaries.as_bundle(target).mcu_fw.bytes;
        assert!(
            !bare_metal_bytes.is_empty(),
            "mcu_bare_metal binary is empty"
        );

        // Sideload and execute bare metal binary
        let sram_base = FPGA_MEMORY_MAP.sram_offset;
        sideload_binary(
            &mut mcu_tap,
            &bare_metal_bytes,
            sram_base,
            FPGA_MEMORY_MAP.mci_offset,
        )
        .expect("Failed to sideload bare metal binary");

        // the ROM throws an error and the sim attempts to exit due to the lack
        // of MCU runtime firmware. This is not relevant to us, as we are about
        // to jump to our sideloaded binary, so clear the error and exit status
        model.clear_mci_fw_fatal_error();
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

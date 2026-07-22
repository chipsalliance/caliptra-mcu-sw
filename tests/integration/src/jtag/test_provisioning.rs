// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use caliptra_mcu_builder::FirmwareBinaries;
    use caliptra_mcu_config_fpga::FPGA_MEMORY_MAP;
    use caliptra_mcu_hw_model::jtag::sideload_binary;
    use caliptra_mcu_hw_model::{DefaultHwModel, Fuses, InitParams, McuHwModel};
    use caliptra_mcu_romtime::LifecycleControllerState;

    use crate::jtag::test::connect_mcu_tap;
    use crate::test::finish_runtime_hw_model;

    #[test]
    fn test_provisioning_jtag_sideload() {
        let firmware_bundle = FirmwareBinaries::from_env().expect("Firmware bundle not found");

        let init_params = InitParams {
            fuses: Fuses::default(),
            caliptra_rom: &firmware_bundle.caliptra_rom,
            mcu_rom: &firmware_bundle.mcu_rom,
            lifecycle_controller_state: Some(LifecycleControllerState::TestUnlocked0),
            rma_or_scrap_ppd: false,
            debug_intent: true,
            bootfsm_break: false,
            enable_mcu_uart_log: true,
            skip_otp_provisioning: true,
            ..Default::default()
        };

        let mut model = DefaultHwModel::new_unbooted(init_params).unwrap();
        // tell the ROM to boot by setting bits 30 and 31
        model.set_mcu_generic_input_wires(&[0, 0xc000_0000]);

        let mut mcu_tap =
            connect_mcu_tap(&mut model).expect("Failed to connect to the Caliptra MCU JTAG TAP.");
        mcu_tap.halt().expect("Failed to halt hart");

        // Pull provisioning FW from bundle
        let binaries = FirmwareBinaries::from_env().expect("Firmware bundle not found");
        let target = &caliptra_mcu_builder::firmware::targets::PROVISIONING_TEST_UNLOCKED_FW;
        let bare_metal_bytes = &binaries.as_bundle(target).mcu_fw.bytes;
        assert!(
            !bare_metal_bytes.is_empty(),
            "caliptra-mcu-provisioning-test-unlocked-fw binary is empty"
        );

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

        // Let simulation advance and verify clean execution exit
        let status = finish_runtime_hw_model(&mut model);
        assert_eq!(status, 0);
    }
}

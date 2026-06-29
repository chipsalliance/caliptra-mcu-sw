// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;
    use zerocopy::IntoBytes;

    use caliptra_api::mailbox::CommandId;
    use caliptra_hw_model::jtag::CaliptraCoreReg;
    use caliptra_hw_model::openocd::openocd_jtag_tap::{JtagParams, JtagTap};
    use caliptra_hw_model::HwModel;
    use caliptra_hw_model::DEFAULT_MANUF_DEBUG_UNLOCK_RAW_TOKEN;

    use caliptra_mcu_builder::FirmwareBinaries;
    use caliptra_mcu_config_fpga::FPGA_MEMORY_MAP;
    use caliptra_mcu_hw_model::jtag::{
        jtag_get_caliptra_mailbox_resp, jtag_send_caliptra_mailbox_cmd, sideload_binary,
    };
    use caliptra_mcu_hw_model::{DefaultHwModel, Fuses, InitParams, McuHwModel, ProvisioningStage};
    use caliptra_mcu_romtime::LifecycleControllerState;

    use crate::jtag::test::{connect_mcu_tap, debug_is_unlocked, ALLHALTED_MASK};
    use crate::test::finish_runtime_hw_model;

    fn create_model(
        lc_state: LifecycleControllerState,
        stage: ProvisioningStage,
    ) -> DefaultHwModel {
        let firmware_bundle = FirmwareBinaries::from_env().expect("Firmware bundle not found");

        let init_params = InitParams {
            fuses: Fuses::default(),
            caliptra_rom: &firmware_bundle.caliptra_rom,
            mcu_rom: &firmware_bundle.mcu_rom,
            lifecycle_controller_state: Some(lc_state),
            rma_or_scrap_ppd: false,
            debug_intent: true,
            bootfsm_break: true,
            enable_mcu_uart_log: true,
            target_provisioning_stage: stage,
            ..Default::default()
        };

        DefaultHwModel::new_unbooted(init_params).unwrap()
    }

    fn run_provisioning_test(mut model: DefaultHwModel, binary_name: &str, success_msg: &str) {
        // tell the ROM to boot by setting bits 30 and 31
        model.set_mcu_generic_input_wires(&[0, 0xc000_0000]);

        let mut mcu_tap =
            connect_mcu_tap(&mut model).expect("Failed to connect to the Caliptra MCU JTAG TAP.");
        mcu_tap.halt().expect("Failed to halt hart");
        mcu_tap
            .wait_status(ALLHALTED_MASK, Duration::from_millis(500))
            .expect("Failed to wait for halt");

        // Pull provisioning FW from bundle
        let binaries = FirmwareBinaries::from_env().expect("Firmware bundle not found");
        let bare_metal_bytes = binaries
            .get_bare_metal(binary_name)
            .expect("failed to fetch bare-metal binary");
        assert!(
            !bare_metal_bytes.is_empty(),
            "{} binary is empty",
            binary_name
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

        // Verify that the sideloaded binary successfully completes by checking UART
        model
            .step_until_output_contains(success_msg)
            .expect("Failed to find expected UART output from provisioning binary");

        // Let simulation advance and verify clean execution exit
        let status = finish_runtime_hw_model(&mut model);
        assert_eq!(status, 0);
    }

    #[test]
    fn test_provisioning_test_unlocked_fw() {
        let model = create_model(
            LifecycleControllerState::TestUnlocked0,
            ProvisioningStage::Raw,
        );
        run_provisioning_test(
            model,
            "caliptra-mcu-provisioning-test-unlocked-fw",
            "TEST_UNLOCKED provisioning completed successfully!",
        );
    }

    #[test]
    fn test_provisioning_manuf_fw() {
        let mut model = create_model(
            LifecycleControllerState::Dev,
            ProvisioningStage::TestUnlocked,
        );

        let jtag_params = JtagParams {
            openocd: PathBuf::from("openocd"),
            adapter_speed_khz: 1000,
            log_stdio: true,
        };

        let mut core_tap = model
            .jtag_tap_connect(&jtag_params, JtagTap::CaliptraCoreTap)
            .expect("Failed to connect to Core TAP");
        let mut mcu_tap = model
            .jtag_tap_connect(&jtag_params, JtagTap::CaliptraMcuTap)
            .expect("Failed to connect to MCU TAP");

        core_tap
            .write_reg(&CaliptraCoreReg::SsDbgManufServiceRegReq, 0x1)
            .expect("Unable to write SsDbgManufServiceRegReq reg.");
        model.base.step();

        core_tap
            .write_reg(&CaliptraCoreReg::BootfsmGo, 0x1)
            .expect("Unable to write BootfsmGo.");
        model.base.step();

        jtag_send_caliptra_mailbox_cmd(
            &mut *core_tap,
            CommandId::MANUF_DEBUG_UNLOCK_REQ_TOKEN,
            DEFAULT_MANUF_DEBUG_UNLOCK_RAW_TOKEN.0.as_bytes(),
        )
        .expect("Failed to send manuf debug unlock token.");
        model.base.step();

        let _ = jtag_get_caliptra_mailbox_resp(&mut *core_tap)
            .expect("Failed to get manuf debug unlock response.");
        model.base.step();

        while let Ok(ss_debug_manuf_response) =
            core_tap.read_reg(&CaliptraCoreReg::SsDbgManufServiceRegRsp)
        {
            if (ss_debug_manuf_response & 0x3) != 0 {
                assert_eq!(ss_debug_manuf_response, 0x1);
                model.base.step();
                break;
            }
            model.base.step();
            thread::sleep(Duration::from_millis(100));
        }

        core_tap
            .reexamine_cpu_target()
            .expect("Failed to reexamine Core CPU target.");
        core_tap
            .set_sysbus_access()
            .expect("Failed to set Core sysbus access.");
        mcu_tap
            .reexamine_cpu_target()
            .expect("Failed to reexamine MCU CPU target.");
        mcu_tap
            .set_sysbus_access()
            .expect("Failed to set MCU sysbus access.");

        let is_unlocked = debug_is_unlocked(&mut *core_tap, &mut *mcu_tap).unwrap_or(false);
        assert_eq!(is_unlocked, true);
        drop(core_tap);
        drop(mcu_tap);

        run_provisioning_test(
            model,
            "caliptra-mcu-provisioning-manuf-fw",
            "MANUF provisioning completed successfully!",
        );
    }
}

// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    use caliptra_hw_model::jtag::CaliptraCoreReg;
    use caliptra_hw_model::lcc::LcCtrlStatus;
    use caliptra_hw_model::openocd::openocd_jtag_tap::{JtagParams, JtagTap};
    use caliptra_hw_model::HwModel;
    use caliptra_hw_model::{
        Fuses, DEFAULT_LIFECYCLE_RAW_TOKEN, DEFAULT_MANUF_DEBUG_UNLOCK_RAW_TOKEN,
    };
    use mcu_builder::FirmwareBinaries;
    use mcu_hw_model::lcc::{lc_token_to_words, lc_transition, read_lc_state, LccUtilError};
    use mcu_hw_model::{DefaultHwModel, InitParams, McuHwModel};
    use mcu_rom_common::LifecycleControllerState;

    fn ss_setup(
        initial_lc_state: Option<LifecycleControllerState>,
        debug_intent: bool,
        bootfsm_break: bool,
        enable_mcu_uart_log: bool,
    ) -> DefaultHwModel {
        let firmware_bundle = FirmwareBinaries::from_env().unwrap();

        let init_params = InitParams {
            caliptra_rom: &firmware_bundle.caliptra_rom,
            mcu_rom: &firmware_bundle.mcu_rom,
            lifecycle_controller_state: initial_lc_state,
            debug_intent,
            bootfsm_break,
            enable_mcu_uart_log,
            ..Default::default()
        };
        let mut model = DefaultHwModel::new_unbooted(init_params).unwrap();
        model.init_fuses(&Fuses::default());
        model
    }

    #[test]
    fn test_raw_unlock() {
        let mut model = ss_setup(
            Some(LifecycleControllerState::Raw),
            /*debug_intent=*/ false,
            /*bootfsm_break=*/ false,
            /*enable_mcu_uart_log=*/ false,
        );

        // Connect to LCC JTAG TAP via OpenOCD.
        let jtag_params = JtagParams {
            openocd: PathBuf::from("openocd"),
            adapter_speed_khz: 1000,
            log_stdio: true,
        };
        let mut tap = model
            .jtag_tap_connect(&jtag_params, JtagTap::LccTap)
            .expect("Failed to connect to the LCC JTAG TAP.");

        // Read the LC state.
        let mut lc_state = read_lc_state(&mut *tap).expect("Unable to read LC state.");
        println!("Initial LC state: {}", lc_state);
        assert_eq!(lc_state, LifecycleControllerState::Raw);

        // Perform the raw unlock LC transition operation.
        const RAW_UNLOCK_TOKEN: [u32; 4] = [0xef1fadea, 0xadfc9693, 0x421748a2, 0xf12a5911];
        lc_state = lc_transition(
            &mut *tap,
            LifecycleControllerState::TestUnlocked0,
            Some(RAW_UNLOCK_TOKEN),
        )
        .expect("Unable to transition to TestUnlocked0.");
        println!("Post transition LC state: {}", lc_state);

        // Reset and read the LC state again.
        model.set_subsystem_reset(true);
        model.set_subsystem_reset(false);
        lc_state = read_lc_state(&mut *tap).expect("Unable to read LC state.");
        println!("LC state after reset: {}", lc_state);
        assert_eq!(lc_state, LifecycleControllerState::TestUnlocked0);
    }

    #[test]
    fn test_lc_walkthrough() {
        let lc_states = vec![
            LifecycleControllerState::TestUnlocked0,
            LifecycleControllerState::TestLocked0,
            LifecycleControllerState::TestUnlocked1,
            LifecycleControllerState::TestLocked1,
            LifecycleControllerState::TestUnlocked2,
            LifecycleControllerState::TestLocked2,
            LifecycleControllerState::TestUnlocked3,
            LifecycleControllerState::TestLocked3,
            LifecycleControllerState::TestUnlocked4,
            LifecycleControllerState::TestLocked4,
            LifecycleControllerState::TestUnlocked5,
            LifecycleControllerState::TestLocked5,
            LifecycleControllerState::TestUnlocked6,
            LifecycleControllerState::TestLocked6,
            LifecycleControllerState::TestUnlocked7,
            LifecycleControllerState::Dev,
            LifecycleControllerState::Prod,
        ];

        // Initialize Caliptra SS in first LC state.
        let mut model = ss_setup(
            Some(lc_states[0]),
            /*debug_intent=*/ false,
            /*bootfsm_break=*/ false,
            /*enable_mcu_uart_log=*/ false,
        );

        // Connect to LCC JTAG TAP via OpenOCD.
        let jtag_params = JtagParams {
            openocd: PathBuf::from("openocd"),
            adapter_speed_khz: 1000,
            log_stdio: true,
        };
        let mut tap = model
            .jtag_tap_connect(&jtag_params, JtagTap::LccTap)
            .expect("Failed to connect to the LCC JTAG TAP.");

        // Iterate over the LC states, transitioning to each one.
        for i in 0..lc_states.len() - 1 {
            let mut lc_state = read_lc_state(&mut *tap).expect("Unable to read LC state.");
            println!("Initial LC state: {}", lc_state);
            assert_eq!(lc_state, lc_states[i]);
            let token = match lc_state {
                LifecycleControllerState::TestLocked0
                | LifecycleControllerState::TestLocked1
                | LifecycleControllerState::TestLocked2
                | LifecycleControllerState::TestLocked3
                | LifecycleControllerState::TestLocked4
                | LifecycleControllerState::TestLocked5
                | LifecycleControllerState::TestLocked6
                | LifecycleControllerState::TestUnlocked7
                | LifecycleControllerState::Dev => {
                    Some(lc_token_to_words(&DEFAULT_LIFECYCLE_RAW_TOKEN.0))
                }
                _ => None,
            };
            lc_state = lc_transition(&mut *tap, lc_states[i + 1], token)
                .expect("Unable to transition to TestUnlocked0.");
            println!("Post transition LC state: {}", lc_state);

            // Reset and read the LC state again.
            model.set_subsystem_reset(true);
            model.set_subsystem_reset(false);
            lc_state = read_lc_state(&mut *tap).expect("Unable to read LC state.");
            println!("LC state after reset: {}", lc_state);
            assert_eq!(lc_state, lc_states[i + 1]);
        }
    }

    #[test]
    fn test_prod_rma_unlock() {
        let mut model = ss_setup(
            Some(LifecycleControllerState::Prod),
            /*debug_intent=*/ false,
            /*bootfsm_break=*/ false,
            /*enable_mcu_uart_log=*/ false,
        );

        // Connect to LCC JTAG TAP via OpenOCD.
        let jtag_params = JtagParams {
            openocd: PathBuf::from("openocd"),
            adapter_speed_khz: 1000,
            log_stdio: true,
        };
        let mut tap = model
            .jtag_tap_connect(&jtag_params, JtagTap::LccTap)
            .expect("Failed to connect to the LCC JTAG TAP.");

        // Read the LC state.
        let lc_state = read_lc_state(&mut *tap).expect("Unable to read LC state.");
        println!("Initial LC state: {}", lc_state);
        assert_eq!(lc_state, LifecycleControllerState::Prod);

        // Perform the RMA LC transition operation.
        // TODO(caliptra-mcu-sw/issues/454): expect a failure until the PPD pin
        // is exposed to the FPGA model to enable testing RMA transitions.
        let result = lc_transition(
            &mut *tap,
            LifecycleControllerState::Rma,
            Some(lc_token_to_words(&DEFAULT_LIFECYCLE_RAW_TOKEN.0)),
        );
        let err = result.unwrap_err();
        let lcc_err = err.downcast_ref::<LccUtilError>().unwrap();
        let status = match lcc_err {
            LccUtilError::StatusErrors(status) => status,
            _ => panic!("Expected LccUtilError::StatusErrors, but got {:?}", lcc_err),
        };

        assert_eq!(
            *status,
            LcCtrlStatus::FLASH_RMA_ERROR | LcCtrlStatus::INITIALIZED
        );
    }

    #[test]
    fn test_manuf_debug_unlock() {
        let mut model = ss_setup(
            Some(LifecycleControllerState::Dev),
            /*debug_intent=*/ true,
            /*bootfsm_break=*/ true,
            /*enable_mcu_uart_log=*/ true,
        );

        // Connect to Caliptra Core JTAG TAP via OpenOCD.
        println!("Connecting to Core TAP ...");
        let jtag_params = JtagParams {
            openocd: PathBuf::from("openocd"),
            adapter_speed_khz: 1000,
            log_stdio: true,
        };
        let mut tap = model
            .jtag_tap_connect(&jtag_params, JtagTap::CaliptraCoreTap)
            .expect("Failed to connect to the Caliptra Core JTAG TAP.");
        println!("Connected.");

        // Check SS Debug Intent is active.
        let debug_intent = tap
            .read_reg(&CaliptraCoreReg::SsDebugIntent)
            .expect("Unable to read SS Debug Inteng.");
        println!("SS Debug Intent: {}", debug_intent);
        assert_eq!(debug_intent, 0x1);

        // Ensure another manuf debug unlock is not in progress.
        let ss_debug_manuf_response = tap
            .read_reg(&CaliptraCoreReg::SsDbgManufServiceRegRsp)
            .expect("Unable to read SsDbgManufServiceRegRes reg.");
        assert_eq!(ss_debug_manuf_response, 0);
        let mut ss_debug_manuf_request = tap
            .read_reg(&CaliptraCoreReg::SsDbgManufServiceRegReq)
            .expect("Unable to read SsDbgManufServiceRegReq reg.");
        assert_eq!(ss_debug_manuf_request, 0);

        // Request manuf debug unlock operation.
        println!("Request to initiate manuf debug unlock ...");
        tap.write_reg(&CaliptraCoreReg::SsDbgManufServiceRegReq, 0x1)
            .expect("Unable to write SsDbgManufServiceRegReq reg.");
        println!(
            "Manuf debug unlock request (before): 0x{:08x})",
            ss_debug_manuf_request
        );
        ss_debug_manuf_request = tap
            .read_reg(&CaliptraCoreReg::SsDbgManufServiceRegReq)
            .expect("Unable to read SsDbgManufServiceRegReq reg.");
        println!(
            "Manuf debug unlock request (after): 0x{:08x})",
            ss_debug_manuf_request
        );
        assert_eq!(ss_debug_manuf_request, 1);
        println!("Request sent.");

        // Continue Caliptra Core boot.
        tap.write_reg(&CaliptraCoreReg::BootfsmGo, 0x1)
            .expect("Unable to write BootfsmGo.");

        // Acquire the Caliptra Core mailbox lock.
        println!("Attempting to acquire Caliptra Core mailbox lock ...");
        let mut lock_acquired = false;
        while let Ok(mbox_lock) = tap.read_reg(&CaliptraCoreReg::MboxLock) {
            if (mbox_lock & 0x1) == 0 {
                lock_acquired = true;
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(lock_acquired, true);
        println!("Lock acquired.");

        // Program the manuf debug unlock token via the Caliptra Core mailbox.
        println!("Programming the manuf debug unlock token ...");
        tap.write_reg(&CaliptraCoreReg::MboxCmd, 0x4d445554)
            .expect("Unable to write MboxCmd reg.");
        tap.write_reg(
            &CaliptraCoreReg::MboxDlen,
            ((DEFAULT_MANUF_DEBUG_UNLOCK_RAW_TOKEN.0.len() + 1) * 4)
                .try_into()
                .unwrap(),
        )
        .expect("Unable to write MboxDlen reg.");
        tap.write_reg(&CaliptraCoreReg::MboxDin, 0xFFFFF8E2)
            .expect("Unable to write to MboxDin register.");
        for token_word in DEFAULT_MANUF_DEBUG_UNLOCK_RAW_TOKEN.0 {
            println!("Writing token word: 0x{:08x}.", token_word);
            tap.write_reg(&CaliptraCoreReg::MboxDin, token_word)
                .expect("Unable to write to MboxDin register.");
        }
        println!("Token programming complete.");

        // Executing the manuf debug unlock operation and wait for completion.
        println!("Executing the manuf debug unlock operation ...");
        tap.write_reg(&CaliptraCoreReg::MboxExecute, 0x1)
            .expect("Unable to write to MboxExecute register.");

        // Wait for debug unlock operation to complete.
        let mut ss_debug_manuf_success = false;
        while let Ok(ss_debug_manuf_response) =
            tap.read_reg(&CaliptraCoreReg::SsDbgManufServiceRegRsp)
        {
            if (ss_debug_manuf_response & 0x4) != 0 {
                println!(
                    "Manuf debug unlock operation in progress (response: 0x{:08x}) ...",
                    ss_debug_manuf_response
                );
            }
            if (ss_debug_manuf_response & 0x3) != 0 {
                println!(
                    "Manuf debug unlock operation complete (response: 0x{:08x}).",
                    ss_debug_manuf_response
                );
                assert_eq!(ss_debug_manuf_response, 0x1);
                ss_debug_manuf_success = true;
                break;
            }
            model.base.step();
            thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(ss_debug_manuf_success, true);
    }
}

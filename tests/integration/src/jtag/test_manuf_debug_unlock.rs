// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    use crate::jtag::test::{debug_is_unlocked, ss_setup};

    use caliptra_api::mailbox::CommandId;
    use caliptra_hw_model::jtag::CaliptraCoreReg;
    use caliptra_hw_model::openocd::openocd_jtag_tap::{JtagParams, JtagTap};
    use caliptra_hw_model::HwModel;
    use caliptra_hw_model::DEFAULT_MANUF_DEBUG_UNLOCK_RAW_TOKEN;
    use mcu_hw_model::jtag::{jtag_get_caliptra_mailbox_resp, jtag_send_caliptra_mailbox_cmd};
    use mcu_rom_common::LifecycleControllerState;

    use zerocopy::IntoBytes;

    #[test]
    fn test_manuf_debug_unlock() {
        let mut model = ss_setup(
            Some(LifecycleControllerState::Dev),
            /*rma_or_scrap_ppd=*/ false,
            /*debug_intent=*/ true,
            /*bootfsm_break=*/ true,
            /*enable_mcu_uart_log=*/ true,
        );

        // Connect to Caliptra Core and MCU JTAG TAPs via OpenOCD.
        let jtag_params = JtagParams {
            openocd: PathBuf::from("openocd"),
            adapter_speed_khz: 1000,
            log_stdio: true,
        };
        println!("Connecting to Core TAP ...");
        let mut core_tap = model
            .jtag_tap_connect(&jtag_params, JtagTap::CaliptraCoreTap)
            .expect("Failed to connect to the Caliptra Core JTAG TAP.");
        println!("Connected.");
        println!("Connecting to MCU TAP ...");
        let mut mcu_tap = model
            .jtag_tap_connect(&jtag_params, JtagTap::CaliptraMcuTap)
            .expect("Failed to connect to the Caliptra MCU JTAG TAP.");
        println!("Connected.");

        // Confirm debug is locked.
        let is_unlocked = debug_is_unlocked(&mut *core_tap, &mut *mcu_tap).unwrap_or(false);
        assert_eq!(is_unlocked, false);

        // Request manuf debug unlock operation.
        core_tap
            .write_reg(&CaliptraCoreReg::SsDbgManufServiceRegReq, 0x1)
            .expect("Unable to write SsDbgManufServiceRegReq reg.");
        model.base.step();

        // Continue Caliptra Core boot.
        core_tap
            .write_reg(&CaliptraCoreReg::BootfsmGo, 0x1)
            .expect("Unable to write BootfsmGo.");
        model.base.step();

        // Send the manuf debug unlock token.
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

        // Wait for debug unlock operation to complete.
        while let Ok(ss_debug_manuf_response) =
            core_tap.read_reg(&CaliptraCoreReg::SsDbgManufServiceRegRsp)
        {
            if (ss_debug_manuf_response & 0x3) != 0 {
                println!(
                    "Manuf debug unlock operation complete (response: 0x{:08x}).",
                    ss_debug_manuf_response
                );
                assert_eq!(ss_debug_manuf_response, 0x1);
                model.base.step();
                break;
            }
            model.base.step();
            thread::sleep(Duration::from_millis(100));
        }

        // Confirm debug is unlocked.
        core_tap
            .reexamine_cpu_target()
            .expect("Failed to reexamine CPU target.");
        core_tap
            .set_sysbus_access()
            .expect("Failed to set sysbus access.");
        mcu_tap
            .reexamine_cpu_target()
            .expect("Failed to reexamine CPU target.");
        mcu_tap
            .set_sysbus_access()
            .expect("Failed to set sysbus access.");
        let is_unlocked = debug_is_unlocked(&mut *core_tap, &mut *mcu_tap).unwrap_or(false);
        assert_eq!(is_unlocked, true);
    }
}

// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    use crate::jtag::test::ss_setup;

    use caliptra_api::mailbox::CommandId;
    use caliptra_hw_model::jtag::CaliptraCoreReg;
    use caliptra_hw_model::openocd::openocd_jtag_tap::{JtagParams, JtagTap};
    use caliptra_hw_model::HwModel;
    use caliptra_hw_model::DEFAULT_MANUF_DEBUG_UNLOCK_RAW_TOKEN;
    use mcu_hw_model::jtag::jtag_send_caliptra_mailbox_cmd;
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

        // Request manuf debug unlock operation.
        tap.write_reg(&CaliptraCoreReg::SsDbgManufServiceRegReq, 0x1)
            .expect("Unable to write SsDbgManufServiceRegReq reg.");
        model.base.step();

        // Continue Caliptra Core boot.
        tap.write_reg(&CaliptraCoreReg::BootfsmGo, 0x1)
            .expect("Unable to write BootfsmGo.");
        model.base.step();

        // Send the manuf debug unlock token.
        jtag_send_caliptra_mailbox_cmd(
            &mut *tap,
            CommandId::MANUF_DEBUG_UNLOCK_REQ_TOKEN,
            DEFAULT_MANUF_DEBUG_UNLOCK_RAW_TOKEN.0.as_bytes(),
        )
        .expect("Failed to send manuf debug unlock token.");
        model.base.step();

        // Wait for debug unlock operation to complete.
        while let Ok(ss_debug_manuf_response) =
            tap.read_reg(&CaliptraCoreReg::SsDbgManufServiceRegRsp)
        {
            if (ss_debug_manuf_response & 0x3) != 0 {
                println!(
                    "Manuf debug unlock operation complete (response: 0x{:08x}).",
                    ss_debug_manuf_response
                );
                assert_eq!(ss_debug_manuf_response, 0x1);
                break;
            }
            model.base.step();
            thread::sleep(Duration::from_millis(100));
        }
    }
}

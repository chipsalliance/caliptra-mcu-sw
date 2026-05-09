// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    use crate::jtag::test::ss_setup;

    use caliptra_hw_model::jtag::CaliptraCoreReg;
    use caliptra_hw_model::openocd::openocd_jtag_tap::{JtagParams, JtagTap};
    use caliptra_hw_model::HwModel;
    use mcu_hw_model::McuHwModel;
    use registers_generated::fuses::{
        SECRET_MANUF_PARTITION_BYTE_OFFSET, SECRET_MANUF_PARTITION_BYTE_SIZE,
    };
    use romtime::LifecycleControllerState;

    #[test]
    fn test_uds() {
        let mut model = ss_setup(
            Some(LifecycleControllerState::Dev),
            /*rma_or_scrap_ppd=*/ false,
            /*debug_intent=*/ false,
            /*bootfsm_break=*/ true,
            /*enable_mcu_uart_log=*/ true,
        );

        // check UDS is blank
        let before_uds = &model.read_otp_memory()[SECRET_MANUF_PARTITION_BYTE_OFFSET
            ..SECRET_MANUF_PARTITION_BYTE_OFFSET + SECRET_MANUF_PARTITION_BYTE_SIZE];
        assert!(before_uds.iter().all(|&b| b == 0));
        println!("Before UDS: {:02x?}", before_uds);

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

        // Request UDS programming.
        tap.write_reg(&CaliptraCoreReg::SsDbgManufServiceRegReq, 4)
            .expect("Unable to write SsDbgManufServiceRegReq reg.");
        model.base.step();

        // Continue Caliptra Core boot.
        tap.write_reg(&CaliptraCoreReg::BootfsmGo, 0x1)
            .expect("Unable to write BootfsmGo.");
        model.base.step();

        // Wait for UDS programming operation to complete.
        while let Ok(ss_debug_manuf_response) =
            tap.read_reg(&CaliptraCoreReg::SsDbgManufServiceRegRsp)
        {
            if (ss_debug_manuf_response & 0x40) != 0 {
                println!(
                    "UDS programming complete (response: 0x{:08x}).",
                    ss_debug_manuf_response
                );
                assert_eq!(ss_debug_manuf_response, 0x40);
                break;
            }
            model.base.step();
            // UDS programming is very fast
            thread::sleep(Duration::from_millis(1));
        }
        // process the logs
        model.base.step();
        let after_uds = &model.read_otp_memory()[SECRET_MANUF_PARTITION_BYTE_OFFSET
            ..SECRET_MANUF_PARTITION_BYTE_OFFSET + SECRET_MANUF_PARTITION_BYTE_SIZE];

        println!("After UDS: {:02x?}", after_uds);
        assert!(!after_uds.iter().all(|&b| b == 0));
    }
}

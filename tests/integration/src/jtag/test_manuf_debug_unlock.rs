// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    use crate::jtag::test::{
        debug_is_unlocked, halt, resume, ss_setup, sysbus_write_read, wait_status, write_csr_reg,
        ALLHALTED_MASK,
    };

    use caliptra_api::mailbox::CommandId;
    use caliptra_hw_model::jtag::{CaliptraCoreReg, CsrReg};
    use caliptra_hw_model::openocd::openocd_jtag_tap::{JtagParams, JtagTap};
    use caliptra_hw_model::HwModel;
    use caliptra_hw_model::DEFAULT_MANUF_DEBUG_UNLOCK_RAW_TOKEN;
    use mcu_config_fpga::FPGA_MEMORY_MAP;
    use mcu_hw_model::jtag::{jtag_get_caliptra_mailbox_resp, jtag_send_caliptra_mailbox_cmd};
    use romtime::LifecycleControllerState;

    use zerocopy::IntoBytes;

    const PRG_OFFSET: u32 = 0x100;
    const PRG_ADDRESS: u32 = FPGA_MEMORY_MAP.sram_offset | PRG_OFFSET;
    const RV32_INSTS: &[u32] = &[
        0x00100513,                                                             // addi x10, x0, 1
        0x00200593,                                                             // addi x11, x0, 2
        0x00b50533,                                                             // add x10, x10, x11
        0x00000637 | (FPGA_MEMORY_MAP.sram_offset & 0xFFFFF000), // lui x12 0xa8c00 (sram base addr)
        0x00a62023 | (PRG_OFFSET & 0x1F) << 7 | (PRG_OFFSET >> 5 & 0x7F) << 25, // sw x10, 0x100(x12)
        0x00100073,                                                             // ebreak
    ];

    const DCSR_SET_EBREAKM: u32 = 0x8003; // to enable debug mode on an ebreak

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

        halt(&mut mcu_tap).expect("Failed to halt MCU");

        // Write program to SRAM (MCU should be halted)
        assert!(matches!(
            sysbus_write_read(&mut *mcu_tap, FPGA_MEMORY_MAP.sram_offset, RV32_INSTS),
            Ok(true)
        ));

        // set PC to start of SRAM
        write_csr_reg(&mut mcu_tap, CsrReg::Dpc, FPGA_MEMORY_MAP.sram_offset)
            .expect("Failed to set PC");

        // Write DCSR to enable ebreakm (bit 15) so ebreak enters debug mode
        write_csr_reg(&mut mcu_tap, CsrReg::Dcsr, DCSR_SET_EBREAKM)
            .expect("Failed to set DCSR to enable debug mode on ebreak");

        resume(&mut mcu_tap).expect("Failed to resume MCU");
        wait_status(&mut mcu_tap, ALLHALTED_MASK, Duration::from_secs(3))
            .expect("MCU did not halt after executing instructions");

        assert_eq!(
            mcu_tap
                .read_memory_32(PRG_ADDRESS)
                .expect("Failed to readback from MCU SRAM"),
            3
        )
    }
}

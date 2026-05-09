// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use mcu_hw_model::{McuHwModel, McuManager};
    use std::sync::atomic::Ordering;

    const MAX_ZEROIZATION_CYCLES: u64 = 500_000_000;

    /// Test that the FIPS zeroization flow writes 0xFFFF_FFFF to the
    /// FC_FIPS_ZEROZATION mask register on cold boot when the PPD signal
    /// is asserted, and (on FPGA) that the UDS and field-entropy OTP
    /// partitions are set to all-ones.
    ///
    /// The ROM detects the PPD signal early in the cold-boot flow and sets
    /// the mask before `SS_CONFIG_DONE_STICKY` locks the register.
    #[test]
    fn test_fips_zeroization_cold_boot() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            rom_only: true,
            fips_zeroization: true,
            ..Default::default()
        });

        // Poll until the ROM writes the zeroization mask or we time out.
        //
        // We cannot use `mci_boot_checkpoint() >= FipsZeroizationComplete`
        // because boot-flow checkpoint values (e.g. ColdBootFlowStarted =
        // 385) are numerically larger than the zeroization checkpoints and
        // would satisfy the condition before the mask is actually written.
        hw.step_until(|hw| {
            let mask = hw
                .mcu_manager()
                .with_mci(|mci| mci.fc_fips_zerozation().read());
            mask == 0xFFFF_FFFF || hw.cycle_count() >= MAX_ZEROIZATION_CYCLES
        });

        let mask = hw
            .mcu_manager()
            .with_mci(|mci| mci.fc_fips_zerozation().read());
        assert_eq!(
            mask, 0xFFFF_FFFF,
            "FC_FIPS_ZEROZATION mask should be 0xFFFF_FFFF, got {:#010x}",
            mask,
        );

        // On FPGA the Caliptra core and fuse controller share a single
        // physical OTP, so after ZEROIZE_UDS_FE the secret partitions
        // (UDS seed, field entropy 0-3) including their digest and
        // zeroize fields must read back as all 0xFF.
        //
        // In the emulator the Caliptra sw-emulator has its own fuse-bank
        // memory that is separate from the MCU emulator's OTP partitions,
        // so this check is only meaningful on real hardware.
        if cfg!(feature = "fpga_realtime") {
            use registers_generated::fuses::{
                SECRET_MANUF_PARTITION_BYTE_OFFSET, SECRET_MANUF_PARTITION_BYTE_SIZE,
                SECRET_PROD_PARTITION_0_BYTE_OFFSET, SECRET_PROD_PARTITION_0_BYTE_SIZE,
                SECRET_PROD_PARTITION_1_BYTE_OFFSET, SECRET_PROD_PARTITION_1_BYTE_SIZE,
                SECRET_PROD_PARTITION_2_BYTE_OFFSET, SECRET_PROD_PARTITION_2_BYTE_SIZE,
                SECRET_PROD_PARTITION_3_BYTE_OFFSET, SECRET_PROD_PARTITION_3_BYTE_SIZE,
            };

            let otp = hw.read_otp_memory();

            let partitions: &[(&str, usize, usize)] = &[
                (
                    "SECRET_MANUF (UDS)",
                    SECRET_MANUF_PARTITION_BYTE_OFFSET,
                    SECRET_MANUF_PARTITION_BYTE_SIZE,
                ),
                (
                    "SECRET_PROD_0 (FE0)",
                    SECRET_PROD_PARTITION_0_BYTE_OFFSET,
                    SECRET_PROD_PARTITION_0_BYTE_SIZE,
                ),
                (
                    "SECRET_PROD_1 (FE1)",
                    SECRET_PROD_PARTITION_1_BYTE_OFFSET,
                    SECRET_PROD_PARTITION_1_BYTE_SIZE,
                ),
                (
                    "SECRET_PROD_2 (FE2)",
                    SECRET_PROD_PARTITION_2_BYTE_OFFSET,
                    SECRET_PROD_PARTITION_2_BYTE_SIZE,
                ),
                (
                    "SECRET_PROD_3 (FE3)",
                    SECRET_PROD_PARTITION_3_BYTE_OFFSET,
                    SECRET_PROD_PARTITION_3_BYTE_SIZE,
                ),
            ];

            for &(name, offset, size) in partitions {
                let region = &otp[offset..offset + size];
                assert!(
                    region.iter().all(|&b| b == 0xFF),
                    "{name} partition (offset {offset:#x}, size {size:#x}) should be \
                     all 0xFF after zeroization, but found non-0xFF bytes",
                );
            }
        }

        lock.fetch_add(1, Ordering::Relaxed);
    }
}

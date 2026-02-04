// Licensed under the Apache-2.0 license

//! Integration tests for the Network Coprocessor CPU.
//!
//! These tests verify that the Network Coprocessor can boot and execute code correctly.
//! The Network CPU is a dedicated RISC-V coprocessor that runs alongside the MCU and Caliptra.

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use mcu_hw_model::McuHwModel;

    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_cpu_rom_start() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Create the hardware model with network ROM using start_runtime_hw_model
        let mut hw = start_runtime_hw_model(TestParams {
            include_network_rom: true,
            rom_only: true, // Don't wait for full runtime boot
            ..Default::default()
        });

        // Verify network CPU was initialized
        assert!(
            hw.has_network_cpu(),
            "Network CPU should be initialized when include_network_rom is true"
        );

        // Run the model until the network CPU prints the ROM start message
        const MAX_CYCLES: u64 = 200_000;
        hw.step_until(|m| {
            if m.cycle_count() >= MAX_CYCLES {
                return true;
            }

            // Check if network CPU has printed the ROM start message
            if let Some(output) = m.network_uart_output() {
                if output.contains("Network Coprocessor ROM Started!") {
                    return true;
                }
            }
            false
        });

        // Check the network CPU UART output
        let output = hw
            .network_uart_output()
            .expect("Network CPU should have UART output");
        println!("Network CPU UART output:\n{}", output);

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

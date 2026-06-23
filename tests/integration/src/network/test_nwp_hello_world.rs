// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_hw_model::McuHwModel;

    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_nwp_hello_world() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            include_network_rom: true,
            rom_only: true,
            network_rom_feature: Some("test-hello-world"),
            ..Default::default()
        });

        assert!(hw.has_network_cpu(), "Network CPU should be initialized");

        const MAX_CYCLES: u64 = 200_000;
        hw.step_until(|m| {
            if m.cycle_count() >= MAX_CYCLES {
                return true;
            }
            if let Some(output) = m.network_uart_output() {
                if output.contains("NWP Hello World OK") {
                    return true;
                }
            }
            false
        });

        let output = hw
            .network_uart_output()
            .expect("Network CPU should have UART output");
        println!("Network CPU UART output:\n{}", output);

        assert!(
            output.contains("NWP Hello World OK"),
            "Should contain hello world message"
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

// Licensed under the Apache-2.0 license

#[cfg(all(test, feature = "fpga_realtime"))]
mod test {
    use crate::test_log_flash_usermode::test::run_logging_test;

    #[test]
    fn test_log_ram_usermode() {
        run_logging_test("test-log-ram-usermode", true);
    }

    #[test]
    fn test_log_ram_linear() {
        run_logging_test("test-log-ram-linear", true);
    }
}

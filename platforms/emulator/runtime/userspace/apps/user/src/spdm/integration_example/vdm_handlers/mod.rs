// Licensed under the Apache-2.0 license

pub mod ide_km_driver;
pub mod tdisp_driver;

/// Simple helper to create test drivers
///
/// Returns a tuple of (TDISP driver, IDE-KM driver)
pub fn create_test_pci_sig_drivers() -> (tdisp_driver::TestTdispDriver, ide_km_driver::TestIdeDriver)
{
    (
        tdisp_driver::TestTdispDriver::new(),
        ide_km_driver::TestIdeDriver::default(),
    )
}

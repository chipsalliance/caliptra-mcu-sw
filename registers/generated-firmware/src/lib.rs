// Licensed under the Apache-2.0 license

#![no_std]
#![recursion_limit = "2048"]

#[cfg(hw_rev = "2.1")]
#[path = "rev_2_1/lib.rs"]
mod selected;
#[cfg(hw_rev = "latest")]
#[path = "latest/lib.rs"]
mod selected;

pub use selected::*;
pub const HARDWARE_REVISION: &str = env!("CALIPTRA_MCU_HW_REV");

#[cfg(all(test, hw_rev = "latest"))]
mod usb_baseline_tests;

#[test]
fn selected_revision_matches_requested_revision() {
    assert_eq!(
        HARDWARE_REVISION,
        option_env!("CALIPTRA_HW_REV").unwrap_or("2.1")
    );
}

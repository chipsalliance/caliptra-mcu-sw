// Licensed under the Apache-2.0 license.

#[cfg(feature = "test-i3c-echo")]
pub(crate) fn run_test_i3c_echo() -> Option<u32> {
    // Safety: this is run after the board has initialized the chip.
    let chip = unsafe { crate::CHIP.unwrap() };
    caliptra_mcu_platforms_common::tests::i3c_target_test::test_i3c_echo(chip)
}

#[cfg(feature = "test-i3c-simple")]
pub(crate) fn run_test_i3c_simple() -> Option<u32> {
    // Safety: this is run after the board has initialized the chip.
    let chip = unsafe { crate::CHIP.unwrap() };
    caliptra_mcu_platforms_common::tests::i3c_target_test::test_i3c_simple(chip)
}

#[cfg(feature = "test-i3c-constant-writes")]
pub(crate) fn run_test_i3c_constant_writes() -> Option<u32> {
    // Safety: this is run after the board has initialized the chip.
    let chip = unsafe { crate::CHIP.unwrap() };
    caliptra_mcu_platforms_common::tests::i3c_target_test::test_i3c_constant_writes(chip)
}

// Licensed under the Apache-2.0 license.

pub(crate) fn run_test_i3c_simple() -> Option<u32> {
    // Safety: this is run after the board has initialized the chip.
    let chip = unsafe { crate::CHIP.unwrap() };
    mcu_platforms_common::tests::i3c_target_test::test_i3c_simple(chip)
}

pub(crate) fn run_test_i3c_constant_writes() -> Option<u32> {
    // Safety: this is run after the board has initialized the chip.
    let chip = unsafe { crate::CHIP.unwrap() };
    mcu_platforms_common::tests::i3c_target_test::test_i3c_constant_writes(chip)
}

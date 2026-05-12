// Licensed under the Apache-2.0 license

use caliptra_cfi_lib::{cfi_assert_eq, cfi_launder, CfiCounter};
use tock_registers::fields::FieldValue;
use tock_registers::interfaces::Writeable;
use tock_registers::{registers::ReadWrite, RegisterLongName};

pub fn cfi_set_register<R: RegisterLongName>(reg: &ReadWrite<u32, R>, val: u32) {
    let val_copy = cfi_launder(val);
    reg.set(val);
    CfiCounter::delay();
    reg.set(val_copy);
    cfi_assert_eq(val_copy, val);
}

#[inline]
pub fn cfi_write_register<R: RegisterLongName>(reg: &ReadWrite<u32, R>, field: FieldValue<u32, R>) {
    cfi_set_register(reg, field.value);
}

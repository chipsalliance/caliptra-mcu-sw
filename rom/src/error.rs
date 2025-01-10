// Licensed under the Apache-2.0 license

#[allow(dead_code)]
#[repr(u32)]
#[derive(Debug)]
pub enum MCUError {
    InvalidDataError = 0xf000_0001,
    FusesError = 0xf000_0002,
}

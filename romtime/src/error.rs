// Licensed under the Apache-2.0 license

#[allow(dead_code)]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McuError {
    InvalidDataError = 0xf000_0001,
    FusesError = 0xf000_0002,
}

impl From<McuError> for u32 {
    fn from(error: McuError) -> Self {
        error as u32
    }
}

use crate::hil::MemoryRegion;
use kernel::ErrorCode;

pub struct McuMbox0Sram {}

impl MemoryRegion<'_> for McuMbox0Sram {
    fn write(&self, _offset: usize, _data: &[u8]) -> Result<(), ErrorCode> {
        Err(kernel::ErrorCode::FAIL)
    }

    fn read(&self, _offset: usize, _data: &mut [u8]) -> Result<(), ErrorCode> {
        Err(kernel::ErrorCode::FAIL)
    }
}


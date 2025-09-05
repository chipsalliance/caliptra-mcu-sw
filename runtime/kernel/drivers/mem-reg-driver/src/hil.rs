// Licensed under the Apache-2.0 license

//! HIL Interface for MCU MemoryRegion Communication

use kernel::ErrorCode;


pub trait MemoryRegion<'a> {
    fn write(
        &self,
        offset: usize,
        data: &[u8],
    ) -> Result<(), ErrorCode>;

    fn read(
        &self,
        offset: usize,
        data: &'a mut [u8],
    ) -> Result<(), ErrorCode>;
}

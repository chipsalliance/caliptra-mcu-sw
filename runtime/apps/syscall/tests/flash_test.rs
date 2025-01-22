// Licensed under the Apache-2.0 license

#[cfg(test)]
mod tests {
    use libsyscall_caliptra::flash::{driver_num, SpiFlash};
    use libtock_unittest::fake::{wait_for_future_ready, FakeFlashDriver, Kernel, Syscalls};
    use std::rc::Rc;

    #[test]
    // Read and write 4096 bytes of flash memory residing in the address 0x0 in chunks of 256 bytes.
    // And writing the same data to address 8192.
    fn test_flash_read_write() {
        // Create the fake kernel and add the fake driver
        let fake_kernel = Kernel::new();
        let fake_driver = FakeFlashDriver::new();

        // Add the fake driver to the kernel
        let fake_driver_rc = Rc::new(fake_driver);
        fake_kernel.add_driver(&fake_driver_rc);
        fake_driver_rc.set_flash_content(vec![0xFF; 16384]); // Initialize flash with 16384 bytes of 0xFF

        let flash_syscall = SpiFlash::<Syscalls>::new(driver_num::IMAGE_PARTITION);
        let mut remaining_size = 4096;
        let mut current_offset = 0;
        let mut current_address = 8192;
        const CHUNK_SIZE: usize = 256;

        while remaining_size > 0 {
            let transfer_size = remaining_size.min(CHUNK_SIZE);
            let mut buffer = [0; CHUNK_SIZE];

            let read_future =
                Box::pin(flash_syscall.read(current_offset, transfer_size, &mut buffer));
            let _ = wait_for_future_ready(read_future);

            let write_future =
                Box::pin(flash_syscall.write(current_address, transfer_size, &buffer));
            let _ = wait_for_future_ready(write_future);
            remaining_size -= transfer_size;
            current_offset += transfer_size;
            current_address += CHUNK_SIZE;
        }
    }
}

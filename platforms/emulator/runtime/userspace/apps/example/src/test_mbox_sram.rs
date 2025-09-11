// Licensed under the Apache-2.0 license

use core::fmt::Write;
use libsyscall_caliptra::{
    mbox_sram::{MboxSram, DRIVER_NUM_MCU_MBOX1_SRAM},
    DefaultSyscalls,
};
use romtime::println;

#[allow(unused)]
pub(crate) async fn test_mem_reg_read_write() {
    println!("Starting test_mem_reg_read_write");
    let mem_reg: MboxSram<DefaultSyscalls> = MboxSram::new(DRIVER_NUM_MCU_MBOX1_SRAM);

    mem_reg.acquire_lock().unwrap();
    let write_buffer = {
        let mut buf = [0u8; 64];
        for i in 0..64 {
            buf[i] = i as u8;
        }
        buf
    };
    mem_reg.write(0, &write_buffer).await.unwrap();

    let mut read_buffer = [0u8; 64];
    mem_reg.read(0, &mut read_buffer).await.unwrap();
    assert_eq!(write_buffer, read_buffer);
    mem_reg.release_lock().unwrap();
}

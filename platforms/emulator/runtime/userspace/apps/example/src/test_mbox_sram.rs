// Licensed under the Apache-2.0 license

use caliptra_mcu_libsyscall_caliptra::{
    mbox_sram::{MboxSram, DRIVER_NUM_MCU_MBOX1_SRAM},
    DefaultSyscalls,
};
use caliptra_mcu_libtock_alarm::Ticks;
use caliptra_mcu_libtock_platform::ErrorCode;
use caliptra_mcu_romtime::println;
use core::fmt::Write;

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

    let partial = [1, 2, 3, 4, 5, 6];
    mem_reg.write(1, &partial).await.unwrap();
    let mut partial_read = [0xff; 6];
    mem_reg.read(1, &mut partial_read).await.unwrap();
    assert_eq!(partial_read, [1, 2, 3, 4, 0xff, 0xff]);
    mem_reg.release_lock().unwrap();

    assert_eq!(
        mem_reg.write(usize::MAX, &write_buffer).await,
        Err(ErrorCode::Invalid)
    );
    // Let the failed command's deferred completion release the capsule.
    crate::AsyncAlarm::<DefaultSyscalls>::sleep_for(Ticks(2000))
        .await
        .unwrap();
    assert_eq!(
        mem_reg.read(usize::MAX, &mut read_buffer).await,
        Err(ErrorCode::Invalid)
    );
}

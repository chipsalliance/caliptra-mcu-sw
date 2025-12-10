// Licensed under the Apache-2.0 license

use libsyscall_caliptra::flash::{FlashCapacity, SpiFlash};
#[allow(unused)]
use mcu_config_emulator::flash::{IMAGE_A_PARTITION, IMAGE_B_PARTITION};
#[allow(unused)]
use mcu_config_fpga::flash::STAGING_PARTITION;

const BUF_LEN: usize = 1024;
const EXPECTED_CHUNK_SIZE: usize = 512;

struct FlashTestConfig<'a> {
    drv_num: u32,
    expected_capacity: FlashCapacity,
    expected_chunk_size: usize,
    e_offset: usize,
    e_len: usize,
    w_offset: usize,
    w_len: usize,
    p_offset: usize,
    w_buf: &'a [u8],
    r_buf: &'a mut [u8],
}

#[cfg(feature = "test-flash-usermode")]
pub async fn test_flash_usermode_emulator() {
    let mut user_r_buf: [u8; BUF_LEN] = [0u8; BUF_LEN];
    // Fill the write buffer with a pattern
    let user_w_buf: [u8; BUF_LEN] = {
        let mut buf = [0u8; BUF_LEN];
        for i in 0..buf.len() {
            buf[i] = (i % 256) as u8;
        }
        buf
    };

    let mut test_cfg_1 = FlashTestConfig {
        drv_num: IMAGE_A_PARTITION.driver_num,
        expected_capacity: FlashCapacity(IMAGE_A_PARTITION.size as u32),
        expected_chunk_size: EXPECTED_CHUNK_SIZE,
        e_offset: IMAGE_A_PARTITION.offset,
        e_len: BUF_LEN,
        w_offset: IMAGE_A_PARTITION.offset + 20,
        p_offset: IMAGE_A_PARTITION.offset,
        w_len: 1000,
        w_buf: &user_w_buf,
        r_buf: &mut user_r_buf,
    };
    simple_test(&mut test_cfg_1).await;

    let mut test_cfg_2 = FlashTestConfig {
        drv_num: IMAGE_B_PARTITION.driver_num,
        expected_capacity: FlashCapacity(IMAGE_B_PARTITION.size as u32),
        expected_chunk_size: EXPECTED_CHUNK_SIZE,
        e_offset: IMAGE_B_PARTITION.offset,
        e_len: BUF_LEN,
        w_offset: IMAGE_B_PARTITION.offset + 20,
        p_offset: IMAGE_B_PARTITION.offset,
        w_len: 1000,
        w_buf: &user_w_buf,
        r_buf: &mut user_r_buf,
    };
    simple_test(&mut test_cfg_2).await;
}

#[cfg(feature = "test-fpga-flash-ctrl")]
pub async fn test_flash_usermode_fpga() {
    let mut user_r_buf: [u8; BUF_LEN] = [0u8; BUF_LEN];
    // Fill the write buffer with a pattern
    let user_w_buf: [u8; BUF_LEN] = {
        let mut buf = [0u8; BUF_LEN];
        for i in 0..buf.len() {
            buf[i] = (i % 256) as u8;
        }
        buf
    };

    let mut test_cfg_1 = FlashTestConfig {
        drv_num: STAGING_PARTITION.driver_num,
        expected_capacity: FlashCapacity(STAGING_PARTITION.size as u32),
        expected_chunk_size: EXPECTED_CHUNK_SIZE,
        e_offset: STAGING_PARTITION.offset,
        e_len: BUF_LEN,
        w_offset: STAGING_PARTITION.offset + 20,
        p_offset: STAGING_PARTITION.offset,
        w_len: 1000,
        w_buf: &user_w_buf,
        r_buf: &mut user_r_buf,
    };
    simple_test(&mut test_cfg_1).await;
}

async fn simple_test<'a>(test_cfg: &'a mut FlashTestConfig<'a>) {
    let flash_par: SpiFlash = SpiFlash::new(test_cfg.drv_num);
    assert_eq!(
        flash_par.get_capacity().unwrap(),
        test_cfg.expected_capacity
    );
    assert_eq!(
        flash_par.get_chunk_size().unwrap(),
        test_cfg.expected_chunk_size
    );

    let ret = flash_par.erase(test_cfg.e_offset, test_cfg.e_len).await;
    assert_eq!(ret, Ok(()));

    // Write test region partially
    let ret = flash_par
        .write(test_cfg.w_offset, test_cfg.w_len, test_cfg.w_buf as &[u8])
        .await;
    assert_eq!(ret, Ok(()));

    // Read the written region
    let ret = flash_par
        .read(
            test_cfg.w_offset,
            test_cfg.w_len,
            test_cfg.r_buf as &mut [u8],
        )
        .await;
    assert_eq!(ret, Ok(()));

    // Data compare read and write
    for i in 0..test_cfg.w_len {
        assert_eq!(
            test_cfg.r_buf[i], test_cfg.w_buf[i],
            "data mismatch at {}",
            i
        );
    }

    // Reset read buffer
    test_cfg.r_buf.iter_mut().for_each(|x| *x = 0);

    // Read whole test region
    let ret = flash_par
        .read(
            test_cfg.e_offset,
            test_cfg.e_len,
            test_cfg.r_buf as &mut [u8],
        )
        .await;
    assert_eq!(ret, Ok(()));

    // Data integrity check
    {
        for i in 0..(test_cfg.w_offset - test_cfg.p_offset).min(test_cfg.r_buf.len()) {
            assert_eq!(test_cfg.r_buf[i], 0xFF, "data mismatch at {}", i);
        }

        for i in test_cfg.w_offset..(test_cfg.w_offset + test_cfg.w_len).min(test_cfg.r_buf.len()) {
            assert_eq!(
                test_cfg.r_buf[i - test_cfg.p_offset],
                test_cfg.w_buf[i - test_cfg.w_offset],
                "data mismatch at {}",
                i
            );
        }

        for i in (test_cfg.w_offset - test_cfg.p_offset + test_cfg.w_len).min(test_cfg.r_buf.len())
            ..test_cfg.e_len.min(test_cfg.r_buf.len())
        {
            assert_eq!(test_cfg.r_buf[i], 0xFF, "data mismatch at {}", i);
        }
    }
}

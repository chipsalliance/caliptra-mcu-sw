// Licensed under the Apache-2.0 license

use crate::flash::flash_api::FlashPartition;
use romtime::{println, test_exit};

pub fn test_rom_flash_access(partition: &FlashPartition) {
    println!("test_rom_flash_access on {:?} started", partition.name());
    // Test flash access: erase, write, read, arbitrary length of data 1024 bytes.
    // Execute the test multiple times with different start addresses.
    const TEST_DATA_SIZE: usize = 1024;
    const NUM_ITER: usize = 4;
    const ADDR_STEP: usize = 0x1000;

    for iter in 0..NUM_ITER {
        let mut test_data = [0u8; TEST_DATA_SIZE];
        for i in 0..test_data.len() {
            test_data[i] = (i & 0xFF) as u8;
        }
        let start_addr = 0x50 + iter * ADDR_STEP;
        let mut read_buf = [0u8; TEST_DATA_SIZE];

        // Erase the flash
        let ret = partition.erase(start_addr, test_data.len());
        if let Err(e) = ret {
            println!("Flash erase failed at addr {:#x}: {:?}", start_addr, e);
            test_exit(1);
        }

        // Write the data to flash
        let ret = partition.write(start_addr, &test_data);
        if let Err(e) = ret {
            println!("Flash write failed at addr {:#x}: {:?}", start_addr, e);
            test_exit(1);
        }

        // Read the data back from flash
        let ret = partition.read(start_addr, &mut read_buf);
        if let Err(e) = ret {
            println!("Flash read failed at addr {:#x}: {:?}", start_addr, e);
            test_exit(1);
        }

        // Verify the data
        for i in 0..test_data.len() {
            if read_buf[i] != test_data[i] {
                println!(
                    "Flash data mismatch at iter {}, index {}: expected {:02x}, got {:02x}",
                    iter, i, test_data[i], read_buf[i]
                );
                test_exit(1);
            }
        }
    }
    println!("test_rom_flash_access on {:?} passed", partition.name());
    test_exit(0);
}

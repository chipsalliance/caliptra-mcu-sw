// Licensed under the Apache-2.0 license

use caliptra_mcu_libsyscall_caliptra::external_otp::ExternalOtp;
use caliptra_mcu_libsyscall_caliptra::system::System;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_romtime::println;

#[allow(unused)]
pub(crate) fn test_external_otp() {
    println!("Starting test_external_otp");

    let otp = ExternalOtp::<DefaultSyscalls>::new();

    // Verify the driver exists.
    otp.exists().unwrap();
    println!("  exists: ok");

    // Check partition count.
    let count = otp.partition_count().unwrap();
    assert!(count >= 2, "expected at least 2 partitions, got {}", count);
    println!("  partition_count: {}", count);

    // Partition 0x01: ECC Cert (548 bytes).
    let ecc_size = otp.partition_size(0x01).unwrap();
    assert_eq!(
        ecc_size, 548,
        "expected ECC partition size 548, got {}",
        ecc_size
    );
    println!("  partition 0x01 size: {}", ecc_size);

    // Partition 0x02: MLDSA signature (4627 bytes).
    let mldsa_size = otp.partition_size(0x02).unwrap();
    assert_eq!(
        mldsa_size, 4627,
        "expected MLDSA partition size 4627, got {}",
        mldsa_size
    );
    println!("  partition 0x02 size: {}", mldsa_size);

    // Write a u32 to partition 0x01 at offset 0.
    let test_val: u32 = 0xDEAD_BEEF;
    otp.write(0x01, 0, test_val).unwrap();
    println!("  write 0x{:08X} to partition 0x01 offset 0: ok", test_val);

    // Read it back.
    let read_val = otp.read(0x01, 0).unwrap();
    assert_eq!(
        read_val, test_val,
        "read mismatch: expected 0x{:08X}, got 0x{:08X}",
        test_val, read_val
    );
    println!("  read back 0x{:08X}: ok", read_val);

    // Write and read at a different offset within the same partition.
    let test_val2: u32 = 0xCAFE_BABE;
    otp.write(0x01, 4, test_val2).unwrap();
    let read_val2 = otp.read(0x01, 4).unwrap();
    assert_eq!(read_val2, test_val2, "read mismatch at offset 4");
    println!("  write/read at offset 4: ok");

    // Verify the first write was not corrupted.
    let read_val_again = otp.read(0x01, 0).unwrap();
    assert_eq!(
        read_val_again, test_val,
        "first write corrupted after second write"
    );
    println!("  re-read offset 0 still correct: ok");

    // Write to partition 0x02 (MLDSA).
    let test_val3: u32 = 0x1234_5678;
    otp.write(0x02, 0, test_val3).unwrap();
    let read_val3 = otp.read(0x02, 0).unwrap();
    assert_eq!(read_val3, test_val3, "partition 0x02 read mismatch");
    println!("  partition 0x02 write/read: ok");

    // Out-of-bounds read should fail.
    let oob_result = otp.read(0x01, ecc_size);
    assert!(
        oob_result.is_err(),
        "expected out-of-bounds error for read at offset {}",
        ecc_size
    );
    println!("  out-of-bounds read rejected: ok");

    // Out-of-bounds write should fail.
    let oob_write = otp.write(0x01, ecc_size, 0);
    assert!(
        oob_write.is_err(),
        "expected out-of-bounds error for write at offset {}",
        ecc_size
    );
    println!("  out-of-bounds write rejected: ok");

    // Invalid partition should fail.
    let bad_part = otp.read(0xFF, 0);
    assert!(bad_part.is_err(), "expected error for invalid partition");
    println!("  invalid partition rejected: ok");

    // --- Lock partition tests ---

    // Partition 0x01 should not be locked yet.
    assert!(
        !otp.is_partition_locked(0x01).unwrap(),
        "partition 0x01 should not be locked before lock_partition"
    );
    println!("  partition 0x01 not locked initially: ok");

    // Lock partition 0x01.
    otp.lock_partition(0x01).unwrap();
    println!("  lock_partition(0x01): ok");

    // Partition 0x01 should now be locked.
    assert!(
        otp.is_partition_locked(0x01).unwrap(),
        "partition 0x01 should be locked after lock_partition"
    );
    println!("  partition 0x01 is locked: ok");

    // Reads should still work on a locked partition.
    let read_after_lock = otp.read(0x01, 0).unwrap();
    assert_eq!(
        read_after_lock, test_val,
        "read after lock should still work"
    );
    println!("  read after lock: ok");

    // Writes to a locked partition should fail.
    let write_after_lock = otp.write(0x01, 8, 0xAAAA_BBBB);
    assert!(
        write_after_lock.is_err(),
        "write to locked partition should fail"
    );
    println!("  write to locked partition rejected: ok");

    // Partition 0x02 should still be writable (not locked).
    assert!(
        !otp.is_partition_locked(0x02).unwrap(),
        "partition 0x02 should not be locked"
    );
    let test_val4: u32 = 0xBBBB_CCCC;
    otp.write(0x02, 4, test_val4).unwrap();
    let read_val4 = otp.read(0x02, 4).unwrap();
    assert_eq!(read_val4, test_val4, "partition 0x02 write after 0x01 lock");
    println!("  partition 0x02 still writable after 0x01 lock: ok");

    println!("test_external_otp passed");
}

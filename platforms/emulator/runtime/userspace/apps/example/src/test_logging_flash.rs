// Licensed under the Apache-2.0 license

// NOTE: Do not call `caliptra_mcu_romtime::println!` from this test. On the
// emulator the printer is wired to a UART MMIO register at 0x1000_1041; on
// the FPGA that address is unmapped and forbidden by user-mode PMP, so any
// `println!` here would fault the test process on real hardware. Test
// success is reported via the process exit code from `main`, not via stdout.
use caliptra_mcu_config_emulator::flash::{
    LOGGING_FLASH_DRIVER_NUMS, LOGGING_FLASH_INSTANCE_COUNT,
};
use caliptra_mcu_libsyscall_caliptra::logging::LoggingSyscall;

pub async fn test_logging_flash_simple() {
    let log: LoggingSyscall = LoggingSyscall::default();

    assert!(log.exists().is_ok(), "Logging driver doesn't exist");
    assert!(log.get_capacity().is_ok(), "Failed to get logging capacity");
    assert!(log.seek_beginning().await.is_ok(), "Seek beginning failed");
    assert!(log.clear().await.is_ok(), "Clear log failed");

    // Prepare a simple entry to append.
    let mut entry = [0u8; 64];
    for i in 0..entry.len() {
        entry[i] = b'A' + (i % 26) as u8;
    }

    assert!(
        log.append_entry(&entry).await.is_ok(),
        "Failed to append entry"
    );

    let mut buffer = [0u8; 256];
    let read_result = log.read_entry(&mut buffer).await;
    assert!(read_result.is_ok(), "Failed to read back the entry");
    let len = read_result.unwrap();
    assert!(buffer[..len] == entry[..len], "Entry mismatch");
}

pub async fn test_logging_flash_various_entries() {
    let log: LoggingSyscall = LoggingSyscall::default();
    assert!(log.exists().is_ok(), "Logging driver doesn't exist");
    assert!(log.get_capacity().is_ok(), "Failed to get logging capacity");
    assert!(log.seek_beginning().await.is_ok(), "Seek beginning failed");
    assert!(log.clear().await.is_ok(), "Clear log failed");

    let mut entry_buf_0 = [0u8; 8];
    let mut entry_buf_1 = [0u8; 32];
    let mut entry_buf_2 = [0u8; 64];
    let mut entry_buf_3 = [0u8; 128];

    for j in 0..entry_buf_0.len() {
        entry_buf_0[j] = b'A' + (j % 26) as u8;
    }
    for j in 0..entry_buf_1.len() {
        entry_buf_1[j] = b'A' + ((1 + j) % 26) as u8;
    }
    for j in 0..entry_buf_2.len() {
        entry_buf_2[j] = b'A' + ((2 + j) % 26) as u8;
    }
    for j in 0..entry_buf_3.len() {
        entry_buf_3[j] = b'A' + ((3 + j) % 26) as u8;
    }

    let entry_refs: [&[u8]; 4] = [
        &entry_buf_0[..],
        &entry_buf_1[..],
        &entry_buf_2[..],
        &entry_buf_3[..],
    ];
    for (i, entry) in entry_refs.iter().enumerate() {
        assert!(
            log.append_entry(entry).await.is_ok(),
            "Failed to append patterned entry {}",
            i
        );
    }

    let mut buffer = [0u8; 128];
    let expected_refs: [&[u8]; 4] = [
        &entry_buf_0[..],
        &entry_buf_1[..],
        &entry_buf_2[..],
        &entry_buf_3[..],
    ];
    for (i, expected) in expected_refs.iter().enumerate() {
        buffer.fill(0);
        let read_result = log.read_entry(&mut buffer).await;
        assert!(read_result.is_ok(), "Failed to read entry {}", i);
        let len = read_result.unwrap();
        assert!(
            &buffer[..len] == &expected[..len],
            "Entry {} contents mismatch",
            i
        );
    }
    assert!(log.sync().await.is_ok(), "Sync failed");
    assert!(log.clear().await.is_ok(), "Clear failed");

    buffer.fill(0);
    let read_after_clear = log.read_entry(&mut buffer).await;
    assert!(read_after_clear.is_err(), "Log should be empty after clear");
}

pub async fn test_logging_flash_multiple_instances() {
    if LOGGING_FLASH_INSTANCE_COUNT < 2 {
        return;
    }

    let log0: LoggingSyscall = LoggingSyscall::default();
    let log1: LoggingSyscall = LoggingSyscall::new(LOGGING_FLASH_DRIVER_NUMS[1]);
    assert!(log0.exists().is_ok(), "Logging instance 0 doesn't exist");
    assert!(log1.exists().is_ok(), "Logging instance 1 doesn't exist");

    assert!(
        log0.seek_beginning().await.is_ok(),
        "Seek beginning failed for instance 0"
    );
    assert!(log0.clear().await.is_ok(), "Clear failed for instance 0");
    assert!(
        log1.seek_beginning().await.is_ok(),
        "Seek beginning failed for instance 1"
    );
    assert!(log1.clear().await.is_ok(), "Clear failed for instance 1");

    let mut entry_0 = [0u8; 32];
    let mut entry_1 = [0u8; 48];
    for i in 0..entry_0.len() {
        entry_0[i] = b'A' + (i % 26) as u8;
    }
    for i in 0..entry_1.len() {
        entry_1[i] = b'a' + (i % 26) as u8;
    }

    assert!(
        log0.append_entry(&entry_0).await.is_ok(),
        "Failed to append entry to instance 0"
    );
    assert!(
        log1.append_entry(&entry_1).await.is_ok(),
        "Failed to append entry to instance 1"
    );

    let mut buffer = [0u8; 64];
    let read_result = log0.read_entry(&mut buffer).await;
    assert!(read_result.is_ok(), "Failed to read entry from instance 0");
    let len = read_result.unwrap();
    assert!(
        buffer[..len] == entry_0[..len],
        "Instance 0 entry contents mismatch"
    );

    buffer.fill(0);
    let read_result = log1.read_entry(&mut buffer).await;
    assert!(read_result.is_ok(), "Failed to read entry from instance 1");
    let len = read_result.unwrap();
    assert!(
        buffer[..len] == entry_1[..len],
        "Instance 1 entry contents mismatch"
    );

    // Clearing instance 0 must not affect instance 1.
    assert!(log0.clear().await.is_ok(), "Clear failed for instance 0");
    let read_after_clear = log0.read_entry(&mut buffer).await;
    assert!(
        read_after_clear.is_err(),
        "Instance 0 should be empty after clear"
    );

    assert!(
        log1.seek_beginning().await.is_ok(),
        "Seek beginning failed for instance 1"
    );
    buffer.fill(0);
    let read_result = log1.read_entry(&mut buffer).await;
    assert!(
        read_result.is_ok(),
        "Failed to read entry from instance 1 after clearing instance 0"
    );
    let len = read_result.unwrap();
    assert!(
        buffer[..len] == entry_1[..len],
        "Instance 1 entry mismatch after clearing instance 0"
    );
}

pub async fn test_logging_flash_invalid_inputs() {
    let log: LoggingSyscall = LoggingSyscall::default();
    assert!(log.exists().is_ok(), "Logging driver doesn't exist");
    assert!(log.get_capacity().is_ok(), "Failed to get logging capacity");
    assert!(log.seek_beginning().await.is_ok(), "Seek beginning failed");
    assert!(log.clear().await.is_ok(), "Clear log failed");

    let empty_entry: &[u8] = &[];
    assert!(
        log.append_entry(empty_entry).await.is_err(),
        "Should not append empty entry"
    );

    let oversized_entry = [0u8; 256];
    assert!(
        log.append_entry(&oversized_entry).await.is_err(),
        "Should not append oversized entry"
    );

    let mut zero_buf = [];
    assert!(
        log.read_entry(&mut zero_buf).await.is_err(),
        "Should not read with zero-sized buffer"
    );
}

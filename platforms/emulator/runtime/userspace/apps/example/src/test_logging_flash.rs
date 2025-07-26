// Licensed under the Apache-2.0 license

use core::fmt::Write;
use libsyscall_caliptra::logging::LoggingSyscall;
use romtime::println;

pub async fn test_logging_flash_simple() {
    println!("test_logging_flash_simple started");
    let log: LoggingSyscall = LoggingSyscall::new();

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
    println!("test_logging_flash_simple succeeded");
}

pub async fn test_logging_flash_various_entries() {
    println!("test_logging_flash_various_entries started");

    let log: LoggingSyscall = LoggingSyscall::new();
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

    println!("test_logging_flash_various_entries succeeded");
}

pub async fn test_logging_flash_invalid_inputs() {
    println!("test_logging_flash_invalid_inputs started");

    let log: LoggingSyscall = LoggingSyscall::new();
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
    println!("test_logging_flash_invalid_inputs succeeded");
}

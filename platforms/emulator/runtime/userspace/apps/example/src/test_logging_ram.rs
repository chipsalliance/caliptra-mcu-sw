// Licensed under the Apache-2.0 license

#[cfg(not(feature = "fpga"))]
use caliptra_mcu_config_emulator as config;
#[cfg(feature = "fpga")]
use caliptra_mcu_config_fpga as config;
use caliptra_mcu_libsyscall_caliptra::logging::LoggingSyscall;
use caliptra_mcu_libtock_platform::{ErrorCode, Syscalls};
use caliptra_mcu_libtock_runtime::TockSyscalls;
use config::ram::LOGGING_PARTITION;
use core::future::{poll_fn, Future};
use core::mem::size_of;
use core::pin::pin;
use core::task::Poll;

#[cfg(not(feature = "test-log-ram-linear"))]
pub async fn test_logging_ram_circular() {
    let log: LoggingSyscall = LoggingSyscall::new(LOGGING_PARTITION.driver_num);
    assert!(log.exists().is_ok());
    assert_eq!(log.get_capacity().unwrap(), LOGGING_PARTITION.size);
    log.clear().await.unwrap();

    let mut entry = [0; 256];
    let retained = LOGGING_PARTITION.size / (entry.len() + size_of::<usize>());
    for sequence in 0..retained + 2 {
        entry.fill(sequence as u8);
        log.append_entry(&entry).await.unwrap();
    }
    log.seek_beginning().await.unwrap();
    let mut output = [0; 256];
    for sequence in 2..retained + 2 {
        assert_eq!(log.read_entry(&mut output).await.unwrap(), output.len());
        assert!(output.iter().all(|byte| *byte == sequence as u8));
    }
    assert!(log.read_entry(&mut output).await.is_err());
    log.clear().await.unwrap();
    assert_eq!(log.sync().await, Err(ErrorCode::NoSupport));
    assert!(log.read_entry(&mut output).await.is_err());
    log.append_entry_sync(b"after clear").unwrap();
    assert_eq!(
        log.read_entry(&mut output).await.unwrap(),
        b"after clear".len()
    );
    assert_eq!(&output[..b"after clear".len()], b"after clear");
}

#[cfg(feature = "test-log-ram-linear")]
pub async fn test_logging_ram_linear() {
    let log: LoggingSyscall = LoggingSyscall::new(LOGGING_PARTITION.driver_num);
    assert_eq!(log.get_capacity().unwrap(), LOGGING_PARTITION.size);
    log.clear().await.unwrap();

    let mut entry = [0; 256];
    let retained = LOGGING_PARTITION.size / (entry.len() + size_of::<usize>());
    for sequence in 0..retained {
        entry.fill(sequence as u8);
        log.append_entry(&entry).await.unwrap();
    }
    assert_eq!(log.append_entry(&entry).await, Err(ErrorCode::Fail));
    log.seek_beginning().await.unwrap();
    let mut output = [0; 256];
    for sequence in 0..retained {
        assert_eq!(log.read_entry(&mut output).await.unwrap(), output.len());
        assert!(output.iter().all(|byte| *byte == sequence as u8));
    }
    assert!(log.read_entry(&mut output).await.is_err());
    // Reading does not reclaim retained records.
    assert_eq!(log.append_entry(&entry).await, Err(ErrorCode::Fail));
    assert_eq!(log.sync().await, Err(ErrorCode::NoSupport));
    log.clear().await.unwrap();
    log.append_entry_sync(b"after clear").unwrap();
    assert_eq!(
        log.read_entry(&mut output).await.unwrap(),
        b"after clear".len()
    );
    assert_eq!(&output[..b"after clear".len()], b"after clear");
}

#[cfg(all(feature = "crash-log", not(feature = "fpga")))]
pub async fn test_logging_ram_multiple_instances() {
    let normal: LoggingSyscall = LoggingSyscall::new(LOGGING_PARTITION.driver_num);
    let crash: LoggingSyscall = LoggingSyscall::new(config::ram::CRASH_LOG_PARTITION.driver_num);
    assert_eq!(
        crash.get_capacity().unwrap(),
        config::ram::CRASH_LOG_PARTITION.size
    );
    normal.clear().await.unwrap();
    crash.clear().await.unwrap();

    let mut normal_append = pin!(normal.append_entry(b"normal record"));
    let mut crash_append = pin!(crash.append_entry(b"crash record"));
    poll_fn(|cx| {
        assert!(normal_append.as_mut().poll(cx).is_pending());
        assert!(crash_append.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    normal_append.await.unwrap();
    crash_append.await.unwrap();

    let mut output = [0; 32];
    for (log, expected) in [
        (&normal, b"normal record".as_slice()),
        (&crash, b"crash record".as_slice()),
    ] {
        assert_eq!(log.read_entry(&mut output).await.unwrap(), expected.len());
        assert_eq!(&output[..expected.len()], expected);
        assert!(log.read_entry(&mut output).await.is_err());
        assert_eq!(log.sync().await, Err(ErrorCode::NoSupport));
    }
    normal.clear().await.unwrap();
    assert!(normal.read_entry(&mut output).await.is_err());
    crash.seek_beginning().await.unwrap();
    assert_eq!(
        crash.read_entry(&mut output).await.unwrap(),
        b"crash record".len()
    );
    assert_eq!(&output[..b"crash record".len()], b"crash record");
    crash.clear().await.unwrap();
}

pub async fn test_logging_ram_simple() {
    let log: LoggingSyscall = LoggingSyscall::new(LOGGING_PARTITION.driver_num);
    assert!(log.exists().is_ok());
    assert_eq!(log.get_capacity().unwrap(), LOGGING_PARTITION.size);
    log.seek_beginning().await.unwrap();
    log.clear().await.unwrap();
    let mut entry = [0; 64];
    for (index, byte) in entry.iter_mut().enumerate() {
        *byte = b'A' + (index % 26) as u8;
    }
    log.append_entry(&entry).await.unwrap();
    let mut buffer = [0; 256];
    let length = log.read_entry(&mut buffer).await.unwrap();
    assert_eq!(length, entry.len());
    assert_eq!(&buffer[..length], &entry);
}

pub async fn test_logging_ram_various_entries() {
    let log: LoggingSyscall = LoggingSyscall::new(LOGGING_PARTITION.driver_num);
    log.seek_beginning().await.unwrap();
    log.clear().await.unwrap();
    let mut entry = [0; 128];
    for (sequence, length) in [8, 32, 64, 128].into_iter().enumerate() {
        for (index, byte) in entry[..length].iter_mut().enumerate() {
            *byte = b'A' + ((sequence + index) % 26) as u8;
        }
        log.append_entry(&entry[..length]).await.unwrap();
    }
    let mut buffer = [0; 128];
    for (sequence, length) in [8, 32, 64, 128].into_iter().enumerate() {
        buffer.fill(0);
        assert_eq!(log.read_entry(&mut buffer).await.unwrap(), length);
        for (index, byte) in buffer[..length].iter().enumerate() {
            assert_eq!(*byte, b'A' + ((sequence + index) % 26) as u8);
        }
    }
    assert_eq!(log.sync().await, Err(ErrorCode::NoSupport));
    log.clear().await.unwrap();
    assert!(log.read_entry(&mut buffer).await.is_err());
}

pub async fn test_logging_ram_invalid_inputs() {
    let log: LoggingSyscall = LoggingSyscall::new(LOGGING_PARTITION.driver_num);
    log.clear().await.unwrap();
    assert!(log.append_entry(&[]).await.is_err());
    // Unlike the emulator's Flash page, RAM can hold a full transfer-buffer record.
    let entry = [0x55; 256];
    log.append_entry(&entry).await.unwrap();
    assert_eq!(log.append_entry(&[0; 257]).await, Err(ErrorCode::Size));
    assert!(log.read_entry(&mut []).await.is_err());
    assert_eq!(log.read_entry(&mut [0; 255]).await, Err(ErrorCode::Size));
    let mut buffer = [0; 256];
    assert_eq!(log.read_entry(&mut buffer).await.unwrap(), entry.len());
    assert_eq!(buffer, entry);
}

pub async fn test_logging_ram_and_flash() {
    let ram: LoggingSyscall = LoggingSyscall::new(LOGGING_PARTITION.driver_num);
    let flash: LoggingSyscall = LoggingSyscall::new(config::flash::LOGGING_PARTITION.driver_num);
    flash.exists().unwrap();
    ram.clear().await.unwrap();
    flash.clear().await.unwrap();

    let default: LoggingSyscall = LoggingSyscall::default();
    default.append_entry_sync(b"default sync").unwrap();
    default.append_entry(b"default async").await.unwrap();
    let mut buffer = [0; 32];
    for (driver_num, log) in [
        (LOGGING_PARTITION.driver_num, &ram),
        (config::flash::LOGGING_PARTITION.driver_num, &flash),
    ] {
        log.seek_beginning().await.unwrap();
        if driver_num == config::DEFAULT_LOGGING_DRIVER_NUM {
            for entry in [b"default sync".as_slice(), b"default async".as_slice()] {
                assert_eq!(log.read_entry(&mut buffer).await.unwrap(), entry.len());
                assert_eq!(&buffer[..entry.len()], entry);
            }
        }
        assert!(log.read_entry(&mut buffer).await.is_err());
        log.clear().await.unwrap();
    }

    let mut append = pin!(flash.append_entry(b"flash record"));
    poll_fn(|cx| {
        assert!(append.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let mut ram_append = pin!(ram.append_entry(b"ram record"));
    poll_fn(|cx| {
        assert!(ram_append.as_mut().poll(cx).is_pending());
        for command in [4, 7, u32::MAX, (1 << 31) | 3] {
            assert_eq!(
                TockSyscalls::command(LOGGING_PARTITION.driver_num, command, 0, 0)
                    .to_result::<(), ErrorCode>(),
                Err(ErrorCode::NoSupport)
            );
        }
        Poll::Ready(())
    })
    .await;
    ram_append.await.unwrap();
    append.await.unwrap();
    flash.sync().await.unwrap();

    let mut buffer = [0; 32];
    ram.seek_beginning().await.unwrap();
    assert_eq!(
        ram.read_entry(&mut buffer).await.unwrap(),
        b"ram record".len()
    );
    assert_eq!(&buffer[..b"ram record".len()], b"ram record");
    flash.seek_beginning().await.unwrap();
    assert_eq!(
        flash.read_entry(&mut buffer).await.unwrap(),
        b"flash record".len()
    );
    assert_eq!(&buffer[..b"flash record".len()], b"flash record");
    ram.clear().await.unwrap();
    assert_eq!(ram.get_capacity().unwrap(), LOGGING_PARTITION.size);
    flash.seek_beginning().await.unwrap();
    assert_eq!(
        flash.read_entry(&mut buffer).await.unwrap(),
        b"flash record".len()
    );
    assert_eq!(&buffer[..b"flash record".len()], b"flash record");
    flash.clear().await.unwrap();
}

// Licensed under the Apache-2.0 license

use crate::sleep;
use caliptra_mcu_libtock::alarm::Milliseconds;
use caliptra_mcu_libtock_platform::{share, AllowRo, AllowRw, DefaultConfig, ErrorCode, Syscalls};
use caliptra_mcu_libtock_runtime::TockSyscalls as S;
use core::cell::Cell;

// Test-only registrations in the emulator board, not the production logging IDs.
const LOG: u32 = 0x9001_f000;
const CONTROL: u32 = LOG + 1;
const EXIT_LOG: u32 = LOG + 2;
const EXIT_CONTROL: u32 = LOG + 3;

fn command(operation: u32, length: u32) -> Result<(), ErrorCode> {
    S::command(LOG, operation, length, 0).to_result()
}

fn control(operation: u32, argument: u32) {
    S::command(CONTROL, operation, argument, 0)
        .to_result::<(), ErrorCode>()
        .unwrap();
}

fn status(operation: u32) -> u32 {
    S::command(CONTROL, operation, 0, 0)
        .to_result::<u32, ErrorCode>()
        .unwrap()
}

fn expect<const UPCALL: u32>(expected: (u32, u32, u32), run: impl FnOnce()) {
    let result = Cell::new(None::<(u32, u32, u32)>);
    share::scope(|subscribe| {
        S::subscribe::<_, _, DefaultConfig, LOG, UPCALL>(subscribe, &result).unwrap();
        run();
        // Completions are already released; do not hang on a missing or misrouted upcall.
        for _ in 0..16 {
            if result.get().is_some() {
                break;
            }
            S::yield_no_wait();
        }
        assert_eq!(result.get(), Some(expected));
        result.set(None);
        for _ in 0..4 {
            S::yield_no_wait();
        }
        assert_eq!(result.get(), None, "Duplicate completion");
    });
}

fn recover() {
    let data = [0x69; 16];
    share::scope(|allow| {
        S::allow_ro::<DefaultConfig, LOG, 0>(allow, &data).unwrap();
        expect::<2>((16, 0, 0), || {
            command(2, 16).unwrap();
            assert_eq!(status(0), 2, "Owner or transfer buffer was not released");
            control(1, 0);
        });
    });
}

fn immediate_errors() {
    let large = [0x33; 257];
    share::scope(|allow| {
        S::allow_ro::<DefaultConfig, LOG, 0>(allow, &large).unwrap();
        let before = status(3);
        assert_eq!(command(2, 257), Err(ErrorCode::Size));
        assert_eq!(status(3), before, "Oversized append reached backend");
        expect::<2>((16, 0, 0), || {
            command(2, 16).unwrap();
            assert_eq!(
                status(0),
                2,
                "Requested length, not allow length, limits append"
            );
            control(1, 0);
        });
    });
    let data = [0; 8];
    let mut read = [0; 8];
    share::scope::<(AllowRo<S, LOG, 0>, AllowRw<S, LOG, 0>), _, _>(|allows| {
        let (ro, rw) = allows.split();
        S::allow_ro::<DefaultConfig, LOG, 0>(ro, &data).unwrap();
        S::allow_rw::<DefaultConfig, LOG, 0>(rw, &mut read).unwrap();
        let before = status(3);
        assert_eq!(command(2, 16), Err(ErrorCode::Size));
        assert_eq!(command(1, 16), Err(ErrorCode::Size));
        assert_eq!(status(3), before, "Short allow reached backend");
        control(2, 1);
        assert_eq!(command(2, 8), Err(ErrorCode::Fail));
        assert_eq!(command(1, 8), Err(ErrorCode::Fail));
        control(2, 0);
    });
    recover();
}

fn queued_allow_changes() {
    for revoke in [false, true] {
        let original = [0x11; 16];
        let short = [0x22; 8];
        share::scope(|allow| {
            S::allow_ro::<DefaultConfig, LOG, 0>(allow, &original).unwrap();
            command(3, 0).unwrap();
            let before = status(3);
            expect::<2>(
                (
                    0,
                    0,
                    if revoke {
                        ErrorCode::Reserve
                    } else {
                        ErrorCode::Size
                    } as u32,
                ),
                || {
                    command(2, 16).unwrap();
                    assert_eq!(command(5, 0), Err(ErrorCode::NoMem));
                    assert_eq!(status(3), before, "Append did not queue behind held seek");
                    if revoke {
                        S::unallow_ro(LOG, 0);
                    } else {
                        S::allow_ro::<DefaultConfig, LOG, 0>(allow, &short).unwrap();
                    }
                    control(1, 0);
                },
            );
            assert_eq!(status(3), before, "Invalid queued append reached backend");
        });
        recover();

        let mut original = [0; 16];
        let mut short = [0; 8];
        share::scope::<(AllowRw<S, LOG, 0>, AllowRw<S, LOG, 0>), _, _>(|allows| {
            let (original_allow, short_allow) = allows.split();
            S::allow_rw::<DefaultConfig, LOG, 0>(original_allow, &mut original).unwrap();
            command(3, 0).unwrap();
            let before = status(3);
            expect::<0>(
                (
                    0,
                    if revoke {
                        ErrorCode::Reserve
                    } else {
                        ErrorCode::Size
                    } as u32,
                    0,
                ),
                || {
                    command(1, 16).unwrap();
                    assert_eq!(status(3), before, "Read did not queue behind held seek");
                    if revoke {
                        S::unallow_rw(LOG, 0);
                    } else {
                        S::allow_rw::<DefaultConfig, LOG, 0>(short_allow, &mut short).unwrap();
                    }
                    control(1, 0);
                },
            );
            assert_eq!(status(3), before, "Invalid queued read reached backend");
        });
        recover();
    }

    let original = [0x11; 16];
    let replacement = [0x77; 16];
    share::scope(|allow| {
        S::allow_ro::<DefaultConfig, LOG, 0>(allow, &original).unwrap();
        command(3, 0).unwrap();
        let before = status(3);
        expect::<2>((16, 0, 0), || {
            command(2, 16).unwrap();
            assert_eq!(status(3), before);
            S::allow_ro::<DefaultConfig, LOG, 0>(allow, &replacement).unwrap();
            control(1, 0);
            assert_eq!(status(0), 2);
            assert_eq!(status(3), before + 1);
            assert_eq!(
                S::command(CONTROL, 6, 0x77, 0).to_result::<u32, ErrorCode>(),
                Ok(1),
                "Queued append must copy the current allow, not stale transfer-buffer bytes"
            );
            control(1, 0);
        });
    });
}

fn queued_failure<const UPCALL: u32>(operation: u32, expected: (u32, u32, u32)) {
    command(if operation == 3 { 4 } else { 3 }, 0).unwrap();
    let before = status(3);
    expect::<UPCALL>(expected, || {
        command(operation, if operation <= 2 { 16 } else { 0 }).unwrap();
        assert_eq!(status(3), before);
        control(2, 1);
        control(1, 0);
    });
    assert_eq!(status(3), before + 1);
    assert_eq!(status(0), 0);
    control(2, 0);
    recover();
}

pub async fn run() -> Result<(), &'static str> {
    // The user app submits a read and an append on separate instances, then
    // uses Tock Exit (not the emulator's System::exit).
    // Leave time for a genuine blocked yield: a 1 ms alarm may already be
    // pending after syscall overhead, keeping this cooperative process runnable.
    for _ in 0..10 {
        if status(5) == 1 {
            break;
        }
        sleep::<S>(Milliseconds(100)).await;
    }
    if status(5) != 1 {
        return Err(if status(7) == 0 {
            "loaded victim never registered after 10 waits; see kernel process states"
        } else {
            "registered victim did not terminate cleanly after 10 waits; see kernel process states"
        });
    }
    assert_eq!(status(0), 1);
    assert_eq!(
        S::command(EXIT_CONTROL, 0, 0, 0).to_result::<u32, ErrorCode>(),
        Ok(2)
    );
    // Queue this process's seek behind the terminated victim's held read.
    expect::<1>((0, 0, 0), || {
        command(3, 0).unwrap();
        assert_eq!(status(0), 1);
        control(1, 0);
        assert_eq!(status(0), 3);
        control(1, 0);
    });
    S::command(EXIT_CONTROL, 1, 0, 0)
        .to_result::<(), ErrorCode>()
        .unwrap();
    assert_eq!(
        status(5),
        1,
        "Completion scheduled work on a terminated process"
    );
    assert_eq!(
        S::command(EXIT_CONTROL, 5, 0, 0).to_result::<u32, ErrorCode>(),
        Ok(1)
    );
    recover();
    let data = [0x42; 16];
    share::scope(|allow| {
        S::allow_ro::<DefaultConfig, EXIT_LOG, 0>(allow, &data).unwrap();
        S::command(EXIT_LOG, 2, 16, 0)
            .to_result::<(), ErrorCode>()
            .unwrap();
        assert_eq!(
            S::command(EXIT_CONTROL, 0, 0, 0).to_result::<u32, ErrorCode>(),
            Ok(2)
        );
        S::command(EXIT_CONTROL, 1, 0, 0)
            .to_result::<(), ErrorCode>()
            .unwrap();
    });

    immediate_errors();
    queued_allow_changes();
    let data = [0x44; 16];
    let mut read = [0; 16];
    share::scope::<(AllowRo<S, LOG, 0>, AllowRw<S, LOG, 0>), _, _>(|allows| {
        let (ro, rw) = allows.split();
        S::allow_ro::<DefaultConfig, LOG, 0>(ro, &data).unwrap();
        S::allow_rw::<DefaultConfig, LOG, 0>(rw, &mut read).unwrap();
        queued_failure::<0>(1, (0, ErrorCode::Fail as u32, 0));
        // recover() revokes its allow; reinstall ours before the queued append.
        S::allow_ro::<DefaultConfig, LOG, 0>(ro, &data).unwrap();
        queued_failure::<2>(2, (0, 0, ErrorCode::Fail as u32));
    });
    queued_failure::<1>(3, (ErrorCode::Fail as u32, 0, 0));
    queued_failure::<3>(4, (ErrorCode::Fail as u32, 0, 0));
    queued_failure::<4>(5, (ErrorCode::Fail as u32, 0, 0));
    Ok(())
}

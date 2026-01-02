// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]
#![allow(static_mut_refs)]

use core::fmt::Write;
use libsyscall_caliptra::system::System;
use libtock::alarm::*;
use libtock_console::Console;
use libtock_platform::{self as platform};
use libtock_platform::{DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;

#[cfg(feature = "test-pldm-request-response")]
mod test_pldm_request_response;

mod test_caliptra_mailbox;

#[cfg(feature = "test-get-device-state")]
mod test_get_device_state;

#[cfg(feature = "test-caliptra-crypto")]
mod test_caliptra_crypto;

#[cfg(feature = "test-dma")]
mod test_dma;

#[cfg(feature = "test-doe-user-loopback")]
mod test_doe_loopback;

#[cfg(feature = "test-caliptra-certs")]
mod test_caliptra_certs;

#[cfg(feature = "test-log-flash-usermode")]
mod test_logging_flash;

#[cfg(any(feature = "test-mci", feature = "test-warm-reset"))]
mod test_mci;

#[cfg(feature = "test-mcu-mbox-usermode")]
mod test_mcu_mbox_usermode;

#[cfg(feature = "test-mbox-sram")]
mod test_mbox_sram;

#[cfg(any(feature = "test-flash-usermode", feature = "test-fpga-flash-ctrl"))]
mod test_flash_io;

#[cfg(target_arch = "riscv32")]
mod riscv;

#[cfg(not(target_arch = "riscv32"))]
pub(crate) fn kernel() -> libtock_unittest::fake::Kernel {
    use libtock_unittest::fake;
    let kernel = fake::Kernel::new();
    let alarm = fake::Alarm::new(1_000_000);
    let console = fake::Console::new();
    kernel.add_driver(&alarm);
    kernel.add_driver(&console);
    kernel
}

#[cfg(not(target_arch = "riscv32"))]
fn main() {
    // build a fake kernel so that the app will at least start without Tock
    let _kernel = kernel();
    // call the main function
    libtockasync::start_async(start());
}

#[cfg(target_arch = "riscv32")]
#[embassy_executor::task]
async fn start() {
    async_main::<libtock_runtime::TockSyscalls>().await;
}

#[cfg(not(target_arch = "riscv32"))]
#[embassy_executor::task]
async fn start() {
    async_main::<libtock_unittest::fake::Syscalls>().await;
}

#[allow(unreachable_code)]
pub(crate) async fn async_main<S: Syscalls>() {
    let mut console_writer = Console::<S>::writer();
    writeln!(
        console_writer,
        "Timer frequency: {}",
        AsyncAlarm::<S>::get_frequency().unwrap().0
    )
    .unwrap();

    match AsyncAlarm::<S>::exists() {
        Ok(()) => {}
        Err(_) => {
            let _ = writeln!(
                console_writer,
                "Alarm capsule not available, so cannot execute tests"
            );
            System::exit(0);
        }
    };

    for _ in 0..5 {
        writeln!(console_writer, "Sleeping for 1 millisecond").unwrap();
        sleep::<S>(Milliseconds(1)).await;
        writeln!(console_writer, "async sleeper woke").unwrap();
    }

    #[cfg(feature = "test-mctp-user-loopback")]
    {
        writeln!(
            console_writer,
            "Running test-mctp-user-loopback test for CALIPTRA message type"
        )
        .unwrap();

        test_mctp_loopback().await;
    }

    #[cfg(feature = "test-doe-user-loopback")]
    {
        writeln!(
            console_writer,
            "Running test-doe-user-loopback test for DOE message type"
        )
        .unwrap();

        // This test is not implemented yet.
        test_doe_loopback::test_doe_loopback().await;
    }

    #[cfg(feature = "test-flash-usermode")]
    {
        writeln!(
            console_writer,
            "Running IO test on emulator flash partitions"
        )
        .unwrap();
        test_flash_io::test_flash_usermode_emulator().await;
        System::exit(0);
    }
    #[cfg(feature = "test-pldm-request-response")]
    {
        test_pldm_request_response::test::test_pldm_request_response().await;
    }
    #[cfg(feature = "test-caliptra-mailbox")]
    {
        test_caliptra_mailbox::test_caliptra_mailbox().await;
        test_caliptra_mailbox::test_caliptra_mailbox_bad_command().await;
        test_caliptra_mailbox::test_caliptra_mailbox_fail().await;
        System::exit(0);
    }

    #[cfg(feature = "test-get-device-state")]
    {
        test_get_device_state::test_get_pcr_quote().await;
        test_get_device_state::test_get_pcrs().await;
        test_get_device_state::test_get_fw_info().await;
        test_get_device_state::test_get_image_info().await;
        test_get_device_state::test_get_fw_version().await;
        System::exit(0);
    }

    #[cfg(feature = "test-caliptra-crypto")]
    {
        test_caliptra_crypto::test_caliptra_sha().await;
        test_caliptra_crypto::test_caliptra_rng().await;
        test_caliptra_crypto::test_caliptra_ecdh().await;
        test_caliptra_crypto::test_caliptra_hmac().await;
        test_caliptra_crypto::test_caliptra_aes_gcm_cipher().await;
        test_caliptra_crypto::test_caliptra_ecdsa().await;
        System::exit(0);
    }

    #[cfg(feature = "test-caliptra-certs")]
    {
        // test_caliptra_certs::test_get_idev_csr().await;
        test_caliptra_certs::test_populate_idev_ecc384_cert().await;
        test_caliptra_certs::test_get_ldev_ecc384_cert().await;
        test_caliptra_certs::test_get_fmc_alias_ecc384cert().await;
        test_caliptra_certs::test_get_rt_alias_ecc384cert().await;
        test_caliptra_certs::test_get_cert_chain().await;
        test_caliptra_certs::test_certify_key().await;
        test_caliptra_certs::test_sign_with_test_key().await;
        System::exit(0);
    }
    #[cfg(feature = "test-dma")]
    {
        test_dma::test_dma_xfer_local_to_local().await;
        test_dma::test_dma_xfer_local_to_external().await;
        System::exit(0);
    }

    #[cfg(feature = "test-log-flash-usermode")]
    {
        test_logging_flash::test_logging_flash_simple().await;
        test_logging_flash::test_logging_flash_various_entries().await;
        test_logging_flash::test_logging_flash_invalid_inputs().await;
        System::exit(0);
    }
    #[cfg(feature = "test-mci")]
    {
        test_mci::test_mci_read_write().await;
        System::exit(0);
    }

    #[cfg(feature = "test-mcu-mbox-usermode")]
    {
        writeln!(console_writer, "Running MCU mailbox usermode loopback test").unwrap();
        test_mcu_mbox_usermode::test_mcu_mbox_usermode_loopback().await;
    }
    #[cfg(any(feature = "test-mcu-svn-gt-fuse", feature = "test-mcu-svn-lt-fuse"))]
    {
        writeln!(console_writer, "MCU Image SVN check passed").unwrap();
        System::exit(0);
    }
    #[cfg(feature = "test-mbox-sram")]
    {
        writeln!(console_writer, "Running MEM-REG read/write test").unwrap();
        test_mbox_sram::test_mem_reg_read_write().await;
        System::exit(0);
    }
    #[cfg(feature = "test-warm-reset")]
    {
        test_mci::test_mci_fw_boot_reset().await;
        System::exit(0);
    }

    #[cfg(feature = "test-fpga-flash-ctrl")]
    {
        writeln!(
            console_writer,
            "Running IO test on FPGA flash staging partition"
        )
        .unwrap();
        test_flash_io::test_flash_usermode_fpga().await;
        writeln!(
            console_writer,
            "IO test on FPGA flash staging partition succeeded"
        )
        .unwrap();
        System::exit(0);
    }
}

#[allow(dead_code)]
async fn test_mctp_loopback() {
    use libsyscall_caliptra::mctp::{driver_num, Mctp};
    let mctp_caliptra: Mctp = Mctp::new(driver_num::MCTP_CALIPTRA);
    loop {
        let mut msg_buffer: [u8; 1024] = [0; 1024];

        assert!(mctp_caliptra.exists());
        let max_msg_size = mctp_caliptra.max_message_size();
        assert!(max_msg_size.is_ok());
        assert!(max_msg_size.unwrap() > 0);

        let result = mctp_caliptra.receive_request(&mut msg_buffer).await;
        assert!(result.is_ok());
        let (msg_len, msg_info) = result.unwrap();
        let msg_len = msg_len as usize;
        assert!(msg_len <= msg_buffer.len());

        let result = mctp_caliptra
            .send_response(&msg_buffer[..msg_len], msg_info)
            .await;
        assert!(result.is_ok());
    }
}

// -----------------------------------------------------------------------------
// Driver number and command IDs
// -----------------------------------------------------------------------------

const DRIVER_NUM: u32 = 0;

// Command IDs
#[allow(unused)]
mod command {
    pub const EXISTS: u32 = 0;
    pub const FREQUENCY: u32 = 1;
    pub const TIME: u32 = 2;
    pub const STOP: u32 = 3;

    pub const SET_RELATIVE: u32 = 5;
    pub const SET_ABSOLUTE: u32 = 6;
}

#[allow(unused)]
mod subscribe {
    pub const CALLBACK: u32 = 0;
}

pub(crate) async fn sleep<S: Syscalls>(time: Milliseconds) {
    let x = AsyncAlarm::<S>::sleep_for(time).await;
    writeln!(Console::<S>::writer(), "Async sleep done {:?}", x).unwrap();
}

pub struct AsyncAlarm<S: Syscalls, C: platform::subscribe::Config = DefaultConfig>(S, C);

impl<S: Syscalls, C: platform::subscribe::Config> AsyncAlarm<S, C> {
    /// Run a check against the console capsule to ensure it is present.
    #[inline(always)]
    #[allow(dead_code)]
    pub fn exists() -> Result<(), ErrorCode> {
        S::command(DRIVER_NUM, command::EXISTS, 0, 0).to_result()
    }

    pub fn get_frequency() -> Result<Hz, ErrorCode> {
        S::command(DRIVER_NUM, command::FREQUENCY, 0, 0)
            .to_result()
            .map(Hz)
    }

    #[allow(dead_code)]
    pub fn get_ticks() -> Result<u32, ErrorCode> {
        S::command(DRIVER_NUM, command::TIME, 0, 0).to_result()
    }

    #[allow(dead_code)]
    pub fn get_milliseconds() -> Result<u64, ErrorCode> {
        let ticks = Self::get_ticks()? as u64;
        let freq = (Self::get_frequency()?).0 as u64;

        Ok(ticks.saturating_div(freq / 1000))
    }

    pub async fn sleep_for<T: Convert>(time: T) -> Result<(), ErrorCode> {
        let freq = Self::get_frequency()?;
        let ticks = time.to_ticks(freq).0;
        writeln!(Console::<S>::writer(), "Sleeping for {} ticks", ticks).unwrap();
        let sub = TockSubscribe::subscribe::<S>(DRIVER_NUM, 0);
        S::command(DRIVER_NUM, command::SET_RELATIVE, ticks, 0)
            .to_result()
            .map(|_when: u32| ())?;
        sub.await.map(|_| ())
    }
}

#[cfg(test)]
mod test {
    use super::{command, kernel, sleep};
    use libtock_alarm::Milliseconds;
    use libtock_unittest::fake;
    use libtock_unittest::fake::Alarm;
    use libtockasync::TockExecutor;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{LazyLock, Mutex};

    #[test]
    fn test_frequency() {
        use fake::SyscallDriver;
        let alarm = Alarm::new(10);

        assert_eq!(
            alarm.command(command::FREQUENCY, 1, 2).get_success_u32(),
            Some(10)
        );
    }

    static SLEEP_COUNTER: LazyLock<Mutex<AtomicU32>> =
        LazyLock::new(|| Mutex::new(AtomicU32::new(0)));

    #[embassy_executor::task]
    async fn run_sleep() {
        sleep::<fake::Syscalls>(Milliseconds(1)).await;
        SLEEP_COUNTER
            .lock()
            .unwrap()
            .fetch_add(1, Ordering::Relaxed);
        // ensure there is always an upcall scheduled
        loop {
            sleep::<fake::Syscalls>(Milliseconds(1)).await;
        }
    }

    #[test]
    fn test_async_sleep() {
        let kernel = kernel();
        let mut executor = TockExecutor::new();
        // Safety: we are upgrading the executor for the lifetime of the test only.
        // This needs to be in the same scope as the test for the static upgrade to work.
        let executor: &'static mut TockExecutor = unsafe { core::mem::transmute(&mut executor) };

        executor.spawner().spawn(run_sleep()).unwrap();
        for _ in 0..10 {
            executor.poll();
        }
        assert_eq!(SLEEP_COUNTER.lock().unwrap().load(Ordering::Relaxed), 1);
        drop(kernel);
    }
}

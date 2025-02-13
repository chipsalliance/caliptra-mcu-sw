// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]
#![feature(impl_trait_in_assoc_type)]
#![allow(static_mut_refs)]

use core::fmt::Write;
use libtock_console::Console;
use libtock_platform::{self as platform};
use libtock_platform::{DefaultConfig, ErrorCode, Syscalls};

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

pub(crate) async fn async_main<S: Syscalls>() {
    let mut console_writer = Console::<S>::writer();
    writeln!(console_writer, "SPDM_APP: Hello SPDM async world!").unwrap();

    writeln!(console_writer, "SPDM_APP: Running SPDM-APP...").unwrap();

    test_mctp_loopback::<S>().await;

    writeln!(console_writer, "SPDM_APP: app finished").unwrap();
}

async fn test_mctp_loopback<S: Syscalls>() {
    let mut console_writer = Console::<S>::writer();
    use libsyscall_caliptra::mctp::{driver_num, Mctp};
    let mctp_spdm = Mctp::<S>::new(driver_num::MCTP_SPDM);
    loop {
        let mut msg_buffer: [u8; 1024] = [0; 1024];

        assert!(mctp_spdm.exists());
        let max_msg_size = mctp_spdm.max_message_size();
        assert!(max_msg_size.is_ok());
        assert!(max_msg_size.unwrap() > 0);

        writeln!(console_writer, "SPDM_APP: waiting for MCTP message").unwrap();
        let result = mctp_spdm.receive_request(&mut msg_buffer).await;
        assert!(result.is_ok());
        let (msg_len, msg_info) = result.unwrap();
        let msg_len = msg_len as usize;
        assert!(msg_len <= msg_buffer.len());

        let result = mctp_spdm
            .send_response(&msg_buffer[..msg_len], msg_info)
            .await;
        assert!(result.is_ok());
    }
}

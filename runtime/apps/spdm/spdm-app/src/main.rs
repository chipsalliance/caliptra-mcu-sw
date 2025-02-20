// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]
#![feature(impl_trait_in_assoc_type)]
#![allow(static_mut_refs)]

use core::char::MAX;
use core::fmt::Write;
use core::result;
use libsyscall_caliptra::mctp::driver_num;
use libtock_console::Console;
use libtock_platform::{self as platform};
use libtock_platform::{DefaultConfig, ErrorCode, Syscalls};
use spdm_lib::context::SpdmContext;
use spdm_lib::message_buf::MessageBuf;
use spdm_lib::transport::MctpTransport;
use spdm_lib::{SpdmVersion, MAX_SPDM_MSG_SIZE};

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

    // let mut raw_buffer = [0; MAX_SPDM_MSG_SIZE];
    let mut raw_buffer = [0; 16];

    spdm_loop::<S>(&mut raw_buffer).await;

    writeln!(console_writer, "SPDM_APP: app finished").unwrap();
}

async fn spdm_loop<S: Syscalls>(raw_buffer: &mut [u8]) {
    let mut console_writer = Console::<S>::writer();
    let mut mctp_spdm_transport = MctpTransport::new(driver_num::MCTP_SPDM);
    let mut mctp_secure_spdm_transport = MctpTransport::new(driver_num::MCTP_SECURE);
    let supported_versions = [SpdmVersion::V12, SpdmVersion::V13];

    // let mut spdm_msg_buf =  MessageBuf::new();

    let mut ctx = match SpdmContext::new(
        &supported_versions,
        &mut mctp_spdm_transport,
        &mut mctp_secure_spdm_transport,
        &mut console_writer,
    ) {
        Ok(ctx) => ctx,
        Err(e) => {
            // writeln!(
            //     console_writer,
            //     "SPDM_APP: Failed to create SPDM context: {:?}",
            //     e
            // )
            // .unwrap();
            return;
        }
    };

    // writeln!(console_writer, "SPDM_APP: Start processing the message").unwrap();
    let mut cons_wr = Console::<S>::writer();
    let mut msg_buffer = MessageBuf::new(raw_buffer);
    // let mut raw_buffer = [0; MAX_SPDM_MSG_SIZE];
    loop {
        let result = ctx.process_message(&mut msg_buffer).await;
        match result {
            Ok(_) => {
                writeln!(cons_wr, "SPDM_APP: Process message successfully").unwrap();
            }
            Err(e) => {
                writeln!(cons_wr, "SPDM_APP: Process message failed: {:?}", e).unwrap();
            }
        }
        // msg_buffer = [0; MAX_SPDM_MSG_SIZE];
        writeln!(cons_wr, "SPDM_APP: Process message finished").unwrap();
    }
}

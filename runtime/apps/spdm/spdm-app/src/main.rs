// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]
#![feature(impl_trait_in_assoc_type)]
#![allow(static_mut_refs)]

use core::fmt::Write;
use libsyscall_caliptra::mctp::driver_num;
use libtock_console::{Console, ConsoleWriter};
use libtock_platform::Syscalls;
use spdm_lib::codec::MessageBuf;
use spdm_lib::context::SpdmContext;
use spdm_lib::protocol::{
    CapabilityFlags, DeviceCapabilities, MeasCapability, PskCapability, SpdmVersion,
    MAX_MCTP_SPDM_MSG_SIZE,
};
use spdm_lib::transport::MctpTransport;

// Calitra Crypto timeout exponent (2^20 us)
pub const CALIPTRA_SPDM_CT_EXPONENT: u8 = 0x20;

#[cfg(target_arch = "riscv32")]
mod riscv;

#[cfg(not(target_arch = "riscv32"))]
pub(crate) fn kernel() -> libtock_unittest::fake::Kernel {
    use libtock_unittest::fake;
    let kernel = fake::Kernel::new();
    let console = fake::Console::new();
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

    let mut raw_buffer = [0; MAX_MCTP_SPDM_MSG_SIZE];

    spdm_loop::<S>(&mut raw_buffer, &mut console_writer).await;

    writeln!(console_writer, "SPDM_APP: app finished").unwrap();
}

async fn spdm_loop<S: Syscalls>(raw_buffer: &mut [u8], cw: &mut ConsoleWriter<S>) {
    let mut console_writer = Console::<S>::writer();
    let mut mctp_spdm_transport: MctpTransport<S> = MctpTransport::new(driver_num::MCTP_SPDM);
    let supported_versions = [
        SpdmVersion::V10,
        SpdmVersion::V11,
        SpdmVersion::V12,
        SpdmVersion::V13,
    ];

    let mut capability_flags = CapabilityFlags::default();
    capability_flags.set_cache_cap(0);
    capability_flags.set_cert_cap(1);
    capability_flags.set_chal_cap(1);
    capability_flags.set_meas_cap(MeasCapability::MeasurementsWithSignature as u8);
    capability_flags.set_meas_fresh_cap(0);
    capability_flags.set_encrypt_cap(0);
    capability_flags.set_mac_cap(0);
    capability_flags.set_mut_auth_cap(0);
    capability_flags.set_key_ex_cap(0);
    capability_flags.set_psk_cap(PskCapability::NoPsk as u8);
    capability_flags.set_encap_cap(0);
    capability_flags.set_hbeat_cap(0);
    capability_flags.set_key_upd_cap(0);
    capability_flags.set_handshake_in_the_clear_cap(0);
    capability_flags.set_pub_key_id_cap(0);
    capability_flags.set_chunk_cap(0);
    capability_flags.set_alias_cert_cap(1);

    let max_mctp_spdm_msg_size =
        (MAX_MCTP_SPDM_MSG_SIZE - mctp_spdm_transport.header_size()) as u32;

    let local_capabilities = DeviceCapabilities {
        ct_exponent: CALIPTRA_SPDM_CT_EXPONENT,
        flags: capability_flags,
        data_transfer_size: max_mctp_spdm_msg_size,
        max_spdm_msg_size: max_mctp_spdm_msg_size,
    };

    let mut ctx = match SpdmContext::new(
        &supported_versions,
        &mut mctp_spdm_transport,
        local_capabilities,
        &mut console_writer,
    ) {
        Ok(ctx) => ctx,
        Err(e) => {
            writeln!(cw, "SPDM_APP: Failed to create SPDM context: {:?}", e).unwrap();
            return;
        }
    };

    let mut msg_buffer = MessageBuf::new(raw_buffer);
    loop {
        let result = ctx.process_message(&mut msg_buffer).await;
        match result {
            Ok(_) => {
                writeln!(cw, "SPDM_APP: Process message successfully").unwrap();
            }
            Err(e) => {
                writeln!(cw, "SPDM_APP: Process message failed: {:?}", e).unwrap();
            }
        }
        writeln!(cw, "SPDM_APP: Process message finished").unwrap();
    }
}

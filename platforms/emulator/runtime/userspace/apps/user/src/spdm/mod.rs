// Licensed under the Apache-2.0 license

mod cert_store;
mod device_cert_store;
mod endorsement_certs;

use core::fmt::Write;
use device_cert_store::{initialize_cert_store, SharedCertStore};
use embassy_executor::Spawner;
use libsyscall_caliptra::doe;
use libsyscall_caliptra::mctp;
use libsyscall_caliptra::DefaultSyscalls;
use libtock_console::Console;
use spdm_lib::codec::MessageBuf;
use spdm_lib::context::{SpdmContext, MAX_SPDM_RESPONDER_BUF_SIZE};
use spdm_lib::protocol::*;
use spdm_lib::transport::common::SpdmTransport;
use spdm_lib::transport::doe::DoeTransport;
use spdm_lib::transport::mctp::MctpTransport;

// Caliptra supported SPDM and Secure SPDM versions
const SPDM_VERSIONS: &[SpdmVersion] = &[SpdmVersion::V12, SpdmVersion::V13];
const SECURE_SPDM_VERSIONS: &[SpdmVersion] = &[SpdmVersion::V12];

// Caliptra Crypto timeout exponent (2^20 us)
const CALIPTRA_SPDM_CT_EXPONENT: u8 = 20;

#[embassy_executor::task]
pub(crate) async fn spdm_task(spawner: Spawner) {
    let mut console_writer = Console::<DefaultSyscalls>::writer();
    writeln!(console_writer, "SPDM_TASK: Running SPDM-TASK...").unwrap();

    // Initialize the shared certificate store
    if let Err(e) = initialize_cert_store().await {
        writeln!(
            console_writer,
            "SPDM_TASK: Failed to initialize certificate store: {:?}",
            e
        )
        .unwrap();
        return;
    }

    if let Err(e) = spawner.spawn(spdm_mctp_responder()) {
        writeln!(
            console_writer,
            "SPDM_TASK: Failed to spawn spdm_mctp_responder: {:?}",
            e
        )
        .unwrap();
    }
    if let Err(e) = spawner.spawn(spdm_doe_responder()) {
        writeln!(
            console_writer,
            "SPDM_TASK: Failed to spawn spdm_doe_responder: {:?}",
            e
        )
        .unwrap();
    }
}

#[embassy_executor::task]
async fn spdm_mctp_responder() {
    let mut raw_buffer = [0; MAX_SPDM_RESPONDER_BUF_SIZE];
    let mut cw = Console::<DefaultSyscalls>::writer();
    let mut mctp_spdm_transport: MctpTransport = MctpTransport::new(mctp::driver_num::MCTP_SPDM);

    let max_mctp_spdm_msg_size =
        (MAX_SPDM_RESPONDER_BUF_SIZE - mctp_spdm_transport.header_size()) as u32;

    let local_capabilities = DeviceCapabilities {
        ct_exponent: CALIPTRA_SPDM_CT_EXPONENT,
        flags: CapabilityFlags::default(),
        data_transfer_size: max_mctp_spdm_msg_size,
        max_spdm_msg_size: max_mctp_spdm_msg_size,
    };

    let local_algorithms = LocalDeviceAlgorithms::default();

    // Create a wrapper for the global certificate store
    let shared_cert_store = SharedCertStore::new();

    let mut ctx = match SpdmContext::new(
        SPDM_VERSIONS,
        SECURE_SPDM_VERSIONS,
        &mut mctp_spdm_transport,
        local_capabilities,
        local_algorithms,
        &shared_cert_store,
        None,
    ) {
        Ok(ctx) => ctx,
        Err(e) => {
            writeln!(
                cw,
                "SPDM_MCTP_RESPONDER: Failed to create SPDM context: {:?}",
                e
            )
            .unwrap();
            return;
        }
    };

    let mut msg_buffer = MessageBuf::new(&mut raw_buffer);
    loop {
        let result = ctx.process_message(&mut msg_buffer).await;
        match result {
            Ok(_) => {
                writeln!(cw, "SPDM_MCTP_RESPONDER: Process message successfully").unwrap();
            }
            Err(e) => {
                writeln!(cw, "SPDM_MCTP_RESPONDER: Process message failed: {:?}", e).unwrap();
            }
        }
    }
}

#[embassy_executor::task]
async fn spdm_doe_responder() {
    let mut raw_buffer = [0; MAX_SPDM_RESPONDER_BUF_SIZE];
    let mut cw = Console::<DefaultSyscalls>::writer();
    let mut doe_spdm_transport: DoeTransport = DoeTransport::new(doe::driver_num::DOE_SPDM);

    let max_doe_spdm_msg_size =
        (MAX_SPDM_RESPONDER_BUF_SIZE - doe_spdm_transport.header_size()) as u32;

    let mut doe_capability_flags = CapabilityFlags::default();
    doe_capability_flags.set_key_ex_cap(1);
    doe_capability_flags.set_mac_cap(1);
    doe_capability_flags.set_encrypt_cap(1);

    let local_capabilities = DeviceCapabilities {
        ct_exponent: CALIPTRA_SPDM_CT_EXPONENT,
        flags: doe_capability_flags,
        data_transfer_size: max_doe_spdm_msg_size,
        max_spdm_msg_size: max_doe_spdm_msg_size,
    };

    let mut device_doe_algorithms = DeviceAlgorithms::default();
    device_doe_algorithms.set_dhe_group();
    device_doe_algorithms.set_aead_cipher_suite();
    device_doe_algorithms.set_spdm_key_schedule();
    device_doe_algorithms.set_other_param_support();

    let local_algorithms = LocalDeviceAlgorithms::new(device_doe_algorithms);

    // Create a wrapper for the global certificate store
    let shared_cert_store = SharedCertStore::new();

    let mut ctx = match SpdmContext::new(
        SPDM_VERSIONS,
        SECURE_SPDM_VERSIONS,
        &mut doe_spdm_transport,
        local_capabilities,
        local_algorithms,
        &shared_cert_store,
        None,
    ) {
        Ok(ctx) => ctx,
        Err(e) => {
            writeln!(
                cw,
                "SPDM_DOE_RESPONDER: Failed to create SPDM context: {:?}",
                e
            )
            .unwrap();
            return;
        }
    };

    let mut msg_buffer = MessageBuf::new(&mut raw_buffer);
    loop {
        let result = ctx.process_message(&mut msg_buffer).await;
        match result {
            Ok(_) => {
                writeln!(cw, "SPDM_DOE_RESPONDER: Process message successfully").unwrap();
            }
            Err(e) => {
                writeln!(cw, "SPDM_DOE_RESPONDER: Process message failed: {:?}", e).unwrap();
            }
        }
    }
}

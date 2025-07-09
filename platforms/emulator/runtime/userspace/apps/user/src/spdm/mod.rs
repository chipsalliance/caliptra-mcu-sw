// Licensed under the Apache-2.0 license

mod cert_slot_mgr;
mod config;

use cert_slot_mgr::cert_store::{
    initialize_shared_cert_store, CertChain, DeviceCertStore, SharedCertStore,
};
use cert_slot_mgr::device_cert::DeviceCertIndex;
use cert_slot_mgr::endorsement_cert::EndorsementCertChain;
use core::fmt::Write;
use embassy_executor::Spawner;
use libapi_caliptra::certificate::CertContext;
use libapi_caliptra::error::CaliptraApiError;
use libsyscall_caliptra::doe;
use libsyscall_caliptra::mctp;
use libsyscall_caliptra::DefaultSyscalls;
use libtock_console::Console;
use spdm_lib::cert_store::CertStoreError;
use spdm_lib::cert_store::CertStoreResult;
use spdm_lib::codec::MessageBuf;
use spdm_lib::context::SpdmContext;
use spdm_lib::protocol::*;
use spdm_lib::transport::common::SpdmTransport;
use spdm_lib::transport::doe::DoeTransport;
use spdm_lib::transport::mctp::MctpTransport;

// Maximum SPDM responder buffer size
const MAX_RESPONDER_BUF_SIZE: usize = 2048;

// Caliptra supported SPDM versions
const SPDM_VERSIONS: &[SpdmVersion] = &[SpdmVersion::V12, SpdmVersion::V13];

// Calitra Crypto timeout exponent (2^20 us)
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
    let mut raw_buffer = [0; MAX_RESPONDER_BUF_SIZE];
    let mut cw = Console::<DefaultSyscalls>::writer();
    let mut mctp_spdm_transport: MctpTransport = MctpTransport::new(mctp::driver_num::MCTP_SPDM);

    let max_mctp_spdm_msg_size =
        (MAX_RESPONDER_BUF_SIZE - mctp_spdm_transport.header_size()) as u32;

    let local_capabilities = DeviceCapabilities {
        ct_exponent: CALIPTRA_SPDM_CT_EXPONENT,
        flags: CapabilityFlags::default(),
        data_transfer_size: max_mctp_spdm_msg_size,
        max_spdm_msg_size: max_mctp_spdm_msg_size,
    };

    // Create a wrapper for the global certificate store
    let shared_cert_store = SharedCertStore::new();

    let mut ctx = match SpdmContext::new(
        SPDM_VERSIONS,
        &mut mctp_spdm_transport,
        local_capabilities,
        &shared_cert_store,
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
    let mut raw_buffer = [0; MAX_RESPONDER_BUF_SIZE];
    let mut cw = Console::<DefaultSyscalls>::writer();
    let mut doe_spdm_transport: DoeTransport = DoeTransport::new(doe::driver_num::DOE_SPDM);

    let max_doe_spdm_msg_size = (MAX_RESPONDER_BUF_SIZE - doe_spdm_transport.header_size()) as u32;

    let local_capabilities = DeviceCapabilities {
        ct_exponent: CALIPTRA_SPDM_CT_EXPONENT,
        flags: CapabilityFlags::default(),
        data_transfer_size: max_doe_spdm_msg_size,
        max_spdm_msg_size: max_doe_spdm_msg_size,
    };

    // Create a wrapper for the global certificate store
    let shared_cert_store = SharedCertStore::new();

    let mut ctx = match SpdmContext::new(
        SPDM_VERSIONS,
        &mut doe_spdm_transport,
        local_capabilities,
        &shared_cert_store,
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

pub async fn initialize_cert_store() -> CertStoreResult<()> {
    // populate signed idev cert into the device.
    populate_idev_cert().await?;

    // Initialize the certificate store
    let mut cert_store = DeviceCertStore::new();

    // Initialize slot 0 certificate chain
    let slot0_endorsement = EndorsementCertChain::new(config::SLOT0_ECC_ROOT_CERT_CHAIN).await?;
    let slot0_cert_chain = CertChain::new(slot0_endorsement, DeviceCertIndex::IdevId);
    cert_store.set_cert_chain(0, slot0_cert_chain)?;

    initialize_shared_cert_store(cert_store).await?;
    Ok(())
}

async fn populate_idev_cert() -> CertStoreResult<()> {
    let mut cert_ctx = CertContext::new();

    while let Err(e) = cert_ctx
        .populate_idev_ecc384_cert(&config::SLOT0_ECC_DEVID_CERT_DER)
        .await
    {
        match e {
            CaliptraApiError::MailboxBusy => continue, // Retry if the mailbox is busy
            _ => Err(CertStoreError::CaliptraApi(e))?,
        }
    }

    Ok(())
}

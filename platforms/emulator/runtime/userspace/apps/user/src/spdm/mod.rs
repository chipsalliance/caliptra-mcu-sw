// Licensed under the Apache-2.0 license

mod cert_store;
mod device_cert_store;
mod device_measurements;
mod endorsement_certs;
#[cfg(feature = "test-doe-spdm-tdisp-ide-validator")]
mod integration_example;

#[cfg(feature = "test-mctp-spdm-responder-conformance")]
use crate::spdm::device_measurements::ocp_eat::init_target_env_claims;
use core::fmt::Write;
use device_cert_store::{initialize_cert_store, SharedCertStore};
use embassy_executor::Spawner;
use libsyscall_caliptra::doe;
use libsyscall_caliptra::mctp;
use libsyscall_caliptra::DefaultSyscalls;
use libtock_console::Console;
use libtock_platform::ErrorCode;
use spdm_lib::codec::MessageBuf;
use spdm_lib::context::{SpdmContext, MAX_SPDM_RESPONDER_BUF_SIZE};
use spdm_lib::error::SpdmError;
use spdm_lib::measurements::SpdmMeasurements;
use spdm_lib::protocol::*;
use spdm_lib::transport::common::SpdmTransport;
use spdm_lib::transport::common::TransportError;
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

    // initialize target environment for claims
    #[cfg(feature = "test-mctp-spdm-responder-conformance")]
    init_target_env_claims();

    #[cfg(feature = "test-mctp-spdm-responder-conformance")]
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

    // Measurements in OCP EAT format
    #[cfg(feature = "test-mctp-spdm-responder-conformance")]
    let (mut device_ocp_eat, meas_value_info) =
        device_measurements::ocp_eat::create_manifest_with_ocp_eat();
    #[cfg(feature = "test-mctp-spdm-responder-conformance")]
    let device_measurements = SpdmMeasurements::new(&meas_value_info, &mut device_ocp_eat);

    #[cfg(not(feature = "test-mctp-spdm-responder-conformance"))]
    let (mut device_pcr_quote, meas_value_info) =
        device_measurements::pcr_quote::create_manifest_with_pcr_quote();
    #[cfg(not(feature = "test-mctp-spdm-responder-conformance"))]
    let device_measurements = SpdmMeasurements::new(&meas_value_info, &mut device_pcr_quote);

    let mut ctx = match SpdmContext::new(
        SPDM_VERSIONS,
        SECURE_SPDM_VERSIONS,
        &mut mctp_spdm_transport,
        local_capabilities,
        local_algorithms,
        &shared_cert_store,
        device_measurements,
        None, // VDM handlers are not supported for MCTP transport in this configuration
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

    // Measurements in PCR Quote format
    let (mut device_pcr_quote, meas_value_info) =
        device_measurements::pcr_quote::create_manifest_with_pcr_quote();
    let device_measurements = SpdmMeasurements::new(&meas_value_info, &mut device_pcr_quote);

    // Create test drivers and VDM handlers locally for integration testing
    #[cfg(feature = "test-doe-spdm-tdisp-ide-validator")]
    let (mut tdisp_driver, mut ide_km_driver) =
        integration_example::vdm_handlers::create_test_pci_sig_drivers();

    #[cfg(feature = "test-doe-spdm-tdisp-ide-validator")]
    let mut tdisp_responder = spdm_lib::vdm_handler::pci_sig::tdisp::TdispResponder::new(
        integration_example::vdm_handlers::tdisp_driver::SUPPORTED_TDISP_VERSIONS,
        &mut tdisp_driver,
    );

    #[cfg(feature = "test-doe-spdm-tdisp-ide-validator")]
    let mut ide_km_responder =
        spdm_lib::vdm_handler::pci_sig::ide_km::IdeKmResponder::new(&mut ide_km_driver);

    #[cfg(feature = "test-doe-spdm-tdisp-ide-validator")]
    let protocol_handlers: [Option<&mut (dyn spdm_lib::vdm_handler::VdmProtocolHandler + Sync)>;
        2] = [
        tdisp_responder
            .as_mut()
            .map(|r| r as &mut (dyn spdm_lib::vdm_handler::VdmProtocolHandler + Sync)),
        Some(&mut ide_km_responder as &mut (dyn spdm_lib::vdm_handler::VdmProtocolHandler + Sync)),
    ];

    #[cfg(feature = "test-doe-spdm-tdisp-ide-validator")]
    let mut pci_sig_handler = spdm_lib::vdm_handler::pci_sig::PciSigCmdHandler::new(
        0x0001, // TEST_PCI_SIG_VENDOR_ID
        protocol_handlers,
    );

    #[cfg(feature = "test-doe-spdm-tdisp-ide-validator")]
    let mut handlers_array: [&mut dyn spdm_lib::vdm_handler::VdmHandler; 1] =
        [&mut pci_sig_handler as &mut dyn spdm_lib::vdm_handler::VdmHandler];

    #[cfg(feature = "test-doe-spdm-tdisp-ide-validator")]
    let vdm_handlers: Option<&mut [&mut dyn spdm_lib::vdm_handler::VdmHandler]> =
        Some(&mut handlers_array);

    #[cfg(not(feature = "test-doe-spdm-tdisp-ide-validator"))]
    let vdm_handlers: Option<&mut [&mut dyn spdm_lib::vdm_handler::VdmHandler]> = None;

    let mut ctx = match SpdmContext::new(
        SPDM_VERSIONS,
        SECURE_SPDM_VERSIONS,
        &mut doe_spdm_transport,
        local_capabilities,
        local_algorithms,
        &shared_cert_store,
        device_measurements,
        vdm_handlers,
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
            Err(SpdmError::Transport(TransportError::DriverError(ErrorCode::NoDevice))) => {
                writeln!(cw, "SPDM_DOE_RESPONDER: No DOE device, exiting task").unwrap();
                break;
            }
            Err(e) => {
                writeln!(cw, "SPDM_DOE_RESPONDER: Process message failed: {:?}", e).unwrap();
            }
        }
    }
}

// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]
#![feature(impl_trait_in_assoc_type)]
#![allow(static_mut_refs)]

use core::fmt::Write;
use libsyscall_caliptra::mctp::driver_num;
use libtock_console::{Console, ConsoleWriter};
use libtock_platform::Syscalls;
use spdm_lib::cert_mgr::DeviceCertsManager;
use spdm_lib::codec::MessageBuf;
use spdm_lib::context::SpdmContext;
use spdm_lib::protocol::*;
use spdm_lib::transport::MctpTransport;

// Caliptra supported SPDM versions
const SPDM_VERSIONS: &[SpdmVersion] = &[
    SpdmVersion::V10,
    SpdmVersion::V11,
    SpdmVersion::V12,
    SpdmVersion::V13,
];

// Calitra Crypto timeout exponent (2^20 us)
const CALIPTRA_SPDM_CT_EXPONENT: u8 = 20;

// Caliptra Hash Priority table
static HASH_PRIORITY_TABLE: &[BaseHashAlgoType] = &[
    BaseHashAlgoType::TpmAlgSha512,
    BaseHashAlgoType::TpmAlgSha384,
    BaseHashAlgoType::TpmAlgSha256,
];

// Only support slot 0 for now. Adjust this when we support multiple slots.
pub const CERT_CHAIN_SLOT_MASK: u8 = 0x01;

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
    let mut mctp_spdm_transport: MctpTransport = MctpTransport::new(driver_num::MCTP_SPDM);

    let max_mctp_spdm_msg_size =
        (MAX_MCTP_SPDM_MSG_SIZE - mctp_spdm_transport.header_size()) as u32;

    let local_capabilities = DeviceCapabilities {
        ct_exponent: CALIPTRA_SPDM_CT_EXPONENT,
        flags: device_capability_flags(),
        data_transfer_size: max_mctp_spdm_msg_size,
        max_spdm_msg_size: max_mctp_spdm_msg_size,
    };

    let local_algorithms = LocalDeviceAlgorithms {
        device_algorithms: device_algorithms(),
        algorithm_priority_table: AlgorithmPriorityTable {
            measurement_specification: None,
            opaque_data_format: None,
            base_asym_algo: None,
            base_hash_algo: Some(HASH_PRIORITY_TABLE),
            mel_specification: None,
            dhe_group: None,
            aead_cipher_suite: None,
            req_base_asym_algo: None,
            key_schedule: None,
        },
    };

    let device_certs_mgr = DeviceCertsManager::new(CERT_CHAIN_SLOT_MASK, CERT_CHAIN_SLOT_MASK);

    let mut ctx = match SpdmContext::new(
        SPDM_VERSIONS,
        &mut mctp_spdm_transport,
        local_capabilities,
        local_algorithms,
        &device_certs_mgr,
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

fn device_capability_flags() -> CapabilityFlags {
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

    capability_flags
}

fn device_algorithms() -> DeviceAlgorithms {
    let mut measurement_spec = MeasurementSpecification::default();
    measurement_spec.set_dmtf_measurement_spec(1);

    let other_param_support = OtherParamSupport::default();

    let mut measurement_hash_algo = MeasurementHashAlgo::default();
    measurement_hash_algo.set_tpm_alg_sha_384(1);

    let mut base_asym_algo = BaseAsymAlgo::default();
    base_asym_algo.set_tpm_alg_ecdsa_ecc_nist_p384(1);

    let mut base_hash_algo = BaseHashAlgo::default();
    base_hash_algo.set_tpm_alg_sha_256(1);
    base_hash_algo.set_tpm_alg_sha_384(1);
    base_hash_algo.set_tpm_alg_sha_512(1);

    let mut mel_specification = MelSpecification::default();
    mel_specification.set_dmtf_mel_spec(1);

    let dhe_group = DheNamedGroup::default();
    let aead_cipher_suite = AeadCipherSuite::default();
    let req_base_asym_algo = ReqBaseAsymAlg::default();
    let key_schedule = KeySchedule::default();

    DeviceAlgorithms {
        measurement_spec,
        other_param_support,
        measurement_hash_algo,
        base_asym_algo,
        base_hash_algo,
        mel_specification,
        dhe_group,
        aead_cipher_suite,
        req_base_asym_algo,
        key_schedule,
    }
}

// Licensed under the Apache-2.0 license

mod common;
pub mod mctp;
mod transport;

pub enum SpdmTestType {
    SpdmResponderConformance,
    SpdmTeeIoValidator,
    SpdmAttestation,
}

pub use common::{
    execute_spdm_attestation, execute_spdm_responder_validator, execute_spdm_tee_io_validator,
    SpdmValidatorRunner, SERVER_LISTENING,
};
pub use transport::SOCKET_TRANSPORT_TYPE_PCI_DOE;

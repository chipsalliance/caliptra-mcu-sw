// Licensed under the Apache-2.0 license

mod common;
pub mod doe;
pub mod mctp;
mod transport;

pub enum SpdmTestType {
    SpdmResponderConformance,
    SpdmTeeIoValidator,
}

pub use common::{execute_spdm_responder_validator, SpdmValidatorRunner, SERVER_LISTENING};

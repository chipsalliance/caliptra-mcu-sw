// Licensed under the Apache-2.0 license

//! Error code constants produced by spdm-lite transports.
//!
//! Subdomain bytes live in [`mcu_spdm_lite_errors`]; this module owns
//! the per-transport [`McuErrorCode`] constants. Each transport gets its
//! own submodule so callers can `use mcu_spdm_lite_transports::errors::mctp::*;`.

use mcu_error::{domain, McuErrorCode};

/// Error codes returned by [`crate::mctp::McuSpdmMctpTransport`].
///
/// All codes live in [`mcu_error::domain::SPDM`] subdomain
/// [`mcu_spdm_lite_errors::SUBDOMAIN_MCTP`].
pub mod mctp {
    use super::{domain, McuErrorCode};
    use mcu_spdm_lite_errors::SUBDOMAIN_MCTP;

    /// The received message did not match the configured MCTP message type.
    pub const UNEXPECTED_MESSAGE_TYPE: McuErrorCode =
        McuErrorCode::new(domain::SPDM, SUBDOMAIN_MCTP, 0x0001);

    /// `send_response` was called without a prior successful
    /// `recv_request` (no captured `MessageInfo`).
    pub const NO_REQUEST_IN_FLIGHT: McuErrorCode =
        McuErrorCode::new(domain::SPDM, SUBDOMAIN_MCTP, 0x0002);

    /// The received message is malformed (shorter than the MCTP
    /// header, or longer than the receive buffer).
    pub const INVALID_MESSAGE: McuErrorCode =
        McuErrorCode::new(domain::SPDM, SUBDOMAIN_MCTP, 0x0003);

    /// A secured-message operation was requested but this transport
    /// does not support SPDM Secured Messages.
    pub const OPERATION_NOT_SUPPORTED: McuErrorCode =
        McuErrorCode::new(domain::SPDM, SUBDOMAIN_MCTP, 0x0004);

    /// The caller-provided receive buffer is too small to hold even
    /// the MCTP transport header.
    pub const BUFFER_TOO_SMALL: McuErrorCode =
        McuErrorCode::new(domain::SPDM, SUBDOMAIN_MCTP, 0x0005);
}

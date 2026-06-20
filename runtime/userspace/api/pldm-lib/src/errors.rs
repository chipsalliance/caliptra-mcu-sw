// Licensed under the Apache-2.0 license

//! PLDM error codes within [`mcu_error::domain::PLDM`].
//!
//! Subdomain and code allocations are owned by this crate.

use mcu_error::{domain, McuErrorCode};

// ----- Subdomain registry under PLDM domain ----------------------------------

/// Transport-layer errors (MCTP send/receive).
pub const SUBDOMAIN_TRANSPORT: u8 = 0x01;

/// Codec errors (encode/decode failures).
pub const SUBDOMAIN_CODEC: u8 = 0x02;

/// PLDM common-layer errors.
pub const SUBDOMAIN_COMMON: u8 = 0x03;

/// Firmware-device operations errors.
pub const SUBDOMAIN_FD_OPS: u8 = 0x04;

/// Utility errors.
pub const SUBDOMAIN_UTIL: u8 = 0x05;

/// Command-interface errors.
pub const SUBDOMAIN_CMD: u8 = 0x06;

// ----- Transport errors (subdomain 0x01) --------------------------------------

/// Generic MCTP driver error.
pub const DRIVER_ERROR: McuErrorCode = McuErrorCode::new(domain::PLDM, SUBDOMAIN_TRANSPORT, 0x0001);

/// Supplied buffer is too small.
pub const BUFFER_TOO_SMALL: McuErrorCode =
    McuErrorCode::new(domain::PLDM, SUBDOMAIN_TRANSPORT, 0x0002);

/// MCTP message type header mismatch.
pub const UNEXPECTED_MESSAGE_TYPE: McuErrorCode =
    McuErrorCode::new(domain::PLDM, SUBDOMAIN_TRANSPORT, 0x0003);

/// Failed to receive from the MCTP driver.
pub const RECEIVE_ERROR: McuErrorCode =
    McuErrorCode::new(domain::PLDM, SUBDOMAIN_TRANSPORT, 0x0004);

/// Failed to send via the MCTP driver.
pub const SEND_ERROR: McuErrorCode = McuErrorCode::new(domain::PLDM, SUBDOMAIN_TRANSPORT, 0x0005);

/// Received a response without a pending request.
pub const RESPONSE_NOT_EXPECTED: McuErrorCode =
    McuErrorCode::new(domain::PLDM, SUBDOMAIN_TRANSPORT, 0x0006);

/// Tried to send a response without a pending request.
pub const NO_REQUEST_IN_FLIGHT: McuErrorCode =
    McuErrorCode::new(domain::PLDM, SUBDOMAIN_TRANSPORT, 0x0007);

// ----- Codec errors (subdomain 0x02) ------------------------------------------

/// PLDM message encode/decode failure.
pub const CODEC_ERROR: McuErrorCode = McuErrorCode::new(domain::PLDM, SUBDOMAIN_CODEC, 0x0001);

// ----- PLDM common errors (subdomain 0x03) ------------------------------------

/// Error from the PLDM common layer.
pub const PLDM_COMMON_ERROR: McuErrorCode =
    McuErrorCode::new(domain::PLDM, SUBDOMAIN_COMMON, 0x0001);

// ----- Firmware-device operations errors (subdomain 0x04) ---------------------

/// Failed to retrieve device identifiers.
pub const DEVICE_IDENTIFIERS_ERROR: McuErrorCode =
    McuErrorCode::new(domain::PLDM, SUBDOMAIN_FD_OPS, 0x0001);

/// Failed to retrieve firmware parameters.
pub const FIRMWARE_PARAMETERS_ERROR: McuErrorCode =
    McuErrorCode::new(domain::PLDM, SUBDOMAIN_FD_OPS, 0x0002);

/// Transfer size negotiation failed.
pub const TRANSFER_SIZE_ERROR: McuErrorCode =
    McuErrorCode::new(domain::PLDM, SUBDOMAIN_FD_OPS, 0x0003);

/// Component-level operation failed.
pub const COMPONENT_ERROR: McuErrorCode = McuErrorCode::new(domain::PLDM, SUBDOMAIN_FD_OPS, 0x0004);

/// Firmware download error.
pub const FW_DOWNLOAD_ERROR: McuErrorCode =
    McuErrorCode::new(domain::PLDM, SUBDOMAIN_FD_OPS, 0x0005);

/// Firmware verify error.
pub const VERIFY_ERROR: McuErrorCode = McuErrorCode::new(domain::PLDM, SUBDOMAIN_FD_OPS, 0x0006);

/// Firmware apply error.
pub const APPLY_ERROR: McuErrorCode = McuErrorCode::new(domain::PLDM, SUBDOMAIN_FD_OPS, 0x0007);

/// Firmware activate error.
pub const ACTIVATE_ERROR: McuErrorCode = McuErrorCode::new(domain::PLDM, SUBDOMAIN_FD_OPS, 0x0008);

/// Cancel update error.
pub const CANCEL_UPDATE_ERROR: McuErrorCode =
    McuErrorCode::new(domain::PLDM, SUBDOMAIN_FD_OPS, 0x0009);

// ----- Utility errors (subdomain 0x05) ----------------------------------------

/// MCTP transport utility error.
pub const UTIL_ERROR: McuErrorCode = McuErrorCode::new(domain::PLDM, SUBDOMAIN_UTIL, 0x0001);

// ----- Command-interface errors (subdomain 0x06) ------------------------------

/// A transport-level failure while handling a command.
pub const TRANSPORT_ERROR: McuErrorCode = McuErrorCode::new(domain::PLDM, SUBDOMAIN_CMD, 0x0001);

/// FD initiator mode error.
pub const FD_INITIATOR_MODE_ERROR: McuErrorCode =
    McuErrorCode::new(domain::PLDM, SUBDOMAIN_CMD, 0x0002);

/// Handler is busy / not ready to accept a new request.
pub const NOT_READY: McuErrorCode = McuErrorCode::new(domain::PLDM, SUBDOMAIN_CMD, 0x0003);

/// Generic firmware-device operations error.
pub const FD_OPS_ERROR: McuErrorCode = McuErrorCode::new(domain::PLDM, SUBDOMAIN_CMD, 0x0004);

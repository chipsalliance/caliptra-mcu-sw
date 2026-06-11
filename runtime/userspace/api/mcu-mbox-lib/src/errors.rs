// Licensed under the Apache-2.0 license

//! MCU-mailbox error codes within [`mcu_error::domain::MAILBOX`].
//!
//! Subdomain and code allocations are owned by this crate.

use mcu_error::{domain, McuErrorCode};

// ----- Subdomain registry under MAILBOX domain --------------------------------

/// Transport-layer errors (driver I/O, framing, checksums).
pub const SUBDOMAIN_TRANSPORT: u8 = 0x01;

/// Command-interface errors (request handling, authorisation).
pub const SUBDOMAIN_CMD: u8 = 0x02;

// ----- Transport errors (subdomain 0x01) --------------------------------------

/// Failed to receive from the mailbox driver.
pub const DRIVER_RX_ERROR: McuErrorCode =
    McuErrorCode::new(domain::MAILBOX, SUBDOMAIN_TRANSPORT, 0x0001);

/// Failed to send via the mailbox driver.
pub const DRIVER_TX_ERROR: McuErrorCode =
    McuErrorCode::new(domain::MAILBOX, SUBDOMAIN_TRANSPORT, 0x0002);

/// Supplied buffer is too small for the operation.
pub const BUFFER_TOO_SMALL: McuErrorCode =
    McuErrorCode::new(domain::MAILBOX, SUBDOMAIN_TRANSPORT, 0x0003);

/// Received request is malformed.
pub const INVALID_REQUEST: McuErrorCode =
    McuErrorCode::new(domain::MAILBOX, SUBDOMAIN_TRANSPORT, 0x0004);

/// Received response is malformed.
pub const INVALID_RESPONSE: McuErrorCode =
    McuErrorCode::new(domain::MAILBOX, SUBDOMAIN_TRANSPORT, 0x0005);

/// Checksum mismatch on a request or response.
pub const CHKSUM_MISMATCH: McuErrorCode =
    McuErrorCode::new(domain::MAILBOX, SUBDOMAIN_TRANSPORT, 0x0006);

// ----- Command-interface errors (subdomain 0x02) ------------------------------

/// A transport-level failure while handling a command.
pub const TRANSPORT_ERROR: McuErrorCode = McuErrorCode::new(domain::MAILBOX, SUBDOMAIN_CMD, 0x0001);

/// Generic MCU-mailbox common layer error.
pub const MCU_MBOX_COMMON: McuErrorCode = McuErrorCode::new(domain::MAILBOX, SUBDOMAIN_CMD, 0x0002);

/// Handler is busy / not ready to accept a new request.
pub const NOT_READY: McuErrorCode = McuErrorCode::new(domain::MAILBOX, SUBDOMAIN_CMD, 0x0003);

/// Invalid parameters in the request payload.
pub const INVALID_PARAMS: McuErrorCode = McuErrorCode::new(domain::MAILBOX, SUBDOMAIN_CMD, 0x0004);

/// The command code is not supported.
pub const UNSUPPORTED_COMMAND: McuErrorCode =
    McuErrorCode::new(domain::MAILBOX, SUBDOMAIN_CMD, 0x0005);

/// The command requires authorization that was not provided.
pub const UNAUTHORIZED_COMMAND: McuErrorCode =
    McuErrorCode::new(domain::MAILBOX, SUBDOMAIN_CMD, 0x0006);

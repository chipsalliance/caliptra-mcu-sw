// Licensed under the Apache-2.0 license

//! Subdomain registry for the SPDM-Lite stack.
//!
//! Every SPDM-Lite crate that produces errors picks a [subdomain
//! byte](#subdomains) from this central registry, then defines its
//! own concrete [`McuErrorCode`] constants in its own `errors` module
//! using `mcu_error::McuErrorCode::new(domain::SPDM, SUBDOMAIN_*, code)`.
//!
//! Centralizing **just the subdomain bytes** here gives:
//!
//! * Collision detection — one file lists every subdomain assigned
//!   under [`domain::SPDM`].
//! * Bit-layout conventions — the SPDM wire-byte encoding lives next
//!   to the subdomain bytes (see [`spdm_wire`] / [`as_spdm_wire`]).
//! * Cross-crate classifier helpers ([`is_spdm_wire`],
//!   [`is_mctp_error`], …) so a logger or error-PDU encoder can
//!   inspect any [`McuErrorCode`] without depending on every owning
//!   crate.
//!
//! Specific error constants (e.g. `SPDM_INVALID_REQUEST`,
//! `MCTP_BUFFER_TOO_SMALL`) stay in the crate that produces them.

#![no_std]
#![forbid(unsafe_code)]

use mcu_error::{domain, McuErrorCode};

// ----- Subdomain registry under [`mcu_error::domain::SPDM`] ------------------

/// spdm-lite stack / codec local errors (never appear on the wire).
///
/// Used by:
/// * `mcu-spdm-lite-codec` for parser/encoder failures
/// * `mcu-spdm-lite-stack` for dispatch/state-machine errors
pub const SUBDOMAIN_LOCAL: u8 = 0x00;

/// SPDM wire errors per DSP0274 §10.10.2.
///
/// The low byte of the resulting [`McuErrorCode::code`] carries the
/// spec-defined SPDM error byte; responders extract it with
/// [`as_spdm_wire`] and inject it into the wire `ERROR` PDU.
pub const SUBDOMAIN_WIRE: u8 = 0x01;

/// MCTP transport (used by SPDM).
///
/// Used by `mcu-spdm-lite-transports::mctp`.
pub const SUBDOMAIN_MCTP: u8 = 0x10;

/// PCIe DOE transport (used by SPDM) — reserved for future use.
pub const SUBDOMAIN_DOE: u8 = 0x11;

// ----- Wire-byte convention --------------------------------------------------

/// Builds an [`McuErrorCode`] from a DSP0274 §10.10.2 SPDM error byte.
///
/// The byte is preserved in the low 8 bits of the resulting `code`,
/// so SPDM responders can recover it via [`as_spdm_wire`] and write
/// it directly into the wire `ERROR` PDU.
#[inline]
pub const fn spdm_wire(spec_byte: u8) -> McuErrorCode {
    McuErrorCode::new(domain::SPDM, SUBDOMAIN_WIRE, spec_byte as u16)
}

/// If `e` is a [`spdm_wire`] error, returns its DSP0274 byte.
#[inline]
pub const fn as_spdm_wire(e: McuErrorCode) -> Option<u8> {
    if e.domain() == domain::SPDM && e.subdomain() == SUBDOMAIN_WIRE {
        Some(e.code() as u8)
    } else {
        None
    }
}

// ----- Classifier helpers ----------------------------------------------------

/// `true` if `e` is an spdm-lite local error (never on the wire).
#[inline]
pub const fn is_spdm_local(e: McuErrorCode) -> bool {
    e.domain() == domain::SPDM && e.subdomain() == SUBDOMAIN_LOCAL
}

/// `true` if `e` is an SPDM wire error (DSP0274 §10.10.2).
#[inline]
pub const fn is_spdm_wire(e: McuErrorCode) -> bool {
    e.domain() == domain::SPDM && e.subdomain() == SUBDOMAIN_WIRE
}

/// `true` if `e` is an MCTP-transport error.
#[inline]
pub const fn is_mctp_error(e: McuErrorCode) -> bool {
    e.domain() == domain::SPDM && e.subdomain() == SUBDOMAIN_MCTP
}

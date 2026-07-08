// Licensed under the Apache-2.0 license

//! SPDM PAL-local error codes.

use caliptra_mcu_spdm_codec::errors::SUBDOMAIN_PAL;
use mcu_error::{domain, McuErrorCode};

/// A cert slot's endorsement/provisioning state changed while producing
/// cert-derived data or a slot-backed signature.
pub const CERT_SLOT_STATE_CHANGED: McuErrorCode =
    McuErrorCode::new(domain::SPDM, SUBDOMAIN_PAL, 0x0001);

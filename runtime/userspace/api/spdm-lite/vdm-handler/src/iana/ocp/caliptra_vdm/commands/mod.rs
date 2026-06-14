// Licensed under the Apache-2.0 license

//! Per-command handlers for the Caliptra VDM protocol.
//!
//! Each handler decodes its command-specific request, invokes the platform
//! [`CaliptraVdmCommands`](super::CaliptraVdmCommands) PAL hook, and writes the
//! VDM response payload `[completion_code, command_data..]`.

pub(crate) mod export_attested_csr;
pub(crate) mod firmware_version;

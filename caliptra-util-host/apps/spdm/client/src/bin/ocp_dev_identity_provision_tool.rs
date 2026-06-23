// Licensed under the Apache-2.0 license

//! OCP device identity provisioning tool for SPDM SET_CERTIFICATE.
//!
//! This follows the mandatory requester-side provisioning flow from
//! `docs/src/cert_slot_mgmt.md`: establish SPDM VCA and send SET_CERTIFICATE for
//! the Owner slot. Optional discovery/verification steps from the sequence
//! diagram are intentionally skipped by default.

use std::path::PathBuf;

use anyhow::Result;
use caliptra_spdm_vdm_client::ocp_dev_identity_provision::{
    default_cert_chain_path, provision_device_identity, ProvisionOptions,
    DEFAULT_LDEVID_KEY_PAIR_ID, DEFAULT_OWNER_SLOT_ID,
};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "ocp_dev_identity_provision_tool")]
#[command(about = "Provision an OCP device identity certificate slot over SPDM")]
struct Args {
    /// Server address (host:port) of the SPDM bridge.
    #[arg(long, default_value = "127.0.0.1:2323")]
    server: String,

    /// SPDM certificate slot to provision.
    #[arg(long, default_value_t = DEFAULT_OWNER_SLOT_ID)]
    slot_id: u8,

    /// SPDM key pair ID to associate with the slot.
    #[arg(long, default_value_t = DEFAULT_LDEVID_KEY_PAIR_ID)]
    key_pair_id: u8,

    /// DER X.509 certificate chain to install. The tool wraps this in the SPDM
    /// certificate-chain header before sending SET_CERTIFICATE.
    #[arg(long, default_value_os_t = default_cert_chain_path())]
    cert_chain: PathBuf,

    /// Verify the installed certificate with GET_CERTIFICATE after provisioning.
    #[arg(long)]
    verify_get_certificate: bool,
}

fn main() -> Result<()> {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .env()
        .init()
        .ok();

    let args = Args::parse();
    provision_device_identity(&ProvisionOptions {
        server: args.server,
        slot_id: args.slot_id,
        key_pair_id: args.key_pair_id,
        cert_chain: args.cert_chain,
        verify_get_certificate: args.verify_get_certificate,
    })
}

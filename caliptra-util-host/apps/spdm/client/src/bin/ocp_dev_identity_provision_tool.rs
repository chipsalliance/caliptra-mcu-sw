// Licensed under the Apache-2.0 license

//! OCP device identity provisioning tool for SPDM SET_CERTIFICATE.
//!
//! Authenticates the Vendor slot, provisions an Owner/LDevID chain from an
//! attested CSR, and verifies the installed Owner slot.

use std::path::PathBuf;

use anyhow::Result;
use caliptra_spdm_vdm_client::ocp_dev_identity_provision::{
    default_vendor_trust_anchor_path, provision_device_identity, ProvisionOptions,
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


    /// DER X.509 root certificate used to authenticate the initial Vendor slot.
    #[arg(long, default_value_os_t = default_vendor_trust_anchor_path())]
    vendor_trust_anchor: PathBuf,
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
        vendor_trust_anchor: args.vendor_trust_anchor,
    })
}

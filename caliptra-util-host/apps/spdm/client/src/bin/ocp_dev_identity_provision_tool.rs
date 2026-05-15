// Licensed under the Apache-2.0 license

//! OCP device identity provisioning tool for SPDM SET_CERTIFICATE.
//!
//! This follows the mandatory requester-side provisioning flow from
//! `docs/src/cert_slot_mgmt.md`: establish SPDM VCA and send SET_CERTIFICATE for
//! the Owner slot. Optional discovery/verification steps from the sequence
//! diagram are intentionally skipped by default.

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use caliptra_spdm_requester::{SpdmConfig, SpdmRequester, SpdmSocketDeviceIo};
use clap::Parser;

const DEFAULT_OWNER_SLOT_ID: u8 = 2;
const DEFAULT_LDEVID_KEY_PAIR_ID: u8 = 1;
const CERT_MODEL_DEVICE_CERT: u8 = 1;

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
    #[arg(long, default_value = default_cert_chain_path())]
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
    run(args)
}

fn run(args: Args) -> Result<()> {
    println!(
        "[ocp_dev_identity_provision_tool] Connecting to bridge at {}",
        args.server
    );
    let mut device_io = SpdmSocketDeviceIo::connect_mctp(&args.server)?;
    device_io.handshake()?;
    let mut stop_io = device_io.try_clone()?;

    let spdm_config = SpdmConfig {
        slot_id: args.slot_id,
        ..SpdmConfig::default()
    };
    let mut requester = SpdmRequester::new(spdm_config, Box::new(device_io))?;

    println!("[ocp_dev_identity_provision_tool] Establishing SPDM connection");
    requester.connect()?;

    let cert_chain = fs::read(&args.cert_chain).with_context(|| {
        format!(
            "failed to read certificate chain {}",
            args.cert_chain.display()
        )
    })?;
    if cert_chain.is_empty() {
        return Err(anyhow!(
            "certificate chain {} is empty",
            args.cert_chain.display()
        ));
    }

    println!(
        "[ocp_dev_identity_provision_tool] SET_CERTIFICATE slot_id={} key_pair_id={} cert_chain={} ({} bytes)",
        args.slot_id,
        args.key_pair_id,
        args.cert_chain.display(),
        cert_chain.len()
    );
    requester.set_certificate(
        None,
        args.slot_id,
        args.key_pair_id,
        CERT_MODEL_DEVICE_CERT,
        &cert_chain,
    )?;

    if args.verify_get_certificate {
        let provisioned = requester.get_certificate(None, args.slot_id)?;
        if provisioned.len() <= cert_chain.len() {
            return Err(anyhow!(
                "GET_CERTIFICATE returned {} bytes, expected SPDM certificate-chain wrapper plus {} DER bytes",
                provisioned.len(),
                cert_chain.len()
            ));
        }
        if !provisioned.ends_with(&cert_chain) {
            return Err(anyhow!(
                "GET_CERTIFICATE slot {} did not return the provisioned certificate chain",
                args.slot_id
            ));
        }

        println!(
            "[ocp_dev_identity_provision_tool] Provisioning verified (GET_CERTIFICATE returned {} bytes)",
            provisioned.len()
        );
    }
    println!("[ocp_dev_identity_provision_tool] Sending STOP to bridge");
    stop_io.send_stop()?;
    Ok(())
}

fn default_cert_chain_path() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .map(|spdm_dir| spdm_dir.join("certs/test_owner_certchain.der"))
        .unwrap_or_else(|| PathBuf::from("certs/test_owner_certchain.der"))
        .to_string_lossy()
        .into_owned()
}

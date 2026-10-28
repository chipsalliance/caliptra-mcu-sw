// Licensed under the Apache-2.0 license

//! OCP Device Identity Provisioning (DIP) host tool.
//!
//! `discover` and `export-csr` retrieve verified DIP evidence over SPDM for
//! offline certificate issuance. `provision-test` is a demo-only
//! SET_CERTIFICATE flow using a fixed test CA key.

use std::path::PathBuf;

use anyhow::Result;
use caliptra_spdm_vdm_client::ocp_dev_identity_provision::{
    default_vendor_trust_anchor_path, discover, export_csr, provision_device_identity,
    DeviceOptions, ExportCsrOptions, ProvisionOptions, DEFAULT_LDEVID_KEY_PAIR_ID,
    DEFAULT_OWNER_SLOT_ID, DEFAULT_SERVER,
};
use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "ocp_dev_identity_provision_tool")]
#[command(about = "OCP Device Identity Provisioning over SPDM")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Retrieve and verify the device's keypair inventory.
    Discover {
        #[command(flatten)]
        bridge: BridgeArgs,
        /// DER X.509 root certificate used to authenticate the Vendor slot.
        #[arg(long)]
        vendor_trust_anchor: PathBuf,
        /// Write a JSON report of the verified inventory.
        #[arg(long)]
        report_json: Option<PathBuf>,
    },
    /// Export a verified attested CSR and its signed evidence.
    ExportCsr {
        #[command(flatten)]
        bridge: BridgeArgs,
        /// DER X.509 root certificate used to authenticate the Vendor slot.
        #[arg(long)]
        vendor_trust_anchor: PathBuf,
        /// Key pair to export; must be listed in the keypair inventory.
        #[arg(long)]
        key_pair_id: u8,
        /// Output path for the DER PKCS#10 CSR.
        #[arg(long)]
        out_csr: PathBuf,
        /// Output path for the signed EAT (COSE_Sign1/CWT) carrying the CSR.
        #[arg(long)]
        out_eat: PathBuf,
        /// Write a JSON report of the verified CSR evidence.
        #[arg(long)]
        report_json: Option<PathBuf>,
    },
    /// DEMO ONLY: issue an Owner chain from a fixed test CA key and install it
    /// with SET_CERTIFICATE.
    ProvisionTest {
        #[command(flatten)]
        bridge: BridgeArgs,
        /// DER X.509 root certificate used to authenticate the Vendor slot.
        /// Defaults to the test vendor root.
        #[arg(long, default_value_os_t = default_vendor_trust_anchor_path())]
        vendor_trust_anchor: PathBuf,
        /// SPDM certificate slot to provision.
        #[arg(long, default_value_t = DEFAULT_OWNER_SLOT_ID)]
        slot_id: u8,
        /// SPDM key pair ID to associate with the slot.
        #[arg(long, default_value_t = DEFAULT_LDEVID_KEY_PAIR_ID)]
        key_pair_id: u8,
    },
}

#[derive(Args, Debug)]
struct BridgeArgs {
    /// Server address (host:port) of the SPDM bridge.
    #[arg(long, default_value = DEFAULT_SERVER)]
    server: String,
}

impl BridgeArgs {
    fn device(self, vendor_trust_anchor: PathBuf) -> DeviceOptions {
        DeviceOptions {
            server: self.server,
            vendor_trust_anchor,
        }
    }
}

fn main() -> Result<()> {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .env()
        .init()
        .ok();

    match Cli::parse().command {
        Command::Discover {
            bridge,
            vendor_trust_anchor,
            report_json,
        } => discover(&bridge.device(vendor_trust_anchor), report_json.as_deref()).map(drop),
        Command::ExportCsr {
            bridge,
            vendor_trust_anchor,
            key_pair_id,
            out_csr,
            out_eat,
            report_json,
        } => export_csr(&ExportCsrOptions {
            device: bridge.device(vendor_trust_anchor),
            key_pair_id,
            out_csr,
            out_eat,
            report_json,
        }),
        Command::ProvisionTest {
            bridge,
            vendor_trust_anchor,
            slot_id,
            key_pair_id,
        } => provision_device_identity(&ProvisionOptions {
            device: bridge.device(vendor_trust_anchor),
            slot_id,
            key_pair_id,
        }),
    }
}

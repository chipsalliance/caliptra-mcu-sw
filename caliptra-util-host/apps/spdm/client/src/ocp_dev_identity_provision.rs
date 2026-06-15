// Licensed under the Apache-2.0 license

//! OCP device identity provisioning over SPDM SET_CERTIFICATE.

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use caliptra_spdm_requester::{SpdmConfig, SpdmRequester, SpdmSocketDeviceIo};

pub const DEFAULT_OWNER_SLOT_ID: u8 = 2;
pub const DEFAULT_LDEVID_KEY_PAIR_ID: u8 = 1;
const CERT_MODEL_DEVICE_CERT: u8 = 1;

/// Request parameters for provisioning an OCP device identity certificate slot.
pub struct ProvisionOptions {
    /// Server address (host:port) of the SPDM bridge.
    pub server: String,
    /// SPDM certificate slot to provision.
    pub slot_id: u8,
    /// SPDM key pair ID to associate with the slot.
    pub key_pair_id: u8,
    /// DER X.509 certificate chain to install.
    pub cert_chain: PathBuf,
    /// Verify the installed certificate with GET_CERTIFICATE after provisioning.
    pub verify_get_certificate: bool,
}

impl Default for ProvisionOptions {
    fn default() -> Self {
        Self {
            server: "127.0.0.1:2323".to_string(),
            slot_id: DEFAULT_OWNER_SLOT_ID,
            key_pair_id: DEFAULT_LDEVID_KEY_PAIR_ID,
            cert_chain: default_cert_chain_path(),
            verify_get_certificate: false,
        }
    }
}

/// Provision an OCP device identity certificate slot.
///
/// This establishes SPDM VCA, sends SET_CERTIFICATE for `options.cert_chain`,
/// optionally verifies the installed chain with GET_CERTIFICATE, and sends STOP
/// to the test bridge before returning success.
pub fn provision_device_identity(options: &ProvisionOptions) -> Result<()> {
    println!(
        "[ocp_dev_identity_provision_tool] Connecting to bridge at {}",
        options.server
    );
    let mut device_io = SpdmSocketDeviceIo::connect_mctp(&options.server)?;
    device_io.handshake()?;
    let mut stop_io = device_io.try_clone()?;

    let spdm_config = SpdmConfig {
        slot_id: options.slot_id,
        accept_unverified_peer_cert_chain: true,
        ..SpdmConfig::default()
    };
    let mut requester = SpdmRequester::new(spdm_config, Box::new(device_io))?;

    println!("[ocp_dev_identity_provision_tool] Establishing SPDM connection");
    requester.connect()?;

    let cert_chain = fs::read(&options.cert_chain).with_context(|| {
        format!(
            "failed to read certificate chain {}",
            options.cert_chain.display()
        )
    })?;
    if cert_chain.is_empty() {
        return Err(anyhow!(
            "certificate chain {} is empty",
            options.cert_chain.display()
        ));
    }

    println!(
        "[ocp_dev_identity_provision_tool] SET_CERTIFICATE slot_id={} key_pair_id={} cert_chain={} ({} bytes)",
        options.slot_id,
        options.key_pair_id,
        options.cert_chain.display(),
        cert_chain.len()
    );
    requester.set_certificate(
        None,
        options.slot_id,
        options.key_pair_id,
        CERT_MODEL_DEVICE_CERT,
        &cert_chain,
    )?;

    if options.verify_get_certificate {
        let provisioned = requester.get_certificate(None, options.slot_id)?;
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
                options.slot_id
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

pub fn default_cert_chain_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .map(|spdm_dir| spdm_dir.join("certs/test_owner_certchain.der"))
        .unwrap_or_else(|| PathBuf::from("certs/test_owner_certchain.der"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_cert_chain_path_points_to_test_owner_certchain() {
        let path = default_cert_chain_path();

        assert!(
            path.ends_with("apps/spdm/certs/test_owner_certchain.der"),
            "unexpected default cert chain path: {}",
            path.display()
        );
        assert!(
            path.is_file(),
            "default cert chain path does not exist: {}",
            path.display()
        );
    }
}

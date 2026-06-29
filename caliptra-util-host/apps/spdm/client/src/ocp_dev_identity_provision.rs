// Licensed under the Apache-2.0 license

//! OCP device identity provisioning over SPDM SET_CERTIFICATE.

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use caliptra_mcu_core_util_host_command_types::certificate::ExportAttestedCsrResponse;
use caliptra_spdm_requester::{SpdmConfig, SpdmRequester, SpdmSocketDeviceIo, SpdmVdmDriverImpl};

use crate::SpdmVdmClient;

pub const DEFAULT_OWNER_SLOT_ID: u8 = 2;
pub const DEFAULT_LDEVID_KEY_PAIR_ID: u8 = 1;
pub const DEFAULT_VENDOR_SLOT_ID: u8 = 0;
pub const DEFAULT_CSR_ALGORITHM_ECC384: u32 = 1;
const CERT_MODEL_ALIAS_CERT: u8 = 2;
const SPDM_CERT_CHAIN_HEADER_LEN: usize = 4;
const SHA384_DIGEST_LEN: usize = 48;

/// Request parameters for provisioning an OCP device identity certificate slot.
pub struct ProvisionOptions {
    /// Server address (host:port) of the SPDM bridge.
    pub server: String,
    /// SPDM certificate slot to provision.
    pub slot_id: u8,
    /// SPDM key pair ID to associate with the slot.
    pub key_pair_id: u8,
    /// Initial vendor certificate slot used for SPDM connection/attestation.
    pub vendor_slot_id: u8,
    /// Algorithm requested from ExportAttestedCsr (1 = ECC384).
    pub csr_algorithm: u32,
    /// DER X.509 certificate chain to install.
    pub cert_chain: PathBuf,
    /// Verify the installed certificate with GET_CERTIFICATE after provisioning.
    /// This is mandatory for the issue-1711 e2e flow; the field is retained for
    /// source compatibility and must be true in production invocations.
    pub verify_get_certificate: bool,
    /// Export and validate an attested CSR before SET_CERTIFICATE.
    pub require_attested_csr: bool,
}

impl Default for ProvisionOptions {
    fn default() -> Self {
        Self {
            server: "127.0.0.1:2323".to_string(),
            slot_id: DEFAULT_OWNER_SLOT_ID,
            key_pair_id: DEFAULT_LDEVID_KEY_PAIR_ID,
            vendor_slot_id: DEFAULT_VENDOR_SLOT_ID,
            csr_algorithm: DEFAULT_CSR_ALGORITHM_ECC384,
            cert_chain: default_cert_chain_path(),
            verify_get_certificate: true,
            require_attested_csr: true,
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
        slot_id: options.vendor_slot_id,
        accept_unverified_peer_cert_chain: true,
        ..SpdmConfig::default()
    };
    let mut requester = SpdmRequester::new(spdm_config, Box::new(device_io))?;

    println!(
        "[ocp_dev_identity_provision_tool] Establishing SPDM connection using Vendor slot {}",
        options.vendor_slot_id
    );
    requester.connect_authenticated()?;
    println!(
        "[ocp_dev_identity_provision_tool] Initial CHALLENGE attestation passed for Vendor slot {}",
        options.vendor_slot_id
    );

    if options.require_attested_csr {
        let nonce = random_nonce()?;
        let csr = export_attested_csr(
            &mut requester,
            options.key_pair_id as u32,
            options.csr_algorithm,
            &nonce,
        )?;
        validate_attested_csr(&csr, &nonce)?;
        println!(
            "[ocp_dev_identity_provision_tool] ExportAttestedCsr key_pair_id={} returned {} bytes",
            options.key_pair_id, csr.data_len
        );
    }

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
    let provisioned_certs = split_der_certificates(&cert_chain).with_context(|| {
        format!(
            "failed to parse DER certificate chain {}",
            options.cert_chain.display()
        )
    })?;
    if provisioned_certs.len() < 2 {
        bail!(
            "owner/LDevID certificate chain {} must contain at least Owner Root + Endorsed LDevID cert, found {} certificate(s)",
            options.cert_chain.display(),
            provisioned_certs.len()
        );
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
        CERT_MODEL_ALIAS_CERT,
        &cert_chain,
    )?;

    if !options.verify_get_certificate {
        println!(
            "[ocp_dev_identity_provision_tool] GET_CERTIFICATE verification is mandatory for this flow; overriding verify_get_certificate=false"
        );
    }
    let provisioned = requester.get_certificate(None, options.slot_id)?;
    verify_returned_owner_chain(options.slot_id, &cert_chain, &provisioned)?;

    println!(
        "[ocp_dev_identity_provision_tool] Provisioning verified (GET_CERTIFICATE returned {} bytes)",
        provisioned.len()
    );

    requester.challenge(options.slot_id)?;
    println!(
        "[ocp_dev_identity_provision_tool] Owner slot {} CHALLENGE attestation passed",
        options.slot_id
    );

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

fn export_attested_csr(
    requester: &mut SpdmRequester,
    device_key_id: u32,
    algorithm: u32,
    nonce: &[u8; 32],
) -> Result<ExportAttestedCsrResponse> {
    let mut vdm = SpdmVdmDriverImpl::new(requester, None);
    let mut client = SpdmVdmClient::new(&mut vdm);
    client.export_attested_csr(device_key_id, algorithm, nonce)
}

fn random_nonce() -> Result<[u8; 32]> {
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).context("failed to generate CSR freshness nonce")?;
    Ok(nonce)
}

fn validate_attested_csr(response: &ExportAttestedCsrResponse, nonce: &[u8; 32]) -> Result<()> {
    response
        .validate_csr_payload()
        .map_err(|e| anyhow!("invalid attested CSR payload: {:?}", e))?;
    let csr = response.csr_bytes();
    if !csr.windows(nonce.len()).any(|window| window == nonce) {
        bail!("attested CSR does not contain the requested freshness nonce");
    }
    // ExportAttestedCsr is specified as a COSE_Sign1 attestation envelope. Full
    // RT-alias signature validation requires extracting the RT-alias public key
    // from the active alias chain; this structural check prevents accepting a raw
    // CSR/static blob while keeping the tool dependency-light.
    if csr.first().copied() != Some(0xD2) && csr.first().copied() != Some(0x84) {
        bail!("attested CSR is not encoded as a COSE_Sign1 structure");
    }
    Ok(())
}

fn verify_returned_owner_chain(
    slot_id: u8,
    installed_der: &[u8],
    returned_spdm_chain: &[u8],
) -> Result<()> {
    let returned_der = strip_spdm_cert_chain_header(returned_spdm_chain)?;
    if !returned_der.starts_with(installed_der) {
        bail!(
            "GET_CERTIFICATE slot {} did not start with installed Owner Root + Endorsed LDevID chain",
            slot_id
        );
    }

    let installed_count = split_der_certificates(installed_der)?.len();
    let returned_count = split_der_certificates(returned_der)?.len();
    if returned_count != installed_count + 3 {
        bail!(
            "GET_CERTIFICATE slot {} returned {} cert(s), expected exactly installed owner chain plus FMC alias, RT alias, and DPE leaf ({} certs)",
            slot_id,
            returned_count,
            installed_count + 3
        );
    }
    let returned_certs = split_der_certificates(returned_der)?;
    let installed_certs = split_der_certificates(installed_der)?;
    for tail_cert in &returned_certs[installed_count..] {
        if installed_certs.iter().any(|installed| installed == tail_cert) {
            bail!(
                "GET_CERTIFICATE slot {} alias/DPE tail duplicates an installed owner-chain certificate",
                slot_id
            );
        }
    }
    Ok(())
}

fn strip_spdm_cert_chain_header(chain: &[u8]) -> Result<&[u8]> {
    if chain.len() < SPDM_CERT_CHAIN_HEADER_LEN + SHA384_DIGEST_LEN {
        bail!("SPDM certificate chain too short: {} bytes", chain.len());
    }
    let declared_len = u16::from_le_bytes([chain[0], chain[1]]) as usize;
    if declared_len != 0 && declared_len != chain.len() {
        bail!(
            "SPDM certificate chain length mismatch: header declares {}, actual {}",
            declared_len,
            chain.len()
        );
    }
    Ok(&chain[SPDM_CERT_CHAIN_HEADER_LEN + SHA384_DIGEST_LEN..])
}

fn split_der_certificates(mut der: &[u8]) -> Result<Vec<&[u8]>> {
    let mut certs = Vec::new();
    let mut offset = 0usize;
    while !der.is_empty() {
        if der[0] != 0x30 {
            bail!(
                "expected DER SEQUENCE tag at offset {}, got 0x{:02x}",
                offset,
                der[0]
            );
        }
        let (len, len_len) = der_len(&der[1..])?;
        let total = 1 + len_len + len;
        if total > der.len() {
            bail!(
                "truncated DER certificate: need {} bytes, have {}",
                total,
                der.len()
            );
        }
        certs.push(&der[..total]);
        der = &der[total..];
        offset += total;
    }
    Ok(certs)
}

fn der_len(bytes: &[u8]) -> Result<(usize, usize)> {
    let first = *bytes.first().ok_or_else(|| anyhow!("missing DER length"))?;
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let octets = (first & 0x7f) as usize;
    if octets == 0 || octets > core::mem::size_of::<usize>() || bytes.len() < 1 + octets {
        bail!("unsupported DER length encoding");
    }
    let mut len = 0usize;
    for b in &bytes[1..=octets] {
        len = (len << 8) | (*b as usize);
    }
    Ok((len, 1 + octets))
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

    #[test]
    fn test_split_der_certificates_parses_default_owner_chain() {
        let chain = fs::read(default_cert_chain_path()).unwrap();
        let certs = split_der_certificates(&chain).unwrap();

        assert!(
            certs.len() >= 2,
            "test owner chain should contain Owner Root + Endorsed LDevID"
        );
        assert_eq!(
            certs.iter().map(|cert| cert.len()).sum::<usize>(),
            chain.len()
        );
    }

    #[test]
    fn test_verify_returned_owner_chain_rejects_suffix_only_match() {
        let chain = fs::read(default_cert_chain_path()).unwrap();
        let certs = split_der_certificates(&chain).unwrap();
        let mut returned_der = certs[0].to_vec();
        returned_der.extend_from_slice(&chain);
        returned_der.extend_from_slice(certs[0]);
        returned_der.extend_from_slice(certs[0]);

        let returned = spdm_chain(&returned_der);
        let err =
            verify_returned_owner_chain(DEFAULT_OWNER_SLOT_ID, &chain, &returned).unwrap_err();
        assert!(err.to_string().contains("did not start with installed"));
    }

    #[test]
    fn test_verify_returned_owner_chain_accepts_owner_then_alias_leaf_chain() {
        let chain = fs::read(default_cert_chain_path()).unwrap();
        let mut returned_der = chain.clone();
        returned_der.extend_from_slice(&[0x30, 0x01, 0xA1]);
        returned_der.extend_from_slice(&[0x30, 0x01, 0xA2]);
        returned_der.extend_from_slice(&[0x30, 0x01, 0xA3]);

        let returned = spdm_chain(&returned_der);
        verify_returned_owner_chain(DEFAULT_OWNER_SLOT_ID, &chain, &returned).unwrap();
    }

    #[test]
    fn test_verify_returned_owner_chain_rejects_duplicate_tail_cert() {
        let chain = fs::read(default_cert_chain_path()).unwrap();
        let certs = split_der_certificates(&chain).unwrap();
        let mut returned_der = chain.clone();
        returned_der.extend_from_slice(certs[0]);
        returned_der.extend_from_slice(&[0x30, 0x01, 0xA2]);
        returned_der.extend_from_slice(&[0x30, 0x01, 0xA3]);

        let returned = spdm_chain(&returned_der);
        let err =
            verify_returned_owner_chain(DEFAULT_OWNER_SLOT_ID, &chain, &returned).unwrap_err();
        assert!(err.to_string().contains("duplicates"));
    }

    fn spdm_chain(der: &[u8]) -> Vec<u8> {
        let len = (SPDM_CERT_CHAIN_HEADER_LEN + SHA384_DIGEST_LEN + der.len()) as u16;
        let mut chain = Vec::new();
        chain.extend_from_slice(&len.to_le_bytes());
        chain.extend_from_slice(&0u16.to_le_bytes());
        chain.extend_from_slice(&[0xA5; SHA384_DIGEST_LEN]);
        chain.extend_from_slice(der);
        chain
    }
}

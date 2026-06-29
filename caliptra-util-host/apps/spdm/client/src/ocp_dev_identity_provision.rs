// Licensed under the Apache-2.0 license

//! OCP device identity provisioning over SPDM SET_CERTIFICATE.

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use caliptra_mcu_core_util_host_command_types::certificate::ExportAttestedCsrResponse;
use caliptra_spdm_requester::{SpdmConfig, SpdmRequester, SpdmSocketDeviceIo, SpdmVdmDriverImpl};
use x509_parser::prelude::{FromDer, X509Certificate, X509CertificationRequest};

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

    let attested_csr = if options.require_attested_csr {
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
        Some(csr)
    } else {
        None
    };

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
    if let Some(csr) = &attested_csr {
        verify_csr_matches_owner_leaf(csr.csr_bytes(), &provisioned_certs)?;
        println!(
            "[ocp_dev_identity_provision_tool] Attested CSR public key matches owner/LDevID leaf certificate"
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
    let parsed_csr = parse_csr(csr)?;
    parsed_csr
        .verify_signature()
        .map_err(|e| anyhow!("attested CSR PKCS#10 signature verification failed: {e:?}"))?;
    if !parsed_csr
        .certification_request_info
        .raw
        .windows(nonce.len())
        .any(|window| window == nonce)
    {
        bail!("attested CSR request info does not contain the requested freshness nonce");
    }
    Ok(())
}

fn verify_csr_matches_owner_leaf(csr_der: &[u8], owner_chain: &[&[u8]]) -> Result<()> {
    let csr_spki = parse_csr_spki(csr_der)?;
    let owner_leaf = owner_chain
        .last()
        .ok_or_else(|| anyhow!("owner/LDevID certificate chain is empty"))?;
    let owner_leaf_spki = parse_certificate_spki(owner_leaf).context(
        "failed to parse owner/LDevID leaf certificate public key from provisioned chain",
    )?;

    if csr_spki != owner_leaf_spki {
        bail!("attested CSR public key does not match owner/LDevID leaf certificate public key");
    }
    Ok(())
}

fn parse_csr_spki(csr_der: &[u8]) -> Result<&[u8]> {
    let csr = parse_csr(csr_der)?;
    Ok(csr.certification_request_info.subject_pki.raw)
}

fn parse_csr(csr_der: &[u8]) -> Result<X509CertificationRequest<'_>> {
    let (remaining, csr) = X509CertificationRequest::from_der(csr_der)
        .map_err(|e| anyhow!("failed to parse attested CSR DER: {e:?}"))?;
    if !remaining.is_empty() {
        bail!(
            "attested CSR DER has {} trailing byte(s) after PKCS#10 structure",
            remaining.len()
        );
    }
    Ok(csr)
}

fn parse_certificate_spki(cert_der: &[u8]) -> Result<&[u8]> {
    let (remaining, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow!("failed to parse X.509 certificate DER: {e:?}"))?;
    if !remaining.is_empty() {
        bail!(
            "X.509 certificate DER has {} trailing byte(s) after certificate structure",
            remaining.len()
        );
    }
    Ok(cert.tbs_certificate.subject_pki.raw)
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
    use caliptra_mcu_core_util_host_command_types::certificate::MAX_CSR_DATA_SIZE;
    use caliptra_mcu_core_util_host_command_types::CommonResponse;
    use p384::ecdsa::signature::Signer;
    use p384::ecdsa::{Signature, SigningKey};

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
    fn test_verify_csr_matches_owner_leaf_accepts_matching_spki() {
        let chain = fs::read(default_cert_chain_path()).unwrap();
        let certs = split_der_certificates(&chain).unwrap();
        let owner_leaf_spki = parse_certificate_spki(certs.last().unwrap()).unwrap();
        let csr = synthetic_csr(owner_leaf_spki, None);

        verify_csr_matches_owner_leaf(&csr, &certs).unwrap();
    }

    #[test]
    fn test_verify_csr_matches_owner_leaf_rejects_mismatched_spki() {
        let chain = fs::read(default_cert_chain_path()).unwrap();
        let certs = split_der_certificates(&chain).unwrap();
        let mut mismatched_spki = parse_certificate_spki(certs.last().unwrap()).unwrap().to_vec();
        let last = mismatched_spki.last_mut().unwrap();
        *last ^= 0x01;
        let csr = synthetic_csr(&mismatched_spki, None);

        let err = verify_csr_matches_owner_leaf(&csr, &certs).unwrap_err();
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn test_validate_attested_csr_accepts_der_csr_with_nonce() {
        let nonce = [0x5Au8; 32];
        let csr = signed_p384_csr(&nonce);
        let response = csr_response(&csr);

        validate_attested_csr(&response, &nonce).unwrap();
    }

    #[test]
    fn test_validate_attested_csr_rejects_invalid_csr_signature() {
        let nonce = [0x5Au8; 32];
        let mut csr = signed_p384_csr(&nonce);
        let last = csr.last_mut().unwrap();
        *last ^= 0x01;
        let response = csr_response(&csr);

        let err = validate_attested_csr(&response, &nonce).unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
    }

    #[test]
    fn test_validate_attested_csr_rejects_missing_nonce() {
        let csr = signed_p384_csr(&[0x5Au8; 32]);
        let response = csr_response(&csr);

        let err = validate_attested_csr(&response, &[0xA5u8; 32]).unwrap_err();
        assert!(err.to_string().contains("freshness nonce"));
    }

    #[test]
    fn test_validate_attested_csr_rejects_nonce_outside_request_info() {
        let chain = fs::read(default_cert_chain_path()).unwrap();
        let certs = split_der_certificates(&chain).unwrap();
        let owner_leaf_spki = parse_certificate_spki(certs.last().unwrap()).unwrap();
        let nonce = [0x5Au8; 32];
        let csr = synthetic_csr_with_signature_payload(owner_leaf_spki, None, &nonce);
        let response = csr_response(&csr);

        let err = validate_attested_csr(&response, &nonce).unwrap_err();
        assert!(!err.to_string().is_empty());
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

    fn csr_response(csr: &[u8]) -> ExportAttestedCsrResponse {
        assert!(csr.len() <= MAX_CSR_DATA_SIZE);
        let mut csr_data = [0u8; MAX_CSR_DATA_SIZE];
        csr_data[..csr.len()].copy_from_slice(csr);
        ExportAttestedCsrResponse {
            common: CommonResponse { fips_status: 0 },
            data_len: csr.len() as u32,
            csr_data,
        }
    }

    fn synthetic_csr(subject_pki: &[u8], subject_common_name: Option<&[u8]>) -> Vec<u8> {
        synthetic_csr_with_signature_payload(subject_pki, subject_common_name, &[0xA5])
    }

    fn synthetic_csr_with_signature_payload(
        subject_pki: &[u8],
        subject_common_name: Option<&[u8]>,
        signature_payload: &[u8],
    ) -> Vec<u8> {
        // PKCS#10 CertificationRequest ::= SEQUENCE {
        //   certificationRequestInfo SEQUENCE {
        //     version INTEGER 0,
        //     subject Name,
        //     subjectPKInfo <from owner leaf cert>,
        //     attributes [0] IMPLICIT SET OF Attribute (empty)
        //   },
        //   signatureAlgorithm ecdsa-with-SHA384,
        //   signature BIT STRING
        // }
        let cri = der_sequence(&[
            vec![0x02, 0x01, 0x00],
            synthetic_subject_name(subject_common_name),
            subject_pki.to_vec(),
            vec![0xA0, 0x00],
        ]);
        let signature_algorithm = der_sequence(&[vec![
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03,
        ]]);
        let mut signature = vec![0x00]; // zero unused bits in BIT STRING
        signature.extend_from_slice(signature_payload);
        der_sequence(&[cri, signature_algorithm, der_tlv(0x03, &signature)])
    }

    fn signed_p384_csr(nonce: &[u8]) -> Vec<u8> {
        let key_bytes = [0x07u8; 48];
        let signing_key = SigningKey::from_bytes((&key_bytes).into()).unwrap();
        let cri = der_sequence(&[
            vec![0x02, 0x01, 0x00],
            synthetic_subject_name(Some(nonce)),
            p384_spki(&signing_key),
            vec![0xA0, 0x00],
        ]);
        let signature_algorithm = der_sequence(&[vec![
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03,
        ]]);
        let signature: Signature = signing_key.sign(&cri);
        let signature_der = signature.to_der();
        let mut signature_bits = vec![0x00]; // zero unused bits in BIT STRING
        signature_bits.extend_from_slice(signature_der.as_bytes());

        der_sequence(&[
            cri,
            signature_algorithm,
            der_tlv(0x03, &signature_bits),
        ])
    }

    fn p384_spki(signing_key: &SigningKey) -> Vec<u8> {
        let verifying_key = signing_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(false);
        let algorithm = der_sequence(&[
            vec![0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01],
            vec![0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22],
        ]);
        let mut public_key_bits = vec![0x00]; // zero unused bits in BIT STRING
        public_key_bits.extend_from_slice(encoded_point.as_bytes());

        der_sequence(&[algorithm, der_tlv(0x03, &public_key_bits)])
    }

    fn synthetic_subject_name(common_name: Option<&[u8]>) -> Vec<u8> {
        let Some(common_name) = common_name else {
            return der_sequence(&[]);
        };
        let cn_attr = der_sequence(&[
            vec![0x06, 0x03, 0x55, 0x04, 0x03], // id-at-commonName
            der_tlv(0x0C, common_name),          // UTF8String; tests pass ASCII nonce bytes
        ]);
        der_sequence(&[der_tlv(0x31, &cn_attr)])
    }

    fn der_sequence(elements: &[Vec<u8>]) -> Vec<u8> {
        let content: Vec<u8> = elements.iter().flatten().copied().collect();
        der_tlv(0x30, &content)
    }

    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut der = vec![tag];
        der.extend_from_slice(&der_len_bytes(content.len()));
        der.extend_from_slice(content);
        der
    }

    fn der_len_bytes(len: usize) -> Vec<u8> {
        if len < 0x80 {
            return vec![len as u8];
        }
        let bytes = len.to_be_bytes();
        let first_nonzero = bytes.iter().position(|b| *b != 0).unwrap();
        let encoded = &bytes[first_nonzero..];
        let mut out = vec![0x80 | encoded.len() as u8];
        out.extend_from_slice(encoded);
        out
    }
}

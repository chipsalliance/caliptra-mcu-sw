// Licensed under the Apache-2.0 license

//! OCP device identity provisioning over SPDM SET_CERTIFICATE.

use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use caliptra_mcu_core_util_host_command_types::certificate::ExportAttestedCsrResponse;
use caliptra_spdm_requester::{
    split_der_certificates, verify_x509_certificate_chain, PeerRootCert, SpdmConfig,
    SpdmRequester, SpdmSocketDeviceIo, SpdmVdmDriverImpl,
};
use coset::{cbor::value::Value, iana::Algorithm, AsCborValue, CoseSign1};
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha384};
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
use x509_cert::name::Name;
use x509_cert::request::CertReq;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use x509_cert::Certificate;

use crate::SpdmVdmClient;

pub const DEFAULT_OWNER_SLOT_ID: u8 = 2;
pub const DEFAULT_LDEVID_KEY_PAIR_ID: u8 = 1;
const VENDOR_SLOT_ID: u8 = 0;
const CSR_ALGORITHM_ECC384: u32 = 1;
const CERT_MODEL_ALIAS_CERT: u8 = 2;
const SPDM_CERT_CHAIN_HEADER_LEN: usize = 4;
const SHA384_DIGEST_LEN: usize = 48;
const EAT_CLAIM_NONCE: i128 = 10;
const OCP_CLAIM_CSR: i128 = -70001;
const OWNER_SLOT_DYNAMIC_TAIL_CERTS: usize = 3; // FMC alias + RT alias + DPE leaf
const TEST_OWNER_ROOT_KEY_BYTES: [u8; 48] = [0x0B; 48];

/// Request parameters for provisioning an OCP device identity certificate slot.
pub struct ProvisionOptions {
    /// Server address (host:port) of the SPDM bridge.
    pub server: String,
    /// SPDM certificate slot to provision.
    pub slot_id: u8,
    /// SPDM key pair ID to associate with the slot.
    pub key_pair_id: u8,
    /// DER X.509 root certificate that authenticates the initial Vendor slot.
    pub vendor_trust_anchor: PathBuf,
}

impl Default for ProvisionOptions {
    fn default() -> Self {
        Self {
            server: "127.0.0.1:2323".to_string(),
            slot_id: DEFAULT_OWNER_SLOT_ID,
            key_pair_id: DEFAULT_LDEVID_KEY_PAIR_ID,
            vendor_trust_anchor: default_vendor_trust_anchor_path(),
        }
    }
}

/// Provision an OCP device identity certificate slot.
///
/// This authenticates Vendor slot 0, validates an attested LDevID CSR, issues
/// and installs an Owner/LDevID chain, verifies the returned chain, performs
/// Owner-slot attestation, and sends STOP to the test bridge.
pub fn provision_device_identity(options: &ProvisionOptions) -> Result<()> {
    println!(
        "[ocp_dev_identity_provision_tool] Connecting to bridge at {}",
        options.server
    );
    let mut device_io = SpdmSocketDeviceIo::connect_mctp(&options.server)?;
    device_io.handshake()?;
    let mut stop_io = device_io.try_clone()?;

    let owner_root = test_owner_root_cert_der()?;
    let vendor_root = fs::read(&options.vendor_trust_anchor).with_context(|| {
        format!(
            "failed to read vendor trust anchor {}",
            options.vendor_trust_anchor.display()
        )
    })?;

    let spdm_config = SpdmConfig {
        slot_id: VENDOR_SLOT_ID,
        peer_root_certs: vec![
            PeerRootCert {
                slot_id: VENDOR_SLOT_ID,
                cert_der: vendor_root,
            },
            PeerRootCert {
                slot_id: options.slot_id,
                cert_der: owner_root,
            },
        ],
        ..SpdmConfig::default()
    };
    let mut requester = SpdmRequester::new(spdm_config, Box::new(device_io))?;

    println!(
        "[ocp_dev_identity_provision_tool] Establishing SPDM connection using Vendor slot {}",
        VENDOR_SLOT_ID
    );
    requester.connect_authenticated()?;
    println!(
        "[ocp_dev_identity_provision_tool] Initial CHALLENGE attestation passed for Vendor slot {}",
        VENDOR_SLOT_ID
    );

    let vendor_spdm_chain = requester
        .get_certificate(None, VENDOR_SLOT_ID)
        .context("failed to read authenticated Vendor slot certificate chain for CSR attestation")?;
    let vendor_chain = parse_spdm_cert_chain(&vendor_spdm_chain)
        .context("failed to parse Vendor slot SPDM certificate chain")?;
    let vendor_certs = split_der_certificates(vendor_chain.der)
        .context("failed to split Vendor slot DER certificate chain")?;
    if vendor_certs.is_empty() {
        bail!("Vendor slot {VENDOR_SLOT_ID} returned an empty certificate chain");
    }
    verify_spdm_root_hash(vendor_chain.root_hash, vendor_certs[0])
        .context("Vendor slot SPDM certificate chain root hash mismatch")?;

    let nonce = random_nonce()?;
    let csr = export_attested_csr(
        &mut requester,
        options.key_pair_id as u32,
        CSR_ALGORITHM_ECC384,
        &nonce,
    )?;
    let csr_der = validate_attested_csr(&csr, &nonce, &vendor_certs)?;
    println!(
        "[ocp_dev_identity_provision_tool] ExportAttestedCsr key_pair_id={} returned {} bytes",
        options.key_pair_id, csr.data_len
    );

    let cert_chain = issue_test_owner_ldev_id_chain_from_csr(&csr_der)
        .context("failed to issue test Owner/LDevID certificate chain from attested CSR")?;
    println!(
        "[ocp_dev_identity_provision_tool] Issued test Owner/LDevID certificate chain from attested CSR ({} bytes)",
        cert_chain.len()
    );

    let provisioned_certs = validate_owner_chain(&cert_chain, "attested CSR")?;
    verify_csr_matches_owner_leaf(&csr_der, &provisioned_certs)?;
    println!(
        "[ocp_dev_identity_provision_tool] Attested CSR public key matches owner/LDevID leaf certificate"
    );

    println!(
        "[ocp_dev_identity_provision_tool] SET_CERTIFICATE slot_id={} key_pair_id={} cert_chain={} ({} bytes)",
        options.slot_id,
        options.key_pair_id,
        "attested CSR",
        cert_chain.len()
    );
    requester.set_certificate(
        None,
        options.slot_id,
        options.key_pair_id,
        CERT_MODEL_ALIAS_CERT,
        &cert_chain,
    )?;

    let provisioned = requester.get_certificate(None, options.slot_id)?;
    verify_returned_owner_chain(
        options.slot_id,
        &cert_chain,
        &vendor_certs,
        &provisioned,
    )?;

    println!(
        "[ocp_dev_identity_provision_tool] Provisioning verified (GET_CERTIFICATE returned {} bytes)",
        provisioned.len()
    );

    println!(
        "[ocp_dev_identity_provision_tool] Owner slot {} certificate chain verified via GET_CERTIFICATE",
        options.slot_id
    );
    requester
        .challenge(options.slot_id)
        .with_context(|| format!("Owner-slot CHALLENGE failed for slot {}", options.slot_id))?;
    println!(
        "[ocp_dev_identity_provision_tool] Owner-slot CHALLENGE passed for slot {}",
        options.slot_id
    );

    println!("[ocp_dev_identity_provision_tool] Sending STOP to bridge");
    stop_io.send_stop()?;
    Ok(())
}

pub fn default_vendor_trust_anchor_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .map(|spdm_dir| spdm_dir.join("certs/test_vendor_root.der"))
        .unwrap_or_else(|| PathBuf::from("certs/test_vendor_root.der"))
}

fn validate_owner_chain<'a>(der: &'a [u8], source: &str) -> Result<Vec<&'a [u8]>> {
    if der.is_empty() {
        bail!("owner/LDevID certificate chain {source} is empty");
    }
    let certs = split_der_certificates(der)
        .with_context(|| format!("failed to parse DER certificate chain {source}"))?;
    if certs.len() < 2 {
        bail!(
            "owner/LDevID certificate chain {source} must contain at least Owner Root + Endorsed LDevID cert, found {} certificate(s)",
            certs.len()
        );
    }
    verify_x509_certificate_chain(&certs)
        .context("provisioned owner/LDevID X.509 chain validation failed")?;
    Ok(certs)
}

fn test_owner_root_signing_key() -> Result<SigningKey> {
    SigningKey::from_bytes((&TEST_OWNER_ROOT_KEY_BYTES).into())
        .map_err(|e| anyhow!("failed to construct test Owner root key: {e:?}"))
}

fn test_owner_root_subject_name() -> Result<Name> {
    Name::from_str("CN=Caliptra Test Owner Root CA")
        .map_err(|e| anyhow!("failed to construct test Owner root subject: {e}"))
}

fn test_owner_root_cert_der() -> Result<Vec<u8>> {
    let key = test_owner_root_signing_key()?;
    let name = test_owner_root_subject_name()?;
    build_test_ca_certificate(0x1001, name.clone(), name, None, 6, &key)
}

fn issue_test_owner_ldev_id_chain_from_csr(csr_der: &[u8]) -> Result<Vec<u8>> {
    let csr = parse_csr(csr_der)?;
    let root_key = test_owner_root_signing_key()?;
    let root = test_owner_root_cert_der()?;
    let issuer = test_owner_root_subject_name()?;
    if csr.info.subject.0.is_empty() {
        bail!("attested CSR subject is empty; cannot issue Owner/LDevID certificate");
    }
    let subject = csr.info.subject;
    let subject_pki = csr.info.public_key;
    let serial_seed = Sha384::digest(csr_der);
    let serial = u64::from_be_bytes(
        serial_seed[..8]
            .try_into()
            .map_err(|_| anyhow!("failed to derive Owner/LDevID serial"))?,
    ) & 0x7fff_ffff_ffff_ffff;
    let leaf = build_test_ca_certificate(
        serial.max(1),
        issuer,
        subject,
        Some(subject_pki),
        3,
        &root_key,
    )?;

    let mut chain = root;
    chain.extend_from_slice(&leaf);
    Ok(chain)
}

fn build_test_ca_certificate(
    serial: u64,
    issuer: Name,
    subject: Name,
    subject_pki: Option<SubjectPublicKeyInfoOwned>,
    path_len: u8,
    signing_key: &SigningKey,
) -> Result<Vec<u8>> {
    let subject_pki = subject_pki.unwrap_or(
        SubjectPublicKeyInfoOwned::from_key(signing_key.verifying_key().to_owned())
            .context("failed to encode test Owner root public key")?,
    );
    let mut builder = CertificateBuilder::new(
        Profile::Manual {
            issuer: Some(issuer),
        },
        SerialNumber::from(serial),
        Validity::from_now(Duration::from_secs(10 * 365 * 24 * 60 * 60))
            .context("failed to construct test certificate validity")?,
        subject,
        subject_pki,
        signing_key,
    )
    .context("failed to construct test certificate")?;
    builder.add_extension(&BasicConstraints {
        ca: true,
        path_len_constraint: Some(path_len),
    })?;
    builder.add_extension(&KeyUsage(
        KeyUsages::DigitalSignature | KeyUsages::KeyCertSign | KeyUsages::CRLSign,
    ))?;
    builder
        .build::<p384::ecdsa::DerSignature>()
        .context("failed to sign test certificate")?
        .to_der()
        .context("failed to encode test certificate")
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

fn validate_attested_csr(
    response: &ExportAttestedCsrResponse,
    nonce: &[u8; 32],
    attestation_certs: &[&[u8]],
) -> Result<Vec<u8>> {
    response
        .validate_csr_payload()
        .map_err(|e| anyhow!("invalid attested CSR payload: {:?}", e))?;
    let payload = response.csr_bytes();

    if parse_csr(payload).is_ok() {
        bail!(
            "attested CSR payload must be a COSE_Sign1/CWT envelope; raw PKCS#10 CSR is not accepted for provisioning"
        );
    }

    let cose = parse_cose_sign1(payload)
        .context("attested CSR payload is not a COSE_Sign1/CWT envelope")?;
    let rt_alias_cert = rt_alias_signing_cert(attestation_certs)?;
    let claims = verify_attested_csr_cose(&cose, rt_alias_cert)?;
    if claims.nonce.as_slice() != nonce {
        bail!("attested CSR COSE payload nonce does not match requested freshness nonce");
    }
    let csr = claims.csr;
    // Caliptra's attested CSR envelope authenticates the PKCS#10 bytes with the
    // SPDM attestation key. Current firmware emits a placeholder PKCS#10
    // self-signature, so do not require CSR self-signature validity on this
    // attested path. The CSR is still parsed strictly and later bound to the
    // provisioned owner/LDevID leaf public key.
    parse_csr(&csr)?;
    Ok(csr)
}

struct AttestedCsrClaims {
    nonce: Vec<u8>,
    csr: Vec<u8>,
}

fn parse_cose_sign1(data: &[u8]) -> Result<CoseSign1> {
    let mut value: Value = ciborium::from_reader(data)
        .context("attested CSR payload is not valid CBOR")?;
    if matches!(value, Value::Tag(55799, _)) {
        value = unwrap_cbor_tag(value, 55799)?;
    }
    value = unwrap_cbor_tag(value, 61)?;
    value = unwrap_cbor_tag(value, 18)?;
    CoseSign1::from_cbor_value(value)
        .map_err(|e| anyhow!("attested CSR payload is not a COSE_Sign1 envelope: {e}"))
}

fn unwrap_cbor_tag(value: Value, expected: u64) -> Result<Value> {
    match value {
        Value::Tag(tag, value) if tag == expected => Ok(*value),
        Value::Tag(tag, _) => bail!("expected CBOR tag {expected}, found {tag}"),
        _ => bail!("attested CSR COSE envelope missing CBOR tag {expected}"),
    }
}

fn verify_attested_csr_cose(
    cose: &CoseSign1,
    rt_alias_cert: &[u8],
) -> Result<AttestedCsrClaims> {
    if !matches!(
        cose.protected.header.alg,
        Some(coset::RegisteredLabelWithPrivate::Assigned(Algorithm::ES384 | Algorithm::ESP384))
    ) {
        bail!("unsupported attested CSR COSE algorithm, expected ES384/ESP384");
    }
    let payload = cose
        .payload
        .as_deref()
        .ok_or_else(|| anyhow!("attested CSR COSE envelope has no payload"))?;
    let kid = (!cose.protected.header.key_id.is_empty())
        .then_some(cose.protected.header.key_id.as_slice());
    verify_cose_signature_with_authenticated_chain(
        &cose.signature,
        &cose.tbs_data(&[]),
        kid,
        &[rt_alias_cert],
    )?;
    parse_attested_csr_claims(payload)
}

fn rt_alias_signing_cert<'a>(attestation_certs: &'a [&'a [u8]]) -> Result<&'a [u8]> {
    if attestation_certs.len() < 2 {
        bail!(
            "attested CSR RT-alias signature validation requires Vendor chain with RT alias and DPE leaf"
        );
    }
    Ok(attestation_certs[attestation_certs.len() - 2])
}

fn parse_attested_csr_claims(payload: &[u8]) -> Result<AttestedCsrClaims> {
    let value: Value = ciborium::from_reader(payload)
        .context("attested CSR COSE payload is not valid CBOR")?;
    let Value::Map(entries) = value else {
        bail!("attested CSR COSE payload is not a map");
    };
    let mut nonce = None;
    let mut csr = None;
    for (key, value) in entries {
        let Value::Integer(key) = key else { continue };
        let key: i128 = key.into();
        match (key, value) {
            (EAT_CLAIM_NONCE, Value::Bytes(bytes)) => nonce = Some(bytes),
            (OCP_CLAIM_CSR, Value::Bytes(bytes)) => csr = Some(bytes),
            _ => {}
        }
    }
    let nonce = nonce.ok_or_else(|| anyhow!("attested CSR COSE payload missing nonce claim"))?;
    let csr = csr.ok_or_else(|| anyhow!("attested CSR COSE payload missing CSR claim"))?;
    if nonce.len() != 32 {
        bail!("attested CSR COSE nonce is {} bytes, expected 32", nonce.len());
    }
    Ok(AttestedCsrClaims { nonce, csr })
}

fn verify_cose_signature_with_authenticated_chain(
    signature: &[u8],
    sig_structure: &[u8],
    kid: Option<&[u8]>,
    attestation_certs: &[&[u8]],
) -> Result<()> {
    if attestation_certs.is_empty() {
        bail!("attested CSR COSE verification requires the authenticated Vendor certificate chain");
    }
    let signature = Signature::from_slice(signature)
        .map_err(|e| anyhow!("invalid attested CSR COSE ECDSA signature length/encoding: {e:?}"))?;

    let mut saw_kid_match = kid.is_none();
    let mut saw_signature_match = false;
    for cert_der in attestation_certs {
        if let Some(kid) = kid {
            if !certificate_matches_cose_kid(cert_der, kid)? {
                continue;
            }
            saw_kid_match = true;
        }
        let public_key = parse_certificate_public_key_sec1(cert_der)?;
        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key)
            .map_err(|e| anyhow!("failed to load P-384 public key from attestation cert: {e:?}"))?;
        if verifying_key.verify(sig_structure, &signature).is_ok() {
            saw_signature_match = true;
            break;
        }
    }

    if !saw_kid_match {
        bail!("attested CSR COSE kid did not match any authenticated Vendor-chain certificate");
    }
    if !saw_signature_match {
        bail!("attested CSR COSE signature did not verify with authenticated Vendor-chain certificates");
    }
    Ok(())
}

fn certificate_matches_cose_kid(cert_der: &[u8], kid: &[u8]) -> Result<bool> {
    if cert_der.windows(kid.len()).any(|window| window == kid) {
        return Ok(true);
    }
    let public_key = parse_certificate_public_key_sec1(cert_der)?;
    if kid.len() == SHA384_DIGEST_LEN && public_key.first() == Some(&0x04) {
        let digest = Sha384::digest(&public_key[1..]);
        return Ok(kid == &digest[..]);
    }
    Ok(false)
}

fn parse_certificate_public_key_sec1(cert_der: &[u8]) -> Result<Vec<u8>> {
    let cert = Certificate::from_der(cert_der).context("failed to parse X.509 certificate DER")?;
    let public_key = cert.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
    if public_key.first() != Some(&0x04) {
        bail!("attestation certificate public key is not an uncompressed P-384 point");
    }
    Ok(public_key.to_vec())
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

fn parse_csr_spki(csr_der: &[u8]) -> Result<Vec<u8>> {
    let csr = parse_csr(csr_der)?;
    csr.info
        .public_key
        .to_der()
        .context("failed to encode attested CSR public key")
}

fn parse_csr(csr_der: &[u8]) -> Result<CertReq> {
    CertReq::from_der(csr_der).context("failed to parse attested CSR DER")
}

fn parse_certificate_spki(cert_der: &[u8]) -> Result<Vec<u8>> {
    let cert = Certificate::from_der(cert_der).context("failed to parse X.509 certificate DER")?;
    cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .context("failed to encode X.509 certificate public key")
}

fn verify_returned_owner_chain(
    slot_id: u8,
    installed_der: &[u8],
    vendor_certs: &[&[u8]],
    returned_spdm_chain: &[u8],
) -> Result<()> {
    let returned = parse_spdm_cert_chain(returned_spdm_chain)?;
    let installed_certs = split_der_certificates(installed_der)?;
    let returned_certs = split_der_certificates(returned.der)?;
    if returned_certs.is_empty() {
        bail!("GET_CERTIFICATE slot {} returned an empty DER chain", slot_id);
    }
    verify_spdm_root_hash(&returned.root_hash, returned_certs[0])?;

    let expected_count = installed_certs.len() + OWNER_SLOT_DYNAMIC_TAIL_CERTS;
    if returned_certs.len() != expected_count {
        bail!(
            "GET_CERTIFICATE slot {} returned {} cert(s), expected installed owner chain plus FMC alias + RT alias + DPE leaf ({} certs total)",
            slot_id,
            returned_certs.len(),
            expected_count
        );
    }
    if returned_certs[..installed_certs.len()] != installed_certs {
        bail!(
            "GET_CERTIFICATE slot {} did not start with the exact installed Owner Root + Endorsed LDevID chain",
            slot_id
        );
    }

    let tail = &returned_certs[installed_certs.len()..];
    if vendor_certs.len() < OWNER_SLOT_DYNAMIC_TAIL_CERTS {
        bail!("Vendor slot chain is missing FMC alias, RT alias, or DPE leaf");
    }
    let vendor_tail = &vendor_certs[vendor_certs.len() - OWNER_SLOT_DYNAMIC_TAIL_CERTS..];
    if tail != vendor_tail {
        bail!(
            "GET_CERTIFICATE slot {} did not return the authenticated FMC alias + RT alias + DPE leaf after the installed owner chain",
            slot_id
        );
    }
    if tail.iter().any(|cert| installed_certs.contains(cert))
        || tail[..2]
            .iter()
            .any(|cert| vendor_certs[..vendor_certs.len() - OWNER_SLOT_DYNAMIC_TAIL_CERTS].contains(cert))
    {
        bail!(
            "GET_CERTIFICATE slot {} duplicated Owner, Caliptra IDevID, or Caliptra LDevID certificates in the dynamic tail",
            slot_id
        );
    }

    verify_x509_certificate_chain(&returned_certs)
        .context("GET_CERTIFICATE returned chain failed X.509 validation")?;
    Ok(())
}

struct SpdmCertChain<'a> {
    root_hash: &'a [u8],
    der: &'a [u8],
}

fn parse_spdm_cert_chain(chain: &[u8]) -> Result<SpdmCertChain<'_>> {
    if chain.len() < SPDM_CERT_CHAIN_HEADER_LEN + SHA384_DIGEST_LEN {
        bail!("SPDM certificate chain too short: {} bytes", chain.len());
    }
    let declared_len = u16::from_le_bytes([chain[0], chain[1]]) as usize;
    if declared_len != chain.len() {
        bail!(
            "SPDM certificate chain length mismatch: header declares {}, actual {}",
            declared_len,
            chain.len()
        );
    }
    let reserved = u16::from_le_bytes([chain[2], chain[3]]);
    if reserved != 0 {
        bail!("SPDM certificate chain reserved field is non-zero: {reserved:#x}");
    }
    Ok(SpdmCertChain {
        root_hash: &chain[SPDM_CERT_CHAIN_HEADER_LEN..SPDM_CERT_CHAIN_HEADER_LEN + SHA384_DIGEST_LEN],
        der: &chain[SPDM_CERT_CHAIN_HEADER_LEN + SHA384_DIGEST_LEN..],
    })
}

fn verify_spdm_root_hash(root_hash: &[u8], root_cert_der: &[u8]) -> Result<()> {
    let digest = Sha384::digest(root_cert_der);
    if root_hash != &digest[..] {
        bail!("SPDM certificate chain root hash does not match the root certificate");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_mcu_core_util_host_command_types::certificate::MAX_CSR_DATA_SIZE;
    use caliptra_mcu_core_util_host_command_types::CommonResponse;
    use p384::ecdsa::signature::Signer;
    use p384::ecdsa::{Signature, SigningKey};
    use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
    use x509_cert::builder::RequestBuilder;

    fn test_owner_chain() -> Vec<u8> {
        let key = SigningKey::from_bytes((&[0x07u8; 48]).into()).unwrap();
        issue_test_owner_ldev_id_chain_from_csr(&test_csr(&key, "CN=Caliptra LDevID"))
            .unwrap()
    }


    #[test]
    fn test_verify_csr_matches_owner_leaf_rejects_mismatched_spki() {
        let chain = test_owner_chain();
        let certs = split_der_certificates(&chain).unwrap();
        let key = SigningKey::from_bytes((&[0x08u8; 48]).into()).unwrap();
        let csr = test_csr(&key, "CN=Other LDevID");

        let err = verify_csr_matches_owner_leaf(&csr, &certs).unwrap_err();
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn test_issue_test_owner_ldev_id_chain_from_csr_uses_csr_spki() {
        let signing_key = SigningKey::from_bytes((&[0x07u8; 48]).into()).unwrap();
        let csr = test_csr(&signing_key, "CN=Caliptra LDevID");

        let chain = issue_test_owner_ldev_id_chain_from_csr(&csr).unwrap();
        let certs = split_der_certificates(&chain).unwrap();

        assert_eq!(certs.len(), 2);
        verify_x509_certificate_chain(&certs).unwrap();
        verify_csr_matches_owner_leaf(&csr, &certs).unwrap();
    }

    #[test]
    fn test_issue_test_owner_ldev_id_chain_from_csr_rejects_empty_subject() {
        let key = SigningKey::from_bytes((&[0x07u8; 48]).into()).unwrap();
        let csr = RequestBuilder::new(Name::default(), &key)
            .unwrap()
            .build::<p384::ecdsa::DerSignature>()
            .unwrap()
            .to_der()
            .unwrap();

        let err = issue_test_owner_ldev_id_chain_from_csr(&csr).unwrap_err();
        assert!(err.to_string().contains("subject is empty"));
    }

    #[test]
    fn test_validate_attested_csr_rejects_raw_der_csr_with_nonce() {
        let nonce = [0x5Au8; 32];
        let key = SigningKey::from_bytes((&[0x07u8; 48]).into()).unwrap();
        let csr = test_csr(&key, "CN=Caliptra LDevID");
        let response = csr_response(&csr);

        let err = validate_attested_csr(&response, &nonce, &[]).unwrap_err();
        assert!(err.to_string().contains("raw PKCS#10 CSR is not accepted"));
    }

    #[test]
    fn test_validate_attested_csr_rejects_unsigned_envelope_with_der_csr() {
        let nonce = [0x5Au8; 32];
        let key = SigningKey::from_bytes((&[0x07u8; 48]).into()).unwrap();
        let csr = test_csr(&key, "CN=Caliptra LDevID");
        let mut envelope = vec![0xd8, 0x3d, 0xd2, 0x84, 0x58, 0x04, 0xde, 0xad, 0xbe, 0xef];
        envelope.extend_from_slice(&csr);
        envelope.extend_from_slice(&[0x58, 0x04, 0xca, 0xfe, 0xba, 0xbe]);
        let response = csr_response(&envelope);

        let err = validate_attested_csr(&response, &nonce, &[]).unwrap_err();
        assert!(err.to_string().contains("COSE_Sign1"));
    }

    #[test]
    fn test_validate_attested_csr_accepts_cose_attested_placeholder_csr_signature() {
        let nonce = [0x5Au8; 32];
        let signer_key = SigningKey::from_bytes((&[0x09u8; 48]).into()).unwrap();
        let signer_cert = synthetic_cert_for_key(&signer_key);
        let csr_key = SigningKey::from_bytes((&[0x07u8; 48]).into()).unwrap();
        let mut csr = test_csr(&csr_key, "CN=Caliptra LDevID");
        *csr.last_mut().unwrap() ^= 0x01;
        let envelope = signed_cose_attested_csr(&signer_key, &nonce, &csr);
        let response = csr_response(&envelope);

        let vendor_root = signer_cert.clone();
        let dpe_leaf = signer_cert.clone();
        let extracted =
            validate_attested_csr(&response, &nonce, &[&vendor_root, &signer_cert, &dpe_leaf])
                .unwrap();
        assert_eq!(extracted, csr);
    }

    #[test]
    fn test_validate_attested_csr_rejects_bad_cose_signature() {
        let nonce = [0x5Au8; 32];
        let signer_key = SigningKey::from_bytes((&[0x09u8; 48]).into()).unwrap();
        let signer_cert = synthetic_cert_for_key(&signer_key);
        let csr_key = SigningKey::from_bytes((&[0x07u8; 48]).into()).unwrap();
        let mut csr = test_csr(&csr_key, "CN=Caliptra LDevID");
        *csr.last_mut().unwrap() ^= 0x01;
        let mut envelope = signed_cose_attested_csr(&signer_key, &nonce, &csr);
        *envelope.last_mut().unwrap() ^= 0x01;
        let response = csr_response(&envelope);

        let vendor_root = signer_cert.clone();
        let dpe_leaf = signer_cert.clone();
        let err = validate_attested_csr(&response, &nonce, &[&vendor_root, &signer_cert, &dpe_leaf])
            .unwrap_err();
        assert!(err.to_string().contains("COSE signature"));
    }


    #[test]
    fn test_verify_returned_owner_chain_rejects_suffix_only_match() {
        let chain = test_owner_chain();
        let certs = split_der_certificates(&chain).unwrap();
        let mut returned_der = certs[0].to_vec();
        returned_der.extend_from_slice(&chain);
        returned_der.extend_from_slice(certs[0]);
        returned_der.extend_from_slice(certs[0]);

        let returned = spdm_chain(&returned_der);
        let err = verify_returned_owner_chain(
            DEFAULT_OWNER_SLOT_ID,
            &chain,
            &certs,
            &returned,
        )
        .unwrap_err();
        assert!(err.to_string().contains("exact installed"));
    }

    #[test]
    fn test_verify_returned_owner_chain_rejects_duplicated_device_identity_certs() {
        let chain = test_owner_chain();
        let certs = split_der_certificates(&chain).unwrap();
        let vendor_certs = [certs[1], certs[0], certs[0]];
        let mut returned_der = chain.clone();
        returned_der.extend_from_slice(vendor_certs[0]);
        returned_der.extend_from_slice(vendor_certs[1]);
        returned_der.extend_from_slice(vendor_certs[2]);

        let returned = spdm_chain(&returned_der);
        let err = verify_returned_owner_chain(
            DEFAULT_OWNER_SLOT_ID,
            &chain,
            &vendor_certs,
            &returned,
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicated"));
    }


    #[test]
    fn test_parse_spdm_cert_chain_rejects_bad_root_hash() {
        let chain = test_owner_chain();
        let certs = split_der_certificates(&chain).unwrap();
        let mut returned_der = chain.clone();
        returned_der.extend_from_slice(certs[0]);
        returned_der.extend_from_slice(certs[0]);
        returned_der.extend_from_slice(certs[0]);
        let mut returned = spdm_chain(&returned_der);
        returned[SPDM_CERT_CHAIN_HEADER_LEN] ^= 0x01;

        let err = verify_returned_owner_chain(
            DEFAULT_OWNER_SLOT_ID,
            &chain,
            &certs,
            &returned,
        )
        .unwrap_err();
        assert!(err.to_string().contains("root hash"));
    }

    fn spdm_chain(der: &[u8]) -> Vec<u8> {
        let certs = split_der_certificates(der).unwrap();
        let root_hash = Sha384::digest(certs[0]);
        let len = (SPDM_CERT_CHAIN_HEADER_LEN + SHA384_DIGEST_LEN + der.len()) as u16;
        let mut chain = Vec::new();
        chain.extend_from_slice(&len.to_le_bytes());
        chain.extend_from_slice(&0u16.to_le_bytes());
        chain.extend_from_slice(&root_hash[..]);
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

    fn test_csr(signing_key: &SigningKey, subject: &str) -> Vec<u8> {
        RequestBuilder::new(Name::from_str(subject).unwrap(), signing_key)
            .unwrap()
            .build::<p384::ecdsa::DerSignature>()
            .unwrap()
            .to_der()
            .unwrap()
    }


    fn signed_cose_attested_csr(signing_key: &SigningKey, nonce: &[u8; 32], csr: &[u8]) -> Vec<u8> {
        let public_key = signing_key.verifying_key().to_encoded_point(false);
        let kid = Sha384::digest(&public_key.as_bytes()[1..]);
        let payload = Value::Map(vec![
            (
                Value::Integer(EAT_CLAIM_NONCE.try_into().unwrap()),
                Value::Bytes(nonce.to_vec()),
            ),
            (
                Value::Integer(OCP_CLAIM_CSR.try_into().unwrap()),
                Value::Bytes(csr.to_vec()),
            ),
        ])
        .to_vec()
        .unwrap();
        let sign1 = CoseSign1Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(Algorithm::ESP384)
                    .key_id(kid.to_vec())
                    .build(),
            )
            .payload(payload)
            .create_signature(&[], |data| {
                let signature: Signature = signing_key.sign(data);
                signature.to_bytes().to_vec()
            })
            .build();
        let sign1 = Value::from_slice(&sign1.to_tagged_vec().unwrap()).unwrap();
        Value::Tag(61, Box::new(sign1)).to_vec().unwrap()
    }

    fn synthetic_cert_for_key(signing_key: &SigningKey) -> Vec<u8> {
        let name = Name::from_str("CN=COSE signer").unwrap();
        build_test_ca_certificate(1, name.clone(), name, None, 0, signing_key).unwrap()
    }


}

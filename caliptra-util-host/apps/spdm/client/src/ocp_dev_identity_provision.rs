// Licensed under the Apache-2.0 license

//! OCP Device Identity Provisioning (DIP) host flows over SPDM.
//!
//! - [`discover`] and [`export_csr`] retrieve and verify DIP evidence (the
//!   keypair inventory and attested CSRs) so a CA can issue certificates
//!   offline. No CA secrets are involved.
//! - [`provision_device_identity`] is a demo-only SET_CERTIFICATE flow that
//!   issues an Owner chain from a fixed test CA key. It is not a production
//!   provisioning path.
//!
//! Every flow first authenticates Vendor slot 0 against a pinned trust anchor
//! with CHALLENGE and verifies evidence against that authenticated chain.

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use caliptra_mcu_core_util_host_command_types::certificate::ExportAttestedCsrRequest;
use caliptra_spdm_requester::{
    split_der_certificates, verify_x509_certificate_chain, PeerRootCert, SpdmConfig, SpdmRequester,
    SpdmSocketDeviceIo, SpdmVdmDriverImpl,
};
use p384::ecdsa::SigningKey;
use serde_json::json;
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

use crate::ocp_dip::{self, AttestedCsr, DerivationAttribute, KeyPair};
use crate::SpdmVdmClient;

macro_rules! status {
    ($($arg:tt)*) => {
        println!("[ocp_dev_identity_provision_tool] {}", format_args!($($arg)*))
    };
}

pub const DEFAULT_SERVER: &str = "127.0.0.1:2323";
pub const DEFAULT_OWNER_SLOT_ID: u8 = 2;
pub const DEFAULT_LDEVID_KEY_PAIR_ID: u8 = 1;
const VENDOR_SLOT_ID: u8 = 0;
/// Evidence is requested and verified as P-384 only: the SPDM Vendor chain
/// carries just the ECC RT alias certificate that signs it.
const EVIDENCE_ALGORITHM: &str = "P-384";
const CERT_MODEL_ALIAS_CERT: u8 = 2;
const SPDM_CERT_CHAIN_HEADER_LEN: usize = 4;
const SHA384_DIGEST_LEN: usize = 48;
const OWNER_SLOT_DYNAMIC_TAIL_CERTS: usize = 3; // FMC alias + RT alias + DPE leaf
const TEST_OWNER_ROOT_KEY_BYTES: [u8; 48] = [0x0B; 48];

/// How to reach and authenticate the device.
#[derive(Debug, Clone)]
pub struct DeviceOptions {
    /// Server address (host:port) of the SPDM bridge.
    pub server: String,
    /// DER X.509 root certificate that authenticates the Vendor slot.
    pub vendor_trust_anchor: PathBuf,
}

/// Request parameters for exporting an attested CSR.
#[derive(Debug, Clone)]
pub struct ExportCsrOptions {
    pub device: DeviceOptions,
    /// Key pair to export; must be listed in the keypair inventory.
    pub key_pair_id: u8,
    /// Destination for the DER PKCS#10 CSR.
    pub out_csr: PathBuf,
    /// Destination for the signed EAT carrying the CSR.
    pub out_eat: PathBuf,
    /// Optional destination for a JSON report.
    pub report_json: Option<PathBuf>,
}

/// Request parameters for the demo SET_CERTIFICATE flow.
#[derive(Debug, Clone)]
pub struct ProvisionOptions {
    pub device: DeviceOptions,
    /// SPDM certificate slot to provision.
    pub slot_id: u8,
    /// SPDM key pair ID to associate with the slot.
    pub key_pair_id: u8,
}

impl Default for ProvisionOptions {
    fn default() -> Self {
        Self {
            device: DeviceOptions {
                server: DEFAULT_SERVER.to_string(),
                vendor_trust_anchor: default_vendor_trust_anchor_path(),
            },
            slot_id: DEFAULT_OWNER_SLOT_ID,
            key_pair_id: DEFAULT_LDEVID_KEY_PAIR_ID,
        }
    }
}

/// Retrieve and verify the device's keypair inventory (key pair ID 0).
pub fn discover(device: &DeviceOptions, report_json: Option<&Path>) -> Result<Vec<KeyPair>> {
    let mut session = AuthenticatedDevice::connect(device, Vec::new())?;
    let (evidence, key_pairs) = session.discover()?;

    print_inventory(&key_pairs);
    if let Some(path) = report_json {
        write_json(
            path,
            json!({
                "algorithm": EVIDENCE_ALGORITHM,
                "nonce": hex::encode(evidence.nonce),
                "eat_sha384": hex::encode(Sha384::digest(&evidence.token)),
                "key_pairs": key_pairs
                    .iter()
                    .map(|kp| json!({ "id": kp.id, "attributes": attributes_json(&kp.attributes) }))
                    .collect::<Vec<_>>(),
            }),
        )?;
    }
    session.stop()?;
    Ok(key_pairs)
}

/// Export a verified attested CSR and its signed evidence for offline issuance.
///
/// The key pair must appear in a freshly verified keypair inventory, and the
/// CSR's derivation attributes must match the inventory entry.
pub fn export_csr(options: &ExportCsrOptions) -> Result<()> {
    let mut session = AuthenticatedDevice::connect(&options.device, Vec::new())?;
    let (_, key_pairs) = session.discover()?;
    print_inventory(&key_pairs);
    let key_pair = find_key_pair(&key_pairs, options.key_pair_id)?;

    let (evidence, csr) = session.attested_csr(options.key_pair_id)?;
    if !same_attributes(&csr.attributes, &key_pair.attributes) {
        bail!(
            "attested CSR derivation attributes for key pair {} differ from the keypair inventory",
            options.key_pair_id
        );
    }

    let subject = CertReq::from_der(&csr.csr_der)
        .context("failed to parse attested CSR DER")?
        .info
        .subject
        .to_string();
    status!(
        "Verified attested CSR for key pair {} ({EVIDENCE_ALGORITHM}), subject \"{subject}\"",
        options.key_pair_id
    );
    csr.attributes
        .iter()
        .for_each(|attr| status!("  derivation: {attr}"));

    write_file(&options.out_csr, &csr.csr_der)?;
    write_file(&options.out_eat, &evidence.token)?;
    if let Some(path) = &options.report_json {
        write_json(
            path,
            json!({
                "key_pair_id": options.key_pair_id,
                "algorithm": EVIDENCE_ALGORITHM,
                "nonce": hex::encode(evidence.nonce),
                "eat_sha384": hex::encode(Sha384::digest(&evidence.token)),
                "csr_sha384": hex::encode(Sha384::digest(&csr.csr_der)),
                "csr_subject": subject,
                "attributes": attributes_json(&csr.attributes),
            }),
        )?;
    }
    session.stop()
}

/// Demo-only: provision an Owner certificate slot from an attested CSR.
///
/// Issues an Owner/LDevID chain with a fixed test CA key, installs it with
/// SET_CERTIFICATE, verifies the returned chain, performs Owner-slot
/// CHALLENGE attestation, and sends STOP to the test bridge.
pub fn provision_device_identity(options: &ProvisionOptions) -> Result<()> {
    let owner_root = test_owner_root_cert_der()?;
    let mut session = AuthenticatedDevice::connect(
        &options.device,
        vec![PeerRootCert {
            slot_id: options.slot_id,
            cert_der: owner_root.clone(),
        }],
    )?;

    let (evidence, csr) = session.attested_csr(options.key_pair_id)?;
    status!(
        "ExportAttestedCsr key_pair_id={} returned {} bytes",
        options.key_pair_id,
        evidence.token.len()
    );

    let cert_chain = issue_test_owner_ldev_id_chain_from_csr(&csr.csr_der, &owner_root)
        .context("failed to issue test Owner/LDevID certificate chain from attested CSR")?;
    status!(
        "Issued test Owner/LDevID certificate chain from attested CSR ({} bytes)",
        cert_chain.len()
    );

    let provisioned_certs = validate_owner_chain(&cert_chain, "attested CSR")?;
    verify_csr_matches_owner_leaf(&csr.csr_der, &provisioned_certs)?;
    status!("Attested CSR public key matches owner/LDevID leaf certificate");

    status!(
        "SET_CERTIFICATE slot_id={} key_pair_id={} cert_chain=attested CSR ({} bytes)",
        options.slot_id,
        options.key_pair_id,
        cert_chain.len()
    );
    session.requester.set_certificate(
        None,
        options.slot_id,
        options.key_pair_id,
        CERT_MODEL_ALIAS_CERT,
        &cert_chain,
    )?;

    let provisioned = session.requester.get_certificate(None, options.slot_id)?;
    verify_returned_owner_chain(
        options.slot_id,
        &cert_chain,
        &session.vendor_certs()?,
        &provisioned,
    )?;
    status!(
        "Owner slot {} certificate chain verified via GET_CERTIFICATE ({} bytes)",
        options.slot_id,
        provisioned.len()
    );

    session
        .requester
        .challenge(options.slot_id)
        .with_context(|| format!("Owner-slot CHALLENGE failed for slot {}", options.slot_id))?;
    status!("Owner-slot CHALLENGE passed for slot {}", options.slot_id);

    session.stop()
}

/// Nonce and raw signed EAT returned by one ExportAttestedCsr request.
struct Evidence {
    nonce: [u8; 32],
    token: Vec<u8>,
}

/// SPDM connection whose Vendor slot has been authenticated with CHALLENGE.
struct AuthenticatedDevice {
    requester: SpdmRequester,
    /// Second handle on the bridge socket, used for the test-bridge STOP.
    bridge: SpdmSocketDeviceIo,
    /// Verified Vendor slot DER certificate chain.
    vendor_chain: Vec<u8>,
}

impl AuthenticatedDevice {
    fn connect(options: &DeviceOptions, extra_roots: Vec<PeerRootCert>) -> Result<Self> {
        status!("Connecting to bridge at {}", options.server);
        let mut device_io = SpdmSocketDeviceIo::connect_mctp(&options.server)?;
        device_io.handshake()?;
        let bridge = device_io.try_clone()?;

        let vendor_root = fs::read(&options.vendor_trust_anchor).with_context(|| {
            format!(
                "failed to read vendor trust anchor {}",
                options.vendor_trust_anchor.display()
            )
        })?;
        let peer_root_certs = std::iter::once(PeerRootCert {
            slot_id: VENDOR_SLOT_ID,
            cert_der: vendor_root,
        })
        .chain(extra_roots)
        .collect();
        let mut requester = SpdmRequester::new(
            SpdmConfig {
                slot_id: VENDOR_SLOT_ID,
                peer_root_certs,
                ..SpdmConfig::default()
            },
            Box::new(device_io),
        )?;

        status!("Establishing SPDM connection using Vendor slot {VENDOR_SLOT_ID}");
        requester.connect_authenticated()?;
        status!("CHALLENGE attestation passed for Vendor slot {VENDOR_SLOT_ID}");

        let spdm_chain = requester
            .get_certificate(None, VENDOR_SLOT_ID)
            .context("failed to read authenticated Vendor slot certificate chain")?;
        let chain = parse_spdm_cert_chain(&spdm_chain)
            .context("failed to parse Vendor slot SPDM certificate chain")?;
        let certs = split_der_certificates(chain.der)
            .context("failed to split Vendor slot DER certificate chain")?;
        let root = certs.first().ok_or_else(|| {
            anyhow!("Vendor slot {VENDOR_SLOT_ID} returned an empty certificate chain")
        })?;
        verify_spdm_root_hash(chain.root_hash, root)
            .context("Vendor slot SPDM certificate chain root hash mismatch")?;
        let vendor_chain = chain.der.to_vec();

        Ok(Self {
            requester,
            bridge,
            vendor_chain,
        })
    }

    fn vendor_certs(&self) -> Result<Vec<&[u8]>> {
        split_der_certificates(&self.vendor_chain)
            .context("failed to split Vendor slot DER certificate chain")
    }

    /// The Vendor chain ends with RT alias + DPE leaf; the RT alias key signs
    /// DIP evidence.
    fn rt_alias_cert(&self) -> Result<&[u8]> {
        let certs = self.vendor_certs()?;
        match certs.len() {
            n if n >= 2 => Ok(certs[n - 2]),
            _ => bail!("Vendor chain is too short to contain the RT alias and DPE leaf"),
        }
    }

    fn signed_eat(&mut self, key_id: u32) -> Result<Evidence> {
        let nonce = random_nonce()?;
        let mut vdm = SpdmVdmDriverImpl::new(&mut self.requester, None);
        let response = SpdmVdmClient::new(&mut vdm).export_attested_csr(
            key_id,
            ExportAttestedCsrRequest::ALGO_ECC384,
            &nonce,
        )?;
        response
            .validate_csr_payload()
            .map_err(|e| anyhow!("invalid ExportAttestedCsr payload: {e:?}"))?;
        Ok(Evidence {
            nonce,
            token: response.csr_bytes().to_vec(),
        })
    }

    fn discover(&mut self) -> Result<(Evidence, Vec<KeyPair>)> {
        let evidence = self.signed_eat(ExportAttestedCsrRequest::KEY_ID_DISCOVERY)?;
        let key_pairs =
            ocp_dip::verify_inventory(&evidence.token, &evidence.nonce, self.rt_alias_cert()?)
                .context("keypair inventory verification failed")?;
        Ok((evidence, key_pairs))
    }

    fn attested_csr(&mut self, key_pair_id: u8) -> Result<(Evidence, AttestedCsr)> {
        if key_pair_id == 0 {
            bail!("key pair ID 0 is reserved for keypair inventory discovery");
        }
        let evidence = self.signed_eat(key_pair_id.into())?;
        let csr =
            ocp_dip::verify_attested_csr(&evidence.token, &evidence.nonce, self.rt_alias_cert()?)
                .with_context(|| {
                format!("attested CSR verification failed for key pair {key_pair_id}")
            })?;
        Ok((evidence, csr))
    }

    /// Send STOP to the test bridge. Call this last: the bridge treats STOP as
    /// success and ends the test harness.
    fn stop(mut self) -> Result<()> {
        status!("Sending STOP to bridge");
        self.bridge.send_stop()
    }
}

fn find_key_pair(key_pairs: &[KeyPair], id: u8) -> Result<&KeyPair> {
    key_pairs.iter().find(|kp| kp.id == id).ok_or_else(|| {
        let listed = key_pairs
            .iter()
            .map(|kp| kp.id.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        anyhow!("key pair {id} is not in the device's keypair inventory (listed: {listed})")
    })
}

/// Attribute maps are unordered, so compare them as sets.
fn same_attributes(a: &[DerivationAttribute], b: &[DerivationAttribute]) -> bool {
    let sorted = |attrs: &[DerivationAttribute]| {
        let mut attrs = attrs
            .iter()
            .map(|attr| (attr.oid, attr.bitfield))
            .collect::<Vec<_>>();
        attrs.sort();
        attrs
    };
    sorted(a) == sorted(b)
}

fn print_inventory(key_pairs: &[KeyPair]) {
    status!("Verified keypair inventory ({EVIDENCE_ALGORITHM}):");
    key_pairs.iter().for_each(|kp| {
        kp.attributes
            .iter()
            .for_each(|attr| status!("  key pair {}: {attr}", kp.id))
    });
}

fn attributes_json(attributes: &[DerivationAttribute]) -> serde_json::Value {
    attributes
        .iter()
        .map(|attr| {
            json!({
                "oid": attr.oid.to_string(),
                "ocp": attr.is_ocp(),
                "bitfield": attr.bitfield,
                "components": attr.components(),
            })
        })
        .collect()
}

fn write_file(path: &Path, data: &[u8]) -> Result<()> {
    fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))?;
    status!("Wrote {} ({} bytes)", path.display(), data.len());
    Ok(())
}

fn write_json(path: &Path, value: serde_json::Value) -> Result<()> {
    write_file(path, &serde_json::to_vec_pretty(&value)?)
}

fn random_nonce() -> Result<[u8; 32]> {
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).context("failed to generate freshness nonce")?;
    Ok(nonce)
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

fn issue_test_owner_ldev_id_chain_from_csr(csr_der: &[u8], root: &[u8]) -> Result<Vec<u8>> {
    let csr = parse_csr(csr_der)?;
    let root_key = test_owner_root_signing_key()?;
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

    let mut chain = root.to_vec();
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
        bail!(
            "GET_CERTIFICATE slot {} returned an empty DER chain",
            slot_id
        );
    }
    verify_spdm_root_hash(returned.root_hash, returned_certs[0])?;

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
        || tail[..2].iter().any(|cert| {
            vendor_certs[..vendor_certs.len() - OWNER_SLOT_DYNAMIC_TAIL_CERTS].contains(cert)
        })
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
        root_hash: &chain
            [SPDM_CERT_CHAIN_HEADER_LEN..SPDM_CERT_CHAIN_HEADER_LEN + SHA384_DIGEST_LEN],
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
    use crate::ocp_dip::OCP_KDA_OID;
    use x509_cert::builder::RequestBuilder;
    use x509_cert::der::asn1::ObjectIdentifier;

    fn test_owner_chain() -> Vec<u8> {
        let key = SigningKey::from_bytes((&[0x07u8; 48]).into()).unwrap();
        issue_test_owner_ldev_id_chain_from_csr(
            &test_csr(&key, "CN=Caliptra LDevID"),
            &test_owner_root_cert_der().unwrap(),
        )
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

        let chain =
            issue_test_owner_ldev_id_chain_from_csr(&csr, &test_owner_root_cert_der().unwrap())
                .unwrap();
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

        let err =
            issue_test_owner_ldev_id_chain_from_csr(&csr, &test_owner_root_cert_der().unwrap())
                .unwrap_err();
        assert!(err.to_string().contains("subject is empty"));
    }

    fn kda(bitfield: u64) -> DerivationAttribute {
        DerivationAttribute {
            oid: OCP_KDA_OID,
            bitfield,
        }
    }

    fn vendor(bitfield: u64) -> DerivationAttribute {
        DerivationAttribute {
            oid: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1"),
            bitfield,
        }
    }

    #[test]
    fn test_find_key_pair_rejects_unlisted_id() {
        let key_pairs = [KeyPair {
            id: 1,
            attributes: vec![kda(3)],
        }];
        assert_eq!(find_key_pair(&key_pairs, 1).unwrap().id, 1);
        let err = find_key_pair(&key_pairs, 4).unwrap_err();
        assert!(err.to_string().contains("listed: 1"), "{err}");
    }

    #[test]
    fn test_same_attributes_ignores_order_but_not_bits() {
        assert!(same_attributes(&[kda(3), vendor(1)], &[vendor(1), kda(3)]));
        assert!(!same_attributes(&[kda(3)], &[kda(0x13)]));
        assert!(!same_attributes(&[kda(3)], &[kda(3), vendor(1)]));
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
        let err = verify_returned_owner_chain(DEFAULT_OWNER_SLOT_ID, &chain, &certs, &returned)
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
        let err =
            verify_returned_owner_chain(DEFAULT_OWNER_SLOT_ID, &chain, &vendor_certs, &returned)
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

        let err = verify_returned_owner_chain(DEFAULT_OWNER_SLOT_ID, &chain, &certs, &returned)
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

    fn test_csr(signing_key: &SigningKey, subject: &str) -> Vec<u8> {
        RequestBuilder::new(Name::from_str(subject).unwrap(), signing_key)
            .unwrap()
            .build::<p384::ecdsa::DerSignature>()
            .unwrap()
            .to_der()
            .unwrap()
    }
}

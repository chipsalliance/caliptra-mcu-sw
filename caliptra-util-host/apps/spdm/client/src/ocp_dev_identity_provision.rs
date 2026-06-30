// Licensed under the Apache-2.0 license

//! OCP device identity provisioning over SPDM SET_CERTIFICATE.

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use caliptra_mcu_core_util_host_command_types::certificate::ExportAttestedCsrResponse;
use caliptra_spdm_requester::{
    PeerRootCert, SpdmConfig, SpdmRequester, SpdmSocketDeviceIo, SpdmVdmDriverImpl,
};
use p384::ecdsa::signature::{Signer, Verifier};
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha384};
use x509_parser::prelude::{FromDer, X509Certificate, X509CertificationRequest};

use crate::SpdmVdmClient;

pub const DEFAULT_OWNER_SLOT_ID: u8 = 2;
pub const DEFAULT_LDEVID_KEY_PAIR_ID: u8 = 1;
pub const DEFAULT_VENDOR_SLOT_ID: u8 = 0;
pub const DEFAULT_CSR_ALGORITHM_ECC384: u32 = 1;
const CERT_MODEL_ALIAS_CERT: u8 = 2;
const SPDM_CERT_CHAIN_HEADER_LEN: usize = 4;
const SHA384_DIGEST_LEN: usize = 48;
const COSE_TAG_CWT: u64 = 61;
const COSE_TAG_SIGN1: u64 = 18;
const COSE_ALG_ES384: i128 = -35;
const COSE_ALG_ESP384: i128 = -51;
const COSE_HEADER_ALG: i128 = 1;
const COSE_HEADER_KID: i128 = 4;
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
    /// Initial vendor certificate slot used for SPDM connection/attestation.
    pub vendor_slot_id: u8,
    /// Algorithm requested from ExportAttestedCsr (1 = ECC384).
    pub csr_algorithm: u32,
    /// DER X.509 certificate chain to install.
    pub cert_chain: PathBuf,
    /// DER X.509 root certificate that authenticates the initial Vendor slot.
    /// Required unless `accept_unverified_peer_cert_chain` is explicitly set.
    pub vendor_trust_anchor: Option<PathBuf>,
    /// Explicitly retain the legacy libspdm trust bypass. This is for debugging
    /// only and should remain false for issue-1711 provisioning.
    pub accept_unverified_peer_cert_chain: bool,
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
            vendor_trust_anchor: None,
            accept_unverified_peer_cert_chain: false,
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

    let static_owner_chain = if options.require_attested_csr {
        None
    } else {
        Some(load_owner_chain_from_path(&options.cert_chain)?)
    };
    let owner_root = if let Some(chain) = &static_owner_chain {
        chain.root.clone()
    } else {
        test_owner_root_cert_der()?
    };
    let vendor_root = match (&options.vendor_trust_anchor, options.accept_unverified_peer_cert_chain)
    {
        (Some(path), _) => fs::read(path)
            .with_context(|| format!("failed to read vendor trust anchor {}", path.display()))?,
        (None, true) => Vec::new(),
        (None, false) => bail!(
            "vendor trust anchor is required for authenticated Vendor slot {}; pass --vendor-trust-anchor or the debug-only --accept-unverified-peer-cert-chain",
            options.vendor_slot_id
        ),
    };

    let spdm_config = SpdmConfig {
        slot_id: options.vendor_slot_id,
        accept_unverified_peer_cert_chain: options.accept_unverified_peer_cert_chain,
        peer_root_certs: [
            (!vendor_root.is_empty()).then_some(PeerRootCert {
                slot_id: options.vendor_slot_id,
                cert_der: vendor_root,
            }),
            Some(PeerRootCert {
                slot_id: options.slot_id,
                cert_der: owner_root,
            }),
        ]
        .into_iter()
        .flatten()
        .collect(),
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

    let vendor_spdm_chain = requester
        .get_certificate(None, options.vendor_slot_id)
        .context("failed to read authenticated Vendor slot certificate chain for CSR attestation")?;
    let vendor_chain = parse_spdm_cert_chain(&vendor_spdm_chain)
        .context("failed to parse Vendor slot SPDM certificate chain")?;
    let vendor_certs = split_der_certificates(vendor_chain.der)
        .context("failed to split Vendor slot DER certificate chain")?;
    if vendor_certs.is_empty() {
        bail!("Vendor slot {} returned an empty certificate chain", options.vendor_slot_id);
    }
    verify_spdm_root_hash(vendor_chain.root_hash, vendor_certs[0])
        .context("Vendor slot SPDM certificate chain root hash mismatch")?;

    let attested_csr = if options.require_attested_csr {
        let nonce = random_nonce()?;
        let csr = export_attested_csr(
            &mut requester,
            options.key_pair_id as u32,
            options.csr_algorithm,
            &nonce,
        )?;
        let csr_der = validate_attested_csr(&csr, &nonce, &vendor_certs)?;
        println!(
            "[ocp_dev_identity_provision_tool] ExportAttestedCsr key_pair_id={} returned {} bytes",
            options.key_pair_id, csr.data_len
        );
        Some((csr, csr_der))
    } else {
        None
    };

    let (cert_chain, cert_chain_source) = if let Some((_csr, csr_der)) = &attested_csr {
        let chain = issue_test_owner_ldev_id_chain_from_csr(csr_der)
            .context("failed to issue test Owner/LDevID certificate chain from attested CSR")?;
        println!(
            "[ocp_dev_identity_provision_tool] Issued test Owner/LDevID certificate chain from attested CSR ({} bytes)",
            chain.len()
        );
        (chain, "attested CSR".to_string())
    } else if let Some(chain) = static_owner_chain {
        (chain.der, options.cert_chain.display().to_string())
    } else {
        bail!("internal error: no attested CSR or static owner chain available")
    };

    let provisioned_certs = validate_owner_chain(&cert_chain, &cert_chain_source)?;
    if let Some((_csr, csr_der)) = &attested_csr {
        verify_csr_matches_owner_leaf(csr_der, &provisioned_certs)?;
        println!(
            "[ocp_dev_identity_provision_tool] Attested CSR public key matches owner/LDevID leaf certificate"
        );
    }

    println!(
        "[ocp_dev_identity_provision_tool] SET_CERTIFICATE slot_id={} key_pair_id={} cert_chain={} ({} bytes)",
        options.slot_id,
        options.key_pair_id,
        cert_chain_source,
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

pub fn default_cert_chain_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .map(|spdm_dir| spdm_dir.join("certs/test_owner_certchain.der"))
        .unwrap_or_else(|| PathBuf::from("certs/test_owner_certchain.der"))
}

struct OwnerChain {
    der: Vec<u8>,
    root: Vec<u8>,
}

fn load_owner_chain_from_path(path: &PathBuf) -> Result<OwnerChain> {
    let der = fs::read(path)
        .with_context(|| format!("failed to read certificate chain {}", path.display()))?;
    let certs = validate_owner_chain(&der, &path.display().to_string())?;
    let root = certs[0].to_vec();
    drop(certs);
    Ok(OwnerChain { der, root })
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

fn test_owner_root_subject_name() -> Vec<u8> {
    synthetic_subject_name(Some(b"Caliptra Test Owner Root CA"))
}

fn test_owner_root_cert_der() -> Result<Vec<u8>> {
    let key = test_owner_root_signing_key()?;
    let name = test_owner_root_subject_name();
    let tbs = x509_tbs_certificate(
        0x1001,
        &name,
        &name,
        &p384_spki(&key),
        Some(6),
    );
    Ok(sign_x509_certificate(&tbs, &key))
}

fn issue_test_owner_ldev_id_chain_from_csr(csr_der: &[u8]) -> Result<Vec<u8>> {
    let csr = parse_csr(csr_der)?;
    let root_key = test_owner_root_signing_key()?;
    let root = test_owner_root_cert_der()?;
    let issuer = test_owner_root_subject_name();
    let subject = csr.certification_request_info.subject.as_raw();
    if csr.certification_request_info.subject.iter().next().is_none() {
        bail!("attested CSR subject is empty; cannot issue Owner/LDevID certificate");
    }
    let subject_pki = csr.certification_request_info.subject_pki.raw;
    let serial_seed = Sha384::digest(csr_der);
    let serial = u64::from_be_bytes(
        serial_seed[..8]
            .try_into()
            .map_err(|_| anyhow!("failed to derive Owner/LDevID serial"))?,
    ) & 0x7fff_ffff_ffff_ffff;
    let tbs = x509_tbs_certificate(serial.max(1), &issuer, subject, subject_pki, Some(3));
    let leaf = sign_x509_certificate(&tbs, &root_key);

    let mut chain = root;
    chain.extend_from_slice(&leaf);
    Ok(chain)
}

fn x509_tbs_certificate(
    serial: u64,
    issuer: &[u8],
    subject: &[u8],
    subject_pki: &[u8],
    ca_path_len: Option<u8>,
) -> Vec<u8> {
    der_sequence(&[
        der_tlv(0xA0, &[0x02, 0x01, 0x02]), // Version v3
        der_integer_u64(serial),
        ecdsa_with_sha384_algorithm(),
        issuer.to_vec(),
        der_sequence(&[
            der_tlv(0x17, b"260101000000Z"),
            der_tlv(0x17, b"360101000000Z"),
        ]),
        subject.to_vec(),
        subject_pki.to_vec(),
        x509_extensions(ca_path_len),
    ])
}

fn sign_x509_certificate(tbs: &[u8], signing_key: &SigningKey) -> Vec<u8> {
    let signature_algorithm = ecdsa_with_sha384_algorithm();
    let signature: Signature = signing_key.sign(tbs);
    let signature_der = signature.to_der();
    let mut signature_bits = vec![0x00];
    signature_bits.extend_from_slice(signature_der.as_bytes());
    der_sequence(&[
        tbs.to_vec(),
        signature_algorithm,
        der_tlv(0x03, &signature_bits),
    ])
}

fn x509_extensions(ca_path_len: Option<u8>) -> Vec<u8> {
    let basic_constraints_value = if let Some(path_len) = ca_path_len {
        der_sequence(&[vec![0x01, 0x01, 0xff], vec![0x02, 0x01, path_len]])
    } else {
        der_sequence(&[])
    };
    let basic_constraints = der_sequence(&[
        vec![0x06, 0x03, 0x55, 0x1d, 0x13],
        vec![0x01, 0x01, 0xff],
        der_tlv(0x04, &basic_constraints_value),
    ]);
    let key_usage_bits = if ca_path_len.is_some() {
        [0x01, 0x86] // digitalSignature | keyCertSign | cRLSign
    } else {
        [0x07, 0x80] // digitalSignature
    };
    let key_usage = der_sequence(&[
        vec![0x06, 0x03, 0x55, 0x1d, 0x0f],
        vec![0x01, 0x01, 0xff],
        der_tlv(0x04, &der_tlv(0x03, &key_usage_bits)),
    ]);
    der_tlv(0xA3, &der_sequence(&[basic_constraints, key_usage]))
}

fn ecdsa_with_sha384_algorithm() -> Vec<u8> {
    der_sequence(&[vec![
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03,
    ]])
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

fn der_integer_u64(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first_nonzero = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let mut encoded = bytes[first_nonzero..].to_vec();
    if encoded.first().map(|b| b & 0x80 != 0).unwrap_or(false) {
        encoded.insert(0, 0);
    }
    der_tlv(0x02, &encoded)
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
    if claims.nonce != nonce {
        bail!("attested CSR COSE payload nonce does not match requested freshness nonce");
    }
    let csr = claims.csr;
    // Caliptra's attested CSR envelope authenticates the PKCS#10 bytes with the
    // SPDM attestation key. Current firmware emits a placeholder PKCS#10
    // self-signature, so do not require CSR self-signature validity on this
    // attested path. The CSR is still parsed strictly and later bound to the
    // provisioned owner/LDevID leaf public key.
    parse_csr(csr)?;
    Ok(csr.to_vec())
}

#[cfg(test)]
fn validate_bare_pkcs10_csr(csr: &[u8], nonce: &[u8; 32]) -> Result<()> {
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

struct CoseSign1Envelope<'a> {
    protected: &'a [u8],
    payload: &'a [u8],
    signature: &'a [u8],
}

struct CoseProtectedHeader<'a> {
    alg: i128,
    kid: Option<&'a [u8]>,
}

struct AttestedCsrClaims<'a> {
    nonce: &'a [u8],
    csr: &'a [u8],
}

fn parse_cose_sign1(data: &[u8]) -> Result<CoseSign1Envelope<'_>> {
    let mut cbor = CborReader::new(data);
    if cbor.peek() == Some(0xd9) {
        let tag = cbor.read_tag()?;
        if tag != 55799 {
            bail!("unexpected outer CBOR self-describe tag {tag}");
        }
    }
    let cwt_tag = cbor.read_tag()?;
    if cwt_tag != COSE_TAG_CWT {
        bail!("attested CSR COSE envelope missing CWT tag: found {cwt_tag}");
    }
    let sign1_tag = cbor.read_tag()?;
    if sign1_tag != COSE_TAG_SIGN1 {
        bail!("attested CSR COSE envelope missing COSE_Sign1 tag: found {sign1_tag}");
    }
    let array_len = cbor.read_array_len()?;
    if array_len != 4 {
        bail!("COSE_Sign1 array length is {array_len}, expected 4");
    }
    let protected = cbor.read_bstr()?;
    cbor.skip_value()?; // unprotected header map
    let payload = cbor.read_bstr()?;
    let signature = cbor.read_bstr()?;
    if !cbor.is_empty() {
        bail!("COSE_Sign1 envelope has trailing bytes");
    }
    Ok(CoseSign1Envelope {
        protected,
        payload,
        signature,
    })
}

fn verify_attested_csr_cose<'a>(
    cose: &'a CoseSign1Envelope<'a>,
    rt_alias_cert: &[u8],
) -> Result<AttestedCsrClaims<'a>> {
    let protected = parse_cose_protected_header(cose.protected)?;
    if protected.alg != COSE_ALG_ES384 && protected.alg != COSE_ALG_ESP384 {
        bail!(
            "unsupported attested CSR COSE algorithm {}, expected ES384/ESP384",
            protected.alg
        );
    }
    let sig_structure = cose_sig_structure(cose.protected, cose.payload);
    verify_cose_signature_with_authenticated_chain(
        cose.signature,
        &sig_structure,
        protected.kid,
        &[rt_alias_cert],
    )?;
    parse_attested_csr_claims(cose.payload)
}

fn rt_alias_signing_cert<'a>(attestation_certs: &'a [&'a [u8]]) -> Result<&'a [u8]> {
    if attestation_certs.len() < 2 {
        bail!(
            "attested CSR RT-alias signature validation requires Vendor chain with RT alias and DPE leaf"
        );
    }
    Ok(attestation_certs[attestation_certs.len() - 2])
}

fn parse_cose_protected_header(protected: &[u8]) -> Result<CoseProtectedHeader<'_>> {
    let mut cbor = CborReader::new(protected);
    let count = cbor.read_map_len()?;
    let mut alg = None;
    let mut kid = None;
    for _ in 0..count {
        let key = cbor.read_int()?;
        match key {
            COSE_HEADER_ALG => alg = Some(cbor.read_int()?),
            COSE_HEADER_KID => kid = Some(cbor.read_bstr()?),
            _ => cbor.skip_value()?,
        }
    }
    if !cbor.is_empty() {
        bail!("COSE protected header has trailing bytes");
    }
    Ok(CoseProtectedHeader {
        alg: alg.ok_or_else(|| anyhow!("COSE protected header missing alg"))?,
        kid,
    })
}

fn parse_attested_csr_claims(payload: &[u8]) -> Result<AttestedCsrClaims<'_>> {
    let mut cbor = CborReader::new(payload);
    let count = cbor.read_map_len()?;
    let mut nonce = None;
    let mut csr = None;
    for _ in 0..count {
        let key = cbor.read_int()?;
        match key {
            EAT_CLAIM_NONCE => nonce = Some(cbor.read_bstr()?),
            OCP_CLAIM_CSR => csr = Some(cbor.read_bstr()?),
            _ => cbor.skip_value()?,
        }
    }
    if !cbor.is_empty() {
        bail!("attested CSR COSE payload has trailing bytes");
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
    let (remaining, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow!("failed to parse X.509 certificate DER: {e:?}"))?;
    if !remaining.is_empty() {
        bail!(
            "X.509 certificate DER has {} trailing byte(s) after certificate structure",
            remaining.len()
        );
    }
    let public_key = cert.tbs_certificate.subject_pki.subject_public_key.data;
    if public_key.first() != Some(&0x04) {
        bail!("attestation certificate public key is not an uncompressed P-384 point");
    }
    Ok(public_key.to_vec())
}

fn cose_sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x84); // array(4)
    out.extend_from_slice(&[
        0x6a, b'S', b'i', b'g', b'n', b'a', b't', b'u', b'r', b'e', b'1',
    ]);
    cbor_write_bstr(&mut out, protected);
    out.push(0x40); // empty external_aad bstr
    cbor_write_bstr(&mut out, payload);
    out
}

fn cbor_write_bstr(out: &mut Vec<u8>, bytes: &[u8]) {
    cbor_write_type_len(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn cbor_write_type_len(out: &mut Vec<u8>, major: u8, value: u64) {
    if value <= 23 {
        out.push((major << 5) | value as u8);
    } else if value <= u8::MAX as u64 {
        out.extend_from_slice(&[(major << 5) | 24, value as u8]);
    } else if value <= u16::MAX as u64 {
        out.push((major << 5) | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        out.push((major << 5) | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push((major << 5) | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

struct CborReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> CborReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos == self.data.len()
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn read_tag(&mut self) -> Result<u64> {
        let (major, value) = self.read_type_len()?;
        if major != 6 {
            bail!("expected CBOR tag, got major type {major}");
        }
        Ok(value)
    }

    fn read_array_len(&mut self) -> Result<usize> {
        let (major, value) = self.read_type_len()?;
        if major != 4 {
            bail!("expected CBOR array, got major type {major}");
        }
        usize::try_from(value).map_err(|_| anyhow!("CBOR array length too large"))
    }

    fn read_map_len(&mut self) -> Result<usize> {
        let (major, value) = self.read_type_len()?;
        if major != 5 {
            bail!("expected CBOR map, got major type {major}");
        }
        usize::try_from(value).map_err(|_| anyhow!("CBOR map length too large"))
    }

    fn read_int(&mut self) -> Result<i128> {
        let (major, value) = self.read_type_len()?;
        match major {
            0 => Ok(value as i128),
            1 => Ok(-1 - value as i128),
            _ => bail!("expected CBOR integer, got major type {major}"),
        }
    }

    fn read_bstr(&mut self) -> Result<&'a [u8]> {
        let (major, value) = self.read_type_len()?;
        if major != 2 {
            bail!("expected CBOR byte string, got major type {major}");
        }
        let len = usize::try_from(value).map_err(|_| anyhow!("CBOR byte string too large"))?;
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| anyhow!("CBOR byte string length overflows"))?;
        let bytes = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| anyhow!("truncated CBOR byte string"))?;
        self.pos = end;
        Ok(bytes)
    }

    fn skip_value(&mut self) -> Result<()> {
        let (major, value) = self.read_type_len()?;
        match major {
            0 | 1 | 7 => Ok(()),
            2 | 3 => {
                let len = usize::try_from(value).map_err(|_| anyhow!("CBOR item too large"))?;
                let end = self
                    .pos
                    .checked_add(len)
                    .ok_or_else(|| anyhow!("CBOR item length overflows"))?;
                if end > self.data.len() {
                    bail!("truncated CBOR item");
                }
                self.pos = end;
                Ok(())
            }
            4 => {
                for _ in 0..value {
                    self.skip_value()?;
                }
                Ok(())
            }
            5 => {
                for _ in 0..value {
                    self.skip_value()?;
                    self.skip_value()?;
                }
                Ok(())
            }
            6 => self.skip_value(),
            _ => bail!("unsupported CBOR major type {major}"),
        }
    }

    fn read_type_len(&mut self) -> Result<(u8, u64)> {
        let first = *self
            .data
            .get(self.pos)
            .ok_or_else(|| anyhow!("unexpected end of CBOR data"))?;
        self.pos += 1;
        let major = first >> 5;
        let addl = first & 0x1f;
        let value = match addl {
            0..=23 => addl as u64,
            24 => self.read_uint::<1>()?,
            25 => self.read_uint::<2>()?,
            26 => self.read_uint::<4>()?,
            27 => self.read_uint::<8>()?,
            _ => bail!("indefinite/reserved CBOR additional info {addl} is unsupported"),
        };
        Ok((major, value))
    }

    fn read_uint<const N: usize>(&mut self) -> Result<u64> {
        let end = self
            .pos
            .checked_add(N)
            .ok_or_else(|| anyhow!("CBOR integer length overflows"))?;
        let bytes = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| anyhow!("truncated CBOR integer"))?;
        self.pos = end;
        let mut value = 0u64;
        for byte in bytes {
            value = (value << 8) | (*byte as u64);
        }
        Ok(value)
    }
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
    let returned = parse_spdm_cert_chain(returned_spdm_chain)?;
    if !returned.der.starts_with(installed_der) {
        bail!(
            "GET_CERTIFICATE slot {} did not start with installed Owner Root + Endorsed LDevID chain",
            slot_id
        );
    }

    let installed_count = split_der_certificates(installed_der)?.len();
    let returned_certs = split_der_certificates(returned.der)?;
    if returned_certs.is_empty() {
        bail!("GET_CERTIFICATE slot {} returned an empty DER chain", slot_id);
    }
    verify_spdm_root_hash(&returned.root_hash, returned_certs[0])?;

    let returned_count = returned_certs.len();
    let expected_count = installed_count + OWNER_SLOT_DYNAMIC_TAIL_CERTS;
    if returned_count != expected_count {
        bail!(
            "GET_CERTIFICATE slot {} returned {} cert(s), expected installed owner chain plus FMC alias + RT alias + DPE leaf ({} certs total)",
            slot_id,
            returned_count,
            expected_count
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

fn verify_x509_certificate_chain(certs: &[&[u8]]) -> Result<()> {
    if certs.is_empty() {
        bail!("X.509 certificate chain is empty");
    }
    let parsed = certs
        .iter()
        .enumerate()
        .map(|(idx, cert)| {
            let (remaining, parsed) = X509Certificate::from_der(cert)
                .map_err(|e| anyhow!("failed to parse X.509 cert {idx}: {e:?}"))?;
            if !remaining.is_empty() {
                bail!(
                    "X.509 cert {idx} has {} trailing byte(s) after certificate structure",
                    remaining.len()
                );
            }
            Ok(parsed)
        })
        .collect::<Result<Vec<_>>>()?;

    parsed[0]
        .verify_signature(None)
        .map_err(|e| anyhow!("root certificate self-signature verification failed: {e:?}"))?;

    for (idx, pair) in parsed.windows(2).enumerate() {
        let parent = &pair[0];
        let child = &pair[1];
        if child.issuer() != parent.subject() {
            bail!(
                "X.509 chain issuer/subject mismatch between cert {} and cert {}",
                idx,
                idx + 1
            );
        }
        child
            .verify_signature(Some(parent.public_key()))
            .map_err(|e| anyhow!("X.509 cert {} signature verification failed: {e:?}", idx + 1))?;
    }
    Ok(())
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
    fn test_issue_test_owner_ldev_id_chain_from_csr_uses_csr_spki() {
        let key_bytes = [0x07u8; 48];
        let signing_key = SigningKey::from_bytes((&key_bytes).into()).unwrap();
        let csr = synthetic_csr(&p384_spki(&signing_key), Some(b"Caliptra LDevID"));

        let chain = issue_test_owner_ldev_id_chain_from_csr(&csr).unwrap();
        let certs = split_der_certificates(&chain).unwrap();

        assert_eq!(certs.len(), 2);
        verify_x509_certificate_chain(&certs).unwrap();
        verify_csr_matches_owner_leaf(&csr, &certs).unwrap();
    }

    #[test]
    fn test_issue_test_owner_ldev_id_chain_from_csr_rejects_empty_subject() {
        let chain = fs::read(default_cert_chain_path()).unwrap();
        let certs = split_der_certificates(&chain).unwrap();
        let owner_leaf_spki = parse_certificate_spki(certs.last().unwrap()).unwrap();
        let csr = synthetic_csr(owner_leaf_spki, None);

        let err = issue_test_owner_ldev_id_chain_from_csr(&csr).unwrap_err();
        assert!(err.to_string().contains("subject is empty"));
    }

    #[test]
    fn test_validate_attested_csr_rejects_raw_der_csr_with_nonce() {
        let nonce = [0x5Au8; 32];
        let csr = signed_p384_csr(&nonce);
        let response = csr_response(&csr);

        let err = validate_attested_csr(&response, &nonce, &[]).unwrap_err();
        assert!(err.to_string().contains("raw PKCS#10 CSR is not accepted"));
    }

    #[test]
    fn test_validate_attested_csr_rejects_unsigned_envelope_with_der_csr() {
        let nonce = [0x5Au8; 32];
        let csr = signed_p384_csr(&nonce);
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
        let csr = synthetic_csr_with_signature_payload(&p384_spki(&csr_key), None, &[0x00]);
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
        let csr = synthetic_csr_with_signature_payload(&p384_spki(&csr_key), None, &[0x00]);
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
    fn test_validate_attested_csr_rejects_invalid_csr_signature() {
        let nonce = [0x5Au8; 32];
        let mut csr = signed_p384_csr(&nonce);
        let last = csr.last_mut().unwrap();
        *last ^= 0x01;

        let err = validate_bare_pkcs10_csr(&csr, &nonce).unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
    }

    #[test]
    fn test_validate_attested_csr_rejects_missing_nonce() {
        let csr = signed_p384_csr(&[0x5Au8; 32]);

        let err = validate_bare_pkcs10_csr(&csr, &[0xA5u8; 32]).unwrap_err();
        assert!(err.to_string().contains("freshness nonce"));
    }

    #[test]
    fn test_validate_attested_csr_rejects_nonce_outside_request_info() {
        let chain = fs::read(default_cert_chain_path()).unwrap();
        let certs = split_der_certificates(&chain).unwrap();
        let owner_leaf_spki = parse_certificate_spki(certs.last().unwrap()).unwrap();
        let nonce = [0x5Au8; 32];
        let csr = synthetic_csr_with_signature_payload(owner_leaf_spki, None, &nonce);

        let err = validate_bare_pkcs10_csr(&csr, &nonce).unwrap_err();
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
    fn test_verify_x509_certificate_chain_accepts_default_owner_chain() {
        let chain = fs::read(default_cert_chain_path()).unwrap();
        let certs = split_der_certificates(&chain).unwrap();

        verify_x509_certificate_chain(&certs).unwrap();
    }

    #[test]
    fn test_verify_returned_owner_chain_rejects_malformed_dynamic_tail() {
        let chain = fs::read(default_cert_chain_path()).unwrap();
        let certs = split_der_certificates(&chain).unwrap();
        let mut returned_der = chain.clone();
        returned_der.extend_from_slice(certs[0]);
        returned_der.extend_from_slice(&[0x30, 0x01, 0xA2]);
        returned_der.extend_from_slice(&[0x30, 0x01, 0xA3]);

        let returned = spdm_chain(&returned_der);
        let err =
            verify_returned_owner_chain(DEFAULT_OWNER_SLOT_ID, &chain, &returned).unwrap_err();
        assert!(err
            .to_string()
            .contains("GET_CERTIFICATE returned chain failed X.509 validation"));
    }

    #[test]
    fn test_parse_spdm_cert_chain_rejects_bad_root_hash() {
        let chain = fs::read(default_cert_chain_path()).unwrap();
        let mut returned_der = chain.clone();
        returned_der.extend_from_slice(&[0x30, 0x01, 0xA1]);
        returned_der.extend_from_slice(&[0x30, 0x01, 0xA2]);
        returned_der.extend_from_slice(&[0x30, 0x01, 0xA3]);
        let mut returned = spdm_chain(&returned_der);
        returned[SPDM_CERT_CHAIN_HEADER_LEN] ^= 0x01;

        let err =
            verify_returned_owner_chain(DEFAULT_OWNER_SLOT_ID, &chain, &returned).unwrap_err();
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

    fn signed_cose_attested_csr(signing_key: &SigningKey, nonce: &[u8; 32], csr: &[u8]) -> Vec<u8> {
        let public_key = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let kid = Sha384::digest(&public_key[1..]);
        let mut protected = Vec::new();
        protected.push(0xA2); // map(2)
        cbor_write_int(&mut protected, COSE_HEADER_ALG);
        cbor_write_int(&mut protected, COSE_ALG_ESP384);
        cbor_write_int(&mut protected, COSE_HEADER_KID);
        cbor_write_bstr(&mut protected, &kid);

        let mut payload = Vec::new();
        payload.push(0xA2); // map(2)
        cbor_write_int(&mut payload, EAT_CLAIM_NONCE);
        cbor_write_bstr(&mut payload, nonce);
        cbor_write_int(&mut payload, OCP_CLAIM_CSR);
        cbor_write_bstr(&mut payload, csr);

        let sig_structure = cose_sig_structure(&protected, &payload);
        let signature: Signature = signing_key.sign(&sig_structure);
        let mut envelope = Vec::new();
        cbor_write_type_len(&mut envelope, 6, COSE_TAG_CWT);
        cbor_write_type_len(&mut envelope, 6, COSE_TAG_SIGN1);
        envelope.push(0x84); // array(4)
        cbor_write_bstr(&mut envelope, &protected);
        envelope.push(0xA0); // unprotected map(0)
        cbor_write_bstr(&mut envelope, &payload);
        cbor_write_bstr(&mut envelope, &signature.to_bytes());
        envelope
    }

    fn synthetic_cert_for_key(signing_key: &SigningKey) -> Vec<u8> {
        let signature_algorithm = der_sequence(&[vec![
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03,
        ]]);
        let name = synthetic_subject_name(Some(b"COSE signer"));
        let validity = der_sequence(&[
            der_tlv(0x17, b"230101000000Z"),
            der_tlv(0x17, b"991231235959Z"),
        ]);
        let tbs = der_sequence(&[
            der_tlv(0xA0, &[0x02, 0x01, 0x02]),
            vec![0x02, 0x01, 0x01],
            signature_algorithm.clone(),
            name.clone(),
            validity,
            name,
            p384_spki(signing_key),
        ]);
        let signature: Signature = signing_key.sign(&tbs);
        let signature_der = signature.to_der();
        let mut signature_bits = vec![0x00];
        signature_bits.extend_from_slice(signature_der.as_bytes());
        der_sequence(&[tbs, signature_algorithm, der_tlv(0x03, &signature_bits)])
    }

    fn cbor_write_int(out: &mut Vec<u8>, value: i128) {
        if value >= 0 {
            cbor_write_type_len(out, 0, value as u64);
        } else {
            cbor_write_type_len(out, 1, (-1 - value) as u64);
        }
    }

}

// Licensed under the Apache-2.0 license

//! OCP Device Identity Provisioning (DIP) evidence verification.
//!
//! Caliptra answers `ExportAttestedCsr` with a COSE_Sign1/CWT signed by the RT
//! alias key. Key pair ID 0 returns the keypair inventory (claim -70003); a
//! non-zero ID returns an attested CSR (claim -70001) plus its key-derivation
//! attributes (claim -70002). This module authenticates and decodes both token
//! kinds. It is transport independent: callers supply the RT alias
//! certificate from an already authenticated certificate chain.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Cursor;

use anyhow::{anyhow, bail, Context, Result};
use coset::{cbor::value::Value, iana::Algorithm, AsCborValue, CoseSign1};
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::Decode;
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::request::CertReq;
use x509_cert::Certificate;

const EAT_CLAIM_NONCE: i128 = 10;
const OCP_CLAIM_CSR: i128 = -70001;
const OCP_CLAIM_KEY_ATTRIBUTES: i128 = -70002;
const OCP_CLAIM_KEYPAIR_INVENTORY: i128 = -70003;

const CBOR_TAG_COSE_SIGN1: u64 = 18;
const CBOR_TAG_CWT: u64 = 61;
const CBOR_TAG_OID: u64 = 111;
const CBOR_TAG_SELF_DESCRIBED: u64 = 55799;

/// OCP DIP key-derivation attribute OID (`ocp-security-dip-kda`).
pub const OCP_KDA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.42623.1.2");

/// Bits of the OCP derivation-component bitfield.
const DERIVATION_COMPONENTS: [(u64, &str); 6] = [
    (1 << 0, "UDS"),
    (1 << 1, "field entropy"),
    (1 << 2, "owner non-confidential fuses"),
    (1 << 3, "vendor non-confidential fuses"),
    (1 << 4, "first mutable code"),
    (1 << 5, "runtime firmware"),
];

/// One entry of a key-attributes map: an OID and its derivation bitfield.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationAttribute {
    pub oid: ObjectIdentifier,
    pub bitfield: u64,
}

impl DerivationAttribute {
    /// Whether this is the OCP-defined derivation-component attribute.
    pub fn is_ocp(&self) -> bool {
        self.oid == OCP_KDA_OID
    }

    /// Names of the set derivation components. Only defined for the OCP
    /// attribute; vendor attributes have vendor-specific bit meanings.
    pub fn components(&self) -> Vec<String> {
        if !self.is_ocp() {
            return Vec::new();
        }
        let known = DERIVATION_COMPONENTS
            .iter()
            .filter(|(bit, _)| self.bitfield & bit != 0)
            .map(|(_, name)| name.to_string());
        let known_mask = DERIVATION_COMPONENTS
            .iter()
            .fold(0, |mask, (bit, _)| mask | bit);
        let reserved = self.bitfield & !known_mask;
        known
            .chain((reserved != 0).then(|| format!("reserved bits {reserved:#x}")))
            .collect()
    }
}

impl fmt::Display for DerivationAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_ocp() {
            write!(
                f,
                "{} (OCP KDA) = {:#x} [{}]",
                self.oid,
                self.bitfield,
                self.components().join(", ")
            )
        } else {
            write!(f, "{} (vendor) = {:#x}", self.oid, self.bitfield)
        }
    }
}

/// A key pair advertised by the keypair inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    pub id: u8,
    pub attributes: Vec<DerivationAttribute>,
}

/// Decoded claims of an attested CSR token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedCsr {
    pub csr_der: Vec<u8>,
    pub attributes: Vec<DerivationAttribute>,
}

/// Authenticate a keypair inventory token and decode its entries.
pub fn verify_inventory(token: &[u8], nonce: &[u8], rt_alias_cert: &[u8]) -> Result<Vec<KeyPair>> {
    let payload = verify_signed_eat(token, rt_alias_cert)?;
    decode_inventory(&payload, nonce)
}

/// Authenticate an attested CSR token and decode its CSR and attributes.
///
/// The PKCS#10 structure is parsed strictly, but its self-signature is not
/// checked: the COSE signature is what authenticates the CSR, and current
/// Caliptra firmware emits a placeholder self-signature.
pub fn verify_attested_csr(
    token: &[u8],
    nonce: &[u8],
    rt_alias_cert: &[u8],
) -> Result<AttestedCsr> {
    let payload = verify_signed_eat(token, rt_alias_cert)?;
    decode_attested_csr(&payload, nonce)
}

/// Verify a tagged CWT COSE_Sign1 with the RT alias key and return its payload.
///
/// The protected `kid` must equal the RT alias certificate's subject key
/// identifier, which is how Caliptra identifies the signing key.
fn verify_signed_eat(token: &[u8], rt_alias_cert: &[u8]) -> Result<Vec<u8>> {
    let cose = parse_cose_sign1(token)?;
    if !matches!(
        cose.protected.header.alg,
        Some(coset::RegisteredLabelWithPrivate::Assigned(
            Algorithm::ES384 | Algorithm::ESP384
        ))
    ) {
        bail!("unsupported COSE algorithm, expected ES384/ESP384");
    }
    // Unprotected headers are not covered by the signature; Caliptra sends none.
    if !cose.unprotected.is_empty() {
        bail!("COSE unprotected header must be empty");
    }

    let cert =
        Certificate::from_der(rt_alias_cert).context("failed to parse RT alias certificate")?;
    let (_, ski) = cert
        .tbs_certificate
        .get::<SubjectKeyIdentifier>()
        .context("failed to decode RT alias subject key identifier")?
        .ok_or_else(|| anyhow!("RT alias certificate has no subject key identifier"))?;
    let kid = &cose.protected.header.key_id;
    if kid.is_empty() {
        bail!("COSE protected header has no kid");
    }
    if kid.as_slice() != ski.0.as_bytes() {
        bail!("COSE kid does not identify the authenticated RT alias certificate");
    }

    let public_key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| anyhow!("RT alias certificate does not hold a P-384 key: {e:?}"))?;
    let signature = Signature::from_slice(&cose.signature)
        .map_err(|e| anyhow!("invalid COSE ECDSA signature encoding: {e:?}"))?;
    verifying_key
        .verify(&cose.tbs_data(&[]), &signature)
        .map_err(|_| anyhow!("COSE signature does not verify with the RT alias key"))?;

    cose.payload
        .ok_or_else(|| anyhow!("COSE_Sign1 has no payload"))
}

fn parse_cose_sign1(token: &[u8]) -> Result<CoseSign1> {
    let mut value = decode_cbor(token).context("signed EAT is not valid CBOR")?;
    if matches!(value, Value::Tag(CBOR_TAG_SELF_DESCRIBED, _)) {
        value = unwrap_cbor_tag(value, CBOR_TAG_SELF_DESCRIBED)?;
    }
    value = unwrap_cbor_tag(value, CBOR_TAG_CWT)?;
    value = unwrap_cbor_tag(value, CBOR_TAG_COSE_SIGN1)?;
    CoseSign1::from_cbor_value(value).map_err(|e| anyhow!("signed EAT is not a COSE_Sign1: {e}"))
}

fn unwrap_cbor_tag(value: Value, expected: u64) -> Result<Value> {
    match value {
        Value::Tag(tag, value) if tag == expected => Ok(*value),
        Value::Tag(tag, _) => bail!("expected CBOR tag {expected}, found {tag}"),
        _ => bail!("signed EAT is missing CBOR tag {expected}"),
    }
}

/// Decode exactly one CBOR item, rejecting trailing bytes.
fn decode_cbor(bytes: &[u8]) -> Result<Value> {
    let mut cursor = Cursor::new(bytes);
    let value = ciborium::from_reader(&mut cursor)?;
    if cursor.position() as usize != bytes.len() {
        bail!("trailing bytes after CBOR item");
    }
    Ok(value)
}

fn decode_inventory(payload: &[u8], nonce: &[u8]) -> Result<Vec<KeyPair>> {
    let mut claims = decode_claims(payload, nonce)?;
    if claims.contains_key(&OCP_CLAIM_CSR) || claims.contains_key(&OCP_CLAIM_KEY_ATTRIBUTES) {
        bail!("keypair inventory token carries attested CSR claims");
    }
    let Some(Value::Array(entries)) = claims.remove(&OCP_CLAIM_KEYPAIR_INVENTORY) else {
        bail!("token has no keypair inventory claim ({OCP_CLAIM_KEYPAIR_INVENTORY})");
    };
    if entries.is_empty() {
        bail!("keypair inventory is empty");
    }
    let key_pairs = entries
        .into_iter()
        .map(decode_inventory_entry)
        .collect::<Result<Vec<_>>>()?;
    let mut ids = BTreeSet::new();
    if let Some(dup) = key_pairs.iter().find(|kp| !ids.insert(kp.id)) {
        bail!("keypair inventory lists key pair {} more than once", dup.id);
    }
    Ok(key_pairs)
}

fn decode_inventory_entry(entry: Value) -> Result<KeyPair> {
    let Value::Array(items) = entry else {
        bail!("keypair inventory entry is not an array");
    };
    let [id, attributes]: [Value; 2] = items
        .try_into()
        .map_err(|_| anyhow!("keypair inventory entry must be [keypair-id, attributes]"))?;
    let id = match id {
        Value::Integer(id) => u8::try_from(id).ok().filter(|id| *id != 0),
        _ => None,
    }
    .ok_or_else(|| {
        anyhow!("keypair inventory entry has an invalid keypair-id (expected 1..=255)")
    })?;
    let attributes =
        decode_attributes(attributes).with_context(|| format!("key pair {id} attributes"))?;
    Ok(KeyPair { id, attributes })
}

fn decode_attested_csr(payload: &[u8], nonce: &[u8]) -> Result<AttestedCsr> {
    let mut claims = decode_claims(payload, nonce)?;
    if claims.contains_key(&OCP_CLAIM_KEYPAIR_INVENTORY) {
        bail!("attested CSR token carries a keypair inventory claim");
    }
    let Some(Value::Bytes(csr_der)) = claims.remove(&OCP_CLAIM_CSR) else {
        bail!("token has no CSR claim ({OCP_CLAIM_CSR})");
    };
    CertReq::from_der(&csr_der).context("attested CSR claim is not a DER PKCS#10 request")?;
    let attributes = claims
        .remove(&OCP_CLAIM_KEY_ATTRIBUTES)
        .ok_or_else(|| anyhow!("token has no key attributes claim ({OCP_CLAIM_KEY_ATTRIBUTES})"))
        .and_then(decode_attributes)?;
    Ok(AttestedCsr {
        csr_der,
        attributes,
    })
}

/// Decode the claims map and check the nonce claim against `nonce`.
fn decode_claims(payload: &[u8], nonce: &[u8]) -> Result<BTreeMap<i128, Value>> {
    let Value::Map(entries) = decode_cbor(payload).context("EAT payload is not valid CBOR")? else {
        bail!("EAT payload is not a claims map");
    };
    let mut claims =
        entries
            .into_iter()
            .try_fold(BTreeMap::new(), |mut claims, (key, value)| {
                let Value::Integer(key) = key else {
                    bail!("EAT claim key is not an integer");
                };
                let key = i128::from(key);
                if claims.insert(key, value).is_some() {
                    bail!("EAT claim {key} appears more than once");
                }
                Ok(claims)
            })?;
    match claims.remove(&EAT_CLAIM_NONCE) {
        Some(Value::Bytes(received)) if received == nonce => Ok(claims),
        Some(Value::Bytes(_)) => bail!("EAT nonce does not match the requested nonce"),
        Some(_) => bail!("EAT nonce claim is not a byte string"),
        None => bail!("EAT has no nonce claim"),
    }
}

/// Decode a key-attributes map (tagged OID -> bitfield). The OCP attribute is
/// required; vendor attributes are preserved.
fn decode_attributes(value: Value) -> Result<Vec<DerivationAttribute>> {
    let Value::Map(entries) = value else {
        bail!("key attributes are not a map");
    };
    let attributes = entries
        .into_iter()
        .map(|(key, value)| {
            let Value::Tag(CBOR_TAG_OID, oid) = key else {
                bail!("key attribute key is not a tagged OID (tag {CBOR_TAG_OID})");
            };
            let Value::Bytes(oid) = *oid else {
                bail!("tagged OID is not a byte string");
            };
            let oid = ObjectIdentifier::from_bytes(&oid)
                .map_err(|e| anyhow!("malformed key attribute OID: {e}"))?;
            let bitfield = match value {
                Value::Integer(bits) => u64::try_from(bits).ok(),
                _ => None,
            }
            .ok_or_else(|| anyhow!("key attribute {oid} bitfield is not an unsigned integer"))?;
            Ok(DerivationAttribute { oid, bitfield })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut oids = BTreeSet::new();
    if let Some(dup) = attributes.iter().find(|attr| !oids.insert(attr.oid)) {
        bail!("key attribute {} appears more than once", dup.oid);
    }
    if !attributes.iter().any(DerivationAttribute::is_ocp) {
        bail!("key attributes lack the OCP derivation attribute {OCP_KDA_OID}");
    }
    Ok(attributes)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
    use p384::ecdsa::signature::Signer;
    use p384::ecdsa::SigningKey;
    use sha2::{Digest, Sha256};
    use std::str::FromStr;
    use std::time::Duration;
    use x509_cert::builder::{Builder, CertificateBuilder, Profile, RequestBuilder};
    use x509_cert::der::asn1::OctetString;
    use x509_cert::der::Encode;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::Validity;

    const NONCE: [u8; 32] = [0x5a; 32];
    const UDS_FE: u64 = 0b11;
    const VENDOR_OID: &str = "1.3.6.1.4.1.99999.1";

    /// Test RT alias key and certificate carrying the Caliptra-style SKI.
    pub(crate) struct RtAlias {
        pub key: SigningKey,
        pub cert: Vec<u8>,
        pub kid: Vec<u8>,
    }

    impl RtAlias {
        pub(crate) fn new(seed: u8) -> Self {
            let key = SigningKey::from_bytes((&[seed; 48]).into()).unwrap();
            let point = key.verifying_key().to_encoded_point(false);
            let kid = Sha256::digest(point.as_bytes())[..20].to_vec();
            let name = Name::from_str("CN=Test RT Alias").unwrap();
            let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).unwrap();
            let mut builder = CertificateBuilder::new(
                Profile::Manual { issuer: None },
                SerialNumber::from(1u32),
                Validity::from_now(Duration::from_secs(3600)).unwrap(),
                name,
                spki,
                &key,
            )
            .unwrap();
            builder
                .add_extension(&SubjectKeyIdentifier(
                    OctetString::new(kid.clone()).unwrap(),
                ))
                .unwrap();
            let cert = builder
                .build::<p384::ecdsa::DerSignature>()
                .unwrap()
                .to_der()
                .unwrap();
            Self { key, cert, kid }
        }

        pub(crate) fn sign(&self, claims: Vec<(Value, Value)>) -> Vec<u8> {
            self.sign_with_kid(claims, &self.kid)
        }

        fn sign_with_kid(&self, claims: Vec<(Value, Value)>, kid: &[u8]) -> Vec<u8> {
            self.sign_with_headers(claims, kid, coset::Header::default())
        }

        fn sign_with_headers(
            &self,
            claims: Vec<(Value, Value)>,
            kid: &[u8],
            unprotected: coset::Header,
        ) -> Vec<u8> {
            let sign1 = CoseSign1Builder::new()
                .unprotected(unprotected)
                .protected(
                    HeaderBuilder::new()
                        .algorithm(Algorithm::ESP384)
                        .key_id(kid.to_vec())
                        .build(),
                )
                .payload(Value::Map(claims).to_vec().unwrap())
                .create_signature(&[], |data| {
                    let signature: Signature = self.key.sign(data);
                    signature.to_bytes().to_vec()
                })
                .build();
            let sign1 = Value::from_slice(&sign1.to_tagged_vec().unwrap()).unwrap();
            Value::Tag(CBOR_TAG_CWT, Box::new(sign1)).to_vec().unwrap()
        }
    }

    fn int(value: i128) -> Value {
        Value::Integer(value.try_into().unwrap())
    }

    fn attr(oid: &str, bits: u64) -> (Value, Value) {
        let oid = ObjectIdentifier::new_unwrap(oid);
        (
            Value::Tag(
                CBOR_TAG_OID,
                Box::new(Value::Bytes(oid.as_bytes().to_vec())),
            ),
            int(bits.into()),
        )
    }

    pub(crate) fn ocp_attrs(bits: u64) -> Value {
        Value::Map(vec![attr(&OCP_KDA_OID.to_string(), bits)])
    }

    fn entry(id: i128, attributes: Value) -> Value {
        Value::Array(vec![int(id), attributes])
    }

    pub(crate) fn nonce_claim(nonce: &[u8]) -> (Value, Value) {
        (int(EAT_CLAIM_NONCE), Value::Bytes(nonce.to_vec()))
    }

    pub(crate) fn inventory_claims(entries: Vec<Value>) -> Vec<(Value, Value)> {
        vec![
            nonce_claim(&NONCE),
            (int(OCP_CLAIM_KEYPAIR_INVENTORY), Value::Array(entries)),
        ]
    }

    pub(crate) fn csr_claims(csr: &[u8], attributes: Value) -> Vec<(Value, Value)> {
        vec![
            nonce_claim(&NONCE),
            (int(OCP_CLAIM_CSR), Value::Bytes(csr.to_vec())),
            (int(OCP_CLAIM_KEY_ATTRIBUTES), attributes),
        ]
    }

    pub(crate) fn caliptra_inventory() -> Vec<Value> {
        vec![
            entry(1, ocp_attrs(UDS_FE)),
            entry(2, ocp_attrs(UDS_FE | 1 << 4)),
            entry(3, ocp_attrs(UDS_FE | 1 << 4 | 1 << 5)),
        ]
    }

    pub(crate) fn test_csr() -> Vec<u8> {
        let key = SigningKey::from_bytes((&[0x07u8; 48]).into()).unwrap();
        RequestBuilder::new(Name::from_str("CN=Caliptra LDevID").unwrap(), &key)
            .unwrap()
            .build::<p384::ecdsa::DerSignature>()
            .unwrap()
            .to_der()
            .unwrap()
    }

    fn inventory_err(entries: Vec<Value>) -> String {
        let rt = RtAlias::new(9);
        let token = rt.sign(inventory_claims(entries));
        format!(
            "{:#}",
            verify_inventory(&token, &NONCE, &rt.cert).unwrap_err()
        )
    }

    #[test]
    fn accepts_caliptra_inventory() {
        let rt = RtAlias::new(9);
        let token = rt.sign(inventory_claims(caliptra_inventory()));
        let key_pairs = verify_inventory(&token, &NONCE, &rt.cert).unwrap();

        assert_eq!(
            key_pairs.iter().map(|kp| kp.id).collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert_eq!(
            key_pairs[2].attributes[0].components(),
            [
                "UDS",
                "field entropy",
                "first mutable code",
                "runtime firmware"
            ]
        );
    }

    #[test]
    fn preserves_vendor_attributes() {
        let attributes = Value::Map(vec![
            attr(&OCP_KDA_OID.to_string(), UDS_FE),
            attr(VENDOR_OID, 0x80),
        ]);
        let rt = RtAlias::new(9);
        let token = rt.sign(inventory_claims(vec![entry(1, attributes)]));
        let key_pairs = verify_inventory(&token, &NONCE, &rt.cert).unwrap();

        let vendor = &key_pairs[0].attributes[1];
        assert!(!vendor.is_ocp());
        assert_eq!(vendor.to_string(), format!("{VENDOR_OID} (vendor) = 0x80"));
    }

    #[test]
    fn rejects_bad_signature() {
        let rt = RtAlias::new(9);
        let mut token = rt.sign(inventory_claims(caliptra_inventory()));
        *token.last_mut().unwrap() ^= 1;
        let err = verify_inventory(&token, &NONCE, &rt.cert).unwrap_err();
        assert!(format!("{err:#}").contains("signature"), "{err}");
    }

    #[test]
    fn rejects_other_signer() {
        let rt = RtAlias::new(9);
        let other = RtAlias::new(10);
        let token = other.sign_with_kid(inventory_claims(caliptra_inventory()), &rt.kid);
        let err = verify_inventory(&token, &NONCE, &rt.cert).unwrap_err();
        assert!(format!("{err:#}").contains("signature"), "{err}");
    }

    #[test]
    fn rejects_kid_mismatch() {
        let rt = RtAlias::new(9);
        let token = rt.sign_with_kid(inventory_claims(caliptra_inventory()), &[0xaa; 20]);
        let err = verify_inventory(&token, &NONCE, &rt.cert).unwrap_err();
        assert!(format!("{err:#}").contains("kid"), "{err}");
    }

    #[test]
    fn rejects_unprotected_header() {
        let rt = RtAlias::new(9);
        let unprotected = HeaderBuilder::new().key_id(vec![0xaa; 20]).build();
        let token =
            rt.sign_with_headers(inventory_claims(caliptra_inventory()), &rt.kid, unprotected);
        let err = verify_inventory(&token, &NONCE, &rt.cert).unwrap_err();
        assert!(format!("{err:#}").contains("unprotected"), "{err}");
    }

    #[test]
    fn rejects_stale_nonce() {
        let rt = RtAlias::new(9);
        let token = rt.sign(inventory_claims(caliptra_inventory()));
        let err = verify_inventory(&token, &[0x11; 32], &rt.cert).unwrap_err();
        assert!(format!("{err:#}").contains("nonce"), "{err}");
    }

    #[test]
    fn rejects_duplicate_key_pair_ids() {
        let err = inventory_err(vec![entry(1, ocp_attrs(1)), entry(1, ocp_attrs(3))]);
        assert!(err.contains("more than once"), "{err}");
    }

    #[test]
    fn rejects_invalid_key_pair_id() {
        let err = inventory_err(vec![entry(0, ocp_attrs(1))]);
        assert!(err.contains("keypair-id"), "{err}");
    }

    #[test]
    fn rejects_missing_ocp_attribute() {
        let err = inventory_err(vec![entry(1, Value::Map(vec![attr(VENDOR_OID, 1)]))]);
        assert!(err.contains("OCP derivation attribute"), "{err}");
    }

    #[test]
    fn rejects_malformed_attribute_oid() {
        let bad_oid = (
            Value::Tag(CBOR_TAG_OID, Box::new(Value::Bytes(vec![0x2b, 0x86]))),
            int(1),
        );
        let err = inventory_err(vec![entry(1, Value::Map(vec![bad_oid]))]);
        assert!(err.contains("malformed"), "{err}");
    }

    #[test]
    fn rejects_untagged_attribute_oid() {
        let untagged = (Value::Bytes(OCP_KDA_OID.as_bytes().to_vec()), int(1));
        let err = inventory_err(vec![entry(1, Value::Map(vec![untagged]))]);
        assert!(err.contains("tagged OID"), "{err}");
    }

    #[test]
    fn rejects_csr_masquerading_as_inventory() {
        let rt = RtAlias::new(9);
        let token = rt.sign(csr_claims(&test_csr(), ocp_attrs(UDS_FE)));
        let err = verify_inventory(&token, &NONCE, &rt.cert).unwrap_err();
        assert!(format!("{err:#}").contains("attested CSR claims"), "{err}");
    }

    #[test]
    fn accepts_attested_csr_with_placeholder_self_signature() {
        let rt = RtAlias::new(9);
        let mut csr = test_csr();
        *csr.last_mut().unwrap() ^= 1;
        let token = rt.sign(csr_claims(&csr, ocp_attrs(UDS_FE)));
        let attested = verify_attested_csr(&token, &NONCE, &rt.cert).unwrap();

        assert_eq!(attested.csr_der, csr);
        assert_eq!(attested.attributes[0].bitfield, UDS_FE);
    }

    #[test]
    fn rejects_inventory_masquerading_as_csr() {
        let rt = RtAlias::new(9);
        let token = rt.sign(inventory_claims(caliptra_inventory()));
        let err = verify_attested_csr(&token, &NONCE, &rt.cert).unwrap_err();
        assert!(format!("{err:#}").contains("keypair inventory"), "{err}");
    }

    #[test]
    fn rejects_csr_without_attributes() {
        let rt = RtAlias::new(9);
        let mut claims = csr_claims(&test_csr(), ocp_attrs(UDS_FE));
        claims.pop();
        let token = rt.sign(claims);
        let err = verify_attested_csr(&token, &NONCE, &rt.cert).unwrap_err();
        assert!(format!("{err:#}").contains("key attributes"), "{err}");
    }

    #[test]
    fn rejects_raw_der_csr() {
        let rt = RtAlias::new(9);
        assert!(verify_attested_csr(&test_csr(), &NONCE, &rt.cert).is_err());
    }
}

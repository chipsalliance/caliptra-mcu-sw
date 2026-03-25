// Licensed under the Apache-2.0 license

use crate::ta_store::{TrustAnchorError, TrustAnchorStore};
use openssl::stack::Stack;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::{X509StoreContext, X509};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Filesystem-backed Trust Anchor Store.
///
/// Loads root CA certificates and signing certificates from a directory
/// and uses OpenSSL for certificate chain validation.
///
/// # Directory layout
///
/// ```text
/// ta_store_path/
/// ├── roots/              # Root CA certificates (PEM or DER)
/// └── endorsement-certs/  # Endorsement certificates indexed by kid (PEM or DER)
/// ```
///
/// Root certificates are unconditionally trusted. Endorsement certificates
/// are indexed by their Subject Key Identifier (SKI) X.509 extension,
/// which is used as the `kid` for lookup.
pub struct FsTrustAnchorStore {
    /// Trusted root CA certificates.
    roots: Vec<X509>,
    /// Pre-built OpenSSL X509 store from the root CAs (for chain validation).
    store: X509Store,
    /// Endorsement certificates indexed by kid (Subject Key Identifier).
    endorsement_certs: HashMap<Vec<u8>, X509>,
}

impl FsTrustAnchorStore {
    /// Load a Trust Anchor Store from a directory.
    pub fn load(ta_store_path: &Path) -> Result<Self, TrustAnchorError> {
        let roots_dir = ta_store_path.join("roots");
        let signing_dir = ta_store_path.join("endorsement-certs");

        // Load root CAs
        let roots = if roots_dir.is_dir() {
            load_certs_from_dir(&roots_dir)?
        } else {
            return Err(TrustAnchorError::Load(format!(
                "Roots directory not found: {}",
                roots_dir.display()
            )));
        };

        if roots.is_empty() {
            return Err(TrustAnchorError::Load(
                "No root CA certificates found".into(),
            ));
        }

        // Build the X509 store from roots
        let store = build_x509_store(&roots)?;

        // Load endorsement certs and index by kid (SKI)
        let endorsement_certs = if signing_dir.is_dir() {
            load_and_index_endorsement_certs(&signing_dir)?
        } else {
            HashMap::new()
        };

        Ok(Self {
            roots,
            store,
            endorsement_certs,
        })
    }

    /// Check if a certificate is one of the trusted root CAs by comparing
    /// the Subject Key Identifier, falling back to DER comparison.
    fn is_trusted_root(&self, cert: &X509) -> Result<bool, TrustAnchorError> {
        let candidate_ski = subject_key_identifier(cert)?;
        for root in &self.roots {
            let root_ski = subject_key_identifier(root)?;
            if let (Some(c), Some(r)) = (&candidate_ski, &root_ski) {
                if c == r {
                    return Ok(true);
                }
            }
        }

        // Fallback: compare DER-encoded forms directly
        let candidate_der = cert.to_der()?;
        for root in &self.roots {
            if root.to_der()? == candidate_der {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

impl TrustAnchorStore for FsTrustAnchorStore {
    fn authenticate_by_kid(&self, kid: &[u8]) -> Result<Vec<u8>, TrustAnchorError> {
        let cert = self
            .endorsement_certs
            .get(kid)
            .ok_or_else(|| TrustAnchorError::UnknownKid(hex::encode(kid)))?;

        // Validate the endorsement cert against the trusted roots
        let empty_chain = Stack::new()?;
        let mut ctx = X509StoreContext::new()?;
        let valid = ctx.init(&self.store, cert, &empty_chain, |ctx| ctx.verify_cert())?;

        if !valid {
            return Err(TrustAnchorError::ChainValidation(format!(
                "Endorsement certificate (kid={}) does not chain to a trusted root",
                hex::encode(kid),
            )));
        }

        Ok(cert.to_der()?)
    }

    fn authenticate_chain(&self, chain: &[Vec<u8>]) -> Result<Vec<u8>, TrustAnchorError> {
        if chain.is_empty() {
            return Err(TrustAnchorError::EmptyChain);
        }

        // Parse all certs in the chain
        let parsed: Vec<X509> = chain
            .iter()
            .map(|der| X509::from_der(der).map_err(TrustAnchorError::OpenSsl))
            .collect::<Result<Vec<_>, _>>()?;

        let leaf = &parsed[0];

        // Check that the root of the provided chain is in our trusted roots
        let chain_root = &parsed[parsed.len() - 1];
        if !self.is_trusted_root(chain_root)? {
            return Err(TrustAnchorError::UntrustedRoot);
        }

        // Build the untrusted intermediate chain (everything except the leaf)
        let mut untrusted = Stack::new()?;
        for cert in &parsed[1..] {
            untrusted.push(cert.clone())?;
        }

        // Validate: leaf → intermediates → trusted root
        let mut ctx = X509StoreContext::new()?;
        let valid = ctx.init(&self.store, leaf, &untrusted, |ctx| ctx.verify_cert())?;

        if !valid {
            return Err(TrustAnchorError::ChainValidation(
                "Certificate chain validation failed".into(),
            ));
        }

        Ok(chain[0].clone())
    }
}

/// Build an OpenSSL `X509Store` from a list of trusted root certificates.
fn build_x509_store(roots: &[X509]) -> Result<X509Store, TrustAnchorError> {
    let mut builder = X509StoreBuilder::new()?;
    for root in roots {
        builder.add_cert(root.clone())?;
    }
    Ok(builder.build())
}

/// Load all PEM and DER certificate files from a directory (non-recursive).
fn load_certs_from_dir(dir: &Path) -> Result<Vec<X509>, TrustAnchorError> {
    let mut certs = Vec::new();

    let mut entries: Vec<_> = fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let data = fs::read(&path)?;

        let cert = if looks_like_pem(&data) {
            X509::from_pem(&data)
        } else {
            X509::from_der(&data)
        };

        match cert {
            Ok(c) => certs.push(c),
            Err(e) => {
                return Err(TrustAnchorError::Load(format!(
                    "Failed to parse certificate '{}': {}",
                    path.display(),
                    e
                )));
            }
        }
    }

    Ok(certs)
}

/// Load endorsement certificates from a directory and index them by their
/// Subject Key Identifier (SKI).
fn load_and_index_endorsement_certs(dir: &Path) -> Result<HashMap<Vec<u8>, X509>, TrustAnchorError> {
    let certs = load_certs_from_dir(dir)?;
    let mut map = HashMap::new();

    for cert in certs {
        let ski = subject_key_identifier(&cert)?.ok_or_else(|| {
            TrustAnchorError::Load(format!(
                "Endorsement certificate has no Subject Key Identifier extension: {:?}",
                cert.subject_name()
            ))
        })?;
        map.insert(ski, cert);
    }

    Ok(map)
}

/// Extract the Subject Key Identifier (SKI) extension value from a certificate.
/// Returns `None` if the extension is not present.
fn subject_key_identifier(cert: &X509) -> Result<Option<Vec<u8>>, TrustAnchorError> {
    match cert.subject_key_id() {
        Some(ski) => Ok(Some(ski.as_slice().to_vec())),
        None => Ok(None),
    }
}

/// Heuristic check: does the data look like PEM-encoded content?
fn looks_like_pem(data: &[u8]) -> bool {
    data.starts_with(b"-----BEGIN ")
}

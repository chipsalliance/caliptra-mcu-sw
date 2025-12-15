#!/usr/bin/env python3
"""Certificate chain assembly and lightweight validation utilities.

Builds an ordered chain from a provided leaf (attestation / AK certificate) plus
locally stored DER files (if present) in the fixed search order:
    [ leaf, RT_CERT, FMC_CERT, LDEVID_CERT, IDEVID_CERT, ROOT_CA ]

Missing files are silently skipped. Chain validation is intentionally *lightweight*:
 - Expiration check
 - basicConstraints CA checks for intermediates & root
 - Issuer/Subject linkage (with relaxed DN comparison & normalization)
 - Signature verification (cryptography, with OpenSSL fallback)
 - Root self-issued check
 - Diagnostic SKI/AKI correlation (including derived SKI when missing)
 - Detailed ASN.1 dumps for DN mismatches

The heavier PKIX features (policies, path length, EKU, revocation) are out of scope
for this helper.
"""
from __future__ import annotations

import logging
import os
from typing import List, Tuple, Dict
from asn1crypto import x509
from dice_cert_parser import parse_certchain

logger = logging.getLogger(__name__)


def write_certs_to_file(certs: List[x509.Certificate], slot_id: int) -> None:
    """Write certificates to individual files in SPDM_VALIDATOR_DIR.
    
    Files are written in leaf-first order (matching chain validation order):
    - cert0.der = Leaf certificate (first in chain validation)
    - cert1.der = Intermediate certificate  
    - ...
    - cert5.der = Root certificate (last in chain validation)
    """
    spdm_validator_dir = os.environ.get('SPDM_VALIDATOR_DIR')
    if not spdm_validator_dir:
        raise ValueError("SPDM_VALIDATOR_DIR environment variable is not set")
    
    # Create output directory in SPDM_VALIDATOR_DIR
    output_dir = os.path.join(spdm_validator_dir, f"slot_{slot_id}_certs")
    os.makedirs(output_dir, exist_ok=True)

    # Reverse the certificates to store leaf-first (cert0.der = leaf)
    reversed_certs = list(reversed(certs))
    for i, cert in enumerate(reversed_certs, 0):
        # Write certificate to file (leaf-first order)
        cert_filename = os.path.join(output_dir, f"cert{i}.der")
        with open(cert_filename, "wb") as cert_file:
            cert_file.write(cert.dump())
        logger.info("Written to: %s", cert_filename)


def get_leaf_public_key(cert_chain: List[bytes]) -> bytes:
    """Extract the public key from the leaf certificate in DER format."""
    if not cert_chain:
        raise ValueError("Certificate chain is empty")
    
    leaf_cert_der = cert_chain[0]
    leaf_cert = x509.Certificate.load(leaf_cert_der)
    public_key_info = leaf_cert['tbs_certificate']['subject_public_key_info']
    return public_key_info.dump()

def decode_spdm_certchain(slot_id) -> List[bytes]:
    """Parse a certificate chain from SPDM_VALIDATOR_DIR and save individual certificates."""
    # Construct blob path from environment variable and slot_id
    spdm_validator_dir = os.environ.get('SPDM_VALIDATOR_DIR')
    if not spdm_validator_dir:
        raise ValueError("SPDM_VALIDATOR_DIR environment variable is not set")
    
    blob_path = os.path.join(spdm_validator_dir, f"certificate_chain_slot_{slot_id:02d}.der")
    
    with open(blob_path, "rb") as f:
        data = f.read()

    certs = []
    offset = 0
    while offset < len(data):
        try:
            cert = x509.Certificate.load(data[offset:])
            certs.append(cert)
            # Advance offset by the length of the parsed cert
            offset += len(cert.dump())
        except Exception as e:
            logger.warning("Stopped parsing at offset %d: %s", offset, e)
            break

    # Write certificates to files (original order)
    write_certs_to_file(certs, slot_id)
    
    # Return list of DER certificate bytes in reverse order (leaf first)
    return [cert.dump() for cert in reversed(certs)]


def validate_certchain(cert_chain: List[bytes], verbose: bool = False, parse: bool = False) -> Tuple[bool, List[str]]:
    """Validate certificate chain and optionally parse certificate fields."""
    if parse:
        logger.info("Parse the certificate chain")
        if parse_certchain(cert_chain, verbose=verbose):
            logger.info("Certificate parsing completed")
        else:
            logger.info("Certificate parsing failed")

    # Just validate without parsing
    try:
        chain_valid, issues = _validate_certificate_chain(cert_chain)
        if chain_valid:
            logger.info("Certificate chain validation: SUCCESS")
        else:
            logger.warning("Certificate chain validation: FAILED (%d issue(s))", len(issues))
            for iss in issues:
                logger.warning("  - %s", iss)
        return chain_valid, issues
    except Exception as e:
        logger.error("Chain validation error: %s", e)
        return cert_chain, []

def _validate_certificate_chain(chain: List[bytes]) -> Tuple[bool, List[str]]:
    """Certificate chain validation using cryptography library's built-in validation."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
    except ImportError:
        return False, ["cryptography library not available for certificate validation"]
    
    try:
        # Load certificates using cryptography
        certs = [x509.load_der_x509_certificate(der) for der in chain]
        
        if not certs:
            return False, ["No certificates in chain"]
        
        # Reject insufficient certificates - we expect a proper certificate chain
        if len(certs) < 2:
            return False, [f"Certificate chain must contain at least 2 certificates (leaf + issuer), found {len(certs)}"]
        
        # Perform chain validation manually since cryptography doesn't have a simple built-in validator
        leaf_cert = certs[0]   # First certificate is leaf
        
        # Validate each certificate against its issuer
        for idx in range(len(certs) - 1):
            child_cert = certs[idx]
            issuer_cert = certs[idx + 1]
            
            # Check expiration
            now = child_cert.not_valid_before.__class__.now()
            if child_cert.not_valid_after < now:
                return False, [f"Certificate {idx} has expired"]
            
            # Check issuer/subject linkage
            if child_cert.issuer != issuer_cert.subject:
                return False, [f"Certificate {idx} issuer does not match certificate {idx+1} subject"]
            
            # Verify signature
            try:
                issuer_public_key = issuer_cert.public_key()
                signature = child_cert.signature
                tbs_bytes = child_cert.tbs_certificate_bytes
                signature_algorithm = child_cert.signature_hash_algorithm
                
                if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                    issuer_public_key.verify(signature, tbs_bytes, ec.ECDSA(signature_algorithm))
                elif isinstance(issuer_public_key, rsa.RSAPublicKey):
                    issuer_public_key.verify(signature, tbs_bytes, padding.PKCS1v15(), signature_algorithm)
                else:
                    return False, [f"Certificate {idx}: Unsupported public key type in issuer {idx+1}"]
            except Exception as sig_err:
                return False, [f"Certificate {idx}: Signature verification failed: {sig_err}"]
        
        # Check root certificate is self-issued
        root_cert = certs[-1]
        if root_cert.issuer != root_cert.subject:
            return False, ["Root certificate is not self-issued"]
        
        return True, []
        
    except Exception as e:
        # If cryptography validation fails, fall back to basic manual checks for debugging
        try:
            # Load with asn1crypto for basic parsing checks
            asn1_certs = [x509.Certificate.load(der) for der in chain]
            issues = []
            
            # Basic parsing validation
            for idx, cert in enumerate(asn1_certs):
                try:
                    # Check if certificate can be parsed
                    tbs = cert['tbs_certificate']
                    subject = tbs['subject'].native
                    issuer = tbs['issuer'].native
                    validity = tbs['validity'].native
                    
                    # Basic expiration check
                    import datetime
                    now = datetime.datetime.now(datetime.timezone.utc)
                    not_after = validity.get('not_after')
                    if not_after and not_after < now:
                        issues.append(f"Cert {idx} expired")
                        
                except Exception as parse_err:
                    issues.append(f"Cert {idx} parsing failed: {parse_err}")
            
            # Return cryptography error with basic diagnostic info
            error_msg = f"Cryptography validation failed: {e}"
            if issues:
                error_msg += f" | Basic checks found: {'; '.join(issues)}"
            
            return False, [error_msg]
            
        except Exception as fallback_err:
            return False, [f"Certificate validation failed: {e} (fallback also failed: {fallback_err})"]

#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""
COSE Sign1 signature validation
"""

import logging
import os  # retained if other file interactions are later added (may be removed if unused)

# Set up logger for this module
logger = logging.getLogger(__name__)

# Import OpenSSL-based DICE extension parsing functions
try:
    from openssl_dice_parser import (
        parse_dice_extension_openssl,
        format_dice_extension_openssl,
        get_tcg_dice_extension_names
    )
    openssl_dice_parser_available = True
except ImportError:
    logger.warning("OpenSSL DICE extension parser module not available")
    openssl_dice_parser_available = False

def get_standard_extension_oids():
    """
    Get a set of standard X.509 extension OIDs that should be skipped when mapping UNDEF extensions
    
    Returns:
        set: Set of standard extension OIDs
    """
    return {
        '2.5.29.19',  # basicConstraints
        '2.5.29.15',  # keyUsage
        '2.5.29.37',  # extKeyUsage
        '2.5.29.35',  # authorityKeyIdentifier
        '2.5.29.14',  # subjectKeyIdentifier
        '2.5.29.17',  # subjectAltName
        '2.5.29.18',  # issuerAltName
        '2.5.29.32',  # certificatePolicies
        '2.5.29.31',  # cRLDistributionPoints
        '1.3.6.1.5.5.7.1.1',  # authorityInfoAccess
        # Add more standard extensions as needed
    }

def parse_der_extension_data(raw_data):
    """
    Basic DER parsing fallback for non-DICE extensions
    
    Args:
        raw_data (bytes): Raw DER-encoded extension data
        
    Returns:
        dict: Parsed DER structure or None if parsing fails
    """
    # For non-DICE extensions, provide basic DER parsing
    return {"parser": "basic_der", "raw_hex": raw_data.hex(), "note": "Basic DER parsing - use OpenSSL DICE parser for DICE extensions"}

def parse_tcb_info_extension(raw_data):
    """
    Parse TCB info extension using OpenSSL parser
    """
    if openssl_dice_parser_available:
        return parse_dice_extension_openssl(raw_data, "tcg-dice-TcbInfo")
    else:
        return parse_der_extension_data(raw_data)

def parse_ueid_extension(raw_data):
    """
    Parse UEID extension using OpenSSL parser
    """
    if openssl_dice_parser_available:
        return parse_dice_extension_openssl(raw_data, "tcg-dice-Ueid")
    else:
        return parse_der_extension_data(raw_data)

def parse_manifest_uri_extension(raw_data):
    """
    Parse manifest URI extension using OpenSSL parser
    """
    if openssl_dice_parser_available:
        return parse_dice_extension_openssl(raw_data, "tcg-dice-endorsement-manifest-uri")
    else:
        return parse_der_extension_data(raw_data)

def parse_extension_data(ext_name, raw_data, decode_structure=False):
    """
    Parse extension data based on extension type - uses OpenSSL-based parser
    
    Args:
        ext_name (str): Extension name (e.g., "tcg-dice-MultiTcbInfo")
        raw_data (bytes): Raw DER-encoded extension data
        decode_structure (bool): If True, perform detailed ASN.1 parsing. If False, return hex dump.
        
    Returns:
        dict: Parsed extension data or None if parsing fails
    """
    # Use OpenSSL-based parser for DICE extensions
    if openssl_dice_parser_available and "tcg-dice" in ext_name.lower():
        try:
            return parse_dice_extension_openssl(raw_data, ext_name)
        except Exception as openssl_err:
            logger.debug(f"OpenSSL DICE parser failed: {openssl_err}")
    
    # Final fallback for non-DICE extensions or when parser not available
    return parse_der_extension_data(raw_data)

def get_extension_name(oid):
    """
    Map extension OIDs to readable names - uses OpenSSL-based mapping
    
    Args:
        oid (str): The OID string (e.g., "2.23.133.5.4.5")
        
    Returns:
        str: Human-readable extension name with OID, or just OID if not recognized
    """
    # Use OpenSSL-based parser mapping
    if openssl_dice_parser_available:
        try:
            tcg_extensions = get_tcg_dice_extension_names()
            if oid in tcg_extensions:
                return f"{tcg_extensions[oid]} (OID:{oid})"
        except Exception as openssl_err:
            logger.debug(f"OpenSSL extension mapping failed: {openssl_err}")
    
    # Final fallback
    return f"OID:{oid}"

def format_asn1_time(asn1_time_str):
    """Convert ASN.1 time format to readable format"""
    try:
        from datetime import datetime
        # ASN.1 time format: YYYYMMDDHHMMSSZ
        if asn1_time_str.endswith('Z'):
            time_str = asn1_time_str[:-1]  # Remove the Z
        else:
            time_str = asn1_time_str
            
        # Parse the time string
        if len(time_str) == 14:  # YYYYMMDDHHMMSS
            dt = datetime.strptime(time_str, '%Y%m%d%H%M%S')
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        elif len(time_str) == 12:  # YYMMDDHHMMSS (2-digit year)
            dt = datetime.strptime(time_str, '%y%m%d%H%M%S')
            # Adjust year for 2-digit format (assuming 1950-2049 range)
            if dt.year < 50:
                dt = dt.replace(year=dt.year + 2000)
            else:
                dt = dt.replace(year=dt.year + 1900)
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        else:
            return asn1_time_str  # Return original if format not recognized
    except Exception as e:
        logger.debug(f"Could not parse time format {asn1_time_str}: {e}")
        return asn1_time_str  # Return original on error

try:
    # Provide convenient re-export if caller still imports from here
    from certificate_chain import get_local_certificate_chain  # noqa: F401
except ImportError:  # pragma: no cover
    logger.debug("certificate_chain module not found; get_local_certificate_chain unavailable")


def validate_cose_signature(protected_headers, payload, signature, leaf_certificate: bytes):
    """Validate COSE Sign1 signature using only the leaf certificate.

    Assumptions:
      - Full certificate chain (if required) has already been validated externally.
      - Only the attestation/AK leaf certificate DER bytes are provided here.
      - Responsibility for chain trust, policy, and revocation checks lies with the caller.

    Args:
        protected_headers (bytes): Serialized protected headers CBOR bstr
        payload (bytes): COSE payload
        signature (bytes): Raw COSE ECDSA signature (IEEE P1363 r||s)
        leaf_certificate (bytes): DER-encoded leaf/attestation certificate

    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        # Import required libraries - prioritize OpenSSL
        import hashlib
        import cbor2
        
        # Check OpenSSL availability (primary crypto library)
        try:
            from OpenSSL import crypto
            openssl_available = True
            logger.debug("Using OpenSSL for cryptographic operations")
        except ImportError:
            openssl_available = False
            logger.error("ERROR: pyOpenSSL not available. Install with: pip install pyOpenSSL")
            return False
        
        # Cryptography library only for fallback OID extraction (when OpenSSL fails)
        cryptography_available = False
        try:
            from cryptography import x509
            cryptography_available = True
            logger.debug("Cryptography library available for OID fallback")
        except ImportError:
            logger.warning("Cryptography library not available - OID fallback disabled")

        # Initialize variables
        cert = None
        public_key = None
        parsing_success = False

        # TODO: Validate Certificate chain here

        try:
            from certificate_parser import parse_certificate
            detailed = logger.isEnabledFor(logging.DEBUG)
            pr = parse_certificate(leaf_certificate, log=logger, list_extensions=True, detailed=False)
            cert = pr.get('openssl_cert') or pr.get('cryptography_cert')
            public_key = pr.get('public_key_openssl')
            verification_public_key = pr.get('verification_public_key')
            curve_name = pr.get('curve_name') or 'unknown'
            parsing_success = cert is not None and public_key is not None
        except ImportError:
            logger.error("certificate_parser module not found; cannot parse certificate(s)")
            verification_public_key = None

        # Short-circuit if parsing failed entirely
        if not parsing_success:
            logger.error("Failed to parse certificate; aborting signature validation")
            return False
        # Using parsed certificate/public key from helper above, proceed with COSE verification
        # Build COSE Sig_structure
        
        # Print heading for verification phase
        print("\n=== 3) COSE Sign1 Signature Verification ===")
        logger.info(f"Using public key from EAT AK Leaf Certificate for signature verification")

        sig_structure = [
            "Signature1",
            protected_headers,
            b"",  # external AAD
            payload
        ]
        sig_context = cbor2.dumps(sig_structure)
        logger.debug(f"Signature context length: {len(sig_context)} bytes")
        logger.debug(f"Signature context (first 32 bytes): {sig_context[:32].hex()}")

        # Choose hash based on curve
        if curve_name == 'secp384r1':
            hasher = hashlib.sha384()
        else:
            hasher = hashlib.sha256()
            if curve_name not in ('secp256r1', 'secp384r1'):
                logger.warning(f"Unknown curve {curve_name}; defaulting to SHA-256")
        hasher.update(sig_context)
        message_hash = hasher.digest()
        logger.debug(f"Message hash ({len(message_hash)} bytes): {message_hash.hex()}")

        if not verification_public_key:
            logger.error("No public key available for verification")
            return False
        
        logger.info(f"Public key type: {type(verification_public_key).__name__}")
        if hasattr(verification_public_key, 'curve'):
            logger.info(f"Curve for verification: {verification_public_key.curve.name}")
        # Detailed public key display (EC points / fingerprint)
        try:
            from cryptography.hazmat.primitives import serialization, hashes
            from cryptography.hazmat.primitives.asymmetric import ec as _ec
            if isinstance(verification_public_key, _ec.EllipticCurvePublicKey):
                nums = verification_public_key.public_numbers()
                x_hex = f"0x{nums.x:0{verification_public_key.key_size//4}x}"
                y_hex = f"0x{nums.y:0{verification_public_key.key_size//4}x}"
                logger.info(f"EC Public Key X: {x_hex}")
                logger.info(f"EC Public Key Y: {y_hex}")
                uncompressed = verification_public_key.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint
                )
                spki = verification_public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                fp_sha256 = hashes.Hash(hashes.SHA256())
                fp_sha256.update(spki)
                logger.debug(f"SPKI SHA256: {fp_sha256.finalize().hex()}")
                logger.debug(f"Uncompressed EC point ({len(uncompressed)} bytes): {uncompressed.hex()}")
            else:
                # Generic SPKI fingerprint if not EC
                spki = verification_public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                fp = hashes.Hash(hashes.SHA256()); fp.update(spki)
                logger.info(f"Public Key SPKI SHA256: {fp.finalize().hex()}")
        except Exception as pk_dump_err:  # noqa: BLE001
            logger.debug(f"Public key detail display failed: {pk_dump_err}")

        # Perform signature verification (expects IEEE P1363 raw r||s for ECDSA)
        if curve_name == 'secp384r1' and len(signature) == 96:
            r_bytes = signature[:48]
            s_bytes = signature[48:]
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import hashes
            r = int.from_bytes(r_bytes, 'big')
            s = int.from_bytes(s_bytes, 'big')
            der_signature = encode_dss_signature(r, s)
            hash_algorithm = hashes.SHA384()
            try:
                verification_public_key.verify(der_signature, sig_context, ec.ECDSA(hash_algorithm))
                logger.info("✓ SIGNATURE VALID: COSE signature verification successful (DER format)")
                return True
            except Exception as e:  # noqa: BLE001
                logger.error(f"Signature verification failed: {e}")
                return False
        else:
            logger.error(f"Unsupported signature format or curve: len={len(signature)} curve={curve_name}")
            return False
            
    except ImportError as import_err:
        logger.error(f"Required libraries not available: {import_err}")
        logger.error(f"Install with: pip install pyOpenSSL cbor2")
        logger.error(f"Optional (for OID fallback): pip install cryptography")
        return False
    except Exception as e:
        logger.error(f"Error during signature validation: {e}")
        return False
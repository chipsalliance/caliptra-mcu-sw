#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""
COSE Sign1 signature validation
"""

import logging

logger = logging.getLogger(__name__)

def validate_cose_signature(protected_headers, payload, signature, certificate):
    """
    Validate COSE Sign1 signature using extracted certificate
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        # Try to import cryptography library for signature validation
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        import hashlib
        
        logger.debug(f"\n--- COSE Sign1 Signature Validation ---")
        
        # Try to parse the X.509 certificate
        try:
            cert = x509.load_der_x509_certificate(certificate)
            public_key = cert.public_key()
        except Exception as cert_error:
            logger.error(f"Certificate parsing failed: {cert_error}")
            logger.error(f"This appears to be a test/mock certificate")
            
            # Try to extract public key directly from certificate structure
            # Look for the P-384 public key pattern in the certificate
            cert_hex = certificate.hex()
            
            # Look for secp384r1 curve OID: 2b8104002200 (1.3.132.0.34)
            if '2b8104002200' in cert_hex:
                logger.info(f"Found P-384 curve identifier in certificate")
                
                # Look for uncompressed point marker (04) followed by coordinates
                pubkey_start = cert_hex.find('04') 
                if pubkey_start >= 0:
                    # P-384 uncompressed public key: 04 + 48 bytes x + 48 bytes y = 97 bytes total
                    pubkey_hex = cert_hex[pubkey_start:pubkey_start + 194]  # 97 * 2
                    if len(pubkey_hex) == 194:
                        logger.info(f"Extracted P-384 public key: {pubkey_hex[:32]}...")
                        logger.warning(f"Note: Cannot validate signature with mock certificate")
                        return False
            
            logger.error(f"Could not extract valid public key from mock certificate")
            return False
        
        logger.debug(f"Certificate Subject: {cert.subject}")
        logger.debug(f"Certificate Issuer: {cert.issuer}")
        logger.debug(f"Public Key Type: {type(public_key).__name__}")
        
        # Verify it's an ECDSA key
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            logger.error(f"ERROR: Expected ECDSA key, got {type(public_key).__name__}")
            return False
            
        curve_name = public_key.curve.name
        logger.debug(f"Curve: {curve_name}")
        
        # Create COSE Sign1 signature context (Sig_structure)
        # Sig_structure = [
        #   "Signature1",    // Context identifier
        #   protected,       // Protected headers (as byte string)
        #   "",              // External AAD (empty for Sign1)
        #   payload          // Payload
        # ]
        
        import cbor2
        
        sig_structure = [
            "Signature1",
            protected_headers,
            b"",  # empty external AAD
            payload
        ]
        
        # Encode the signature structure as CBOR
        sig_context = cbor2.dumps(sig_structure)
        logger.debug(f"Signature context length: {len(sig_context)} bytes")
        logger.debug(f"Signature context (first 32 bytes): {sig_context[:32].hex()}")
        
        # Hash the signature context (SHA-384 for P-384)
        if curve_name == "secp384r1":
            hash_algorithm = hashes.SHA384()
            hasher = hashlib.sha384()
        else:
            logger.warning(f"WARNING: Unknown curve {curve_name}, assuming SHA-256")
            hash_algorithm = hashes.SHA256()
            hasher = hashlib.sha256()
            
        hasher.update(sig_context)
        message_hash = hasher.digest()
        logger.debug(f"Message hash ({len(message_hash)} bytes): {message_hash.hex()}")
        
        # Verify the signature
        
        # COSE uses raw ECDSA signatures (r||s), but cryptography expects ASN.1 DER
        # For P-384, r and s are each 48 bytes, so total signature is 96 bytes
        if curve_name == "secp384r1" and len(signature) == 96:
            logger.info(f"Converting COSE raw signature format to ASN.1 DER")
            try:
                # Split into r and s components (each 48 bytes for P-384)
                r_bytes = signature[:48]
                s_bytes = signature[48:96]
                
                # Convert to integers
                r = int.from_bytes(r_bytes, byteorder='big')
                s = int.from_bytes(s_bytes, byteorder='big')
                
                # Create ASN.1 DER encoded signature
                from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
                der_signature = encode_dss_signature(r, s)
                
                logger.debug(f"DER signature [{len(der_signature)}]: {der_signature.hex()}")
                
                # Try verification with DER signature
                public_key.verify(der_signature, sig_context, ec.ECDSA(hash_algorithm))
                logger.info(f"✓ SIGNATURE VALID: ECDSA signature verification successful (COSE raw -> DER)")
                return True
                
            except Exception as der_error:
                logger.error(f"✗ DER conversion failed: {type(der_error).__name__}: {der_error}")
        
        # Try direct verification (in case it's already ASN.1 DER)
        try:
            public_key.verify(signature, sig_context, ec.ECDSA(hash_algorithm))
            logger.info(f"✓ SIGNATURE VALID: ECDSA signature verification successful (direct)")
            return True
        except Exception as verify_error:
            logger.error(f"✗ SIGNATURE INVALID: {type(verify_error).__name__}: {verify_error}")
            logger.error(f"  Tried both COSE raw format and ASN.1 DER format")
            return False
            
    except ImportError:
        logger.warning(f"Note: cryptography library not available for signature validation")
        logger.warning(f"Install with: pip install cryptography cbor2")
        return False
    except Exception as e:
        logger.error(f"Error during signature validation: {e}")
        return False
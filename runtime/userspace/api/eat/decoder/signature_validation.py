#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""
COSE Sign1 signature validation
"""

import logging

# Set up logger for this module
logger = logging.getLogger(__name__)

# Import DICE extension parsing functions
try:
    from dice_extension_parser import (
        parse_dice_extension_data,
        map_oid_to_extension_name,
        is_dice_extension,
        get_tcg_dice_extension_names
    )
    dice_parser_available = True
except ImportError:
    logger.warning("DICE extension parser module not available")
    dice_parser_available = False

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
    Legacy wrapper for basic DER parsing - use dice_extension_parser module for DICE extensions
    
    Args:
        raw_data (bytes): Raw DER-encoded extension data
        
    Returns:
        dict: Parsed DER structure or None if parsing fails
    """
    # For non-DICE extensions, provide basic DER parsing
    return {"parser": "basic_der", "raw_hex": raw_data.hex(), "note": "Use dice_extension_parser module for DICE extensions"}

def parse_tcb_info_extension(raw_data):
    """
    Legacy wrapper - use dice_extension_parser.parse_dice_extension_data() instead
    """
    if dice_parser_available:
        return parse_dice_extension_data("tcg-dice-MultiTcbInfo", raw_data)
    else:
        return parse_der_extension_data(raw_data)

def parse_ueid_extension(raw_data):
    """
    Legacy wrapper - use dice_extension_parser.parse_dice_extension_data() instead
    """
    if dice_parser_available:
        return parse_dice_extension_data("tcg-dice-Ueid", raw_data)
    else:
        return parse_der_extension_data(raw_data)

def parse_manifest_uri_extension(raw_data):
    """
    Legacy wrapper - use dice_extension_parser.parse_dice_extension_data() instead
    """
    if dice_parser_available:
        return parse_dice_extension_data("tcg-dice-endorsement-manifest-uri", raw_data)
    else:
        return parse_der_extension_data(raw_data)

def parse_extension_data(ext_name, raw_data, decode_structure=False):
    """
    Parse extension data based on extension type - now uses dice_extension_parser module
    
    Args:
        ext_name (str): Extension name (e.g., "tcg-dice-MultiTcbInfo")
        raw_data (bytes): Raw DER-encoded extension data
        decode_structure (bool): If True, perform detailed ASN.1 parsing. If False, return hex dump.
        
    Returns:
        dict: Parsed extension data or None if parsing fails
    """
    if dice_parser_available and is_dice_extension(ext_name):
        return parse_dice_extension_data(ext_name, raw_data, decode_structure)
    else:
        # Fallback for non-DICE extensions or when parser not available
        return parse_der_extension_data(raw_data)

def get_extension_name(oid):
    """
    Map extension OIDs to readable names - now uses dice_extension_parser module
    
    Args:
        oid (str): The OID string (e.g., "2.23.133.5.4.5")
        
    Returns:
        str: Human-readable extension name with OID, or just OID if not recognized
    """
    if dice_parser_available:
        return map_oid_to_extension_name(oid)
    else:
        # Fallback mapping when parser not available
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

def validate_cose_signature(protected_headers, payload, signature, certificate):
    """
    Validate COSE Sign1 signature using extracted certificate
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        # Import required libraries
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        import hashlib
        import cbor2
        
        # Check OpenSSL availability
        try:
            from OpenSSL import crypto
            openssl_available = True
        except ImportError:
            openssl_available = False
            logger.warning("Note: pyOpenSSL not available. Install with: pip install pyOpenSSL")

        # Initialize variables
        cert = None
        public_key = None
        parsing_success = False

        # TODO: Validate Certificate chain here

        logger.info(f"\n=== 2) Parsing EAT AK Certificate ===")

        # METHOD 1: Try OpenSSL first (preferred method)
        if openssl_available:
            try:
                logger.debug(f"--- Primary method: OpenSSL Library ---")
                
                # Try multiple OpenSSL parsing approaches for critical extension issues
                openssl_cert = None
                openssl_public_key = None


                # Approach 1: Standard DER parsing
                try:
                    openssl_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate)
                    openssl_public_key = openssl_cert.get_pubkey()
                    logger.debug(f"✓ OpenSSL DER parsing successful")
                    
                except Exception as der_error:
                    logger.debug(f"OpenSSL DER parsing failed: {der_error}")

                    # Check if this is a critical extension parsing error
                    if "critical" in str(der_error).lower() or "extension" in str(der_error).lower():
                        logger.warning(f"🔧 Detected critical extension parsing issue")
                        logger.warning(f"   This may be due to non-standard extension encoding")

                        # Approach 2: Try PEM conversion as workaround
                        try:
                            import base64
                            logger.warning(f"🔧 Attempting PEM conversion workaround...")

                            # Convert DER to PEM format
                            pem_cert = b"-----BEGIN CERTIFICATE-----\n"
                            pem_cert += base64.b64encode(certificate)
                            pem_cert += b"\n-----END CERTIFICATE-----\n"
                            
                            openssl_cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)
                            openssl_public_key = openssl_cert.get_pubkey()
                            logger.debug(f"✓ OpenSSL PEM parsing successful (workaround)")
                            
                        except Exception as pem_error:
                            logger.error(f"OpenSSL PEM workaround also failed: {pem_error}")
                            raise der_error  # Re-raise original error
                    else:
                        raise der_error  # Re-raise if not extension related
                
                if openssl_cert and openssl_public_key:
                    logger.debug(f"✓ OpenSSL parsing successful")
                    # print("------------------------------")
                    logger.debug(f"Certificate Subject: {openssl_cert.get_subject()}")
                    logger.debug(f"Certificate Issuer: {openssl_cert.get_issuer()}")
                    logger.debug(f"Serial Number: {openssl_cert.get_serial_number()}")
                    logger.debug(f"Version: {openssl_cert.get_version()}")
                    logger.debug(f"Public Key Bits: {openssl_public_key.bits()}")
                    logger.debug(f"Public Key Type: {openssl_public_key.type()}")

                # Get certificate validity period
                not_before = openssl_cert.get_notBefore().decode('ascii')
                not_after = openssl_cert.get_notAfter().decode('ascii')
                
                # Convert to readable format
                not_before_readable = format_asn1_time(not_before)
                not_after_readable = format_asn1_time(not_after)
                
                print(f"Certificate Details:")
                
                logger.info(f"Not Before: {not_before_readable}")
                logger.info(f"Not After: {not_after_readable}")

                # # Also show raw format if different
                # if not_before_readable != not_before:
                #     logger.debug(f"Not Before (raw): {not_before}")
                # if not_after_readable != not_after:
                #     logger.debug(f"Not After (raw): {not_after}")

                # Check if certificate has expired
                if openssl_cert.has_expired():
                    logger.warning(f"⚠️  Certificate has expired")
                else:
                    logger.debug(f"Certificate is valid (not expired)")

                # Get signature algorithm
                sig_algo = openssl_cert.get_signature_algorithm().decode('ascii')
                logger.debug(f"Signature Algorithm: {sig_algo}")

                # Get subject components
                subject = openssl_cert.get_subject()
                for component in subject.get_components():
                    name, value = component
                    logger.info(f"Subject {name.decode('ascii')}: {value.decode('ascii')}")

                # Handle extensions safely to avoid critical extension parsing errors
                # print(f"\n--- Certificate Extensions ---")
                try:
                    ext_count = openssl_cert.get_extension_count()
                    logger.info(f"Number of extensions: {ext_count}")
                    
                    # Parse with cryptography library to get OIDs for UNDEF extensions
                    crypto_extension_oids = []
                    try:
                        from cryptography import x509
                        crypto_cert = x509.load_der_x509_certificate(certificate)
                        for crypto_ext in crypto_cert.extensions:
                            oid_str = crypto_ext.oid.dotted_string
                            crypto_extension_oids.append(oid_str)
                    except Exception as crypto_parse_err:
                        logger.debug(f"Could not parse extensions with cryptography library: {crypto_parse_err}")
                    
                    # Track which crypto OIDs we've used (to map UNDEF extensions)
                    undef_oid_index = 0
                    
                    for i in range(ext_count):
                        try:
                            ext = openssl_cert.get_extension(i)
                            
                            # Get extension name
                            try:
                                ext_name = ext.get_short_name().decode('ascii')
                                # If it's UNDEF, try to map to actual OID from cryptography library
                                if ext_name == "UNDEF" and undef_oid_index < len(crypto_extension_oids):
                                    # Find the next non-standard OID (skip common X.509 extensions)
                                    # Find the next non-standard OID (skip common X.509 extensions)
                                    standard_oids = get_standard_extension_oids()
                                    for oid in crypto_extension_oids[undef_oid_index:]:
                                        if oid not in standard_oids:
                                            ext_name = get_extension_name(oid)
                                            undef_oid_index = crypto_extension_oids.index(oid) + 1
                                            break
                            except:
                                ext_name = "UNKNOWN"
                            
                            # Handle critical extensions carefully - never fail here
                            try:
                                critical = ext.get_critical()
                                critical_str = "Critical" if critical else "Non-Critical"
                            except:
                                critical_str = "Unknown"
                            
                            # Check if this is a TCG DICE extension
                            if "tcg-dice" in ext_name.lower():
                                logger.info(f"\tTCG Extension {i}: {ext_name} ({critical_str})")
                            else:
                                logger.info(f"\tStandard Extension {i}: {ext_name} ({critical_str})")

                            # Method 1: Try to get extension data as string
                            parsed_successfully = False
                            try:
                                # For TCG DICE extensions, skip OpenSSL string parsing and go directly to DER
                                if "tcg-dice" in ext_name:
                                    logger.debug(f"  Parsing as TCG DICE extension...")
                                    try:
                                        raw_data = ext.get_data()
                                        # Set decode_structure=False to display hex bytes instead of complex parsing
                                        parsed_data = parse_extension_data(ext_name, raw_data, decode_structure=False)
                                        if parsed_data:
                                            logger.debug(f"  Structured Data:")
                                            for field, value in parsed_data.items():
                                                logger.debug(f"    {field}: {value}")
                                            parsed_successfully = True
                                        else:
                                            logger.debug(f"  Raw DER ({len(raw_data)} bytes): {raw_data.hex()}")
                                            parsed_successfully = True
                                    except Exception as parse_err:
                                        logger.debug(f"  TCG DICE parsing failed: {parse_err}")
                                        try:
                                            raw_data = ext.get_data()
                                            logger.debug(f"  Raw DER ({len(raw_data)} bytes): {raw_data.hex()}")
                                            parsed_successfully = True
                                        except:
                                            logger.debug(f"  Raw DER: [Could not access raw data]")
                                else:
                                    # For standard extensions, try OpenSSL string parsing first
                                    ext_data = str(ext)
                                    if len(ext_data) > 100:
                                        ext_data = ext_data[:100] + "..."
                                    logger.debug(f"  Parsed Data: {ext_data}")
                                    parsed_successfully = True
                                    
                                    # Only show raw data if parsing failed or for debugging unknown extensions
                                    if ext_name == "UNKNOWN":
                                        try:
                                            raw_data = ext.get_data()
                                            logger.debug(f"  Raw DER ({len(raw_data)} bytes): {raw_data.hex()}")
                                        except:
                                            logger.debug(f"  Raw DER: [Could not access raw data]")

                            except Exception as ext_data_err:
                                logger.debug(f"  Parsed Data: [Error: {str(ext_data_err) if str(ext_data_err) else 'Unknown parsing error'}]")
                                parsed_successfully = False
                                
                            # Always show raw data when parsing fails
                            if not parsed_successfully:
                                try:
                                    raw_data = ext.get_data()
                                    logger.debug(f"  Raw DER ({len(raw_data)} bytes): {raw_data.hex()}")
                                    
                                    # Try to decode the raw data for common extensions
                                    try:
                                        if ext_name == "basicConstraints":
                                            logger.debug(f"    -> Basic Constraints Extension")
                                            if len(raw_data) >= 2:
                                                # Parse basic constraints: SEQUENCE { BOOLEAN ca, INTEGER pathLenConstraint OPTIONAL }
                                                if raw_data[0] == 0x30:  # SEQUENCE
                                                    logger.debug(f"    -> DER Analysis: SEQUENCE of {raw_data[1]} bytes")
                                        elif ext_name == "subjectAltName":
                                            logger.debug(f"    -> Subject Alternative Name")
                                            # Parse SAN: SEQUENCE OF GeneralName
                                        elif ext_name == "keyUsage":
                                            logger.debug(f"    -> Key Usage Extension")
                                            if len(raw_data) >= 2 and raw_data[0] == 0x03:  # BIT STRING
                                                logger.debug(f"    -> BIT STRING of {raw_data[1]} bytes")
                                                if len(raw_data) >= 4:
                                                    # Key usage bits
                                                    unused_bits = raw_data[2]
                                                    key_usage_byte = raw_data[3] if len(raw_data) > 3 else 0
                                                    logger.debug(f"    -> Usage bits: 0x{key_usage_byte:02x} (unused: {unused_bits})")
                                                    
                                                    # Decode key usage flags
                                                    usage_flags = []
                                                    if key_usage_byte & 0x80: usage_flags.append("digitalSignature")
                                                    if key_usage_byte & 0x40: usage_flags.append("nonRepudiation")
                                                    if key_usage_byte & 0x20: usage_flags.append("keyEncipherment")
                                                    if key_usage_byte & 0x10: usage_flags.append("dataEncipherment")
                                                    if key_usage_byte & 0x08: usage_flags.append("keyAgreement")
                                                    if key_usage_byte & 0x04: usage_flags.append("keyCertSign")
                                                    if key_usage_byte & 0x02: usage_flags.append("cRLSign")
                                                    if key_usage_byte & 0x01: usage_flags.append("encipherOnly")
                                                    logger.debug(f"    -> Flags: {', '.join(usage_flags)}")
                                    except:
                                        # Never fail on raw data analysis
                                        pass
                                    
                                except:
                                    logger.debug(f"  Raw DER: [Could not access raw data]")
                                
                        except Exception as ext_err:
                            # Never fail on extension access - just show what we can
                            logger.debug(f"Extension {i}: [Error accessing extension: {ext_err}]")
                            
                except Exception as ext_access_err:
                    # Never fail on extension access errors - just log and continue
                    logger.error(f"Warning: Error accessing extensions: {ext_access_err}")
                    logger.error(f"This may be due to non-standard critical extension encoding")
                    logger.error(f"Continuing with certificate processing...")

                # Extract public key directly from OpenSSL certificate
                public_key = openssl_public_key
                cert = openssl_cert  # Keep OpenSSL certificate for signature validation
                
                parsing_success = True

            except Exception as openssl_error:
                logger.error(f"✗ OpenSSL parsing failed: {openssl_error}")
                parsing_success = False
        
        # METHOD 2: Fallback to Cryptography library if OpenSSL failed
        if not parsing_success:
            try:
                logger.debug(f"\nFallback method: CRYPTOGRAPHY library ===")
                
                # Load with cryptography library
                cert = x509.load_der_x509_certificate(certificate)
                public_key = cert.public_key()

                logger.debug(f"✓ Cryptography library parsing successful")
                logger.debug(f"Certificate Subject: {cert.subject}")
                logger.debug(f"Certificate Issuer: {cert.issuer}")
                logger.debug(f"Serial Number: {cert.serial_number}")
                logger.debug(f"Version: {cert.version}")
                logger.debug(f"Not Valid Before: {cert.not_valid_before}")
                logger.debug(f"Not Valid After: {cert.not_valid_after}")
                logger.debug(f"Signature Algorithm: {cert.signature_algorithm_oid._name}")
                logger.debug(f"Public Key Type: {type(public_key).__name__}")

                # Public key details
                if isinstance(public_key, ec.EllipticCurvePublicKey):
                    logger.debug(f"Curve: {public_key.curve.name}")
                    logger.debug(f"Key Size: {public_key.curve.key_size} bits")

                    # Get public key coordinates
                    public_numbers = public_key.public_numbers()
                    logger.debug(f"Public Key X: {hex(public_numbers.x)}")
                    logger.debug(f"Public Key Y: {hex(public_numbers.y)}")

                parsing_success = True
                logger.debug(f"✓ Certificate successfully parsed with Cryptography library")

            except Exception as crypto_error:
                logger.debug(f"✗ Cryptography library parsing also failed: {crypto_error}")
                parsing_success = False
        
        # If both methods failed, return False
        if not parsing_success:
            logger.debug(f"\n❌ Both OpenSSL and Cryptography library failed to parse certificate")
            return False

        # Continue with signature validation using the successfully parsed certificate
        logger.debug(f"Public Key Type: {type(public_key).__name__}")
        
        # Handle different public key types (OpenSSL vs Cryptography)
        curve_name = None
        
        # Check if we have an OpenSSL public key
        if hasattr(public_key, 'type') and hasattr(public_key, 'bits'):
            # OpenSSL public key
            logger.debug(f"Using OpenSSL public key")
            logger.debug(f"Key type: {public_key.type()}")
            logger.debug(f"Key bits: {public_key.bits()}")
            
            # For OpenSSL, we need to determine the curve based on key size
            key_bits = public_key.bits()
            if key_bits == 384:
                curve_name = "secp384r1"
                logger.debug(f"Detected curve: {curve_name} (P-384)")
            elif key_bits == 256:
                curve_name = "secp256r1"
                logger.debug(f"Detected curve: {curve_name} (P-256)")
            else:
                logger.debug(f"WARNING: Unknown key size {key_bits} bits, assuming P-384")
                curve_name = "secp384r1"
                
            # Create COSE Sign1 signature context (Sig_structure)
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

            # Hash the signature context
            if curve_name == "secp384r1":
                hasher = hashlib.sha384()
            else:
                hasher = hashlib.sha256()
                
            hasher.update(sig_context)
            message_hash = hasher.digest()
            logger.debug(f"Message hash ({len(message_hash)} bytes): {message_hash.hex()}")
            
            # Convert OpenSSL public key to cryptography format for COSE verification
            try:
                from OpenSSL import crypto
                from cryptography.hazmat.primitives import serialization
                
                # Get the public key in DER format from OpenSSL
                public_key_der = crypto.dump_publickey(crypto.FILETYPE_ASN1, openssl_public_key)
                logger.debug(f"Extracted public key DER ({len(public_key_der)} bytes)")
                
                # Load the DER public key into cryptography format
                crypto_public_key = serialization.load_der_public_key(public_key_der)
                logger.debug(f"Successfully converted OpenSSL public key to cryptography format")
                logger.debug(f"Cryptography public key type: {type(crypto_public_key).__name__}")
                
                # Verify it's an ECDSA key and get curve info
                if isinstance(crypto_public_key, ec.EllipticCurvePublicKey):
                    curve_name = crypto_public_key.curve.name
                    logger.debug(f"Converted curve: {curve_name}")
                    
                    # Get public key coordinates for verification
                    public_numbers = crypto_public_key.public_numbers()
                    logger.info(f"Public Key X: {hex(public_numbers.x)}")
                    logger.info(f"Public Key Y: {hex(public_numbers.y)}")
                    
                    # Now use the converted public key for COSE signature verification
                    public_key = crypto_public_key  # Use converted key
                    
                else:
                    logger.error(f"Converted key is not ECDSA: {type(crypto_public_key).__name__}")
                    return False
                    
            except Exception as conversion_err:
                logger.warning(f"Could not convert OpenSSL public key to cryptography format: {conversion_err}")
                logger.info(f"Falling back to direct cryptography certificate loading...")
                
                # Fallback: Load certificate directly with cryptography
                try:
                    crypto_cert = x509.load_der_x509_certificate(certificate)
                    crypto_public_key = crypto_cert.public_key()
                    
                    if isinstance(crypto_public_key, ec.EllipticCurvePublicKey):
                        curve_name = crypto_public_key.curve.name
                        logger.debug(f"Fallback - Curve: {curve_name}")
                        public_key = crypto_public_key
                    else:
                        logger.error(f"Not an ECDSA key in cryptography format")
                        return False
                        
                except Exception as crypto_fallback_err:
                    logger.error(f"Both OpenSSL conversion and cryptography fallback failed")
                    logger.error(f"Conversion error: {conversion_err}")
                    logger.error(f"Fallback error: {crypto_fallback_err}")
                    return False
            # print("------------------------------")
            logger.info(f"✓ Certificate successfully parsed and validated")
            
            # Now perform COSE signature verification with the converted/fallback public key
            print("\n=== 3) COSE Sign1 Signature Verification ===")
            logger.info(f"Using public key type: {type(public_key).__name__}")

            if isinstance(public_key, ec.EllipticCurvePublicKey):
                curve_name = public_key.curve.name
                logger.info(f"Curve for verification: {curve_name}")
                
                # Create COSE Sign1 signature context (Sig_structure)
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
                    logger.warning(f"Unknown curve {curve_name}, assuming SHA-256")
                    hash_algorithm = hashes.SHA256()
                    hasher = hashlib.sha256()
                    
                hasher.update(sig_context)
                message_hash = hasher.digest()
                logger.debug(f"Message hash ({len(message_hash)} bytes): {message_hash.hex()}")
                
                # Verify the signature
                try:
                    logger.info(f"Signature format analysis:")
                    logger.info(f"  Signature length: {len(signature)} bytes")
                    logger.info(f"  Expected length for P-384: 96 bytes (48+48)")
                    logger.debug(f"  Signature (hex): {signature.hex()}")

                    # For P-384, COSE uses IEEE P1363 format: r (48 bytes) || s (48 bytes)
                    if len(signature) == 96 and curve_name == "secp384r1":
                        r_bytes = signature[:48]
                        s_bytes = signature[48:]
                        logger.debug(f"  r component (48 bytes): {r_bytes.hex()}")
                        logger.debug(f"  s component (48 bytes): {s_bytes.hex()}")

                        # Try direct IEEE P1363 format first
                        try:
                            public_key.verify(signature, sig_context, ec.ECDSA(hash_algorithm))
                            logger.info(f"✓ SIGNATURE VALID: COSE signature verification successful (IEEE P1363 format)")
                            return True
                        except Exception as p1363_err:
                            # Try converting to DER format
                            try:
                                from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
                                
                                # Convert r and s to integers
                                r = int.from_bytes(r_bytes, 'big')
                                s = int.from_bytes(s_bytes, 'big')
                                # print(f"  r (int): {hex(r)}")
                                # print(f"  s (int): {hex(s)}")
                                
                                # Encode as DER
                                der_signature = encode_dss_signature(r, s)
                                logger.info(f"  DER signature ({len(der_signature)} bytes): {der_signature.hex()}")
                                
                                # Try verification with DER format
                                public_key.verify(der_signature, sig_context, ec.ECDSA(hash_algorithm))
                                logger.info(f"✓ SIGNATURE VALID: COSE signature verification successful (DER format)")
                                return True
                                
                            except Exception as der_err:
                                logger.error(f"DER format conversion/verification failed: {der_err}")
                    else:
                        # Try direct verification for other cases
                        public_key.verify(signature, sig_context, ec.ECDSA(hash_algorithm))
                        logger.info(f"✓ SIGNATURE VALID: COSE signature verification successful")
                        return True
                        
                except Exception as verify_error:
                    logger.error(f"✗ SIGNATURE INVALID: {verify_error}")

                    # Additional debugging: try verifying just the hash
                    try:
                        logger.info(f"\nTrying hash-only verification:")
                        # Some implementations sign the hash directly instead of the message
                        if len(signature) == 96 and curve_name == "secp384r1":
                            r_bytes = signature[:48]
                            s_bytes = signature[48:]
                            r = int.from_bytes(r_bytes, 'big')
                            s = int.from_bytes(s_bytes, 'big')
                            
                            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
                            der_signature = encode_dss_signature(r, s)
                            
                            # Try verifying the pre-computed hash
                            from cryptography.hazmat.primitives.asymmetric import ec
                            from cryptography.hazmat.primitives import hashes
                            public_key.verify(der_signature, message_hash, ec.ECDSA(ec.utils.Prehashed(hash_algorithm)))
                            logger.info(f"✓ SIGNATURE VALID: Hash-only verification successful")
                            return True
                    except Exception as hash_verify_err:
                        logger.error(f"Hash-only verification also failed: {hash_verify_err}")

                    return False
            else:
                logger.error(f"ERROR: Final public key is not ECDSA: {type(public_key).__name__}")
                return False
                
        elif hasattr(public_key, 'curve'):
            # Cryptography public key
            logger.info(f"Using Cryptography public key")
            
            # Verify it's an ECDSA key
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                logger.error(f"ERROR: Expected ECDSA key, got {type(public_key).__name__}")
                return False
                
            curve_name = public_key.curve.name
            logger.info(f"Curve: {curve_name}")

            # Create COSE Sign1 signature context (Sig_structure)
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
            try:
                public_key.verify(signature, sig_context, ec.ECDSA(hash_algorithm))
                logger.info(f"✓ SIGNATURE VALID: ECDSA signature verification successful")
                return True
            except Exception as verify_error:
                logger.error(f"✗ SIGNATURE INVALID: {verify_error}")
                return False
        else:
            logger.error(f"ERROR: Unknown public key type: {type(public_key)}")
            return False
            
    except ImportError:
        logger.error(f"Note: Required libraries not available for signature validation")
        logger.error(f"Install with: pip install cryptography pyOpenSSL cbor2")
        return False
    except Exception as e:
        logger.error(f"Error during signature validation: {e}")
        return False
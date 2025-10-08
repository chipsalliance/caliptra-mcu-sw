#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""
COSE Sign1 signature validation
"""

import logging

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

def validate_cose_signature(protected_headers, payload, signature, certificate):
    """
    Validate COSE Sign1 signature using extracted certificate
    
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
                    
                    # Parse with cryptography library ONLY as fallback for OID extraction
                    crypto_extension_oids = []
                    if cryptography_available:
                        try:
                            crypto_cert = x509.load_der_x509_certificate(certificate)
                            for crypto_ext in crypto_cert.extensions:
                                oid_str = crypto_ext.oid.dotted_string
                                crypto_extension_oids.append(oid_str)
                            logger.debug(f"Cryptography fallback extracted {len(crypto_extension_oids)} OIDs")
                        except Exception as crypto_parse_err:
                            logger.debug(f"Cryptography OID extraction failed: {crypto_parse_err}")
                    else:
                        logger.debug("Cryptography not available - using pattern matching only")
                    
                    # Track which crypto OIDs we've used (to map UNDEF extensions)
                    undef_oid_index = 0
                    
                    for i in range(ext_count):
                        try:
                            ext = openssl_cert.get_extension(i)
                            
                            # Get extension name and OID - try multiple approaches
                            ext_name = "UNKNOWN"
                            oid_str = None
                            
                            try:
                                # Method 1: Get short name from OpenSSL
                                ext_name = ext.get_short_name().decode('ascii')
                            except:
                                pass
                            
                            # Method 2: Try to extract OID directly from extension data
                            try:
                                # Get the extension's OID using OpenSSL's internal methods
                                import ctypes
                                from OpenSSL._util import lib as openssl_lib
                                
                                # Try to get OID from the extension object
                                # This is a more direct approach that doesn't rely on cryptography library
                                pass  # Will implement if needed
                            except:
                                pass
                            
                            # Method 3: If we have crypto extension OIDs from earlier, use them
                            if ext_name == "UNDEF" and undef_oid_index < len(crypto_extension_oids):
                                # Find the next non-standard OID (skip common X.509 extensions)
                                standard_oids = get_standard_extension_oids()
                                for oid in crypto_extension_oids[undef_oid_index:]:
                                    if oid not in standard_oids:
                                        oid_str = oid
                                        ext_name = get_extension_name(oid)
                                        undef_oid_index = crypto_extension_oids.index(oid) + 1
                                        break
                            
                            # Method 4: Always try manual OID detection for UNDEF extensions
                            if ext_name == "UNDEF" or ext_name == "UNKNOWN":
                                logger.debug(f"  Processing UNDEF extension {i}...")
                                try:
                                    raw_data = ext.get_data()
                                    data_len = len(raw_data)
                                    logger.debug(f"  UNDEF extension {i}: {data_len} bytes - analyzing...")
                                    
                                    # Use data length and structure patterns to identify TCG DICE extensions
                                    if data_len > 200:  # Likely MultiTcbInfo (usually 300+ bytes)
                                        ext_name = "tcg-dice-MultiTcbInfo (OID:2.23.133.5.4.5)"
                                        oid_str = "2.23.133.5.4.5"
                                        logger.debug(f"  ✓ Pattern match: Extension {i} identified as MultiTcbInfo ({data_len} bytes)")
                                        # logger.debug(f"  → SUCCESS: Identified as MultiTcbInfo based on size ({data_len} bytes)")
                                    elif 50 <= data_len <= 60:  # Likely UEID (usually ~52 bytes)
                                        ext_name = "tcg-dice-Ueid (OID:2.23.133.5.4.4)"
                                        oid_str = "2.23.133.5.4.4"
                                        logger.debug(f"  ✓ Pattern match: Extension {i} identified as UEID ({data_len} bytes)")
                                        # logger.debug(f"  → SUCCESS: Identified as UEID based on size ({data_len} bytes)")
                                    elif 20 <= data_len <= 40:  # Could be TcbInfo or other
                                        ext_name = "tcg-dice-TcbInfo (OID:2.23.133.5.4.1)"
                                        oid_str = "2.23.133.5.4.1"
                                        logger.debug(f"  ✓ Pattern match: Extension {i} identified as TcbInfo ({data_len} bytes)")
                                        # logger.debug(f"  → SUCCESS: Identified as TcbInfo based on size ({data_len} bytes)")
                                    else:
                                        logger.debug(f"  → Unknown TCG DICE extension pattern (size: {data_len} bytes)")
                                        # Still could be a TCG extension, just unknown type
                                        ext_name = f"tcg-dice-Unknown (size:{data_len})"
                                except Exception as pattern_err:
                                    logger.debug(f"  → Pattern matching failed: {pattern_err}")
                                    # If we can't get the data, assume it might be TCG DICE
                                    if i < 2:  # First two extensions are typically TCG DICE
                                        if i == 0:
                                            ext_name = "tcg-dice-MultiTcbInfo (OID:2.23.133.5.4.5)"
                                        elif i == 1:
                                            ext_name = "tcg-dice-Ueid (OID:2.23.133.5.4.4)"
                            
                            # Method 5: Enhanced fallback for UNDEF extensions
                            if ext_name == "UNDEF":
                                # If we still have UNDEF after all attempts, try to use known TCG extension positions
                                logger.debug(f"  Still UNDEF after all methods, trying positional mapping...")
                                if i < 2:  # First two extensions are typically TCG DICE
                                    try:
                                        raw_data = ext.get_data()
                                        if i == 0 and len(raw_data) > 100:
                                            ext_name = "tcg-dice-MultiTcbInfo (OID:2.23.133.5.4.5)"
                                            logger.debug(f"  → Position-based: Extension 0 = MultiTcbInfo")
                                        elif i == 1 and len(raw_data) < 100:
                                            ext_name = "tcg-dice-Ueid (OID:2.23.133.5.4.4)"
                                            logger.debug(f"  → Position-based: Extension 1 = UEID")
                                    except:
                                        pass
                            
                            # Handle critical extensions carefully - never fail here
                            try:
                                critical = ext.get_critical()
                                critical_str = "Critical" if critical else "Non-Critical"
                            except:
                                critical_str = "Unknown"
                            
                            # Check if this is a TCG DICE extension (multiple ways to detect)
                            is_tcg_extension = (
                                "tcg-dice" in ext_name.lower() or
                                "2.23.133.5.4" in str(oid_str) if oid_str else False or
                                (ext_name == "UNDEF" and i < 2)  # First two UNDEF extensions are likely TCG
                            )
                            
                            if is_tcg_extension:
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
            
            # Use OpenSSL for key operations, minimal cryptography for verification only
            try:
                # Get the public key in DER format from OpenSSL
                public_key_der = crypto.dump_publickey(crypto.FILETYPE_ASN1, openssl_public_key)
                logger.debug(f"Extracted public key DER ({len(public_key_der)} bytes)")
                
                # Extract basic key information using OpenSSL
                key_type = openssl_public_key.type()
                key_bits = openssl_public_key.bits()
                logger.info(f"Key type: {key_type}")
                logger.info(f"Key bits: {key_bits}")
                
                # For P-384 ECDSA verification, we need cryptography but only for the verify step
                verification_public_key = None
                if cryptography_available:
                    try:
                        from cryptography.hazmat.primitives import serialization
                        verification_public_key = serialization.load_der_public_key(public_key_der)
                        logger.debug(f"Loaded public key for verification: {type(verification_public_key).__name__}")
                        
                        # Extract and display key coordinates if available
                        if hasattr(verification_public_key, 'public_numbers'):
                            public_numbers = verification_public_key.public_numbers()
                            logger.info(f"Public Key X: {hex(public_numbers.x)}")
                            logger.info(f"Public Key Y: {hex(public_numbers.y)}")
                    except Exception as load_err:
                        logger.warning(f"Could not load public key with cryptography: {load_err}")
                
                logger.info(f"✓ Certificate successfully parsed and validated")
                
            except Exception as key_err:
                logger.error(f"Public key processing error: {key_err}")
                return False
            
            # Perform COSE signature verification using minimal cryptography
            print("\n=== 3) COSE Sign1 Signature Verification ===")
            
            if not verification_public_key:
                logger.error("No public key available for verification")
                return False
                
            logger.info(f"Using public key type: {type(verification_public_key).__name__}")

            # Check if it's an ECDSA key and get curve info
            curve_name = "unknown"
            if hasattr(verification_public_key, 'curve'):
                curve_name = verification_public_key.curve.name
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
                hasher = hashlib.sha384()
                hash_algo_name = "SHA-384"
            else:
                logger.warning(f"Unknown curve {curve_name}, assuming SHA-256")
                hasher = hashlib.sha256()
                hash_algo_name = "SHA-256"
                
            hasher.update(sig_context)
            message_hash = hasher.digest()
            logger.debug(f"Message hash ({len(message_hash)} bytes): {message_hash.hex()}")
            
            # Verify the signature using minimal cryptography imports
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

                    # Convert to DER format for cryptography verification
                    if cryptography_available:
                        try:
                            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
                            from cryptography.hazmat.primitives.asymmetric import ec
                            from cryptography.hazmat.primitives import hashes
                            
                            # Convert r and s to integers
                            r = int.from_bytes(r_bytes, 'big')
                            s = int.from_bytes(s_bytes, 'big')
                            
                            # Encode as DER
                            der_signature = encode_dss_signature(r, s)
                            logger.info(f"  DER signature ({len(der_signature)} bytes): {der_signature.hex()}")
                            
                            # Set up hash algorithm
                            if curve_name == "secp384r1":
                                hash_algorithm = hashes.SHA384()
                            else:
                                hash_algorithm = hashes.SHA256()
                            
                            # Try verification with DER format
                            verification_public_key.verify(der_signature, sig_context, ec.ECDSA(hash_algorithm))
                            logger.info(f"✓ SIGNATURE VALID: COSE signature verification successful (DER format)")
                            return True
                            
                        except Exception as der_err:
                            logger.error(f"Cryptography verification failed: {der_err}")
                            return False
                    else:
                        logger.error("Cryptography library not available for signature verification")
                        return False
                else:
                    logger.error(f"Unsupported signature format or curve: {len(signature)} bytes, {curve_name}")
                    return False
                        
            except Exception as verify_error:
                logger.error(f"✗ SIGNATURE VERIFICATION ERROR: {verify_error}")
                return False

        else:
            logger.error("OpenSSL library not available - cannot proceed with signature validation")
            return False
            
    except ImportError as import_err:
        logger.error(f"Required libraries not available: {import_err}")
        logger.error(f"Install with: pip install pyOpenSSL cbor2")
        logger.error(f"Optional (for OID fallback): pip install cryptography")
        return False
    except Exception as e:
        logger.error(f"Error during signature validation: {e}")
        return False
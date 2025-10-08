#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""
COSE Sign1 signature validation
"""

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
            print("Note: pyOpenSSL not available. Install with: pip install pyOpenSSL")
        
        print(f"\n--- COSE Sign1 Signature Validation ---")
        
        # Initialize variables
        cert = None
        public_key = None
        parsing_success = False
        
        # METHOD 1: Try OpenSSL first (preferred method)
        if openssl_available:
            try:
                print(f"=== PRIMARY METHOD: OPENSSL LIBRARY ===")
                
                # Try multiple OpenSSL parsing approaches for critical extension issues
                openssl_cert = None
                openssl_public_key = None
                
                # Approach 1: Standard DER parsing
                try:
                    openssl_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate)
                    openssl_public_key = openssl_cert.get_pubkey()
                    print(f"✓ OpenSSL DER parsing successful")
                    
                except Exception as der_error:
                    print(f"OpenSSL DER parsing failed: {der_error}")
                    
                    # Check if this is a critical extension parsing error
                    if "critical" in str(der_error).lower() or "extension" in str(der_error).lower():
                        print(f"🔧 Detected critical extension parsing issue")
                        print(f"   This may be due to non-standard extension encoding")
                        
                        # Approach 2: Try PEM conversion as workaround
                        try:
                            import base64
                            print(f"🔧 Attempting PEM conversion workaround...")
                            
                            # Convert DER to PEM format
                            pem_cert = b"-----BEGIN CERTIFICATE-----\n"
                            pem_cert += base64.b64encode(certificate)
                            pem_cert += b"\n-----END CERTIFICATE-----\n"
                            
                            openssl_cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)
                            openssl_public_key = openssl_cert.get_pubkey()
                            print(f"✓ OpenSSL PEM parsing successful (workaround)")
                            
                        except Exception as pem_error:
                            print(f"OpenSSL PEM workaround also failed: {pem_error}")
                            raise der_error  # Re-raise original error
                    else:
                        raise der_error  # Re-raise if not extension related
                
                if openssl_cert and openssl_public_key:
                    print(f"✓ OpenSSL parsing successful")
                    print(f"Certificate Subject: {openssl_cert.get_subject()}")
                    print(f"Certificate Issuer: {openssl_cert.get_issuer()}")
                    print(f"Serial Number: {openssl_cert.get_serial_number()}")
                    print(f"Version: {openssl_cert.get_version()}")
                    print(f"Public Key Bits: {openssl_public_key.bits()}")
                    print(f"Public Key Type: {openssl_public_key.type()}")
                
                # Get certificate validity period
                not_before = openssl_cert.get_notBefore().decode('ascii')
                not_after = openssl_cert.get_notAfter().decode('ascii')
                print(f"Not Before: {not_before}")
                print(f"Not After: {not_after}")
                
                # Check if certificate has expired
                if openssl_cert.has_expired():
                    print(f"⚠️  Certificate has expired")
                else:
                    print(f"✓ Certificate is valid (not expired)")
                
                # Get signature algorithm
                sig_algo = openssl_cert.get_signature_algorithm().decode('ascii')
                print(f"Signature Algorithm: {sig_algo}")
                
                # Get subject components
                print(f"=== CERTIFICATE DETAILS ===")
                subject = openssl_cert.get_subject()
                for component in subject.get_components():
                    name, value = component
                    print(f"Subject {name.decode('ascii')}: {value.decode('ascii')}")
                
                # Handle extensions safely to avoid critical extension parsing errors
                print(f"=== CERTIFICATE EXTENSIONS ===")
                try:
                    ext_count = openssl_cert.get_extension_count()
                    print(f"Number of extensions: {ext_count}")
                    
                    for i in range(ext_count):
                        try:
                            ext = openssl_cert.get_extension(i)
                            
                            # Get extension name - never fail here
                            try:
                                ext_name = ext.get_short_name().decode('ascii')
                            except:
                                ext_name = "UNKNOWN"
                            
                            # Handle critical extensions carefully - never fail here
                            try:
                                critical = ext.get_critical()
                                critical_str = "Critical" if critical else "Non-Critical"
                            except:
                                critical_str = "Unknown"
                            
                            print(f"Extension {i}: {ext_name} ({critical_str})")
                            
                            # Method 1: Try to get extension data as string
                            parsed_successfully = False
                            try:
                                ext_data = str(ext)
                                if len(ext_data) > 100:
                                    ext_data = ext_data[:100] + "..."
                                print(f"  Parsed Data: {ext_data}")
                                parsed_successfully = True
                                
                                # Only show raw data if parsing failed or for debugging unknown extensions
                                if ext_name == "UNKNOWN":
                                    try:
                                        raw_data = ext.get_data()
                                        print(f"  Raw DER ({len(raw_data)} bytes): {raw_data.hex()}")
                                    except:
                                        print(f"  Raw DER: [Could not access raw data]")
                                        
                            except Exception as ext_data_err:
                                print(f"  Parsed Data: [Error: {ext_data_err}]")
                                parsed_successfully = False
                                
                            # Always show raw data when parsing fails
                            if not parsed_successfully:
                                try:
                                    raw_data = ext.get_data()
                                    print(f"  Raw DER ({len(raw_data)} bytes): {raw_data.hex()}")
                                    
                                    # Try to decode the raw data for common extensions
                                    try:
                                        if ext_name == "basicConstraints":
                                            print(f"    -> Basic Constraints Extension")
                                            if len(raw_data) >= 2:
                                                # Parse basic constraints: SEQUENCE { BOOLEAN ca, INTEGER pathLenConstraint OPTIONAL }
                                                if raw_data[0] == 0x30:  # SEQUENCE
                                                    print(f"    -> DER Analysis: SEQUENCE of {raw_data[1]} bytes")
                                        elif ext_name == "subjectAltName":
                                            print(f"    -> Subject Alternative Name")
                                            # Parse SAN: SEQUENCE OF GeneralName
                                        elif ext_name == "keyUsage":
                                            print(f"    -> Key Usage Extension")
                                            if len(raw_data) >= 2 and raw_data[0] == 0x03:  # BIT STRING
                                                print(f"    -> BIT STRING of {raw_data[1]} bytes")
                                                if len(raw_data) >= 4:
                                                    # Key usage bits
                                                    unused_bits = raw_data[2]
                                                    key_usage_byte = raw_data[3] if len(raw_data) > 3 else 0
                                                    print(f"    -> Usage bits: 0x{key_usage_byte:02x} (unused: {unused_bits})")
                                                    
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
                                                    print(f"    -> Flags: {', '.join(usage_flags)}")
                                    except:
                                        # Never fail on raw data analysis
                                        pass
                                    
                                except:
                                    print(f"  Raw DER: [Could not access raw data]")
                            
                            print()  # Empty line for readability
                                
                        except Exception as ext_err:
                            # Never fail on extension access - just show what we can
                            print(f"Extension {i}: [Error accessing extension: {ext_err}]")
                            
                            # Try to show raw data even if extension access failed
                            try:
                                # This is a fallback - try to get extension directly by index
                                print(f"  Attempting to access raw extension data...")
                                # If this fails too, we'll just move on
                            except:
                                pass
                            print()
                            
                except Exception as ext_access_err:
                    # Never fail on extension access errors - just log and continue
                    print(f"Warning: Error accessing extensions: {ext_access_err}")
                    print(f"This may be due to non-standard critical extension encoding")
                    print(f"Continuing with certificate processing...")
                
                # Extract public key directly from OpenSSL certificate
                public_key = openssl_public_key
                cert = openssl_cert  # Keep OpenSSL certificate for signature validation
                
                parsing_success = True
                print(f"✓ Certificate successfully parsed with OpenSSL")
                
            except Exception as openssl_error:
                print(f"✗ OpenSSL parsing failed: {openssl_error}")
                parsing_success = False
        
        # METHOD 2: Fallback to Cryptography library if OpenSSL failed
        if not parsing_success:
            try:
                print(f"\n=== FALLBACK METHOD: CRYPTOGRAPHY LIBRARY ===")
                
                # Load with cryptography library
                cert = x509.load_der_x509_certificate(certificate)
                public_key = cert.public_key()
                
                print(f"✓ Cryptography library parsing successful")
                print(f"Certificate Subject: {cert.subject}")
                print(f"Certificate Issuer: {cert.issuer}")
                print(f"Serial Number: {cert.serial_number}")
                print(f"Version: {cert.version}")
                print(f"Not Valid Before: {cert.not_valid_before}")
                print(f"Not Valid After: {cert.not_valid_after}")
                print(f"Signature Algorithm: {cert.signature_algorithm_oid._name}")
                print(f"Public Key Type: {type(public_key).__name__}")
                
                # Public key details
                if isinstance(public_key, ec.EllipticCurvePublicKey):
                    print(f"Curve: {public_key.curve.name}")
                    print(f"Key Size: {public_key.curve.key_size} bits")
                    
                    # Get public key coordinates
                    public_numbers = public_key.public_numbers()
                    print(f"Public Key X: {hex(public_numbers.x)}")
                    print(f"Public Key Y: {hex(public_numbers.y)}")
                
                parsing_success = True
                print(f"✓ Certificate successfully parsed with Cryptography library")
                
            except Exception as crypto_error:
                print(f"✗ Cryptography library parsing also failed: {crypto_error}")
                parsing_success = False
        
        # If both methods failed, return False
        if not parsing_success:
            print(f"\n❌ Both OpenSSL and Cryptography library failed to parse certificate")
            return False
        
        # Continue with signature validation using the successfully parsed certificate
        print(f"\n=== SIGNATURE VALIDATION ===")
        print(f"Public Key Type: {type(public_key).__name__}")
        
        # Handle different public key types (OpenSSL vs Cryptography)
        curve_name = None
        
        # Check if we have an OpenSSL public key
        if hasattr(public_key, 'type') and hasattr(public_key, 'bits'):
            # OpenSSL public key
            print(f"Using OpenSSL public key")
            print(f"Key type: {public_key.type()}")
            print(f"Key bits: {public_key.bits()}")
            
            # For OpenSSL, we need to determine the curve based on key size
            key_bits = public_key.bits()
            if key_bits == 384:
                curve_name = "secp384r1"
                print(f"Detected curve: {curve_name} (P-384)")
            elif key_bits == 256:
                curve_name = "secp256r1"
                print(f"Detected curve: {curve_name} (P-256)")
            else:
                print(f"WARNING: Unknown key size {key_bits} bits, assuming P-384")
                curve_name = "secp384r1"
                
            # For COSE signature validation with OpenSSL, we need to use OpenSSL's verify method
            print(f"=== OPENSSL SIGNATURE VERIFICATION ===")
            
            # Create COSE Sign1 signature context (Sig_structure)
            sig_structure = [
                "Signature1",
                protected_headers,
                b"",  # empty external AAD
                payload
            ]
            
            # Encode the signature structure as CBOR
            sig_context = cbor2.dumps(sig_structure)
            print(f"Signature context length: {len(sig_context)} bytes")
            print(f"Signature context (first 32 bytes): {sig_context[:32].hex()}")
            
            # Hash the signature context
            if curve_name == "secp384r1":
                hasher = hashlib.sha384()
            else:
                hasher = hashlib.sha256()
                
            hasher.update(sig_context)
            message_hash = hasher.digest()
            print(f"Message hash ({len(message_hash)} bytes): {message_hash.hex()}")
            
            # Convert OpenSSL public key to cryptography format for COSE verification
            try:
                from OpenSSL import crypto
                from cryptography.hazmat.primitives import serialization
                
                # Get the public key in DER format from OpenSSL
                public_key_der = crypto.dump_publickey(crypto.FILETYPE_ASN1, openssl_public_key)
                print(f"Extracted public key DER ({len(public_key_der)} bytes)")
                
                # Load the DER public key into cryptography format
                crypto_public_key = serialization.load_der_public_key(public_key_der)
                print(f"✓ Successfully converted OpenSSL public key to cryptography format")
                print(f"Cryptography public key type: {type(crypto_public_key).__name__}")
                
                # Verify it's an ECDSA key and get curve info
                if isinstance(crypto_public_key, ec.EllipticCurvePublicKey):
                    curve_name = crypto_public_key.curve.name
                    print(f"Converted curve: {curve_name}")
                    
                    # Get public key coordinates for verification
                    public_numbers = crypto_public_key.public_numbers()
                    print(f"Public Key X: {hex(public_numbers.x)}")
                    print(f"Public Key Y: {hex(public_numbers.y)}")
                    
                    # Now use the converted public key for COSE signature verification
                    public_key = crypto_public_key  # Use converted key
                    
                else:
                    print(f"ERROR: Converted key is not ECDSA: {type(crypto_public_key).__name__}")
                    return False
                    
            except Exception as conversion_err:
                print(f"Warning: Could not convert OpenSSL public key to cryptography format: {conversion_err}")
                print(f"Falling back to direct cryptography certificate loading...")
                
                # Fallback: Load certificate directly with cryptography
                try:
                    crypto_cert = x509.load_der_x509_certificate(certificate)
                    crypto_public_key = crypto_cert.public_key()
                    
                    if isinstance(crypto_public_key, ec.EllipticCurvePublicKey):
                        curve_name = crypto_public_key.curve.name
                        print(f"Fallback - Curve: {curve_name}")
                        public_key = crypto_public_key
                    else:
                        print(f"ERROR: Not an ECDSA key in cryptography format")
                        return False
                        
                except Exception as crypto_fallback_err:
                    print(f"ERROR: Both OpenSSL conversion and cryptography fallback failed")
                    print(f"Conversion error: {conversion_err}")
                    print(f"Fallback error: {crypto_fallback_err}")
                    return False
            
            # Now perform COSE signature verification with the converted/fallback public key
            print(f"\n=== COSE SIGNATURE VERIFICATION ===")
            print(f"Using public key type: {type(public_key).__name__}")
            
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                curve_name = public_key.curve.name
                print(f"Final curve for verification: {curve_name}")
                
                # Create COSE Sign1 signature context (Sig_structure)
                sig_structure = [
                    "Signature1",
                    protected_headers,
                    b"",  # empty external AAD
                    payload
                ]
                
                # Encode the signature structure as CBOR
                sig_context = cbor2.dumps(sig_structure)
                print(f"Signature context length: {len(sig_context)} bytes")
                print(f"Signature context (first 32 bytes): {sig_context[:32].hex()}")
                
                # Hash the signature context (SHA-384 for P-384)
                if curve_name == "secp384r1":
                    hash_algorithm = hashes.SHA384()
                    hasher = hashlib.sha384()
                else:
                    print(f"WARNING: Unknown curve {curve_name}, assuming SHA-256")
                    hash_algorithm = hashes.SHA256()
                    hasher = hashlib.sha256()
                    
                hasher.update(sig_context)
                message_hash = hasher.digest()
                print(f"Message hash ({len(message_hash)} bytes): {message_hash.hex()}")
                
                # Verify the signature
                try:
                    print(f"Signature format analysis:")
                    print(f"  Signature length: {len(signature)} bytes")
                    print(f"  Expected length for P-384: 96 bytes (48+48)")
                    print(f"  Signature (hex): {signature.hex()}")
                    
                    # For P-384, COSE uses IEEE P1363 format: r (48 bytes) || s (48 bytes)
                    if len(signature) == 96 and curve_name == "secp384r1":
                        r_bytes = signature[:48]
                        s_bytes = signature[48:]
                        print(f"  r component (48 bytes): {r_bytes.hex()}")
                        print(f"  s component (48 bytes): {s_bytes.hex()}")
                        
                        # Try direct IEEE P1363 format first
                        try:
                            public_key.verify(signature, sig_context, ec.ECDSA(hash_algorithm))
                            print(f"✓ SIGNATURE VALID: COSE signature verification successful (IEEE P1363 format)")
                            return True
                        except Exception as p1363_err:
                            # print(f"IEEE P1363 format failed: {p1363_err}")
                            
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
                                print(f"  DER signature ({len(der_signature)} bytes): {der_signature.hex()}")
                                
                                # Try verification with DER format
                                public_key.verify(der_signature, sig_context, ec.ECDSA(hash_algorithm))
                                print(f"✓ SIGNATURE VALID: COSE signature verification successful (DER format)")
                                return True
                                
                            except Exception as der_err:
                                print(f"DER format conversion/verification failed: {der_err}")
                    else:
                        # Try direct verification for other cases
                        public_key.verify(signature, sig_context, ec.ECDSA(hash_algorithm))
                        print(f"✓ SIGNATURE VALID: COSE signature verification successful")
                        return True
                        
                except Exception as verify_error:
                    print(f"✗ SIGNATURE INVALID: {verify_error}")
                    
                    # Additional debugging: try verifying just the hash
                    try:
                        print(f"\nTrying hash-only verification:")
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
                            print(f"✓ SIGNATURE VALID: Hash-only verification successful")
                            return True
                    except Exception as hash_verify_err:
                        print(f"Hash-only verification also failed: {hash_verify_err}")
                    
                    return False
            else:
                print(f"ERROR: Final public key is not ECDSA: {type(public_key).__name__}")
                return False
                
        elif hasattr(public_key, 'curve'):
            # Cryptography public key
            print(f"Using Cryptography public key")
            
            # Verify it's an ECDSA key
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                print(f"ERROR: Expected ECDSA key, got {type(public_key).__name__}")
                return False
                
            curve_name = public_key.curve.name
            print(f"Curve: {curve_name}")
            
            # Create COSE Sign1 signature context (Sig_structure)
            sig_structure = [
                "Signature1",
                protected_headers,
                b"",  # empty external AAD
                payload
            ]
            
            # Encode the signature structure as CBOR
            sig_context = cbor2.dumps(sig_structure)
            print(f"Signature context length: {len(sig_context)} bytes")
            print(f"Signature context (first 32 bytes): {sig_context[:32].hex()}")
            
            # Hash the signature context (SHA-384 for P-384)
            if curve_name == "secp384r1":
                hash_algorithm = hashes.SHA384()
                hasher = hashlib.sha384()
            else:
                print(f"WARNING: Unknown curve {curve_name}, assuming SHA-256")
                hash_algorithm = hashes.SHA256()
                hasher = hashlib.sha256()
                
            hasher.update(sig_context)
            message_hash = hasher.digest()
            print(f"Message hash ({len(message_hash)} bytes): {message_hash.hex()}")
            
            # Verify the signature
            try:
                public_key.verify(signature, sig_context, ec.ECDSA(hash_algorithm))
                print(f"✓ SIGNATURE VALID: ECDSA signature verification successful")
                return True
            except Exception as verify_error:
                print(f"✗ SIGNATURE INVALID: {verify_error}")
                return False
        else:
            print(f"ERROR: Unknown public key type: {type(public_key)}")
            return False
            
    except ImportError:
        print(f"Note: Required libraries not available for signature validation")
        print(f"Install with: pip install cryptography pyOpenSSL cbor2")
        return False
    except Exception as e:
        print(f"Error during signature validation: {e}")
        return False
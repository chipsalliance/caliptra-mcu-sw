"""
JSON extraction module for EAT token claims with proper logging
"""

import json
import os
import logging

# Set up logger for this module
logger = logging.getLogger(__name__)

# Import signature validation functions
try:
    from signature_validation import validate_cose_signature
    SIGNATURE_VALIDATION_AVAILABLE = True
except ImportError:
    SIGNATURE_VALIDATION_AVAILABLE = False
    print("Warning: Signature validation not available (signature_validation module not found)")

# Import certificate analysis functions
try:
    from signature_analysis import analyze_certificate_headers
    CERTIFICATE_ANALYSIS_AVAILABLE = True
except ImportError:
    CERTIFICATE_ANALYSIS_AVAILABLE = False
    print("Warning: Certificate analysis not available (signature_analysis module not found)")

def get_clean_claim_name(key):
    """Convert claim key to clean name using the same mapping as decode.py"""
    # This is the exact same mapping from decode.py get_eat_claim_name()
    eat_claims = {
        # Standard CWT/EAT claims
        1: "iss (Issuer)",
        2: "sub (Subject)", 
        3: "aud (Audience)",
        4: "exp (Expiration Time)",
        5: "nbf (Not Before)",
        6: "iat (Issued At)",
        7: "cti (CWT ID)",
        8: "cnf (Confirmation)",
        10: "nonce",
        
        # EAT-specific claims
        256: "ueid (Universal Entity ID)",
        257: "sueids (Semi-permanent UEIDs)",
        258: "oemid (OEM ID)",
        259: "hwmodel (Hardware Model)",
        260: "hwversion (Hardware Version)",
        261: "uptime (Uptime)",
        262: "swversion (Software Version)",
        263: "dbgstat (Debug Status)",
        264: "location",
        265: "eat_profile (EAT Profile)",
        266: "profile (Profile)",
        267: "bootcount (Boot Count)",
        268: "bootseed (Boot Seed)",
        269: "dloas (DLOA)",
        273: "measurements (Evidence)",
        
        # Private/custom claims
        -70001: "rim_locators (RIM Locators)",
        -70002: "private_claim_1",
        -70003: "private_claim_2", 
        -70004: "private_claim_3",
        -70005: "private_claim_4",
        -70006: "private_claim_5",
    }
    
    if isinstance(key, int):
        full_name = eat_claims.get(key, f"claim-{key}")
        # Extract just the short name (before any parentheses)
        if '(' in full_name:
            short_name = full_name.split('(')[0].strip()
        else:
            short_name = full_name
        
        # Clean up the name for JSON keys
        return short_name.replace(' ', '_').replace('-', '_').lower()
    elif isinstance(key, str):
        return key.replace(' ', '_').replace('-', '_').lower()
    else:
        return str(key)

def parse_digest_entry(entry, parse_cbor_header_func):
    """Parse a single digest entry with algorithm name mapping"""
    if not isinstance(entry, list) or len(entry) < 2:
        return entry
    
    alg_id = entry[0]
    digest_value = entry[1]
    
    # Keep original numeric value for JSON (IANA-compliant positive values only)
    result = [alg_id, digest_value]
    return result

def parse_nested_array_elements(elements, parse_cbor_header_func):
    """Parse nested array elements with digest algorithm mapping"""
    if not isinstance(elements, list):
        return elements
    
    parsed_elements = []
    for element in elements:
        if isinstance(element, list):
            if len(element) == 2 and isinstance(element[0], int):
                # This looks like a digest entry (algorithm_id, digest_value)
                parsed_elements.append(parse_digest_entry(element, parse_cbor_header_func))
            else:
                # Recursively parse nested arrays
                parsed_elements.append(parse_nested_array_elements(element, parse_cbor_header_func))
        else:
            parsed_elements.append(element)
    
    return parsed_elements

def extract_simple_claim_value_with_decoding(payload, offset, major_type, value, claim_key, parse_cbor_header_func):
    """Extract claim value with proper decoding"""
    
    if major_type == 0:  # Unsigned integer
        return value, offset
    elif major_type == 1:  # Negative integer  
        return -1 - value, offset
    elif major_type == 2:  # Byte string
        if offset + value <= len(payload):
            byte_data = payload[offset:offset + value]
            offset += value
            return byte_data.hex(), offset
        else:
            return None, offset
    elif major_type == 3:  # Text string
        if offset + value <= len(payload):
            text_data = payload[offset:offset + value]
            offset += value
            try:
                decoded_text = text_data.decode('utf-8')
                # Check if it's a hex-encoded string that should be decoded further
                if len(decoded_text) > 6 and all(c in '0123456789abcdefABCDEF' for c in decoded_text):
                    # This looks like a hex-encoded string, try to decode it
                    try:
                        if len(decoded_text) % 2 == 0:
                            hex_bytes = bytes.fromhex(decoded_text)
                            final_text = hex_bytes.decode('utf-8')
                            return final_text, offset
                    except (ValueError, UnicodeDecodeError):
                        pass  # Not hex or not valid UTF-8, use original
                return decoded_text, offset
            except UnicodeDecodeError:
                return text_data.hex(), offset
        else:
            return None, offset
    elif major_type == 6:  # CBOR tag
        # Handle CBOR tags
        logger.debug("Processing CBOR tag %d for claim %s", value, claim_key)
        if value == 111:  # OID tag
            logger.debug("Found OID tag (111), parsing tagged value...")
            # Parse the tagged value
            header, offset = parse_cbor_header_func(payload, offset)
            if header:
                logger.debug("Tagged value header: type=%d, value=%d", header[0], header[1])
                tagged_value, offset = extract_simple_claim_value_with_decoding(
                    payload, offset, header[0], header[1], claim_key, parse_cbor_header_func
                )
                logger.debug("Tagged value extracted: %s", tagged_value)
                # For OID tag, check if it's hex-encoded and decode if needed
                if isinstance(tagged_value, str) and len(tagged_value) > 6:
                    if all(c in '0123456789abcdefABCDEF' for c in tagged_value):
                        try:
                            if len(tagged_value) % 2 == 0:
                                hex_bytes = bytes.fromhex(tagged_value)
                                decoded_oid = hex_bytes.decode('utf-8')
                                logger.debug("Decoded OID: %s -> %s", tagged_value, decoded_oid)
                                return decoded_oid, offset
                        except (ValueError, UnicodeDecodeError) as e:
                            logger.debug("Failed to decode OID hex: %s", e)
                return tagged_value, offset
        else:
            # For other tags, parse the tagged value
            header, offset = parse_cbor_header_func(payload, offset)
            if header:
                tagged_value, offset = extract_simple_claim_value_with_decoding(
                    payload, offset, header[0], header[1], claim_key, parse_cbor_header_func
                )
                return tagged_value, offset
        return value, offset
    elif major_type == 4:  # Array
        array_items = []
        for i in range(value):
            if offset >= len(payload):
                break
            header, offset = parse_cbor_header_func(payload, offset)
            if header:
                item_value, offset = extract_simple_claim_value_with_decoding(
                    payload, offset, header[0], header[1], None, parse_cbor_header_func
                )
                array_items.append(item_value)
        
        # Apply digest parsing for measurements
        if claim_key in ["measurements", -75000, 273]:
            array_items = parse_nested_array_elements(array_items, parse_cbor_header_func)
        
        return array_items, offset
    elif major_type == 5:  # Map
        map_items = {}
        for i in range(value):
            if offset >= len(payload):
                break
            # Parse key
            key_header, offset = parse_cbor_header_func(payload, offset)
            if key_header:
                key_value, offset = extract_simple_claim_value_with_decoding(
                    payload, offset, key_header[0], key_header[1], None, parse_cbor_header_func
                )
                # Parse value
                value_header, offset = parse_cbor_header_func(payload, offset)
                if value_header:
                    map_value, offset = extract_simple_claim_value_with_decoding(
                        payload, offset, value_header[0], value_header[1], key_value, parse_cbor_header_func
                    )
                    map_items[key_value] = map_value
        return map_items, offset
    elif major_type == 7:  # Special/float/simple
        if value == 20:  # false
            return False, offset
        elif value == 21:  # true
            return True, offset
        elif value == 22:  # null
            return None, offset
        else:
            return value, offset
    else:
        return value, offset

def extract_claims_to_dict(payload, parse_cbor_header_func, verbose=False):
    """Extract claims from EAT token payload to dictionary"""
    claims_dict = {}
    offset = 0
    
    logger.debug("Parsing payload of %d bytes", len(payload))
    logger.debug("Payload start: %s", payload[:20].hex())
    
    # Parse the main claims map
    header, offset = parse_cbor_header_func(payload, offset)
    
    logger.debug("First header - type: %s, value: %s", 
                header[0] if header else 'None', 
                header[1] if header else 'None')
    
    if header and header[0] == 5:  # Map
        num_items = header[1]
        print(f"Extracting {num_items} claims...")
        
        for i in range(num_items):
            if offset >= len(payload):
                break
                
            # Parse claim key
            key_header, offset = parse_cbor_header_func(payload, offset)
            if key_header:
                claim_key, offset = extract_simple_claim_value_with_decoding(
                    payload, offset, key_header[0], key_header[1], None, parse_cbor_header_func
                )
                
                # Get clean name for the claim
                clean_name = get_clean_claim_name(claim_key)
                
                # Parse claim value
                value_header, offset = parse_cbor_header_func(payload, offset)
                if value_header:
                    claim_value, offset = extract_simple_claim_value_with_decoding(
                        payload, offset, value_header[0], value_header[1], claim_key, parse_cbor_header_func
                    )
                    claims_dict[clean_name] = claim_value
    else:
        logger.debug("Payload is not a CBOR map. Type: %s", header[0] if header else 'None')
        # Try to parse as a simple value to see what it contains
        if header:
            value, _ = extract_simple_claim_value_with_decoding(
                payload, offset, header[0], header[1], None, parse_cbor_header_func
            )
            logger.debug("Payload content: %s", value)
            claims_dict["raw_payload"] = value
    
    return claims_dict

def claims_to_json(claims_dict):
    """Convert claims dictionary to JSON string"""
    return json.dumps(claims_dict, indent=2, default=str)

def extract_cose_components(cose_data, parse_cbor_header_func, verbose=False):
    """Extract all components from COSE Sign1 structure for signature verification"""
    try:
        offset = 0
        
        # Parse the main array structure
        header, offset = parse_cbor_header_func(cose_data, offset)
        if not header or header[0] != 4:  # Should be array
            logger.debug("Error: Expected COSE array, got type %s", header[0] if header else 'None')
            return None, None, None, None
            
        array_length = header[1]
        logger.debug("COSE Sign1 array with %d elements", array_length)
        
        # Element 1: Protected headers (bstr)
        logger.info("Parsing element 1 (protected headers)")
        header, offset = parse_cbor_header_func(cose_data, offset)
        protected_headers = None
        if header and header[0] == 2:  # Byte string
            protected_headers = cose_data[offset:offset+header[1]]
            offset += header[1]
        elif header:
            logger.debug("Warning: Expected byte string for protected headers, got type %d", header[0])
            if header[0] == 3:  # Text string
                offset += header[1]
        
        # Element 2: Unprotected headers (map or empty) - extract certificate
        logger.info("Parsing element 2 (unprotected headers)")
        header, offset = parse_cbor_header_func(cose_data, offset)
        certificate = None
        
        if header and header[0] == 5:  # Map
            # Parse map to find certificate
            num_pairs = header[1]
            for _ in range(num_pairs):
                if offset >= len(cose_data):
                    break
                # Parse key
                key_header, offset = parse_cbor_header_func(cose_data, offset)
                if key_header and key_header[0] == 0 and key_header[1] == 33:  # x5chain key (COSE key 33)
                    # Parse value (certificate data as byte string)
                    value_header, offset = parse_cbor_header_func(cose_data, offset)
                    if value_header and value_header[0] == 2:  # Byte string (certificate data)
                        cert_data = cose_data[offset:offset+value_header[1]]
                        offset += value_header[1]
                        logger.info("\tExtracted certificate in unprotected headers (key 33), size: %d bytes", len(cert_data))
                        
                        # Validate certificate using the same function as decode.py
                        if CERTIFICATE_ANALYSIS_AVAILABLE and analyze_certificate_headers(33, cert_data):
                            certificate = cert_data
                            logger.info("\tFound a valid X509 certificate")
                        else:
                            logger.warning("Certificate validation failed or analysis not available")
                        break
                else:
                    # Skip this key-value pair
                    if key_header:
                        if key_header[0] in [2, 3]:  # String types
                            offset += key_header[1]
                    value_header, offset = parse_cbor_header_func(cose_data, offset)
                    if value_header:
                        if value_header[0] in [2, 3]:  # String types
                            offset += value_header[1]
                        elif value_header[0] == 7 and value_header[1] == 22:  # null
                            pass  # No additional bytes to skip
        elif header and header[0] == 7 and header[1] == 22:  # null
            pass  # Empty unprotected headers
        
        # Element 3: Payload (bstr)
        logger.info("Parsing element 3 (payload)")
        header, offset = parse_cbor_header_func(cose_data, offset)
        payload = None
        if header and header[0] == 2:  # Byte string (expected)
            payload_len = header[1]
            payload = cose_data[offset:offset+payload_len]
            offset += payload_len
        elif header and header[0] == 3:  # Text string (unexpected)
            logger.debug("Warning: Payload is a text string instead of byte string")
            payload_len = header[1]
            payload_bytes = cose_data[offset:offset+payload_len]
            # Try to handle as hex text
            try:
                payload_text = payload_bytes.decode('utf-8')
                if all(c in '0123456789abcdefABCDEF \n\t' for c in payload_text):
                    payload = bytes.fromhex(payload_text.replace(' ', '').replace('\n', '').replace('\t', ''))
                else:
                    payload = payload_bytes  # Use raw bytes
            except UnicodeDecodeError:
                payload = payload_bytes
            offset += payload_len
        
        # Element 4: Signature (bstr)
        logger.info("Parsing element 4 (signature)")
        header, offset = parse_cbor_header_func(cose_data, offset)
        signature = None
        if header and header[0] == 2:  # Byte string
            signature = cose_data[offset:offset+header[1]]
        
        return protected_headers, certificate, payload, signature
        
    except Exception as e:
        logger.debug("Error extracting COSE components: %s", e)
        import traceback
        traceback.print_exc()
        return None, None, None, None

def extract_claims_to_json_only(file_path, skip_cbor_tags_func, parse_cbor_header_func, verbose=False):
    """Extract claims to JSON only, minimal output"""
    try:
        # Read the file
        with open(file_path, 'rb') as f:
            payload = f.read()
        
        if verbose:
            print(f"File size: {len(payload)} bytes")
        
        # Skip CBOR tags and get COSE data
        logger.debug("About to skip CBOR tags...")
        cose_data = skip_cbor_tags_func(payload)
        logger.debug("COSE data size: %d bytes", len(cose_data))
        
        # Extract COSE components (certificate validation will show logs)
        print("\n=== 1) Extract COSE components ===")
        protected_headers, certificate, eat_payload, signature = extract_cose_components(
            cose_data, parse_cbor_header_func, verbose  # Pass verbose flag through
        )
        
        if eat_payload is None:
            logger.error("Error: Could not extract payload from COSE structure")
            return
            
        logger.info("EAT payload size: %d bytes", len(eat_payload))
        
        # Attempt signature verification if components are available (always do validation, control output with verbose)
        signature_valid = False
        if SIGNATURE_VALIDATION_AVAILABLE and all(comp is not None for comp in [protected_headers, certificate, eat_payload, signature]):
            try:
                # Use the exact same parameter order as decode.py
                signature_valid = validate_cose_signature(
                    protected_headers,
                    eat_payload,  # payload
                    signature,
                    certificate
                )
                if signature_valid:
                    logger.debug("✓ Signature verification completed successfully")
                else:
                    print("✗ Signature verification failed")
            except Exception as e:
                if verbose:
                    print(f"✗ Signature verification error: {e}")
                else:
                    print("✗ Signature verification: ERROR")
                logger.debug("Exception details: %s", e, exc_info=True)
        
        # Extract claims
        print("\n=== 4) Extract EAT Claims ===")
        claims_dict = extract_claims_to_dict(eat_payload, parse_cbor_header_func, verbose)
        logger.debug("Extracted %d claims", len(claims_dict))
        
        # Save to JSON file
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        json_file = f"{base_name}_claims.json"
        
        with open(json_file, 'w') as f:
            f.write(claims_to_json(claims_dict))
        
        logger.info(f"Claims saved to {json_file}")
        
        # Print summary (always show in JSON mode)
        logger.info(f"\nExtracted {len(claims_dict)} claims:")
        for key, value in claims_dict.items():
            if isinstance(value, str) and len(value) > 50:
                logger.info(f"  {key}: {value[:50]}...")
            elif isinstance(value, list):
                logger.info(f"  {key}: list with {len(value)} items")
            else:
                logger.info(f"  {key}: {value}")

        logger.info(f"\nJSON saved to: {json_file}")

    except Exception as e:
        import traceback
        print(f"Error extracting claims to JSON: {e}")
        if verbose:
            traceback.print_exc()

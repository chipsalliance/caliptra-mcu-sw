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

def get_clean_claim_name(key):
    """Convert claim key to clean name"""
    claim_names = {
        1: "iss",
        2: "sub", 
        3: "aud",
        4: "exp",
        5: "nbf",
        6: "iat",
        7: "cti",
        8: "cnf",
        10: "nonce",
        11: "ueid",
        258: "eat_nonce",
        259: "ueid",
        265: "location",
        266: "eat_profile", 
        267: "submods",
        -75000: "measurements"
    }
    
    if isinstance(key, int):
        return claim_names.get(key, f"claim_{key}")
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
                return text_data.decode('utf-8'), offset
            except UnicodeDecodeError:
                return text_data.hex(), offset
        else:
            return None, offset
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
        if claim_key in ["measurements", -75000]:
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
        logger.debug("Parsing element 1 (protected headers)")
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
        logger.debug("Parsing element 2 (unprotected headers)")
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
                if key_header and key_header[0] == 0 and key_header[1] == 4:  # x5chain key
                    # Parse value (should be array of certificates)
                    value_header, offset = parse_cbor_header_func(cose_data, offset)
                    if value_header and value_header[0] == 4:  # Array
                        # Get first certificate
                        cert_header, offset = parse_cbor_header_func(cose_data, offset)
                        if cert_header and cert_header[0] == 2:  # Byte string
                            certificate = cose_data[offset:offset+cert_header[1]]
                            offset += cert_header[1]
                            # Skip remaining certificates
                            for _ in range(value_header[1] - 1):
                                if offset >= len(cose_data):
                                    break
                                skip_header, offset = parse_cbor_header_func(cose_data, offset)
                                if skip_header and skip_header[0] == 2:
                                    offset += skip_header[1]
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
        logger.debug("Parsing element 3 (payload)")
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
        logger.debug("Parsing element 4 (signature)")
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
    """Extract claims to JSON only, with signature verification"""
    try:
        # Read the file
        with open(file_path, 'rb') as f:
            payload = f.read()
        
        print(f"File size: {len(payload)} bytes")
        
        # Skip CBOR tags and get COSE data
        logger.debug("About to skip CBOR tags...")
        cose_data = skip_cbor_tags_func(payload)
        logger.debug("COSE data size: %d bytes", len(cose_data))
        
        # Extract all COSE components for signature verification
        logger.debug("About to parse COSE structure and extract components...")
        protected_headers, certificate, eat_payload, signature = extract_cose_components(
            cose_data, parse_cbor_header_func, verbose
        )
        
        if eat_payload is None:
            print("Error: Could not extract payload from COSE structure")
            return
            
        logger.debug("EAT payload size: %d bytes", len(eat_payload))
        
        # Attempt signature verification if components are available
        signature_valid = False
        if SIGNATURE_VALIDATION_AVAILABLE and all(comp is not None for comp in [protected_headers, certificate, eat_payload, signature]):
            try:
                print("\n=== COSE Sign1 Signature Verification ===\n")
                signature_valid = validate_cose_signature(protected_headers, certificate, eat_payload, signature)
                if signature_valid:
                    print("✓ Signature verification completed successfully")
                else:
                    print("✗ Signature verification failed")
            except Exception as e:
                print(f"✗ Signature verification error: {e}")
        
        # Extract claims
        logger.debug("About to extract claims...")
        claims_dict = extract_claims_to_dict(eat_payload, parse_cbor_header_func, verbose)
        logger.debug("Extracted %d claims", len(claims_dict))
        
        # Add signature verification result to claims
        claims_dict["_signature_verification"] = {
            "verified": signature_valid,
            "verification_attempted": SIGNATURE_VALIDATION_AVAILABLE and all(comp is not None for comp in [protected_headers, certificate, eat_payload, signature]),
            "components_available": {
                "protected_headers": protected_headers is not None,
                "certificate": certificate is not None,
                "payload": eat_payload is not None,
                "signature": signature is not None
            }
        }
        
        # Save to JSON file
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        json_file = f"{base_name}_claims.json"
        
        with open(json_file, 'w') as f:
            f.write(claims_to_json(claims_dict))
        
        print(f"Claims saved to {json_file}")
        
        # Print summary
        print(f"\nExtracted {len(claims_dict)} claims:")
        for key, value in claims_dict.items():
            if key == "_signature_verification":
                print(f"  {key}: dict with {len(value)} keys")
            elif isinstance(value, str) and len(value) > 50:
                print(f"  {key}: {value[:50]}...")
            elif isinstance(value, list):
                print(f"  {key}: list with {len(value)} items")
            else:
                print(f"  {key}: {value}")
        
        print(f"\nJSON saved to: {json_file}")
        
    except Exception as e:
        import traceback
        print(f"Error extracting claims to JSON: {e}")
        traceback.print_exc()

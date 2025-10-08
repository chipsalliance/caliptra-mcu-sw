"""
JSON extraction module for EAT token claims with proper logging
"""

import json
import os
import logging
from decode_eat_claims_json import parse_eat_claims_to_dict as structured_claims_parser

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
        
        # Extract claims (structured parser only)
        print("\n=== 4) Extract EAT Claims ===")
        claims_dict = structured_claims_parser(eat_payload)
        logger.debug("Structured parser extracted %d claims", len(claims_dict))
        
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

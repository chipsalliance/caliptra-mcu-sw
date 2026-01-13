#!/usr/bin/env python3
"""Signed CWT/EAT token decoding and claims extraction utilities."""

import os
import json
import logging
from typing import List, Tuple, Dict, Any
from decode import parse_cbor_header
from eat_claims import parse_eat_claims_json
from signature_analysis import analyze_certificate_headers
from signature_validation import validate_cose_signature
from certchain import validate_certchain

logger = logging.getLogger(__name__)

def _extract_protected_headers(cose_data: bytes, offset: int) -> Tuple[bytes, int]:
    """Extract protected headers from COSE Sign1 structure."""
    logger.info("Parsing element 1 (protected headers)")
    header, offset = parse_cbor_header(cose_data, offset)
    protected_headers = None
    
    if header and header[0] == 2:  # Byte string
        protected_headers = cose_data[offset:offset+header[1]]
        offset += header[1]
    elif header:
        logger.debug("Warning: Expected byte string for protected headers, got type %d", header[0])
        if header[0] == 3:  # Text string
            offset += header[1]
    
    return protected_headers, offset


def _extract_unprotected_headers(cose_data: bytes, offset: int) -> Tuple[bytes, int]:
    """Extract certificate from unprotected headers in COSE Sign1 structure."""
    logger.info("Parsing element 2 (unprotected headers)")
    header, offset = parse_cbor_header(cose_data, offset)
    certificate = None
    
    if header and header[0] == 5:  # Map
        # Parse map to find certificate
        num_pairs = header[1]
        for _ in range(num_pairs):
            if offset >= len(cose_data):
                break
            # Parse key
            key_header, offset = parse_cbor_header(cose_data, offset)
            if key_header and key_header[0] == 0 and key_header[1] == 33:  # x5chain key (COSE key 33)
                # Parse value (certificate data as byte string)
                value_header, offset = parse_cbor_header(cose_data, offset)
                if value_header and value_header[0] == 2:  # Byte string (certificate data)
                    cert_data = cose_data[offset:offset+value_header[1]]
                    offset += value_header[1]
                    logger.info("\tExtracted certificate in unprotected headers (key 33), size: %d bytes", len(cert_data))
                    
                    # Validate certificate using the same function as decode.py
                    if analyze_certificate_headers(33, cert_data):
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
                value_header, offset = parse_cbor_header(cose_data, offset)
                if value_header:
                    if value_header[0] in [2, 3]:  # String types
                        offset += value_header[1]
                    elif value_header[0] == 7 and value_header[1] == 22:  # null
                        pass  # No additional bytes to skip
    elif header and header[0] == 7 and header[1] == 22:  # null
        pass  # Empty unprotected headers
    
    return certificate, offset


def _extract_payload(cose_data: bytes, offset: int) -> Tuple[bytes, int]:
    """Extract payload from COSE Sign1 structure."""
    logger.info("Parsing element 3 (payload)")
    header, offset = parse_cbor_header(cose_data, offset)
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
    
    return payload, offset


def _extract_signature(cose_data: bytes, offset: int) -> bytes:
    """Extract signature from COSE Sign1 structure."""
    logger.info("Parsing element 4 (signature)")
    header, offset = parse_cbor_header(cose_data, offset)
    signature = None
    
    if header and header[0] == 2:  # Byte string
        signature = cose_data[offset:offset+header[1]]
    
    return signature


def _extract_cose_components(cose_data, verbose=False):
    """Extract all components from COSE Sign1 structure for signature verification"""
    try:
        offset = 0
        
        # Parse the main array structure
        header, offset = parse_cbor_header(cose_data, offset)
        if not header or header[0] != 4:  # Should be array
            logger.debug("Error: Expected COSE array, got type %s", header[0] if header else 'None')
            return None, None, None, None
            
        array_length = header[1]
        logger.debug("COSE Sign1 array with %d elements", array_length)
        
        # Extract each component using dedicated functions
        protected_headers, offset = _extract_protected_headers(cose_data, offset)
        certificate, offset = _extract_unprotected_headers(cose_data, offset)
        payload, offset = _extract_payload(cose_data, offset)
        signature = _extract_signature(cose_data, offset)

        return protected_headers, certificate, payload, signature
        
    except Exception as e:
        logger.debug("Error extracting COSE components: %s", e)
        import traceback
        traceback.print_exc()
        raise ValueError(f"Failed to extract COSE components: {e}")
    
def save_claims_to_json_file(claims_dict: Dict[str, Any], base_filename: str = "eat") -> bool:
    """Save claims dictionary to a JSON file in SPDM_VALIDATOR_DIR."""
    try:
        # Get SPDM_VALIDATOR_DIR from environment
        spdm_validator_dir = os.environ.get('SPDM_VALIDATOR_DIR')
        if not spdm_validator_dir:
            logger.warning("SPDM_VALIDATOR_DIR environment variable is not set, saving to current directory")
            output_dir = "."
        else:
            output_dir = spdm_validator_dir
            
        # Generate the JSON filename and full path
        base_name = os.path.splitext(os.path.basename(base_filename))[0]
        json_filename = f"{base_name}_claims.json"
        json_file_path = os.path.join(output_dir, json_filename)
        
        with open(json_file_path, 'w', encoding='utf-8') as f:
            json.dump(claims_dict, f, indent=2, ensure_ascii=False)
        logger.info(f"Claims saved to {json_file_path}")
        return True
    except (OSError, IOError, PermissionError) as e:
        logger.error(f"File I/O error saving claims to JSON file: {e}")
        return False
    except (TypeError, ValueError) as e:
        logger.error(f"JSON serialization error: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error saving claims to JSON file: {e}")
        return False

def process_signed_eat(cose_data: bytes, cert_chain : List[bytes], verbose=False):
    """Process signed EAT token: validate CoseSign1 signature and extract claims."""
    try:
        # Extract COSE components (certificate validation will show logs)
        logger.info("\n\n======= Extract COSE components =======")
        protected_headers, certificate, eat_payload, signature = _extract_cose_components(
            cose_data, verbose  # Pass verbose flag through
        )
        logger.info("EAT payload size: %d bytes", len(eat_payload))

        logger.info("\n\n======= Prepare Full Certificate Chain with EAT AK Leaf and Authenticate =======")
        if certificate:
            # Replace leaf certificate with the one from COSE headers
            cert_chain[0] = certificate
            validate_certchain(cert_chain, verbose=verbose, parse=True)
        else:
            logger.error("No certificate found in COSE unprotected headers")
            raise ValueError("No certificate found in COSE unprotected headers")
            
        # Attempt signature verification if components are available
        if all(comp is not None for comp in [protected_headers, certificate, eat_payload, signature]):
            # Use the exact same parameter order as decode.py
            # NOTE: Only the leaf certificate is passed. Full chain (if assembled) is validated earlier.
            logger.info("\n\n======= COSE Sign1 Signature Validation ========")
            signature_valid = validate_cose_signature(
                protected_headers,
                eat_payload,  # payload
                signature,
                certificate
            )
            if not signature_valid:
                raise ValueError("Signature verification failed")
        
        # Extract claims (structured parser only)
        logger.info("\n\n======= Extract EAT Claims ========")
        claims_dict = parse_eat_claims_json(eat_payload)
        logger.info("Structured parser extracted %d claims", len(claims_dict))
        logger.info(f"Claims {list(claims_dict.keys())}")
        
        # Save to JSON file
        save_claims_to_json_file(claims_dict, "eat")

        return claims_dict

    except Exception as e:
        import traceback
        logger.error(f"Error extracting claims to JSON: {e}")
        if verbose:
            traceback.print_exc()
        raise
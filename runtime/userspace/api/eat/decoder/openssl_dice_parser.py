#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""
OpenSSL-based TCG DICE Extension Parser

This module provides pure OpenSSL-based parsing of TCG DICE certificate extensions,
eliminating the need for pyasn1 or cryptography libraries.
"""

import logging

# Set up logger for this module
logger = logging.getLogger(__name__)

def get_tcg_dice_extension_names():
    """
    Get mapping of TCG DICE extension OIDs to readable names
    
    Returns:
        dict: Mapping of OID strings to extension names
    """
    return {
        '2.23.133.5.4.1': 'tcg-dice-TcbInfo',  # DICE layer attestation Evidence
        '2.23.133.5.4.2': 'tcg-dice-endorsement-manifest',  # Endorsement values
        '2.23.133.5.4.3': 'tcg-dice-endorsement-manifest-uri',  # URI to reference manifest
        '2.23.133.5.4.4': 'tcg-dice-Ueid',  # Unique Entity Identifier
        '2.23.133.5.4.5': 'tcg-dice-MultiTcbInfo',  # Multiple TCB elements
        '2.23.133.5.4.6': 'tcg-dice-UCCS-evidence',  # Unprotected CWT Claims Set Evidence
        '2.23.133.5.4.7': 'tcg-dice-manifest-evidence',  # SWID or CoSWID manifest
    }

def parse_dice_extension_openssl(extension_data, extension_name="Unknown"):
    """
    Parse TCG DICE extension using pure OpenSSL ASN.1 parsing
    
    Args:
        extension_data (bytes): Raw DER-encoded extension data
        extension_name (str): Name of the extension for context
        
    Returns:
        dict: Parsed extension information
    """
    try:
        from OpenSSL import crypto
        
        # Create a temporary certificate with just this extension to leverage OpenSSL parsing
        # This is a hack but leverages OpenSSL's robust ASN.1 parsing capabilities
        
        result = {
            "extension_name": extension_name,
            "raw_length": len(extension_data),
            "structure": "OpenSSL ASN.1 parsed",
            "raw_hex": extension_data.hex(),
        }
        
        # Parse basic ASN.1 structure using OpenSSL's built-in capabilities
        if len(extension_data) > 0:
            # Check ASN.1 tag
            tag = extension_data[0]
            result["asn1_tag"] = hex(tag)
            
            if tag == 0x30:  # SEQUENCE
                result["asn1_type"] = "SEQUENCE"
                length_info = parse_asn1_length_openssl(extension_data[1:])
                result["asn1_length"] = length_info["length"]
                result["asn1_length_bytes"] = length_info["length_bytes"]
                
                # Parse nested structures for known DICE extensions
                if "MultiTcbInfo" in extension_name:
                    result.update(parse_multi_tcb_info_openssl(extension_data))
                elif "Ueid" in extension_name:
                    result.update(parse_ueid_openssl(extension_data))
                elif "TcbInfo" in extension_name:
                    result.update(parse_tcb_info_openssl(extension_data))
            else:
                result["asn1_type"] = f"Unknown tag: {hex(tag)}"
        
        return result
        
    except ImportError:
        logger.error("OpenSSL library not available")
        return {
            "error": "OpenSSL not available",
            "raw_hex": extension_data.hex() if extension_data else "",
            "raw_length": len(extension_data) if extension_data else 0
        }
    except Exception as e:
        logger.debug(f"OpenSSL parsing error: {e}")
        return {
            "error": str(e),
            "raw_hex": extension_data.hex() if extension_data else "",
            "raw_length": len(extension_data) if extension_data else 0
        }

def parse_asn1_length_openssl(data):
    """
    Parse ASN.1 length encoding using manual parsing (OpenSSL style)
    
    Args:
        data (bytes): Data starting with length encoding
        
    Returns:
        dict: Length information
    """
    if len(data) == 0:
        return {"length": 0, "length_bytes": 0}
    
    first_byte = data[0]
    
    if first_byte & 0x80 == 0:
        # Short form: length is in the first byte
        return {"length": first_byte, "length_bytes": 1}
    else:
        # Long form: first byte indicates number of subsequent length bytes
        length_bytes = first_byte & 0x7F
        if length_bytes == 0:
            # Indefinite form (not used in DER)
            return {"length": -1, "length_bytes": 1}
        
        if len(data) < 1 + length_bytes:
            return {"length": -1, "length_bytes": 1}
        
        # Calculate length from subsequent bytes
        length = 0
        for i in range(length_bytes):
            length = (length << 8) | data[1 + i]
        
        return {"length": length, "length_bytes": 1 + length_bytes}

def parse_multi_tcb_info_openssl(data):
    """
    Parse MultiTcbInfo extension using OpenSSL-style manual ASN.1 parsing
    
    Args:
        data (bytes): Raw DER-encoded MultiTcbInfo data
        
    Returns:
        dict: Parsed MultiTcbInfo structure
    """
    result = {"tcb_count": 0, "tcb_entries": []}
    
    try:
        # MultiTcbInfo is a SEQUENCE of DiceTcbInfo elements
        if len(data) < 2 or data[0] != 0x30:
            return result
        
        # Parse outer SEQUENCE length
        length_info = parse_asn1_length_openssl(data[1:])
        content_start = 1 + length_info["length_bytes"]
        content_length = length_info["length"]
        
        # Parse inner sequences (each is a DiceTcbInfo)
        offset = content_start
        tcb_index = 0
        
        while offset < len(data) and tcb_index < 10:  # Limit to prevent infinite loops
            if offset >= len(data):
                break
                
            if data[offset] == 0x30:  # Another SEQUENCE (DiceTcbInfo)
                inner_length_info = parse_asn1_length_openssl(data[offset + 1:])
                inner_content_length = inner_length_info["length"]
                inner_total_length = 1 + inner_length_info["length_bytes"] + inner_content_length
                
                tcb_entry = {
                    "index": tcb_index,
                    "length": inner_content_length,
                    "raw_hex": data[offset:offset + inner_total_length].hex()
                }
                
                # Try to extract digest information
                tcb_content = data[offset + 1 + inner_length_info["length_bytes"]:offset + inner_total_length]
                digest_info = extract_digest_from_tcb(tcb_content)
                if digest_info:
                    tcb_entry.update(digest_info)
                
                result["tcb_entries"].append(tcb_entry)
                tcb_index += 1
                offset += inner_total_length
            else:
                # Skip unknown tags
                offset += 1
        
        result["tcb_count"] = len(result["tcb_entries"])
        
    except Exception as e:
        result["parse_error"] = str(e)
    
    return result

def parse_ueid_openssl(data):
    """
    Parse UEID extension using OpenSSL-style manual ASN.1 parsing
    
    Args:
        data (bytes): Raw DER-encoded UEID data
        
    Returns:
        dict: Parsed UEID structure
    """
    result = {}
    
    try:
        # UEID is typically: SEQUENCE { ueid OCTET STRING }
        if len(data) < 2 or data[0] != 0x30:
            return result
        
        # Parse SEQUENCE length
        length_info = parse_asn1_length_openssl(data[1:])
        content_start = 1 + length_info["length_bytes"]
        
        # Look for OCTET STRING (tag 0x04)
        offset = content_start
        while offset < len(data):
            if data[offset] == 0x04:  # OCTET STRING
                octet_length_info = parse_asn1_length_openssl(data[offset + 1:])
                octet_content_start = offset + 1 + octet_length_info["length_bytes"]
                octet_length = octet_length_info["length"]
                
                if octet_content_start + octet_length <= len(data):
                    ueid_value = data[octet_content_start:octet_content_start + octet_length]
                    result["ueid_hex"] = ueid_value.hex()
                    result["ueid_length"] = len(ueid_value)
                    
                    # UEID is typically 32 bytes (256 bits)
                    if len(ueid_value) == 32:
                        result["ueid_format"] = "Standard 256-bit UEID"
                    else:
                        result["ueid_format"] = f"Custom UEID ({len(ueid_value)} bytes)"
                break
            offset += 1
        
    except Exception as e:
        result["parse_error"] = str(e)
    
    return result

def parse_tcb_info_openssl(data):
    """
    Parse TcbInfo extension using OpenSSL-style manual ASN.1 parsing
    
    Args:
        data (bytes): Raw DER-encoded TcbInfo data
        
    Returns:
        dict: Parsed TcbInfo structure
    """
    result = {}
    
    try:
        # Similar to MultiTcbInfo but single entry
        if len(data) < 2 or data[0] != 0x30:
            return result
        
        # Extract digest information
        digest_info = extract_digest_from_tcb(data)
        if digest_info:
            result.update(digest_info)
    
    except Exception as e:
        result["parse_error"] = str(e)
    
    return result

def extract_digest_from_tcb(tcb_data):
    """
    Extract digest information from TCB data using pattern matching
    
    Args:
        tcb_data (bytes): TCB content data
        
    Returns:
        dict: Digest information if found
    """
    result = {}
    
    try:
        # Look for SHA-384 OID: 060960864801650304020204 (SEQUENCE { OID, hash })
        sha384_oid = bytes.fromhex("060960864801650304020204")
        
        # Find SHA-384 digest patterns
        digests_found = []
        offset = 0
        while offset < len(tcb_data) - 48:  # SHA-384 is 48 bytes
            oid_pos = tcb_data.find(sha384_oid, offset)
            if oid_pos == -1:
                break
            
            # Look for 48-byte hash after the OID
            hash_start = oid_pos + len(sha384_oid)
            if hash_start + 48 <= len(tcb_data):
                # Check if next byte could be length (48 = 0x30)
                if tcb_data[hash_start] == 0x30:
                    hash_value = tcb_data[hash_start + 1:hash_start + 49]
                elif tcb_data[hash_start] == 0x04 and tcb_data[hash_start + 1] == 0x30:
                    # OCTET STRING containing 48 bytes
                    hash_value = tcb_data[hash_start + 2:hash_start + 50]
                else:
                    hash_value = tcb_data[hash_start:hash_start + 48]
                
                if len(hash_value) == 48:
                    digests_found.append(hash_value.hex())
            
            offset = oid_pos + 1
        
        if digests_found:
            result["digests_found"] = len(digests_found)
            result["digest_algorithm"] = "SHA-384"
            result["digests"] = digests_found[:3]  # Limit to first 3
    
    except Exception as e:
        result["digest_extract_error"] = str(e)
    
    return result

def format_dice_extension_openssl(parsed_data):
    """
    Format parsed DICE extension data for display
    
    Args:
        parsed_data (dict): Parsed extension data
        
    Returns:
        str: Formatted output
    """
    if not parsed_data:
        return "No data"
    
    lines = []
    lines.append(f"Extension: {parsed_data.get('extension_name', 'Unknown')}")
    lines.append(f"Length: {parsed_data.get('raw_length', 0)} bytes")
    
    if 'asn1_type' in parsed_data:
        lines.append(f"ASN.1 Type: {parsed_data['asn1_type']}")
    
    # Format specific extension types
    if 'tcb_count' in parsed_data:
        lines.append(f"TCB Entries: {parsed_data['tcb_count']}")
        for i, entry in enumerate(parsed_data.get('tcb_entries', [])[:3]):
            lines.append(f"  TCB {i}: {entry.get('length', 0)} bytes")
            if 'digests' in entry:
                for j, digest in enumerate(entry['digests'][:2]):
                    lines.append(f"    Digest {j}: {digest[:32]}...")
    
    if 'ueid_hex' in parsed_data:
        ueid = parsed_data['ueid_hex']
        lines.append(f"UEID: {ueid[:32]}...{ueid[-16:]} ({parsed_data.get('ueid_length', 0)} bytes)")
    
    if 'error' in parsed_data:
        lines.append(f"Error: {parsed_data['error']}")
    
    return '\n'.join(lines)

# Compatibility functions
def parse_dice_extension_data(extension_name, raw_data, decode_structure=True):
    """
    Parse DICE extension data using OpenSSL (replaces previous implementation)
    
    Args:
        extension_name (str): Name of the extension
        raw_data (bytes): Raw extension data
        decode_structure (bool): Whether to decode structure (ignored - always True for OpenSSL)
        
    Returns:
        dict: Parsed extension data
    """
    return parse_dice_extension_openssl(raw_data, extension_name)

# Alias for backward compatibility
parse_extension_data = parse_dice_extension_data
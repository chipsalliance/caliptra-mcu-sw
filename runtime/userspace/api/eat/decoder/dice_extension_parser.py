#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""
TCG DICE Extension Parser

This module provides functions to parse TCG DICE certificate extensions
with context-specific tagged ASN.1 structures.
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

def parse_der_structure_generic(raw_data):
    """
    Parse DER-encoded data using basic ASN.1 decoding with multiple fallback strategies
    
    Args:
        raw_data (bytes): Raw DER-encoded data
        
    Returns:
        dict: Parsed DER structure information
    """
    try:
        # Try with pyasn1 first (most comprehensive)
        try:
            from pyasn1.codec.der import decoder
            from pyasn1.type import univ
            
            # Try generic decoding without strict schema
            decoded_data, remainder = decoder.decode(raw_data)
            result = {
                "parser": "pyasn1",
                "type": type(decoded_data).__name__,
                "decoded": str(decoded_data)[:500] + "..." if len(str(decoded_data)) > 500 else str(decoded_data)
            }
            
            # For SEQUENCE, try to show component summary
            if hasattr(decoded_data, '__len__'):
                try:
                    result["component_count"] = len(decoded_data)
                    if len(decoded_data) <= 5:  # Only show details for small sequences
                        result["components"] = []
                        for i, comp in enumerate(decoded_data):
                            comp_str = str(comp)
                            result["components"].append({
                                "index": i,
                                "type": type(comp).__name__,
                                "value": comp_str[:100] + "..." if len(comp_str) > 100 else comp_str
                            })
                except:
                    pass
            
            return result
            
        except ImportError:
            pass
        except Exception as pyasn1_err:
            result = {"pyasn1_error": str(pyasn1_err)}
        
        # Fallback to basic DER structure analysis
        result = {"parser": "basic_der", "raw_hex": raw_data.hex()}
        
        # Basic DER structure analysis
        if len(raw_data) > 0:
            tag = raw_data[0]
            result["der_tag"] = f"0x{tag:02x}"
            
            # Identify common ASN.1 types
            if tag == 0x30:  # SEQUENCE
                result["type"] = "SEQUENCE"
                # Try to get length
                if len(raw_data) > 1:
                    length_byte = raw_data[1]
                    if length_byte & 0x80 == 0:  # Short form
                        result["length"] = length_byte
                        result["content_start"] = 2
                    else:  # Long form
                        length_bytes = length_byte & 0x7f
                        if len(raw_data) > 1 + length_bytes:
                            length = 0
                            for i in range(length_bytes):
                                length = (length << 8) + raw_data[2 + i]
                            result["length"] = length
                            result["content_start"] = 2 + length_bytes
            elif tag == 0x04:  # OCTET STRING
                result["type"] = "OCTET STRING"
                if len(raw_data) > 2:
                    length = raw_data[1]
                    if length < 128:  # Short form
                        content = raw_data[2:2+length]
                        result["content_hex"] = content.hex()
                        result["content_length"] = len(content)
                        # Try to decode as UTF-8
                        try:
                            result["content_utf8"] = content.decode('utf-8')
                        except:
                            pass
            elif tag == 0x0c:  # UTF8String
                result["type"] = "UTF8String"
                if len(raw_data) > 2:
                    length = raw_data[1]
                    if length < 128:
                        content = raw_data[2:2+length]
                        try:
                            result["content"] = content.decode('utf-8')
                        except:
                            result["content_hex"] = content.hex()
            else:
                result["type"] = f"TAG_0x{tag:02x}"
        
        return result
        
    except Exception as e:
        return {"error": str(e), "raw_hex": raw_data.hex()}

def analyze_der_structure(data, offset=0, depth=0, max_elements=20):
    """
    Manually parse DER structure to handle context-specific tags
    
    Args:
        data (bytes): DER-encoded data to analyze
        offset (int): Starting offset in data
        depth (int): Current recursion depth
        max_elements (int): Maximum number of elements to parse
        
    Returns:
        list: List of parsed DER structure elements
    """
    results = []
    while offset < len(data) and len(results) < max_elements:
        if offset + 1 >= len(data):
            break
            
        tag = data[offset]
        length_byte = data[offset + 1]
        
        # Parse length
        if length_byte & 0x80 == 0:  # Short form
            length = length_byte
            content_start = offset + 2
        else:  # Long form
            length_bytes = length_byte & 0x7f
            if offset + 1 + length_bytes >= len(data):
                break
            length = 0
            for i in range(length_bytes):
                length = (length << 8) + data[offset + 2 + i]
            content_start = offset + 2 + length_bytes
            
        if content_start + length > len(data):
            break
            
        # Analyze tag
        tag_class = (tag & 0xC0) >> 6
        constructed = (tag & 0x20) != 0
        tag_number = tag & 0x1F
        
        tag_info = {
            'offset': offset,
            'tag': f'0x{tag:02x}',
            'tag_class': ['universal', 'application', 'context', 'private'][tag_class],
            'constructed': constructed,
            'tag_number': tag_number,
            'length': length,
            'content': data[content_start:content_start + length]
        }
        
        # For context-specific tags, show the tag number and interpret content
        if tag_class == 2:  # Context-specific
            tag_info['context_tag'] = f'[{tag_number}]'
            
            # Map context tags to field names based on TCG DICE ASN.1 structure
            field_mapping = {
                0: 'vendor',
                1: 'model', 
                2: 'version',
                3: 'svn',
                4: 'layer',
                5: 'index',
                6: 'fwids',
                7: 'flags',
                8: 'vendor_info',
                9: 'tci_type',
                10: 'integrity_registers'
            }
            
            if tag_number in field_mapping:
                tag_info['field_name'] = field_mapping[tag_number]
                
                # Try to interpret the content based on field type
                content = tag_info['content']
                if tag_number in [0, 1, 2]:  # String fields
                    try:
                        tag_info['interpreted_value'] = content.decode('utf-8')
                    except:
                        tag_info['interpreted_value'] = f"String data (hex: {content.hex()})"
                elif tag_number in [3, 4, 5]:  # Integer fields
                    try:
                        if len(content) <= 8:
                            tag_info['interpreted_value'] = int.from_bytes(content, 'big')
                        else:
                            tag_info['interpreted_value'] = f"Large integer (hex: {content.hex()})"
                    except:
                        tag_info['interpreted_value'] = f"Integer data (hex: {content.hex()})"
                elif tag_number in [8, 9]:  # OCTET STRING fields
                    if len(content) <= 32:
                        tag_info['interpreted_value'] = content.hex()
                    else:
                        tag_info['interpreted_value'] = content[:16].hex() + f"... ({len(content)} bytes total)"
                elif tag_number == 7:  # BIT STRING (flags)
                    tag_info['interpreted_value'] = f"Flags: {content.hex()}"
                elif tag_number in [6, 10]:  # SEQUENCE fields (fwids, integrity_registers)
                    if constructed:
                        tag_info['interpreted_value'] = f"Sequence ({length} bytes)"
                        # Could recursively parse here if needed
                    else:
                        tag_info['interpreted_value'] = f"Sequence data (hex: {content[:16].hex()}...)"
                else:
                    tag_info['interpreted_value'] = f"Data (hex: {content[:16].hex()}...)"
        
        results.append(tag_info)
        
        # If it's constructed and we're not too deep, we could recurse
        # But for now, just mark it as having nested content
        if constructed and length > 0:
            tag_info['has_nested_content'] = True
            
        # Move to next element
        offset = content_start + length
        
    return results

def parse_tcb_info_extension(raw_data):
    """
    Parse TCG DICE MultiTcbInfo extension according to ASN.1 structure:
    DiceTcbInfoSeq ::= SEQUENCE SIZE (1..MAX) OF DiceTcbInfo
    
    DiceTcbInfo ::= SEQUENCE { 
        vendor       [0] IMPLICIT UTF8String    
        model        [1] IMPLICIT UTF8String  
        version      [2] IMPLICIT UTF8String  
        svn          [3] IMPLICIT INTEGER          
        layer        [4] IMPLICIT INTEGER          
        index        [5] IMPLICIT INTEGER          
        fwids        [6] IMPLICIT FWIDLIST          
        flags        [7] IMPLICIT OperationalFlags 
        vendorInfo   [8] IMPLICIT OCTET STRING  
        type         [9] IMPLICIT OCTET STRING  
    }
    
    Args:
        raw_data (bytes): Raw DER-encoded extension data
        
    Returns:
        dict: Parsed MultiTcbInfo fields or fallback structure information
    """
    try:
        def parse_length(data, offset):
            """Parse DER length field and return (length, next_offset)"""
            if offset >= len(data):
                return None, offset
                
            length_byte = data[offset]
            if length_byte & 0x80 == 0:  # Short form
                return length_byte, offset + 1
            else:  # Long form
                length_bytes = length_byte & 0x7f
                if offset + length_bytes >= len(data):
                    return None, offset
                length = 0
                for i in range(length_bytes):
                    length = (length << 8) + data[offset + 1 + i]
                return length, offset + 1 + length_bytes

        def parse_context_specific_tag(data, offset, expected_tag):
            """Parse context-specific tag and extract content"""
            if offset >= len(data):
                return None, None, offset
                
            tag = data[offset]
            # Check if it's context-specific class (bits 7-6 = 10) and matches expected tag number
            if (tag & 0xC0) != 0x80 or (tag & 0x1F) != expected_tag:
                return None, None, offset
                
            offset += 1
            length, offset = parse_length(data, offset)
            if length is None or offset + length > len(data):
                return None, None, offset
                
            content = data[offset:offset + length]
            return tag, content, offset + length

        def parse_fwid_list(fwid_data):
            """Parse FWIDLIST ::= SEQUENCE SIZE (1..MAX) OF FWID"""
            fwids = []
            offset = 0
            
            # Should start with SEQUENCE tag
            if offset >= len(fwid_data) or fwid_data[offset] != 0x30:
                return {"error": "Expected SEQUENCE for FWIDLIST", "raw_hex": fwid_data.hex()}
            
            offset += 1
            seq_length, offset = parse_length(fwid_data, offset)
            if seq_length is None:
                return {"error": "Invalid FWIDLIST length", "raw_hex": fwid_data.hex()}
            
            # Parse individual FWID entries
            end_offset = offset + seq_length
            fwid_index = 0
            
            while offset < end_offset and fwid_index < 10:  # Limit to prevent excessive output
                # Each FWID should be a SEQUENCE
                if offset >= len(fwid_data) or fwid_data[offset] != 0x30:
                    break
                    
                offset += 1
                fwid_length, offset = parse_length(fwid_data, offset)
                if fwid_length is None or offset + fwid_length > len(fwid_data):
                    break
                
                fwid_content = fwid_data[offset:offset + fwid_length]
                fwid_info = {"index": fwid_index}
                
                # Parse FWID structure: hashAlg OBJECT IDENTIFIER, digest OCTET STRING
                fwid_offset = 0
                if fwid_offset < len(fwid_content) and fwid_content[fwid_offset] == 0x06:  # OID
                    fwid_offset += 1
                    oid_length, fwid_offset = parse_length(fwid_content, fwid_offset)
                    if oid_length and fwid_offset + oid_length <= len(fwid_content):
                        oid_bytes = fwid_content[fwid_offset:fwid_offset + oid_length]
                        fwid_info["hash_algorithm_oid"] = ".".join(str(b) for b in oid_bytes) if len(oid_bytes) <= 10 else oid_bytes.hex()
                        fwid_offset += oid_length
                
                if fwid_offset < len(fwid_content) and fwid_content[fwid_offset] == 0x04:  # OCTET STRING
                    fwid_offset += 1
                    digest_length, fwid_offset = parse_length(fwid_content, fwid_offset)
                    if digest_length and fwid_offset + digest_length <= len(fwid_content):
                        digest_bytes = fwid_content[fwid_offset:fwid_offset + digest_length]
                        fwid_info["digest"] = digest_bytes.hex()
                        fwid_info["digest_length"] = len(digest_bytes)
                
                fwids.append(fwid_info)
                offset += fwid_length
                fwid_index += 1
            
            return {"fwid_count": len(fwids), "fwids": fwids}

        def parse_operational_flags(flags_data):
            """Parse OperationalFlags ::= BIT STRING"""
            if len(flags_data) == 0:
                return {"error": "Empty flags data"}
            
            # First byte is unused bits count for BIT STRING
            unused_bits = flags_data[0] if len(flags_data) > 0 else 0
            flag_bytes = flags_data[1:] if len(flags_data) > 1 else b''
            
            flags = {
                "unused_bits": unused_bits,
                "raw_hex": flag_bytes.hex(),
                "flags": []
            }
            
            # Parse individual flag bits
            flag_names = ["notConfigured", "notSecure", "recovery", "debug"]
            for byte_idx, byte_val in enumerate(flag_bytes):
                for bit_idx in range(8):
                    bit_position = byte_idx * 8 + bit_idx
                    if bit_position < len(flag_names) and (byte_val & (0x80 >> bit_idx)):
                        flags["flags"].append(flag_names[bit_position])
            
            return flags

        # Parse the main SEQUENCE (DiceTcbInfoSeq)
        offset = 0
        if offset >= len(raw_data) or raw_data[offset] != 0x30:
            logger.debug(f"Expected SEQUENCE for DiceTcbInfoSeq, got 0x{raw_data[offset]:02x}")
            return parse_der_structure_generic(raw_data)
        
        offset += 1
        seq_length, offset = parse_length(raw_data, offset)
        if seq_length is None:
            logger.debug("Invalid SEQUENCE length in DiceTcbInfoSeq")
            return parse_der_structure_generic(raw_data)
        
        result = {
            "type": "DiceTcbInfoSeq",
            "structure": "SEQUENCE SIZE (1..MAX) OF DiceTcbInfo",
            "asn1_structure": {
                "sequence_length": seq_length,
                "total_parsed_bytes": 0
            },
            "tcb_info_entries": []
        }
        
        # Parse each DiceTcbInfo entry
        end_offset = offset + seq_length
        tcb_index = 0
        
        while offset < end_offset and tcb_index < 10:  # Limit entries to prevent excessive output
            # Each DiceTcbInfo should be a SEQUENCE
            if offset >= len(raw_data) or raw_data[offset] != 0x30:
                break
            
            offset += 1
            tcb_length, offset = parse_length(raw_data, offset)
            if tcb_length is None or offset + tcb_length > len(raw_data):
                break
            
            tcb_info = {
                "entry_index": tcb_index,
                "length": tcb_length,
                "fields": {}
            }
            
            tcb_end_offset = offset + tcb_length
            
            # Parse context-specific fields [0] through [9]
            field_parsers = {
                0: ("vendor", lambda x: x.decode('utf-8', errors='replace')),
                1: ("model", lambda x: x.decode('utf-8', errors='replace')),
                2: ("version", lambda x: x.decode('utf-8', errors='replace') if all(32 <= b <= 126 for b in x[:min(len(x), 20)]) else x.hex()),
                3: ("svn", lambda x: int.from_bytes(x, 'big') if len(x) <= 8 else f"Large integer: {x.hex()}"),
                4: ("layer", lambda x: int.from_bytes(x, 'big') if len(x) <= 8 else f"Large integer: {x.hex()}"),
                5: ("index", lambda x: int.from_bytes(x, 'big') if len(x) <= 8 else f"Large integer: {x.hex()}"),
                6: ("fwids", parse_fwid_list),
                7: ("flags", parse_operational_flags),
                8: ("vendor_info", lambda x: x.hex()),
                9: ("type", lambda x: x.hex() + f" (ASCII: {x.decode('ascii', errors='replace')})" if all(32 <= b <= 126 for b in x) else x.hex())
            }
            
            # Parse all fields sequentially by scanning through the TCB info content
            scan_offset = offset
            while scan_offset < tcb_end_offset:
                # Check if this is a context-specific tag
                if scan_offset >= len(raw_data):
                    break
                    
                tag_byte = raw_data[scan_offset]
                tag_class = (tag_byte & 0xC0) >> 6
                tag_number = tag_byte & 0x1F
                
                if tag_class == 2:  # Context-specific class
                    tag, content, new_scan_offset = parse_context_specific_tag(raw_data, scan_offset, tag_number)
                    if tag is not None and content is not None and tag_number in field_parsers:
                        field_name, parser = field_parsers[tag_number]
                        try:
                            parsed_value = parser(content)
                            tcb_info["fields"][field_name] = parsed_value
                        except Exception as e:
                            tcb_info["fields"][field_name] = {
                                "error": f"Parse error: {e}",
                                "raw_hex": content.hex()
                            }
                        scan_offset = new_scan_offset
                    else:
                        scan_offset += 1
                else:
                    scan_offset += 1
            
            # Update offset to end of this TCB info entry
            offset = tcb_end_offset
            
            result["tcb_info_entries"].append(tcb_info)
            tcb_index += 1
        
        result["asn1_structure"]["total_parsed_bytes"] = offset
        result["tcb_info_count"] = len(result["tcb_info_entries"])
        
        return result
        
    except Exception as e:
        logger.debug(f"MultiTcbInfo parsing failed: {e}. Falling back to basic DER parsing.")
        return parse_der_structure_generic(raw_data)

def parse_ueid_extension(raw_data):
    """
    Parse TCG DICE UEID extension data
    
    Args:
        raw_data (bytes): Raw DER-encoded extension data
        
    Returns:
        dict: Parsed UEID data or fallback structure information
    """
    try:
        # UEID is typically wrapped in a SEQUENCE containing an OCTET STRING
        if len(raw_data) >= 4 and raw_data[0] == 0x30:  # SEQUENCE
            seq_length = raw_data[1]
            if seq_length < 128:  # Short form length
                # Look for OCTET STRING inside
                offset = 2
                if raw_data[offset] == 0x04:  # OCTET STRING
                    ueid_length = raw_data[offset + 1]
                    if ueid_length < 128:
                        ueid_bytes = raw_data[offset + 2:offset + 2 + ueid_length]
                        return {
                            "type": "UEID (Unique Entity Identifier)",
                            "hex": ueid_bytes.hex(),
                            "length": len(ueid_bytes),
                            "structure": "SEQUENCE { OCTET STRING }"
                        }
        
        # Try direct OCTET STRING format as fallback
        elif len(raw_data) >= 2 and raw_data[0] == 0x04:  # OCTET STRING
            length = raw_data[1]
            if length < 128:  # Short form length
                ueid_bytes = raw_data[2:2+length]
                return {
                    "type": "UEID (Unique Entity Identifier)",
                    "hex": ueid_bytes.hex(),
                    "length": len(ueid_bytes),
                    "structure": "OCTET STRING"
                }
        
        # Fallback to general DER parsing
        return parse_der_structure_generic(raw_data)
        
    except Exception as e:
        logger.debug(f"UEID parsing failed: {e}")
        return parse_der_structure_generic(raw_data)

def parse_manifest_uri_extension(raw_data):
    """
    Parse TCG DICE endorsement manifest URI extension data
    
    Args:
        raw_data (bytes): Raw DER-encoded extension data
        
    Returns:
        dict: Parsed URI data or fallback structure information
    """
    try:
        # URI is typically a UTF8String
        if len(raw_data) >= 2 and raw_data[0] == 0x0c:  # UTF8String
            length = raw_data[1]
            if length < 128:  # Short form length
                uri_bytes = raw_data[2:2+length]
                try:
                    uri = uri_bytes.decode('utf-8')
                    return {
                        "type": "Manifest URI",
                        "uri": uri
                    }
                except:
                    pass
        
        # Fallback to general DER parsing
        return parse_der_structure_generic(raw_data)
        
    except Exception as e:
        logger.debug(f"Manifest URI parsing failed: {e}")
        return parse_der_structure_generic(raw_data)

def format_hex_dump(data, bytes_per_line=16):
    """Format binary data as a readable hex dump"""
    if not data:
        return ""
    
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        lines.append(f'{i:08x}: {hex_part:<{bytes_per_line*3-1}} {ascii_part}')
    
    return '\n'.join(lines)

def parse_dice_extension_data(ext_name, raw_data, decode_structure=True):
    """
    Parse DICE extension data based on extension type
    
    Args:
        ext_name (str): Extension name (e.g., "tcg-dice-MultiTcbInfo")
        raw_data (bytes): Raw DER-encoded extension data
        decode_structure (bool): If True, perform detailed ASN.1 parsing. If False, return hex dump only.
        
    Returns:
        dict: Parsed extension data with structure information or hex dump
    """
    # If detailed decoding is disabled, just return hex dump
    if not decode_structure:
        return {
            "type": ext_name,
            "structure": "Raw hex data",
            "raw_hex": raw_data.hex(),
            "length": len(raw_data)
        }
    
    # Route to appropriate parser based on extension name
    if "tcg-dice-MultiTcbInfo" in ext_name or "tcg-dice-TcbInfo" in ext_name:
        return parse_tcb_info_extension(raw_data)
    elif "tcg-dice-Ueid" in ext_name:
        return parse_ueid_extension(raw_data)
    elif "tcg-dice-endorsement-manifest-uri" in ext_name:
        return parse_manifest_uri_extension(raw_data)
    elif "tcg-dice-endorsement-manifest" in ext_name:
        # General manifest data - could be complex ASN.1 structure
        return parse_der_structure_generic(raw_data)
    elif "tcg-dice-UCCS-evidence" in ext_name:
        # UCCS Evidence - likely CBOR or complex structure
        return parse_der_structure_generic(raw_data)
    elif "tcg-dice-manifest-evidence" in ext_name:
        # SWID/CoSWID manifest - could be XML or CBOR
        return parse_der_structure_generic(raw_data)
    else:
        # Generic DER parsing for unknown extensions
        return parse_der_structure_generic(raw_data)

def map_oid_to_extension_name(oid):
    """
    Map extension OID to readable name, especially for TCG DICE extensions
    
    Args:
        oid (str): The OID string (e.g., "2.23.133.5.4.5")
        
    Returns:
        str: Human-readable extension name with OID, or just OID if not recognized
    """
    tcg_extension_names = get_tcg_dice_extension_names()
    
    if oid in tcg_extension_names:
        return f"{tcg_extension_names[oid]} (OID:{oid})"
    else:
        return f"OID:{oid}"

def is_dice_extension(oid_or_name):
    """
    Check if an OID or extension name is a TCG DICE extension
    
    Args:
        oid_or_name (str): OID string or extension name
        
    Returns:
        bool: True if it's a DICE extension
    """
    if oid_or_name.startswith('2.23.133.5.4.'):
        return True
    if 'tcg-dice' in oid_or_name.lower():
        return True
    return False
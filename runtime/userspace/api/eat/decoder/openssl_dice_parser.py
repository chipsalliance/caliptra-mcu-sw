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
        
        MAX_ENTRIES = 16  # hard safety cap
        while offset < len(data) and tcb_index < MAX_ENTRIES:  # Limit to prevent infinite loops / abuse
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

                # Structured per-entry TcbInfo field parsing (re-use single parser on full inner SEQUENCE)
                try:
                    # Provide full inner SEQUENCE bytes to single-entry parser for rich fields
                    parsed_inner = parse_tcb_info_openssl(data[offset:offset + inner_total_length])
                    # Merge top-level known fields into the entry (avoid key collisions by prefixing if needed)
                    FIELD_KEYS = ["vendor","model","version","svn","layer","index","fwids","flags","vendor_info","tci_type","integrity_registers","legacy_digests"]
                    for k in FIELD_KEYS:
                        if k in parsed_inner:
                            # If collision with existing primitive key, namespace it
                            if k in tcb_entry and not isinstance(tcb_entry[k], dict):
                                tcb_entry[f"tcb_{k}"] = parsed_inner[k]
                            else:
                                tcb_entry[k] = parsed_inner[k]
                    # Preserve parse errors if any
                    if 'parse_error' in parsed_inner:
                        tcb_entry['parse_error'] = parsed_inner['parse_error']
                except Exception as inner_e:  # noqa: BLE001
                    tcb_entry['parse_error'] = f"inner parse error: {inner_e}" 
                
                result["tcb_entries"].append(tcb_entry)
                tcb_index += 1
                offset += inner_total_length
            else:
                # Skip unknown tags
                offset += 1
        
        result["tcb_count"] = len(result["tcb_entries"])
        if tcb_index == MAX_ENTRIES and offset < len(data):
            result['truncated'] = True
        
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
    result = {"parsed": True}

    # Helper readers ------------------------------------------------------
    def read_length(buf, off):
        if off >= len(buf):
            raise ValueError("length past end")
        b = buf[off]
        off += 1
        if b & 0x80 == 0:
            return b, off
        n = b & 0x7F
        if n == 0 or off + n > len(buf):
            raise ValueError("invalid long form length")
        val = 0
        for _ in range(n):
            val = (val << 8) | buf[off]
            off += 1
        return val, off

    def read_tlv(buf, off):
        if off >= len(buf):
            return None
        tag_byte = buf[off]
        off += 1
        tag_class = (tag_byte & 0xC0) >> 6  # 0=univ,1=app,2=ctx,3=priv
        constructed = bool(tag_byte & 0x20)
        tag_num = tag_byte & 0x1F
        if tag_num == 0x1F:
            raise ValueError("high-tag-number form not expected")
        length, off = read_length(buf, off)
        end = off + length
        if end > len(buf):
            raise ValueError("TLV length exceeds buffer")
        value = buf[off:end]
        return {
            'class': tag_class,
            'constructed': constructed,
            'tag': tag_num,
            'value': value,
            'start': off - (1 + (1 if length < 0x80 else 0)),
            'length': length
        }, end

    try:
        # Outer SEQUENCE
        if len(data) < 2 or data[0] != 0x30:
            return {"error": "Not a SEQUENCE"}
        outer_len_info = parse_asn1_length_openssl(data[1:])
        outer_len = outer_len_info['length']
        content_off = 1 + outer_len_info['length_bytes']
        end_outer = content_off + outer_len
        if end_outer > len(data):
            return {"error": "Outer length beyond buffer"}

        cursor = content_off
        fields = {}

        # Mapping from context tag -> field name & type
        TAG_MAP = {
            0: ("vendor", "utf8"),
            1: ("model", "utf8"),
            2: ("version", "utf8"),
            3: ("svn", "int"),
            4: ("layer", "int"),
            5: ("index", "int"),
            6: ("fwids", "seq_fwid"),
            7: ("flags", "bitstring"),
            8: ("vendor_info", "octets"),
            9: ("tci_type", "octets"),
            10: ("integrity_registers", "seq_integrity"),
        }

        def parse_integer(raw_bytes):
            # Minimal INTEGER decoder (two's complement). Expect <= 8 bytes for u64
            if not raw_bytes:
                return 0
            # Remove leading 0x00 if present for positive value
            rb = raw_bytes
            if len(rb) > 1 and rb[0] == 0x00:
                rb = rb[1:]
            val = 0
            for b in rb:
                val = (val << 8) | b
            return val

        def parse_utf8(raw_bytes):
            try:
                return raw_bytes.decode('utf-8')
            except Exception:
                return raw_bytes.hex()

        def parse_bitstring(raw_bytes):
            if not raw_bytes:
                return {"unused": 0, "hex": ""}
            unused = raw_bytes[0]
            bits = raw_bytes[1:]
            return {"unused": unused, "hex": bits.hex()}

        def parse_fwids(raw_bytes):
            # Expect SEQUENCE OF FWID. Each FWID assumed SEQUENCE { algorithmOID, digest OCTET STRING }
            entries = []
            try:
                off = 0
                if off >= len(raw_bytes) or raw_bytes[off] != 0x30:
                    return {"raw_hex": raw_bytes.hex(), "note": "fwids not a SEQUENCE"}
                linfo = parse_asn1_length_openssl(raw_bytes[off+1:])
                seq_len = linfo['length']
                off = off + 1 + linfo['length_bytes']
                end = off + seq_len
                while off < end:
                    if raw_bytes[off] != 0x30:
                        break
                    l2 = parse_asn1_length_openssl(raw_bytes[off+1:])
                    inner_len = l2['length']
                    inner_start = off + 1 + l2['length_bytes']
                    inner_end = inner_start + inner_len
                    comp = raw_bytes[inner_start:inner_end]
                    # naive scan for OCTET STRING (0x04) digest of typical sizes (32,48)
                    dig = None
                    pos = 0
                    while pos < len(comp):
                        if comp[pos] == 0x04:
                            ldig = parse_asn1_length_openssl(comp[pos+1:])
                            dlen = ldig['length']
                            dstart = pos + 1 + ldig['length_bytes']
                            dbytes = comp[dstart:dstart+dlen]
                            if dlen in (32, 48):
                                dig = dbytes.hex()
                                break
                            pos = dstart + dlen
                        else:
                            pos += 1
                    entries.append({"raw_hex": raw_bytes[off:inner_end].hex(), **({"digest": dig} if dig else {})})
                    off = inner_end
            except Exception as e:  # noqa: BLE001
                return {"error": f"fwids parse error: {e}", "raw_hex": raw_bytes.hex()}
            return {"count": len(entries), "entries": entries[:5]}

        def parse_integrity(raw_bytes):
            # Similar heuristic to fwids, but keep raw entries
            entries = []
            try:
                off = 0
                if off >= len(raw_bytes) or raw_bytes[off] != 0x30:
                    return {"raw_hex": raw_bytes.hex(), "note": "integrity not a SEQUENCE"}
                linfo = parse_asn1_length_openssl(raw_bytes[off+1:])
                seq_len = linfo['length']
                off = off + 1 + linfo['length_bytes']
                end = off + seq_len
                while off < end:
                    if raw_bytes[off] != 0x30:
                        break
                    l2 = parse_asn1_length_openssl(raw_bytes[off+1:])
                    inner_len = l2['length']
                    inner_start = off + 1 + l2['length_bytes']
                    inner_end = inner_start + inner_len
                    entries.append({"raw_hex": raw_bytes[off:inner_end].hex()})
                    off = inner_end
            except Exception as e:  # noqa: BLE001
                return {"error": f"integrity parse error: {e}", "raw_hex": raw_bytes.hex()}
            return {"count": len(entries), "entries": entries[:5]}

        while cursor < end_outer:
            tlv, next_off = read_tlv(data, cursor)
            if tlv is None:
                break
            cursor = next_off
            if tlv['class'] != 2:  # context-specific only
                continue
            tag = tlv['tag']
            if tag not in TAG_MAP:
                continue
            field_name, ftype = TAG_MAP[tag]
            val_bytes = tlv['value']
            try:
                if ftype == 'utf8':
                    fields[field_name] = parse_utf8(val_bytes)
                elif ftype == 'int':
                    # Always interpret svn (and any int field) using full bytes, then for svn specifically
                    # collapse to the last byte per simplified spec decision.
                    intval = parse_integer(val_bytes)
                    if field_name == 'svn':
                        fields['svn_raw_hex'] = val_bytes.hex()
                        if len(val_bytes) == 0:
                            fields[field_name] = 0
                        else:
                            fields[field_name] = val_bytes[-1]
                    else:
                        fields[field_name] = intval
                elif ftype == 'bitstring':
                    fields[field_name] = parse_bitstring(val_bytes)
                elif ftype == 'octets':
                    fields[field_name] = val_bytes.hex()
                elif ftype == 'seq_fwid':
                    fields[field_name] = parse_fwids(val_bytes)
                elif ftype == 'seq_integrity':
                    fields[field_name] = parse_integrity(val_bytes)
            except Exception as fe:  # noqa: BLE001
                fields[field_name] = {"error": str(fe), "raw_hex": val_bytes.hex()}

        result.update(fields)
        # Add digest scan (legacy) if fwids absent
        if 'fwids' not in result:
            legacy = extract_digest_from_tcb(data)
            if legacy:
                result['legacy_digests'] = legacy
    except Exception as e:  # noqa: BLE001
        result['parse_error'] = str(e)
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
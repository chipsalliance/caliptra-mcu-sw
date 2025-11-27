#!/usr/bin/env python3
"""Certificate display and parsing utilities for detailed certificate field extraction and display.

This module provides functionality to parse and display X.509 certificate fields
in a human-readable format, including support for TCG DICE extensions.
"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from asn1crypto import x509, core, algos


class Fwid(core.Sequence):
    """FWID ASN.1 structure - SEQUENCE { hashAlg OBJECT IDENTIFIER, digest OCTET STRING }"""
    _fields = [
        ('hash_alg', core.ObjectIdentifier),
        ('digest', core.OctetString),
    ]


class FwidList(core.SequenceOf):
    """FWIDLIST ASN.1 structure - SEQUENCE SIZE (1..MAX) OF FWID"""
    _child_spec = Fwid


class TcbInfo(core.Sequence):
    _fields = [
        ('vendor', core.UTF8String, {'implicit': 0, 'optional': True}),
        ('model', core.UTF8String, {'implicit': 1, 'optional': True}),
        ('version', core.UTF8String, {'implicit': 2, 'optional': True}),
        ('svn', core.Integer, {'implicit': 3, 'optional': True}),
        ('layer', core.Integer, {'implicit': 4, 'optional': True}),
        ('index', core.Integer, {'implicit': 5, 'optional': True}),
        ('fwids', FwidList, {'implicit': 6, 'optional': True}),
        ('flags', core.BitString, {'implicit': 7, 'optional': True}),
        ('vendor_info', core.OctetString, {'implicit': 8, 'optional': True}),
        ('tcb_type', core.OctetString, {'implicit': 9, 'optional': True}),
        ('flags_mask', core.BitString, {'implicit': 10, 'optional': True}),
    ]


class DiceTcbInfoSeq(core.SequenceOf):
    """DiceTcbInfoSeq ASN.1 structure - SEQUENCE SIZE (1..MAX) OF DiceTcbInfo"""
    _child_spec = TcbInfo

logger = logging.getLogger(__name__)

# Use asn1crypto to decode hash algorithm OIDs instead of manual mapping
def _get_hash_algorithm_name(oid_str: str) -> str:
    """Get hash algorithm name from OID using asn1crypto."""
    try:
        # Try to get the algorithm name from asn1crypto's built-in mappings
        alg_id = algos.DigestAlgorithmId(oid_str)
        # Convert to uppercase for consistent formatting (sha384 -> SHA-384)
        name = alg_id.native.upper()
        if name.startswith('SHA') and len(name) > 3 and name[3:].isdigit():
            return f"SHA-{name[3:]}"  # sha384 -> SHA-384
        return name
    except (ValueError, KeyError):
        # Fall back to the OID string if not recognized
        return oid_str

_TCG_DICE_OIDS = {
    "2.23.133.5.4.1": "tcg-dice-TcbInfo (OID:2.23.133.5.4.1)",
    "2.23.133.5.4.4": "tcg-dice-Ueid (OID:2.23.133.5.4.4)",
    "2.23.133.5.4.5": "tcg-dice-MultiTcbInfo (OID:2.23.133.5.4.5)",
}


def parse_tcg_dice_multi_tcbinfo(raw_data: bytes) -> Optional[List[Dict[str, Any]]]:
    """Parse TCG DICE MultiTcbInfo extension data - SEQUENCE OF TcbInfo."""
    try:
        # Parse using the defined schema
        multi_tcb_info = DiceTcbInfoSeq.load(raw_data)
        result = []
        
        for i, tcb_info in enumerate(multi_tcb_info):
            try:
                parsed_tcb = _parse_single_tcbinfo(tcb_info)
                if parsed_tcb:
                    logger.debug(f"Successfully parsed TcbInfo[{i}]: {parsed_tcb}")
                    result.append(parsed_tcb)
                else:
                    logger.warning(f"TcbInfo[{i}] parsed but returned no data")
            except Exception as tcb_error:
                logger.error(f"Failed to parse individual TcbInfo[{i}]: {str(tcb_error)}")
                # Re-raise the exception so caller can handle it
                raise tcb_error
        
        return result if result else None
        
    except Exception as e:
        logger.warning(f"Failed to parse MultiTcbInfo with schema: {e}")
        return None


def _parse_single_tcbinfo(tcb_info: TcbInfo) -> Optional[Dict[str, Any]]:
    """Parse a single TcbInfo structure and return the result dictionary."""
    result = {}
    
    # Extract only fields that are actually present (not None/empty)
    if tcb_info['vendor'] is not None and tcb_info['vendor'].native:
        result['vendor'] = tcb_info['vendor'].native
        
    if tcb_info['model'] is not None and tcb_info['model'].native:
        result['model'] = tcb_info['model'].native
        
    if tcb_info['version'] is not None and tcb_info['version'].native:
        result['version'] = tcb_info['version'].native
        
    if tcb_info['svn'] is not None:
        raw_svn = tcb_info['svn'].native
        if raw_svn is not None:
            # Decode fixed-width SVN: high byte should be 1, low byte is actual SVN
            actual_svn = raw_svn & 0xFF  # Extract low byte
            high_byte = (raw_svn >> 8) & 0xFF  # Extract high byte
            
            if high_byte == 1:
                result['svn'] = actual_svn
            else:
                # Unexpected format, show raw value
                result['svn'] = raw_svn
        else:
            # SVN field present but no value
            result['svn'] = None
        
    if tcb_info['layer'] is not None:
        result['layer'] = tcb_info['layer'].native
        
    if tcb_info['index'] is not None:
        result['index'] = tcb_info['index'].native
        
    if tcb_info['fwids'] is not None:
        # Parse FWID list - SEQUENCE OF FWID
        fwids_list = []
        try:
            for i, fwid in enumerate(tcb_info['fwids']):
                hash_alg_oid = fwid['hash_alg'].dotted
                hash_alg_name = _get_hash_algorithm_name(hash_alg_oid)
                fwid_info = {
                    'hashAlg': hash_alg_name,
                    'digest': f"0x{fwid['digest'].contents.hex()}"
                }
                fwids_list.append(fwid_info)
            result['fwids'] = fwids_list
        except Exception as e:
            logger.debug(f"Failed to parse individual FWIDs, showing raw: {e}")
            result['fwids'] = f"0x{tcb_info['fwids'].contents.hex()}"
        
    if tcb_info['flags'] is not None and tcb_info['flags'].contents:
        result['flags'] = f"0x{tcb_info['flags'].contents.hex()}"
        
    if tcb_info['vendor_info'] is not None and tcb_info['vendor_info'].contents:
        result['VendorInfo'] = f"0x{tcb_info['vendor_info'].contents.hex()}"
        
    if tcb_info['tcb_type'] is not None:
        try:
            # Try to decode as string
            text = tcb_info['tcb_type'].native.decode('utf-8')
            result['tcb_type'] = text if text.isprintable() else f"0x{tcb_info['tcb_type'].contents.hex()}"
        except:
            result['tcb_type'] = f"0x{tcb_info['tcb_type'].contents.hex()}"
            
    if tcb_info['flags_mask'] is not None and tcb_info['flags_mask'].contents:
        result['flags_mask'] = f"0x{tcb_info['flags_mask'].contents.hex()}"
        
    return result if result else None


def parse_tcg_dice_tcbinfo(raw_data: bytes) -> Optional[Dict[str, Any]]:
    """Parse TCG DICE TcbInfo extension data using asn1crypto schema.
    
    Based on Rust struct definition:
    TcbInfo ::= SEQUENCE {
        vendor      [0] IMPLICIT UTF8String OPTIONAL
        model       [1] IMPLICIT UTF8String OPTIONAL
        version     [2] IMPLICIT UTF8String OPTIONAL  
        svn         [3] IMPLICIT u32 OPTIONAL
        layer       [4] IMPLICIT u64 OPTIONAL
        index       [5] IMPLICIT u64 OPTIONAL
        fwids       [6] IMPLICIT SEQUENCE OF FWID OPTIONAL
        flags       [7] IMPLICIT BitString OPTIONAL
        vendor_info [8] IMPLICIT OCTET STRING OPTIONAL
        tcb_type    [9] IMPLICIT OCTET STRING OPTIONAL
        flags_mask  [10] IMPLICIT BitString OPTIONAL
    }
    """
    try:
        # Parse using the defined schema
        tcb_info = TcbInfo.load(raw_data)
        return _parse_single_tcbinfo(tcb_info)
        
    except Exception as e:
        logger.debug(f"Failed to parse TcbInfo with schema: {e}")
        return None


def parse_extension_value(ext_id: str, ext_value: Any) -> str:
    """Parse extension value with special handling for TCG DICE extensions."""
    # Try to get raw bytes - the extension value might be wrapped
    raw_bytes = None
    if isinstance(ext_value, bytes):
        raw_bytes = ext_value
    elif hasattr(ext_value, 'dump'):
        # It's an asn1crypto object, get the raw bytes
        raw_bytes = ext_value.dump()
    elif hasattr(ext_value, 'contents'):
        raw_bytes = ext_value.contents
    
    # Handle TCG DICE MultiTcbInfo extension
    if ext_id == "2.23.133.5.4.5":
        if raw_bytes:
            parsed_multi_tcbinfo = parse_tcg_dice_multi_tcbinfo(raw_bytes)
            if parsed_multi_tcbinfo:
                return _format_multi_tcbinfo_as_keyvalue(parsed_multi_tcbinfo)
        
        # If parsing failed, show the hex representation with note
        hex_data = raw_bytes.hex() if raw_bytes else str(ext_value)
        return f"0x{hex_data} (MultiTcbInfo parsing failed - showing raw data)"
    
    # Handle TCG DICE TcbInfo extension
    elif ext_id == "2.23.133.5.4.1":
        if raw_bytes:
            parsed_tcbinfo = parse_tcg_dice_tcbinfo(raw_bytes)
            if parsed_tcbinfo:
                return _format_tcbinfo_as_keyvalue(parsed_tcbinfo)
        
        # If parsing failed, show the hex representation with note
        hex_data = raw_bytes.hex() if raw_bytes else str(ext_value)
        return f"0x{hex_data} (TcbInfo parsing failed - showing raw data)"
    
    # Default formatting for other extensions
    return _format_ordered_dict(ext_value)

def parse_certchain(cert_chain: List[bytes], verbose: bool = False) -> bool:
    """Parse and log detailed certificate information from the chain."""
    try:
        certs = [x509.Certificate.load(der) for der in cert_chain]
        for i, cert in enumerate(certs):
            tbs_certificate = cert['tbs_certificate']
            signature = tbs_certificate['signature']
            issuer = tbs_certificate['issuer']
            validity = tbs_certificate['validity']
            subject = tbs_certificate['subject']
            subject_public_key_info = tbs_certificate['subject_public_key_info']
            subject_public_key_algorithm = subject_public_key_info['algorithm']
            subject_public_key = subject_public_key_info['public_key']
            extensions = tbs_certificate['extensions']
            
            logger.info("\n-------------------------- Certificate %d -------------------------", i)
            logger.info("Subject: %s", _format_ordered_dict(subject.native))
            logger.info("Issuer: %s", _format_ordered_dict(issuer.native))
            logger.info("Validity: %s", _format_ordered_dict(validity.native))
            logger.info("Signature Algorithm: %s", _format_ordered_dict(signature.native))
            logger.info("Public Key Algorithm: %s", _format_ordered_dict(subject_public_key_algorithm.native))
            logger.info("Public Key: %s", subject_public_key.native.hex() if hasattr(subject_public_key.native, 'hex') else _format_ordered_dict(subject_public_key.native))
            
            # Print extensions as individual key-value pairs
            if extensions.native:
                logger.info("Extensions:")
                for ext in extensions.native:
                    ext_id = ext.get('extn_id', 'Unknown')
                    critical = ext.get('critical', False)
                    ext_value = ext.get('extn_value', 'No value')
                    
                    # Use TCG DICE OID mapping if available, otherwise use the original ext_id
                    ext_name = _TCG_DICE_OIDS.get(ext_id, ext_id)
                    
                    # Parse extension value with special handling for TCG DICE extensions
                    formatted_value = parse_extension_value(ext_id, ext_value)
                    
                    logger.info("  %s (Critical: %s): %s", ext_name, critical, formatted_value)
            else:
                logger.info("Extensions: None")
            
            if verbose:
                logger.info("Full Certificate ASN.1:\n%s", cert.pretty_print())
                
    except Exception as e:
        logger.error("Failed to load certificates for parsing: %s", e)
        return False
    return True


def _format_multi_tcbinfo_as_keyvalue(multi_tcbinfo: List[Dict[str, Any]]) -> str:
    """Format MultiTcbInfo as key-value pairs for each TcbInfo entry."""
    lines = []
    for i, tcbinfo in enumerate(multi_tcbinfo):
        lines.append(f"  TcbInfo[{i}]:")
        for key, value in tcbinfo.items():
            if key == 'fwids' and isinstance(value, list):
                # Special formatting for FWID list
                lines.append(f"    {key}:")
                for j, fwid in enumerate(value):
                    lines.append(f"      FWID[{j}]:")
                    for fwid_key, fwid_value in fwid.items():
                        lines.append(f"        {fwid_key}: {fwid_value}")
            else:
                lines.append(f"    {key}: {value}")
    return "\n" + "\n".join(lines)


def _format_tcbinfo_as_keyvalue(tcbinfo: Dict[str, Any]) -> str:
    """Format TcbInfo as key-value pairs separated by newlines."""
    lines = []
    for key, value in tcbinfo.items():
        if key == 'fwids' and isinstance(value, list):
            # Special formatting for FWID list
            lines.append(f"    {key}:")
            for i, fwid in enumerate(value):
                lines.append(f"      FWID[{i}]:")
                for fwid_key, fwid_value in fwid.items():
                    lines.append(f"        {fwid_key}: {fwid_value}")
        else:
            lines.append(f"    {key}: {value}")
    return "\n" + "\n".join(lines)


def _format_ordered_dict(data) -> str:
    """Format OrderedDict or similar structures in a pretty way."""
    if hasattr(data, 'items'):
        # Handle dict-like objects (recursively format values)
        items = []
        for key, value in data.items():
            formatted_value = _format_ordered_dict(value) if hasattr(value, 'items') or isinstance(value, (list, tuple, set)) else str(value)
            items.append(f"{key}: {formatted_value}")
        return "{" + ", ".join(items) + "}"
    elif isinstance(data, (list, tuple)):
        # Handle list/tuple - recursively format each item
        items = []
        for item in data:
            if hasattr(item, 'items'):
                # This is a dict-like object, format it
                items.append(_format_ordered_dict(item))
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                key, value = item[0], item[1]
                formatted_value = _format_ordered_dict(value) if hasattr(value, 'items') or isinstance(value, (list, tuple, set)) else str(value)
                items.append(f"{key}: {formatted_value}")
            else:
                items.append(str(item))
        return "[" + ", ".join(items) + "]"
    elif isinstance(data, set):
        # Handle sets
        return "{" + ", ".join(sorted(str(item) for item in data)) + "}"
    elif isinstance(data, bytes):
        # Handle bytes objects - show as hex
        return f"0x{data.hex()}"
    else:
        return str(data)


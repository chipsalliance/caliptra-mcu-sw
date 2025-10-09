#!/usr/bin/env python3
"""
Reusable certificate parsing utilities extracted from signature validation logic.

Primary goals:
 - Parse an X.509 certificate (DER bytes) with OpenSSL first; fall back to cryptography.
 - Collect: cert object(s), public key(s), curve name (if EC), validity period, signature algorithm.
 - Enumerate and heuristically classify TCG DICE extensions without failing on unknown/critical ones.
 - Produce a structured result dictionary that higher-level callers can use for multiple certificates
   in a chain (e.g., AK cert, intermediate certs, root certs).

Returned structure (on success):
  {
    'openssl_cert': <OpenSSL.crypto.X509 or None>,
    'public_key_openssl': <OpenSSL PKey or None>,
    'verification_public_key': <cryptography public key or None>,
    'cryptography_cert': <cryptography.x509.Certificate or None>,
    'curve_name': 'secp384r1' | 'secp256r1' | 'unknown' | None,
    'not_before': 'YYYY-mm-dd ... UTC' | raw string,
    'not_after': '... UTC' | raw string,
    'sig_algorithm': str | None,
    'expired': bool,
    'subject_components': [(name, value), ...],
    'extensions': [ { 'index': i, 'name': str, 'critical': bool|None, 'is_tcg': bool, 'raw_len': int, 'parse': {...} }, ... ],
    'errors': [ str, ... ]
  }
On failure: result['errors'] non-empty and result['openssl_cert'] / keys may be None.

This module intentionally does NOT perform chain validation or signature verification.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Optional imports guarded at runtime
try:  # pyOpenSSL
    from OpenSSL import crypto
    _OPENSSL_AVAILABLE = True
except ImportError:
    _OPENSSL_AVAILABLE = False
    logger.debug("pyOpenSSL not available for certificate parsing")

try:  # cryptography
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    _CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    _CRYPTOGRAPHY_AVAILABLE = False
    logger.debug("cryptography not available for certificate fallback")

try:  # DICE extension helpers (optional)
    from openssl_dice_parser import (
        parse_dice_extension_openssl,
        get_tcg_dice_extension_names,
    )
    _DICE_HELPERS_AVAILABLE = True
except ImportError:
    _DICE_HELPERS_AVAILABLE = False
    logger.debug("OpenSSL DICE parser helpers not available")


# ---- Helper functions duplicated (lightweight) to avoid circular import ----
def _format_asn1_time(asn1_time_str: str) -> str:
    try:
        from datetime import datetime
        if asn1_time_str.endswith('Z'):
            time_str = asn1_time_str[:-1]
        else:
            time_str = asn1_time_str
        if len(time_str) == 14:
            dt = datetime.strptime(time_str, '%Y%m%d%H%M%S')
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        elif len(time_str) == 12:
            dt = datetime.strptime(time_str, '%y%m%d%H%M%S')
            if dt.year < 50:
                dt = dt.replace(year=dt.year + 2000)
            else:
                dt = dt.replace(year=dt.year + 1900)
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        return asn1_time_str
    except Exception:
        return asn1_time_str


def _get_standard_extension_oids():
    return {
        '2.5.29.19', '2.5.29.15', '2.5.29.37', '2.5.29.35', '2.5.29.14',
        '2.5.29.17', '2.5.29.18', '2.5.29.32', '2.5.29.31', '1.3.6.1.5.5.7.1.1'
    }


def _basic_der_fallback(raw_data: bytes):
    return {"parser": "basic_der", "raw_hex": raw_data.hex(), "note": "Basic DER parsing; install dice parser for richer output"}


def _parse_extension_data(ext_name: str, raw_data: bytes):
    if _DICE_HELPERS_AVAILABLE and "tcg-dice" in ext_name.lower():
        try:
            return parse_dice_extension_openssl(raw_data, ext_name)
        except Exception as e:  # noqa: BLE001
            logger.debug(f"DICE extension parse failed for {ext_name}: {e}")
    return _basic_der_fallback(raw_data)


def _map_extension_name(oid: str) -> str:
    if _DICE_HELPERS_AVAILABLE:
        try:
            names = get_tcg_dice_extension_names()
            if oid in names:
                return f"{names[oid]} (OID:{oid})"
        except Exception:  # noqa: BLE001
            pass
    return f"OID:{oid}"


# Explicit TCG DICE extension OIDs (per TCG spec) for deterministic mapping
_TCG_DICE_OIDS = {
    "2.23.133.5.4.1": "tcg-dice-TcbInfo (OID:2.23.133.5.4.1)",
    "2.23.133.5.4.4": "tcg-dice-Ueid (OID:2.23.133.5.4.4)",
    "2.23.133.5.4.5": "tcg-dice-MultiTcbInfo (OID:2.23.133.5.4.5)",
}


def _extract_tcbinfo_sequences(raw: bytes):
    """Best-effort extraction of nested TcbInfo sequences from a MultiTcbInfo / TcbInfo DER value.

    This does NOT perform full ASN.1 decoding; it walks DER SEQUENCE tags (0x30) and collects
    child sequence boundaries. For MultiTcbInfo (outer SEQUENCE of SEQUENCEs) it will return
    a list of dicts with size and a short hex preview. For a single TcbInfo it returns one entry.
    Any parse anomaly results in a simple note rather than raising.
    """
    entries = []
    try:
        if not raw or raw[0] != 0x30:
            return [{"note": "not a DER SEQUENCE", "preview": raw[:16].hex()}]
        # Helper to read length (supports short & long form)
        def read_len(buf, idx):
            if idx >= len(buf):
                return None, idx
            l = buf[idx]
            idx += 1
            if l & 0x80:
                nbytes = l & 0x7F
                if nbytes == 0 or idx + nbytes > len(buf):
                    return None, idx
                val = 0
                for _ in range(nbytes):
                    val = (val << 8) | buf[idx]
                    idx += 1
                return val, idx
            else:
                return l, idx
        # Outer sequence
        outer_len, pos = read_len(raw, 1)
        if outer_len is None or pos + outer_len > len(raw):
            return [{"note": "invalid outer length", "preview": raw[:16].hex()}]
        end_outer = pos + outer_len
        # Iterate child sequences
        while pos < end_outer:
            if raw[pos] != 0x30:
                # Skip unknown tag safely
                pos += 1
                continue
            child_start = pos
            clen, pos2 = read_len(raw, pos + 1)
            if clen is None:
                break
            child_content_start = pos2
            child_end = pos2 + clen
            if child_end > end_outer:
                break
            child_bytes = raw[child_start:child_end]
            entries.append({
                "size": len(child_bytes),
                "preview": child_bytes[:24].hex(),
            })
            pos = child_end
        if not entries:
            # Single TcbInfo case: treat entire body as one
            entries.append({"size": end_outer - pos, "preview": raw[pos:end_outer][:24].hex()})
    except Exception as e:  # noqa: BLE001
        return [{"note": f"tcbinfo parse error: {e}", "preview": raw[:24].hex()}]
    return entries


def parse_certificate(certificate_der: bytes, *, log: logging.Logger | None = None, list_extensions: bool = True, detailed: bool = False) -> dict:
    """
    Parse a DER-encoded certificate returning a structured dict.

    This isolates parsing concerns from signature logic, enabling reuse for chain handling.
    """
    log = log or logger
    result = {
        'openssl_cert': None,
        'public_key_openssl': None,
        'verification_public_key': None,
        'cryptography_cert': None,
        'curve_name': None,
        'not_before': None,
        'not_after': None,
        'sig_algorithm': None,
        'expired': None,
        'subject_components': [],
        'issuer_components': [],
        'extensions': [],
        'errors': [],
    }

    openssl_cert = None
    openssl_public_key = None
    crypto_cert = None

    # ---- OpenSSL primary parsing ----
    if _OPENSSL_AVAILABLE:
        try:
            openssl_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate_der)
            openssl_public_key = openssl_cert.get_pubkey()
        except Exception as e:  # noqa: BLE001
            # Try PEM workaround for some malformed DER encodings
            if "extension" in str(e).lower() or "critical" in str(e).lower():
                try:
                    import base64
                    pem_cert = b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(certificate_der) + b"\n-----END CERTIFICATE-----\n"
                    openssl_cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)
                    openssl_public_key = openssl_cert.get_pubkey()
                except Exception as e2:  # noqa: BLE001
                    result['errors'].append(f"OpenSSL parsing failed (PEM fallback): {e2}")
            else:
                result['errors'].append(f"OpenSSL parsing failed: {e}")
    else:
        result['errors'].append("pyOpenSSL not available")

    # ---- Cryptography fallback or augmentation ----
    if _CRYPTOGRAPHY_AVAILABLE:
        try:
            crypto_cert = x509.load_der_x509_certificate(certificate_der)
        except Exception as e:  # noqa: BLE001
            result['errors'].append(f"cryptography parsing failed: {e}")
    else:
        result['errors'].append("cryptography not available")

    # If we have OpenSSL cert, extract meta
    if openssl_cert:
        try:
            nb_raw = openssl_cert.get_notBefore().decode('ascii')
            na_raw = openssl_cert.get_notAfter().decode('ascii')
            result['not_before'] = _format_asn1_time(nb_raw)
            result['not_after'] = _format_asn1_time(na_raw)
        except Exception as e:  # noqa: BLE001
            result['errors'].append(f"time decode failed: {e}")
        try:
            result['sig_algorithm'] = openssl_cert.get_signature_algorithm().decode('ascii')
        except Exception:
            pass
        try:
            result['expired'] = openssl_cert.has_expired()
        except Exception:
            result['expired'] = None
        try:
            subject = openssl_cert.get_subject()
            for comp in subject.get_components():
                name, value = comp
                result['subject_components'].append((name.decode('ascii'), value.decode('ascii')))
        except Exception:
            pass
        try:
            issuer = openssl_cert.get_issuer()
            for comp in issuer.get_components():
                name, value = comp
                result['issuer_components'].append((name.decode('ascii'), value.decode('ascii')))
        except Exception:
            pass

        # Extensions enumeration (best-effort, never fatal)
        try:
            ext_count = openssl_cert.get_extension_count()
            crypto_oids = []
            if crypto_cert:
                for cext in crypto_cert.extensions:
                    crypto_oids.append(cext.oid.dotted_string)
            undef_idx = 0
            standard = _get_standard_extension_oids()
            for i in range(ext_count):
                entry = {
                    'index': i,
                    'name': None,
                    'critical': None,
                    'is_tcg': False,
                    'raw_len': None,
                    'parse': None,
                    'oid': None,
                }
                try:
                    ext = openssl_cert.get_extension(i)
                    try:
                        entry['name'] = ext.get_short_name().decode('ascii')
                    except Exception:
                        entry['name'] = 'UNKNOWN'
                    try:
                        entry['critical'] = bool(ext.get_critical())
                    except Exception:
                        entry['critical'] = None
                    # OID positional mapping
                    if i < len(crypto_oids):
                        oid = crypto_oids[i]
                        entry['oid'] = oid
                        if oid in _TCG_DICE_OIDS:
                            entry['name'] = _TCG_DICE_OIDS[oid]
                        elif oid not in standard and entry['name'] in ('UNDEF','UNKNOWN'):
                            entry['name'] = _map_extension_name(oid)
                    if entry['name'] == 'UNDEF' and undef_idx < len(crypto_oids):
                        for oid2 in crypto_oids[undef_idx:]:
                            if oid2 not in standard:
                                entry['oid'] = oid2
                                if oid2 in _TCG_DICE_OIDS:
                                    entry['name'] = _TCG_DICE_OIDS[oid2]
                                else:
                                    entry['name'] = _map_extension_name(oid2)
                                undef_idx = crypto_oids.index(oid2) + 1
                                break
                    raw = None
                    try:
                        raw = ext.get_data()
                        entry['raw_len'] = len(raw)
                        size = entry['raw_len']
                        # Size heuristics suppressed unless no OID match (we no longer force rename)
                        if (entry['oid'] is None or entry['oid'] not in _TCG_DICE_OIDS):
                            pass
                    except Exception:
                        pass
                    entry['is_tcg'] = (entry.get('oid') in _TCG_DICE_OIDS) or ('tcg-dice' in (entry['name'] or '').lower())
                    if raw is not None and entry['is_tcg']:
                        try:
                            entry['parse'] = _parse_extension_data(entry['name'], raw)
                        except Exception as e:  # noqa: BLE001
                            entry['parse'] = {'error': str(e)}
                        # Best-effort TcbInfo / MultiTcbInfo extraction when OID explicit and dice parser absent or minimal
                        try:
                            if entry.get('oid') in ("2.23.133.5.4.1", "2.23.133.5.4.5"):
                                # Only add if not already richly parsed
                                if 'tcb_entries' not in entry['parse']:
                                    entry['parse']['tcb_entries'] = _extract_tcbinfo_sequences(raw)
                        except Exception as te:  # noqa: BLE001
                            entry['parse'].setdefault('tcb_info_note', f"tcb parsing fallback error: {te}")
                except Exception as e:  # noqa: BLE001
                    entry['parse'] = {'error': f'extension access failed: {e}'}
                result['extensions'].append(entry)
        except Exception as e:  # noqa: BLE001
            result['errors'].append(f"extension enumeration failed: {e}")

    # Determine curve name (only for EC) via OpenSSL key bits if possible
    curve_name = None
    if openssl_public_key is not None:
        try:
            bits = openssl_public_key.bits()
            if bits == 384:
                curve_name = 'secp384r1'
            elif bits == 256:
                curve_name = 'secp256r1'
            else:
                curve_name = 'unknown'
        except Exception:
            pass

    verification_public_key = None
    if _CRYPTOGRAPHY_AVAILABLE and openssl_public_key is not None:
        try:
            pk_der = crypto.dump_publickey(crypto.FILETYPE_ASN1, openssl_public_key)
            verification_public_key = serialization.load_der_public_key(pk_der)
        except Exception as e:  # noqa: BLE001
            result['errors'].append(f"public key DER load failed: {e}")

    # Populate result
    result['openssl_cert'] = openssl_cert
    result['public_key_openssl'] = openssl_public_key
    result['cryptography_cert'] = crypto_cert
    result['verification_public_key'] = verification_public_key
    result['curve_name'] = curve_name

    # Emit extension summary if requested
    if list_extensions and result['extensions']:
        try:
            if detailed:
                log.info("  Extensions:")
            for ext in result['extensions']:
                name = ext.get('name') or 'UNKNOWN'
                crit = ext.get('critical')
                crit_str = 'critical' if crit else 'non-critical' if crit is not None else 'unknown-criticality'
                size = ext.get('raw_len')
                prefix = 'TCG' if ext.get('is_tcg') else 'STD'
                if detailed:
                    log.info(f"    [{ext['index']:02d}] {prefix} {name} ({crit_str}, {size if size is not None else '?'} bytes)")
                # if detailed and ext.get('parse'):
                    # Dump parsed fields at DEBUG to avoid overwhelming normal INFO stream
                    # log.debug(f"       parsed: {ext['parse']}")
        except Exception:  # noqa: BLE001
            pass

    return result


__all__ = [
    'parse_certificate',
]

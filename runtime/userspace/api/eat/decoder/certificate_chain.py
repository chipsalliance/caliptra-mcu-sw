#!/usr/bin/env python3
"""Certificate chain assembly and lightweight validation utilities.

Builds an ordered chain from a provided leaf (attestation / AK certificate) plus
locally stored DER files (if present) in the fixed search order:
    [ leaf, RT_CERT, FMC_CERT, LDEVID_CERT, IDEVID_CERT, ROOT_CA ]

Missing files are silently skipped. Chain validation is intentionally *lightweight*:
 - Expiration check
 - basicConstraints CA checks for intermediates & root
 - Issuer/Subject linkage (with relaxed DN comparison & normalization)
 - Signature verification (cryptography, with OpenSSL fallback)
 - Root self-issued check
 - Diagnostic SKI/AKI correlation (including derived SKI when missing)
 - Detailed ASN.1 dumps for DN mismatches

The heavier PKIX features (policies, path length, EKU, revocation) are out of scope
for this helper.
"""
from __future__ import annotations

import logging
import os
from typing import List, Tuple, Dict

logger = logging.getLogger(__name__)

_SEARCH_ORDER = [
    'cert4.der',
    'cert3.der',
    'cert2.der',
    'cert1.der',
    'cert0.der',
]

def get_local_certificate_chain(leaf_certificate: bytes, directory: str = '.') -> List[bytes]:
    """Return chain list starting with provided leaf then discovered local certs."""
    chain: List[bytes] = [leaf_certificate]
    for fname in _SEARCH_ORDER:
        path = os.path.join(directory, fname)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, 'rb') as f:
                data = f.read()
            if data:
                chain.append(data)
                logger.info("Added certificate from %s (size=%d bytes)", fname, len(data))
            else:
                logger.warning("File %s is empty; skipping", fname)
        except OSError as e:  # noqa: BLE001
            logger.warning("Could not read %s: %s", fname, e)
    logger.info("Constructed chain of %d cert(s) (leaf + %d additional)", len(chain), len(chain)-1)
    return chain


def assemble_and_parse_chain(leaf_cert: bytes, directory: str = '.', verbose: bool = False) -> Tuple[List[bytes], List[Dict]]:
    """Assemble local chain and parse each certificate if parser available."""
    chain = get_local_certificate_chain(leaf_cert, directory=directory)
    try:
        from certificate_parser import parse_certificate  # type: ignore
        parser_available = True
    except ImportError:
        parser_available = False
        logger.warning("certificate_parser module not available; skipping certificate parsing stage")

    if not parser_available:
        return chain, []

    detailed = logger.isEnabledFor(logging.DEBUG) or verbose
    parsed: List[Dict] = []
    logger.info("[Cert Idx :SubjectCN] : |Role | Size | Curve |Expired | IssuerCN | Extensions | Errors")

    for idx, der in enumerate(chain):
        role = 'leaf' if idx == 0 else ('root' if idx == len(chain)-1 else 'intermediate')
        try:
            meta = parse_certificate(der, log=logger, list_extensions=True, detailed=True, log_extensions=False)
            subject_components = meta.get('subject_components') or []
            issuer_components = meta.get('issuer_components') or []

            def _first_cn(components):
                for name, value in components:
                    if name.lower() in ('cn', 'commonname', 'common name'):
                        return value
                return components[0][1] if components else ''

            subj_cn = _first_cn(subject_components)
            issuer_cn_raw = _first_cn(issuer_components)
            if not issuer_cn_raw:
                if issuer_components:
                    issuer_cn = ";".join(f"{k}={v}" for k, v in issuer_components[:3])
                else:
                    issuer_cn = "-"
            else:
                issuer_cn = issuer_cn_raw
            curve = meta.get('curve_name') or 'unk'
            expired = 'Y' if meta.get('expired') else 'N'
            exts = len(meta.get('extensions', []))
            errors = meta.get('errors')
            meta_summary: Dict = {
                'index': idx,
                'role': role,
                'curve': curve,
                'expired': meta.get('expired'),
                'subject': subject_components,
                'issuer': issuer_components,
                'extensions': exts,
            }
            if errors:
                meta_summary['errors'] = errors
            parsed.append(meta_summary)
            idx_token = f"[Cert {idx}: {subj_cn}] :"
            logger.info("%s | %s | %d | %s | expired:%s | issuer:%s | extensions:%d | %s",
                        idx_token, role, len(der), curve, expired, issuer_cn, exts,
                        '|' .join(errors) if errors else '-')
            # Now log extensions AFTER the cert summary (reversing prior order)
            ex_list = meta.get('extensions') or []
            if ex_list:
                logger.info("  Extensions:")
                for ext in ex_list:
                    name = ext.get('name') or 'UNKNOWN'
                    crit = ext.get('critical')
                    crit_str = 'critical' if crit else 'non-critical' if crit is not None else 'unknown-criticality'
                    size = ext.get('raw_len')
                    prefix = 'TCG' if ext.get('is_tcg') else 'STD'
                    parsed_full = ext.get('parse') or {}
                    try:
                        if ext.get('is_tcg') and 'Ueid' in (name or '') and 'ueid_hex' in parsed_full:
                            logger.info(f"    [{ext['index']:02d}] {prefix} {name} ({crit_str}) :: ueid={parsed_full['ueid_hex']}")
                        elif ext.get('is_tcg') and 'MultiTcbInfo' in (name or ''):
                            tcb_count = parsed_full.get('tcb_count') or len(parsed_full.get('tcb_entries', []))
                            entries = parsed_full.get('tcb_entries', [])
                            parts = [f"tcb_count={tcb_count}"]
                            # Add digest previews (first up to 2 entries)
                            for e in entries[:2]:
                                digests = e.get('digests') or []
                                if digests:
                                    parts.append(f"tcb{e.get('index',0)}_digest={digests[0][:12]}...")
                            # Inline first two entries key fields
                            def summarize_entry(e):
                                kv_inline = []
                                for fld in ('vendor','model','version','svn','layer','index'):
                                    if fld in e and e[fld] not in (None,''):
                                        val = e[fld]
                                        if isinstance(val, dict):
                                            if fld == 'fwids':
                                                c = val.get('count') or len(val.get('entries', [])) if isinstance(val.get('entries'), list) else None
                                                val = f"count={c}" if c is not None else 'present'
                                            else:
                                                val = 'present'
                                        elif fld == 'svn' and isinstance(val, int):
                                            val = hex(val)
                                        kv_inline.append(f"{fld}={val}")
                                if 'tci_type' in e and isinstance(e['tci_type'], str):
                                    raw_hex_candidate = e['tci_type']
                                    if all(ch in '0123456789abcdefABCDEF' for ch in raw_hex_candidate) and len(raw_hex_candidate) % 2 == 0:
                                        try:
                                            raw_bytes = bytes.fromhex(raw_hex_candidate)
                                            if raw_bytes and all(32 <= b < 127 for b in raw_bytes):
                                                kv_inline.append(f"tci_type={raw_bytes.decode('ascii')}")
                                        except Exception:  # noqa: BLE001
                                            pass
                                return kv_inline
                            if entries:
                                kv1 = summarize_entry(entries[0])
                                if kv1:
                                    parts.append('first={' + ','.join(kv1) + '}')
                            if len(entries) > 1:
                                kv2 = summarize_entry(entries[1])
                                if kv2:
                                    parts.append('second={' + ','.join(kv2) + '}')
                            logger.info(f"    [{ext['index']:02d}] {prefix} {name} ({crit_str}) :: {' | '.join(parts)}")
                        elif ext.get('is_tcg') and 'TcbInfo' in (name or ''):
                            field_order = ['vendor','model','version','svn','layer','index','fwids','flags','vendor_info','tci_type','integrity_registers']
                            kv = []
                            for fld in field_order:
                                if fld in parsed_full and parsed_full[fld] is not None:
                                    val = parsed_full[fld]
                                    if isinstance(val, dict):
                                        if fld == 'fwids':
                                            c = val.get('count') or len(val.get('entries', [])) if isinstance(val.get('entries'), list) else None
                                            val = f"count={c}" if c is not None else 'present'
                                        elif fld == 'integrity_registers':
                                            c = val.get('count') or len(val.get('entries', [])) if isinstance(val.get('entries'), list) else None
                                            val = f"count={c}" if c is not None else 'present'
                                        elif fld == 'flags':
                                            val = val.get('hex')
                                        else:
                                            val = 'present'
                                    elif fld == 'svn' and isinstance(val, int):
                                        val = hex(val)
                                    if fld in ('vendor_info','tci_type') and isinstance(parsed_full[fld], str):
                                        raw_hex_candidate = parsed_full[fld]
                                        if all(ch in '0123456789abcdefABCDEF' for ch in raw_hex_candidate) and len(raw_hex_candidate) % 2 == 0:
                                            try:
                                                raw_bytes = bytes.fromhex(raw_hex_candidate)
                                                if raw_bytes and all(32 <= b < 127 for b in raw_bytes):
                                                    val = raw_bytes.decode('ascii')
                                            except Exception:  # noqa: BLE001
                                                pass
                                    kv.append(f"{fld}={val}")
                            if 'legacy_digests' in parsed_full and 'digests_found' in parsed_full['legacy_digests']:
                                kv.append(f"legacy_digests={parsed_full['legacy_digests'].get('digests_found')}")
                            logger.info(f"    [{ext['index']:02d}] {prefix} {name} ({crit_str}) :: {' | '.join(kv) if kv else 'no-fields'}")
                        else:
                            logger.info(f"    [{ext['index']:02d}] {prefix} {name} ({crit_str}, {size if size is not None else '?'} bytes)")
                        if logger.isEnabledFor(logging.DEBUG) and ext.get('parse'):
                            logger.debug(f"       parsed(full): {ext['parse']}")
                    except Exception as elog:  # noqa: BLE001
                        logger.debug("Extension log error: %s", elog)
        except Exception as e:  # noqa: BLE001
            logger.error("Failed to parse certificate index %d: %s", idx, e)

    try:
        chain_valid, issues = _validate_certificate_chain(chain)
        if chain_valid:
            logger.info("Certificate chain validation: SUCCESS")
        else:
            logger.warning("Certificate chain validation: FAILED (%d issue(s))", len(issues))
            for iss in issues:
                logger.warning("  - %s", iss)
        if parsed:
            parsed[0]['chain_valid'] = chain_valid
            if issues:
                parsed[0]['chain_issues'] = issues
    except Exception as e:  # noqa: BLE001
        logger.error("Chain validation error: %s", e)
        if parsed:
            parsed[0]['chain_valid'] = False
            parsed[0]['chain_issues'] = [str(e)]
    return chain, parsed


def _validate_certificate_chain(chain: List[bytes]) -> Tuple[bool, List[str]]:
    """Lightweight validation & diagnostics over chain (leaf -> root)."""
    issues: List[str] = []
    try:
        from OpenSSL import crypto  # type: ignore
    except Exception as e:  # noqa: BLE001
        return False, [f"OpenSSL unavailable: {e}"]

    openssl_certs = []
    for idx, der in enumerate(chain):
        try:
            openssl_certs.append(crypto.load_certificate(crypto.FILETYPE_ASN1, der))
        except Exception as e:  # noqa: BLE001
            issues.append(f"Cert {idx} load failed: {e}")
            return False, issues

    # Expiration & basicConstraints
    for idx, cert in enumerate(openssl_certs):
        try:
            if cert.has_expired():
                issues.append(f"Cert {idx} expired")
        except Exception:
            pass
        try:
            for i in range(cert.get_extension_count()):
                ext = cert.get_extension(i)
                name = ext.get_short_name().decode('ascii', 'ignore').lower()
                if name == 'basicconstraints':
                    val = str(ext)
                    if idx != 0 and 'CA:TRUE' not in val:
                        issues.append(f"Cert {idx} missing CA:TRUE")
        except Exception:
            pass

    # Signature + linkage
    try:
        from cryptography import x509 as c_x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
        from cryptography.hazmat.primitives import serialization
    except Exception as e:  # noqa: BLE001
        issues.append(f"cryptography unavailable for signature checks: {e}")
        return False, issues

    def _name(cert, which: str) -> str:
        try:
            obj = cert.get_subject() if which == 'subject' else cert.get_issuer()
            for c in obj.get_components():
                k, v = c
                if k.decode('ascii', 'ignore').lower() == 'cn':
                    return v.decode('utf-8','ignore')
            comps = []
            for c in obj.get_components()[:3]:
                k, v = c
                comps.append(f"{k.decode('ascii','ignore')}={v.decode('utf-8','ignore')}")
            return ';'.join(comps) if comps else '?'
        except Exception:
            return '?'

    def _dn_components(cert, which: str):
        try:
            obj = cert.get_subject() if which == 'subject' else cert.get_issuer()
            return [(k.decode('ascii','ignore').lower(), v.decode('utf-8','ignore')) for k,v in obj.get_components()]
        except Exception:
            return []

    def _dump_name_asn1(cert, which: str) -> str:
        try:
            from cryptography import x509 as c_x509  # type: ignore
            from cryptography.x509.oid import NameOID  # type: ignore
            x = c_x509.load_der_x509_certificate(crypto.dump_certificate(crypto.FILETYPE_ASN1, cert))
            name = x.subject if which == 'subject' else x.issuer
            lines = [f"Name ({which}) RDNSequence (len={len(name.rdns)})"]
            for rdn_idx, rdn in enumerate(name.rdns):
                lines.append(f"  RDN[{rdn_idx}] SET size={len(rdn)}")
                for attr_idx, attr in enumerate(rdn):
                    oid = attr.oid.dotted_string
                    try:
                        from cryptography.x509.oid import NameOID as _NO
                        mapping = {
                            _NO.COMMON_NAME: 'CN', _NO.ORGANIZATION_NAME: 'O', _NO.ORGANIZATIONAL_UNIT_NAME: 'OU',
                            _NO.COUNTRY_NAME: 'C', _NO.STATE_OR_PROVINCE_NAME: 'ST', _NO.LOCALITY_NAME: 'L',
                            _NO.SERIAL_NUMBER: 'serialNumber'
                        }
                        oname = mapping.get(attr.oid, oid)
                    except Exception:
                        oname = oid
                    lines.append(f"    [{attr_idx}] OID={oid} ({oname}) :: {attr.value}")
            return '\n'.join(lines)
        except Exception as e:  # noqa: BLE001
            try:
                obj = cert.get_subject() if which == 'subject' else cert.get_issuer()
                comps = [f"{k.decode('ascii','ignore')}={v.decode('utf-8','ignore')}" for k,v in obj.get_components()]
                return f"Name ({which}) fallback components: '" + ', '.join(comps) + f"' (error decoding structured: {e})"
            except Exception as e2:  # noqa: BLE001
                return f"Name ({which}) <unavailable> ({e}/{e2})"

    def _dn_cmp_relaxed(child_issuer_comps, issuer_subject_comps):
        if not child_issuer_comps or not issuer_subject_comps:
            return False
        canon = { 'cn','o','c','st','serialnumber' }
        ignorable_prefix = {'cn','sn','serialnumber'}
        def strip_leading_ignorable(seq):
            i = 0
            while i < len(seq) and seq[i][0] in ignorable_prefix:
                i += 1
            return seq[i:]
        child_stripped = strip_leading_ignorable(child_issuer_comps)
        issuer_stripped = strip_leading_ignorable(issuer_subject_comps)
        child_f = [(a,v) for a,v in child_stripped if a in canon]
        issuer_f = [(a,v) for a,v in issuer_stripped if a in canon]
        child_set = set(child_f)
        issuer_set = set(issuer_f)
        if child_set and child_set.issubset(issuer_set):
            child_cn = next((v for a,v in child_f if a=='cn'), None)
            issuer_cn = next((v for a,v in issuer_f if a=='cn'), None)
            if child_cn and issuer_cn and child_cn == issuer_cn:
                return True
        return False

    for idx in range(len(openssl_certs)-1):
        child = openssl_certs[idx]
        issuer = openssl_certs[idx+1]
        child_subj = _name(child, 'subject')
        child_iss = _name(child, 'issuer')
        issuer_subj = _name(issuer, 'subject')
        if child.get_issuer().der() != issuer.get_subject().der():
            child_iss_norm = child_iss.replace(' ','').lower()
            issuer_subj_norm = issuer_subj.replace(' ','').lower()
            comps_child = _dn_components(child,'issuer')
            comps_issuer = _dn_components(issuer,'subject')
            if not (child_iss_norm == issuer_subj_norm or _dn_cmp_relaxed(comps_child, comps_issuer)):
                detail = "(text equal after normalization)" if child_iss_norm == issuer_subj_norm else f"components_child={comps_child}; components_issuer={comps_issuer}"
                dump_child = _dump_name_asn1(child, 'issuer')
                dump_issuer = _dump_name_asn1(issuer, 'subject')
                asn1_block = f"\n------ child {idx} issuer ASN.1 ------\n{dump_child}\n------ issuer {idx+1} subject ASN.1 ------\n{dump_issuer}"
                issues.append(f"Issuer/Subject mismatch: child {idx} issuer DN ({child_iss}) != issuer {idx+1} subject DN ({issuer_subj}) {detail}{asn1_block}")
        # Attempt signature verification (may be skipped if cryptography cannot parse)
        try:
            child_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, child)
            issuer_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, issuer)
            child_c = c_x509.load_der_x509_certificate(child_der)
            issuer_c = c_x509.load_der_x509_certificate(issuer_der)
            pub = issuer_c.public_key()
            sig = child_c.signature
            tbs = child_c.tbs_certificate_bytes
            sig_hash = child_c.signature_hash_algorithm
            if isinstance(pub, ec.EllipticCurvePublicKey):
                try:
                    pub.verify(sig, tbs, ec.ECDSA(sig_hash))
                except Exception as primary_err:
                    try:
                        # Attempt OpenSSL fallback
                        crypto.verify(issuer, sig, tbs, sig_hash.name.replace('sha','sha'))
                    except Exception:
                        raise primary_err
            elif isinstance(pub, rsa.RSAPublicKey):
                pub.verify(sig, tbs, padding.PKCS1v15(), sig_hash)
            else:
                issues.append(f"Unsupported public key type in issuer {idx+1}")
        except Exception as e:  # noqa: BLE001
            diag_lines = []
            try:
                from cryptography.x509.oid import ExtensionOID  # type: ignore
                aki = None; ski = None; derived_ski = None
                # If parsing failed before child_c / issuer_c assignment, skip deeper diagnostics
                child_c_defined = 'child_c' in locals()
                issuer_c_defined = 'issuer_c' in locals()
                try:
                    if child_c_defined:
                        ext_aki = child_c.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
                        aki = ext_aki.value.key_identifier.hex() if ext_aki.value.key_identifier else None
                except Exception:  # noqa: BLE001
                    pass
                try:
                    if issuer_c_defined:
                        ext_ski = issuer_c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
                        ski = ext_ski.value.digest.hex()
                except Exception:  # noqa: BLE001
                    pass
                if ski is None and issuer_c_defined:
                    try:
                        from cryptography.hazmat.primitives import hashes as _hashes
                        spki_der = issuer_c.public_key().public_bytes(
                            encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        )  # type: ignore[arg-type]
                        h = _hashes.Hash(_hashes.SHA1())  # legacy SKI derivation
                        h.update(spki_der)  # noqa: SIM115
                        derived_ski = h.finalize().hex()
                    except Exception:  # noqa: BLE001
                        pass
                if aki or ski or derived_ski:
                    effective_ski = ski or derived_ski
                    match = 'N/A'
                    if aki and effective_ski:
                        match = 'YES' if aki == effective_ski else 'NO'
                    diag_lines.append(f"AKI(child)={aki or 'None'} SKI(issuer)={ski or 'None'} derivedSKI={derived_ski or 'None'} match={match}")
                if child_c_defined:
                    try:
                        sig = child_c.signature
                        tbs = child_c.tbs_certificate_bytes
                        # We may not have pub/sig_hash if earlier steps failed
                        if 'sig_hash' in locals() and getattr(sig_hash, 'name', '').lower() == 'sha384':
                            import hashlib
                            tbs_digest = hashlib.sha384(tbs).hexdigest()
                            diag_lines.append(f"TBS.sha384={tbs_digest[:32]}.. len={len(tbs)}")
                        if sig:
                            diag_lines.append(f"sig.len={len(sig)} sig.head={sig[:8].hex()}")
                    except Exception:  # noqa: BLE001
                        pass
                if 'pub' in locals():
                    try:
                        if isinstance(pub, ec.EllipticCurvePublicKey):
                            diag_lines.append(f"issuer.pub=EC {pub.curve.name}")
                        elif isinstance(pub, rsa.RSAPublicKey):
                            diag_lines.append(f"issuer.pub=RSA {pub.key_size} bits")
                    except Exception:  # noqa: BLE001
                        pass
            except Exception as diag_err:  # noqa: BLE001
                diag_lines.append(f"(diagnostic error: {diag_err})")
            # If the only failure reason is cryptography parse error, downgrade to warning (OpenSSL loaded it)
            msg_text = str(e)
            if 'ParseError' in msg_text and 'crypto.' not in msg_text:
                issues.append(
                    f"Signature check skipped (cryptography parse error) for cert {idx} subject={child_subj} issuerExpected={issuer_subj}: {e}\n    "
                    + " | ".join(diag_lines)
                )
            else:
                issues.append(
                    f"Signature verify failed: cert {idx} subject={child_subj} issuerExpected={issuer_subj} (issuer index {idx+1}): {e}\n    "
                    + " | ".join(diag_lines)
                )

    if openssl_certs:
        root = openssl_certs[-1]
        if root.get_subject().der() != root.get_issuer().der():
            issues.append("Root not self-issued")

    return len(issues) == 0, issues

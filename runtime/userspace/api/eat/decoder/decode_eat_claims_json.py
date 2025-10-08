#!/usr/bin/env python3
"""EAT claims to JSON extractor (standalone)

This module duplicates (intentionally) a minimal subset of the logic in
`decode.py` but instead of printing a human readable walk, it produces a
clean JSON dictionary of the claims contained in an EAT / COSE_Sign1 token.

Design goals:
  * Do NOT emit CBOR tag wrapper information (e.g. omit tag numbers 55799, 61, 18, 571, 111 etc.)
  * For tagged OID (tag 111) values, just return the textual OID string
  * Use short snake_case claim keys (same convention as earlier tooling)
  * Keep measurement claim (273) content faithful without adding artificial metadata
  * Pure Python, no external CBOR library dependencies

Notes:
  * This parser is intentionally conservative: it only implements what is
    currently observed in the provided tokens. Unknown / future structures
    are captured via simple fallbacks.
    * Concise Evidence (inside measurements) is now recursively parsed to a
        structured JSON object (environment / class / measurements) mirroring
        the logic in decode.py but without the pretty-printed text lines and
        without including CBOR tag numbers in the final JSON values.
"""

import sys
import struct
import json
from typing import Tuple, Any, Dict


# ------------------------- CBOR PRIMITIVES ------------------------- #

def parse_cbor_header(data: bytes, offset: int = 0) -> Tuple[Tuple[int, int] | None, int]:
    if offset >= len(data):
        return None, offset
    initial = data[offset]
    major = (initial >> 5) & 0x7
    ai = initial & 0x1F
    offset += 1
    if ai < 24:
        value = ai
    elif ai == 24:
        value = data[offset]
        offset += 1
    elif ai == 25:
        value = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
    elif ai == 26:
        value = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
    elif ai == 27:
        value = struct.unpack('>Q', data[offset:offset+8])[0]
        offset += 8
    else:
        # indefinite or reserved – not expected in current tokens
        value = ai
    return (major, value), offset


def skip_cbor_tags(data: bytes) -> bytes:
    """Strip leading tag layers, return the first non-tag major type slice."""
    offset = 0
    while offset < len(data):
        hdr, new_off = parse_cbor_header(data, offset)
        if not hdr:
            break
        major, value = hdr
        if major == 6:  # tag
            offset = new_off
            continue
        return data[offset:]
    return data


# ----------------------- EAT CLAIM NAME MAP ----------------------- #

EAT_CLAIM_NAMES = {
    1: "iss (Issuer)",
    2: "sub (Subject)",
    3: "aud (Audience)",
    4: "exp (Expiration Time)",
    5: "nbf (Not Before)",
    6: "iat (Issued At)",
    7: "cti (CWT ID)",
    8: "cnf (Confirmation)",
    10: "nonce",
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
}


def clean_claim_key(k: int | str) -> str:
    if isinstance(k, int):
        name = EAT_CLAIM_NAMES.get(k, f"claim-{k}")
        if '(' in name:
            name = name.split('(')[0].strip()
        return name.lower().replace(' ', '_').replace('-', '_')
    return str(k).lower().replace(' ', '_').replace('-', '_')


# ----------------------- GENERIC VALUE PARSER --------------------- #

def parse_value(payload: bytes, offset: int, major: int, value: int) -> Tuple[Any, int]:
    """Return a native Python value ignoring tag wrappers in final output.
    For tags (major=6) we parse the tagged item and just return its underlying
    semantic value (e.g. OID string for tag 111 if text)."""
    if major == 0:  # unsigned int
        return value, offset
    if major == 1:  # negative int
        return -1 - value, offset
    if major == 2:  # byte string
        b = payload[offset:offset+value]
        return b.hex(), offset + value
    if major == 3:  # text string
        b = payload[offset:offset+value]
        try:
            return b.decode('utf-8'), offset + value
        except UnicodeDecodeError:
            return b.hex(), offset + value
    if major == 4:  # array
        arr = []
        cur = offset
        for _ in range(value):
            hdr, cur = parse_cbor_header(payload, cur)
            if not hdr:
                break
            m2, v2 = hdr
            val, cur = parse_value(payload, cur, m2, v2)
            arr.append(val)
        return arr, cur
    if major == 5:  # map
        mp: Dict[Any, Any] = {}
        cur = offset
        for _ in range(value):
            k_hdr, cur = parse_cbor_header(payload, cur)
            if not k_hdr:
                break
            km, kv = k_hdr
            k_val, cur = parse_value(payload, cur, km, kv)
            v_hdr, cur = parse_cbor_header(payload, cur)
            if not v_hdr:
                break
            vm, vv = v_hdr
            v_val, cur = parse_value(payload, cur, vm, vv)
            mp[k_val] = v_val
        return mp, cur
    if major == 6:  # tag – consume the tagged item and just return its parsed value
        tagged_hdr, new_off = parse_cbor_header(payload, offset)
        if not tagged_hdr:
            return None, offset
        tm, tv = tagged_hdr
        inner, final_off = parse_value(payload, new_off, tm, tv)
        return inner, final_off
    if major == 7:  # simple / float / bool / null (restricted subset)
        if value == 20:
            return False, offset
        if value == 21:
            return True, offset
        if value == 22:
            return None, offset
        return value, offset
    return value, offset


# ----------------------- MEASUREMENT HELPERS ---------------------- #

def parse_measurements_array(meas_array: list) -> list:
    """Interpret the measurements claim (array of MeasurementFormat arrays)."""
    out = []
    for entry in meas_array:
        if not isinstance(entry, list) or len(entry) < 2:
            out.append({"raw": entry})
            continue
        content_type = entry[0]
        concise_raw = entry[1]
        parsed = {"content_type": content_type}
        if isinstance(concise_raw, str):  # hex of concise evidence bstr
            try:
                ce_bytes = bytes.fromhex(concise_raw)
                parsed["concise_evidence"] = parse_concise_evidence_bytes(ce_bytes)
            except ValueError:
                parsed["concise_evidence"] = {"error": "invalid_hex", "raw_hex": concise_raw}
        else:
            parsed["concise_evidence"] = {"error": "unexpected_concise_evidence_format", "raw": concise_raw}
        # Preserve trailing elements if any (future extension fields)
        if len(entry) > 2:
            parsed["extra"] = entry[2:]
        out.append(parsed)
    return out


# ----------------------- CLAIMS PARSER CORE ----------------------- #

def parse_eat_claims_to_dict(payload: bytes) -> Dict[str, Any]:
    """Parse the CBOR EAT claims map into a JSON friendly dict.
    Assumes `payload` is the COSE Sign1 payload (already extracted)."""
    offset = 0
    header, offset = parse_cbor_header(payload, offset)
    if not header or header[0] != 5:
        return {"error": "payload_not_cbor_map"}
    num_pairs = header[1]
    claims: Dict[str, Any] = {}
    for _ in range(num_pairs):
        k_hdr, offset = parse_cbor_header(payload, offset)
        if not k_hdr:
            break
        km, kv = k_hdr
        key_val, offset = parse_value(payload, offset, km, kv)
        v_hdr, offset = parse_cbor_header(payload, offset)
        if not v_hdr:
            break
        vm, vv = v_hdr
        val, offset = parse_value(payload, offset, vm, vv)
        clean_key = clean_claim_key(key_val)
        # Special handling: measurements claim (numeric 273 or name)
        if (isinstance(key_val, int) and key_val == 273) or clean_key == "measurements":
            if isinstance(val, list):
                val = parse_measurements_array(val)
        claims[clean_key] = val
    # Post-process select claims for readability
    if 'eat_profile' in claims:
        from inspect import isfunction  # local import not expensive; ensure helper exists
        if '_maybe_hex_ascii' in globals():
            try:
                claims['eat_profile'] = _maybe_hex_ascii(claims['eat_profile'])
            except Exception:
                pass
    return claims


# ----------------------- COSE STRUCTURE PARSER -------------------- #

def extract_cose_payload(cose_data: bytes) -> bytes | None:
    """Extract payload (3rd element) from a COSE_Sign1 array (4 element)."""
    offset = 0
    hdr, offset = parse_cbor_header(cose_data, offset)
    if not hdr or hdr[0] != 4:
        return None
    arr_len = hdr[1]
    # element 1 protected headers
    ph_hdr, offset = parse_cbor_header(cose_data, offset)
    if ph_hdr and ph_hdr[0] == 2:  # byte string
        offset += ph_hdr[1]
    # element 2 unprotected map
    uh_hdr, offset = parse_cbor_header(cose_data, offset)
    if uh_hdr and uh_hdr[0] == 5:
        # skip map contents (key-value pairs)
        pairs = uh_hdr[1]
        for _ in range(pairs):
            k, offset = parse_cbor_header(cose_data, offset)
            if not k:
                return None
            km, kv = k
            # skip key body if text/bytes
            if km in (2, 3):
                offset += kv
            v, offset = parse_cbor_header(cose_data, offset)
            if not v:
                return None
            vm, vv = v
            if vm in (2, 3):
                offset += vv
            elif vm == 6:  # tag inside unprotected not expected, but handle
                inner, offset = parse_cbor_header(cose_data, offset)
                if inner:
                    im, iv = inner
                    if im in (2, 3):
                        offset += iv
    # element 3 payload
    payload_hdr, offset = parse_cbor_header(cose_data, offset)
    if not payload_hdr or payload_hdr[0] != 2:
        return None
    plen = payload_hdr[1]
    payload = cose_data[offset:offset+plen]
    offset += plen
    # element 4 signature (skip)
    sig_hdr, offset = parse_cbor_header(cose_data, offset)
    if sig_hdr and sig_hdr[0] == 2:
        offset += sig_hdr[1]
    return payload


# -------------------- CONCISE EVIDENCE PARSING -------------------- #

def _read_text(data: bytes, offset: int, length: int) -> Tuple[str, int]:
    raw = data[offset:offset+length]
    try:
        return raw.decode('utf-8'), offset + length
    except UnicodeDecodeError:
        return raw.hex(), offset + length

def _maybe_hex_ascii(val: str) -> str:
    """If `val` is a hex string representing clean printable ASCII (A-Z,a-z,0-9,_-.)
    of reasonable length (>=4) return the decoded ASCII, otherwise original."""
    if not isinstance(val, str):
        return val
    # quick hex check
    if len(val) % 2 != 0:
        return val
    if any(c not in '0123456789abcdefABCDEF' for c in val):
        return val
    try:
        decoded = bytes.fromhex(val)
        if not decoded:
            return val
        # ensure printable and no control chars
        if all(32 <= b <= 126 for b in decoded):
            txt = decoded.decode('utf-8')
            allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.:")
            if set(txt) <= allowed:
                # Accept if it has alpha OR it's a dotted numeric OID-like string
                if any(ch.isalpha() for ch in txt) or ('.' in txt and all((c.isdigit() or c=='.') for c in txt)):
                    return txt
    except Exception:
        return val
    return val

def _parse_tag_strip(data: bytes, offset: int) -> Tuple[Any, int]:
    """Parse a tagged value returning only the inner semantic value (skip tag number)."""
    hdr, new_off = parse_cbor_header(data, offset)
    if not hdr:
        return None, offset
    m, v = hdr
    if m == 2:  # bstr
        bs = data[new_off:new_off+v]
        hex_val = bs.hex()
        return _maybe_hex_ascii(hex_val), new_off + v
    if m == 3:  # tstr
        return _read_text(data, new_off, v)
    # recurse generically
    return _parse_generic_value(data, new_off, m, v)

def _parse_generic_value(data: bytes, offset: int, major: int, value: int):  # returns (val, new_offset)
    if major == 0:
        return value, offset
    if major == 1:
        return -1 - value, offset
    if major == 2:
        bs = data[offset:offset+value]
        return bs.hex(), offset + value
    if major == 3:
        return _read_text(data, offset, value)
    if major == 4:  # array
        arr = []
        cur = offset
        for _ in range(value):
            h, cur = parse_cbor_header(data, cur)
            if not h:
                break
            m2, v2 = h
            if m2 == 6:  # tag inside array
                inner, cur = _parse_tag_strip(data, cur)
                arr.append(inner)
            else:
                val, cur = _parse_generic_value(data, cur, m2, v2)
                arr.append(val)
        return arr, cur
    if major == 5:  # map
        mp = {}
        cur = offset
        for _ in range(value):
            k_hdr, cur = parse_cbor_header(data, cur)
            if not k_hdr:
                break
            km, kv = k_hdr
            if km == 3:
                k_val, cur = _read_text(data, cur, kv)
            elif km == 0:
                k_val = kv
            else:
                k_val, cur = _parse_generic_value(data, cur, km, kv)
            v_hdr, cur = parse_cbor_header(data, cur)
            if not v_hdr:
                break
            vm, vv = v_hdr
            if vm == 6:  # tag
                v_val, cur = _parse_tag_strip(data, cur)
            else:
                v_val, cur = _parse_generic_value(data, cur, vm, vv)
            mp[k_val] = v_val
        return mp, cur
    if major == 6:
        return _parse_tag_strip(data, offset)
    if major == 7:
        if value == 20: return False, offset
        if value == 21: return True, offset
        if value == 22: return None, offset
        return value, offset
    return value, offset

def parse_concise_evidence_bytes(data: bytes) -> Dict[str, Any]:
    """Parse ConciseEvidence (optionally tagged 571) into structured JSON."""
    try:
        offset = 0
        first, off = parse_cbor_header(data, offset)
        if not first:
            return {"error": "empty_concise_evidence"}
        # Handle optional tag 571
        if first[0] == 6 and first[1] == 571:
            # Next must be map
            map_hdr, off = parse_cbor_header(data, off)
        else:
            map_hdr = first
            off = off
        if map_hdr[0] != 5:
            return {"error": f"expected_map_got_{map_hdr[0]}"}
        entries = map_hdr[1]
        result = {}
        for _ in range(entries):
            k_hdr, off = parse_cbor_header(data, off)
            if not k_hdr:
                break
            if k_hdr[0] != 0:  # key must be positive int
                return {"error": "non_int_key_in_concise_evidence"}
            key_int = k_hdr[1]
            v_hdr, off2 = parse_cbor_header(data, off)
            if not v_hdr:
                break
            vm, vv = v_hdr
            # According to new CDDL reference provided by user, key 0 is now ce.ev-triples map.
            if key_int == 0:
                # Parse as map then we will reshape.
                ev_val, off = _parse_generic_value(data, off2, vm, vv)
                result['ce_ev_triples_raw'] = ev_val
            elif key_int == 1:  # evidence-id
                evid_val, off = _parse_generic_value(data, off2, vm, vv)
                result['ce_evidence_id'] = evid_val
            elif key_int == 2:  # profile
                profile_val, off = _parse_generic_value(data, off2, vm, vv)
                result['ce_profile'] = profile_val
            else:
                generic, off = _parse_generic_value(data, off2, vm, vv)
                result[f'key_{key_int}'] = generic

        # Derive structured ev-triples-map if raw present OR fall back to legacy environment/class lists.
        ev_triples_out = {}
        raw_ev = result.get('ce_ev_triples_raw')
        # Legacy fallback: if token used older layout (environment/class/measurements)
        legacy_classes = None
        if isinstance(raw_ev, dict):
            # Expect maybe keys 0..5 referencing various triple categories per new spec
            evidence_triples_raw = raw_ev.get(0)
            if isinstance(evidence_triples_raw, list):
                # Each evidence-triple-record is [ environment-map, [ + measurement-map ] ]
                evidence_triples = []
                for rec in evidence_triples_raw:
                    if (isinstance(rec, list) and len(rec) == 2 and isinstance(rec[0], dict) and isinstance(rec[1], list)):
                        evidence_triples.append({
                            'environment': rec[0],
                            'measurements': rec[1]
                        })
                    else:
                        evidence_triples.append({'raw': rec})
                if evidence_triples:
                    ev_triples_out['evidence_triples'] = evidence_triples
            # TODO: handle other triple categories (identity, dependency, etc.) when populated
            # identity triples key=1, dependency=2, membership=3, coswid=4, attest-key=5
            for cat_key, cat_name in [(1,'identity_triples'), (2,'dependency_triples'), (3,'membership_triples'), (4,'coswid_triples'), (5,'attest_key_triples')]:
                cat_val = raw_ev.get(cat_key)
                if isinstance(cat_val, list) and cat_val:
                    ev_triples_out[cat_name] = cat_val
        else:
            # Legacy mapping: build evidence_triples from environment.class transformed earlier (if present)
            legacy_env = result.get('environment') if isinstance(result.get('environment'), dict) else None
            if legacy_env:
                legacy_classes = legacy_env.get('class')
            if isinstance(legacy_classes, list):
                evidence_triples = []
                for cls in legacy_classes:
                    if isinstance(cls, dict) and 'class_id' in cls:
                        env_map = {'class': [{k: cls[k] for k in ('class_id','vendor','model') if k in cls}]}
                        measurements = cls.get('measurements', [])
                        evidence_triples.append({'environment': env_map, 'measurements': measurements})
                    else:
                        evidence_triples.append({'raw': cls})
                if evidence_triples:
                    ev_triples_out['evidence_triples'] = evidence_triples
        if ev_triples_out:
            # A-C Normalization Pass
            ALG_MAP = {7: 'sha384'}
            norm_evidence = []
            # Helper for dual key access (int or str) reused for measurements too
            def _fetch(mp, key):
                if not isinstance(mp, dict):
                    return None
                return mp.get(key) if key in mp else mp.get(str(key))

            for triple in ev_triples_out.get('evidence_triples', []):
                if not isinstance(triple, dict):
                    norm_evidence.append(triple)
                    continue
                env = triple.get('environment')
                measurements = triple.get('measurements')
                # A) Normalize environment/class map keys
                norm_env = None
                if isinstance(env, dict):
                    cls_container = env.get('0')  # key 0 => class-map per legacy/raw form
                    if isinstance(cls_container, dict):
                        # class-map numeric keys
                        class_id = cls_container.get('0')
                        vendor = cls_container.get('1')
                        model = cls_container.get('2')
                        norm_env = {'class': {k: v for k, v in (
                            ('class_id', class_id), ('vendor', vendor), ('model', model)) if v is not None}}
                # B/C) Normalize measurements list
                norm_meas_list = []
                if isinstance(measurements, list):
                    for mrec in measurements:
                        meas_obj = {}
                        auth = None
                        idx = None
                        detail = None
                        # Unified dict form
                        if isinstance(mrec, dict):
                            idx = _fetch(mrec, 0)  # mkey
                            detail = _fetch(mrec, 1)  # mval
                            auth = _fetch(mrec, 2)
                        elif isinstance(mrec, list):
                            if len(mrec) >= 2:
                                idx = mrec[0]
                                detail = mrec[1]
                        # Attempt unwrap of legacy {'raw': {...}} shape
                        if (not isinstance(detail, dict)) and isinstance(mrec, dict) and len(mrec) == 1:
                            only_key = next(iter(mrec.keys()))
                            inner = mrec[only_key]
                            if isinstance(inner, dict):
                                # Try interpret this dict directly as measurement-map
                                idx_candidate = _fetch(inner, 0)
                                detail_candidate = _fetch(inner, 1)
                                if detail is None and detail_candidate is not None:
                                    detail = detail_candidate
                                if idx is None and idx_candidate is not None:
                                    idx = idx_candidate
                        if idx is not None:
                            meas_obj['mkey'] = idx
                        if auth is not None:
                            meas_obj['authorized_by'] = auth
                        # Populate mval
                        if isinstance(detail, dict):
                            dct = detail
                            mval_obj = {}
                            def add_field(field_key_int, out_name):
                                val = _fetch(dct, field_key_int)
                                if val is not None:
                                    mval_obj[out_name] = val
                            add_field(0, 'version')
                            add_field(1, 'svn')
                            # digests (list of [alg_id, digest])
                            digests_raw = _fetch(dct, 2)
                            if isinstance(digests_raw, list):
                                dig_map = {}
                                for d in digests_raw:
                                    if isinstance(d, list) and len(d) >= 2:
                                        alg_id, hexdigest = d[0], d[1]
                                        alg_name = ALG_MAP.get(alg_id, f'alg_{alg_id}')
                                        dig_map[alg_name] = hexdigest
                                if dig_map:
                                    mval_obj['digests'] = dig_map
                            # optional scalar / simple fields
                            add_field(3, 'flags')
                            add_field(4, 'raw_value')
                            add_field(5, 'raw_value_mask')
                            add_field(6, 'mac_addr')
                            add_field(7, 'ip_addr')
                            add_field(8, 'serial_number')
                            add_field(9, 'ueid')
                            add_field(10, 'uuid')
                            add_field(11, 'name')
                            add_field(13, 'cryptokeys')
                            # integrity-registers map (14)
                            integ_raw = _fetch(dct, 14)
                            if isinstance(integ_raw, dict):
                                integ_map_out = {}
                                for _, reg_list in integ_raw.items():
                                    if isinstance(reg_list, list):
                                        for d in reg_list:
                                            if isinstance(d, list) and len(d) >= 2:
                                                alg_id, hexdigest = d[0], d[1]
                                                alg_name = ALG_MAP.get(alg_id, f'alg_{alg_id}')
                                                integ_map_out.setdefault(alg_name, []).append(hexdigest)
                                if integ_map_out:
                                    mval_obj['integrity_registers'] = integ_map_out
                            if mval_obj:
                                meas_obj['mval'] = mval_obj
                        # Decide fallback: only if nothing recognized
                        if meas_obj:
                            norm_meas_list.append(meas_obj)
                        else:
                            norm_meas_list.append({'raw': mrec})
                norm_evidence.append({
                    'environment': norm_env if norm_env is not None else env,
                    'measurements': norm_meas_list
                })
            if norm_evidence:
                ev_triples_out['evidence_triples'] = norm_evidence
            result['ce_ev_triples'] = ev_triples_out
        # Remove raw helper if processed
        if 'ce_ev_triples_raw' in result:
            del result['ce_ev_triples_raw']
        # Environment normalization pass
        def _get(mp, key):
            if mp is None:
                return None
            return mp.get(key) if key in mp else mp.get(str(key))
        ev_triples = result.get('ce_ev_triples', {}).get('evidence_triples')
        if isinstance(ev_triples, list):
            for trip in ev_triples:
                if not isinstance(trip, dict):
                    continue
                raw_env = trip.get('environment')
                if not isinstance(raw_env, dict):
                    continue
                cls_map = _get(raw_env, 0)
                instance_val = _get(raw_env, 1)
                group_val = _get(raw_env, 2)
                norm_env = {}
                if isinstance(cls_map, dict):
                    cls_obj = {}
                    cid = _get(cls_map, 0)
                    if cid is not None:
                        cls_obj['class_id'] = cid
                    vendor = _get(cls_map, 1)
                    if vendor is not None:
                        cls_obj['vendor'] = vendor
                    model = _get(cls_map, 2)
                    if model is not None:
                        cls_obj['model'] = model
                    for k,v in cls_map.items():
                        ks = str(k)
                        if ks not in ('0','1','2'):
                            cls_obj[f'key_{ks}'] = v
                    if cls_obj:
                        norm_env['class'] = cls_obj
                if instance_val is not None:
                    norm_env['instance'] = instance_val
                if group_val is not None:
                    norm_env['group'] = group_val
                if norm_env:
                    trip['environment'] = norm_env
        # Backward compatibility: keep original environment/class/measurements if they existed.
        return result
    except Exception as e:
        return {"error": f"concise_evidence_parse_failure: {e}"}

def _parse_environment_map(data: bytes, offset: int, major: int, value: int):
    """Parse EnvironmentMap according to spec:
    environment-map = non-empty<{
       ? &(class: 0) => class-map (array form in our encoding)
       ? &(instance: 1) => $instance-id-type-choice
       ? &(group: 2) => $group-id-type-choice
    }>

    We map keys: 0->"class", 1->"instance", 2->"group".
    Unknown integer keys preserved as key_<n>.
    """
    if major != 5:
        val, new_off = _parse_generic_value(data, offset, major, value)
        return val, new_off
    cur = offset
    env: Dict[str, Any] = {}
    for _ in range(value):
        k_hdr, cur = parse_cbor_header(data, cur)
        if not k_hdr:
            break
        # Only positive int keys expected
        if k_hdr[0] != 0:
            # Skip value for robustness
            v_skip, cur = parse_cbor_header(data, cur)
            if v_skip:
                cur = _parse_generic_value(data, cur, v_skip[0], v_skip[1])[1]
            continue
        key_int = k_hdr[1]
        v_hdr, value_offset = parse_cbor_header(data, cur)
        if not v_hdr:
            break
        vm, vv = v_hdr
        if key_int == 0:  # class
            class_array, new_off = _parse_class_array(data, value_offset, vm, vv)
            env['class'] = class_array
            cur = new_off
        elif key_int == 1:  # instance
            # Instance identifiers can be text, bytes, int, or tagged -> normalize
            if vm == 6:
                inst_val, new_off = _parse_tag_strip(data, value_offset)
            else:
                inst_val, new_off = _parse_generic_value(data, value_offset, vm, vv)
            env['instance'] = inst_val
            cur = new_off
        elif key_int == 2:  # group
            if vm == 6:
                grp_val, new_off = _parse_tag_strip(data, value_offset)
            else:
                grp_val, new_off = _parse_generic_value(data, value_offset, vm, vv)
            env['group'] = grp_val
            cur = new_off
        else:
            other_val, new_off = _parse_generic_value(data, value_offset, vm, vv)
            env[f'key_{key_int}'] = other_val
            cur = new_off
    return env, cur

def _parse_class_map(data: bytes, offset: int, major: int, value: int):
    if major != 5:
        return _parse_generic_value(data, offset, major, value)
    cur = offset
    out = {}
    for _ in range(value):
        k_hdr, cur = parse_cbor_header(data, cur)
        if not k_hdr or k_hdr[0] != 0:
            break
        key_int = k_hdr[1]
        v_hdr, cur2 = parse_cbor_header(data, cur)
        vm, vv = v_hdr
        if vm == 6:  # tag (e.g., class_id)
            inner, cur = _parse_tag_strip(data, cur2)
            if key_int == 0:
                out['class_id'] = _maybe_hex_ascii(inner)
            elif key_int == 1:
                out['vendor'] = inner
            elif key_int == 2:
                out['model'] = inner
            else:
                out[f'key_{key_int}'] = inner
        else:
            val, cur = _parse_generic_value(data, cur2, vm, vv)
            if key_int == 0:
                out['class_id'] = _maybe_hex_ascii(val)
            elif key_int == 1:
                out['vendor'] = val
            elif key_int == 2:
                out['model'] = val
            else:
                out[f'key_{key_int}'] = val
    return out, cur

def _parse_class_array(data: bytes, offset: int, major: int, value: int):
    if major != 4:
        return [], offset
    cur = offset
    arr = []
    for idx in range(value):
        entry_hdr, cur = parse_cbor_header(data, cur)
        if not entry_hdr or entry_hdr[0] != 4:  # each class entry is an array
            break
        entry_len = entry_hdr[1]
        entry_items = []
        for _ in range(entry_len):
            h, cur2 = parse_cbor_header(data, cur)
            if not h:
                cur = cur2
                break
            m, v = h
            if m == 5:  # map
                val, cur = _parse_generic_value(data, cur2, m, v)
            elif m == 4:
                val, cur = _parse_generic_value(data, cur2, m, v)
            elif m == 6:
                val, cur = _parse_tag_strip(data, cur2)
            else:
                val, cur = _parse_generic_value(data, cur2, m, v)
            entry_items.append(val)
        # Transform raw structure into semantic object if recognizable
        transformed = None
        if len(entry_items) == 2 and isinstance(entry_items[0], dict) and isinstance(entry_items[1], list):
            raw_cls_container = entry_items[0]  # expect key 0 => class-map
            class_map_inner = raw_cls_container.get(0)
            class_obj = {}
            if isinstance(class_map_inner, dict):
                cid = class_map_inner.get(0)
                if isinstance(cid, str):
                    cid = _maybe_hex_ascii(cid)
                if cid is not None:
                    class_obj['class_id'] = cid
                vendor = class_map_inner.get(1)
                if vendor is not None:
                    class_obj['vendor'] = vendor
                model = class_map_inner.get(2)
                if model is not None:
                    class_obj['model'] = model
                # preserve any other keys
                for k,vv in class_map_inner.items():
                    if k in (0,1,2):
                        continue
                    class_obj[f'key_{k}'] = vv
            measurements_raw = entry_items[1]
            measurements_out = []
            for mrec in measurements_raw:
                if not isinstance(mrec, dict):
                    measurements_out.append({'raw': mrec})
                    continue
                rec_index = mrec.get(0)
                rec_detail = mrec.get(1)
                rec_obj = {}
                if rec_index is not None:
                    rec_obj['index'] = rec_index
                if isinstance(rec_detail, dict):
                    version = rec_detail.get(0)
                    if version is not None:
                        rec_obj['version'] = version
                    svn = rec_detail.get(1)
                    if svn is not None:
                        rec_obj['svn'] = svn
                    # digests list: key 2
                    digests_list = rec_detail.get(2)
                    if isinstance(digests_list, list):
                        digest_objs = []
                        for d in digests_list:
                            if isinstance(d, list) and len(d) >= 2:
                                alg_id = d[0]
                                digest_hex = d[1]
                                alg_name = {7: 'sha384'}.get(alg_id, f'alg_{alg_id}')
                                digest_objs.append({'alg': alg_name, 'digest': digest_hex})
                            else:
                                digest_objs.append({'raw': d})
                        if digest_objs:
                            rec_obj['digests'] = digest_objs
                    # integrity registers key 14 -> map of indices each with array of digest arrays
                    integ = rec_detail.get(14)
                    if isinstance(integ, dict):
                        regs = []
                        for _, reg_list in integ.items():
                            if isinstance(reg_list, list):
                                for d in reg_list:
                                    if isinstance(d, list) and len(d) >= 2:
                                        alg_id = d[0]
                                        digest_hex = d[1]
                                        alg_name = {7: 'sha384'}.get(alg_id, f'alg_{alg_id}')
                                        regs.append({'alg': alg_name, 'digest': digest_hex})
                                    else:
                                        regs.append({'raw': d})
                        if regs:
                            rec_obj['integrity_registers'] = regs
                    # preserve unknown keys
                    for k,vv in rec_detail.items():
                        if k in (0,1,2,14):
                            continue
                        rec_obj[f'key_{k}'] = vv
                measurements_out.append(rec_obj)
            transformed = class_obj
            transformed['measurements'] = measurements_out
        arr.append(transformed if transformed is not None else entry_items)
    return arr, cur

def _parse_ce_measurements(data: bytes, offset: int, major: int, value: int):
    if major != 4:
        val, new_off = _parse_generic_value(data, offset, major, value)
        return val, new_off
    cur = offset
    measurements = []
    for _ in range(value):
        rec_hdr, cur = parse_cbor_header(data, cur)
        if not rec_hdr:
            break
        if rec_hdr[0] == 4:  # array
            rec_val, cur = _parse_generic_value(data, cur, rec_hdr[0], rec_hdr[1])
            measurements.append(rec_val)
        else:
            rec_val, cur = _parse_generic_value(data, cur, rec_hdr[0], rec_hdr[1])
            measurements.append(rec_val)
    return measurements, cur


# ------------------------------ CLI -------------------------------- #

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 decode_eat_claims_json.py <eat_token_file> [--pretty]")
        sys.exit(1)
    path = sys.argv[1]
    pretty = "--pretty" in sys.argv
    with open(path, 'rb') as f:
        raw = f.read()
    cose = skip_cbor_tags(raw)
    payload = extract_cose_payload(cose)
    if payload is None:
        print(json.dumps({"error": "cose_parse_failed"}, indent=2))
        sys.exit(2)
    claims = parse_eat_claims_to_dict(payload)
    if pretty:
        print(json.dumps(claims, indent=2))
    else:
        print(json.dumps(claims))


if __name__ == "__main__":
    main()

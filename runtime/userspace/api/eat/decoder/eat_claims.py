import logging

from decode import parse_cbor_header, get_eat_claim_name, parse_cbor_header_with_names

logger = logging.getLogger(__name__)

def parse_cbor_value_json(data, offset):
    """
    Generic recursive CBOR value parser: returns Python-native value, new offset.
    Works with parse_cbor_header from decode.py!
    """
    header, offset = parse_cbor_header(data, offset)
    if not header:
        return None, offset
    major_type, value = header
    if major_type == 0:
        return value, offset
    elif major_type == 1:
        return -value - 1, offset
    elif major_type == 2:
        bval = data[offset:offset+value]
        offset += value
        # Try to decode as ASCII if all bytes are printable ASCII
        try:
            if all(32 <= b <= 126 for b in bval):  # Printable ASCII range
                return bval.decode('ascii'), offset
        except:
            pass
        return bval.hex(), offset
    elif major_type == 3:
        sval = data[offset:offset+value].decode('utf-8', errors='replace')
        offset += value
        return sval, offset
    elif major_type == 4:
        arr = []
        for _ in range(value):
            el, offset = parse_cbor_value_json(data, offset)
            arr.append(el)
        return arr, offset
    elif major_type == 5:
        dct = {}
        for _ in range(value):
            k, offset = parse_cbor_value_json(data, offset)
            v, offset = parse_cbor_value_json(data, offset)
            dct[k] = v
        return dct, offset
    elif major_type == 6:  # Tag
        tval = value
        v, offset = parse_cbor_value_json(data, offset)
        return v, offset
    elif major_type == 7:
        return value, offset
    return value, offset

def parse_measurements_claim_json(data, offset, num_measurements):
    """
    Parse claim 273 (measurements) recursively to JSON-serializable structure.
    """
    measurements = []
    curr = offset
    for i in range(num_measurements):
        m_val, curr = parse_measurement_format_json(data, curr)
        measurements.append(m_val)
    return curr, measurements

def parse_measurement_format_json(data, offset):
    """
    Walks the EAT measurement format, collecting a Python dict
    representing structure for JSON.
    """
    array_info, new_offset = parse_cbor_header_with_names(data, offset)
    if array_info[0] != 'array':
        raise ValueError(f"Expected array, got {array_info[0]}")
    
    count = array_info[1]
    result = {}
    current_offset = new_offset
    for i in range(count):
        if i == 0:
            # content_type
            item_info, current_offset = parse_cbor_header_with_names(data, current_offset)
            if item_info[0] == "positive_int":
                result['content_type'] = f"{item_info[1]} (CoAP Content-Format)"
            else:
                result['content_type'] = item_info
        elif i == 1:
            # Secind element: concise_evidence (byte string)
            item_info, current_offset = parse_cbor_header_with_names(data, current_offset)
            if item_info[0] == 'byte_string':
                evidence_data = data[current_offset:current_offset + item_info[1]]
                current_offset += item_info[1]
                # recursively parse concise evidence according to EAT
                evidence_json, _ = parse_concise_evidence_json(evidence_data, 0)
                result['concise_evidence'] = evidence_json
            else:
                result['concise_evidence'] = item_info
        else:
            # additional elements
            item_info, current_offset = parse_cbor_header_with_names(data, current_offset)
            result[f"element_{i}"] = item_info
    return result, current_offset

def parse_concise_evidence_json(data, offset):
    """
    Parse ConciseEvidence while producing Python-native objects for JSON.
    Handles both tagged (571) and untagged forms.
    Returns (dict, new_offset)
    """
    try:
        # Check for CBOR tag 571
        first_info, new_offset = parse_cbor_header_with_names(data, offset)
        if first_info[0] == 'tag' and first_info[1] == 571:
            # Tagged ConciseEvidence (CBOR tag 571) - tagged-concise-evidence
            concise_evidence, after = parse_concise_evidence_map_json(data, new_offset)
            return {"tagged_concise_evidence": {"concise_evidence_map": concise_evidence}}, after
        else:
            # Untagged concise-evidence-map
            concise_evidence, after = parse_concise_evidence_map_json(data, offset)
            return {"concise_evidence_map": concise_evidence}, after
    except Exception as e:
        return {"error": f"Error parsing ConciseEvidence: {e}"}, offset

def parse_concise_evidence_map_json(data, offset):
    """
    Parse ConciseEvidenceMap as a dict for JSON.
    Returns (dict, new_offset)
    """
    try:
        map_info, new_offset = parse_cbor_header_with_names(data, offset)
        if map_info[0] != 'map':
            return {"error": f"Expected map, got {map_info[0]}"}, offset
        count = map_info[1]
        current_offset = new_offset
        result = {}
        for i in range(count):
            key_info, current_offset = parse_cbor_header_with_names(data, current_offset)
            # Only positive_int keys (0, 1, 2, ...) are handled in your reference code
            if key_info[0] == 'positive_int':
                key = key_info[1]
                # Parse value recursively using proper CDDL key names
                if key == 0:  # ce.ev-triples: 0 => ev-triples-map
                    ev_triples_val, current_offset = parse_ev_triples_map_json(data, current_offset)
                    result["ce.ev-triples"] = ev_triples_val
                elif key == 1:  # ce.evidence-id: 1 => $evidence-id-type-choice
                    evidence_id_val, current_offset = parse_cbor_value_json(data, current_offset)
                    result["ce.evidence-id"] = evidence_id_val
                elif key == 2:  # profile: 2 => $profile-type-choice
                    profile_val, current_offset = parse_cbor_value_json(data, current_offset)
                    result["profile"] = profile_val
                else:
                    v, current_offset = parse_cbor_value_json(data, current_offset)
                    result[f"extension_key_{key}"] = v
            else:
                v, current_offset = parse_cbor_value_json(data, current_offset)
                result["unknown_key"] = v
        return result, current_offset
    except Exception as e:
        return {"error": f"Error parsing ConciseEvidenceMap: {e}"}, offset

def parse_ev_triples_map_json(data, offset):
    """
    Parse ev-triples-map according to CDDL:
    ev-triples-map = non-empty< {
      ? &(ce.evidence-triples: 0) => [ + evidence-triple-record ]
      ? &(ce.identity-triples: 1) => [ + ev-identity-triple-record ]
      ? &(ce.dependency-triples: 2) => [ + ev-dependency-triple-record ]
      ? &(ce.membership-triples: 3) => [ + ev-membership-triple-record ]
      ? &(ce.coswid-triples: 4) => [ + ev-coswid-triple-record ]
      ? &(ce.attest-key-triples: 5) => [ + ev-attest-key-triple-record ]
      * $$ev-triples-map-extension
    } >
    """
    try:
        map_info, new_offset = parse_cbor_header_with_names(data, offset)
        if map_info[0] != 'map':
            return {"error": f"Expected map, got {map_info[0]}"}, offset
        
        count = map_info[1]
        current_offset = new_offset
        result = {}
        
        for i in range(count):
            key_info, current_offset = parse_cbor_header_with_names(data, current_offset)
            if key_info[0] == 'positive_int':
                key = key_info[1]
                
                if key == 0:  # ce.evidence-triples: 0 - fully implemented
                    triples_val, current_offset = parse_evidence_triples_json(data, current_offset)
                    result["ce.evidence-triples"] = triples_val
                elif key == 1:  # ce.identity-triples: 1 - unimplemented placeholder
                    triples_val, current_offset = parse_cbor_value_json(data, current_offset)
                    result["ce.identity-triples"] = {"unimplemented": "placeholder", "raw_data": triples_val}
                elif key == 2:  # ce.dependency-triples: 2 - unimplemented placeholder
                    triples_val, current_offset = parse_cbor_value_json(data, current_offset)
                    result["ce.dependency-triples"] = {"unimplemented": "placeholder", "raw_data": triples_val}
                elif key == 3:  # ce.membership-triples: 3 - unimplemented placeholder
                    triples_val, current_offset = parse_cbor_value_json(data, current_offset)
                    result["ce.membership-triples"] = {"unimplemented": "placeholder", "raw_data": triples_val}
                elif key == 4:  # ce.coswid-triples: 4 - unimplemented placeholder
                    triples_val, current_offset = parse_cbor_value_json(data, current_offset)
                    result["ce.coswid-triples"] = {"unimplemented": "placeholder", "raw_data": triples_val}
                elif key == 5:  # ce.attest-key-triples: 5 - unimplemented placeholder
                    triples_val, current_offset = parse_cbor_value_json(data, current_offset)
                    result["ce.attest-key-triples"] = {"unimplemented": "placeholder", "raw_data": triples_val}
                else:
                    # Extension keys
                    triples_val, current_offset = parse_cbor_value_json(data, current_offset)
                    result[f"extension_triple_{key}"] = triples_val
            else:
                # Non-integer keys
                val, current_offset = parse_cbor_value_json(data, current_offset)
                result["unknown_key"] = val
        
        return result, current_offset
    except Exception as e:
        return {"error": f"Error parsing ev-triples-map: {e}"}, offset

def parse_evidence_triples_json(data, offset):
    """
    Parse evidence-triple-record array for ce.evidence-triples: 0
    According to CDDL:
    evidence-triple-record = [
      environment-map
      [ + measurement-map ]
    ]
    Returns (list, new_offset)
    """
    try:
        array_info, new_offset = parse_cbor_header_with_names(data, offset)
        if array_info[0] != 'array':
            return {"error": f"Expected array, got {array_info[0]}"}, offset
        
        count = array_info[1]
        current_offset = new_offset
        result = []
        
        for i in range(count):
            # Parse each evidence-triple-record
            triple_record, current_offset = parse_evidence_triple_record_json(data, current_offset)
            result.append(triple_record)
        
        return result, current_offset
    except Exception as e:
        return {"error": f"Error parsing evidence-triples: {e}"}, offset

def parse_evidence_triple_record_json(data, offset):
    """
    Parse a single evidence-triple-record according to CDDL:
    evidence-triple-record = [
      environment-map
      [ + measurement-map ]
    ]
    Returns (dict, new_offset)
    """
    try:
        array_info, new_offset = parse_cbor_header_with_names(data, offset)
        if array_info[0] != 'array':
            # If it's not an array, treat it as a flexible structure
            flexible_record, current_offset = parse_cbor_value_json(data, offset)
            return {"flexible_structure": flexible_record}, current_offset
        
        array_count = array_info[1]
        current_offset = new_offset
        
        if array_count == 2:
            # Standard CDDL structure: [environment-map, [measurement-maps]]
            # Element 0: environment-map
            environment_map, current_offset = parse_environment_map_json(data, current_offset)
            
            # Element 1: array of measurement-maps
            measurement_maps, current_offset = parse_measurement_maps_array_json(data, current_offset)
            
            return {
                "environment-map": environment_map,
                "measurement-map": measurement_maps
            }, current_offset
        else:
            # Flexible parsing for non-standard array lengths
            elements = []
            for i in range(array_count):
                element, current_offset = parse_cbor_value_json(data, current_offset)
                elements.append(element)
            
            return {"elements": elements}, current_offset
            
    except Exception as e:
        return {"error": f"Error parsing evidence-triple-record: {e}"}, offset

def parse_measurement_maps_array_json(data, offset):
    """
    Parse array of measurement-maps: [ + measurement-map ]
    Returns (list, new_offset)
    """
    try:
        array_info, new_offset = parse_cbor_header_with_names(data, offset)
        if array_info[0] != 'array':
            # If not an array, parse as single measurement-map
            measurement_map, current_offset = parse_measurement_map_json(data, offset)
            return [measurement_map], current_offset
        
        count = array_info[1]
        current_offset = new_offset
        result = []
        
        for i in range(count):
            measurement_map, current_offset = parse_measurement_map_json(data, current_offset)
            result.append(measurement_map)
        
        return result, current_offset
        
    except Exception as e:
        return {"error": f"Error parsing measurement-maps array: {e}"}, offset

def parse_measurement_map_json(data, offset):
    """
    Parse a single measurement-map structure
    Returns (dict, new_offset)
    """
    try:
        map_info, new_offset = parse_cbor_header_with_names(data, offset)
        if map_info[0] == 'map':
            # Parse as CBOR map
            map_count = map_info[1]
            measurement_map, current_offset = parse_measurement_map_with_names_json(data, new_offset, map_count)
            return measurement_map, current_offset
        else:
            # Parse as generic CBOR value
            measurement_map, current_offset = parse_cbor_value_json(data, offset)
            return measurement_map, current_offset
        
    except Exception as e:
        return {"error": f"Error parsing measurement-map: {e}"}, offset

def parse_measurement_map_with_names_json(data, offset, map_count):
    """
    Parse measurement-map according to CDDL specification:
    measurement-map = {
       ? &(mkey: 0) => $measured-element-type-choice
       &(mval: 1) => measurement-values-map
       ? &(authorized-by: 2) => [ + $crypto-key-type-choice ]
    }
    """
    result = {}
    current_offset = offset

    for _ in range(map_count):
        # Parse key
        key_info, key_offset = parse_cbor_header_with_names(data, current_offset)
        if key_info[0] == 'positive_int':
            key = key_info[1]
            val_offset = key_offset
            
            # Map numeric keys to CDDL field names
            if key == 0:
                field_name = "mkey"  # measured-element-type-choice
            elif key == 1:
                field_name = "mval"  # measurement-values-map
            elif key == 2:
                field_name = "authorized-by"  # [ + $crypto-key-type-choice ]
            else:
                field_name = f"extension_field_{key}"
        elif key_info[0] == 'text_string':
            field_name = data[key_offset : key_offset + key_info[1]].decode('utf-8', errors='replace')
            val_offset = key_offset + key_info[1]
        else:
            field_name = str(key_info)
            val_offset = key_offset

        # Parse value with special handling for measurement-values-map
        if field_name == "mval":
            # Parse measurement-values-map with CDDL field names
            val, next_offset = parse_measurement_values_map_json(data, val_offset)
        else:
            # Parse value recursively
            val, next_offset = parse_cbor_value_json(data, val_offset)
        
        result[field_name] = val
        current_offset = next_offset

    return result, current_offset

def parse_measurement_values_map_json(data, offset):
    """
    Parse measurement-values-map according to CDDL specification:
    measurement-values-map = non-empty<{
       ? &(version: 0) => version-map
       ? &(svn: 1) => svn-type-choice
       ? &(digests: 2) => digests-type
       ? &(flags: 3) => flags-map
       ? (&(raw-value: 4) => $raw-value-type-choice,
          ? &(raw-value-mask-DEPRECATED: 5) => raw-value-mask-type)
       ? &(mac-addr: 6) => mac-addr-type-choice
       ? &(ip-addr: 7) => ip-addr-type-choice
       ? &(serial-number: 8) => text
       ? &(ueid: 9) => ueid-type
       ? &(uuid: 10) => uuid-type
       ? &(name: 11) => text
       ? &(cryptokeys: 13) => [ + $crypto-key-type-choice ]
       ? &(integrity-registers: 14) => integrity-registers
       ? &(int-range: 15) => int-range-type-choice
       * $$measurement-values-map-extension
    }>
    """
    try:
        # Check if it's a map
        map_info, new_offset = parse_cbor_header_with_names(data, offset)
        if map_info[0] != 'map':
            # Not a map, parse as generic value
            return parse_cbor_value_json(data, offset)
        
        map_count = map_info[1]
        result = {}
        current_offset = new_offset
        
        for _ in range(map_count):
            # Parse key
            key_info, key_offset = parse_cbor_header_with_names(data, current_offset)
            if key_info[0] == 'positive_int':
                key = key_info[1]
                val_offset = key_offset
                
                # Map numeric keys to CDDL field names
                if key == 0:
                    field_name = "version"
                elif key == 1:
                    field_name = "svn"
                elif key == 2:
                    field_name = "digests"
                elif key == 3:
                    field_name = "flags"
                elif key == 4:
                    field_name = "raw-value"
                elif key == 5:
                    field_name = "raw-value-mask-DEPRECATED"
                elif key == 6:
                    field_name = "mac-addr"
                elif key == 7:
                    field_name = "ip-addr"
                elif key == 8:
                    field_name = "serial-number"
                elif key == 9:
                    field_name = "ueid"
                elif key == 10:
                    field_name = "uuid"
                elif key == 11:
                    field_name = "name"
                elif key == 13:
                    field_name = "cryptokeys"
                elif key == 14:
                    field_name = "integrity-registers"
                elif key == 15:
                    field_name = "int-range"
                else:
                    field_name = f"extension_field_{key}"
            elif key_info[0] == 'text_string':
                field_name = data[key_offset : key_offset + key_info[1]].decode('utf-8', errors='replace')
                val_offset = key_offset + key_info[1]
            else:
                field_name = str(key_info)
                val_offset = key_offset
            
            # Parse value with special handling for specific fields
            if field_name == "digests":
                # Parse digests-type as array of digest structures
                val, next_offset = parse_digests_type_json(data, val_offset)
            elif field_name == "integrity-registers":
                # Parse integrity-registers according to CDDL
                val, next_offset = parse_integrity_registers_json(data, val_offset)
            else:
                # Parse value recursively
                val, next_offset = parse_cbor_value_json(data, val_offset)
            result[field_name] = val
            current_offset = next_offset
        
        return result, current_offset
        
    except Exception as e:
        return {"error": f"Error parsing measurement-values-map: {e}"}, offset

def parse_digests_type_json(data, offset):
    """
    Parse digests-type according to CDDL specification:
    digest = [
       alg: (int / text),
       val: bytes
    ]
    digests-type = [ + digest ]
    """
    try:
        array_info, new_offset = parse_cbor_header_with_names(data, offset)
        if array_info[0] != 'array':
            # Not an array, parse as generic value
            return parse_cbor_value_json(data, offset)
        
        count = array_info[1]
        result = []
        current_offset = new_offset
        
        for _ in range(count):
            # Parse each digest structure
            digest, current_offset = parse_digest_json(data, current_offset)
            result.append(digest)
        
        return result, current_offset
        
    except Exception as e:
        return {"error": f"Error parsing digests-type: {e}"}, offset

def parse_digest_json(data, offset):
    """
    Parse a single digest structure:
    digest = [
       alg: (int / text),
       val: bytes
    ]
    """
    try:
        array_info, new_offset = parse_cbor_header_with_names(data, offset)
        if array_info[0] != 'array':
            # Not an array, parse as generic value
            return parse_cbor_value_json(data, offset)
        
        array_count = array_info[1]
        current_offset = new_offset
        
        if array_count >= 2:
            # Standard digest structure: [alg, val]
            # Element 0: alg (int / text) - parse with algorithm name resolution
            alg_info, current_offset = parse_cbor_header_with_names(data, current_offset)
            alg_name = "unknown"
            alg_val = None
            
            if alg_info[0] == 'negative_int':
                alg_id = -alg_info[1] - 1
                alg_val = alg_id
                alg_name = f"alg_{alg_id}"
            elif alg_info[0] == 'positive_int':
                alg_val = alg_info[1]
                # Named Information Hash Algorithm registry mappings
                if alg_val == 0:
                    alg_name = "Reserved"
                elif alg_val == 1:
                    alg_name = "sha-256"
                elif alg_val == 2:
                    alg_name = "sha-256-128"
                elif alg_val == 3:
                    alg_name = "sha-256-120"
                elif alg_val == 4:
                    alg_name = "sha-256-96"
                elif alg_val == 5:
                    alg_name = "sha-256-64"
                elif alg_val == 6:
                    alg_name = "sha-256-32"
                elif alg_val == 7:
                    alg_name = "sha-384"
                elif alg_val == 8:
                    alg_name = "sha-512"
                elif alg_val == 9:
                    alg_name = "sha3-224"
                elif alg_val == 10:
                    alg_name = "sha3-256"
                elif alg_val == 11:
                    alg_name = "sha3-384"
                elif alg_val == 12:
                    alg_name = "sha3-512"
                elif alg_val == 32:
                    alg_name = "Reserved"
                else:
                    alg_name = f"hash_alg_{alg_val}"
            elif alg_info[0] == 'text_string':
                alg_val = data[current_offset:current_offset + alg_info[1]].decode('utf-8', errors='replace')
                current_offset += alg_info[1]
                alg_name = alg_val
            else:
                alg_val = alg_info
                
            # Element 1: val (bytes)
            val_val, current_offset = parse_cbor_value_json(data, current_offset)
            
            result = {
                "alg": alg_name,
                "val": val_val
            }
            
            # Parse any additional elements
            for i in range(2, array_count):
                extra_val, current_offset = parse_cbor_value_json(data, current_offset)
                result[f"element_{i}"] = extra_val
            
            return result, current_offset
        else:
            # Flexible parsing for non-standard array lengths
            elements = []
            for i in range(array_count):
                element, current_offset = parse_cbor_value_json(data, current_offset)
                elements.append(element)
            
            return {"elements": elements}, current_offset
            
    except Exception as e:
        return {"error": f"Error parsing digest: {e}"}, offset

def parse_integrity_registers_json(data, offset):
    """
    Parse integrity-registers according to CDDL specification:
    integrity-registers = {
       + integrity-register-id-type-choice => digests-type
    }
    """
    try:
        map_info, new_offset = parse_cbor_header_with_names(data, offset)
        if map_info[0] != 'map':
            # Not a map, parse as generic value
            return parse_cbor_value_json(data, offset)
        
        map_count = map_info[1]
        result = {}
        current_offset = new_offset
        
        for _ in range(map_count):
            # Parse register ID (key)
            key_info, key_offset = parse_cbor_header_with_names(data, current_offset)
            if key_info[0] == 'positive_int':
                register_id = f"register_{key_info[1]}"
                val_offset = key_offset
            elif key_info[0] == 'text_string':
                register_id = data[key_offset : key_offset + key_info[1]].decode('utf-8', errors='replace')
                val_offset = key_offset + key_info[1]
            else:
                register_id = str(key_info)
                val_offset = key_offset
            
            # Parse register value (digests-type)
            digests, next_offset = parse_digests_type_json(data, val_offset)
            result[register_id] = digests
            current_offset = next_offset
        
        return result, current_offset
        
    except Exception as e:
        return {"error": f"Error parsing integrity-registers: {e}"}, offset

def parse_class_array_element_json(data, offset):
    """
    Parse elements within a class array, producing Python-native values.
    Mirrors the original parse_class_array_element logic, but returns structures.
    Returns (value, new_offset)
    """
    elem_info, current_offset = parse_cbor_header_with_names(data, offset)

    if elem_info[0] == 'map':
        map_count = elem_info[1]
        val, current_offset = parse_nested_map_json(data, current_offset, map_count)
        return val, current_offset

    elif elem_info[0] == 'array':
        array_count = elem_info[1]
        # Use parse_measurement_array_json to emulate your CBOR/EAT logic for arrays
        arr, current_offset = parse_measurement_array_json(data, current_offset, array_count)
        return arr, current_offset

    elif elem_info[0] == 'text_string':
        s = data[current_offset:current_offset + elem_info[1]].decode('utf-8', errors='replace')
        current_offset += elem_info[1]
        return s, current_offset

    elif elem_info[0] == 'byte_string':
        b = data[current_offset:current_offset + elem_info[1]]
        current_offset += elem_info[1]
        return b.hex(), current_offset

    elif elem_info[0] == 'positive_int':
        return elem_info[1], current_offset

    else:
        # Fallback: use the generic CBOR value walker
        v, current_offset = parse_cbor_value_json(data, offset)
        return v, current_offset

def parse_environment_map_json(data, offset):
    """
    Parse EnvironmentMap structure according to CDDL:
    environment-map = non-empty<{
         ? &(class: 0) => class-map
         ? &(instance: 1) => $instance-id-type-choice
         ? &(group: 2) => $group-id-type-choice
       }>
    Returns (dict, new_offset)
    """
    try:
        map_info, new_offset = parse_cbor_header_with_names(data, offset)
        if map_info[0] != 'map':
            return {"error": f"Expected map, got {map_info[0]}"}, offset
        count = map_info[1]
        env = {}
        current_offset = new_offset

        for _ in range(count):
            # Parse key
            key_info, current_offset = parse_cbor_header_with_names(data, current_offset)
            if key_info[0] == 'positive_int':
                key = key_info[1]
                if key == 0:  # class: 0 => class-map
                    class_map, current_offset = parse_class_map_json(data, current_offset)
                    env["class"] = class_map
                elif key == 1:  # instance: 1 => $instance-id-type-choice
                    instance_val, current_offset = parse_cbor_value_json(data, current_offset)
                    env["instance"] = instance_val
                elif key == 2:  # group: 2 => $group-id-type-choice
                    group_val, current_offset = parse_cbor_value_json(data, current_offset)
                    env["group"] = group_val
                else:
                    # Extension or unknown keys
                    v, current_offset = parse_cbor_value_json(data, current_offset)
                    env[f"extension_key_{key}"] = v
            else:
                # Unknown or string key types (rare)
                v, current_offset = parse_cbor_value_json(data, current_offset)
                env["unknown_key"] = v
        return env, current_offset
    except Exception as e:
        return {"error": f"Error parsing EnvironmentMap: {e}"}, offset

def parse_nested_map_json(data, offset, map_count):
    """
    Parse a nested CBOR map with `map_count` entries, producing a Python dict.
    Returns (dict, new_offset).
    """
    result = {}
    current_offset = offset

    for _ in range(map_count):
        # Parse key (could be int or text string)
        key_info, key_offset = parse_cbor_header_with_names(data, current_offset)
        if key_info[0] == 'text_string':
            key = data[key_offset : key_offset + key_info[1]].decode('utf-8', errors='replace')
            val_offset = key_offset + key_info[1]
        elif key_info[0] == 'positive_int':
            key = key_info[1]
            val_offset = key_offset
        else:
            key = str(key_info)
            val_offset = key_offset

        # Parse value (map, array, string, int, etc.)
        val_info, peek_offset = parse_cbor_header_with_names(data, val_offset)
        if val_info[0] == 'map':
            v, next_offset = parse_nested_map_json(data, peek_offset, val_info[1])
        elif val_info[0] == 'array':
            arr, next_offset = parse_measurement_array_json(data, peek_offset, val_info[1])
            v = arr
        elif val_info[0] == 'text_string':
            v = data[peek_offset:peek_offset + val_info[1]].decode('utf-8', errors='replace')
            next_offset = peek_offset + val_info[1]
        elif val_info[0] == 'byte_string':
            b = data[peek_offset:peek_offset + val_info[1]]
            v = b.hex()
            next_offset = peek_offset + val_info[1]
        elif val_info[0] == 'positive_int':
            v = val_info[1]
            next_offset = peek_offset
        elif val_info[0] == 'negative_int':
            v = -val_info[1] - 1
            next_offset = peek_offset
        else:
            v, next_offset = parse_cbor_value_json(data, val_offset)

        result[key] = v
        current_offset = next_offset

    return result, current_offset

def parse_measurement_array_json(data, offset, array_elem_count):
    """
    Parse a CBOR array of measurements, returning a Python-native list.
    Uses parse_cbor_header_with_names to extract type and count.
    Each measurement element can be a map, array, string, integer, etc.
    Returns (list, new_offset)
    """
    result = []
    current_offset = offset

    for _ in range(array_elem_count):
        measurement_info, peek_offset = parse_cbor_header_with_names(data, current_offset)
        if measurement_info[0] == 'map':
            map_count = measurement_info[1]
            val, current_offset = parse_nested_map_json(data, peek_offset, map_count)
            result.append(val)
        elif measurement_info[0] == 'array':
            arr, current_offset = parse_cbor_value_json(data, current_offset)
            result.append(arr)
        elif measurement_info[0] == 'text_string':
            s = data[peek_offset:peek_offset + measurement_info[1]].decode('utf-8', errors='replace')
            current_offset = peek_offset + measurement_info[1]
            result.append(s)
        elif measurement_info[0] == 'byte_string':
            b = data[peek_offset:peek_offset + measurement_info[1]]
            current_offset = peek_offset + measurement_info[1]
            result.append(b.hex())
        elif measurement_info[0] == 'positive_int':
            result.append(measurement_info[1])
            current_offset = peek_offset
        elif measurement_info[0] == 'negative_int':
            result.append(-measurement_info[1] - 1)
            current_offset = peek_offset
        else:
            # fallback: use generic parser
            v, current_offset = parse_cbor_value_json(data, current_offset)
            result.append(v)

    return result, current_offset

def parse_class_array_entry_json(data, offset):
    """
    Parse a single class array entry, producing a list of items (dicts/strings/ints).
    Returns (list, new_offset)
    """
    try:
        class_info, current_offset = parse_cbor_header_with_names(data, offset)
        if class_info[0] != 'array':
            return {"error": f"Expected array, got {class_info[0]}"}, offset
        
        array_count = class_info[1]
        class_entry = []
        
        for _ in range(array_count):
            elem, current_offset = parse_class_array_element_json(data, current_offset)
            class_entry.append(elem)
        
        return class_entry, current_offset
    except Exception as e:
        return {"error": f"Error parsing class array entry: {e}"}, offset

def parse_class_map_json(data, offset):
    """
    Parse ClassMap structure according to CDDL:
    class-map = non-empty<{
         ? &(class-id: 0) => $class-id-type-choice
         ? &(vendor: 1) => tstr
         ? &(model: 2) => tstr
         ? &(layer: 3) => uint
         ? &(index: 4) => uint
       }>
    Returns (dict, new_offset)
    """
    try:
        map_info, new_offset = parse_cbor_header_with_names(data, offset)
        if map_info[0] != 'map':
            logger.error(f"Expected map for class, got {map_info[0]}")
            return {"error": f"Expected map, got {map_info[0]}"}, offset
        
        count = map_info[1]
        class_map = {}
        current_offset = new_offset

        for _ in range(count):
            # Parse key
            key_info, current_offset = parse_cbor_header_with_names(data, current_offset)
            
            if key_info[0] == 'positive_int':
                key = key_info[1]
                
                if key == 0:  # class-id: 0 => $class-id-type-choice
                    class_id_val, current_offset = parse_cbor_value_json(data, current_offset)
                    class_map["class-id"] = class_id_val
                elif key == 1:  # vendor: 1 => tstr
                    vendor_val, current_offset = parse_cbor_value_json(data, current_offset)
                    class_map["vendor"] = vendor_val
                elif key == 2:  # model: 2 => tstr
                    model_val, current_offset = parse_cbor_value_json(data, current_offset)
                    class_map["model"] = model_val
                elif key == 3:  # layer: 3 => uint
                    layer_val, current_offset = parse_cbor_value_json(data, current_offset)
                    class_map["layer"] = layer_val
                elif key == 4:  # index: 4 => uint
                    index_val, current_offset = parse_cbor_value_json(data, current_offset)
                    class_map["index"] = index_val
                else:
                    # Extension keys
                    extension_val, current_offset = parse_cbor_value_json(data, current_offset)
                    class_map[f"extension_key_{key}"] = extension_val
            else:
                # Non-integer keys - parse generically
                key_val, current_offset = parse_cbor_value_json(data, offset)
                value_val, current_offset = parse_cbor_value_json(data, current_offset)
                class_map[str(key_val)] = value_val
        
        return class_map, current_offset
    except Exception as e:
        logger.error(f"Error parsing ClassMap: {e}")
        return {"error": f"Error parsing ClassMap: {e}"}, offset

def parse_evidence_measurements_json(data, offset):
    """
    Parse evidence measurements structure recursively to a Python list.
    Returns (list, new_offset)
    """
    try:
        array_info, new_offset = parse_cbor_header_with_names(data, offset)
        if array_info[0] != 'array':
            logger.error(f"Expected array for measurements, got {array_info[0]}")
            raise ValueError(f"Expected array for measurements, got {array_info[0]}")
        
        count = array_info[1]
        measurements = []
        current_offset = new_offset

        for _ in range(count):
            # Parse each measurement entry
            measurement, current_offset = parse_cbor_value_json(data, current_offset)
            measurements.append(measurement)
        
        return measurements, current_offset
    except Exception as e:
        logger.error(f"Error parsing evidence measurements: {e}")
        return {"error": f"Error parsing evidence measurements: {e}"}, offset

def parse_eat_profile_claim_json(payload, claims_offset, value_info):
    """
    Parse EAT Profile claim (265) with CBOR tag and return the OID value.
    
    Args:
        payload: CBOR payload bytes
        claims_offset: Current offset in payload
        value_info: Tag number from CBOR header
        
    Returns:
        tuple: (oid_string, new_offset)
    """
    try:
        logger.info(f"    Value: CBOR tag ({value_info})")
        if value_info == 111:  # OID tag
            logger.info(f"      Tag type: OID (111)")
        
        # Parse the tagged value
        tag_value_header, new_offset = parse_cbor_header(payload, claims_offset)
        if tag_value_header:
            if tag_value_header[0] == 3:  # Text string
                profile_len = tag_value_header[1]
                profile_value = payload[new_offset:new_offset+profile_len].decode('utf-8')
                logger.info(f"      EAT Profile OID: '{profile_value}'")
                return profile_value, new_offset + profile_len
                
            elif tag_value_header[0] == 2:  # Byte string  
                profile_len = tag_value_header[1]
                profile_bytes = payload[new_offset:new_offset+profile_len]
                try:
                    profile_value = profile_bytes.decode('utf-8')
                    logger.info(f"      EAT Profile OID: '{profile_value}'")
                    return profile_value, new_offset + profile_len
                except UnicodeDecodeError:
                    # If not valid UTF-8, return as hex
                    hex_value = profile_bytes.hex()
                    logger.info(f"      EAT Profile (hex): {hex_value}")
                    return hex_value, new_offset + profile_len
                
            else:
                # Handle other CBOR types - return string representation
                logger.info(f"      Tagged value type: {tag_value_header[0]}")
                return str(tag_value_header[1]), new_offset
        else:
            logger.warning(f"      Could not parse tagged value")
            return "unknown", claims_offset
            
    except Exception as e:
        logger.error(f"Error parsing EAT profile claim: {e}")
        return "error", claims_offset

def parse_eat_claims_json(payload):
    """
    Parses EAT claims CBOR payload and returns JSON-serializable dict of claims.
    Uses decode.py for all generic CBOR work.
    """
    logger.info("=== EAT Claims Analysis ===")
    claims_offset = 0
    claims_header, claims_offset = parse_cbor_header(payload, claims_offset)
    if not (claims_header and claims_header[0] == 5):
        logger.error("EAT payload is not a CBOR map")
        return {}

    num_claims = claims_header[1]
    logger.info(f"EAT claims: map with {num_claims} entries")
    claims_dict = {}

    for i in range(num_claims):
        key_header, claims_offset = parse_cbor_header(payload, claims_offset)
        if not key_header:
            continue
        if key_header[0] == 0:
            key = key_header[1]
            claim_name = get_eat_claim_name(key)
            logger.info(f"  Claim {i+1}: {claim_name} (key={key})")
            dict_key = claim_name
        elif key_header[0] == 3:
            key_len = key_header[1]
            key = payload[claims_offset:claims_offset+key_len].decode('utf-8')
            claims_offset += key_len
            logger.info(f"  Claim {i+1}: '{key}' (string key)")
            dict_key = key
        else:
            logger.warning(f"  Claim {i+1}: Key = unknown type {key_header[0]}")
            dict_key = str(key_header)

        # Look ahead for claim type and value header
        value_header, value_offset = parse_cbor_header(payload, claims_offset)
        if dict_key == "measurements (Evidence)" and value_header and value_header[0] == 4:
            num_measurements = value_header[1]
            claims_offset = value_offset
            claims_offset, measurements_val = parse_measurements_claim_json(payload, claims_offset, num_measurements)
            claims_dict[dict_key] = measurements_val
            logger.info(f"    Value: [measurements array, {num_measurements} entries]")
        elif dict_key == "eat_profile (EAT Profile)" and value_header and value_header[0] == 6:  # CBOR tag
            # Parse EAT profile with tag handling
            profile_value, claims_offset = parse_eat_profile_claim_json(payload, value_offset, value_header[1])
            claims_dict[dict_key] = profile_value
        else:
            # Generic claim value parsing
            val, claims_offset = parse_cbor_value_json(payload, claims_offset)
            logger.info(f"    Value: {val}")
            claims_dict[dict_key] = val
    return claims_dict

def validate_eat_claims_json(claims_dict, nonce=None):
    """
    Validate the parsed EAT claims dictionary for required fields and structure.
    Returns (is_valid, error_message)
    """
    logger.info("\n\n======= Validate EAT claims =======")
    try:
      if "nonce" in claims_dict:
            logger.info("Validating Nonce claim...")
            claim_nonce = claims_dict["nonce"]
            logger.info(f"Nonce in EAT: {claim_nonce}")
            logger.info(f"Expected Nonce: {nonce}")
            if nonce is not None and claim_nonce != nonce:
                return False, "Nonce value does not match expected nonce"
    
            logger.info(f"Nonce claim verified! ✓")
     
    except Exception as e:
        return False, f"Error during validation: {e}"
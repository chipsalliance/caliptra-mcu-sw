// Licensed under the Apache-2.0 license

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use caliptra_ocp_eat::cbor_tags;
use caliptra_ocp_eat::cose::{header_params, CoseAlgorithm, CoseHeaderPair, CoseSign1};
use caliptra_ocp_eat::ocp_profile::{
    ClassIdTypeChoice, ClassMap, ConciseEvidence, ConciseEvidenceMap, DebugStatus, DigestEntry,
    EnvironmentMap, EvTriplesMap, EvidenceTripleRecord, IntegrityRegisterEntry,
    IntegrityRegisterIdChoice, MeasurementFormat, MeasurementMap, MeasurementValue, OcpEatClaims,
    OcpEatProfile, PrivateClaim, TaggedConciseEvidence,
};
use caliptra_ocp_eat::{CborEncodable, CborEncoder, TaggedBytes};
use serde::Deserialize;

const NONCE_LEN: usize = 32;
const KID_LEN: usize = 48;
const DEFAULT_CONCISE_EVIDENCE_MEASUREMENT_COUNT: usize = 8;
const CONCISE_EVIDENCE_MEASUREMENT_COUNT_ENV: &str = "CALIPTRA_CONCISE_EVIDENCE_MEASUREMENT_COUNT";
const EAT_CLAIMS_CONFIG_ENV: &str = "CALIPTRA_EAT_CLAIMS_CONFIG";
const EVIDENCE_DIGEST_SIZE: usize = 48;
const EVIDENCE_MEASUREMENT_KEY: u64 = 1;
const EVIDENCE_INTEGRITY_REGISTER_ID: u64 = 0;
const EVIDENCE_SHA384_ALG_ID: i32 = 7;
const MAX_FW_ID_CLASS_ID: &[u8; 10] = b"0xFFFFFFFF";
const MAX_PLATFORM_INFO_LEN: usize = 100;
const MAX_CONCISE_EVIDENCE_FIXED_HEADROOM: usize = 1024;
const MAX_CONCISE_EVIDENCE_MEASUREMENT_BYTES: usize = 512;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationEvidenceConfig {
    eat_claims: Option<EatClaimsConfig>,
    measurements: Option<MeasurementsConfig>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct EatClaimsConfig {
    issuer: Option<String>,
    cti_hex: Option<String>,
    ueid_hex: Option<String>,
    sueid_hex: Option<String>,
    oemid_hex: Option<String>,
    hwmodel_hex: Option<String>,
    uptime: Option<u64>,
    bootcount: Option<u64>,
    bootseed_hex: Option<String>,
    private_claims: Option<Vec<PrivateClaimConfig>>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct MeasurementsConfig {
    measurement_count: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateClaimConfig {
    key: i32,
    value_hex: String,
}

fn main() {
    println!("cargo:rerun-if-env-changed={EAT_CLAIMS_CONFIG_ENV}");
    println!("cargo:rerun-if-env-changed={CONCISE_EVIDENCE_MEASUREMENT_COUNT_ENV}");
    write_eat_claims_template();
    write_eat_cose_template();
}

fn write_eat_claims_template() {
    let config = read_config();
    let concise_evidence_measurement_count = concise_evidence_measurement_count(&config);
    let concise_evidence_max_size = concise_evidence_max_size(concise_evidence_measurement_count);
    let nonce_marker = marker::<NONCE_LEN>(0xa0);
    let concise_evidence = template_concise_evidence();
    let encoded_concise_evidence = encode_to_vec(&concise_evidence);
    let encoded_concise_evidence_bstr = encode_bytes(&encoded_concise_evidence);
    let debug_status_key = encode_type_value(0, 263);
    let debug_status_marker = encode_type_value(0, DebugStatus::Disabled as u64);

    let measurement_format = [MeasurementFormat::new(&concise_evidence)];
    let claim_values = ClaimValues::from_config(config.eat_claims.as_ref());
    let claims = OcpEatClaims {
        nonce: &nonce_marker,
        dbgstat: DebugStatus::Disabled,
        eat_profile: OcpEatProfile::EccMldsaX5ChainOrKid.oid(),
        measurements: &measurement_format,
        issuer: claim_values.issuer.as_deref(),
        cti: claim_values.cti.as_deref(),
        ueid: claim_values.ueid.as_deref(),
        sueid: claim_values.sueid.as_deref(),
        oemid: claim_values.oemid.as_deref(),
        hwmodel: claim_values.hwmodel.as_deref(),
        uptime: claim_values.uptime,
        bootcount: claim_values.bootcount,
        bootseed: claim_values.bootseed.as_deref(),
        dloas: None,
        rim_locators: None,
        private_claims: &claim_values.private_claims,
    };

    let mut evidence_scratch = [0u8; 512];
    let template = encode_claims_to_vec(&claims, &mut evidence_scratch);
    let nonce_pos = find_subslice(&template, &nonce_marker).expect("nonce marker not found");
    let debug_status_key_pos =
        find_subslice_from(&template, &debug_status_key, nonce_pos + nonce_marker.len())
            .expect("debug status claim key not found");
    let debug_status_pos = debug_status_key_pos + debug_status_key.len();
    assert_eq!(
        template.get(debug_status_pos..debug_status_pos + debug_status_marker.len()),
        Some(debug_status_marker.as_slice()),
        "debug status marker did not follow debug status claim key"
    );
    let evidence_pos = find_subslice_from(
        &template,
        &encoded_concise_evidence_bstr,
        debug_status_pos + debug_status_marker.len(),
    )
    .expect("concise evidence marker not found");

    let mut generated = String::new();
    generated.push_str("// Licensed under the Apache-2.0 license\n");
    generated.push_str("// AUTO-GENERATED FILE. DO NOT EDIT.\n");
    generated.push_str("// Generated by attestation-evidence build.rs from caliptra-ocp-eat\n\n");
    generated.push_str(&format!(
        "pub const CONCISE_EVIDENCE_MEASUREMENT_COUNT: usize = {concise_evidence_measurement_count};\n"
    ));
    generated.push_str(&format!(
        "pub const CONCISE_EVIDENCE_MAX_SIZE: usize = {concise_evidence_max_size};\n\n"
    ));
    write_bytes_const(&mut generated, "EAT_CLAIMS_PREFIX", &template[..nonce_pos]);
    write_bytes_const(
        &mut generated,
        "EAT_CLAIMS_EVIDENCE_PREFIX",
        &template[debug_status_pos + debug_status_marker.len()..evidence_pos],
    );
    write_bytes_const(
        &mut generated,
        "EAT_CLAIMS_DBGSTAT_PREFIX",
        &template[nonce_pos + nonce_marker.len()..debug_status_pos],
    );
    write_bytes_const(
        &mut generated,
        "EAT_CLAIMS_SUFFIX",
        &template[evidence_pos + encoded_concise_evidence_bstr.len()..],
    );

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    fs::write(out_dir.join("eat_claims_template.rs"), generated)
        .expect("write generated EAT claims template");
}

struct CoseTemplate {
    cose_preamble: Vec<u8>,
    sig_preamble: Vec<u8>,
    sig_bstr_header: Vec<u8>,
    signature_size: usize,
}

fn generate_cose_template(algorithm: CoseAlgorithm) -> CoseTemplate {
    let protected = algorithm.protected_header();
    let kid_marker = marker::<KID_LEN>(0x50);
    let unprotected = [CoseHeaderPair {
        key: header_params::KID,
        value: &kid_marker,
    }];
    let payload_marker = marker::<32>(0x60);
    let sig_marker = vec![0x70u8; algorithm.signature_size()];

    let mut ctx_buf = vec![0u8; 1024];
    let mut cose_buf = vec![0u8; 8192];

    let cose = CoseSign1::new(&mut cose_buf)
        .protected_header(&protected)
        .unprotected_headers(&unprotected)
        .payload(&payload_marker)
        .signature(&sig_marker);

    let sig_ctx_len = cose
        .get_signature_context(&mut ctx_buf)
        .expect("encode signature context");
    let sig_ctx = &ctx_buf[..sig_ctx_len];

    let cose_len = cose
        .encode(Some(&[cbor_tags::SELF_DESCRIBED_CBOR, cbor_tags::CWT]))
        .expect("encode COSE_Sign1");
    let cose_bytes = &cose_buf[..cose_len];

    let kid_pos = find_subslice(cose_bytes, &kid_marker).expect("kid marker not found");
    let cose_preamble = &cose_bytes[..kid_pos];

    let payload_bstr = encode_bytes(&payload_marker);
    let payload_bstr_pos = find_subslice_from(cose_bytes, &payload_bstr, kid_pos + KID_LEN)
        .expect("payload bstr not found");
    assert_eq!(payload_bstr_pos, kid_pos + KID_LEN);

    let sig_pos = find_subslice_from(
        cose_bytes,
        &sig_marker,
        payload_bstr_pos + payload_bstr.len(),
    )
    .expect("signature marker not found");
    let sig_bstr_header = &cose_bytes[payload_bstr_pos + payload_bstr.len()..sig_pos];
    assert_eq!(sig_pos + algorithm.signature_size(), cose_len);

    let sig_payload_pos =
        find_subslice(sig_ctx, &payload_bstr).expect("sig payload bstr not found");
    let sig_preamble = &sig_ctx[..sig_payload_pos];
    assert_eq!(sig_payload_pos + payload_bstr.len(), sig_ctx_len);

    CoseTemplate {
        cose_preamble: cose_preamble.to_vec(),
        sig_preamble: sig_preamble.to_vec(),
        sig_bstr_header: sig_bstr_header.to_vec(),
        signature_size: algorithm.signature_size(),
    }
}

fn write_eat_cose_template() {
    let esp384 = generate_cose_template(CoseAlgorithm::Esp384);
    let mldsa87 = generate_cose_template(CoseAlgorithm::Mldsa87);

    assert_eq!(
        esp384.cose_preamble.len(),
        mldsa87.cose_preamble.len(),
        "COSE preamble length must match across algorithms"
    );
    assert_eq!(
        esp384.sig_preamble.len(),
        mldsa87.sig_preamble.len(),
        "SIG preamble length must match across algorithms"
    );

    let mut generated = String::new();
    generated.push_str("// Licensed under the Apache-2.0 license\n");
    generated.push_str("// AUTO-GENERATED FILE. DO NOT EDIT.\n");
    generated.push_str("// Generated by attestation-evidence build.rs from caliptra-ocp-eat\n\n");

    generated.push_str(&format!(
        "pub const COSE_PREAMBLE_LEN: usize = {};\n",
        esp384.cose_preamble.len()
    ));
    generated.push_str(&format!(
        "#[allow(dead_code)]\npub const SIG_PREAMBLE_LEN: usize = {};\n",
        esp384.sig_preamble.len()
    ));
    generated.push_str(&format!("pub const KID_LEN: usize = {KID_LEN};\n"));
    generated.push_str("pub const PAYLOAD_BSTR_HEADER_LEN: usize = 3;\n");
    generated.push_str(&format!(
        "pub const ESP384_SIGNATURE_SIZE: usize = {};\n",
        esp384.signature_size
    ));
    generated.push_str(&format!(
        "pub const MLDSA87_SIGNATURE_SIZE: usize = {};\n\n",
        mldsa87.signature_size
    ));

    write_bytes_const(
        &mut generated,
        "ESP384_COSE_PREAMBLE",
        &esp384.cose_preamble,
    );
    write_bytes_const(&mut generated, "ESP384_SIG_PREAMBLE", &esp384.sig_preamble);
    write_bytes_const(
        &mut generated,
        "ESP384_SIG_BSTR_HEADER",
        &esp384.sig_bstr_header,
    );

    write_bytes_const(
        &mut generated,
        "MLDSA87_COSE_PREAMBLE",
        &mldsa87.cose_preamble,
    );
    write_bytes_const(
        &mut generated,
        "MLDSA87_SIG_PREAMBLE",
        &mldsa87.sig_preamble,
    );
    write_bytes_const(
        &mut generated,
        "MLDSA87_SIG_BSTR_HEADER",
        &mldsa87.sig_bstr_header,
    );

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    fs::write(out_dir.join("eat_cose_template.rs"), generated)
        .expect("write generated EAT COSE template");
}

fn read_config() -> AttestationEvidenceConfig {
    match env::var(EAT_CLAIMS_CONFIG_ENV) {
        Ok(path) => {
            let path = resolve_config_path(&path);
            println!("cargo:rerun-if-changed={}", path.display());
            let contents = fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
            toml::from_str(&contents)
                .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
        }
        Err(env::VarError::NotPresent) => AttestationEvidenceConfig::default(),
        Err(env::VarError::NotUnicode(_)) => {
            panic!("CALIPTRA_EAT_CLAIMS_CONFIG must be valid UTF-8")
        }
    }
}

fn resolve_config_path(path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() || path.exists() {
        return path;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let crate_relative = manifest_dir.join(&path);
    if crate_relative.exists() {
        return crate_relative;
    }

    if let Some(workspace_root) = find_workspace_root(&manifest_dir) {
        return workspace_root.join(path);
    }

    path
}

fn find_workspace_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|path| {
            fs::read_to_string(path.join("Cargo.toml"))
                .map(|contents| contents.lines().any(|line| line.trim() == "[workspace]"))
                .unwrap_or(false)
        })
        .map(Path::to_path_buf)
}

fn concise_evidence_measurement_count(config: &AttestationEvidenceConfig) -> usize {
    match env::var(CONCISE_EVIDENCE_MEASUREMENT_COUNT_ENV) {
        Ok(value) => value
            .parse::<usize>()
            .expect("CALIPTRA_CONCISE_EVIDENCE_MEASUREMENT_COUNT must be a usize"),
        Err(env::VarError::NotPresent) => config
            .measurements
            .as_ref()
            .and_then(|measurements| measurements.measurement_count)
            .unwrap_or(DEFAULT_CONCISE_EVIDENCE_MEASUREMENT_COUNT),
        Err(env::VarError::NotUnicode(_)) => {
            panic!("CALIPTRA_CONCISE_EVIDENCE_MEASUREMENT_COUNT must be valid UTF-8")
        }
    }
}

fn concise_evidence_max_size(measurement_count: usize) -> usize {
    let current_digest = [0xff; EVIDENCE_DIGEST_SIZE];
    let journey_digest = [0xff; EVIDENCE_DIGEST_SIZE];
    let vendor = "V".repeat(MAX_PLATFORM_INFO_LEN);
    let model = "M".repeat(MAX_PLATFORM_INFO_LEN);
    let digest = [DigestEntry {
        alg_id: EVIDENCE_SHA384_ALG_ID,
        value: &current_digest,
    }];
    let integrity_digest = [DigestEntry {
        alg_id: EVIDENCE_SHA384_ALG_ID,
        value: &journey_digest,
    }];
    let integrity_registers = [IntegrityRegisterEntry {
        id: IntegrityRegisterIdChoice::Uint(EVIDENCE_INTEGRITY_REGISTER_ID),
        digests: &integrity_digest,
    }];
    let measurements = [MeasurementMap {
        key: EVIDENCE_MEASUREMENT_KEY,
        mval: MeasurementValue {
            version: None,
            svn: Some(u64::MAX),
            digests: Some(&digest),
            integrity_registers: Some(&integrity_registers),
            raw_value: None,
            raw_value_mask: None,
        },
    }];
    let mut triples = Vec::with_capacity(measurement_count);
    for _ in 0..measurement_count {
        triples.push(EvidenceTripleRecord {
            environment: EnvironmentMap {
                class: ClassMap {
                    class_id: ClassIdTypeChoice::TaggedBytes(TaggedBytes::new(MAX_FW_ID_CLASS_ID)),
                    vendor: Some(&vendor),
                    model: Some(&model),
                },
            },
            measurements: &measurements,
        });
    }
    let evidence = ConciseEvidence::Tagged(TaggedConciseEvidence {
        concise_evidence: ConciseEvidenceMap {
            ev_triples: EvTriplesMap {
                evidence_triples: Some(&triples),
                identity_triples: None,
                dependency_triples: None,
                membership_triples: None,
                coswid_triples: None,
                attest_key_triples: None,
            },
            evidence_id: None,
            profile: None,
        },
    });
    let capacity = measurement_count
        .checked_mul(MAX_CONCISE_EVIDENCE_MEASUREMENT_BYTES)
        .and_then(|len| len.checked_add(MAX_CONCISE_EVIDENCE_FIXED_HEADROOM))
        .expect("configured measurement_count is too large");
    encode_to_vec_with_capacity(&evidence, capacity).len()
}

struct ClaimValues {
    issuer: Option<String>,
    cti: Option<Vec<u8>>,
    ueid: Option<Vec<u8>>,
    sueid: Option<Vec<u8>>,
    oemid: Option<Vec<u8>>,
    hwmodel: Option<Vec<u8>>,
    uptime: Option<u64>,
    bootcount: Option<u64>,
    bootseed: Option<Vec<u8>>,
    private_claim_values: Vec<Vec<u8>>,
    private_claims: Vec<PrivateClaim<'static>>,
}

impl ClaimValues {
    fn from_config(config: Option<&EatClaimsConfig>) -> Self {
        let mut out = Self {
            issuer: config.and_then(|config| config.issuer.clone()),
            cti: config.and_then(|config| decode_optional_hex(&config.cti_hex, "cti_hex")),
            ueid: config.and_then(|config| decode_optional_hex(&config.ueid_hex, "ueid_hex")),
            sueid: config.and_then(|config| decode_optional_hex(&config.sueid_hex, "sueid_hex")),
            oemid: config.and_then(|config| decode_optional_hex(&config.oemid_hex, "oemid_hex")),
            hwmodel: config
                .and_then(|config| decode_optional_hex(&config.hwmodel_hex, "hwmodel_hex")),
            uptime: config.and_then(|config| config.uptime),
            bootcount: config.and_then(|config| config.bootcount),
            bootseed: config
                .and_then(|config| decode_optional_hex(&config.bootseed_hex, "bootseed_hex")),
            private_claim_values: config
                .and_then(|config| config.private_claims.as_ref())
                .map(|claims| {
                    claims
                        .iter()
                        .map(|claim| decode_hex(&claim.value_hex, "private_claims.value_hex"))
                        .collect()
                })
                .unwrap_or_default(),
            private_claims: Vec::new(),
        };

        if let Some(claims) = config.and_then(|config| config.private_claims.as_ref()) {
            out.private_claims = claims
                .iter()
                .zip(out.private_claim_values.iter())
                .map(|(claim, value)| PrivateClaim {
                    key: claim.key,
                    value: leak_bytes(value),
                })
                .collect();
        }

        out
    }
}

fn decode_optional_hex(value: &Option<String>, name: &str) -> Option<Vec<u8>> {
    value.as_ref().map(|value| decode_hex(value, name))
}

fn decode_hex(value: &str, name: &str) -> Vec<u8> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if !value.len().is_multiple_of(2) {
        panic!("{name} must have an even number of hex digits");
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    let mut chars = value.as_bytes().chunks_exact(2);
    for pair in &mut chars {
        let high = hex_nibble(pair[0]).unwrap_or_else(|| panic!("{name} contains invalid hex"));
        let low = hex_nibble(pair[1]).unwrap_or_else(|| panic!("{name} contains invalid hex"));
        out.push((high << 4) | low);
    }
    out
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn leak_bytes(bytes: &[u8]) -> &'static [u8] {
    Box::leak(bytes.to_vec().into_boxed_slice())
}

fn template_concise_evidence() -> ConciseEvidence<'static> {
    ConciseEvidence::Tagged(TaggedConciseEvidence {
        concise_evidence: ConciseEvidenceMap {
            ev_triples: EvTriplesMap {
                evidence_triples: Some(&[]),
                identity_triples: None,
                dependency_triples: None,
                membership_triples: None,
                coswid_triples: None,
                attest_key_triples: None,
            },
            evidence_id: None,
            profile: None,
        },
    })
}

fn marker<const N: usize>(start: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = start.wrapping_add(idx as u8);
    }
    out
}

fn encode_claims_to_vec(claims: &OcpEatClaims<'_>, scratch: &mut [u8]) -> Vec<u8> {
    let mut out = [0u8; 1024];
    let len = {
        let mut encoder = CborEncoder::new(&mut out);
        claims
            .encode(&mut encoder, scratch)
            .expect("encode EAT claims template");
        encoder.len()
    };
    out[..len].to_vec()
}

fn encode_to_vec<T: CborEncodable>(value: &T) -> Vec<u8> {
    encode_to_vec_with_capacity(value, 512)
}

fn encode_to_vec_with_capacity<T: CborEncodable>(value: &T, capacity: usize) -> Vec<u8> {
    let mut out = vec![0u8; capacity];
    let len = {
        let mut encoder = CborEncoder::new(&mut out);
        value.encode(&mut encoder).expect("encode template value");
        encoder.len()
    };
    out[..len].to_vec()
}

fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = encode_type_value(2, bytes.len() as u64);
    out.extend_from_slice(bytes);
    out
}

fn encode_type_value(major_type: u8, value: u64) -> Vec<u8> {
    let major = major_type << 5;
    if value <= 23 {
        vec![major | value as u8]
    } else if value <= 0xff {
        vec![major | 24, value as u8]
    } else if value <= 0xffff {
        let mut out = vec![major | 25];
        out.extend_from_slice(&(value as u16).to_be_bytes());
        out
    } else if value <= 0xffff_ffff {
        let mut out = vec![major | 26];
        out.extend_from_slice(&(value as u32).to_be_bytes());
        out
    } else {
        let mut out = vec![major | 27];
        out.extend_from_slice(&value.to_be_bytes());
        out
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    find_subslice_from(haystack, needle, 0)
}

fn find_subslice_from(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    haystack
        .get(start..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|pos| start + pos)
}

fn write_bytes_const(out: &mut String, name: &str, bytes: &[u8]) {
    out.push_str(&format!("pub const {name}: &[u8] = &[\n"));
    for chunk in bytes.chunks(12) {
        out.push_str("    ");
        for byte in chunk {
            out.push_str(&format!("0x{byte:02x}, "));
        }
        out.push('\n');
    }
    out.push_str("];\n\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_mandatory_claims_and_default_measurement_count() {
        let config = AttestationEvidenceConfig::default();
        let claims = ClaimValues::from_config(config.eat_claims.as_ref());

        assert_eq!(claims.issuer, None);
        assert!(claims.cti.is_none());
        assert!(claims.ueid.is_none());
        assert!(claims.private_claims.is_empty());
        assert_eq!(
            concise_evidence_measurement_count(&config),
            DEFAULT_CONCISE_EVIDENCE_MEASUREMENT_COUNT
        );
        assert!(concise_evidence_max_size(DEFAULT_CONCISE_EVIDENCE_MEASUREMENT_COUNT) > 0);
    }

    #[test]
    fn configured_claims_and_measurement_count_are_static_template_inputs() {
        let config: AttestationEvidenceConfig = toml::from_str(
            r#"
[eat_claims]
issuer = "Caliptra-AK"
ueid_hex = "01020304050607"
private_claims = [
    { key = -80000, value_hex = "aabbccdd" },
]

[measurements]
measurement_count = 4
"#,
        )
        .unwrap();

        let claims = ClaimValues::from_config(config.eat_claims.as_ref());

        assert_eq!(claims.issuer.as_deref(), Some("Caliptra-AK"));
        assert_eq!(claims.ueid.as_deref(), Some(&[1, 2, 3, 4, 5, 6, 7][..]));
        assert_eq!(claims.private_claims.len(), 1);
        assert_eq!(claims.private_claims[0].key, -80000);
        assert_eq!(claims.private_claims[0].value, &[0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(concise_evidence_measurement_count(&config), 4);
        assert!(concise_evidence_max_size(4) < concise_evidence_max_size(5));
    }

    #[test]
    fn configured_claims_do_not_affect_concise_evidence_max_size() {
        let claims_only: AttestationEvidenceConfig = toml::from_str(
            r#"
[eat_claims]
issuer = "Caliptra-AK"
ueid_hex = "01020304050607"
private_claims = [
    { key = -80000, value_hex = "aabbccdd" },
]

[measurements]
measurement_count = 4
"#,
        )
        .unwrap();
        let mandatory_only: AttestationEvidenceConfig = toml::from_str(
            r#"
[measurements]
measurement_count = 4
"#,
        )
        .unwrap();

        let claims_count = concise_evidence_measurement_count(&claims_only);
        let mandatory_count = concise_evidence_measurement_count(&mandatory_only);

        assert_eq!(claims_count, mandatory_count);
        assert_eq!(
            concise_evidence_max_size(claims_count),
            concise_evidence_max_size(mandatory_count)
        );
    }

    #[test]
    fn cose_templates_match_rfc9052_structure() {
        let esp384 = generate_cose_template(CoseAlgorithm::Esp384);
        let mldsa87 = generate_cose_template(CoseAlgorithm::Mldsa87);

        assert_eq!(esp384.cose_preamble.len(), 20);
        assert_eq!(mldsa87.cose_preamble.len(), 20);
        assert_eq!(esp384.sig_preamble.len(), 22);
        assert_eq!(mldsa87.sig_preamble.len(), 22);

        assert_eq!(esp384.sig_bstr_header, &[0x58, 0x60]);
        assert_eq!(esp384.signature_size, 96);

        assert_eq!(mldsa87.sig_bstr_header, &[0x59, 0x12, 0x13]);
        assert_eq!(mldsa87.signature_size, 4627);

        // Preambles start with tags 55799, 61, 18, and array(4)
        assert_eq!(
            &esp384.cose_preamble[..7],
            &[0xd9, 0xd9, 0xf7, 0xd8, 0x3d, 0xd2, 0x84]
        );
        assert_eq!(
            &mldsa87.cose_preamble[..7],
            &[0xd9, 0xd9, 0xf7, 0xd8, 0x3d, 0xd2, 0x84]
        );

        // Sig preambles start with array(4), "Signature1"
        assert_eq!(
            &esp384.sig_preamble[..12],
            &[0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31]
        );
        assert_eq!(
            &mldsa87.sig_preamble[..12],
            &[0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31]
        );
    }

    #[test]
    fn eat_claims_template_uses_ecc_mldsa_profile_oid() {
        let nonce_marker = marker::<NONCE_LEN>(0xa0);
        let concise_evidence = template_concise_evidence();
        let measurement_format = [MeasurementFormat::new(&concise_evidence)];
        let claims = OcpEatClaims {
            nonce: &nonce_marker,
            dbgstat: DebugStatus::Disabled,
            eat_profile: OcpEatProfile::EccMldsaX5ChainOrKid.oid(),
            measurements: &measurement_format,
            issuer: None,
            cti: None,
            ueid: None,
            sueid: None,
            oemid: None,
            hwmodel: None,
            uptime: None,
            bootcount: None,
            bootseed: None,
            dloas: None,
            rim_locators: None,
            private_claims: &[],
        };
        let mut scratch = [0u8; 512];
        let encoded = encode_claims_to_vec(&claims, &mut scratch);
        let oid_bytes = OcpEatProfile::EccMldsaX5ChainOrKid.oid().as_bytes();
        assert!(find_subslice(&encoded, oid_bytes).is_some());
    }
}

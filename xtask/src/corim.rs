// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use caliptra_auth_man_types::AuthorizationManifest;
use caliptra_image_types::{ImageManifest, IMAGE_MANIFEST_BYTE_SIZE};
use p384::elliptic_curve::sec1::ToEncodedPoint;
use p384::pkcs8::EncodePrivateKey;
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha384};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use zerocopy::FromBytes;

const CALIPTRA_FW_NAME: &str = "caliptra_fw.bin";
const SOC_MANIFEST_NAME: &str = "soc_manifest.bin";
const MCU_RUNTIME_NAME: &str = "mcu_runtime.bin";

/// Default seed string for test signing key generation when no signing config is provided.
const DEFAULT_TEST_KEY_SEED: &str = "caliptra-corim-default-test-signing-key";

/// Class-ID strings matching the OCP EAT evidence triples produced by the device.
/// See platforms/emulator/runtime/userspace/apps/user/src/soc_env.rs
const CLASS_ID_FMC: &str = "FMC_INFO";
const CLASS_ID_RT: &str = "RT_INFO";

/// MCU runtime firmware identifier.
/// See common/flash-image/src/lib.rs: MCU_RT_IDENTIFIER = 0x00000002
const MCU_RT_FW_ID: u32 = 0x00000002;

fn default_vendor() -> String {
    "ChipsAlliance".to_string()
}
fn default_model() -> String {
    "Caliptra-SS".to_string()
}
fn default_hash_algo() -> String {
    "sha-384".to_string()
}
fn default_output_dir() -> String {
    "target/corim".to_string()
}

/// Configuration for CoRIM generation, loaded from a JSON config file.
#[derive(Deserialize)]
pub struct CorimConfig {
    /// Vendor string for SoC firmware components.
    #[serde(default = "default_vendor")]
    pub vendor: String,

    /// Model string for SoC firmware components.
    #[serde(default = "default_model")]
    pub model: String,

    /// Hash algorithm for reference value digests ("sha-256" or "sha-384").
    #[serde(default = "default_hash_algo")]
    pub hash_algo: String,

    /// Output directory for generated CoRIM/CoMID files.
    #[serde(default = "default_output_dir")]
    pub output_dir: String,

    /// Signing configuration (omit for unsigned output).
    pub signing: Option<SigningConfig>,
}

impl Default for CorimConfig {
    fn default() -> Self {
        Self {
            vendor: default_vendor(),
            model: default_model(),
            hash_algo: default_hash_algo(),
            output_dir: default_output_dir(),
            signing: None,
        }
    }
}

impl CorimConfig {
    /// Load config from a JSON file, or return defaults if no path is given.
    pub fn load(path: Option<&str>) -> Result<Self> {
        match path {
            Some(p) => {
                let data = std::fs::read_to_string(p)
                    .map_err(|e| anyhow::anyhow!("Failed to read config file '{}': {}", p, e))?;
                let config: CorimConfig = serde_json::from_str(&data)
                    .map_err(|e| anyhow::anyhow!("Failed to parse config file '{}': {}", p, e))?;
                config.validate()?;
                Ok(config)
            }
            None => Ok(Self::default()),
        }
    }

    /// Print a sample config JSON to stdout with all fields documented.
    pub fn print_sample() {
        let sample = r#"{
  // Vendor string for SoC firmware components (default: "ChipsAlliance")
  "vendor": "ChipsAlliance",

  // Model string for SoC firmware components (default: "Caliptra-SS")
  "model": "Caliptra-SS",

  // Hash algorithm for reference value digests: "sha-256" or "sha-384" (default: "sha-384")
  "hash_algo": "sha-384",

  // Output directory for generated CoRIM/CoMID files (default: "target/corim")
  "output_dir": "target/corim",

  // Signing configuration (omit entirely for unsigned output)
  "signing": {
    // Option A: Deterministic test key — seed string hashed with SHA-384 to derive P-384 key pair
    "test_key": "my-test-seed-string"

    // Option B: External signing key (mutually exclusive with test_key)
    // "key":  "/path/to/signing-key.jwk",   // JWK private key file (required)
    // "cert": "/path/to/signing-cert.der",   // X.509 certificate in DER format (required)
    // "meta": "/path/to/meta.json"           // Signing meta JSON (optional, auto-generated if omitted)
  }
}"#;
        println!("{}", sample);
    }

    fn validate(&self) -> Result<()> {
        if let Some(signing) = &self.signing {
            if signing.test_key.is_some() && signing.key.is_some() {
                bail!(
                    "Config error: 'test_key' and 'key' are mutually exclusive in signing config"
                );
            }
            if signing.key.is_some() && signing.cert.is_none() {
                bail!("Config error: 'cert' is required when 'key' is specified in signing config");
            }
        }
        Ok(())
    }
}

/// Signing configuration within the CoRIM config.
#[derive(Deserialize)]
pub struct SigningConfig {
    /// Seed string for deterministic test key generation.
    pub test_key: Option<String>,
    /// Path to JWK signing key file.
    pub key: Option<String>,
    /// Path to DER signing certificate file.
    pub cert: Option<String>,
    /// Path to signing meta JSON (auto-generated if not provided).
    pub meta: Option<String>,
}

/// A firmware component whose reference values will appear in the CoMID,
/// structured to match the OCP EAT evidence triples from the device.
struct EvidenceComponent {
    /// Class-ID string matching the evidence environment (e.g. "FMC_INFO").
    class_id: String,
    /// Measurement key matching the evidence mkey.
    mkey: usize,
    /// Vendor string (only set for SOC firmware components).
    vendor: Option<String>,
    /// Model string (only set for SOC firmware components).
    model: Option<String>,
    /// Pre-formatted digest string (e.g. "sha-384:base64...").
    digest: String,
    /// Security Version Number (omitted for SoC firmware components).
    svn: Option<u32>,
}

/// Compute SHA-256 digest and return as "sha-256:<base64>" string.
fn sha256_digest_str(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("sha-256:{}", STANDARD.encode(hash))
}

/// Compute SHA-384 digest and return as "sha-384:<base64>" string.
fn sha384_digest_str(data: &[u8]) -> String {
    let hash = Sha384::digest(data);
    format!("sha-384:{}", STANDARD.encode(hash))
}

/// Compute digest string using the configured hash algorithm.
fn compute_digest(data: &[u8], hash_algo: &str) -> String {
    match hash_algo {
        "sha-256" => sha256_digest_str(data),
        _ => sha384_digest_str(data),
    }
}

/// Format a raw SHA-384 digest (from auth manifest metadata) as a digest string.
fn sha384_raw_to_digest_str(digest: &[u8; 48]) -> String {
    format!("sha-384:{}", STANDARD.encode(digest))
}

/// Read firmware binaries from the all-build ZIP bundle and decompose them
/// into evidence-matching components.
///
/// Returns components matching the OCP EAT evidence structure:
///   mkey 0: FMC_INFO      - Caliptra FMC binary (from caliptra_fw.bin)
///   mkey 1: RT_INFO        - Caliptra Runtime binary (from caliptra_fw.bin)
///   mkey 2+: SoC firmware  - Auto-discovered from AuthManifest metadata
fn read_evidence_components(
    bundle_path: &Path,
    config: &CorimConfig,
    feature: Option<&str>,
) -> Result<Vec<EvidenceComponent>> {
    let file = std::fs::File::open(bundle_path)?;
    let mut zip = zip::ZipArchive::new(file)?;

    // When a feature is specified, prefer per-feature entries over generic ones.
    let soc_manifest_name = feature
        .map(|f| format!("mcu-test-soc-manifest-{}.bin", f))
        .unwrap_or_else(|| SOC_MANIFEST_NAME.to_string());
    let mcu_runtime_name = feature
        .map(|f| format!("mcu-test-runtime-{}.bin", f))
        .unwrap_or_else(|| MCU_RUNTIME_NAME.to_string());

    let mut caliptra_fw_data: Option<Vec<u8>> = None;
    let mut soc_manifest_data: Option<Vec<u8>> = None;
    let mut mcu_runtime_data: Option<Vec<u8>> = None;

    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        let name = file.name().to_string();
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        if name == CALIPTRA_FW_NAME {
            caliptra_fw_data = Some(data);
        } else if name == soc_manifest_name {
            soc_manifest_data = Some(data);
        } else if name == mcu_runtime_name {
            mcu_runtime_data = Some(data);
        }
    }

    let caliptra_fw = caliptra_fw_data
        .ok_or_else(|| anyhow::anyhow!("{} not found in bundle", CALIPTRA_FW_NAME))?;
    let soc_manifest = soc_manifest_data
        .ok_or_else(|| anyhow::anyhow!("{} not found in bundle", soc_manifest_name))?;

    // Decompose caliptra_fw.bin into FMC and Runtime
    if caliptra_fw.len() < IMAGE_MANIFEST_BYTE_SIZE {
        bail!(
            "caliptra_fw.bin too small ({} bytes) to contain manifest ({} bytes)",
            caliptra_fw.len(),
            IMAGE_MANIFEST_BYTE_SIZE
        );
    }

    let image_manifest: ImageManifest = {
        let bytes: [u8; IMAGE_MANIFEST_BYTE_SIZE] = caliptra_fw[..IMAGE_MANIFEST_BYTE_SIZE]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to read manifest bytes"))?;
        zerocopy::transmute!(bytes)
    };

    let fmc_offset = image_manifest.fmc.offset as usize;
    let fmc_size = image_manifest.fmc.size as usize;
    let rt_offset = image_manifest.runtime.offset as usize;
    let rt_size = image_manifest.runtime.size as usize;

    if fmc_offset + fmc_size > caliptra_fw.len() || rt_offset + rt_size > caliptra_fw.len() {
        bail!("caliptra_fw.bin truncated - FMC or runtime extends beyond bundle size");
    }

    let fmc_content = &caliptra_fw[fmc_offset..fmc_offset + fmc_size];
    let rt_content = &caliptra_fw[rt_offset..rt_offset + rt_size];

    // Extract SVN from the Caliptra image manifest header
    let caliptra_fw_svn = image_manifest.header.svn;

    // Parse AuthManifest to get preamble version/SVN and per-image metadata
    let auth_manifest = AuthorizationManifest::read_from_bytes(&soc_manifest).map_err(|e| {
        anyhow::anyhow!(
            "Failed to parse soc_manifest.bin as AuthorizationManifest: {:?}",
            e
        )
    })?;
    // Build the fixed evidence components (mkeys 0-1)
    let mut components = vec![
        EvidenceComponent {
            class_id: CLASS_ID_FMC.to_string(),
            mkey: 0,
            vendor: None,
            model: None,
            digest: compute_digest(fmc_content, &config.hash_algo),
            svn: Some(caliptra_fw_svn),
        },
        EvidenceComponent {
            class_id: CLASS_ID_RT.to_string(),
            mkey: 1,
            vendor: None,
            model: None,
            digest: compute_digest(rt_content, &config.hash_algo),
            svn: Some(caliptra_fw_svn),
        },
    ];

    // Auto-discover SoC firmware components from the AuthManifest metadata
    let entry_count = auth_manifest.image_metadata_col.entry_count as usize;
    for i in 0..entry_count {
        if i >= auth_manifest.image_metadata_col.image_metadata_list.len() {
            break;
        }
        let metadata = &auth_manifest.image_metadata_col.image_metadata_list[i];

        // For MCU runtime, compute digest from the binary in the ZIP,
        // padded to match the flash image alignment used at runtime.
        // The flash image builder pads images to 256-byte boundaries, and
        // Caliptra's AUTHORIZE_AND_STASH hashes the padded data.
        // For other SoC images, use the SHA-384 digest from the manifest metadata.
        let digest = if metadata.fw_id == MCU_RT_FW_ID {
            if let Some(ref mcu_rt) = mcu_runtime_data {
                let padded_len = mcu_rt.len().next_multiple_of(256);
                let mut padded = mcu_rt.clone();
                padded.resize(padded_len, 0);
                compute_digest(&padded, &config.hash_algo)
            } else {
                sha384_raw_to_digest_str(&metadata.digest)
            }
        } else {
            sha384_raw_to_digest_str(&metadata.digest)
        };

        components.push(EvidenceComponent {
            class_id: format!("0x{:08X}", metadata.fw_id),
            mkey: 2 + i,
            vendor: Some(config.vendor.clone()),
            model: Some(config.model.clone()),
            digest,
            svn: None,
        });
    }

    Ok(components)
}

/// Generate the CoMID JSON template with reference values structured to match
/// the OCP EAT evidence triples from the device.
///
/// Each evidence component gets its own environment (class-id) and measurement
/// entry with svn and digests fields.
fn generate_comid_template(components: &[EvidenceComponent]) -> serde_json::Value {
    let tag_id = uuid::Uuid::new_v4().to_string().to_uppercase();

    let reference_values: Vec<serde_json::Value> = components
        .iter()
        .map(|comp| {
            // Encode class-id string as bytes (base64 of UTF-8).
            //
            // NOTE: The evidence encoder (ocp-eat crate) wraps class-id strings
            // with CBOR Tag 111 (OID), but cocli's "oid" type requires valid
            // dotted-notation OIDs and BER-encodes them. Since the evidence uses
            // raw UTF-8 text under Tag 111 (not proper BER-encoded OIDs), cocli
            // cannot produce a matching encoding. Using "bytes" (Tag 560) here
            // preserves the correct byte content. The evidence encoder's class-id
            // encoding should be updated to use either proper OIDs or Tag 560 for
            // full verifier compatibility.
            let class_id_b64 = STANDARD.encode(comp.class_id.as_bytes());

            // Build class map - include vendor/model only when present
            let mut class_map = serde_json::json!({
                "id": {
                    "type": "bytes",
                    "value": class_id_b64
                }
            });
            if let Some(vendor) = &comp.vendor {
                class_map["vendor"] = serde_json::json!(vendor);
            }
            if let Some(model) = &comp.model {
                class_map["model"] = serde_json::json!(model);
            }

            let mut meas_value = serde_json::json!({
                "digests": [comp.digest]
            });
            if let Some(svn) = comp.svn {
                meas_value["svn"] = serde_json::json!({
                    "type": "exact-value",
                    "value": svn
                });
            }

            serde_json::json!({
                "environment": {
                    "class": class_map
                },
                "measurements": [
                    {
                        "key": {
                            "type": "uint",
                            "value": comp.mkey
                        },
                        "value": meas_value
                    }
                ]
            })
        })
        .collect();

    serde_json::json!({
        "tag-identity": {
            "id": tag_id,
            "version": 0
        },
        "entities": [
            {
                "name": "ChipsAlliance",
                "regid": "https://chipsalliance.org",
                "roles": ["tagCreator", "creator", "maintainer"]
            }
        ],
        "triples": {
            "reference-values": reference_values
        }
    })
}

/// Generate the CoRIM JSON template.
fn generate_corim_template() -> serde_json::Value {
    let corim_id = uuid::Uuid::new_v4().to_string();

    serde_json::json!({
        "corim-id": corim_id,
        "validity": {
            "not-before": "2025-01-01T00:00:00Z",
            "not-after": "2035-12-31T00:00:00Z"
        },
        "entities": [
            {
                "name": "ChipsAlliance",
                "regid": "chipsalliance.org",
                "roles": ["manifestCreator"]
            }
        ]
    })
}

/// Generate ECC P-384 test signing keys from a caller-supplied 48-byte seed.
///
/// The seed is used directly as the P-384 private scalar, so the same seed
/// always produces the same key pair.
///
/// Produces:
///   - `signing-key.jwk`  (JWK private key for cocli)
///   - `signing-key.pem`  (PKCS#8 PEM for openssl cert generation)
///   - `signing-cert.der` (self-signed X.509 certificate in DER format)
fn generate_test_keys(
    keys_dir: &Path,
    seed: &[u8; 48],
    subject: &str,
) -> Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(keys_dir)?;

    let jwk_path = keys_dir.join("signing-key.jwk");
    let cert_path = keys_dir.join("signing-cert.der");

    // Skip regeneration if both key and certificate already exist
    if jwk_path.exists() && cert_path.exists() {
        println!(
            "  Reusing existing test signing keys in {}",
            keys_dir.display()
        );
        return Ok((jwk_path, cert_path));
    }

    let secret_key = p384::SecretKey::from_bytes(seed[..].into())
        .map_err(|e| anyhow::anyhow!("Failed to create P-384 key from seed: {}", e))?;

    // Extract public key coordinates
    let public_key = secret_key.public_key();
    let point = public_key.to_encoded_point(false);
    let x_bytes = point
        .x()
        .ok_or_else(|| anyhow::anyhow!("missing x coordinate"))?;
    let y_bytes = point
        .y()
        .ok_or_else(|| anyhow::anyhow!("missing y coordinate"))?;

    // Write JWK (JSON Web Key) — cocli requires this format for signing
    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-384",
        "x": URL_SAFE_NO_PAD.encode(&x_bytes[..]),
        "y": URL_SAFE_NO_PAD.encode(&y_bytes[..]),
        "d": URL_SAFE_NO_PAD.encode(&seed[..])
    });
    std::fs::write(&jwk_path, serde_json::to_string_pretty(&jwk)?)?;

    // Write PKCS#8 PEM (for openssl certificate generation)
    let pem_path = keys_dir.join("signing-key.pem");
    let pkcs8_der = secret_key
        .to_pkcs8_der()
        .map_err(|e| anyhow::anyhow!("Failed to encode PKCS#8 DER: {}", e))?;
    let pem_b64 = STANDARD.encode(pkcs8_der.as_bytes());
    let mut pem_string = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in pem_b64.as_bytes().chunks(64) {
        pem_string.push_str(std::str::from_utf8(chunk).unwrap());
        pem_string.push('\n');
    }
    pem_string.push_str("-----END PRIVATE KEY-----\n");
    std::fs::write(&pem_path, pem_string.as_bytes())?;

    // Generate self-signed X.509 certificate in DER format using openssl
    let openssl_result = Command::new("openssl")
        .args([
            "req",
            "-new",
            "-x509",
            "-key",
            pem_path.to_str().unwrap(),
            "-out",
            cert_path.to_str().unwrap(),
            "-outform",
            "DER",
            "-days",
            "3650",
            "-subj",
            subject,
            "-sha384",
        ])
        .output();

    match openssl_result {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("openssl certificate generation failed: {}", stderr);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("openssl not found in PATH. Install OpenSSL to generate test certificates.");
        }
        Err(e) => {
            bail!("Failed to run openssl: {}", e);
        }
    }

    Ok((jwk_path, cert_path))
}

/// Generate the CoRIM signing meta JSON template.
fn generate_meta_template(output_dir: &Path) -> Result<PathBuf> {
    let meta = serde_json::json!({
        "signer": {
            "name": "Caliptra Test Signer",
            "uri": "https://chipsalliance.org"
        },
        "validity": {
            "not-before": "2025-01-01T00:00:00Z",
            "not-after": "2035-12-31T00:00:00Z"
        }
    });
    let meta_path = output_dir.join("meta-caliptra.json");
    std::fs::write(&meta_path, serde_json::to_string_pretty(&meta)?)?;
    Ok(meta_path)
}

/// Generate CoRIM from a firmware bundle ZIP using cocli.
///
/// The generated CoMID reference values are structured to match the OCP EAT
/// evidence triples produced by the Caliptra subsystem:
///
///   mkey 0: FMC_INFO      - Caliptra FMC digest
///   mkey 1: RT_INFO        - Caliptra Runtime digest
///   mkey 2+: SoC FW        - Auto-discovered from AuthManifest metadata
///
/// Each measurement includes svn and digest fields.
///
/// Note: integrity-registers (journey PCR values) are runtime-computed and
/// cannot be pre-determined from static build artifacts. They are not included
/// in the reference values.
pub fn generate(bundle: &str, config: CorimConfig, feature: Option<&str>) -> Result<()> {
    let bundle_path = Path::new(bundle);
    if !bundle_path.exists() {
        bail!(
            "Bundle file not found: {}. Run `cargo xtask all-build` first.",
            bundle
        );
    }

    let output_path = Path::new(&config.output_dir);
    std::fs::create_dir_all(output_path)?;

    // Step 1: Read and decompose firmware binaries to match evidence structure
    println!("Reading firmware binaries from: {}", bundle);
    let components = read_evidence_components(bundle_path, &config, feature)?;
    for comp in &components {
        println!(
            "  [mkey {}] {} ({})",
            comp.mkey,
            comp.class_id,
            comp.digest.split(':').next().unwrap_or("unknown"),
        );
    }
    println!();
    println!("Note: integrity-registers (journey PCR values) are runtime-computed");
    println!("and are not included in the reference values.");

    // Step 2: Generate CoMID JSON template
    let comid_template = generate_comid_template(&components);
    let comid_template_path = output_path.join("comid-caliptra.json");
    let comid_json = serde_json::to_string_pretty(&comid_template)?;
    std::fs::write(&comid_template_path, &comid_json)?;
    println!(
        "Generated CoMID template: {}",
        comid_template_path.display()
    );

    // Step 3: Generate CoRIM JSON template
    let corim_template = generate_corim_template();
    let corim_template_path = output_path.join("corim-caliptra.json");
    let corim_json = serde_json::to_string_pretty(&corim_template)?;
    std::fs::write(&corim_template_path, &corim_json)?;
    println!(
        "Generated CoRIM template: {}",
        corim_template_path.display()
    );

    // Step 4: Create CBOR-encoded CoMID using cocli
    println!("Creating CBOR-encoded CoMID...");
    let comid_create = Command::new("cocli")
        .args([
            "comid",
            "create",
            "--template",
            comid_template_path.to_str().unwrap(),
            "--output-dir",
            output_path.to_str().unwrap(),
        ])
        .output();

    let comid_cbor_path = output_path.join("comid-caliptra.cbor");
    match comid_create {
        Ok(output) if output.status.success() => {
            println!("  CoMID CBOR created successfully");
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("cocli comid create failed: {}", stderr);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!(
                "cocli not found in PATH. Install it with: go install github.com/veraison/cocli@latest"
            );
        }
        Err(e) => {
            bail!("Failed to run cocli: {}", e);
        }
    }

    // Step 5: Create unsigned CoRIM from CoMID + template
    println!("Creating unsigned CoRIM...");
    let corim_output_path = output_path.join("corim-caliptra.cbor");
    let corim_create = Command::new("cocli")
        .args([
            "corim",
            "create",
            "--template",
            corim_template_path.to_str().unwrap(),
            "--comid",
            comid_cbor_path.to_str().unwrap(),
            "--output",
            corim_output_path.to_str().unwrap(),
        ])
        .output();

    match corim_create {
        Ok(output) if output.status.success() => {
            println!(
                "CoRIM created successfully: {}",
                corim_output_path.display()
            );
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("cocli corim create failed: {}", stderr);
        }
        Err(e) => {
            bail!("Failed to run cocli: {}", e);
        }
    }

    // Display the unsigned CoRIM contents for verification
    println!("\nDisplaying unsigned CoRIM contents...");
    let display = Command::new("cocli")
        .args([
            "corim",
            "display",
            "--file",
            corim_output_path.to_str().unwrap(),
            "--show-tags",
        ])
        .output();

    if let Ok(output) = display {
        if output.status.success() {
            println!("{}", String::from_utf8_lossy(&output.stdout));
        }
    }

    // Resolve signing key and certificate paths — always sign the CoRIM.
    // When no signing config is provided, use a default test key seed.
    let (jwk_path, cert_path) = if let Some(ref sign_cfg) = config.signing {
        if let Some(ref seed_str) = sign_cfg.test_key {
            // Generate deterministic test keys from seed
            let keys_dir = output_path.join("fake_keys");
            println!("Generating deterministic P-384 test signing keys...");
            let seed: [u8; 48] = Sha384::digest(seed_str.as_bytes()).into();
            generate_test_keys(&keys_dir, &seed, "/CN=Caliptra Test Signer/O=ChipsAlliance")?
        } else if let Some(ref key_path) = sign_cfg.key {
            // Use provided key and certificate
            let jwk_path = PathBuf::from(key_path);
            let cert_path = PathBuf::from(sign_cfg.cert.as_ref().unwrap());
            if !jwk_path.exists() {
                bail!("Signing key not found: {}", jwk_path.display());
            }
            if !cert_path.exists() {
                bail!("Signing certificate not found: {}", cert_path.display());
            }
            (jwk_path, cert_path)
        } else {
            // signing config present but no key specified — use default test key
            let keys_dir = output_path.join("fake_keys");
            println!("Generating deterministic P-384 test signing keys (default seed)...");
            let seed: [u8; 48] = Sha384::digest(DEFAULT_TEST_KEY_SEED.as_bytes()).into();
            generate_test_keys(&keys_dir, &seed, "/CN=Caliptra Test Signer/O=ChipsAlliance")?
        }
    } else {
        // No signing config at all — use default test key
        let keys_dir = output_path.join("fake_keys");
        println!("Generating deterministic P-384 test signing keys (default seed)...");
        let seed: [u8; 48] = Sha384::digest(DEFAULT_TEST_KEY_SEED.as_bytes()).into();
        generate_test_keys(&keys_dir, &seed, "/CN=Caliptra Test Signer/O=ChipsAlliance")?
    };
    println!("  JWK key:     {}", jwk_path.display());
    println!("  Certificate: {}", cert_path.display());

    // Resolve meta path
    let meta_path = if let Some(ref m) = config.signing.as_ref().and_then(|s| s.meta.as_ref()) {
        let p = PathBuf::from(m);
        if !p.exists() {
            bail!("Meta file not found: {}", p.display());
        }
        p
    } else {
        generate_meta_template(output_path)?
    };
    println!("  Meta:        {}", meta_path.display());

    // Sign the CoRIM
    println!("\nSigning CoRIM...");
    let signed_corim_path = output_path.join("signed-corim-refval-caliptra.cbor");
    let corim_sign = Command::new("cocli")
        .args([
            "corim",
            "sign",
            "--file",
            corim_output_path.to_str().unwrap(),
            "--key",
            jwk_path.to_str().unwrap(),
            "--meta",
            meta_path.to_str().unwrap(),
            "--cert",
            cert_path.to_str().unwrap(),
            "--output",
            signed_corim_path.to_str().unwrap(),
        ])
        .output();

    match corim_sign {
        Ok(output) if output.status.success() => {
            println!("Signed CoRIM created: {}", signed_corim_path.display());
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("cocli corim sign failed: {}", stderr);
        }
        Err(e) => {
            bail!("Failed to run cocli: {}", e);
        }
    }

    println!("\nOutput files:");
    println!("  CoMID template:  {}", comid_template_path.display());
    println!("  CoRIM template:  {}", corim_template_path.display());
    println!("  CoMID CBOR:      {}", comid_cbor_path.display());
    println!("  CoRIM CBOR:      {}", corim_output_path.display());
    println!("  Signed CoRIM:    {}", signed_corim_path.display());
    println!("  Signing key:     {}", jwk_path.display());
    println!("  Certificate:     {}", cert_path.display());

    Ok(())
}

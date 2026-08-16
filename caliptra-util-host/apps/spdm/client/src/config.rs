// Licensed under the Apache-2.0 license

//! Validator test configuration (TOML-based).
//!
//! Each VDM command has its own config section. Adding a new command:
//! 1. Add a new config struct (e.g., `ExportAttestedCsrConfig`)
//! 2. Add it as a `#[serde(default)]` field in `TestConfig`

use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TestConfig {
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub spdm: SpdmTestConfig,
    #[serde(default)]
    pub validation: ValidationConfig,
    #[serde(default)]
    pub export_attested_csr: ExportAttestedCsrConfig,
    #[serde(default)]
    pub get_attestation: GetAttestationConfig,
    #[serde(default)]
    pub debug_unlock: DebugUnlockConfig,
    #[serde(default)]
    pub authorized_commands: AuthorizedCommandsConfig,
    #[serde(default)]
    pub fe_prog: FeProgConfig,
    #[serde(default)]
    pub provision_vendor_pk_hash: ProvisionVendorPkHashConfig,
    #[serde(default)]
    pub provision_owner_pk_hash: ProvisionOwnerPkHashConfig,
    #[serde(default)]
    pub increase_caliptra_min_svn: IncreaseCaliptraMinSvnConfig,
    #[serde(default)]
    pub revoke_vendor_pub_key: RevokeVendorPubKeyConfig,
    #[serde(default)]
    pub revoke_vendor_pk_hash: RevokeVendorPkHashConfig,
    #[serde(default)]
    pub dot: DotConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "default_server_address")]
    pub server_address: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            server_address: default_server_address(),
        }
    }
}

fn default_server_address() -> String {
    "127.0.0.1:2323".to_string()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SpdmTestConfig {
    #[serde(default)]
    pub slot_id: u8,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ValidationConfig {
    /// Optional isolated validator suite selected by the integration harness.
    #[serde(default)]
    pub fuse_suite: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExportAttestedCsrConfig {
    #[serde(default = "default_key_ids")]
    pub key_ids: Vec<u32>,
    #[serde(default = "default_algorithm")]
    pub algorithm: u32,
}

fn default_key_ids() -> Vec<u32> {
    vec![0, 1, 2]
}

fn default_algorithm() -> u32 {
    1
}

impl Default for ExportAttestedCsrConfig {
    fn default() -> Self {
        Self {
            key_ids: default_key_ids(),
            algorithm: default_algorithm(),
        }
    }
}

/// Configuration for the `GET_ATTESTATION` validation.
///
/// The set of formats to exercise is not configured here: the validator asks
/// the device for its supported-format bitmap and drives that, so the test
/// tracks the firmware's build-time feature set automatically.
#[derive(Debug, Clone, Deserialize)]
pub struct GetAttestationConfig {
    #[serde(default = "default_algorithm")]
    pub algorithm: u32,
    /// 32-byte freshness nonce, hex-encoded. Randomly generated when unset.
    #[serde(default)]
    pub nonce: Option<String>,
}

impl Default for GetAttestationConfig {
    fn default() -> Self {
        Self {
            algorithm: default_algorithm(),
            nonce: None,
        }
    }
}

impl GetAttestationConfig {
    /// Returns the configured nonce, or a freshly generated random one.
    ///
    /// A nonce is always sent; the only choice is whether it is pinned. It is
    /// random by default because a hardcoded value makes the request identical
    /// on every run, which a replayed or cached response would satisfy. Pin it
    /// in config only to reproduce a specific failure.
    pub fn nonce_bytes(&self) -> anyhow::Result<[u8; 32]> {
        match &self.nonce {
            None => {
                let mut out = [0u8; 32];
                getrandom::getrandom(&mut out)
                    .map_err(|e| anyhow::anyhow!("failed to generate a random nonce: {e}"))?;
                Ok(out)
            }
            Some(hex) => {
                let raw = hex.trim().trim_start_matches("0x");
                if raw.len() != 64 {
                    anyhow::bail!("get_attestation.nonce must be 64 hex characters (32 bytes)");
                }
                let mut out = [0u8; 32];
                for (i, byte) in out.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16)
                        .map_err(|_| anyhow::anyhow!("get_attestation.nonce is not valid hex"))?;
                }
                Ok(out)
            }
        }
    }
}

impl TestConfig {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DebugUnlockConfig {
    #[serde(default = "default_unlock_level")]
    pub unlock_level: u8,
    #[serde(default)]
    pub enabled: bool,
}

fn default_unlock_level() -> u8 {
    1
}

impl Default for DebugUnlockConfig {
    fn default() -> Self {
        Self {
            unlock_level: default_unlock_level(),
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthorizedCommandsConfig {
    #[serde(default)]
    pub ecc_auth_key: Option<String>,
    #[serde(default)]
    pub mldsa_auth_key: Option<String>,
    #[serde(default)]
    pub negative_authorization_tests: bool,
    #[serde(default)]
    pub policy_rejection_tests: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FeProgConfig {
    #[serde(default)]
    pub partition: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for FeProgConfig {
    fn default() -> Self {
        Self {
            partition: 0,
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProvisionVendorPkHashConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub slot: u32,
    #[serde(default)]
    pub hash: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProvisionOwnerPkHashConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub hash: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct IncreaseCaliptraMinSvnConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub flags: u32,
    #[serde(default)]
    pub svn: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RevokeVendorPubKeyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub reserved: u32,
    #[serde(default)]
    pub vendor_pk_hash_slot: u32,
    #[serde(default)]
    pub key_type: u32,
    #[serde(default)]
    pub key_index: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RevokeVendorPkHashConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub reserved: u32,
    #[serde(default)]
    pub vendor_pk_hash_slot: u32,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DotConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cak: Option<String>,
    #[serde(default)]
    pub ecc_lak_private_key: Option<String>,
    #[serde(default)]
    pub mldsa_lak_seed: Option<String>,
}

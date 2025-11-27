// Licensed under the Apache-2.0 license.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize)]
pub struct FuseConfig {
    pub partitions: Option<Vec<FusePartitionInfo>>,
    /// Vendor-specific secret fuses
    pub secret_vendor: Vec<HashMap<String, u32>>,
    /// Vendor-specific non-secret fuses
    pub non_secret_vendor: Vec<HashMap<String, u32>>,
    /// Additional fuses outside of the standard areas
    /// TODO: define this
    pub other_fuses: Option<HashMap<String, String>>,
    /// Field definitions with specific bit configurations
    pub fields: Vec<FieldDefinition>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FusePartitionInfo {
    pub num: u32,
    pub name: String,
    pub dot: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FieldDefinition {
    /// Globally unique field name
    pub name: String,
    /// Size of the field in bits
    pub bits: u32,
}

pub fn parse_fuse_hjson(fname: &str) -> Result<FuseConfig> {
    let content = std::fs::read_to_string(fname)?;
    parse_fuse_hjson_str(&content)
}

pub fn parse_fuse_hjson_str(hjson_str: &str) -> Result<FuseConfig> {
    let config: FuseConfig = serde_hjson::from_str(hjson_str)?;
    Ok(config)
}

impl FuseConfig {
    /// Get the total size of secret vendor fuses in bytes
    pub fn secret_vendor_total_size(&self) -> u32 {
        self.secret_vendor.iter().flat_map(|map| map.values()).sum()
    }

    /// Get the total size of non-secret vendor fuses in bytes
    pub fn non_secret_vendor_total_size(&self) -> u32 {
        self.non_secret_vendor
            .iter()
            .flat_map(|map| map.values())
            .sum()
    }

    /// Find a field definition by name
    pub fn find_field(&self, name: &str) -> Option<&FieldDefinition> {
        self.fields.iter().find(|field| field.name == name)
    }

    /// Get all secret vendor fuse names and sizes
    pub fn secret_vendor_fuses(&self) -> Vec<(&str, u32)> {
        self.secret_vendor
            .iter()
            .flat_map(|map| map.iter())
            .map(|(name, size)| (name.as_str(), *size))
            .collect()
    }

    /// Get all non-secret vendor fuse names and sizes
    pub fn non_secret_vendor_fuses(&self) -> Vec<(&str, u32)> {
        self.non_secret_vendor
            .iter()
            .flat_map(|map| map.iter())
            .map(|(name, size)| (name.as_str(), *size))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuse_parse() {
        let example_hjson = r#"
{
  // vendor-specific secret fuses
  secret_vendor: [
    {"example_key1": 48}, // size in bytes
    {"example_key2": 48}, // size in bytes
    {"example_key3": 48}, // size in bytes
    {"example_key4": 48}, // size in bytes
  ],
  // vendor-specific non-secret-fuses
  non_secret_vendor: [
    {"example_key_revocation": 1}
  ],
  // TBD how we allow additional fuses outside of these areas, if this is allowed by OTP
  other_fuses: {},
  // entries to define how many bits are in each field, and potentially other information
  fields: [
    // set specifics on Subsystem fuses
    // By default, all bits in each field are assumed to be backed by actual fuse bits.
    // Names should be globally unique
    {name: "CPTRA_SS_OWNER_ECC_REVOCATION", bits: 4}, // size in bits
    // set specifics on vendor-specific fuses
    {name: "example_key_revocation", bits: 4},
  ]
}
"#;

        let config: FuseConfig = parse_fuse_hjson_str(example_hjson).unwrap();

        // Test secret vendor fuses
        assert_eq!(config.secret_vendor.len(), 4);
        assert_eq!(config.secret_vendor_total_size(), 192); // 4 * 48 bytes

        // Test non-secret vendor fuses
        assert_eq!(config.non_secret_vendor.len(), 1);
        assert_eq!(config.non_secret_vendor_total_size(), 1);

        // Test fields
        assert_eq!(config.fields.len(), 2);
        let ecc_revocation = config.find_field("CPTRA_SS_OWNER_ECC_REVOCATION").unwrap();
        assert_eq!(ecc_revocation.bits, 4);

        let key_revocation = config.find_field("example_key_revocation").unwrap();
        assert_eq!(key_revocation.bits, 4);

        // Test helper methods
        let secret_fuses = config.secret_vendor_fuses();
        assert_eq!(secret_fuses.len(), 4);
        assert!(secret_fuses.contains(&("example_key1", 48)));
        assert!(secret_fuses.contains(&("example_key2", 48)));

        let non_secret_fuses = config.non_secret_vendor_fuses();
        assert_eq!(non_secret_fuses.len(), 1);
        assert!(non_secret_fuses.contains(&("example_key_revocation", 1)));
    }

    #[test]
    fn test_empty_other_fuses() {
        let hjson = r#"
{
  secret_vendor: [],
  non_secret_vendor: [],
  other_fuses: {},
  fields: []
}
"#;

        let config: FuseConfig = parse_fuse_hjson_str(hjson).unwrap();
        assert_eq!(config.secret_vendor.len(), 0);
        assert_eq!(config.non_secret_vendor.len(), 0);
        assert_eq!(config.other_fuses.unwrap().len(), 0);
        assert_eq!(config.fields.len(), 0);
    }
}

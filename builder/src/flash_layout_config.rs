// Licensed under the Apache-2.0 license

use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

/// Top-level flash layout configuration.
#[derive(Debug, Deserialize)]
pub struct FlashLayoutConfig {
    pub flash: FlashConfig,
    pub partition_table: PartitionTableConfig,
    pub slot_a: SlotConfig,
    pub slot_b: SlotConfig,
    pub staging: Option<SlotConfig>,
}

/// Global flash parameters.
#[derive(Debug, Deserialize)]
pub struct FlashConfig {
    pub block_size: u64,
}

/// Partition table location and redundancy offsets.
#[derive(Debug, Deserialize)]
pub struct PartitionTableConfig {
    pub offset: u64,
    pub size: u64,
    pub copy_0_offset: u64,
    pub copy_1_offset: u64,
}

/// A single flash slot (image partition or staging area).
#[derive(Debug, Deserialize)]
pub struct SlotConfig {
    pub name: String,
    pub flash: String,
    pub offset: u64,
    pub size: u64,
}

impl FlashLayoutConfig {
    /// Load a flash layout configuration from a TOML file.
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| anyhow!("Failed to read flash layout config {}: {}", path.display(), e))?;
        let config: FlashLayoutConfig = toml::from_str(&content)
            .map_err(|e| anyhow!("Failed to parse flash layout config {}: {}", path.display(), e))?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_valid_config() {
        let toml_content = r#"
[flash]
block_size = 65536

[partition_table]
offset = 0x00000000
size = 65536
copy_0_offset = 0x00000000
copy_1_offset = 0x00008000

[slot_a]
name = "image_a"
flash = "primary"
offset = 0x00010000
size = 0x00200000

[slot_b]
name = "image_b"
flash = "secondary"
offset = 0x00000000
size = 0x00100000
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flash_layout.toml");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(toml_content.as_bytes()).unwrap();

        let config = FlashLayoutConfig::from_file(&path).unwrap();
        assert_eq!(config.flash.block_size, 65536);
        assert_eq!(config.partition_table.size, 65536);
        assert_eq!(config.slot_a.name, "image_a");
        assert_eq!(config.slot_b.name, "image_b");
        assert!(config.staging.is_none());
    }

    #[test]
    fn test_load_config_with_staging() {
        let toml_content = r#"
[flash]
block_size = 65536

[partition_table]
offset = 0x00000000
size = 65536
copy_0_offset = 0x00000000
copy_1_offset = 0x00008000

[slot_a]
name = "image_a"
flash = "primary"
offset = 0x00010000
size = 0x00200000

[slot_b]
name = "image_b"
flash = "secondary"
offset = 0x00000000
size = 0x00100000

[staging]
name = "staging"
flash = "secondary"
offset = 0x00100000
size = 0x00100000
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flash_layout.toml");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(toml_content.as_bytes()).unwrap();

        let config = FlashLayoutConfig::from_file(&path).unwrap();
        let staging = config.staging.unwrap();
        assert_eq!(staging.name, "staging");
        assert_eq!(staging.flash, "secondary");
        assert_eq!(staging.offset, 0x00100000);
        assert_eq!(staging.size, 0x00100000);
    }

    #[test]
    fn test_load_config_missing_field() {
        let toml_content = r#"
[flash]
block_size = 65536

[partition_table]
offset = 0x00000000
size = 65536
copy_0_offset = 0x00000000
copy_1_offset = 0x00008000

[slot_a]
name = "image_a"
flash = "primary"
offset = 0x00010000
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flash_layout.toml");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(toml_content.as_bytes()).unwrap();

        let result = FlashLayoutConfig::from_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_config_invalid_toml() {
        let toml_content = "this is not valid toml {{{}}}";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flash_layout.toml");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(toml_content.as_bytes()).unwrap();

        let result = FlashLayoutConfig::from_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_config_nonexistent_file() {
        let path = Path::new("/tmp/nonexistent_flash_layout_config.toml");
        let result = FlashLayoutConfig::from_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_emulator_reference_config() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir.parent().unwrap();
        let config_path = repo_root.join("platforms/emulator/flash_layout.toml");
        let config = FlashLayoutConfig::from_file(&config_path)
            .expect("Failed to load emulator reference flash_layout.toml");

        assert_eq!(config.flash.block_size, 65536);
        assert_eq!(config.partition_table.offset, 0);
        assert_eq!(config.partition_table.copy_1_offset, 0x00008000);
        assert_eq!(config.slot_a.name, "image_a");
        assert_eq!(config.slot_a.flash, "primary");
        assert_eq!(config.slot_b.name, "image_b");
        assert_eq!(config.slot_b.flash, "secondary");
        let staging = config.staging.expect("Emulator config should have staging");
        assert_eq!(staging.name, "staging");
    }
}

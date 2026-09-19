// Licensed under the Apache-2.0 license

use crate::{ComponentSvnEntry, ComponentSvnValidationConfig, ImageCfg};
use anyhow::{bail, Context, Result};
use caliptra_mcu_romtime::{
    McuComponentSvnEntry, McuComponentSvnManifest, MCU_COMPONENT_SVN_MANIFEST_ENTRY_COUNT,
    MCU_COMPONENT_SVN_MANIFEST_MAGIC, MCU_COMPONENT_SVN_MANIFEST_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zerocopy::IntoBytes;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentConfig {
    pub vendor: String,
    pub model: String,
    pub soc_manifest_svn: u32,
    pub component_svn_manifest: ComponentSvnManifestConfig,
    #[serde(default)]
    pub mcu_image: Option<ComponentImageConfig>,
    #[serde(default)]
    pub soc_images: Vec<ComponentImageConfig>,
    #[serde(default)]
    pub features: BTreeMap<String, ComponentConfigOverride>,
    #[serde(skip)]
    base_dir: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentSvnManifestConfig {
    pub current_svn: u16,
    pub min_svn: u16,
    pub caliptra_runtime_min_svn: u16,
    pub soc_manifest_min_svn: u16,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentImageConfig {
    pub path: PathBuf,
    #[serde(alias = "fw_id")]
    pub image_id: u32,
    pub component_id: u32,
    #[serde(alias = "load_address")]
    pub load_addr: u64,
    #[serde(alias = "staging_address")]
    pub staging_addr: u64,
    pub exec_bit: u32,
    pub current_svn: u16,
    pub min_svn: u16,
    #[serde(default)]
    pub is_tcb: bool,
    #[serde(default)]
    pub is_ak_target: bool,
    #[serde(default)]
    pub network_filename: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ComponentConfigOverride {
    pub soc_manifest_svn: Option<u32>,
    pub mcu_image: Option<ComponentImageOverride>,
    pub soc_images: Option<Vec<ComponentImageConfig>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ComponentImageOverride {
    pub path: Option<PathBuf>,
    #[serde(alias = "fw_id")]
    pub image_id: Option<u32>,
    pub component_id: Option<u32>,
    #[serde(alias = "load_address")]
    pub load_addr: Option<u64>,
    #[serde(alias = "staging_address")]
    pub staging_addr: Option<u64>,
    pub exec_bit: Option<u32>,
    pub current_svn: Option<u16>,
    pub min_svn: Option<u16>,
    pub is_tcb: Option<bool>,
    pub is_ak_target: Option<bool>,
    pub network_filename: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ResolvedComponentConfig {
    pub vendor: String,
    pub model: String,
    pub soc_manifest_svn: u32,
    pub component_svn_manifest: ComponentSvnManifestConfig,
    pub mcu_image: Option<ImageCfg>,
    pub mcu_component_svn: Option<ComponentSvnEntry>,
    pub soc_images: Vec<ImageCfg>,
    pub component_svn_validation: ComponentSvnValidationConfig,
}

impl ComponentConfig {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let source = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read component config {}", path.display()))?;
        let mut config: Self = toml::from_str(&source)
            .with_context(|| format!("failed to parse component config {}", path.display()))?;
        config.base_dir = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        config.validate()?;
        Ok(config)
    }

    pub fn resolve(&self, feature: Option<&str>) -> Result<ResolvedComponentConfig> {
        self.resolve_for_platform(feature, false)
    }

    pub fn resolve_for_platform(
        &self,
        feature: Option<&str>,
        fpga: bool,
    ) -> Result<ResolvedComponentConfig> {
        let feature_override = feature.and_then(|feature| self.features.get(feature));
        let soc_manifest_svn = feature_override
            .and_then(|config| config.soc_manifest_svn)
            .unwrap_or(self.soc_manifest_svn);
        let soc_images = feature_override
            .and_then(|config| config.soc_images.as_ref())
            .unwrap_or(&self.soc_images);
        let mut mcu_image = self.mcu_image.clone();
        if let Some(image_override) = feature_override.and_then(|config| config.mcu_image.as_ref())
        {
            let image = mcu_image.get_or_insert_with(|| default_mcu_image(fpga));
            image.apply(image_override);
        }

        if let Some(image) = &mcu_image {
            validate_svn_range(
                &format!("MCU component {:#x}", image.component_id),
                image.current_svn,
                image.min_svn,
            )?;
        }
        for image in soc_images {
            validate_svn_range(
                &format!("SoC component {:#x}", image.component_id),
                image.current_svn,
                image.min_svn,
            )?;
        }

        let entries = soc_images
            .iter()
            .map(|image| ComponentSvnEntry {
                component_id: image.component_id,
                current_svn: image.current_svn,
                min_svn: image.min_svn,
            })
            .collect::<Vec<_>>();

        Ok(ResolvedComponentConfig {
            vendor: self.vendor.clone(),
            model: self.model.clone(),
            soc_manifest_svn,
            component_svn_manifest: self.component_svn_manifest.clone(),
            mcu_component_svn: mcu_image.as_ref().map(|image| ComponentSvnEntry {
                component_id: image.component_id,
                current_svn: image.current_svn,
                min_svn: image.min_svn,
            }),
            mcu_image: mcu_image.map(|image| image.to_image_cfg(&self.base_dir, feature)),
            soc_images: soc_images
                .iter()
                .map(|image| image.to_image_cfg(&self.base_dir, feature))
                .collect(),
            component_svn_validation: ComponentSvnValidationConfig {
                entries,
                ..Default::default()
            },
        })
    }

    pub fn resolve_for_features<'a>(
        &self,
        features: impl IntoIterator<Item = &'a str>,
        fpga: bool,
    ) -> Result<ResolvedComponentConfig> {
        let matches = features
            .into_iter()
            .filter(|feature| self.features.contains_key(*feature))
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            bail!(
                "multiple component config feature overrides are active: {}",
                matches.join(", ")
            );
        }
        self.resolve_for_platform(matches.first().copied(), fpga)
    }

    fn validate(&self) -> Result<()> {
        validate_svn_range(
            "component_svn_manifest",
            self.component_svn_manifest.current_svn,
            self.component_svn_manifest.min_svn,
        )?;
        for image in self.mcu_image.iter().chain(self.soc_images.iter()) {
            validate_svn_range(
                &format!("component {:#x}", image.component_id),
                image.current_svn,
                image.min_svn,
            )?;
        }
        for (feature, config) in &self.features {
            for image in config.soc_images.iter().flatten() {
                validate_svn_range(
                    &format!("feature {feature} component {:#x}", image.component_id),
                    image.current_svn,
                    image.min_svn,
                )?;
            }
        }
        Ok(())
    }
}

impl ComponentImageConfig {
    fn apply(&mut self, value: &ComponentImageOverride) {
        if let Some(path) = &value.path {
            self.path = path.clone();
        }
        if let Some(image_id) = value.image_id {
            self.image_id = image_id;
        }
        if let Some(component_id) = value.component_id {
            self.component_id = component_id;
        }
        if let Some(load_addr) = value.load_addr {
            self.load_addr = load_addr;
        }
        if let Some(staging_addr) = value.staging_addr {
            self.staging_addr = staging_addr;
        }
        if let Some(exec_bit) = value.exec_bit {
            self.exec_bit = exec_bit;
        }
        if let Some(current_svn) = value.current_svn {
            self.current_svn = current_svn;
        }
        if let Some(min_svn) = value.min_svn {
            self.min_svn = min_svn;
        }
        if let Some(is_tcb) = value.is_tcb {
            self.is_tcb = is_tcb;
        }
        if let Some(is_ak_target) = value.is_ak_target {
            self.is_ak_target = is_ak_target;
        }
        if let Some(network_filename) = &value.network_filename {
            self.network_filename = Some(network_filename.clone());
        }
    }

    fn to_image_cfg(&self, base_dir: &Path, feature: Option<&str>) -> ImageCfg {
        let path = if self.path.is_absolute() {
            self.path.clone()
        } else {
            base_dir.join(&self.path)
        };
        ImageCfg {
            path,
            network_filename: self.network_filename.clone(),
            load_addr: self.load_addr,
            staging_addr: self.staging_addr,
            image_id: self.image_id,
            exec_bit: self.exec_bit,
            component_id: self.component_id,
            is_tcb: self.is_tcb,
            is_ak_target: self.is_ak_target,
            feature: feature.unwrap_or("none").to_string(),
        }
    }
}

fn default_mcu_image(fpga: bool) -> ComponentImageConfig {
    let image = crate::caliptra::default_mcu_image_cfg(fpga);
    ComponentImageConfig {
        path: image.path,
        image_id: image.image_id,
        component_id: image.component_id,
        load_addr: image.load_addr,
        staging_addr: image.staging_addr,
        exec_bit: image.exec_bit,
        current_svn: 0,
        min_svn: 0,
        is_tcb: false,
        is_ak_target: false,
        network_filename: None,
    }
}

fn validate_svn_range(name: &str, current_svn: u16, min_svn: u16) -> Result<()> {
    if min_svn > current_svn {
        bail!("{name} min_svn {min_svn} is greater than current_svn {current_svn}");
    }
    Ok(())
}

impl ResolvedComponentConfig {
    /// Serialize the resolved SVN policy using the exact header layout consumed by MCU ROM.
    pub fn component_svn_manifest_bytes(&self) -> Result<Vec<u8>> {
        let config = &self.component_svn_manifest;
        let current_svn = u8::try_from(config.current_svn)
            .context("component SVN manifest current_svn exceeds 255")?;
        let min_svn =
            u8::try_from(config.min_svn).context("component SVN manifest min_svn exceeds 255")?;
        let caliptra_runtime_min_svn = u8::try_from(config.caliptra_runtime_min_svn)
            .context("caliptra_runtime_min_svn exceeds 255")?;
        let soc_manifest_min_svn = u8::try_from(config.soc_manifest_min_svn)
            .context("soc_manifest_min_svn exceeds 255")?;

        let mut component_entries = self.component_svn_validation.entries.clone();
        if let Some(mcu) = self.mcu_component_svn {
            component_entries.insert(0, mcu);
        }
        if component_entries.len() > MCU_COMPONENT_SVN_MANIFEST_ENTRY_COUNT {
            bail!(
                "component SVN manifest has {} entries, maximum is {}",
                component_entries.len(),
                MCU_COMPONENT_SVN_MANIFEST_ENTRY_COUNT
            );
        }

        let mut entries = [McuComponentSvnEntry::default(); MCU_COMPONENT_SVN_MANIFEST_ENTRY_COUNT];
        for (output, input) in entries.iter_mut().zip(component_entries) {
            *output = McuComponentSvnEntry {
                component_id: input.component_id,
                current_svn: input.current_svn,
                min_svn: input.min_svn,
            };
        }

        Ok(McuComponentSvnManifest {
            magic: MCU_COMPONENT_SVN_MANIFEST_MAGIC,
            format_version: MCU_COMPONENT_SVN_MANIFEST_VERSION,
            current_svn,
            min_svn,
            caliptra_runtime_min_svn,
            soc_manifest_min_svn,
            reserved: [0; 6],
            entries,
        }
        .as_bytes()
        .to_vec())
    }

    pub fn write_generated_configs(&self, target_dir: &Path, generated_by: &str) -> Result<()> {
        crate::attestation_manifest::write_config_to_target_dir(
            target_dir,
            &self.vendor,
            &self.model,
            &self.soc_images,
            generated_by,
            "Generated",
        )?;

        #[derive(Serialize)]
        struct Manifest {
            current_svn: u16,
            min_svn: u16,
            caliptra_runtime_min_svn: u16,
            soc_manifest_min_svn: u16,
            components: Vec<ComponentSvnEntry>,
        }

        let mut components = self.component_svn_validation.entries.clone();
        if let Some(mcu) = self.mcu_component_svn {
            components.insert(0, mcu);
        }
        let config = &self.component_svn_manifest;
        let manifest = Manifest {
            current_svn: config.current_svn,
            min_svn: config.min_svn,
            caliptra_runtime_min_svn: config.caliptra_runtime_min_svn,
            soc_manifest_min_svn: config.soc_manifest_min_svn,
            components,
        };
        let generated_dir = target_dir.join("generated");
        std::fs::create_dir_all(&generated_dir)?;
        let mut source = String::from("# AUTO-GENERATED FILE. DO NOT EDIT.\n");
        source.push_str(&format!("# Generated by {generated_by}\n"));
        source.push_str(&toml::to_string(&manifest)?);
        std::fs::write(generated_dir.join("component_svn_manifest.toml"), source)?;
        std::fs::write(
            generated_dir.join("component_svn_manifest.bin"),
            self.component_svn_manifest_bytes()?,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_feature_overrides_and_relative_paths() {
        let source = r#"
vendor = "Vendor A"
model = "Model-XXXX"
soc_manifest_svn = 5

[component_svn_manifest]
current_svn = 3
min_svn = 2
caliptra_runtime_min_svn = 7
soc_manifest_min_svn = 5

[mcu_image]
path = "mcu.bin"
fw_id = 1
component_id = 1
load_address = 0x1000
staging_address = 0x2000
exec_bit = 2
current_svn = 4
min_svn = 2

[[soc_images]]
path = "soc.bin"
fw_id = 0x1000
component_id = 0x1000
load_address = 0xB0000000
staging_address = 0x80000000
exec_bit = 5
current_svn = 4
min_svn = 2

[features.update]
soc_manifest_svn = 6

[features.update.mcu_image]
staging_address = 0x60080000
current_svn = 6
min_svn = 4
"#;
        let mut config: ComponentConfig = toml::from_str(source).unwrap();
        config.base_dir = PathBuf::from("config");
        config.validate().unwrap();
        let resolved = config.resolve(Some("update")).unwrap();
        let bytes = resolved.component_svn_manifest_bytes().unwrap();
        let manifest = McuComponentSvnManifest::parse_if_present(&bytes)
            .unwrap()
            .unwrap();

        assert_eq!(resolved.soc_manifest_svn, 6);
        assert_eq!(resolved.mcu_image.unwrap().staging_addr, 0x6008_0000);
        assert_eq!(resolved.soc_images[0].path, PathBuf::from("config/soc.bin"));
        assert_eq!(resolved.component_svn_validation.entries.len(), 1);
        assert_eq!(bytes.len(), 1024);
        assert_eq!(manifest.current_svn, 3);
        assert_eq!(manifest.min_svn, 2);
        assert_eq!(manifest.caliptra_runtime_min_svn, 7);
        assert_eq!(manifest.soc_manifest_min_svn, 5);
        assert_eq!(manifest.entries[0].component_id, 1);
        assert_eq!(manifest.entries[0].current_svn, 6);
        assert_eq!(manifest.entries[1].component_id, 0x1000);
    }

    #[test]
    fn rejects_invalid_svn_range() {
        assert!(validate_svn_range("test", 2, 3).is_err());
    }

    #[test]
    fn partial_mcu_override_inherits_platform_defaults() {
        let source = r#"
vendor = "Vendor A"
model = "Model-XXXX"
soc_manifest_svn = 5

[component_svn_manifest]
current_svn = 3
min_svn = 2
caliptra_runtime_min_svn = 7
soc_manifest_min_svn = 5

[features.update.mcu_image]
staging_address = 0x60080000
current_svn = 6
min_svn = 4
"#;
        let config: ComponentConfig = toml::from_str(source).unwrap();
        let resolved = config.resolve_for_platform(Some("update"), true).unwrap();
        let mcu = resolved.mcu_image.unwrap();

        assert_ne!(mcu.image_id, 0);
        assert_ne!(mcu.component_id, 0);
        assert_ne!(mcu.load_addr, 0);
        assert_eq!(mcu.staging_addr, 0x6008_0000);
        assert_eq!(resolved.mcu_component_svn.unwrap().current_svn, 6);
    }
}

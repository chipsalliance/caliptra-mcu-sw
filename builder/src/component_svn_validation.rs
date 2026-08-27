// Licensed under the Apache-2.0 license

use crate::ImageCfg;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ComponentSvnEntry {
    pub component_id: u32,
    pub current_svn: u16,
    pub min_svn: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ComponentSvnFuseMapEntry {
    pub component_id: u32,
    pub fuse_slot: u32,
    pub max_svn: u16,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ComponentSvnValidationConfig {
    pub entries: Vec<ComponentSvnEntry>,
    pub fuse_map: Vec<ComponentSvnFuseMapEntry>,
    pub unenforced_component_ids: Vec<u32>,
    pub future_or_absent_component_ids: Vec<u32>,
}

pub(crate) fn validate_component_svns(
    images: &[ImageCfg],
    config: &ComponentSvnValidationConfig,
) -> Result<()> {
    let image_components: BTreeSet<_> = images.iter().map(|image| image.component_id).collect();
    let unenforced: BTreeSet<_> = config.unenforced_component_ids.iter().copied().collect();
    let future_or_absent: BTreeSet<_> = config
        .future_or_absent_component_ids
        .iter()
        .copied()
        .collect();

    let mut entries = BTreeMap::new();
    for entry in &config.entries {
        if let Some(previous) = entries.insert(entry.component_id, *entry) {
            if previous != *entry {
                bail!(
                    "conflicting SVN entries for component_id {:#x}",
                    entry.component_id
                );
            }
        }
        if entry.min_svn > entry.current_svn {
            bail!(
                "component_id {:#x} has min_svn {} greater than current_svn {}",
                entry.component_id,
                entry.min_svn,
                entry.current_svn
            );
        }
        if !image_components.contains(&entry.component_id)
            && !future_or_absent.contains(&entry.component_id)
        {
            bail!(
                "SVN entry references unknown component_id {:#x}",
                entry.component_id
            );
        }
    }

    for component_id in &image_components {
        if !unenforced.contains(component_id) && !entries.contains_key(component_id) {
            bail!(
                "protected component_id {:#x} is missing SVN metadata",
                component_id
            );
        }
    }

    let mut fuse_map = BTreeMap::new();
    for mapping in &config.fuse_map {
        if let Some(previous) = fuse_map.insert(mapping.component_id, *mapping) {
            if previous != *mapping {
                bail!(
                    "conflicting fuse mappings for component_id {:#x}",
                    mapping.component_id
                );
            }
        }
    }

    let mut slot_floors = BTreeMap::new();
    for entry in entries.values() {
        if unenforced.contains(&entry.component_id) {
            continue;
        }
        let Some(mapping) = fuse_map.get(&entry.component_id) else {
            bail!(
                "protected component_id {:#x} has no SVN fuse mapping",
                entry.component_id
            );
        };
        if entry.current_svn > mapping.max_svn || entry.min_svn > mapping.max_svn {
            bail!(
                "component_id {:#x} SVN exceeds fuse slot {} maximum {}",
                entry.component_id,
                mapping.fuse_slot,
                mapping.max_svn
            );
        }
        if let Some(previous_floor) = slot_floors.insert(mapping.fuse_slot, entry.min_svn) {
            if previous_floor != entry.min_svn {
                bail!(
                    "components sharing fuse slot {} request conflicting floors {} and {}",
                    mapping.fuse_slot,
                    previous_floor,
                    entry.min_svn
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(image_id: u32, component_id: u32) -> ImageCfg {
        ImageCfg {
            image_id,
            component_id,
            ..Default::default()
        }
    }

    fn entry(component_id: u32, current_svn: u16, min_svn: u16) -> ComponentSvnEntry {
        ComponentSvnEntry {
            component_id,
            current_svn,
            min_svn,
        }
    }

    fn mapping(component_id: u32, fuse_slot: u32) -> ComponentSvnFuseMapEntry {
        ComponentSvnFuseMapEntry {
            component_id,
            fuse_slot,
            max_svn: 10,
        }
    }

    #[test]
    fn accepts_multiple_fw_ids_for_one_component() {
        let config = ComponentSvnValidationConfig {
            entries: vec![entry(0x1000, 5, 3)],
            fuse_map: vec![mapping(0x1000, 0)],
            ..Default::default()
        };

        validate_component_svns(&[image(1, 0x1000), image(2, 0x1000)], &config).unwrap();
    }

    #[test]
    fn rejects_conflicting_duplicate_entries() {
        let config = ComponentSvnValidationConfig {
            entries: vec![entry(0x1000, 5, 3), entry(0x1000, 6, 3)],
            fuse_map: vec![mapping(0x1000, 0)],
            ..Default::default()
        };

        assert!(validate_component_svns(&[image(1, 0x1000)], &config)
            .unwrap_err()
            .to_string()
            .contains("conflicting SVN entries"));
    }

    #[test]
    fn rejects_unknown_component_unless_future_or_absent() {
        let mut config = ComponentSvnValidationConfig {
            entries: vec![entry(0x2000, 5, 3)],
            fuse_map: vec![mapping(0x2000, 0)],
            ..Default::default()
        };

        assert!(validate_component_svns(&[], &config).is_err());
        config.future_or_absent_component_ids.push(0x2000);
        validate_component_svns(&[], &config).unwrap();
    }

    #[test]
    fn rejects_missing_metadata_unless_unenforced() {
        let mut config = ComponentSvnValidationConfig::default();

        assert!(validate_component_svns(&[image(1, 0x1000)], &config).is_err());
        config.unenforced_component_ids.push(0x1000);
        validate_component_svns(&[image(1, 0x1000)], &config).unwrap();
    }

    #[test]
    fn rejects_invalid_svn_and_fuse_range() {
        let mut config = ComponentSvnValidationConfig {
            entries: vec![entry(0x1000, 3, 4)],
            fuse_map: vec![mapping(0x1000, 0)],
            ..Default::default()
        };
        assert!(validate_component_svns(&[image(1, 0x1000)], &config).is_err());

        config.entries[0] = entry(0x1000, 11, 3);
        assert!(validate_component_svns(&[image(1, 0x1000)], &config).is_err());
    }

    #[test]
    fn rejects_missing_mapping() {
        let config = ComponentSvnValidationConfig {
            entries: vec![entry(0x1000, 5, 3)],
            ..Default::default()
        };

        assert!(validate_component_svns(&[image(1, 0x1000)], &config).is_err());
    }

    #[test]
    fn validates_shared_fuse_slot_floor_policy() {
        let mut config = ComponentSvnValidationConfig {
            entries: vec![entry(0x1000, 5, 3), entry(0x1001, 6, 3)],
            fuse_map: vec![mapping(0x1000, 0), mapping(0x1001, 0)],
            ..Default::default()
        };
        let images = [image(1, 0x1000), image(2, 0x1001)];

        validate_component_svns(&images, &config).unwrap();
        config.entries[1].min_svn = 4;
        assert!(validate_component_svns(&images, &config).is_err());
    }
}

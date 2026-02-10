// Licensed under the Apache-2.0 license

//! Configuration for name transformations and filtering during code generation.
//!
//! This module provides [`NameConfig`] which controls how register, regfile,
//! and addrmap names are transformed when generating Rust code. Common use
//! cases include stripping suffixes like `_csr` or `_reg` to produce cleaner
//! struct names.
//!
//! It also provides [`FilterConfig`] which controls which registers and address
//! map blocks are included or excluded from code generation.

/// Configuration for name transformations during code generation.
///
/// This allows stripping common prefixes and suffixes from addrmap names
/// to produce cleaner struct and module names.
///
/// # Example
///
/// ```
/// use mcu_registers_generator_new::config::NameConfig;
///
/// // Use defaults (strips _csr, _reg, _top, _ctrl, etc.)
/// let config = NameConfig::with_defaults();
/// assert_eq!(config.transform("I3CCSR"), "I3C");
/// assert_eq!(config.transform("otp_ctrl_reg"), "otp");
///
/// // Custom configuration
/// let config = NameConfig::none()
///     .add_suffix("_controller")
///     .add_prefix("my_");
/// assert_eq!(config.transform("my_uart_controller"), "uart");
/// ```
#[derive(Clone, Debug, Default)]
pub struct NameConfig {
    /// Suffixes to strip from names (case-insensitive, checked in order).
    /// Default includes common register file suffixes: `_csr`, `_reg`, `_top`, `_ifc`, `_ctrl`, `csr`
    pub strip_suffixes: Vec<String>,

    /// Prefixes to strip from names (case-insensitive, checked in order).
    pub strip_prefixes: Vec<String>,

    /// When flattening nested regfiles, strip the first-level regfile prefix from
    /// nested regfile register names. This matches the old generator behavior.
    ///
    /// For example, with `mci_reg` containing `intr_block_rf`:
    /// - `false`: `mci_reg_intr_block_rf_error0_intr_en_r`
    /// - `true` (default): `intr_block_rf_error0_intr_en_r`
    pub strip_first_level_prefix_in_nested: bool,
}

impl NameConfig {
    /// Create a new NameConfig with default suffix stripping.
    ///
    /// Default suffixes stripped (case-insensitive):
    /// - `_csr`, `_reg`, `_top`, `_ifc`, `_ctrl` (with underscore)
    /// - `csr` (without underscore, e.g., for "I3CCSR" -> "I3C")
    ///
    /// Also enables `strip_first_level_prefix_in_nested` to match old generator behavior.
    pub fn with_defaults() -> Self {
        Self {
            strip_suffixes: vec![
                "_csr".to_string(),
                "_reg".to_string(),
                "_top".to_string(),
                "_ifc".to_string(),
                "_ctrl".to_string(),
                "csr".to_string(), // Without underscore, for names like "I3CCSR"
            ],
            strip_prefixes: vec![],
            strip_first_level_prefix_in_nested: true,
        }
    }

    /// Create a NameConfig that performs no transformations.
    pub fn none() -> Self {
        Self::default()
    }

    /// Add a suffix to strip (case-insensitive).
    pub fn add_suffix(mut self, suffix: &str) -> Self {
        self.strip_suffixes.push(suffix.to_string());
        self
    }

    /// Add a prefix to strip (case-insensitive).
    pub fn add_prefix(mut self, prefix: &str) -> Self {
        self.strip_prefixes.push(prefix.to_string());
        self
    }

    /// Set whether to strip the first-level regfile prefix from nested regfile registers.
    pub fn strip_first_level_prefix(mut self, strip: bool) -> Self {
        self.strip_first_level_prefix_in_nested = strip;
        self
    }

    /// Apply name transformations to the given name.
    ///
    /// Strips matching prefixes first, then suffixes.
    /// Matching is case-insensitive but preserves the case of the remaining characters.
    pub fn transform(&self, name: &str) -> String {
        let mut result = name.to_string();

        // Strip prefixes (case-insensitive)
        for prefix in &self.strip_prefixes {
            let lower_result = result.to_lowercase();
            let lower_prefix = prefix.to_lowercase();
            if lower_result.starts_with(&lower_prefix) {
                result = result[prefix.len()..].to_string();
            }
        }

        // Strip suffixes (case-insensitive), repeatedly until none match
        loop {
            let mut matched = false;
            for suffix in &self.strip_suffixes {
                let lower_result = result.to_lowercase();
                let lower_suffix = suffix.to_lowercase();
                if lower_result.ends_with(&lower_suffix) && result.len() > suffix.len() {
                    result = result[..result.len() - suffix.len()].to_string();
                    matched = true;
                    break; // Start over to handle chained suffixes
                }
            }
            if !matched {
                break;
            }
        }

        result
    }
}

/// Configuration for filtering which registers and blocks are generated.
///
/// This allows limiting code generation to specific offset ranges or
/// excluding certain register/block names.
///
/// # Example
///
/// ```
/// use mcu_registers_generator_new::config::FilterConfig;
///
/// // Only generate registers in a specific offset range
/// let config = FilterConfig::new()
///     .include_offset_range(0x0, 0x100);
///
/// // Exclude specific register or block names
/// let config = FilterConfig::new()
///     .exclude_name("debug_reg")
///     .exclude_name("test_block");
///
/// // Exclude an offset range
/// let config = FilterConfig::new()
///     .exclude_offset_range(0x200, 0x300);
/// ```
#[derive(Clone, Debug, Default)]
pub struct FilterConfig {
    /// Only include registers whose offsets fall within these ranges (inclusive).
    /// If empty, all offsets are included (subject to exclude_offset_ranges).
    pub include_offset_ranges: Vec<(usize, usize)>,

    /// Exclude registers whose offsets fall within these ranges (inclusive).
    pub exclude_offset_ranges: Vec<(usize, usize)>,

    /// Exclude registers or addrmap blocks whose names match (case-insensitive).
    pub exclude_names: Vec<String>,
}

impl FilterConfig {
    /// Create a new FilterConfig with no filtering (everything included).
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an inclusive offset range. Only registers with offsets in at least
    /// one of the included ranges will be generated. If no include ranges are
    /// specified, all offsets are included (subject to exclude ranges).
    pub fn include_offset_range(mut self, start: usize, end: usize) -> Self {
        self.include_offset_ranges.push((start, end));
        self
    }

    /// Add an exclusive offset range. Registers with offsets falling within
    /// any excluded range will be skipped.
    pub fn exclude_offset_range(mut self, start: usize, end: usize) -> Self {
        self.exclude_offset_ranges.push((start, end));
        self
    }

    /// Exclude registers or blocks whose name matches (case-insensitive).
    pub fn exclude_name(mut self, name: &str) -> Self {
        self.exclude_names.push(name.to_lowercase());
        self
    }

    /// Returns true if this filter has no constraints (everything passes).
    pub fn is_empty(&self) -> bool {
        self.include_offset_ranges.is_empty()
            && self.exclude_offset_ranges.is_empty()
            && self.exclude_names.is_empty()
    }

    /// Check whether a register at the given offset with the given name
    /// should be included in code generation.
    pub fn should_include(&self, offset: usize, name: &str) -> bool {
        // Check name exclusion
        let name_lower = name.to_lowercase();
        if self.exclude_names.iter().any(|n| *n == name_lower) {
            return false;
        }

        // Check offset exclusion
        if self
            .exclude_offset_ranges
            .iter()
            .any(|(start, end)| offset >= *start && offset <= *end)
        {
            return false;
        }

        // Check offset inclusion (empty means include all)
        if !self.include_offset_ranges.is_empty()
            && !self
                .include_offset_ranges
                .iter()
                .any(|(start, end)| offset >= *start && offset <= *end)
        {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_suffix_stripping() {
        let config = NameConfig::with_defaults();
        assert_eq!(config.transform("I3CCSR"), "I3C");
        // Note: _ctrl is also a stripped suffix, so otp_ctrl_reg → otp_reg → otp
        assert_eq!(config.transform("otp_ctrl_reg"), "otp");
        assert_eq!(config.transform("mci_top"), "mci");
        assert_eq!(config.transform("flash_ifc"), "flash");
    }

    #[test]
    fn test_custom_config() {
        let config = NameConfig::none()
            .add_suffix("_controller")
            .add_prefix("my_");
        assert_eq!(config.transform("my_uart_controller"), "uart");
    }

    #[test]
    fn test_no_transform() {
        let config = NameConfig::none();
        assert_eq!(config.transform("I3CCSR"), "I3CCSR");
    }

    #[test]
    fn test_preserves_case() {
        let config = NameConfig::with_defaults();
        assert_eq!(config.transform("MyModule_CSR"), "MyModule");
    }

    #[test]
    fn test_filter_config_empty() {
        let config = FilterConfig::new();
        assert!(config.is_empty());
        assert!(config.should_include(0x0, "any_name"));
        assert!(config.should_include(0xFFFF_FFFF, "another_name"));
    }

    #[test]
    fn test_filter_config_include_offset_range() {
        let config = FilterConfig::new().include_offset_range(0x100, 0x200);
        assert!(!config.should_include(0x0, "reg"));
        assert!(!config.should_include(0xFF, "reg"));
        assert!(config.should_include(0x100, "reg"));
        assert!(config.should_include(0x150, "reg"));
        assert!(config.should_include(0x200, "reg"));
        assert!(!config.should_include(0x201, "reg"));
    }

    #[test]
    fn test_filter_config_exclude_offset_range() {
        let config = FilterConfig::new().exclude_offset_range(0x100, 0x200);
        assert!(config.should_include(0x0, "reg"));
        assert!(config.should_include(0xFF, "reg"));
        assert!(!config.should_include(0x100, "reg"));
        assert!(!config.should_include(0x150, "reg"));
        assert!(!config.should_include(0x200, "reg"));
        assert!(config.should_include(0x201, "reg"));
    }

    #[test]
    fn test_filter_config_exclude_name() {
        let config = FilterConfig::new()
            .exclude_name("debug_reg")
            .exclude_name("Test_Block");
        assert!(config.should_include(0x0, "normal_reg"));
        assert!(!config.should_include(0x0, "debug_reg"));
        assert!(!config.should_include(0x0, "DEBUG_REG")); // case-insensitive
        assert!(!config.should_include(0x0, "test_block"));
    }

    #[test]
    fn test_filter_config_combined() {
        let config = FilterConfig::new()
            .include_offset_range(0x0, 0x200)
            .exclude_name("debug_reg");
        // In range, not excluded
        assert!(config.should_include(0x100, "normal_reg"));
        // In range, but excluded by name
        assert!(!config.should_include(0x100, "debug_reg"));
        // Out of range
        assert!(!config.should_include(0x300, "normal_reg"));
    }
}

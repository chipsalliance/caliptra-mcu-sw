// Licensed under the Apache-2.0 license

//! Code generation logic for Tock register definitions.
//!
//! This module contains the `impl World` block that handles converting
//! the parsed SystemRDL representation into Rust tock-registers code.

use super::*;

impl World {
    /// Generate tock_registers code for the specified addrmap.
    pub(super) fn generate_addrmap_code(
        &self,
        addrmap_name: &str,
        base_offset: usize,
    ) -> Result<Option<String>, anyhow::Error> {
        self.generate_addrmap_code_with_config(
            addrmap_name,
            base_offset,
            &NameConfig::with_defaults(),
            &FilterConfig::new(),
        )
    }

    pub(super) fn generate_addrmap_code_with_config(
        &self,
        addrmap_name: &str,
        base_offset: usize,
        name_config: &NameConfig,
        filter_config: &FilterConfig,
    ) -> Result<Option<String>, anyhow::Error> {
        // Find the addrmap component
        for component_idx in self.child_components.iter().copied() {
            let component = &self.component_arena[component_idx];
            if component.component_type() == ComponentType::AddrMap
                && component.name() == Some(addrmap_name)
            {
                // Apply name transformations to get the cleaned-up name
                let transformed_name = name_config.transform(addrmap_name);

                let mut generated = GeneratedAddrMap {
                    name: transformed_name.clone(),
                    base_address: base_offset,
                    ..Default::default()
                };

                // Collect register types and instances from this addrmap
                self.collect_addrmap_registers(
                    component_idx,
                    &mut generated,
                    name_config,
                    filter_config,
                )?;

                // When filtering is active, remove register types that are no longer
                // referenced by any register instance
                if !filter_config.is_empty() {
                    let referenced_types: std::collections::HashSet<&str> = generated
                        .registers
                        .iter()
                        .filter_map(|r| r.type_name.as_deref())
                        .collect();
                    generated
                        .register_types
                        .retain(|rt| referenced_types.contains(rt.name.as_str()));
                }

                return Ok(Some(generated.generate_code(&format!(
                    "crate::{}::",
                    snake_case(&transformed_name)
                ))));
            }
        }
        Ok(None)
    }

    pub(super) fn collect_addrmap_registers(
        &self,
        addrmap_idx: ComponentIdx,
        generated: &mut GeneratedAddrMap,
        name_config: &NameConfig,
        filter_config: &FilterConfig,
    ) -> Result<(), anyhow::Error> {
        self.collect_addrmap_registers_with_offset(
            addrmap_idx,
            0,
            "",
            None,
            generated,
            name_config,
            filter_config,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn collect_addrmap_registers_with_offset(
        &self,
        addrmap_idx: ComponentIdx,
        base_offset: usize,
        prefix: &str,
        first_level_prefix: Option<&str>,
        generated: &mut GeneratedAddrMap,
        name_config: &NameConfig,
        filter_config: &FilterConfig,
    ) -> Result<(), anyhow::Error> {
        let addrmap = self.component_arena[addrmap_idx]
            .as_addrmap()
            .ok_or_else(|| anyhow::anyhow!("Not an addrmap"))?;

        // Collect child register types (types don't need offset, only instances do)
        for child_idx in addrmap.children.iter().copied() {
            let child = &self.component_arena[child_idx];
            match child.component_type() {
                ComponentType::Reg => {
                    self.collect_register_type(child_idx, generated)?;
                }
                ComponentType::RegFile => {
                    // Collect register types defined inside regfiles
                    self.collect_regfile_register_types(child_idx, generated)?;
                }
                ComponentType::AddrMap => {
                    // For nested addrmap types, collect their register types
                    // The instances and their offsets are handled below
                    self.collect_addrmap_register_types(child_idx, generated)?;
                }
                _ => {}
            }
        }

        // Collect instances with proper offsets
        for inst_idx in addrmap.child_instances.iter().copied() {
            let inst = &self.instance_arena[inst_idx];
            let component = &self.component_arena[inst.type_idx];
            let inst_offset = base_offset + inst.offset;
            let inst_name = if prefix.is_empty() {
                inst.name.clone()
            } else {
                format!("{}_{}", prefix, inst.name)
            };

            match component.component_type() {
                ComponentType::Reg => {
                    // Check filter before including this register
                    if !filter_config.should_include(inst_offset, &inst_name) {
                        continue;
                    }

                    let type_name = component.name().map(|s| s.to_string());

                    // Determine read/write access from properties
                    let (can_read, can_write) = self.get_register_access(inst.type_idx);

                    let array_size = inst.array_size.as_ref().map(|v| v.iter().product());

                    let width = self.get_register_width_bits(inst.type_idx);

                    generated.registers.push(GeneratedRegister {
                        name: inst_name,
                        offset: inst_offset,
                        type_name,
                        can_read,
                        can_write,
                        array_size,
                        width,
                    });
                }
                ComponentType::RegFile => {
                    // First collect the register types from this regfile
                    // This ensures bitfield types are available before we reference them
                    self.collect_regfile_register_types(inst.type_idx, generated)?;

                    // For regfiles, DON'T include the parent addrmap prefix in the regfile name.
                    // This matches the old generator behavior where nested regfiles reset the prefix.
                    // E.g., in mci_top → mci_reg (addrmap) → intr_block_rf (regfile),
                    // registers should be named intr_block_rf_foo, not mci_reg_intr_block_rf_foo.
                    let regfile_name = inst.name.clone();

                    // Check filter on the regfile block name itself
                    if !filter_config.should_include(inst_offset, &regfile_name) {
                        continue;
                    }

                    // Track the first-level regfile prefix for potential stripping of nested regfile prefixes
                    let new_first_level = first_level_prefix.or(Some(&regfile_name));

                    // Expand regfile instances into their contained registers
                    // Pass just the regfile name (without addrmap prefix) for naming
                    self.collect_regfile_instances(
                        inst.type_idx,
                        inst_offset,
                        &regfile_name,
                        new_first_level,
                        generated,
                        name_config,
                        filter_config,
                    )?;
                }
                ComponentType::AddrMap => {
                    // Check filter on the addrmap block name
                    if !filter_config.should_include(inst_offset, &inst_name) {
                        continue;
                    }

                    // Recursively collect from nested addrmap instances with accumulated offset
                    self.collect_addrmap_registers_with_offset(
                        inst.type_idx,
                        inst_offset,
                        &inst_name,
                        first_level_prefix,
                        generated,
                        name_config,
                        filter_config,
                    )?;
                }
                ComponentType::Mem => {
                    // Collect memory region
                    if let AllComponent::Mem(mem) = component {
                        // Calculate size in bytes: entries * (width in bits / 8)
                        let size_bytes = mem.entries * (mem.width / 8);
                        generated.memories.push(GeneratedMemory {
                            name: inst_name,
                            offset: inst_offset,
                            size_bytes,
                            description: mem.properties.get("name").and_then(|v| {
                                if let StringOrInt::String(s) = v {
                                    Some(s.clone())
                                } else {
                                    None
                                }
                            }),
                        });
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Collect register types from a nested addrmap (recursively)
    pub(super) fn collect_addrmap_register_types(
        &self,
        addrmap_idx: ComponentIdx,
        generated: &mut GeneratedAddrMap,
    ) -> Result<(), anyhow::Error> {
        let addrmap = self.component_arena[addrmap_idx]
            .as_addrmap()
            .ok_or_else(|| anyhow::anyhow!("Not an addrmap"))?;

        for child_idx in addrmap.children.iter().copied() {
            let child = &self.component_arena[child_idx];
            match child.component_type() {
                ComponentType::Reg => {
                    self.collect_register_type(child_idx, generated)?;
                }
                ComponentType::RegFile => {
                    self.collect_regfile_register_types(child_idx, generated)?;
                }
                ComponentType::AddrMap => {
                    self.collect_addrmap_register_types(child_idx, generated)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Collect register types defined inside a regfile component
    pub(super) fn collect_regfile_register_types(
        &self,
        regfile_idx: ComponentIdx,
        generated: &mut GeneratedAddrMap,
    ) -> Result<(), anyhow::Error> {
        let component = &self.component_arena[regfile_idx];
        if let AllComponent::RegFile(regfile) = component {
            // Collect register types from 'fields' map (type definitions)
            for field_idx in regfile.fields.values().copied() {
                let field_component = &self.component_arena[field_idx];
                if field_component.component_type() == ComponentType::Reg {
                    self.collect_register_type(field_idx, generated)?;
                }
            }

            // Also collect register types from 'reg_instances' (instantiated registers)
            // For anonymous inline registers, use the instance ID as the type name
            for reg_inst in &regfile.reg_instances {
                let reg_component = &self.component_arena[reg_inst.type_idx];
                match reg_component.component_type() {
                    ComponentType::Reg => {
                        // If register has no name, use instance ID as type name
                        let name_override = if reg_component.name().is_none() {
                            Some(reg_inst.id.as_str())
                        } else {
                            None
                        };
                        self.collect_register_type_with_name(
                            reg_inst.type_idx,
                            name_override,
                            generated,
                        )?;
                    }
                    ComponentType::RegFile => {
                        // Recursively collect from nested regfiles
                        self.collect_regfile_register_types(reg_inst.type_idx, generated)?;
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Collect register instances from a regfile, adding base_offset to each register's offset
    /// The regfile_instance_name is used to prefix register names for uniqueness
    /// first_level_prefix tracks the first regfile name for potential stripping
    #[allow(clippy::too_many_arguments)]
    pub(super) fn collect_regfile_instances(
        &self,
        regfile_idx: ComponentIdx,
        base_offset: usize,
        regfile_instance_name: &str,
        first_level_prefix: Option<&str>,
        generated: &mut GeneratedAddrMap,
        name_config: &NameConfig,
        filter_config: &FilterConfig,
    ) -> Result<(), anyhow::Error> {
        let component = &self.component_arena[regfile_idx];
        if let AllComponent::RegFile(regfile) = component {
            // Use reg_instances for register instances within regfiles
            for reg_inst in &regfile.reg_instances {
                let reg_component = &self.component_arena[reg_inst.type_idx];
                match reg_component.component_type() {
                    ComponentType::Reg => {
                        // Use register's own name, or instance ID for anonymous registers
                        let type_name = reg_component
                            .name()
                            .map(|s| s.to_string())
                            .or_else(|| Some(reg_inst.id.clone()));
                        let (can_read, can_write) = self.get_register_access(reg_inst.type_idx);

                        // Use the regfile instance name as prefix for register instance names
                        let combined_name = format!("{}_{}", regfile_instance_name, &reg_inst.id);

                        // Optionally strip the first-level prefix from the name
                        // Only strip if we're in a nested regfile (first_level_prefix != regfile_instance_name)
                        let final_name = if name_config.strip_first_level_prefix_in_nested {
                            if let Some(prefix) = first_level_prefix {
                                // Only strip if the current regfile is deeper than the first level
                                if regfile_instance_name != prefix {
                                    combined_name
                                        .strip_prefix(prefix)
                                        .and_then(|s| s.strip_prefix('_'))
                                        .map(|s| s.to_string())
                                        .unwrap_or(combined_name)
                                } else {
                                    // We're still at the first level, don't strip
                                    combined_name
                                }
                            } else {
                                combined_name
                            }
                        } else {
                            combined_name
                        };

                        let reg_offset = base_offset + reg_inst.offset;

                        // Check filter before including this register
                        if !filter_config.should_include(reg_offset, &final_name) {
                            continue;
                        }

                        let array_size = reg_inst.array_size.as_ref().map(|v| v.iter().product());

                        let width = self.get_register_width_bits(reg_inst.type_idx);

                        generated.registers.push(GeneratedRegister {
                            name: final_name,
                            offset: reg_offset,
                            type_name,
                            can_read,
                            can_write,
                            array_size,
                            width,
                        });
                    }
                    ComponentType::RegFile => {
                        // Nested regfile - recursively collect its registers
                        // Collect register types from the nested regfile
                        self.collect_regfile_register_types(reg_inst.type_idx, generated)?;

                        // Collect register instances with combined prefix and offset
                        let combined_name = format!("{}_{}", regfile_instance_name, &reg_inst.id);
                        self.collect_regfile_instances(
                            reg_inst.type_idx,
                            base_offset + reg_inst.offset,
                            &combined_name,
                            first_level_prefix,
                            generated,
                            name_config,
                            filter_config,
                        )?;
                    }
                    _ => {
                        // Skip other component types
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn collect_register_type(
        &self,
        reg_idx: ComponentIdx,
        generated: &mut GeneratedAddrMap,
    ) -> Result<(), anyhow::Error> {
        self.collect_register_type_with_name(reg_idx, None, generated)
    }

    /// Collect register type with an optional name override.
    /// For anonymous inline registers, the instance name can be used as the type name.
    pub(super) fn collect_register_type_with_name(
        &self,
        reg_idx: ComponentIdx,
        name_override: Option<&str>,
        generated: &mut GeneratedAddrMap,
    ) -> Result<(), anyhow::Error> {
        let component = &self.component_arena[reg_idx];
        if let AllComponent::Reg(reg) = component {
            // Use override name if provided, otherwise use the register's own name
            let name = name_override
                .map(|s| s.to_string())
                .or_else(|| reg.name.clone());

            if let Some(name) = name {
                // Check if this register type has already been collected
                if generated.register_types.iter().any(|rt| rt.name == name) {
                    return Ok(()); // Already collected, skip
                }

                let mut fields = Vec::new();

                for field_inst in &reg.field_instances {
                    let field_component_idx = reg.fields.get(&field_inst.id);

                    let description = field_component_idx.and_then(|idx| {
                        self.component_arena[*idx]
                            .properties()
                            .get("desc")
                            .map(|v| {
                                // Strip surrounding quotes from the description
                                let s = v.to_string();
                                s.trim_matches('"').to_string()
                            })
                    });

                    // Look for enum values
                    let mut enum_values = Vec::new();
                    if let Some(encode_name) = field_component_idx.and_then(|idx| {
                        self.component_arena[*idx]
                            .properties()
                            .get("encode")
                            .map(|v| v.to_string())
                    }) {
                        // First search in field's enums
                        let mut found = false;
                        if let Some(field_idx) = field_component_idx {
                            for e in self.component_arena[*field_idx].enums() {
                                if e.name == encode_name {
                                    for v in &e.values {
                                        enum_values.push((v.name.clone(), v.value.value));
                                    }
                                    found = true;
                                    break;
                                }
                            }
                        }
                        // If not found, search in register's enums
                        if !found {
                            for e in &reg.enums {
                                if e.name == encode_name {
                                    for v in &e.values {
                                        enum_values.push((v.name.clone(), v.value.value));
                                    }
                                    break;
                                }
                            }
                        }
                    }

                    fields.push(GeneratedField {
                        name: field_inst.id.clone(),
                        offset: field_inst.offset,
                        width: field_inst.width,
                        description,
                        enum_values,
                    });
                }

                // Get register width in bits
                let reg_width = self.get_register_width_bits(reg_idx);

                generated.register_types.push(GeneratedRegisterType {
                    name: name.clone(),
                    width: reg_width,
                    fields,
                });
            }
        }
        Ok(())
    }

    /// Get the width in bytes of a component for offset calculation.
    /// Returns 4 bytes (32 bits) for registers, or calculates based on regfile/addrmap contents.
    pub(super) fn get_component_width(&self, component: &AllComponent) -> usize {
        match component.component_type() {
            ComponentType::Reg => {
                // Check for regwidth property, default to 32 bits (4 bytes)
                if let AllComponent::Reg(reg) = component {
                    if let Some(StringOrInt::Int(int)) = reg.properties.get("regwidth") {
                        return (int.value as usize + 7) / 8; // Convert bits to bytes, round up
                    }
                }
                4 // Default: 32-bit registers = 4 bytes
            }
            ComponentType::RegFile => {
                // Calculate total size from contained registers
                if let AllComponent::RegFile(regfile) = component {
                    let mut max_end: usize = 0;
                    for reg_inst in &regfile.reg_instances {
                        let reg_component = &self.component_arena[reg_inst.type_idx];
                        let reg_width = self.get_component_width(reg_component);
                        let reg_width = if reg_width > 0 { reg_width } else { 4 };
                        let count: usize = reg_inst
                            .array_size
                            .as_ref()
                            .map(|s| s.iter().product())
                            .unwrap_or(1);
                        let end = reg_inst.offset + count * reg_width;
                        if end > max_end {
                            max_end = end;
                        }
                    }
                    return max_end;
                }
                0
            }
            ComponentType::AddrMap => {
                // Nested addrmaps typically have explicit offsets
                0
            }
            _ => 0,
        }
    }

    /// Get the width in bits of a register (8, 16, 32, or 64).
    /// Returns 32 as default if regwidth property is not set.
    pub(super) fn get_register_width_bits(&self, reg_idx: ComponentIdx) -> u8 {
        let component = &self.component_arena[reg_idx];
        if let AllComponent::Reg(reg) = component {
            if let Some(StringOrInt::Int(int)) = reg.properties.get("regwidth") {
                return int.value as u8;
            }
        }
        32 // Default: 32-bit registers
    }

    pub(super) fn get_register_access(&self, reg_idx: ComponentIdx) -> (bool, bool) {
        let component = &self.component_arena[reg_idx];
        if let AllComponent::Reg(reg) = component {
            // Check field properties for sw access
            let mut can_read = false;
            let mut can_write = false;
            // First, check for default sw property at register level
            let default_sw = reg.properties.get("sw").map(|v| v.to_string());

            for field_inst in &reg.field_instances {
                // Try to get sw property from field definition
                let field_sw = reg.fields.get(&field_inst.id).and_then(|field_idx| {
                    self.component_arena[*field_idx]
                        .properties()
                        .get("sw")
                        .map(|v| v.to_string())
                });

                // Use field sw if present, otherwise use register default
                let sw = field_sw.or_else(|| default_sw.clone());

                if let Some(sw_val) = sw {
                    match sw_val.as_str() {
                        "r" => can_read = true,
                        "w" | "w1" => can_write = true,
                        "rw" | "wr" | "rw1" => {
                            can_read = true;
                            can_write = true;
                        }
                        "na" => {
                            // No access - don't set either flag
                        }
                        _ => {
                            // Unknown access type, default to rw
                            can_read = true;
                            can_write = true;
                        }
                    }
                } else {
                    // No sw property anywhere, default to rw for this field
                    can_read = true;
                    can_write = true;
                }
            }

            // If no fields, check register-level sw property or default to rw
            if reg.field_instances.is_empty() {
                if let Some(sw_val) = default_sw {
                    match sw_val.as_str() {
                        "r" => return (true, false),
                        "w" | "w1" => return (false, true),
                        "rw" | "wr" | "rw1" => return (true, true),
                        "na" => return (false, false),
                        _ => return (true, true),
                    }
                }
                return (true, true);
            }

            (can_read, can_write)
        } else {
            (true, true) // Default
        }
    }
}

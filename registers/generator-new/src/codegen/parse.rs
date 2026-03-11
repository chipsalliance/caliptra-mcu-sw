// Licensed under the Apache-2.0 license

//! Parsing logic for SystemRDL files.
//!
//! This module contains the `impl World` block that handles parsing SystemRDL
//! source files, evaluating expressions, and building the internal component tree.

use super::*;

impl World {
    /// Check if the current context uses msb0 bit ordering.
    /// Walks the parent chain looking for `msb0 = true` or `lsb0 = false` properties.
    fn is_msb0(&self, parent: Option<ComponentIdx>) -> bool {
        let mut idx = parent;
        while let Some(i) = idx {
            let component = &self.component_arena[i];
            let props = component.properties();
            if let Some(val) = props.get("msb0") {
                return val.to_string() == "true";
            }
            if let Some(val) = props.get("lsb0") {
                return val.to_string() == "false";
            }
            idx = component.parent();
        }
        false
    }

    /// Resolve the addressing mode from a component's properties or its parents.
    /// Returns: alignment in bytes for a register with the given width.
    /// SystemRDL 5.1.2.2:
    /// - compact: no alignment gaps, registers packed to accesswidth boundary
    /// - regalign (default): aligned to regwidth boundary
    /// - fullalign: aligned to next power-of-2 >= regwidth
    fn resolve_alignment(&self, parent: Option<ComponentIdx>, reg_width_bytes: usize) -> usize {
        let addressing = self.resolve_property_str(parent, "addressing");
        let _accesswidth_bytes = self
            .resolve_property_u64(parent, "accesswidth")
            .map(|bits| ((bits as usize) + 7) / 8)
            .unwrap_or(reg_width_bytes);

        match addressing.as_deref() {
            Some("compact") => {
                // Compact: no alignment padding, registers packed tightly
                1
            }
            Some("fullalign") => {
                // Fullalign: align to next power-of-2 >= regwidth
                reg_width_bytes.next_power_of_two()
            }
            _ => {
                // Regalign (default): align to regwidth
                reg_width_bytes
            }
        }
    }

    /// Look up a string property by walking the parent chain.
    fn resolve_property_str(&self, parent: Option<ComponentIdx>, name: &str) -> Option<String> {
        let mut idx = parent;
        while let Some(i) = idx {
            let component = &self.component_arena[i];
            if let Some(val) = component.properties().get(name) {
                return Some(val.to_string());
            }
            idx = component.parent();
        }
        None
    }

    /// Look up an integer property by walking the parent chain.
    fn resolve_property_u64(&self, parent: Option<ComponentIdx>, name: &str) -> Option<u64> {
        let mut idx = parent;
        while let Some(i) = idx {
            let component = &self.component_arena[i];
            if let Some(StringOrInt::Int(int)) = component.properties().get(name) {
                return Some(int.value);
            }
            idx = component.parent();
        }
        None
    }

    /// Push a new parameter scope onto the stack.
    pub(super) fn push_param_scope(&mut self, scope: HashMap<String, Value>) {
        self.param_scope_stack.push(scope);
    }

    /// Pop the current parameter scope.
    pub(super) fn pop_param_scope(&mut self) {
        self.param_scope_stack.pop();
    }

    /// Look up a parameter in the current scope stack.
    /// Searches from innermost scope outward.
    pub(super) fn lookup_param(&self, name: &str) -> Option<&Value> {
        for scope in self.param_scope_stack.iter().rev() {
            if let Some(val) = scope.get(name) {
                return Some(val);
            }
        }
        None
    }

    /// Extract parameter definitions from a ParamDef and evaluate default values.
    pub(super) fn extract_param_defaults(
        &self,
        param_def: &Option<ParamDef>,
    ) -> HashMap<String, Value> {
        let mut params = HashMap::new();
        if let Some(ParamDef::Params(elems)) = param_def {
            for elem in elems {
                match elem {
                    ParamDefElem::ParamDefElem(_data_type, name, _array_type, default_expr) => {
                        if let Some(expr) = default_expr {
                            if let Ok(val) = self.evaluate_constant_expr(expr) {
                                params.insert(name.clone(), val);
                            }
                        }
                    }
                }
            }
        }
        params
    }

    pub fn parse(root: &Root) -> Result<Self, anyhow::Error> {
        let mut world = World::default();
        world.parse_root(root)?;
        Ok(world)
    }

    pub fn parse_root(&mut self, root: &Root) -> Result<(), anyhow::Error> {
        for d in root.descriptions.iter() {
            match d {
                Description::EnumDef(e) => {
                    let e = self.parse_enum(e)?;
                    self.enums.push(e);
                }
                Description::ComponentDef(c) => {
                    if c.insts.is_some() {
                        panic!("Cannot instantiate outside of addrmap");
                    }
                    match c.def.type_ {
                        ComponentType::AddrMap => {
                            let name = c.def.name.as_deref().unwrap_or("anon");
                            self.add_addrmap(None, name, &c.def.param_def, &c.def.body)?;
                        }
                        ComponentType::Reg => {
                            // Root-level register type definition
                            let name = c.def.name.as_deref().unwrap_or("anon");
                            let reg = self.convert_reg(None, Some(name), &c.def.body)?;
                            self.component_arena.push(AllComponent::Reg(reg));
                            self.child_components.push(self.component_arena.len() - 1);
                        }
                        ComponentType::RegFile => {
                            let name = c.def.name.as_deref().unwrap_or("anon");
                            let regfile = self.convert_regfile(None, name, &c.def.body)?;
                            self.component_arena.push(AllComponent::RegFile(regfile));
                            self.child_components.push(self.component_arena.len() - 1);
                        }
                        ComponentType::Field => {
                            // Root-level field type definition
                            let name = c.def.name.as_deref().unwrap_or("anon");
                            let (field, _) = self.convert_field(None, Some(name), &c.def.body)?;
                            self.component_arena.push(AllComponent::Field(field));
                            self.child_components.push(self.component_arena.len() - 1);
                        }
                        ComponentType::Signal | ComponentType::Mem => {
                            // Skip signal and mem components - not needed for register generation
                        }
                        _ => {
                            // Skip other unsupported root component types
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub(super) fn eval_parameter(
        &self,
        _component_idx: Option<ComponentIdx>,
        value: &ConstantExpr,
    ) -> Result<Value, anyhow::Error> {
        // Evaluate a constant expression to get a Value
        self.evaluate_constant_expr(value)
    }

    pub(super) fn convert_field(
        &self,
        parent: Option<ComponentIdx>,
        name: Option<&str>,
        body: &ComponentBody,
    ) -> Result<(FieldType, Vec<FieldInstance>), anyhow::Error> {
        let instances = vec![];
        let mut properties = HashMap::new();
        let mut enums = Vec::new();
        for elem in body.elements.iter() {
            match elem {
                ComponentBodyElem::PropertyAssignment(pa) => {
                    if let Some((key, value)) = self.evaluate_property(pa) {
                        properties.insert(key, value);
                    }
                }
                ComponentBodyElem::EnumDef(enum_def) => {
                    let enum_ = self.parse_enum(enum_def)?;
                    enums.push(enum_);
                }
                ComponentBodyElem::ConstraintDef(_) => {
                    // Constraint definitions can be ignored for codegen
                }
                _ => {
                    // Skip other unsupported field body elements
                }
            }
        }
        Ok((
            FieldType {
                parent,
                name: name.map(|s| s.to_string()),
                properties,
                enums,
                ..Default::default()
            },
            instances,
        ))
    }

    pub(super) fn convert_reg(
        &mut self,
        parent: Option<ComponentIdx>,
        name: Option<&str>,
        body: &ComponentBody,
    ) -> Result<RegisterType, anyhow::Error> {
        let mut reg = RegisterType {
            parent,
            name: name.map(|name| name.to_string()),
            ..Default::default()
        };
        let mut next_bit: u64 = 0;
        for elem in body.elements.iter() {
            match elem {
                ComponentBodyElem::PropertyAssignment(pa) => {
                    if let Some((key, value)) = self.evaluate_property(pa) {
                        reg.properties.insert(key, value);
                    }
                }
                ComponentBodyElem::ComponentDef(component) => {
                    let comp = self.convert_component_field(parent, component)?;
                    if let Some(comp_idx) = comp {
                        let comp = &self.component_arena[comp_idx];
                        // For named field types, insert by type name
                        if let Some(name) = comp.name() {
                            reg.fields.insert(name.to_string(), comp_idx);
                        }
                        // Also insert field instances
                        if let Some(insts) = component.insts.as_ref() {
                            let new_insts =
                                self.convert_field_instances(comp_idx, insts, &mut next_bit)?;
                            // For anonymous field types, insert by instance name
                            if comp.name().is_none() {
                                for inst in &new_insts {
                                    reg.fields.insert(inst.id.clone(), comp_idx);
                                }
                            }
                            reg.field_instances.extend(new_insts);
                        }
                    }
                    // else: ComponentDef in a register that isn't a field - silently skip
                }
                ComponentBodyElem::EnumDef(enum_def) => {
                    let enum_ = self.parse_enum(enum_def)?;
                    reg.enums.push(enum_);
                }
                ComponentBodyElem::ExplicitComponentInst(inst) => {
                    // look in the register components first
                    if reg.fields.contains_key(&inst.component_name) {
                        let field_idx = reg.fields[&inst.component_name];
                        let new_insts = self.convert_field_instances(
                            field_idx,
                            &inst.component_insts,
                            &mut next_bit,
                        )?;
                        reg.field_instances.extend(new_insts);
                    } else if reg.enums.iter().any(|e| e.name == inst.component_name) {
                        // found in enums - nothing to do, enum is just a type reference
                    } else {
                        // Try to find field type in parent scope or root components
                        let field_idx = if let Some(parent) = parent {
                            self.find_component(&self.component_arena[parent], &inst.component_name)
                        } else {
                            None
                        }
                        .or_else(|| self.find_root_component(&inst.component_name));

                        if let Some(field_idx) = field_idx {
                            // Found field type in parent/root scope - create instances
                            let new_insts = self.convert_field_instances(
                                field_idx,
                                &inst.component_insts,
                                &mut next_bit,
                            )?;
                            reg.field_instances.extend(new_insts);
                        } else {
                            bail!("Component {} not found in scope", inst.component_name);
                        }
                    }
                }
                ComponentBodyElem::StructDef(_) => {
                    // Struct definitions in registers are not used for code generation
                }
                ComponentBodyElem::ConstraintDef(_) => {
                    // Constraint definitions are for verification, not code generation
                }
            }
        }

        // If msb0 bit ordering is active, convert field positions from msb0 to lsb0.
        // In msb0 mode, bit 0 is the MSB. We convert to lsb0 positions for hardware:
        //   lsb0_offset = regwidth - msb0_offset - field_width
        if self.is_msb0(parent) {
            let regwidth = reg
                .properties
                .get("regwidth")
                .and_then(|v| {
                    if let StringOrInt::Int(int) = v {
                        Some(int.value as usize)
                    } else {
                        None
                    }
                })
                .unwrap_or(32);
            for field in &mut reg.field_instances {
                field.offset = regwidth - field.offset - field.width;
            }
        }

        Ok(reg)
    }

    pub(super) fn convert_regfile(
        &mut self,
        parent: Option<ComponentIdx>,
        name: &str,
        body: &ComponentBody,
    ) -> Result<RegisterFileType, anyhow::Error> {
        //panic!("Regfile {} body: {:?}", name, body);
        let mut regfile = RegisterFileType {
            parent,
            name: name.to_string(),
            ..Default::default()
        };
        let mut next_bit: u64 = 0;
        let mut next_reg_offset: usize = 0;
        for elem in body.elements.iter() {
            match elem {
                ComponentBodyElem::PropertyAssignment(pa) => {
                    if let Some((key, value)) = self.evaluate_property(pa) {
                        regfile.properties.insert(key, value);
                    }
                }
                ComponentBodyElem::ComponentDef(component) => {
                    let comp = self.convert_component_field(parent, component)?;
                    if let Some(comp_idx) = comp {
                        let comp = &self.component_arena[comp_idx];
                        if let Some(name) = comp.name() {
                            regfile.fields.insert(name.to_string(), comp_idx);
                        }
                        if component.insts.is_some() {
                            let new_insts = self.convert_field_instances(
                                comp_idx,
                                component.insts.as_ref().unwrap(),
                                &mut next_bit,
                            )?;
                            regfile.field_instances.extend(new_insts);
                        }
                    }
                    let comp = self.convert_component_reg(parent, component)?;
                    if let Some(comp_idx) = comp {
                        let comp = &self.component_arena[comp_idx];
                        if let Some(name) = comp.name() {
                            regfile.fields.insert(name.to_string(), comp_idx);
                        }
                        if component.insts.is_some() {
                            // For register instances, use convert_reg_instances (not field_instances)
                            let new_insts = self.convert_reg_instances(
                                comp_idx,
                                component.insts.as_ref().unwrap(),
                                &mut next_reg_offset,
                                parent,
                            )?;
                            regfile.reg_instances.extend(new_insts);
                        }
                    }
                }
                ComponentBodyElem::EnumDef(enum_def) => {
                    let enum_ = self.parse_enum(enum_def)?;
                    regfile.enums.push(enum_);
                }
                ComponentBodyElem::ExplicitComponentInst(inst) => {
                    // look in the register components first
                    if regfile.fields.contains_key(&inst.component_name) {
                        let type_idx = regfile.fields[&inst.component_name];
                        let comp = &self.component_arena[type_idx];
                        if comp.component_type() == ComponentType::Reg {
                            // Register instance
                            let new_insts = self.convert_reg_instances(
                                type_idx,
                                &inst.component_insts,
                                &mut next_reg_offset,
                                parent,
                            )?;
                            regfile.reg_instances.extend(new_insts);
                        } else {
                            // Field instance
                            let new_insts = self.convert_field_instances(
                                type_idx,
                                &inst.component_insts,
                                &mut next_bit,
                            )?;
                            regfile.field_instances.extend(new_insts);
                        }
                    } else if regfile.enums.iter().any(|e| e.name == inst.component_name) {
                        // found in enums
                    } else {
                        // Try to find component in parent scope or root scope
                        let maybe_component_idx = if let Some(parent) = parent {
                            self.find_component(&self.component_arena[parent], &inst.component_name)
                        } else {
                            // Look in root-level components
                            self.find_root_component(&inst.component_name)
                        };

                        if let Some(component_idx) = maybe_component_idx {
                            let comp = &self.component_arena[component_idx];
                            match comp.component_type() {
                                ComponentType::Reg => {
                                    // Register instance from external scope
                                    let new_insts = self.convert_reg_instances(
                                        component_idx,
                                        &inst.component_insts,
                                        &mut next_reg_offset,
                                        parent,
                                    )?;
                                    regfile.reg_instances.extend(new_insts);
                                    // Also add to fields for later lookup
                                    regfile
                                        .fields
                                        .insert(inst.component_name.clone(), component_idx);
                                }
                                ComponentType::RegFile => {
                                    // Nested regfile instance - store reference for later expansion
                                    let new_insts = self.convert_regfile_refs(
                                        component_idx,
                                        &inst.component_insts,
                                        &mut next_reg_offset,
                                    )?;
                                    regfile.reg_instances.extend(new_insts);
                                }
                                _ => {
                                    // Skip other component types (signals, mems, etc.)
                                }
                            }
                        } else {
                            bail!(
                                "Component {} not found in regfile scope {}",
                                inst.component_name,
                                name
                            );
                        }
                    }
                }
                _ => {
                    // Skip unsupported elements instead of panicking
                }
            }
        }
        Ok(regfile)
    }

    /// Convert a memory component definition
    pub(super) fn convert_mem(
        &mut self,
        parent: Option<ComponentIdx>,
        name: Option<&str>,
        body: &ComponentBody,
    ) -> Result<MemType, anyhow::Error> {
        let mut mem = MemType {
            parent,
            name: name.map(|s| s.to_string()),
            entries: 1,
            width: 32, // Default 32-bit width
            ..Default::default()
        };

        for elem in body.elements.iter() {
            match elem {
                ComponentBodyElem::PropertyAssignment(pa) => {
                    if let Some((key, value)) = self.evaluate_property(pa) {
                        // Handle mementries and memwidth properties
                        match key.as_str() {
                            "mementries" => {
                                if let StringOrInt::Int(v) = &value {
                                    mem.entries = v.value as usize;
                                }
                            }
                            "memwidth" => {
                                if let StringOrInt::Int(v) = &value {
                                    mem.width = v.value as usize;
                                }
                            }
                            _ => {
                                mem.properties.insert(key, value);
                            }
                        }
                    }
                }
                _ => {
                    // Skip other body elements for memory components
                }
            }
        }

        Ok(mem)
    }

    pub(super) fn find_field(&self, src: &AllComponent, name: &str) -> Option<ComponentIdx> {
        if let Some(f) = src.fields().get(name) {
            Some(*f)
        } else if let Some(parent) = src.parent() {
            self.find_field(&self.component_arena[parent], name)
        } else {
            None
        }
    }

    pub(super) fn convert_field_instances(
        &self,
        field_idx: ComponentIdx,
        insts: &ComponentInsts,
        next_bit: &mut u64,
    ) -> Result<Vec<FieldInstance>, anyhow::Error> {
        let mut instances = vec![];
        for inst in insts.component_insts.iter() {
            let (lsb, fieldwidth) = match inst.array_or_range.as_ref() {
                Some(ArrayOrRange::Array(expr)) => {
                    if expr.len() != 1 {
                        bail!("Only single dimension arrays supported for field instances");
                    }
                    let width = self.evaluate_constant_expr_int(&expr[0])?.value;
                    let lsb = *next_bit;
                    *next_bit = lsb + width;
                    (lsb, width)
                }
                Some(ArrayOrRange::Range(range)) => {
                    // Range syntax: [high:low] specifies bit positions
                    let mcu_registers_systemrdl_new::ast::Range::Range(high_expr, low_expr) = range;
                    let high = self.evaluate_constant_expr_int(high_expr)?.value;
                    let low = self.evaluate_constant_expr_int(low_expr)?.value;
                    if high < low {
                        bail!("Invalid field range: high ({}) < low ({})", high, low);
                    }
                    let width = high - low + 1;
                    // Update next_bit to be after this field
                    *next_bit = high + 1;
                    (low, width)
                }
                None => {
                    // Check for fieldwidth property on the field definition
                    let width = self.component_arena[field_idx]
                        .properties()
                        .get("fieldwidth")
                        .and_then(|v| {
                            if let StringOrInt::Int(int) = v {
                                Some(int.value)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(1);
                    let lsb = *next_bit;
                    *next_bit = lsb + width;
                    (lsb, width)
                }
            };
            let instance = FieldInstance {
                id: inst.id.clone(),
                width: fieldwidth as usize,
                offset: lsb as usize,
            };
            instances.push(instance);
        }
        Ok(instances)
    }

    /// Convert register instances within a regfile, using @ offset syntax or sequential layout.
    /// next_offset tracks the next available offset for registers without explicit @ offset.
    pub(super) fn convert_reg_instances(
        &self,
        type_idx: ComponentIdx,
        insts: &ComponentInsts,
        next_offset: &mut usize,
        parent: Option<ComponentIdx>,
    ) -> Result<Vec<RegInstance>, anyhow::Error> {
        // Get register width in bytes
        let component = &self.component_arena[type_idx];
        let reg_width = self.get_component_width(component);
        let reg_width = if reg_width > 0 { reg_width } else { 4 }; // Default to 4 bytes

        // Resolve alignment based on addressing mode (compact/regalign/fullalign)
        let alignment = self.resolve_alignment(parent, reg_width);
        let alignment = if alignment > 0 { alignment } else { 1 };

        let mut instances = vec![];
        for inst in insts.component_insts.iter() {
            // Apply %= alignment if specified (overrides addressing mode)
            if let Some(align_expr) = &inst.percent_equals {
                let explicit_align = self.evaluate_constant_expr_int(align_expr)?.value as usize;
                if explicit_align > 0 {
                    *next_offset = next_offset.div_ceil(explicit_align) * explicit_align;
                }
            }
            let offset = if let Some(at) = &inst.at {
                let explicit_offset = self.evaluate_constant_expr_int(at)?.value as usize;
                // Update next_offset to be after this register
                *next_offset = explicit_offset + reg_width;
                explicit_offset
            } else {
                // Align per addressing mode (SystemRDL 5.1.2.2)
                let aligned_offset = (*next_offset).div_ceil(alignment) * alignment;
                *next_offset = aligned_offset + reg_width;
                aligned_offset
            };
            let array_size = if let Some(ArrayOrRange::Array(arr)) = &inst.array_or_range {
                let mut sizes = vec![];
                for dim in arr.iter() {
                    sizes.push(self.evaluate_constant_expr_int(dim)?.value as usize);
                }
                // Use += stride if specified, otherwise default to reg_width
                let stride = if let Some(stride_expr) = &inst.plus_equals {
                    self.evaluate_constant_expr_int(stride_expr)?.value as usize
                } else {
                    reg_width
                };
                // Update next_offset to account for array size
                let total_count: usize = sizes.iter().product();
                *next_offset = offset + (total_count * stride);
                Some(sizes)
            } else if let Some(ArrayOrRange::Range(_)) = &inst.array_or_range {
                bail!(
                    "Range syntax [msb:lsb] is not valid on register instance '{}'",
                    inst.id
                );
            } else {
                None
            };
            instances.push(RegInstance {
                id: inst.id.clone(),
                offset,
                type_idx,
                array_size,
            });
        }
        Ok(instances)
    }

    pub(super) fn eval_params(
        &self,
        component_idx: Option<ComponentIdx>,
        param_insts: &[ParamElem],
    ) -> Result<HashMap<String, Value>, anyhow::Error> {
        // collect parameters
        let mut params = HashMap::new();
        for param in param_insts.iter() {
            let name = param.id.clone();
            let value = self.eval_parameter(component_idx, &param.param_value)?;
            params.insert(name, value);
        }
        Ok(params)
    }

    pub(super) fn convert_component(
        &mut self,
        parent: Option<ComponentIdx>,
        component: &mcu_registers_systemrdl_new::ast::Component,
    ) -> Result<(Option<ComponentIdx>, Vec<InstanceIdx>), anyhow::Error> {
        // Wrapper that doesn't track offset (for backward compatibility)
        let mut next_offset = 0;
        self.convert_component_with_offset(parent, component, &mut next_offset)
    }

    pub(super) fn convert_component_with_offset(
        &mut self,
        parent: Option<ComponentIdx>,
        component: &mcu_registers_systemrdl_new::ast::Component,
        next_offset: &mut usize,
    ) -> Result<(Option<ComponentIdx>, Vec<InstanceIdx>), anyhow::Error> {
        let t = component.def.type_;
        let name = component.def.name.clone().unwrap_or("anon".to_string());
        let body = &component.def.body;

        match t {
            ComponentType::AddrMap => {
                let component_idx =
                    self.add_addrmap(parent, &name, &component.def.param_def, body)?;
                let mut insts: Vec<_> = vec![];
                if let Some(component_insts) = component.insts.as_ref() {
                    let params = self.eval_params(parent, &component_insts.param_insts)?;
                    for inst in component_insts.component_insts.iter() {
                        let offset = if let Some(at) = &inst.at {
                            self.evaluate_constant_expr_int(at)?.value as usize
                        } else {
                            0
                        };
                        self.instance_arena.push(Instance {
                            name: inst.id.clone(),
                            offset,
                            type_idx: component_idx,
                            parent,
                            parameters: params.clone(),
                            ..Default::default()
                        });
                        let inst_idx = self.instance_arena.len() - 1;
                        insts.push(inst_idx);
                    }
                }
                Ok((Some(component_idx), insts))
            }
            ComponentType::Signal => Ok((None, vec![])),
            ComponentType::Field => {
                let (field, _insts) =
                    self.convert_field(parent, component.def.name.as_deref(), body)?;
                self.component_arena.push(AllComponent::Field(field));
                let component_idx = self.component_arena.len() - 1;
                // we don't care about fields for the purposes of instances
                Ok((Some(component_idx), vec![]))
            }
            ComponentType::Reg => {
                // For anonymous registers, use the first instance name as the type name
                let type_name = if component.def.name.is_some() {
                    name.clone()
                } else if let Some(insts) = component.insts.as_ref() {
                    if let Some(first_inst) = insts.component_insts.first() {
                        first_inst.id.clone()
                    } else {
                        name.clone()
                    }
                } else {
                    name.clone()
                };
                let reg = self.convert_reg(parent, Some(&type_name), body)?;
                self.component_arena.push(AllComponent::Reg(reg));
                let component_idx = self.component_arena.len() - 1;

                // Get register width for offset calculation (default 4 bytes = 32 bits)
                let reg_width = self.get_component_width(&self.component_arena[component_idx]);

                let mut insts: Vec<_> = vec![];
                if let Some(component_insts) = component.insts.as_ref() {
                    let params = self.eval_params(parent, &component_insts.param_insts)?;
                    for inst in component_insts.component_insts.iter() {
                        let offset = if let Some(at) = &inst.at {
                            let explicit_offset =
                                self.evaluate_constant_expr_int(at)?.value as usize;
                            // Update next_offset to be after this register
                            *next_offset = explicit_offset + reg_width;
                            explicit_offset
                        } else {
                            // Align per addressing mode (SystemRDL 5.1.2.2)
                            let alignment = self.resolve_alignment(parent, reg_width);
                            let alignment = if alignment > 0 { alignment } else { 1 };
                            let aligned_offset = (*next_offset).div_ceil(alignment) * alignment;
                            *next_offset = aligned_offset + reg_width;
                            aligned_offset
                        };
                        let array_size = if let Some(ArrayOrRange::Array(arr)) =
                            &inst.array_or_range
                        {
                            let mut sizes = vec![];
                            for dim in arr.iter() {
                                sizes.push(self.evaluate_constant_expr_int(dim)?.value as usize);
                            }
                            // Update next_offset to account for array size
                            let total_count: usize = sizes.iter().product();
                            *next_offset = offset + (total_count * reg_width);
                            Some(sizes)
                        } else if let Some(ArrayOrRange::Range(_)) = &inst.array_or_range {
                            bail!(
                                "Range syntax [msb:lsb] is not valid on regfile instance '{}'",
                                inst.id
                            );
                        } else {
                            None
                        };
                        self.instance_arena.push(Instance {
                            name: inst.id.clone(),
                            offset,
                            array_size,
                            type_idx: component_idx,
                            parent,
                            parameters: params.clone(),
                            ..Default::default()
                        });
                        let inst_idx = self.instance_arena.len() - 1;
                        insts.push(inst_idx);
                    }
                }
                Ok((Some(component_idx), insts))
            }
            ComponentType::RegFile => {
                let regfile = self.convert_regfile(parent, &name, body)?;
                self.component_arena.push(AllComponent::RegFile(regfile));
                let component_idx = self.component_arena.len() - 1;
                let mut insts: Vec<_> = vec![];
                if let Some(component_insts) = component.insts.as_ref() {
                    let params = self.eval_params(parent, &component_insts.param_insts)?;
                    let regfile_size = {
                        let component = &self.component_arena[component_idx];
                        self.get_component_width(component)
                    };
                    let regfile_size = if regfile_size > 0 { regfile_size } else { 4 };
                    // Nested regfiles align to next power-of-2 of their total size
                    let regfile_align = regfile_size.next_power_of_two();
                    for inst in component_insts.component_insts.iter() {
                        let offset = if let Some(at) = &inst.at {
                            let explicit_offset =
                                self.evaluate_constant_expr_int(at)?.value as usize;
                            *next_offset = explicit_offset + regfile_size;
                            explicit_offset
                        } else {
                            let aligned = (*next_offset).div_ceil(regfile_align) * regfile_align;
                            *next_offset = aligned + regfile_size;
                            aligned
                        };
                        self.instance_arena.push(Instance {
                            name: inst.id.clone(),
                            offset,
                            type_idx: component_idx,
                            parent,
                            parameters: params.clone(),
                            ..Default::default()
                        });
                        let inst_idx = self.instance_arena.len() - 1;
                        insts.push(inst_idx);
                    }
                }
                Ok((Some(component_idx), insts))
            }
            ComponentType::Mem => {
                // Parse memory component and create instances
                let mem = self.convert_mem(parent, Some(&name), body)?;
                self.component_arena.push(AllComponent::Mem(mem));
                let component_idx = self.component_arena.len() - 1;
                let mut insts = Vec::new();

                // Compute memory size from memwidth and mementries
                let mem_size = if let AllComponent::Mem(m) = &self.component_arena[component_idx] {
                    let width_bytes = (m.width + 7) / 8; // Convert bits to bytes, round up
                    let width_bytes = if width_bytes > 0 { width_bytes } else { 4 };
                    width_bytes * m.entries
                } else {
                    4
                };
                let mem_size = if mem_size > 0 { mem_size } else { 4 };

                if let Some(component_insts) = component.insts.as_ref() {
                    let params = self.eval_params(parent, &component_insts.param_insts)?;
                    for inst in component_insts.component_insts.iter() {
                        let offset = if let Some(at) = &inst.at {
                            let explicit_offset =
                                self.evaluate_constant_expr_int(at)?.value as usize;
                            *next_offset = explicit_offset + mem_size;
                            explicit_offset
                        } else {
                            let offset = *next_offset;
                            *next_offset += mem_size;
                            offset
                        };
                        self.instance_arena.push(Instance {
                            name: inst.id.clone(),
                            offset,
                            type_idx: component_idx,
                            parent,
                            parameters: params.clone(),
                            ..Default::default()
                        });
                        let inst_idx = self.instance_arena.len() - 1;
                        insts.push(inst_idx);
                    }
                }
                Ok((Some(component_idx), insts))
            }
            ComponentType::Constraint | ComponentType::Enum | ComponentType::EnumVariant => {
                // Skip signal, constraint, and enum components - not needed for register generation
                // Enums are handled separately via EnumDef in component bodies
                Ok((None, vec![]))
            }
        }
    }

    pub(super) fn convert_component_field(
        &mut self,
        parent: Option<ComponentIdx>,
        component: &mcu_registers_systemrdl_new::ast::Component,
    ) -> Result<Option<ComponentIdx>, anyhow::Error> {
        let t = component.def.type_;
        let name = component.def.name.clone();
        let body = &component.def.body;
        match t {
            ComponentType::Field => {
                // Note: Instances are handled by the caller (convert_reg/convert_regfile),
                // not here. We only create the type definition.
                let (field, _insts) = self.convert_field(parent, name.as_deref(), body)?;
                self.component_arena.push(AllComponent::Field(field));
                Ok(Some(self.component_arena.len() - 1))
            }
            _ => Ok(None),
        }
    }

    pub(super) fn convert_component_reg(
        &mut self,
        parent: Option<ComponentIdx>,
        component: &mcu_registers_systemrdl_new::ast::Component,
    ) -> Result<Option<ComponentIdx>, anyhow::Error> {
        let t = component.def.type_;
        let name = component.def.name.clone();
        let body = &component.def.body;
        match t {
            ComponentType::Reg => {
                // Note: Instances are handled by the caller (add_addrmap/convert_regfile),
                // not here. We only create the type definition.
                let reg = self.convert_reg(parent, name.as_deref(), body)?;
                self.component_arena.push(AllComponent::Reg(reg));
                Ok(Some(self.component_arena.len() - 1))
            }
            _ => Ok(None),
        }
    }

    /// Finds a component by name in the scope of the given component (and any parent scopes).
    /// Searches children first, then fields (for field types), then recurses to parent.
    pub(super) fn find_component(&self, src: &AllComponent, name: &str) -> Option<ComponentIdx> {
        // Check children first
        for child_idx in src.children().iter().copied() {
            let child = &self.component_arena[child_idx];
            if child.name() == Some(name) {
                return Some(child_idx);
            }
        }
        // Check fields (for field types defined in this scope)
        if let Some(&field_idx) = src.fields().get(name) {
            return Some(field_idx);
        }
        // Recurse to parent scope
        if let Some(parent) = src.parent() {
            self.find_component(&self.component_arena[parent], name)
        } else {
            // Check root-level components
            for child_idx in self.child_components.iter().copied() {
                let child = &self.component_arena[child_idx];
                if child.name() == Some(name) {
                    return Some(child_idx);
                }
            }
            None
        }
    }

    /// Find a component by name in the root-level components
    pub(super) fn find_root_component(&self, name: &str) -> Option<ComponentIdx> {
        for child_idx in self.child_components.iter().copied() {
            let child = &self.component_arena[child_idx];
            if child.name() == Some(name) {
                return Some(child_idx);
            }
        }
        None
    }

    /// Convert regfile references for nested regfile instances
    /// This creates RegInstance entries that point to the nested regfile
    pub(super) fn convert_regfile_refs(
        &self,
        regfile_type_idx: ComponentIdx,
        insts: &ComponentInsts,
        next_offset: &mut usize,
    ) -> Result<Vec<RegInstance>, anyhow::Error> {
        let mut instances = vec![];
        let regfile_component = &self.component_arena[regfile_type_idx];
        let regfile_size = self.get_component_width(regfile_component);
        let regfile_size = if regfile_size > 0 { regfile_size } else { 4 };
        let regfile_align = regfile_size.next_power_of_two();
        for inst in insts.component_insts.iter() {
            let offset = if let Some(at) = &inst.at {
                // For nested regfiles, we need to calculate how much space it takes
                // The actual size will be determined when expanding the regfile
                self.evaluate_constant_expr_int(at)?.value as usize
            } else {
                // Align to next power-of-2 of regfile size (matches PeakRDL behavior)
                (*next_offset).div_ceil(regfile_align) * regfile_align
            };
            // Create a RegInstance that references the nested regfile
            // The type_idx points to the regfile component
            let array_size = if let Some(ArrayOrRange::Array(arr)) = &inst.array_or_range {
                let mut sizes = vec![];
                for dim in arr.iter() {
                    sizes.push(self.evaluate_constant_expr_int(dim)?.value as usize);
                }
                Some(sizes)
            } else if let Some(ArrayOrRange::Range(_)) = &inst.array_or_range {
                bail!(
                    "Range syntax [msb:lsb] is not valid on regfile instance '{}'",
                    inst.id
                );
            } else {
                None
            };
            // Compute array count before moving array_size
            let count: usize = array_size.as_ref().map(|s| s.iter().product()).unwrap_or(1);
            instances.push(RegInstance {
                id: inst.id.clone(),
                offset,
                type_idx: regfile_type_idx,
                array_size,
            });
            *next_offset = offset + count * regfile_size;
        }
        Ok(instances)
    }

    /// Run a code block with the addrmap component at the given index.
    pub(super) fn with_addrmap<T>(
        &mut self,
        idx: ComponentIdx,
        f: impl FnOnce(&mut AddrMapType) -> T,
    ) -> T {
        if let AllComponent::AddrMap(addrmap) = &mut self.component_arena[idx] {
            f(addrmap)
        } else {
            panic!("Not an addrmap");
        }
    }

    /// Add an addrmap component to the world, returning the index of the new component.
    pub(super) fn add_addrmap(
        &mut self,
        parent: Option<ComponentIdx>,
        name: &str,
        param_def: &Option<ParamDef>,
        body: &ComponentBody,
    ) -> Result<ComponentIdx, anyhow::Error> {
        // Extract and push parameter defaults for this addrmap
        let param_defaults = self.extract_param_defaults(param_def);
        self.push_param_scope(param_defaults);

        let addrmap = AddrMapType {
            parent,
            name: name.to_string(),
            ..Default::default()
        };
        self.component_arena.push(AllComponent::AddrMap(addrmap));
        let addrmap_idx = self.component_arena.len() - 1;
        self.child_components.push(addrmap_idx);

        // Track sequential offset for registers/components without explicit @ offset
        let mut next_offset: usize = 0;

        for elem in body.elements.iter() {
            match elem {
                ComponentBodyElem::ComponentDef(component) => {
                    let (comp, instances) = self.convert_component_with_offset(
                        Some(addrmap_idx),
                        component,
                        &mut next_offset,
                    )?;
                    if let Some(comp_idx) = comp {
                        self.with_addrmap(addrmap_idx, |addrmap| {
                            addrmap.children.push(comp_idx);
                            addrmap.child_instances.extend(instances);
                        });
                    }
                }
                ComponentBodyElem::EnumDef(enum_def) => {
                    let e = self.parse_enum(enum_def)?;
                    self.with_addrmap(addrmap_idx, |addrmap| {
                        addrmap.enums.push(e);
                    });
                }
                ComponentBodyElem::StructDef(_) => {
                    // Struct definitions in addrmaps are not used for register code generation
                }
                ComponentBodyElem::ConstraintDef(_) => {
                    // Constraint definitions are for verification, not code generation
                }
                ComponentBodyElem::ExplicitComponentInst(explicit_component_inst) => {
                    if let Some(component_idx) = self.find_component(
                        &self.component_arena[addrmap_idx],
                        &explicit_component_inst.component_name,
                    ) {
                        // collect parameters
                        let params = self.eval_params(
                            Some(component_idx),
                            &explicit_component_inst.component_insts.param_insts,
                        )?;

                        // Push parameter scope for this instantiation
                        self.push_param_scope(params.clone());
                        for inst in explicit_component_inst
                            .component_insts
                            .component_insts
                            .iter()
                        {
                            // Calculate register width based on component type
                            let component = &self.component_arena[component_idx];
                            let reg_width = self.get_component_width(component);
                            let is_regfile = matches!(component, AllComponent::RegFile(_));

                            // Apply %= alignment if specified
                            if let Some(align_expr) = &inst.percent_equals {
                                let alignment =
                                    self.evaluate_constant_expr_int(align_expr)?.value as usize;
                                if alignment > 0 {
                                    next_offset = next_offset.div_ceil(alignment) * alignment;
                                }
                            }
                            let offset = if let Some(at) = &inst.at {
                                let explicit_offset =
                                    self.evaluate_constant_expr_int(at)?.value as usize;
                                // Update next_offset to be after this component
                                next_offset = explicit_offset + reg_width;
                                explicit_offset
                            } else if is_regfile {
                                // Regfiles align to next power-of-2 of their total size
                                let alignment = reg_width.next_power_of_two();
                                let aligned_offset = next_offset.div_ceil(alignment) * alignment;
                                next_offset = aligned_offset + reg_width;
                                aligned_offset
                            } else {
                                // Align per addressing mode (SystemRDL 5.1.2.2)
                                let alignment =
                                    self.resolve_alignment(Some(addrmap_idx), reg_width);
                                let alignment = if alignment > 0 { alignment } else { 1 };
                                let aligned_offset = next_offset.div_ceil(alignment) * alignment;
                                next_offset = aligned_offset + reg_width;
                                aligned_offset
                            };
                            let array_size = if let Some(ArrayOrRange::Array(arr)) =
                                &inst.array_or_range
                            {
                                let mut sizes = vec![];
                                for dim in arr.iter() {
                                    sizes
                                        .push(self.evaluate_constant_expr_int(dim)?.value as usize);
                                }
                                // Use += stride if specified, otherwise default to reg_width
                                let stride = if let Some(stride_expr) = &inst.plus_equals {
                                    self.evaluate_constant_expr_int(stride_expr)?.value as usize
                                } else {
                                    reg_width
                                };
                                // Update next_offset to account for array size
                                let total_count: usize = sizes.iter().product();
                                next_offset = offset + (total_count * stride);
                                Some(sizes)
                            } else if let Some(ArrayOrRange::Range(_)) = &inst.array_or_range {
                                bail!(
                                    "Range syntax [msb:lsb] is not valid on component instance '{}'",
                                    inst.id
                                );
                            } else {
                                None
                            };
                            self.instance_arena.push(Instance {
                                name: inst.id.clone(),
                                offset,
                                array_size,
                                type_idx: component_idx,
                                parent: Some(addrmap_idx),
                                parameters: params.clone(),
                                ..Default::default()
                            });
                            let inst_idx = self.instance_arena.len() - 1;
                            self.with_addrmap(addrmap_idx, |addrmap| {
                                addrmap.child_instances.push(inst_idx);
                            })
                        }
                        // Pop parameter scope
                        self.pop_param_scope();
                    } else {
                        bail!(
                            "Component {} not found in scope",
                            explicit_component_inst.component_name
                        );
                    }
                }
                ComponentBodyElem::PropertyAssignment(property_assignment) => {
                    if let Some((key, value)) = self.evaluate_property(property_assignment) {
                        self.with_addrmap(addrmap_idx, |addrmap| {
                            addrmap.properties.insert(key, value);
                        });
                    }
                }
            }
        }

        // Pop the parameter scope we pushed at the start
        self.pop_param_scope();

        Ok(addrmap_idx)
    }

    pub(super) fn evaluate_property(
        &self,
        property_assignment: &PropertyAssignment,
    ) -> Option<(String, StringOrInt)> {
        match property_assignment {
            PropertyAssignment::ExplicitOrDefaultPropAssignment(pa) => match pa {
                ExplicitOrDefaultPropAssignment::ExplicitPropModifier(
                    _default_keyword,
                    explicit_prop_modifier,
                ) => Some((
                    explicit_prop_modifier.id.clone(),
                    StringOrInt::String(explicit_prop_modifier.prop_mod.to_string()),
                )),
                ExplicitOrDefaultPropAssignment::ExplicitPropAssignment(_default, epa) => {
                    match epa {
                        ExplicitPropertyAssignment::Assignment(
                            identity_or_prop_keyword,
                            prop_assignment_rhs,
                        ) => {
                            let id = match identity_or_prop_keyword {
                                IdentityOrPropKeyword::Id(id) => id.clone(),
                                IdentityOrPropKeyword::PropKeyword(prop_keyword) => {
                                    prop_keyword.to_string()
                                }
                            };
                            let rhs = match prop_assignment_rhs {
                                Some(rhs) => match rhs {
                                    PropAssignmentRhs::ConstantExpr(constant_expr) => self
                                        .evaluate_constant_expr_str(constant_expr)
                                        .ok()
                                        .map(StringOrInt::String)
                                        .or(self
                                            .evaluate_constant_expr_int(constant_expr)
                                            .map(StringOrInt::Int)
                                            .ok())
                                        .or_else(|| {
                                            // Handle boolean literals (e.g., `lsb0 = true;`)
                                            if let Ok(val) =
                                                self.evaluate_constant_expr(constant_expr)
                                            {
                                                match val {
                                                    crate::value::Value::Bool(b) => {
                                                        Some(StringOrInt::String(b.to_string()))
                                                    }
                                                    _ => None,
                                                }
                                            } else {
                                                None
                                            }
                                        }),
                                    PropAssignmentRhs::PrecedenceType(precedence_type) => {
                                        let s = match precedence_type {
                                        mcu_registers_systemrdl_new::ast::PrecedenceType::Hw => "hw",
                                        mcu_registers_systemrdl_new::ast::PrecedenceType::Sw => "sw",
                                    };
                                        Some(StringOrInt::String(s.to_string()))
                                    }
                                },
                                // No RHS means boolean flag (e.g., `hwclr;`) - treat as true
                                None => Some(StringOrInt::String("true".to_string())),
                            };
                            rhs.map(|rhs| (id.clone(), rhs))
                        }
                        ExplicitPropertyAssignment::EncodeAssignment(e) => {
                            Some(("encode".to_string(), StringOrInt::String(e.clone())))
                        }
                    }
                }
            },
            PropertyAssignment::PostPropAssignment(post_prop_assignment) => {
                // Post property assignments are used to set properties on existing instances
                // or to use hierarchical references. For code generation, we primarily need
                // the inline property assignments on components/fields, so these can be skipped.
                match post_prop_assignment {
                    PostPropAssignment::PropRef(_prop_ref, _prop_assignment_rhs) => {
                        // Dynamic property assignments on instance references are not needed
                        // for static register code generation
                        None
                    }
                    PostPropAssignment::PostEncodeAssignment(_) => {
                        // Post encode assignments are for dynamic property binding, not needed for codegen
                        None
                    }
                }
            }
        }
    }

    pub(super) fn evaluate_constant_expr_str(
        &self,
        expr: &ConstantExpr,
    ) -> Result<String, anyhow::Error> {
        match expr {
            ConstantExpr::ConstantPrimary(prim, cont) => {
                if cont.is_some() {
                    bail!("Unsupported complex expression for string");
                }
                match prim {
                    ConstantPrimary::Base(constant_primary_base) => match constant_primary_base {
                        ConstantPrimaryBase::PrimaryLiteral(primary_literal) => {
                            match primary_literal {
                                PrimaryLiteral::StringLiteral(s) => Ok(s.clone()),
                                PrimaryLiteral::AccessTypeLiteral(at) => {
                                    Ok(format!("{:?}", at).to_lowercase())
                                }
                                PrimaryLiteral::AddressingTypeLiteral(at) => {
                                    Ok(format!("{:?}", at).to_lowercase())
                                }
                                _ => bail!(
                                    "Unsupported literal in string evaluation context: {:?}",
                                    primary_literal
                                ),
                            }
                        }
                        ConstantPrimaryBase::InstanceOrPropRef(ipr) => {
                            // Handle bare identifiers like `compact`, `regalign`, etc.
                            if ipr.id_or_prop.is_none()
                                && ipr.iref.elements.len() == 1
                                && ipr.iref.elements[0].arrays.is_empty()
                            {
                                Ok(ipr.iref.elements[0].id.clone())
                            } else {
                                bail!("Unsupported instance/property ref for string");
                            }
                        }
                        _ => {
                            bail!("Unsupported expression for string");
                        }
                    },
                    ConstantPrimary::Cast(_constant_primary_base, _constant_expr) => {
                        bail!("Casting string not supported")
                    }
                }
            }
            ConstantExpr::UnaryOp(op, _expr, _cont) => {
                bail!("Unsupported unary operation on string: {:?}", op);
            }
        }
    }

    pub(super) fn evaluate_constant_expr_cont_int(
        &self,
        val: Integer,
        cont: &Option<Box<ConstantExprContinue>>,
    ) -> Result<Integer, anyhow::Error> {
        match cont {
            None => Ok(val),
            Some(cont) => {
                match cont.as_ref() {
                    ConstantExprContinue::BinaryOp(op, expr, _cont) => {
                        let rhs = self.evaluate_constant_expr_int(expr.as_ref())?;

                        let a = val.value;
                        let b = rhs.value;
                        let width = val.width;

                        // short circuit for shift since they may have different widths
                        let new_val = match op {
                            BinaryOp::RightShift => Some(a >> b),
                            BinaryOp::LeftShift => Some(a << b),
                            _ => None,
                        };
                        if let Some(value) = new_val {
                            return Ok(Integer { width, value });
                        }

                        if val.width != rhs.width {
                            bail!(
                                "Incompatible widths in expression: {} and {}",
                                val.width,
                                rhs.width
                            );
                        }

                        // Check booleans
                        let bool_value = match op {
                            BinaryOp::LessThan => Some(if a < b { TRUE } else { FALSE }),
                            BinaryOp::GreaterThan => Some(if a > b { TRUE } else { FALSE }),
                            BinaryOp::LessThanOrEqual => Some(if a <= b { TRUE } else { FALSE }),
                            BinaryOp::GreaterThanOrEqual => Some(if a >= b { TRUE } else { FALSE }),
                            BinaryOp::EqualsEquals => Some(if a == b { TRUE } else { FALSE }),
                            BinaryOp::NotEquals => Some(if a != b { TRUE } else { FALSE }),
                            _ => None,
                        };

                        if let Some(b) = bool_value {
                            return Ok(b);
                        }

                        let value: u64 = match op {
                            BinaryOp::AndAnd => a & b,
                            BinaryOp::OrOr => a | b,
                            BinaryOp::And => a & b,
                            BinaryOp::Or => a | b,
                            BinaryOp::Xor => a ^ b,
                            BinaryOp::Xnor => !(a ^ b),
                            BinaryOp::Times => a * b,
                            BinaryOp::Divide => a / b,
                            BinaryOp::Modulus => a % b,
                            BinaryOp::Plus => a + b,
                            BinaryOp::Minus => a - b,
                            BinaryOp::Power => a.pow(b as u32),
                            _ => unreachable!(),
                        };
                        Ok(Integer { width, value })
                    }
                    ConstantExprContinue::TernaryOp(b, c, cont) => {
                        let a = val;
                        if a.width != 1 {
                            bail!("Cannot use non-boolean value as ternary condition");
                        }
                        let b = self.evaluate_constant_expr_int(b.as_ref())?;
                        let c = self.evaluate_constant_expr_int(c.as_ref())?;
                        if a == TRUE {
                            self.evaluate_constant_expr_cont_int(b, cont)
                        } else {
                            self.evaluate_constant_expr_cont_int(c, cont)
                        }
                    }
                }
            }
        }
    }

    pub(super) fn evaluate_constant_expr_cont(
        &self,
        val: Value,
        cont: &Option<Box<ConstantExprContinue>>,
    ) -> Result<Value, anyhow::Error> {
        match cont {
            None => Ok(val),
            Some(cont) => match cont.as_ref() {
                ConstantExprContinue::BinaryOp(op, expr, _cont) => {
                    let rhs = self.evaluate_constant_expr(expr.as_ref())?;
                    match op {
                        BinaryOp::AndAnd => val.try_andand(&rhs),
                        BinaryOp::OrOr => val.try_oror(&rhs),
                        BinaryOp::LessThan => val.try_lt(&rhs),
                        BinaryOp::GreaterThan => val.try_gt(&rhs),
                        BinaryOp::LessThanOrEqual => val.try_lte(&rhs),
                        BinaryOp::GreaterThanOrEqual => val.try_gte(&rhs),
                        BinaryOp::EqualsEquals => val.try_eq(&rhs),
                        BinaryOp::NotEquals => val.try_neq(&rhs),
                        BinaryOp::RightShift => val.try_rshift(&rhs),
                        BinaryOp::LeftShift => val.try_lshift(&rhs),
                        BinaryOp::And => val.try_and(&rhs),
                        BinaryOp::Or => val.try_or(&rhs),
                        BinaryOp::Xor => val.try_xor(&rhs),
                        BinaryOp::Xnor => val.try_xnor(&rhs),
                        BinaryOp::Times => val.try_times(&rhs),
                        BinaryOp::Divide => val.try_divide(&rhs),
                        BinaryOp::Modulus => val.try_modulus(&rhs),
                        BinaryOp::Plus => val.try_add(&rhs),
                        BinaryOp::Minus => val.try_sub(&rhs),
                        BinaryOp::Power => val.try_pow(&rhs),
                    }
                }
                ConstantExprContinue::TernaryOp(b, c, cont) => {
                    if !val.is_bool() {
                        bail!("Cannot use non-boolean value as ternary condition");
                    }
                    let b = self.evaluate_constant_expr(b.as_ref())?;
                    let c = self.evaluate_constant_expr(c.as_ref())?;
                    if val.as_bool() {
                        self.evaluate_constant_expr_cont(b, cont)
                    } else {
                        self.evaluate_constant_expr_cont(c, cont)
                    }
                }
            },
        }
    }

    pub(super) fn evaluate_primary_literal(
        &self,
        p: &PrimaryLiteral,
    ) -> Result<Value, anyhow::Error> {
        let value = match p {
            PrimaryLiteral::Number(n) => Value::U64(*n),
            PrimaryLiteral::Bits(b) => Value::Bits(*b),
            PrimaryLiteral::StringLiteral(s) => Value::String(s.clone()),
            PrimaryLiteral::BooleanLiteral(b) => Value::Bool(*b),
            PrimaryLiteral::AccessTypeLiteral(access_type) => Value::AccessType(*access_type),
            PrimaryLiteral::OnReadTypeLiteral(on_read_type) => Value::OnReadType(*on_read_type),
            PrimaryLiteral::OnWriteTypeLiteral(on_write_type) => Value::OnWriteType(*on_write_type),
            PrimaryLiteral::AddressingTypeLiteral(addressing_type) => {
                Value::AddressingType(*addressing_type)
            }
            PrimaryLiteral::EnumeratorLiteral(a, b) => Value::EnumReference(a.clone(), b.clone()),
            PrimaryLiteral::This => bail!("'this' not supported in evaluation"),
        };
        Ok(value)
    }

    pub(super) fn evaluate_primary_literal_int(
        &self,
        p: &PrimaryLiteral,
    ) -> Result<Integer, anyhow::Error> {
        let value = match p {
            PrimaryLiteral::Number(n) => Integer {
                width: 32,
                value: *n,
            },
            PrimaryLiteral::Bits(b) => Integer {
                width: b.w() as u8,
                value: b.val(),
            },
            _ => bail!("Unsupported literal in integer evaluation context: {:?}", p),
        };
        Ok(value)
    }

    pub(super) fn evalutate_instance_or_prop_ref(
        &self,
        i: &InstanceOrPropRef,
    ) -> Result<Value, anyhow::Error> {
        // For single-element references, try to look up the parameter in the scope stack
        if i.iref.elements.len() == 1 {
            let ref_name = &i.iref.elements[0].id;
            if let Some(val) = self.lookup_param(ref_name) {
                return Ok(val.clone());
            }
            // If not found in scope, return a default value
            // This allows parsing to continue even without full parameter resolution
            Ok(Value::U64(0))
        } else {
            // Multi-element reference (like reg.field.property)
            Ok(Value::U64(0))
        }
    }

    pub(super) fn evaluate_constant_primary_base(
        &self,
        base: &ConstantPrimaryBase,
    ) -> Result<Value, anyhow::Error> {
        match base {
            ConstantPrimaryBase::PrimaryLiteral(p) => self.evaluate_primary_literal(p),
            ConstantPrimaryBase::ConstantExpr(c) => self.evaluate_constant_expr(c),
            ConstantPrimaryBase::InstanceOrPropRef(i) => self.evalutate_instance_or_prop_ref(i),
            ConstantPrimaryBase::StructLiteral(_, _) => {
                bail!("Struct literal not supported in evaluation")
            }
            ConstantPrimaryBase::ArrayLiteral(_) => {
                bail!("Array literal not supported in evaluation")
            }
            ConstantPrimaryBase::SimpleTypeCast(_, _) => {
                bail!("Simple type cast not supported in evaluation")
            }
            ConstantPrimaryBase::BooleanCast(_) => {
                bail!("Boolean type cast not supported in evaluation")
            }
            ConstantPrimaryBase::ConstantConcat(_) => {
                bail!("Concatenation not supported in evaluation")
            }
            ConstantPrimaryBase::ConstantMultipleConcat(_, _) => {
                bail!("Multiple concatenation not supported in evaluation")
            }
        }
    }

    pub(super) fn evaluate_constant_primary_base_int(
        &self,
        base: &ConstantPrimaryBase,
    ) -> Result<Integer, anyhow::Error> {
        match base {
            ConstantPrimaryBase::PrimaryLiteral(p) => self.evaluate_primary_literal_int(p),
            ConstantPrimaryBase::ConstantExpr(c) => self.evaluate_constant_expr_int(c),
            ConstantPrimaryBase::InstanceOrPropRef(iref) => {
                // Look up the reference in the parameter scope
                let val = self.evalutate_instance_or_prop_ref(iref)?;
                match val {
                    Value::U64(n) => Ok(Integer {
                        width: 32,
                        value: n,
                    }),
                    Value::Bits(b) => Ok(Integer {
                        width: b.w() as u8,
                        value: b.val(),
                    }),
                    _ => bail!("Expected integer value for reference, got: {:?}", val),
                }
            }
            ConstantPrimaryBase::StructLiteral(_, _) => {
                bail!("Struct literal not supported in integer context")
            }
            ConstantPrimaryBase::ArrayLiteral(_) => {
                bail!("Array literal not supported in integer context")
            }
            ConstantPrimaryBase::SimpleTypeCast(_, _) => {
                bail!("Simple type cast not supported in integer context")
            }
            ConstantPrimaryBase::BooleanCast(_) => {
                bail!("Boolean type cast not supported in integer context")
            }
            ConstantPrimaryBase::ConstantConcat(_) => bail!("Integer concatenation not supported"),
            ConstantPrimaryBase::ConstantMultipleConcat(_, _) => {
                bail!("Integer multiple concatenation not supported")
            }
        }
    }

    pub(super) fn evaluate_cast(
        &self,
        _value: Integer,
        _expr: &ConstantExpr,
    ) -> Result<Integer, anyhow::Error> {
        bail!("Casting not supported");
    }

    pub(super) fn evaluate_cast_value(
        &self,
        _value: Value,
        _expr: &ConstantExpr,
    ) -> Result<Value, anyhow::Error> {
        bail!("Casting not supported");
    }

    pub(super) fn evaluate_constant_primary_int(
        &self,
        prim: &ConstantPrimary,
    ) -> Result<Integer, anyhow::Error> {
        match prim {
            ConstantPrimary::Base(base) => self.evaluate_constant_primary_base_int(base),
            ConstantPrimary::Cast(base, cast) => {
                let base = self.evaluate_constant_primary_base_int(base)?;
                self.evaluate_cast(base, cast.as_ref())
            }
        }
    }

    pub(super) fn eval_constant_primary_value(
        &self,
        prim: &ConstantPrimary,
    ) -> Result<Value, anyhow::Error> {
        match prim {
            ConstantPrimary::Base(base) => self.evaluate_constant_primary_base(base),
            ConstantPrimary::Cast(base, cast) => {
                let base = self.evaluate_constant_primary_base(base)?;
                self.evaluate_cast_value(base, cast.as_ref())
            }
        }
    }

    pub(super) fn evaluate_constant_expr(
        &self,
        expr: &ConstantExpr,
    ) -> Result<Value, anyhow::Error> {
        match expr {
            ConstantExpr::ConstantPrimary(prim, cont) => {
                let val = self.eval_constant_primary_value(prim)?;
                self.evaluate_constant_expr_cont(val, cont)
            }
            ConstantExpr::UnaryOp(op, expr, cont) => {
                let expr = self.evaluate_constant_expr(expr)?;
                if !expr.is_integral() {
                    bail!("Unsupported unary operation on non-integral type: {:?}", op);
                }
                let new_val = match op {
                    UnaryOp::LogicalNot => expr.logical_not(),
                    UnaryOp::Plus => expr,
                    UnaryOp::Minus => -expr,
                    UnaryOp::Not => !expr,
                    UnaryOp::And => bail!("Unsupported unary operation on integral type: &"),
                    UnaryOp::Nand => bail!("Unsupported unary operation on integral type: ~&"),
                    UnaryOp::Or => bail!("Unsupported unary operation on integral type: |"),
                    UnaryOp::Nor => bail!("Unsupported unary operation on integral type: ~&"),
                    UnaryOp::Xor => bail!("Unsupported unary operation on integral type: ^"),
                    UnaryOp::Xnor => bail!("Unsupported unary operation on integral type: ~^"),
                };
                self.evaluate_constant_expr_cont(new_val, cont)
            }
        }
    }

    pub(super) fn evaluate_constant_expr_int(
        &self,
        expr: &ConstantExpr,
    ) -> Result<Integer, anyhow::Error> {
        match expr {
            ConstantExpr::ConstantPrimary(prim, cont) => {
                let val = self.evaluate_constant_primary_int(prim)?;
                self.evaluate_constant_expr_cont_int(val, cont)
            }
            ConstantExpr::UnaryOp(op, expr, cont) => {
                let expr = self.evaluate_constant_expr_int(expr)?;
                let width = expr.width;
                let val = expr.value;
                let new_val = match op {
                    UnaryOp::LogicalNot => !val,
                    UnaryOp::Plus => val,
                    UnaryOp::Minus => (!val) + 1,
                    UnaryOp::Not => !val,
                    UnaryOp::And => bail!("Unsupported unary operation on integer: &"),
                    UnaryOp::Nand => bail!("Unsupported unary operation on integer: ~&"),
                    UnaryOp::Or => bail!("Unsupported unary operation on integer: |"),
                    UnaryOp::Nor => bail!("Unsupported unary operation on integer: ~&"),
                    UnaryOp::Xor => bail!("Unsupported unary operation on integer: ^"),
                    UnaryOp::Xnor => bail!("Unsupported unary operation on integer: &"),
                };
                let val = Integer {
                    width,
                    value: new_val,
                };
                self.evaluate_constant_expr_cont_int(val, cont)
            }
        }
    }

    pub(super) fn parse_enum(&self, e: &EnumDef) -> Result<Enum, anyhow::Error> {
        let mut values = vec![];
        let mut last_value: Option<Integer> = None;
        for entry in e.body.iter() {
            let val = match (&last_value, &entry.expr) {
                (None, None) => Integer {
                    width: 32,
                    value: 0,
                },
                (Some(last_val), None) => last_val.add(1),
                (_, Some(expr)) => self.evaluate_constant_expr_int(expr)?,
            };
            last_value = Some(val);
            let val = EnumValue {
                name: entry.id.clone(),
                value: val,
            };
            values.push(val);
        }
        Ok(Enum {
            name: e.id.clone(),
            values,
        })
    }

    // fn instantiate_addrmap(
    //     &mut self,
    //     addrmap_name: &str,
    //     offset: usize,
    // ) -> Result<usize, anyhow::Error> {
    //     for component_idx in self.child_components.iter().copied() {
    //         let addrmap_component = &self.component_arena[component_idx];
    //         if addrmap_component.component_type() == ComponentType::AddrMap
    //             && addrmap_component.name() == Some(addrmap_name)
    //         {
    //             let instance = Instance {
    //                 name: addrmap_name.to_string(),
    //                 type_idx: component_idx,
    //                 ..Default::default()
    //             };
    //             self.instance_arena.push(instance);
    //             let addrmap_instance_idx: InstanceIdx = self.instance_arena.len() - 1;
    //             self.child_instances.push(self.instance_arena.len() - 1);

    //             // now we need to instantiate all of the sub-components and instances of the addrmap
    //             let addrmap = addrmap_component.as_addrmap().unwrap();
    //             // TODO: child instances
    //             addrmap.explicit_instances.iter().for_each(|inst| {
    //                 let component_name = inst.component_name;
    //                 self.find_component(addrmap_component, &component_name)
    //                     .unwrap();
    //                 // evaluate the parameter map
    //                 for param_elem in inst.component_insts.param_insts.iter() {
    //                     self.eval_param_elem(component_idx, param_elem);
    //                 }

    //                 for component_inst in inst.component_insts.component_insts.iter() {
    //                     self.instantiate_component_under_instance(addrmap_instance_idx, )
    //                 }
    //             });

    //             return Ok(addrmap_instance_idx);
    //         }
    //     }
    //     bail!("Addrmap {} not found", addrmap_name)
    // }

    pub(super) fn instantiate_addrmap(
        &mut self,
        addrmap_name: &str,
        _offset: usize,
    ) -> Result<usize, anyhow::Error> {
        // TODO: I don't think we need all that. We can instantiate as we go.
        bail!("Addrmap {} not found", addrmap_name)
    }
}

/*++
Licensed under the Apache-2.0 license.
--*/

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::component_meta::PropertyMeta;
use crate::file_source::FileSource;
use crate::value::{AddressingType, ComponentType, InterruptType, PropertyType, ScopeType};
use crate::ParseError;
use crate::{
    component_meta, token::Token, token_iter::TokenIter, Bits, FileParseError, RdlError, Result,
    Value,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicAssignment {
    instance_path: Vec<String>,
    prop_name: String,
    value: Value,
}
impl DynamicAssignment {
    fn parse<'a>(
        tokens: &mut TokenIter<'a>,
        scope: &Scope,
        parameters: Option<&'_ ParameterScope<'_>>,
    ) -> Result<'a, Self> {
        let mut instance_path = vec![];
        loop {
            instance_path.push(tokens.expect_identifier()?);
            if *tokens.peek(0) != Token::Period {
                break;
            }
            tokens.next();
        }
        let instance = scope.lookup_instance_by_path(instance_path.iter().cloned())?;

        let ScopeType::Component(instance_ty) = instance.ty else {
            return Err(RdlError::CantSetPropertyInRootScope);
        };

        tokens.expect(Token::Pointer)?;

        let prop_name = tokens.expect_identifier()?;
        let prop_meta = component_meta::property(instance_ty, prop_name)?;

        let value = if *tokens.peek(0) == Token::Semicolon {
            Value::Bool(true)
        } else {
            tokens.expect(Token::Equals)?;
            prop_meta.ty.eval(tokens, parameters)?
        };
        Ok(Self {
            instance_path: instance_path.into_iter().map(|s| s.to_string()).collect(),
            prop_name: prop_name.into(),
            value,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParameterDefinition {
    ty: PropertyType,
    default: Value,
}
impl ParameterDefinition {
    fn parse_map<'a>(
        tokens: &mut TokenIter<'a>,
        parent: Option<&ParameterScope<'_>>,
        overrides: Option<&HashMap<String, Value>>,
    ) -> Result<'a, HashMap<String, ParameterDefinition>> {
        tokens.expect(Token::Hash)?;
        tokens.expect(Token::ParenOpen)?;

        let mut result = HashMap::new();
        loop {
            let ty = PropertyType::parse_type(tokens)?;
            let name = tokens.expect_identifier()?;
            // default value for bits is 0
            let mut default =
                if tokens.peek(0) == &Token::Comma || tokens.peek(0) == &Token::ParenClose {
                    if ty == PropertyType::Bits {
                        Value::Bits(Bits::new(32, 0))
                    } else {
                        return Err(RdlError::NotImplemented);
                    }
                } else {
                    tokens.expect(Token::Equals)?;
                    ty.eval(
                        tokens,
                        Some(&ParameterScope {
                            parent,
                            parameters: result.clone(),
                        }),
                    )?
                };
            if ty == PropertyType::Bits {
                if let Value::U64(value) = default {
                    default = Value::Bits(Bits::new(32, value));
                }
            }
            if let Some(value) = overrides.and_then(|values| values.get(name)) {
                default = value.clone();
            }
            if result.contains_key(name) {
                return Err(RdlError::DuplicateParameterName(name));
            }
            result.insert(name.into(), ParameterDefinition { ty, default });
            if tokens.peek(0) == &Token::ParenClose {
                break;
            }
            tokens.expect(Token::Comma)?;
        }
        tokens.expect(Token::ParenClose)?;
        Ok(result)
    }
}

fn uses_property(ty: ScopeType, name: &str) -> bool {
    if component_meta::default_property(ty, name).is_ok() {
        return true;
    }
    let ScopeType::Component(ty) = ty else {
        return false;
    };
    component_meta::property(ty, name).is_ok()
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scope {
    pub ty: ScopeType,
    pub types: HashMap<String, Scope>,
    pub instances: Vec<Instance>,
    pub default_properties: HashMap<String, Value>,
    pub properties: HashMap<String, Value>,
    pub dynamic_assignments: Vec<DynamicAssignment>,
    pub template: Option<ScopeTemplate>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeTemplate {
    parameters: HashMap<String, ParameterDefinition>,
    inherited_parameters: HashMap<String, ParameterDefinition>,
    path: PathBuf,
    offset: usize,
    defines: HashSet<String>,
}

impl Scope {
    fn new(ty: ScopeType) -> Self {
        Scope {
            ty,
            ..Default::default()
        }
    }

    pub fn property_val<'a, T: TryFrom<Value, Error = RdlError<'static>>>(
        &self,
        name: &'a str,
    ) -> Result<'a, T> {
        match self.property_val_opt(name)? {
            Some(val) => Ok(val),
            None => Err(RdlError::ExpectedPropertyNotFound(name)),
        }
    }
    pub fn property_val_opt<T: TryFrom<Value, Error = RdlError<'static>>>(
        &self,
        name: &str,
    ) -> Result<'static, Option<T>> {
        match self.properties.get(name) {
            Some(val) => Ok(Some(T::try_from(val.clone())?)),
            None => Ok(None),
        }
    }
    pub fn lookup_instance_by_path<'a>(
        &self,
        mut path_iter: impl Iterator<Item = &'a str>,
    ) -> Result<'a, &Scope> {
        if let Some(instance_name) = path_iter.next() {
            if let Some(instance) = self.instances.iter().find(|e| e.name == instance_name) {
                instance.scope.lookup_instance_by_path(path_iter)
            } else {
                Err(RdlError::UnknownInstanceName(instance_name))
            }
        } else {
            Ok(self)
        }
    }

    fn set_property_defaults(&mut self, parent: Option<&ParentScope<'_>>) {
        if let ScopeType::Component(ty) = self.ty {
            let mut next_parent = parent;
            while let Some(parent_scope) = next_parent {
                for (prop_name, val) in parent_scope.scope.default_properties.iter() {
                    if self.properties.contains_key(prop_name) {
                        continue;
                    }
                    if component_meta::property(ty, prop_name).is_err() {
                        continue;
                    }
                    self.properties.insert(prop_name.into(), val.clone());
                }
                next_parent = parent_scope.parent;
            }
        }
    }

    pub fn as_parent(&self) -> ParentScope<'_> {
        ParentScope {
            scope: self,
            parent: None,
        }
    }

    fn calculate_offsets(&mut self) -> Result<'static, ()> {
        for assignment in self.dynamic_assignments.clone() {
            self.set_instance_property(
                &assignment.instance_path,
                &assignment.prop_name,
                assignment.value,
            )?;
        }
        for instance in std::mem::take(&mut self.instances) {
            if instance
                .scope
                .property_val_opt::<bool>("ispresent")?
                .unwrap_or(true)
            {
                self.instances.push(instance);
            }
        }
        let addr_mode = AddressingType::Compact;

        let default_alignment = self.property_val_opt::<u64>("alignment").ok().flatten();
        // Set reg offsets
        let mut next_offset = 0;
        for instance in self.instances.iter_mut() {
            if instance.scope.ty == ComponentType::Mem.into() {
                // need to account for memory when computing offsets
                let mementries: u64 = instance
                    .scope
                    .property_val_opt("mementries")
                    .ok()
                    .flatten()
                    .unwrap();
                let memsize = instance
                    .scope
                    .property_val_opt("memwidth")
                    .ok()
                    .flatten()
                    .unwrap_or(32u64);

                let size = mementries * memsize / 8;

                if instance.offset.is_none() {
                    instance.offset = Some(next_offset);
                }
                if let Some(offset) = instance.offset {
                    next_offset = offset + size;
                }
                continue;
            }
            if instance.scope.ty != ComponentType::Reg.into()
                && instance.scope.ty != ComponentType::Mem.into()
            {
                continue;
            }
            let reg_width = instance
                .scope
                .property_val_opt("regwidth")
                .ok()
                .flatten()
                .unwrap_or(32u64);
            let access_width = instance
                .scope
                .property_val_opt("accesswidth")
                .ok()
                .flatten()
                .unwrap_or(reg_width);
            let align = if let Some(next_alignment) = instance.next_alignment {
                next_alignment
            } else if let Some(default_alignment) = default_alignment {
                default_alignment
            } else {
                match addr_mode {
                    AddressingType::Compact => access_width / 8,
                    AddressingType::RegAlign => instance.element_size(),
                    AddressingType::FullAlign => instance.total_size()?,
                }
            };
            if instance.offset.is_none() {
                if next_offset % align != 0 {
                    next_offset = ((next_offset / align) + 1) * align;
                }
                instance.offset = Some(next_offset);
            }
            if let Some(offset) = instance.offset {
                next_offset = offset + instance.total_size()?;
            }
        }

        let mut next_offset = 0;
        for instance in self.instances.iter_mut() {
            if instance.scope.ty != ComponentType::Field.into() {
                continue;
            }
            if instance.dimension_sizes.len() > 1 {
                return Err(RdlError::MultidimensionalFieldsNotSupported);
            }
            let field_width = if instance.dimension_sizes.len() == 1 {
                instance.dimension_sizes[0]
            } else {
                instance
                    .scope
                    .property_val_opt("fieldwidth")
                    .ok()
                    .flatten()
                    .unwrap_or(1u64)
            };

            if instance.offset.is_none() {
                instance.offset = Some(next_offset);
            }
            if let Some(offset) = instance.offset {
                next_offset = offset + field_width;
            }
        }
        for ty in self.types.values_mut() {
            ty.calculate_offsets()?;
        }
        for el in self.instances.iter_mut() {
            el.scope.calculate_offsets()?;
        }
        Ok(())
    }

    fn set_instance_property(
        &mut self,
        path: &[String],
        name: &str,
        value: Value,
    ) -> Result<'static, ()> {
        if let Some((head, tail)) = path.split_first() {
            let instance = self
                .instances
                .iter_mut()
                .find(|instance| instance.name == *head)
                .ok_or_else(|| {
                    RdlError::InvalidExpression(format!("unknown dynamic assignment target {head}"))
                })?;
            instance.scope.set_instance_property(tail, name, value)
        } else {
            self.properties.insert(name.to_owned(), value);
            Ok(())
        }
    }

    fn parse<'a>(
        &mut self,
        tokens: &mut TokenIter<'a>,
        parent: Option<&ParentScope<'_>>,
        parameters: Option<&ParameterScope<'_>>,
    ) -> Result<'a, ()> {
        loop {
            if self.ty == ScopeType::Root && *tokens.peek(0) == Token::EndOfFile {
                break;
            }
            if *tokens.peek(0) == Token::BraceClose {
                break;
            }

            let peek0 = tokens.peek(0).clone();
            let peek1 = tokens.peek(1).clone();
            if let Ok(component_type) = component_keyword(&peek0, &peek1) {
                if tokens.next() == Token::External {
                    let token = tokens.next();
                    if token != Token::Reg && token != Token::Mem {
                        return Err(RdlError::UnexpectedToken(token));
                    }
                }
                let type_name = if *tokens.peek(0) == Token::BraceOpen {
                    None
                } else {
                    Some(tokens.expect_identifier()?)
                };

                let template_position = (
                    tokens.current_file_path().to_path_buf(),
                    tokens.last_span().end,
                    tokens.defines(),
                );
                let pscope = if type_name.is_some() && tokens.peek(0) == &Token::Hash {
                    Some(ParameterScope {
                        parent: parameters,
                        parameters: ParameterDefinition::parse_map(tokens, parameters, None)?,
                    })
                } else {
                    None
                };
                let parameters = pscope.as_ref().or(parameters);

                let mut ty_scope = Self::new(ScopeType::Component(component_type));
                tokens.expect(Token::BraceOpen)?;
                let template = pscope.as_ref().map(|scope| ScopeTemplate {
                    parameters: scope.parameters.clone(),
                    inherited_parameters: scope
                        .parent
                        .map(ParameterScope::flatten)
                        .unwrap_or_default(),
                    path: template_position.0,
                    offset: template_position.1,
                    defines: template_position.2,
                });
                ty_scope.parse(
                    tokens,
                    Some(&ParentScope {
                        parent,
                        scope: self,
                    }),
                    parameters,
                )?;
                ty_scope.set_property_defaults(Some(&ParentScope {
                    parent,
                    scope: self,
                }));
                tokens.expect(Token::BraceClose)?;
                ty_scope.template = template;

                if let Some(type_name) = type_name {
                    if self.types.contains_key(type_name) {
                        return Err(RdlError::DuplicateTypeName(type_name));
                    }
                    self.types.insert(type_name.into(), ty_scope.clone());
                }
                if *tokens.peek(0) != Token::Semicolon {
                    if *tokens.peek(0) == Token::External {
                        tokens.next(); // ignore external keyword
                    }
                    loop {
                        let instance = Instance::parse(
                            ty_scope.clone(),
                            tokens,
                            parameters,
                            Some(&ParentScope {
                                parent,
                                scope: self,
                            }),
                        )?;
                        if self.instances.iter().any(|e| e.name == instance.name) {
                            return Err(RdlError::DuplicateInstanceName(instance.name));
                        }
                        self.instances.push(instance);
                        if *tokens.peek(0) == Token::Comma {
                            tokens.next();
                            continue;
                        }
                        break;
                    }
                }
                tokens.expect(Token::Semicolon)?;
                continue;
            }
            if *tokens.peek(0) == Token::Identifier("default") {
                tokens.next();

                let prop = PropertyAssignment::parse(tokens, parameters, |prop_name| {
                    component_meta::default_property(self.ty, prop_name)
                })?;

                #[rustfmt::skip]
                let prev_components_use_property =
                    self.instances.iter().any(|i| uses_property(i.scope.ty, prop.prop_name)) ||
                    self.types.values().any(|s| uses_property(s.ty, prop.prop_name));

                if prev_components_use_property {
                    // Error if this default value could have been used by
                    // previously defined components in this scope (the spec
                    // isn't clear whether defaults apply to previously defined
                    // components, so discourage users from doing ambiguous
                    // things).
                    return Err(RdlError::DefaultPropertiesMustBeDefinedBeforeComponents);
                }
                self.default_properties
                    .insert(prop.prop_name.into(), prop.value);
                continue;
            }

            if (is_intr_modifier(tokens.peek(0)) && *tokens.peek(1) == Token::Identifier("intr"))
                || tokens.peek(0).is_identifier()
                    && (*tokens.peek(1) == Token::Equals || *tokens.peek(1) == Token::Semicolon)
            {
                match self.ty {
                    ScopeType::Component(ComponentType::Enum) => {
                        let enum_variant_name = tokens.expect_identifier()?;
                        // Enums don't have properties
                        let mut variant_scope = Scope {
                            ty: ScopeType::Component(ComponentType::EnumVariant),
                            ..Default::default()
                        };
                        let mut value = None;
                        if *tokens.peek(0) == Token::Equals {
                            tokens.next();
                            value = Some(tokens.expect_bits()?);
                            if *tokens.peek(0) == Token::BraceOpen {
                                tokens.next();
                                variant_scope =
                                    Self::new(ScopeType::Component(ComponentType::EnumVariant));
                                variant_scope.parse(
                                    tokens,
                                    Some(&ParentScope {
                                        parent,
                                        scope: self,
                                    }),
                                    parameters,
                                )?;
                                tokens.expect(Token::BraceClose)?;
                            }
                        }
                        self.instances.push(Instance {
                            name: enum_variant_name.into(),
                            reset: value,
                            scope: variant_scope,
                            ..Default::default()
                        });

                        tokens.expect(Token::Semicolon)?;
                        continue;
                    }
                    _ => {
                        // This is a property
                        let ScopeType::Component(ty) = self.ty else {
                            return Err(RdlError::CantSetPropertyInRootScope);
                        };
                        let assignment =
                            PropertyAssignment::parse(tokens, parameters, |prop_name| {
                                component_meta::property(ty, prop_name)
                            })?;

                        if self.properties.contains_key(assignment.prop_name) {
                            return Err(RdlError::DuplicatePropertyName(assignment.prop_name));
                        }
                        self.properties
                            .insert(assignment.prop_name.into(), assignment.value);
                        continue;
                    }
                }
            }
            if tokens.peek(0).is_identifier() && *tokens.peek(1) == Token::Period
                || *tokens.peek(1) == Token::Pointer
            {
                let assignment = DynamicAssignment::parse(tokens, self, parameters)?;
                tokens.expect(Token::Semicolon)?;
                self.dynamic_assignments.push(assignment);
                continue;
            }

            let external = *tokens.peek(0) == Token::External;
            if external {
                tokens.next();
            }
            let alias_of = if *tokens.peek(0) == Token::Identifier("alias") {
                tokens.next();
                let name = tokens.expect_identifier()?;
                let primary = self
                    .instances
                    .iter()
                    .find(|instance| instance.name == name)
                    .ok_or(RdlError::UnknownInstanceName(name))?;
                if primary.scope.ty != ComponentType::Reg.into() {
                    return Err(RdlError::InvalidExpression(format!(
                        "alias primary {name} is not a register"
                    )));
                }
                Some(name.to_string())
            } else {
                None
            };
            let type_name = tokens.expect_identifier()?;

            // This is a template instantiation
            let (ty_scope, definition_parent) = lookup_typedef(self, parent, type_name)?;
            if alias_of.is_some() && ty_scope.ty != ComponentType::Reg.into() {
                return Err(RdlError::InvalidExpression(
                    "alias type is not a register".into(),
                ));
            }
            if external
                && ty_scope.ty != ComponentType::Mem.into()
                && ty_scope.ty != ComponentType::Reg.into()
            {
                return Err(RdlError::UnexpectedToken(Token::External));
            }
            let mut instance = Instance::parse(
                ty_scope.clone(),
                tokens,
                parameters,
                Some(&definition_parent),
            )?;
            instance.type_name = Some(type_name.into());
            instance.alias_of = alias_of;
            if self.instances.iter().any(|e| e.name == instance.name) {
                return Err(RdlError::DuplicateInstanceName(instance.name));
            }
            self.instances.push(instance);
            tokens.expect(Token::Semicolon)?;
        }
        Ok(())
    }

    pub fn parse_root<'a>(
        file_source: &'a dyn FileSource,
        input_files: &[PathBuf],
    ) -> std::result::Result<Self, FileParseError<'a>> {
        let mut result = Self::parse_root_internal(file_source, input_files)?;
        result
            .calculate_offsets()
            .map_err(|_| FileParseError::CouldNotCalculateOffsets)?;
        Ok(result)
    }

    fn parse_root_internal<'a>(
        file_source: &'a dyn FileSource,
        input_files: &[PathBuf],
    ) -> std::result::Result<Self, FileParseError<'a>> {
        let mut result = Self::new(ScopeType::Root);
        for path in input_files.iter() {
            let mut tokens = TokenIter::from_path(file_source, path).map_err(FileParseError::Io)?;
            match result.parse(&mut tokens, None, None) {
                Ok(()) => {}
                Err(error) => {
                    return Err(FileParseError::Parse(ParseError::new(
                        tokens.current_file_path(),
                        tokens.current_file_contents(),
                        tokens.last_span().clone(),
                        error,
                    )));
                }
            }
        }
        Ok(result)
    }
}

fn component_keyword<'a>(token: &Token<'a>, token2: &Token<'a>) -> Result<'a, ComponentType> {
    match (token, token2) {
        (Token::Field, _) => Ok(ComponentType::Field),
        (Token::External, Token::Reg) => Ok(ComponentType::Reg),
        (Token::External, Token::Mem) => Ok(ComponentType::Mem),
        (Token::Reg, _) => Ok(ComponentType::Reg),
        (Token::RegFile, _) => Ok(ComponentType::RegFile),
        (Token::AddrMap, _) => Ok(ComponentType::AddrMap),
        (Token::Signal, _) => Ok(ComponentType::Signal),
        (Token::Enum, _) => Ok(ComponentType::Enum),
        (Token::Mem, _) => Ok(ComponentType::Mem),
        (Token::Constraint, _) => Ok(ComponentType::Constraint),
        (unexpected, _) => Err(RdlError::UnexpectedToken(unexpected.clone())),
    }
}

pub struct ParameterScope<'a> {
    parent: Option<&'a ParameterScope<'a>>,
    parameters: HashMap<String, ParameterDefinition>,
}
impl ParameterScope<'_> {
    fn flatten(&self) -> HashMap<String, ParameterDefinition> {
        let mut result = self.parent.map(Self::flatten).unwrap_or_default();
        result.extend(self.parameters.clone());
        result
    }
}

#[derive(Copy, Clone)]
pub struct ParentScope<'a> {
    pub parent: Option<&'a ParentScope<'a>>,
    pub scope: &'a Scope,
}
impl<'a> ParentScope<'a> {
    pub fn instance_iter(&'a self) -> impl Iterator<Item = InstanceRef<'a>> {
        self.scope.instances.iter().map(|i| InstanceRef {
            instance: i,
            scope: ParentScope {
                parent: Some(self),
                scope: &i.scope,
            },
        })
    }
    pub fn type_iter(&'a self) -> impl Iterator<Item = (&'a str, ParentScope<'a>)> {
        self.scope.types.iter().map(|(name, scope)| {
            (
                name.as_str(),
                ParentScope {
                    parent: Some(self),
                    scope,
                },
            )
        })
    }
    pub fn lookup_typedef(&'a self, name: &'_ str) -> Option<ParentScope<'a>> {
        let mut parent = self;
        loop {
            if let Some(result) = parent.scope.types.get(name) {
                return Some(ParentScope {
                    scope: result,
                    parent: Some(parent),
                });
            }
            if let Some(new_parent) = parent.parent {
                parent = new_parent;
            } else {
                return None;
            }
        }
    }
}

fn lookup_typedef<'a, 'b>(
    mut scope: &'b Scope,
    mut parent: Option<&'b ParentScope<'_>>,
    name: &'a str,
) -> Result<'a, (&'b Scope, ParentScope<'b>)> {
    loop {
        if let Some(result) = scope.types.get(name) {
            return Ok((result, ParentScope { scope, parent }));
        }
        if let Some(parent_scope) = parent {
            scope = parent_scope.scope;
            parent = parent_scope.parent;
        } else {
            return Err(RdlError::UnknownTypeName(name));
        }
    }
}

#[derive(Copy, Clone)]
pub struct InstanceRef<'a> {
    pub instance: &'a Instance,
    pub scope: ParentScope<'a>,
}

pub fn lookup_parameter<'a, 'b>(
    parameters: Option<&'b ParameterScope<'b>>,
    name: &'a str,
) -> Result<'a, &'b Value> {
    if let Some(p) = parameters {
        if let Some(val) = p.parameters.get(name) {
            return Ok(&val.default);
        }
        return lookup_parameter(p.parent, name);
    }
    Err(RdlError::UnknownIdentifier(name))
}

pub fn lookup_parameter_of_type<'a, 'b>(
    parameters: Option<&'b ParameterScope<'b>>,
    name: &'a str,
    ty: PropertyType,
) -> Result<'a, &'b Value> {
    let value = lookup_parameter(parameters, name)?;
    if value.property_type() != ty {
        return Err(RdlError::UnexpectedPropertyType {
            expected_type: ty,
            value: value.clone(),
        });
    }
    Ok(value)
}

fn expect_number<'a>(
    i: &mut TokenIter<'a>,
    parameters: Option<&ParameterScope<'_>>,
) -> Result<'a, u64> {
    crate::expression::integer(PropertyType::U64.eval(i, parameters)?)
}

fn parse_parameter_map<'a>(
    i: &mut TokenIter<'a>,
    parameters: Option<&ParameterScope<'_>>,
    template: Option<&ScopeTemplate>,
) -> Result<'a, HashMap<String, Value>> {
    i.expect(Token::Hash)?;
    i.expect(Token::ParenOpen)?;
    if *i.peek(0) == Token::ParenClose {
        i.next();
        return Ok(HashMap::new());
    }

    let mut map: HashMap<String, Value> = HashMap::new();
    loop {
        i.expect(Token::Period)?;
        let name = i.expect_identifier()?;
        i.expect(Token::ParenOpen)?;
        let definition = template
            .and_then(|template| template.parameters.get(name))
            .ok_or_else(|| RdlError::InvalidParameter(format!("unknown parameter {name}")))?;
        let mut value = definition.ty.eval(i, parameters)?;
        if definition.ty == PropertyType::Bits {
            let Value::Bits(default) = definition.default else {
                return Err(RdlError::InvalidParameter(format!(
                    "invalid bit parameter {name}"
                )));
            };
            value = Value::Bits(Bits::new(default.w(), crate::expression::integer(value)?));
        }
        if map.insert(name.into(), value).is_some() {
            return Err(RdlError::DuplicateParameterName(name));
        }
        i.expect(Token::ParenClose)?;
        if *i.peek(0) == Token::ParenClose {
            i.next();
            return Ok(map);
        }
        i.expect(Token::Comma)?;
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Instance {
    pub name: String,
    // If this instance was instantiated from a common type, this is the name of
    // that type
    pub type_name: Option<String>,
    // [2][4] parses to vec![2, 4], which means there is an array of 2 elements,
    // where each element is an array of 4 values. In rust notation this would be [[u32; 4]; 2].
    pub dimension_sizes: Vec<u64>,
    pub reset: Option<Bits>,
    pub offset: Option<u64>,
    pub stride: Option<u64>,
    pub next_alignment: Option<u64>,
    pub scope: Scope,
    pub parameters: HashMap<String, Value>,
    pub alias_of: Option<String>,
}
impl Instance {
    pub fn element_size(&self) -> u64 {
        if let Ok(Some(w)) = self.scope.property_val_opt::<u64>("regwidth") {
            w / 8
        } else {
            // According to section 10.1 of the SystemRDL 2.0 spec, the default regwidth is 32-bits
            4
        }
    }
    pub fn total_size(&self) -> Result<'static, u64> {
        let stride = if let Some(stride) = self.stride {
            stride
        } else {
            self.element_size()
        };
        if stride < self.element_size() {
            return Err(RdlError::StrideIsLessThanElementSize);
        }
        let total_elements: u64 = self.dimension_sizes.iter().product();
        Ok(total_elements * stride)
    }
    fn parse<'a>(
        mut scope: Scope,
        i: &mut TokenIter<'a>,
        parameters: Option<&ParameterScope<'_>>,
        definition_parent: Option<&ParentScope<'_>>,
    ) -> Result<'a, Self> {
        let ScopeType::Component(component_type) = scope.ty else {
            return Err(RdlError::RootCantBeInstantiated);
        };
        let component_meta = component_meta::get_component_meta(component_type);
        if !component_meta.can_instantiate {
            return Err(RdlError::ComponentTypeCantBeInstantiated(component_type));
        }

        // check for parameters
        let specified_params = if *i.peek(0) == Token::Hash {
            parse_parameter_map(i, parameters, scope.template.as_ref())?
        } else {
            HashMap::new()
        };
        if !specified_params.is_empty() {
            let template = scope
                .template
                .as_ref()
                .ok_or_else(|| RdlError::InvalidParameter("component has no parameters".into()))?;
            let inherited = ParameterScope {
                parent: None,
                parameters: template.inherited_parameters.clone(),
            };
            let mut tokens = i
                .at_position(&template.path, template.offset, template.defines.clone())
                .map_err(|error| RdlError::InvalidParameter(error.to_string()))?;
            let definitions = ParameterDefinition::parse_map(
                &mut tokens,
                Some(&inherited),
                Some(&specified_params),
            )?;
            let parameters = ParameterScope {
                parent: Some(&inherited),
                parameters: definitions,
            };
            tokens.expect(Token::BraceOpen)?;
            let mut expanded = Scope::new(scope.ty);
            expanded.parse(&mut tokens, definition_parent, Some(&parameters))?;
            tokens.expect(Token::BraceClose)?;
            expanded.set_property_defaults(definition_parent);
            expanded.template = scope.template.clone();
            scope = expanded;
        }

        let mut result = Self {
            name: i.expect_identifier()?.to_string(),
            scope,
            parameters: specified_params,
            ..Default::default()
        };
        if component_type == ComponentType::Field && *i.peek(0) == Token::BracketOpen {
            i.next();
            let first = expect_number(i, parameters)?;
            if *i.peek(0) == Token::Colon {
                i.next();
                let lsb = expect_number(i, parameters)?;
                if first < lsb {
                    return Err(RdlError::MsbLessThanLsb);
                }
                result.dimension_sizes.push(first - lsb + 1);
                result.offset = Some(lsb);
            } else {
                result.dimension_sizes.push(first);
            }
            i.expect(Token::BracketClose)?;
        } else {
            while *i.peek(0) == Token::BracketOpen {
                i.next();
                result.dimension_sizes.push(expect_number(i, parameters)?);
                i.expect(Token::BracketClose)?;
            }
        }
        if *i.peek(0) == Token::Equals {
            i.next();
            let value = PropertyType::Bits.eval(i, parameters)?;
            result.reset = Some(match value {
                Value::Bits(bits) => bits,
                value => Bits::new(
                    result.dimension_sizes.iter().product(),
                    crate::expression::integer(value)?,
                ),
            });
        }
        if result.scope.ty == ComponentType::Reg.into()
            || result.scope.ty == ComponentType::RegFile.into()
            || result.scope.ty == ComponentType::AddrMap.into()
            || result.scope.ty == ComponentType::Mem.into()
        {
            if *i.peek(0) == Token::At {
                i.next();
                result.offset = Some(expect_number(i, parameters)?);
            }
            if *i.peek(0) == Token::PlusEqual {
                i.next();
                result.stride = Some(expect_number(i, parameters)?);
            }
            if *i.peek(0) == Token::PercentEqual {
                i.next();
                result.next_alignment = Some(expect_number(i, parameters)?);
            }
        }
        Ok(result)
    }
}

fn is_intr_modifier(token: &Token) -> bool {
    matches!(
        *token,
        Token::Identifier("posedge" | "negedge" | "bothedge" | "level" | "nonsticky" | "sticky")
    )
}

struct PropertyAssignment<'a> {
    prop_name: &'a str,
    value: Value,
}

static INTR_BOOL_PROPERTY: PropertyMeta = PropertyMeta {
    name: "intr",
    ty: PropertyType::Boolean,
    is_dynamic: true,
};
fn intr_bool_property<'a>(_name: &str) -> Result<'a, &'static PropertyMeta> {
    Ok(&INTR_BOOL_PROPERTY)
}

impl<'a> PropertyAssignment<'a> {
    fn parse(
        tokens: &mut TokenIter<'a>,
        parameters: Option<&ParameterScope<'_>>,
        meta_lookup_fn: impl Fn(&'a str) -> Result<'a, &'static PropertyMeta>,
    ) -> Result<'a, Self> {
        if is_intr_modifier(tokens.peek(0)) && *tokens.peek(1) == Token::Identifier("intr") {
            let intr_modifier = tokens.expect_identifier()?;
            // skip the bool tokens...
            PropertyAssignment::parse(tokens, parameters, intr_bool_property)?;
            return Ok(Self {
                prop_name: "intr",
                value: match intr_modifier {
                    "posedge" => InterruptType::PosEdge.into(),
                    "negedge" => InterruptType::NegEdge.into(),
                    "bothedge" => InterruptType::BothEdge.into(),
                    "level" => InterruptType::Level.into(),
                    "nonsticky" => InterruptType::NonSticky.into(),
                    "sticky" => InterruptType::Sticky.into(),
                    _ => InterruptType::Level.into(),
                },
            });
        }

        let prop_name = tokens.expect_identifier()?;
        let prop_meta = meta_lookup_fn(prop_name)?;

        let value = if *tokens.peek(0) == Token::Semicolon {
            // This must be a boolean property set to true or an intr
            if prop_meta.ty != PropertyType::Boolean
                && prop_meta.ty != PropertyType::BooleanOrReference
                && prop_meta.ty != PropertyType::FieldInterrupt
            {
                return Err(RdlError::UnexpectedPropertyType {
                    expected_type: prop_meta.ty,
                    value: true.into(),
                });
            }
            true.into()
        } else {
            tokens.expect(Token::Equals)?;
            prop_meta.ty.eval(tokens, parameters)?
        };
        tokens.expect(Token::Semicolon)?;
        Ok(Self { prop_name, value })
    }
}

#[cfg(test)]
mod tests {
    use crate::{file_source::MemFileSource, value::AccessType, EnumReference};

    use super::*;

    fn parse(text: &str) -> Scope {
        let fs = MemFileSource::from_entries(&[("test.rdl".into(), text.into())]);
        Scope::parse_root(&fs, &["test.rdl".into()]).unwrap()
    }

    #[test]
    fn parameter_overrides_elaborate_nested_layouts_resets_and_presence() {
        let scope = parse(
            r#"
            addrmap device #(longint unsigned ENDPOINTS = 14, bit TOGGLE = 1) {
                reg {
                    field {sw = rw;} endpoints[ENDPOINTS + 1:0] = ENDPOINTS;
                } status @ 0x20;
                reg {
                    field {ispresent = TOGGLE != 0; sw = rw;} visible[ENDPOINTS + 1:0] = 0;
                    field {ispresent = TOGGLE == 0; sw = r;} hidden[ENDPOINTS + 1:0] = 0;
                } toggle @ 0x34;
            };
            addrmap combo #(longint unsigned ENDPOINTS = 14) {
                device #(.ENDPOINTS(ENDPOINTS), .TOGGLE(0)) device0 @ 0;
            };
            addrmap soc {
                combo #(.ENDPOINTS(28)) usb @ 0x20000000;
                device defaults @ 0x20002000;
            };
        "#,
        );
        let soc = &scope.types["soc"];
        let overridden = &soc.instances[0].scope.instances[0].scope;
        let status = &overridden.instances[0].scope.instances[0];
        assert_eq!(status.dimension_sizes, [30]);
        assert_eq!(status.reset, Some(Bits::new(30, 28)));
        let toggle = &overridden.instances[1].scope.instances;
        assert_eq!(toggle.len(), 1);
        assert_eq!(toggle[0].name, "hidden");
        assert_eq!(toggle[0].dimension_sizes, [30]);
        let default = &soc.instances[1].scope.instances[0].scope.instances[0];
        assert_eq!(default.dimension_sizes, [16]);
        assert_eq!(default.reset, Some(Bits::new(16, 14)));
        assert_eq!(
            scope.types["device"].instances[1].scope.instances[0].name,
            "visible"
        );
    }

    #[test]
    fn parameter_templates_keep_lexical_types_and_parameters() {
        let scope = parse(
            r#"
            addrmap outer #(longint unsigned WIDTH = 8) {
                reg word {field {sw = r;} bits[WIDTH - 1:0] = WIDTH;};
                addrmap nested #(longint unsigned OFFSET = 0) {
                    word value @ OFFSET;
                };
                addrmap caller {
                    reg word {field {} different[0:0];};
                    nested #(.OFFSET(4)) inner @ 0;
                } instance @ 0;
            };
            addrmap soc {outer #(.WIDTH(16)) usb @ 0;};
        "#,
        );
        let outer = &scope.types["soc"].instances[0].scope;
        let word = &outer.instances[0].scope.instances[0].scope.instances[0];
        assert_eq!(word.offset, Some(4));
        assert_eq!(word.scope.instances[0].name, "bits");
        assert_eq!(word.scope.instances[0].dimension_sizes, [16]);
        assert_eq!(word.scope.instances[0].reset, Some(Bits::new(16, 16)));
    }

    #[test]
    fn overrides_recompute_dependent_defaults_and_preserve_bit_width() {
        let scope = parse(
            r#"
            addrmap device #(longint unsigned COUNT = 14,
                             longint unsigned WIDTH = COUNT + 2, bit FLAGS = 8'hff) {
                reg {field {} bitmap[WIDTH - 1:0] = FLAGS;} status @ 0;
            };
            addrmap soc {
                device #(.COUNT(28), .FLAGS(16'h1234)) first @ 0;
                device #(.COUNT(28), .WIDTH(8)) second @ 0x100;
            };
        "#,
        );
        let instances = &scope.types["soc"].instances;
        let first = &instances[0].scope.instances[0].scope.instances[0];
        assert_eq!(first.dimension_sizes, [30]);
        assert_eq!(first.reset.unwrap().val(), 0x34);
        assert_eq!(
            instances[0].parameters["FLAGS"],
            Value::Bits(Bits::new(8, 0x34))
        );
        assert_eq!(
            instances[1].scope.instances[0].scope.instances[0].dimension_sizes,
            [8]
        );
    }

    #[test]
    fn aliases_external_memories_and_dynamic_assignments() {
        let scope = parse(
            r#"
            mem packet #(longint unsigned ENTRIES = 4) {
                memwidth = 64; mementries = ENTRIES; sw = rw;
            };
            addrmap soc {
                reg status_t {field {sw = rw; onwrite = woclr;} pending[29:0] = 0;};
                status_t status @ 0x20;
                alias status status_t set_status @ 0x28;
                set_status.pending->onwrite = woset;
                external packet #(.ENTRIES(8192)) buffer @ 0x30000000;
            };
        "#,
        );
        let instances = &scope.types["soc"].instances;
        assert_eq!(instances[1].alias_of.as_deref(), Some("status"));
        assert_eq!(
            instances[0].scope.instances[0].scope.properties["onwrite"],
            Value::OnWriteType(crate::OnWriteType::WoClr)
        );
        assert_eq!(
            instances[1].scope.instances[0].scope.properties["onwrite"],
            Value::OnWriteType(crate::OnWriteType::WoSet)
        );
        assert_eq!(
            instances[2]
                .scope
                .property_val::<u64>("mementries")
                .unwrap(),
            8192
        );
        assert_eq!(
            instances[2].scope.property_val::<u64>("memwidth").unwrap(),
            64
        );
    }

    #[test]
    fn invalid_parameter_overrides_and_aliases_are_rejected() {
        for instance in [
            "device #(.UNKNOWN(1)) instance;",
            "device #(.COUNT(1), .COUNT(2)) instance;",
            "device #(.COUNT(\"wrong\")) instance;",
            "device #(.FLAG(\"wrong\")) instance;",
            "alias absent word instance;",
            "alias memory word instance;",
            "word status; alias status device instance;",
        ] {
            let source = format!(
                r#"
                addrmap device #(longint unsigned COUNT = 14, bit FLAG = 1) {{}};
                reg word {{field {{}} value;}};
                mem {{memwidth = 32; mementries = 4;}} memory;
                {instance}
            "#
            );
            let fs = MemFileSource::from_entries(&[("test.rdl".into(), source)]);
            assert!(
                Scope::parse_root(&fs, &["test.rdl".into()]).is_err(),
                "{instance}"
            );
        }
    }

    #[test]
    fn test_scope_def() {
        let fs = MemFileSource::from_entries(&[(
            "main.rdl".into(),
            r#"
            field {} some_field;
            field a_field_ty {};
        "#
            .into(),
        )]);

        let root_scope = Scope::parse_root_internal(&fs, &["main.rdl".into()]).unwrap();
        assert_eq!(
            Scope {
                ty: ScopeType::Root,
                types: HashMap::from([(
                    "a_field_ty".into(),
                    Scope {
                        ty: ScopeType::Component(ComponentType::Field),
                        ..Default::default()
                    }
                ),]),
                instances: vec![Instance {
                    name: "some_field".into(),
                    scope: Scope {
                        ty: ScopeType::Component(ComponentType::Field),
                        ..Default::default()
                    },
                    ..Default::default()
                }],
                ..Default::default()
            },
            root_scope
        );
    }
    #[test]
    fn test_type_instantiation() {
        let fs = MemFileSource::from_entries(&[(
            "main.rdl".into(),
            r#"
            field a_field_ty {desc = "Hello";};
            a_field_ty my_field;
        "#
            .into(),
        )]);

        let root_scope = Scope::parse_root_internal(&fs, &["main.rdl".into()]).unwrap();
        assert_eq!(
            Scope {
                ty: ScopeType::Root,
                types: HashMap::from([(
                    "a_field_ty".into(),
                    Scope {
                        ty: ScopeType::Component(ComponentType::Field),
                        properties: HashMap::from([("desc".into(), "Hello".into())]),
                        ..Default::default()
                    }
                ),]),
                instances: vec![Instance {
                    name: "my_field".into(),
                    type_name: Some("a_field_ty".into()),
                    scope: Scope {
                        ty: ScopeType::Component(ComponentType::Field),
                        properties: HashMap::from([("desc".into(), "Hello".into())]),
                        ..Default::default()
                    },
                    ..Default::default()
                }],
                ..Default::default()
            },
            root_scope
        );
    }

    #[test]
    fn test_stuff() {
        let fs = MemFileSource::from_entries(&[(
            "main.rdl".into(),
            r#"
            addrmap {
                addressing = compact;
                lsb0 = true;

                default regwidth = 32;

                reg {
                    name = "Status register";
                    desc = "Status of the peripheral";
                    field {sw = r; hw = w;} READY = 1'b0;
                    field {hwclr; sw = r; hw = w;} VALID = 1'b0;
                    field {sw = rw; hw = rw;} ID[23:16] = 0xd2;
                } STATUS;

                reg {
                    enum mode_t {
                        ALERT;
                        TIRED = 2'd1;
                        SLEEPING = 2'd2 {
                            desc = "Power consumption is minimal";
                        };
                    };
                    field {encode=mode_t;} MODE = 4'hf;
                } MODE @0x1000;
            } my_addrmap;
        "#
            .into(),
        )]);

        let root_scope = Scope::parse_root_internal(&fs, &["main.rdl".into()]).unwrap();

        assert_eq!(
            Scope {
                ty: ScopeType::Root,
                instances: vec![Instance {
                    name: "my_addrmap".into(),
                    scope: Scope {
                        ty: ScopeType::Component(ComponentType::AddrMap),
                        properties: HashMap::from([
                            ("addressing".into(), AddressingType::Compact.into()),
                            ("lsb0".into(), true.into()),
                        ]),
                        default_properties: HashMap::from([("regwidth".into(), 32.into()),]),
                        instances: vec![
                            Instance {
                                name: "STATUS".into(),
                                scope: Scope {
                                    ty: ScopeType::Component(ComponentType::Reg),
                                    properties: HashMap::from([
                                        ("name".into(), "Status register".into()),
                                        ("desc".into(), "Status of the peripheral".into()),
                                        ("regwidth".into(), 32.into()),
                                    ]),
                                    instances: vec![
                                        Instance {
                                            name: "READY".into(),
                                            reset: Some(Bits::new(1, 0)),
                                            scope: Scope {
                                                ty: ScopeType::Component(ComponentType::Field),
                                                properties: HashMap::from([
                                                    ("sw".into(), AccessType::R.into()),
                                                    ("hw".into(), AccessType::W.into()),
                                                ]),
                                                ..Default::default()
                                            },
                                            ..Default::default()
                                        },
                                        Instance {
                                            name: "VALID".into(),
                                            reset: Some(Bits::new(1, 0)),
                                            scope: Scope {
                                                ty: ScopeType::Component(ComponentType::Field),
                                                properties: HashMap::from([
                                                    ("hwclr".into(), true.into()),
                                                    ("sw".into(), AccessType::R.into()),
                                                    ("hw".into(), AccessType::W.into()),
                                                ]),
                                                ..Default::default()
                                            },
                                            ..Default::default()
                                        },
                                        Instance {
                                            name: "ID".into(),
                                            reset: Some(Bits::new(8, 0xd2)),
                                            dimension_sizes: vec![8],
                                            offset: Some(16),
                                            scope: Scope {
                                                ty: ScopeType::Component(ComponentType::Field),
                                                properties: HashMap::from([
                                                    ("sw".into(), AccessType::Rw.into()),
                                                    ("hw".into(), AccessType::Rw.into()),
                                                ]),
                                                ..Default::default()
                                            },
                                            ..Default::default()
                                        },
                                    ],
                                    ..Default::default()
                                },
                                ..Default::default()
                            },
                            Instance {
                                name: "MODE".into(),
                                offset: Some(0x1000),
                                scope: Scope {
                                    ty: ComponentType::Reg.into(),
                                    properties: HashMap::from([("regwidth".into(), 32.into()),]),
                                    types: HashMap::from([(
                                        "mode_t".into(),
                                        Scope {
                                            ty: ScopeType::Component(ComponentType::Enum),
                                            instances: vec![
                                                Instance {
                                                    name: "ALERT".into(),
                                                    scope: Scope {
                                                        ty: ComponentType::EnumVariant.into(),
                                                        ..Default::default()
                                                    },
                                                    ..Default::default()
                                                },
                                                Instance {
                                                    name: "TIRED".into(),
                                                    reset: Some(Bits::new(2, 1)),
                                                    scope: Scope {
                                                        ty: ComponentType::EnumVariant.into(),
                                                        ..Default::default()
                                                    },
                                                    ..Default::default()
                                                },
                                                Instance {
                                                    name: "SLEEPING".into(),
                                                    reset: Some(Bits::new(2, 2)),
                                                    scope: Scope {
                                                        ty: ComponentType::EnumVariant.into(),
                                                        properties: HashMap::from([(
                                                            "desc".into(),
                                                            "Power consumption is minimal".into()
                                                        ),]),
                                                        ..Default::default()
                                                    },
                                                    ..Default::default()
                                                },
                                            ],
                                            ..Default::default()
                                        }
                                    )]),
                                    instances: vec![Instance {
                                        name: "MODE".into(),
                                        reset: Some(Bits::new(4, 0xf)),
                                        scope: Scope {
                                            ty: ScopeType::Component(ComponentType::Field),
                                            properties: HashMap::from([(
                                                "encode".into(),
                                                EnumReference("mode_t".into()).into()
                                            ),]),
                                            ..Default::default()
                                        },
                                        ..Default::default()
                                    },],
                                    ..Default::default()
                                },
                                ..Default::default()
                            }
                        ],
                        ..Default::default()
                    },
                    ..Default::default()
                }],
                ..Default::default()
            },
            root_scope
        );
    }
}

// Licensed under the Apache-2.0 license.

//! Contains the winnow parser production rules for the SystemRDL language.

use crate::ast::*;
use crate::lexer::Lexer;
use crate::token::TokenKind;
use crate::token::{Token, Tokens};
use winnow::combinator::{alt, fail, opt, preceded, repeat, separated, terminated};
use winnow::error::ParserError;
use winnow::stream::Stream;
use winnow::{Parser, Result};

fn identifier(i: &mut Tokens) -> Result<String> {
    match i.next_token() {
        Some(Token {
            kind: TokenKind::Identifier(id),
            ..
        }) => Ok(id.to_string()),
        _ => fail.parse_next(i)?,
    }
}

// component_type ::=
//     component_primary_type
//   | signal
// component_primary_type ::= addrmap | regfile | reg | field | mem
fn component_type(i: &mut Tokens<'_>) -> Result<ComponentType> {
    let ct = match i.next_token() {
        Some(Token {
            kind: TokenKind::Reg,
            ..
        }) => ComponentType::Reg,
        Some(Token {
            kind: TokenKind::RegFile,
            ..
        }) => ComponentType::RegFile,
        Some(Token {
            kind: TokenKind::Signal,
            ..
        }) => ComponentType::Signal,
        Some(Token {
            kind: TokenKind::Mem,
            ..
        }) => ComponentType::Mem,
        Some(Token {
            kind: TokenKind::Field,
            ..
        }) => ComponentType::Field,
        Some(Token {
            kind: TokenKind::AddrMap,
            ..
        }) => ComponentType::AddrMap,
        _ => fail.parse_next(i)?,
    };
    Ok(ct)
}

// component_primary_type ::= addrmap | regfile | reg | field | mem
fn component_primary_type(i: &mut Tokens<'_>) -> Result<ComponentType> {
    let ct = match i.next_token() {
        Some(Token {
            kind: TokenKind::Reg,
            ..
        }) => ComponentType::Reg,
        Some(Token {
            kind: TokenKind::RegFile,
            ..
        }) => ComponentType::RegFile,
        Some(Token {
            kind: TokenKind::Mem,
            ..
        }) => ComponentType::Mem,
        Some(Token {
            kind: TokenKind::Field,
            ..
        }) => ComponentType::Field,
        Some(Token {
            kind: TokenKind::AddrMap,
            ..
        }) => ComponentType::AddrMap,
        _ => fail.parse_next(i)?,
    };
    Ok(ct)
}

// signing ::= unsigned
fn signing(i: &mut Tokens<'_>) -> Result<()> {
    TokenKind::Unsigned.parse_next(i)?;
    Ok(())
}

// integer_vector_type ::= bit
fn integer_type_bit(i: &mut Tokens<'_>) -> Result<IntegerType> {
    TokenKind::Bit.parse_next(i).map(|_| IntegerType::Bit)
}

// integer_atom_type ::= longint
fn integer_type_longint(i: &mut Tokens<'_>) -> Result<IntegerType> {
    TokenKind::Longint
        .parse_next(i)
        .map(|_| IntegerType::Longint)
}

// simple_type ::= integer_type
// integer_type ::=
//     integer_vector_type
//   | integer_atom_type
fn simple_type(i: &mut Tokens<'_>) -> Result<IntegerType> {
    alt((integer_type_bit, integer_type_longint, fail)).parse_next(i)
}

// basic_data_type ::=
//     simple_type [ signing ]
fn basic_data_type_simple_type_signing(i: &mut Tokens<'_>) -> Result<BasicDataType> {
    let (st, s) = (simple_type, opt(signing)).parse_next(i)?;
    match s {
        Some(_) => Ok(BasicDataType::UnsignedIntegerType(st)),
        _ => Ok(BasicDataType::IntegerType(st)),
    }
}

// basic_data_type ::=
//   | string
fn basic_data_type_string(i: &mut Tokens<'_>) -> Result<BasicDataType> {
    let _ = TokenKind::String.parse_next(i)?;
    Ok(BasicDataType::String)
}

// basic_data_type ::=
//   | boolean
fn basic_data_type_boolean(i: &mut Tokens<'_>) -> Result<BasicDataType> {
    let _ = TokenKind::Boolean.parse_next(i)?;
    Ok(BasicDataType::Boolean)
}

// basic_data_type ::=
//   | id
fn basic_data_type_id(i: &mut Tokens<'_>) -> Result<BasicDataType> {
    let x = identifier.parse_next(i)?;
    Ok(BasicDataType::Identifier(x))
}

// basic_data_type ::=
//     simple_type [ signing ]
//   | string
//   | boolean
//   | id
fn basic_data_type(i: &mut Tokens<'_>) -> Result<BasicDataType> {
    alt((
        basic_data_type_simple_type_signing,
        basic_data_type_string,
        basic_data_type_boolean,
        basic_data_type_id,
        fail,
    ))
    .parse_next(i)
}

// data_type ::=
//   | accesstype
fn data_type_basic_data_type(i: &mut Tokens<'_>) -> Result<DataType> {
    basic_data_type.parse_next(i).map(DataType::BasicDataType)
}

// data_type ::=
//   | accesstype
fn data_type_accesstype(i: &mut Tokens<'_>) -> Result<DataType> {
    TokenKind::AccessType
        .parse_next(i)
        .map(|_| DataType::AccessType)
}

// data_type ::=
//   | addressingtype
fn data_type_adressingtype(i: &mut Tokens<'_>) -> Result<DataType> {
    TokenKind::AddressingType
        .parse_next(i)
        .map(|_| DataType::AddressingType)
}

// data_type ::=
//   | onreadtype
fn data_type_onreadtype(i: &mut Tokens<'_>) -> Result<DataType> {
    TokenKind::OnReadType
        .parse_next(i)
        .map(|_| DataType::OnReadType)
}

// data_type ::=
//   | onwritetype
fn data_type_onwritetype(i: &mut Tokens<'_>) -> Result<DataType> {
    TokenKind::OnWriteType
        .parse_next(i)
        .map(|_| DataType::OnWriteType)
}

// data_type ::=
//     basic_data_type
//   | accesstype
//   | addressingtype
//   | onreadtype
//   | onwritetype
fn data_type(i: &mut Tokens<'_>) -> Result<DataType> {
    alt((
        data_type_basic_data_type,
        data_type_accesstype,
        data_type_adressingtype,
        data_type_onreadtype,
        data_type_onwritetype,
        fail,
    ))
    .parse_next(i)
}

// array_type ::= [ ]
fn array_type(i: &mut Tokens<'_>) -> Result<ArrayType> {
    let _ = (TokenKind::BracketOpen, TokenKind::BracketClose).parse_next(i)?;
    Ok(ArrayType {})
}

// param_def_elem ::= data_type id [ array_type ] [ = constant_expression ]
fn param_def_elem(i: &mut Tokens<'_>) -> Result<ParamDefElem> {
    let (dt, id, at, expr) = (
        data_type,
        identifier,
        opt(array_type),
        opt(preceded(TokenKind::Equals, constant_expr)),
    )
        .parse_next(i)?;
    Ok(ParamDefElem::ParamDefElem(dt, id, at, expr))
}

// param_def ::= # ( param_def_elem { , param_def_elem } )
fn param_def(i: &mut Tokens<'_>) -> Result<ParamDef> {
    let (_, _, params, _) = (
        TokenKind::Hash,
        TokenKind::ParenOpen,
        separated(1.., param_def_elem, TokenKind::Comma),
        TokenKind::ParenClose,
    )
        .parse_next(i)?;
    Ok(ParamDef::Params(params))
}

// component_body ::= { { component_body_elem } }
fn component_body(i: &mut Tokens<'_>) -> Result<ComponentBody> {
    let (_, elements, _) = (
        TokenKind::BraceOpen,
        repeat(0.., component_body_elem),
        TokenKind::BraceClose,
    )
        .parse_next(i)?;

    Ok(ComponentBody { elements })
}

fn explicit_encode_assignment(i: &mut Tokens<'_>) -> Result<String> {
    let (_, _, id) = (TokenKind::Encode, TokenKind::Equals, identifier).parse_next(i)?;
    Ok(id)
}

// prop_assignment_lhs ::=
//     prop_keyword
//   | id
fn prop_assignment_lhs(i: &mut Tokens<'_>) -> Result<IdentityOrPropKeyword> {
    id_or_prop_keyword.parse_next(i)
}

// precedencetype_literal ::= hw | sw
fn precedence_type(i: &mut Tokens<'_>) -> Result<PrecedenceType> {
    match i.next_token() {
        Some(Token {
            kind: TokenKind::PrecedenceTypeLiteral(x),
            ..
        }) => Ok(*x),
        _ => fail.parse_next(i),
    }
}

// prop_assignment_rhs ::=
//     constant_expression
//   | precedencetype_literal
fn prop_assignment_rhs(i: &mut Tokens<'_>) -> Result<PropAssignmentRhs> {
    if let Some(x) = opt(constant_expr).parse_next(i)? {
        Ok(PropAssignmentRhs::ConstantExpr(x))
    } else if let Some(x) = opt(precedence_type).parse_next(i)? {
        Ok(PropAssignmentRhs::PrecedenceType(x))
    } else {
        fail.parse_next(i)
    }
}

// explicit_prop_assignment ::=
//     prop_assignment_lhs [ = prop_assignment_rhs ]
//   | explicit_encode_assignment
fn explicit_prop_assignment(i: &mut Tokens<'_>) -> Result<ExplicitPropertyAssignment> {
    if let Some((lhs, rhs)) = opt((
        prop_assignment_lhs,
        opt(preceded(TokenKind::Equals, prop_assignment_rhs)),
    ))
    .parse_next(i)?
    {
        Ok(ExplicitPropertyAssignment::Assignment(lhs, rhs))
    } else if let Some(id) = opt(explicit_encode_assignment).parse_next(i)? {
        Ok(ExplicitPropertyAssignment::EncodeAssignment(id))
    } else {
        fail.parse_next(i)
    }
}

// enum_property_assignment ::= { { explicit_prop_assignment ; } }
fn enum_property_assignment(i: &mut Tokens<'_>) -> Result<Vec<ExplicitPropertyAssignment>> {
    let (_, assignments, _) = (
        TokenKind::BraceOpen,
        repeat(
            0..,
            terminated(explicit_prop_assignment, TokenKind::Semicolon),
        ),
        TokenKind::BraceClose,
    )
        .parse_next(i)?;
    Ok(assignments)
}

// enum_entry ::= id [ = constant_expression ] [ enum_property_assignment ] ;
fn enum_entry(i: &mut Tokens<'_>) -> Result<EnumEntry> {
    let (id, expr, props, _) = (
        identifier,
        opt((TokenKind::Equals, constant_expr)),
        opt(enum_property_assignment),
        TokenKind::Semicolon,
    )
        .parse_next(i)?;
    Ok(EnumEntry {
        id,
        expr: expr.map(|(_, expr)| expr),
        property_assignments: props.unwrap_or_default(),
    })
}

// enum_body ::= { enum_entry { enum_entry } }
fn enum_body(i: &mut Tokens<'_>) -> Result<Vec<EnumEntry>> {
    let (_, elements, _) = (
        TokenKind::BraceOpen,
        repeat(1.., enum_entry),
        TokenKind::BraceClose,
    )
        .parse_next(i)?;
    Ok(elements)
}

// enum_def ::= enum id enum_body ;
fn enum_def(i: &mut Tokens<'_>) -> Result<EnumDef> {
    let (_, id, body, _) =
        (TokenKind::Enum, identifier, enum_body, TokenKind::Semicolon).parse_next(i)?;
    Ok(EnumDef { id, body })
}

// struct_type ::=
//     data_type
//   | component_type
fn struct_type(i: &mut Tokens<'_>) -> Result<StructType> {
    if let Some(data_type) = opt(data_type).parse_next(i)? {
        Ok(StructType::DataType(data_type))
    } else if let Some(component_type) = opt(component_type).parse_next(i)? {
        Ok(StructType::ComponentType(component_type))
    } else {
        fail.parse_next(i)
    }
}

// struct_elem ::= struct_type id [ array_type ] ;
fn struct_elem(i: &mut Tokens<'_>) -> Result<StructElem> {
    let (struct_type, id, array_type, _) = (
        struct_type,
        identifier,
        opt(array_type),
        TokenKind::Semicolon,
    )
        .parse_next(i)?;
    Ok(StructElem {
        struct_type,
        id,
        array_type,
    })
}

// struct_body ::= { { struct_elem } }
fn struct_body(i: &mut Tokens<'_>) -> Result<Vec<StructElem>> {
    let (_, elements, _) = (
        TokenKind::BraceOpen,
        repeat(0.., struct_elem),
        TokenKind::BraceClose,
    )
        .parse_next(i)?;
    Ok(elements)
}

// struct_def ::= [ abstract ] struct id [ : id ] struct_body ;
fn struct_def(i: &mut Tokens<'_>) -> Result<StructDef> {
    let (_, _, id, base, body, _) = (
        opt(TokenKind::Abstract),
        TokenKind::Struct,
        identifier,
        opt((TokenKind::Colon, identifier)),
        struct_body,
        TokenKind::Semicolon,
    )
        .parse_next(i)?;
    Ok(StructDef {
        id,
        base: base.map(|x| x.1),
        body,
    })
}

// constraint_lhs ::=
//     this
//  | instance_ref
fn constraint_lhs(i: &mut Tokens<'_>) -> Result<ConstraintLhs> {
    if opt(TokenKind::This).parse_next(i)?.is_some() {
        Ok(ConstraintLhs::This)
    } else if let Some(iref) = opt(instance_ref).parse_next(i)? {
        Ok(ConstraintLhs::InstanceRef(iref))
    } else {
        fail.parse_next(i)
    }
}

// constraint_prop_assignment ::= id = constant_expression
fn constraint_prop_assignment(i: &mut Tokens<'_>) -> Result<ConstraintPropAssignment> {
    let (id, _, expr) = (identifier, TokenKind::Equals, constant_expr).parse_next(i)?;
    Ok(ConstraintPropAssignment { id, expr })
}

// constraint_value ::=
//     constant_expression
//   | [ constant_expression : constant_expression ]
fn constraint_value(i: &mut Tokens<'_>) -> Result<ConstraintValue> {
    if let Some(x) = opt(constant_expr).parse_next(i)? {
        Ok(ConstraintValue::ConstantExpr(x))
    } else if let Some((_, a, _, b, _)) = opt((
        TokenKind::BracketOpen,
        constant_expr,
        TokenKind::Colon,
        constant_expr,
        TokenKind::BracketClose,
    ))
    .parse_next(i)?
    {
        return Ok(ConstraintValue::Range(a, b));
    } else {
        fail.parse_next(i)
    }
}

// constraint_values ::= constraint_value { , constraint_value }
fn constraint_values(i: &mut Tokens<'_>) -> Result<Vec<ConstraintValue>> {
    separated(1.., constraint_value, TokenKind::Comma).parse_next(i)
}

// constraint_elem ::=
//     constant_expression
//   | constraint_prop_assignment
//   | constraint_lhs inside { constraint_values }
//   | constraint_lhs inside id
fn constraint_elem(i: &mut Tokens<'_>) -> Result<ConstraintElem> {
    if let Some(x) = opt(constant_expr).parse_next(i)? {
        Ok(ConstraintElem::ConstantExpr(x))
    } else if let Some(x) = opt(constraint_prop_assignment).parse_next(i)? {
        Ok(ConstraintElem::ConstraintPropAssignment(x))
    } else if let Some((lhs, _, _, values, _)) = opt((
        constraint_lhs,
        TokenKind::Inside,
        TokenKind::BracketOpen,
        constraint_values,
        TokenKind::BracketClose,
    ))
    .parse_next(i)?
    {
        Ok(ConstraintElem::ConstraintInsideValues(lhs, values))
    } else if let Some((lhs, _, id)) =
        opt((constraint_lhs, TokenKind::Inside, identifier)).parse_next(i)?
    {
        Ok(ConstraintElem::ConstraintInsideId(lhs, id))
    } else {
        fail.parse_next(i)
    }
}

// constraint_body ::= { { constraint_elem ; } }
fn constraint_body(i: &mut Tokens<'_>) -> Result<ConstraintBody> {
    let (_, elements, _) = (
        TokenKind::BraceOpen,
        repeat(0.., terminated(constraint_elem, TokenKind::Semicolon)),
        TokenKind::BraceClose,
    )
        .parse_next(i)?;
    Ok(ConstraintBody { elements })
}

// constraint_insts ::= id { , id }
fn constraint_insts(i: &mut Tokens<'_>) -> Result<Vec<String>> {
    separated(1.., identifier, TokenKind::Comma).parse_next(i)
}

// constraint_def_exp ::= id constraint_body [ constraint_insts ]
fn constraint_def_exp(i: &mut Tokens<'_>) -> Result<ConstraintDef> {
    let (id, body, insts) = (identifier, constraint_body, opt(constraint_insts)).parse_next(i)?;
    Ok(ConstraintDef::Exp(id, body, insts.unwrap_or_default()))
}

// constraint_def_anon ::= constraint_body constraint_insts
fn constraint_def_anon(i: &mut Tokens<'_>) -> Result<ConstraintDef> {
    let (body, insts) = (constraint_body, constraint_insts).parse_next(i)?;
    Ok(ConstraintDef::Anon(body, insts))
}

// constraint_def ::=
//     constraint constraint_def_exp ;
//   | constraint constraint_def_anon ;
fn constraint_def(i: &mut Tokens<'_>) -> Result<ConstraintDef> {
    preceded(
        TokenKind::Constraint,
        terminated(
            alt((constraint_def_exp, constraint_def_anon)),
            TokenKind::Semicolon,
        ),
    )
    .parse_next(i)
}

// component_inst_alias ::= alias id
fn component_inst_alias(i: &mut Tokens<'_>) -> Result<ComponentInstAlias> {
    preceded(TokenKind::Alias, identifier)
        .parse_next(i)
        .map(|id| ComponentInstAlias { id })
}

// explicit_component_inst ::= [ component_inst_type ] [ component_inst_alias ] id component_insts ;
fn explicit_component_inst(i: &mut Tokens<'_>) -> Result<ExplicitComponentInst> {
    let (component_inst_type, component_inst_alias, id, component_insts) = terminated(
        (
            opt(component_inst_type),
            opt(component_inst_alias),
            identifier,
            component_insts,
        ),
        TokenKind::Semicolon,
    )
    .parse_next(i)?;

    Ok(ExplicitComponentInst {
        component_inst_type,
        component_inst_alias,
        component_name: id,
        component_insts,
    })
}

// prop_mod ::= posedge | negedge | bothedge | level | nonsticky
fn prop_mod(i: &mut Tokens<'_>) -> Result<PropMod> {
    match i.next_token() {
        Some(Token {
            kind: TokenKind::PosEdge,
            ..
        }) => Ok(PropMod::PosEdge),
        Some(Token {
            kind: TokenKind::NegEdge,
            ..
        }) => Ok(PropMod::NegEdge),
        Some(Token {
            kind: TokenKind::BothEdge,
            ..
        }) => Ok(PropMod::BothEdge),
        Some(Token {
            kind: TokenKind::Level,
            ..
        }) => Ok(PropMod::Level),
        Some(Token {
            kind: TokenKind::NonSticky,
            ..
        }) => Ok(PropMod::NonSticky),
        _ => fail.parse_next(i),
    }
}

// explicit_prop_modifier ::= prop_mod id
fn explicit_prop_modifier(i: &mut Tokens<'_>) -> Result<ExplicitPropModifier> {
    let (prop_mod, id) = (prop_mod, identifier).parse_next(i)?;
    Ok(ExplicitPropModifier { prop_mod, id })
}

// default
fn default(i: &mut Tokens<'_>) -> Result<DefaultKeyword> {
    TokenKind::Default.parse_next(i).map(|_| DefaultKeyword {})
}

// explicit_or_default_prop_assignment ::=
//     [ default ] explicit_prop_modifier ;
fn explicit_or_default_prop_assignment_explicit_prop_modifier(
    i: &mut Tokens<'_>,
) -> Result<ExplicitOrDefaultPropAssignment> {
    let (default, explicit_prop_modifier) =
        terminated((opt(default), explicit_prop_modifier), TokenKind::Semicolon).parse_next(i)?;
    Ok(ExplicitOrDefaultPropAssignment::ExplicitPropModifier(
        default,
        explicit_prop_modifier,
    ))
}

// explicit_or_default_prop_assignment ::=
//     [ default ] explicit_prop_assignment ;
fn explicit_or_default_prop_assignment_explicit_prop_assignment(
    i: &mut Tokens<'_>,
) -> Result<ExplicitOrDefaultPropAssignment> {
    let (default, explicit_prop_assignment) = terminated(
        (opt(default), explicit_prop_assignment),
        TokenKind::Semicolon,
    )
    .parse_next(i)?;
    Ok(ExplicitOrDefaultPropAssignment::ExplicitPropAssignment(
        default,
        explicit_prop_assignment,
    ))
}

// explicit_or_default_prop_assignment ::=
//     [ default ] explicit_prop_modifier ;
//   | [ default ] explicit_prop_assignment ;
fn explicit_or_default_prop_assignment(i: &mut Tokens<'_>) -> Result<PropertyAssignment> {
    alt((
        explicit_or_default_prop_assignment_explicit_prop_modifier,
        explicit_or_default_prop_assignment_explicit_prop_assignment,
        fail,
    ))
    .parse_next(i)
    .map(PropertyAssignment::ExplicitOrDefaultPropAssignment)
}

// prop_ref ::=
//     instance_ref -> prop_keyword
//   | instance_ref -> id
fn prop_ref(i: &mut Tokens<'_>) -> Result<PropRef> {
    let (iref, id_or_prop) = (
        terminated(instance_ref, TokenKind::Pointer),
        id_or_prop_keyword,
    )
        .parse_next(i)?;
    Ok(PropRef { iref, id_or_prop })
}

// post_encode_assignment ::= instance_ref -> encode = id
fn post_encode_assignment(i: &mut Tokens<'_>) -> Result<PostEncodeAssignment> {
    let (iref, _, _, _, id) = (
        instance_ref,
        TokenKind::Pointer,
        TokenKind::Encode,
        TokenKind::Equals,
        identifier,
    )
        .parse_next(i)?;
    Ok(PostEncodeAssignment { iref, id })
}

// post_prop_assignment ::=
//     prop_ref [ = prop_assignment_rhs ] ;
fn post_prop_assignment_prop_ref(i: &mut Tokens<'_>) -> Result<PostPropAssignment> {
    let rhs = opt(preceded(TokenKind::Equals, prop_assignment_rhs));
    let (prop_ref, rhs) = terminated((prop_ref, rhs), TokenKind::Semicolon).parse_next(i)?;
    Ok(PostPropAssignment::PropRef(prop_ref, rhs))
}

// post_prop_assignment ::=
//   | post_encode_assignment ;
fn post_prop_assignment_post_encode_assignment(i: &mut Tokens<'_>) -> Result<PostPropAssignment> {
    let post_encode_assignment =
        terminated(post_encode_assignment, TokenKind::Semicolon).parse_next(i)?;

    Ok(PostPropAssignment::PostEncodeAssignment(
        post_encode_assignment,
    ))
}
// post_prop_assignment ::=
//     prop_ref [ = prop_assignment_rhs ] ;
//   | post_encode_assignment ;
fn post_prop_assignment(i: &mut Tokens<'_>) -> Result<PropertyAssignment> {
    alt((
        post_prop_assignment_prop_ref,
        post_prop_assignment_post_encode_assignment,
        fail,
    ))
    .parse_next(i)
    .map(PropertyAssignment::PostPropAssignment)
}

// property_assignment ::=
//     explicit_or_default_prop_assignment
//   | post_prop_assignment
fn property_assignment(i: &mut Tokens<'_>) -> Result<PropertyAssignment> {
    alt((
        explicit_or_default_prop_assignment,
        post_prop_assignment,
        fail,
    ))
    .parse_next(i)
}

// component_body_elem ::=
//     component_def
fn component_body_elem_component_def(i: &mut Tokens<'_>) -> Result<ComponentBodyElem> {
    component_def
        .parse_next(i)
        .map(ComponentBodyElem::ComponentDef)
}

// component_body_elem ::=
//   | enum_def
fn component_body_elem_enum_def(i: &mut Tokens<'_>) -> Result<ComponentBodyElem> {
    enum_def.parse_next(i).map(ComponentBodyElem::EnumDef)
}

// component_body_elem ::=
//   | struct_def
fn component_body_elem_struct_def(i: &mut Tokens<'_>) -> Result<ComponentBodyElem> {
    struct_def.parse_next(i).map(ComponentBodyElem::StructDef)
}

// component_body_elem ::=
//   | constraint_def
fn component_body_elem_constraint_def(i: &mut Tokens<'_>) -> Result<ComponentBodyElem> {
    constraint_def
        .parse_next(i)
        .map(ComponentBodyElem::ConstraintDef)
}

// component_body_elem ::=
//   | explicit_component_inst
fn component_body_elem_explicit_component_inst(i: &mut Tokens<'_>) -> Result<ComponentBodyElem> {
    explicit_component_inst
        .parse_next(i)
        .map(ComponentBodyElem::ExplicitComponentInst)
}

// component_body_elem ::=
//   | property_assignment
fn component_body_elem_property_assignment(i: &mut Tokens<'_>) -> Result<ComponentBodyElem> {
    property_assignment
        .parse_next(i)
        .map(ComponentBodyElem::PropertyAssignment)
}

// component_body_elem ::=
//     component_def
//   | enum_def
//   | struct_def
//   | constraint_def
//   | explicit_component_inst
//   | property_assignment
fn component_body_elem(i: &mut Tokens<'_>) -> Result<ComponentBodyElem> {
    alt((
        component_body_elem_component_def,
        component_body_elem_enum_def,
        component_body_elem_struct_def,
        component_body_elem_constraint_def,
        component_body_elem_explicit_component_inst,
        component_body_elem_property_assignment,
        fail,
    ))
    .parse_next(i)
}

// component_named_def ::= component_type id [ param_def ] component_body
fn component_named_def(i: &mut Tokens<'_>) -> Result<ComponentDef> {
    let (type_, name, param_def, body) =
        (component_type, identifier, opt(param_def), component_body).parse_next(i)?;

    Ok(ComponentDef {
        type_,
        name: Some(name),
        param_def,
        body,
    })
}

// component_anon_def::= component_type component_body
fn component_anon_def(i: &mut Tokens<'_>) -> Result<ComponentDef> {
    let (type_, body) = (component_type, component_body).parse_next(i)?;
    Ok(ComponentDef {
        type_,
        name: None,
        param_def: None,
        body,
    })
}

// component_inst_type ::= external | internal
fn component_inst_type(i: &mut Tokens<'_>) -> Result<ComponentInstType> {
    match i.next_token() {
        Some(Token {
            kind: TokenKind::Internal,
            ..
        }) => Ok(ComponentInstType::Internal),
        Some(Token {
            kind: TokenKind::External,
            ..
        }) => Ok(ComponentInstType::External),
        _ => fail.parse_next(i),
    }
}

// param_elem ::= . id ( param_value )
fn param_elem(i: &mut Tokens<'_>) -> Result<ParamElem> {
    let (_, id, _, param_value, _) = (
        TokenKind::Period,
        identifier,
        TokenKind::ParenOpen,
        constant_expr,
        TokenKind::ParenClose,
    )
        .parse_next(i)?;
    Ok(ParamElem { id, param_value })
}

// param_inst ::= # ( param_elem { , param_elem } )
fn param_inst(i: &mut Tokens<'_>) -> Result<Vec<ParamElem>> {
    let (_, _, params, _) = (
        TokenKind::Hash,
        TokenKind::ParenOpen,
        separated(1.., param_elem, TokenKind::Comma),
        TokenKind::ParenClose,
    )
        .parse_next(i)?;
    Ok(params)
}

// component_insts ::= [ param_inst ] component_inst { , component_inst }
fn component_insts(i: &mut Tokens<'_>) -> Result<ComponentInsts> {
    let param_insts = opt(param_inst).parse_next(i)?.unwrap_or_default();
    let component_insts = separated(1.., component_inst, TokenKind::Comma).parse_next(i)?;
    Ok(ComponentInsts {
        param_insts,
        component_insts,
    })
}

// primary_literal ::=
//     number
//   | string_literal
//   | boolean_literal
//   | accesstype_literal
//   | onreadtype_literal
//   | onwritetype_literal
//   | addressingtype_literal
//   | enumerator_literal
//   | this
fn primary_literal(i: &mut Tokens<'_>) -> Result<PrimaryLiteral> {
    match i.next_token() {
        Some(Token {
            kind: TokenKind::Number(n),
            ..
        }) => Ok(PrimaryLiteral::Number(*n)),
        Some(Token {
            kind: TokenKind::Bits(b),
            ..
        }) => Ok(PrimaryLiteral::Bits(*b)),
        Some(Token {
            kind: TokenKind::StringLiteral(s),
            ..
        }) => Ok(PrimaryLiteral::StringLiteral(s.to_string())),
        Some(Token {
            kind: TokenKind::True,
            ..
        }) => Ok(PrimaryLiteral::BooleanLiteral(true)),
        Some(Token {
            kind: TokenKind::False,
            ..
        }) => Ok(PrimaryLiteral::BooleanLiteral(false)),
        Some(Token {
            kind: TokenKind::AccessTypeLiteral(x),
            ..
        }) => Ok(PrimaryLiteral::AccessTypeLiteral(*x)),
        Some(Token {
            kind: TokenKind::OnReadTypeLiteral(x),
            ..
        }) => Ok(PrimaryLiteral::OnReadTypeLiteral(*x)),
        Some(Token {
            kind: TokenKind::OnWriteTypeLiteral(x),
            ..
        }) => Ok(PrimaryLiteral::OnWriteTypeLiteral(*x)),
        Some(Token {
            kind: TokenKind::AddressingTypeLiteral(x),
            ..
        }) => Ok(PrimaryLiteral::AddressingTypeLiteral(*x)),
        Some(Token {
            kind: TokenKind::This,
            ..
        }) => Ok(PrimaryLiteral::This),
        _ => {
            let (a, _, _, b) =
                (identifier, TokenKind::Colon, TokenKind::Colon, identifier).parse_next(i)?;
            Ok(PrimaryLiteral::EnumeratorLiteral(a, b))
        }
    }
}

// constant_concatenation ::= { constant_expression { , constant_expression } }
fn constant_concat(i: &mut Tokens<'_>) -> Result<Vec<ConstantExpr>> {
    preceded(
        TokenKind::BraceOpen,
        terminated(
            separated(1.., constant_expr, TokenKind::Comma),
            TokenKind::BraceClose,
        ),
    )
    .parse_next(i)
}

// constant_multiple_concatenation ::= { constant_expression constant_concatenation }
fn constant_multiple_concat(i: &mut Tokens<'_>) -> Result<ConstantPrimaryBase> {
    let (_, expr, constants, _) = (
        TokenKind::BraceOpen,
        constant_expr,
        constant_concat,
        TokenKind::BraceClose,
    )
        .parse_next(i)?;
    Ok(ConstantPrimaryBase::ConstantMultipleConcat(
        Box::new(expr),
        constants,
    ))
}

// instance_ref_element ::= id { array }
fn instance_ref_element(i: &mut Tokens<'_>) -> Result<InstanceRefElement> {
    let (id, arrays) = (identifier, repeat(0.., array)).parse_next(i)?;
    Ok(InstanceRefElement { id, arrays })
}

// instance_ref ::= instance_ref_element { . instance_ref_element }
fn instance_ref(i: &mut Tokens<'_>) -> Result<InstanceRef> {
    let elements = separated(1.., instance_ref_element, TokenKind::Period).parse_next(i)?;
    Ok(InstanceRef { elements })
}

fn id_or_prop_keyword(i: &mut Tokens<'_>) -> Result<IdentityOrPropKeyword> {
    match i.next_token() {
        Some(Token {
            kind: TokenKind::Identifier(id),
            ..
        }) => Ok(IdentityOrPropKeyword::Id(id.to_string())),
        Some(Token {
            kind: TokenKind::PrecedenceTypeLiteral(PrecedenceType::Hw),
            ..
        }) => Ok(IdentityOrPropKeyword::PropKeyword(PropKeyword::Hw)),
        Some(Token {
            kind: TokenKind::PrecedenceTypeLiteral(PrecedenceType::Sw),
            ..
        }) => Ok(IdentityOrPropKeyword::PropKeyword(PropKeyword::Sw)),
        Some(Token {
            kind: TokenKind::OnReadTypeLiteral(OnReadType::RClr),
            ..
        }) => Ok(IdentityOrPropKeyword::PropKeyword(PropKeyword::RClr)),
        Some(Token {
            kind: TokenKind::OnReadTypeLiteral(OnReadType::RSet),
            ..
        }) => Ok(IdentityOrPropKeyword::PropKeyword(PropKeyword::RSet)),
        Some(Token {
            kind: TokenKind::OnWriteTypeLiteral(OnWriteType::WoClr),
            ..
        }) => Ok(IdentityOrPropKeyword::PropKeyword(PropKeyword::WoClr)),
        Some(Token {
            kind: TokenKind::OnWriteTypeLiteral(OnWriteType::WoSet),
            ..
        }) => Ok(IdentityOrPropKeyword::PropKeyword(PropKeyword::WoSet)),
        _ => fail.parse_next(i)?,
    }
}

// instance_or_prop_ref ::=
//     instance_ref -> prop_keyword
//   | instance_ref -> id
//   | instance_ref
fn instance_or_prop_ref(i: &mut Tokens<'_>) -> Result<InstanceOrPropRef> {
    let (iref, id_or_prop) = (
        instance_ref,
        opt(preceded(TokenKind::Pointer, id_or_prop_keyword)),
    )
        .parse_next(i)?;
    Ok(InstanceOrPropRef { iref, id_or_prop })
}

// struct_literal ::= id '{ struct_literal_body }
fn struct_literal(i: &mut Tokens<'_>) -> Result<ConstantPrimaryBase> {
    let (id, _, _, body, _) = (
        identifier,
        TokenKind::Quote,
        TokenKind::BraceOpen,
        struct_literal_body,
        TokenKind::BraceClose,
    )
        .parse_next(i)?;
    Ok(ConstantPrimaryBase::StructLiteral(id, body))
}

// struct_literal_elem ::= id : constant_expression
fn struct_literal_element(i: &mut Tokens<'_>) -> Result<StructLiteralElement> {
    let (id, _, expr) = (identifier, TokenKind::Colon, constant_expr).parse_next(i)?;
    Ok(StructLiteralElement { id, expr })
}

// struct_literal_body ::= [ struct_literal_elem { , struct_literal_elem } ]
fn struct_literal_body(i: &mut Tokens<'_>) -> Result<Vec<StructLiteralElement>> {
    separated(0.., struct_literal_element, TokenKind::Comma).parse_next(i)
}

// errata states that 0 is allowed
// array_literal_body ::= [ constant_expression { , constant_expression } ]
fn array_literal_body(i: &mut Tokens<'_>) -> Result<Vec<ConstantExpr>> {
    separated(0.., constant_expr, TokenKind::Comma).parse_next(i)
}

// array_literal ::= '{ array_literal_body }
fn array_literal(i: &mut Tokens<'_>) -> Result<ConstantPrimaryBase> {
    let (_, _, exprs, _) = (
        TokenKind::Quote,
        TokenKind::BraceOpen,
        array_literal_body,
        TokenKind::BraceClose,
    )
        .parse_next(i)?;
    Ok(ConstantPrimaryBase::ArrayLiteral(exprs))
}

fn simple_type_cast(i: &mut Tokens<'_>) -> Result<ConstantPrimaryBase> {
    let (st, expr) = (simple_type, cast_expr).parse_next(i)?;
    Ok(ConstantPrimaryBase::SimpleTypeCast(st, Box::new(expr)))
}

fn boolean_cast(i: &mut Tokens<'_>) -> Result<ConstantPrimaryBase> {
    let (_, expr) = (TokenKind::Boolean, cast_expr).parse_next(i)?;
    Ok(ConstantPrimaryBase::BooleanCast(Box::new(expr)))
}

// constant_primary_base ::= constant_primary
//     primary_literal
//   | constant_concatenation
//   | constant_multiple_concatenation
//   | ( constant_expression )
//   | simple_type ' ( constant_expression )
//   | boolean ' ( constant_expression )
//   | instance_or_prop_ref
//   | struct_literal
//   | array_literal
fn constant_primary_base(i: &mut Tokens<'_>) -> Result<ConstantPrimaryBase> {
    if let Some(x) = opt(primary_literal).parse_next(i)? {
        Ok(ConstantPrimaryBase::PrimaryLiteral(x))
    } else if let Some(cc) = opt(constant_concat).parse_next(i)? {
        Ok(ConstantPrimaryBase::ConstantConcat(cc))
    } else if let Some(cc) = opt(constant_multiple_concat).parse_next(i)? {
        Ok(cc)
    } else if let Some((_, cc, _)) =
        opt((TokenKind::ParenOpen, constant_expr, TokenKind::ParenClose)).parse_next(i)?
    {
        Ok(ConstantPrimaryBase::ConstantExpr(Box::new(cc)))
    } else if let Some(cc) = opt(simple_type_cast).parse_next(i)? {
        Ok(cc)
    } else if let Some(cc) = opt(boolean_cast).parse_next(i)? {
        Ok(cc)
    } else if let Some(x) = opt(instance_or_prop_ref).parse_next(i)? {
        Ok(ConstantPrimaryBase::InstanceOrPropRef(x))
    } else if let Some(x) = opt(struct_literal).parse_next(i)? {
        Ok(x)
    } else if let Some(x) = opt(array_literal).parse_next(i)? {
        Ok(x)
    } else {
        fail.parse_next(i)
    }
}

// cast_expr ::= ' ( constant_expression )
fn cast_expr(i: &mut Tokens<'_>) -> Result<ConstantExpr> {
    let (_, _, expr, _) = (
        TokenKind::Quote,
        TokenKind::ParenOpen,
        constant_expr,
        TokenKind::ParenClose,
    )
        .parse_next(i)?;
    Ok(expr)
}

// constant_primary ::= constant_primary_base [ cast_expr ]
fn constant_primary(i: &mut Tokens<'_>) -> Result<ConstantPrimary> {
    let (constant_primary_base, cast_expr) =
        (constant_primary_base, opt(cast_expr)).parse_next(i)?;

    Ok(match cast_expr {
        Some(cast_expr) => ConstantPrimary::Cast(constant_primary_base, Box::new(cast_expr)),
        None => ConstantPrimary::Base(constant_primary_base),
    })
}

// unary_operator :
//     ! | + | - | ~ | & | ~& | | | ~| | ^ | ~^ | ^~
fn unary_operator(i: &mut Tokens<'_>) -> Result<UnaryOp> {
    match i.next_token() {
        Some(Token {
            kind: TokenKind::And,
            ..
        }) => Ok(UnaryOp::And),
        Some(Token {
            kind: TokenKind::Or,
            ..
        }) => Ok(UnaryOp::Or),
        Some(Token {
            kind: TokenKind::Not,
            ..
        }) => Ok(UnaryOp::LogicalNot),
        Some(Token {
            kind: TokenKind::Plus,
            ..
        }) => Ok(UnaryOp::Plus),
        Some(Token {
            kind: TokenKind::Minus,
            ..
        }) => Ok(UnaryOp::Minus),
        Some(Token {
            kind: TokenKind::Tilde,
            ..
        }) => Ok(UnaryOp::Not),
        Some(Token {
            kind: TokenKind::TildeAnd,
            ..
        }) => Ok(UnaryOp::Nand),
        Some(Token {
            kind: TokenKind::TildeOr,
            ..
        }) => Ok(UnaryOp::Nor),
        Some(Token {
            kind: TokenKind::Xor,
            ..
        }) => Ok(UnaryOp::Xor),
        Some(Token {
            kind: TokenKind::TildeXor,
            ..
        }) => Ok(UnaryOp::Xnor),
        Some(Token {
            kind: TokenKind::XorTilde,
            ..
        }) => Ok(UnaryOp::Xnor),
        _ => fail.parse_next(i)?,
    }
}

// binary_operator ::=
//     && | || | < | > | <= | >= | == | != | >> | <<
//   | & | | | ^ | ~^| ^~ | * | / | % | + | - | **
fn binary_operator(i: &mut Tokens<'_>) -> Result<BinaryOp> {
    match i.next_token() {
        Some(Token {
            kind: TokenKind::AndAnd,
            ..
        }) => Ok(BinaryOp::AndAnd),
        Some(Token {
            kind: TokenKind::OrOr,
            ..
        }) => Ok(BinaryOp::OrOr),
        Some(Token {
            kind: TokenKind::LessThan,
            ..
        }) => Ok(BinaryOp::LessThan),
        Some(Token {
            kind: TokenKind::GreaterThan,
            ..
        }) => Ok(BinaryOp::GreaterThan),
        Some(Token {
            kind: TokenKind::LessThanOrEqual,
            ..
        }) => Ok(BinaryOp::LessThanOrEqual),
        Some(Token {
            kind: TokenKind::GreaterThanOrEqual,
            ..
        }) => Ok(BinaryOp::GreaterThanOrEqual),
        Some(Token {
            kind: TokenKind::RightShift,
            ..
        }) => Ok(BinaryOp::RightShift),
        Some(Token {
            kind: TokenKind::LeftShift,
            ..
        }) => Ok(BinaryOp::LeftShift),
        Some(Token {
            kind: TokenKind::And,
            ..
        }) => Ok(BinaryOp::And),
        Some(Token {
            kind: TokenKind::Or,
            ..
        }) => Ok(BinaryOp::Or),
        Some(Token {
            kind: TokenKind::Xor,
            ..
        }) => Ok(BinaryOp::Xor),
        Some(Token {
            kind: TokenKind::TildeXor,
            ..
        }) => Ok(BinaryOp::Xnor),
        Some(Token {
            kind: TokenKind::XorTilde,
            ..
        }) => Ok(BinaryOp::Xnor),
        Some(Token {
            kind: TokenKind::Star,
            ..
        }) => Ok(BinaryOp::Times),
        Some(Token {
            kind: TokenKind::Slash,
            ..
        }) => Ok(BinaryOp::Divide),
        Some(Token {
            kind: TokenKind::Percent,
            ..
        }) => Ok(BinaryOp::Modulus),
        Some(Token {
            kind: TokenKind::Plus,
            ..
        }) => Ok(BinaryOp::Plus),
        Some(Token {
            kind: TokenKind::Minus,
            ..
        }) => Ok(BinaryOp::Minus),
        Some(Token {
            kind: TokenKind::Power,
            ..
        }) => Ok(BinaryOp::Power),
        Some(Token {
            kind: TokenKind::EqualsEquals,
            ..
        }) => Ok(BinaryOp::EqualsEquals),
        Some(Token {
            kind: TokenKind::NotEquals,
            ..
        }) => Ok(BinaryOp::NotEquals),
        _ => fail.parse_next(i)?,
    }
}

// constant_expression ::=
//     constant_primary [ constant_expression_continue ]
fn constant_expr_constant_primary(i: &mut Tokens<'_>) -> Result<ConstantExpr> {
    let (constant_primary, constant_expr_continue) =
        (constant_primary, opt(constant_expr_continue)).parse_next(i)?;
    Ok(ConstantExpr::ConstantPrimary(
        constant_primary,
        constant_expr_continue.map(Box::new),
    ))
}

// constant_expression ::=
//   | unary_operator constant_primary [ constant_expression_continue ]
fn constant_expr_unary_operator_constant_primary(i: &mut Tokens<'_>) -> Result<ConstantExpr> {
    let (op, x, cont) =
        (unary_operator, constant_expr, opt(constant_expr_continue)).parse_next(i)?;
    Ok(ConstantExpr::UnaryOp(op, Box::new(x), cont.map(Box::new)))
}

// constant_expression_continue ::=
//   | binary_operator constant_expression [ constant_expression_continue ]
fn constant_expr_binary(i: &mut Tokens<'_>) -> Result<ConstantExprContinue> {
    let (op, b, cont) =
        (binary_operator, constant_expr, opt(constant_expr_continue)).parse_next(i)?;
    Ok(ConstantExprContinue::BinaryOp(
        op,
        Box::new(b),
        cont.map(Box::new),
    ))
}

// constant_expression_continue ::=
//   | ? constant_expression : constant_expression [ constant_expression_continue ]
fn constant_expr_ternary(i: &mut Tokens<'_>) -> Result<ConstantExprContinue> {
    let (_, b, _, c, cont) = (
        TokenKind::QuestionMark,
        constant_expr,
        TokenKind::Colon,
        constant_expr,
        opt(constant_expr_continue),
    )
        .parse_next(i)?;
    Ok(ConstantExprContinue::TernaryOp(
        Box::new(b),
        Box::new(c),
        cont.map(Box::new),
    ))
}

// constant_expression_continue ::=
//   | binary_operator constant_expression [ constant_expression_continue ]
//   | ? constant_expression : constant_expression [ constant_expression_continue ]
fn constant_expr_continue(i: &mut Tokens<'_>) -> Result<ConstantExprContinue> {
    alt((constant_expr_binary, constant_expr_ternary, fail)).parse_next(i)
}

// constant_expression ::=
//     constant_primary [ constant_expression_continue ]
//   | unary_operator constant_primary [ constant_expression_continue ]

fn constant_expr(i: &mut Tokens<'_>) -> Result<ConstantExpr> {
    alt((
        constant_expr_constant_primary,
        constant_expr_unary_operator_constant_primary,
        fail,
    ))
    .parse_next(i)
}

// array ::= [ constant_expression ]
fn array(i: &mut Tokens<'_>) -> Result<ConstantExpr> {
    let (_, expr, _) = (
        TokenKind::BracketOpen,
        constant_expr,
        TokenKind::BracketClose,
    )
        .parse_next(i)?;
    Ok(expr)
}

// range ::= [ constant_expression : constant_expression ]
fn range(i: &mut Tokens<'_>) -> Result<Range> {
    let (_, a, _, b, _) = (
        TokenKind::BracketOpen,
        constant_expr,
        TokenKind::Colon,
        constant_expr,
        TokenKind::BracketClose,
    )
        .parse_next(i)?;
    Ok(Range::Range(a, b))
}

// component_inst_array_or_range ::=
//     array { array }
//   | range
fn component_inst_array_or_range(i: &mut Tokens<'_>) -> Result<ArrayOrRange> {
    if let Some(x) = opt(repeat(1.., array)).parse_next(i)? {
        Ok(ArrayOrRange::Array(x))
    } else if let Some(y) = opt(range).parse_next(i)? {
        Ok(ArrayOrRange::Range(y))
    } else {
        fail.parse_next(i)
    }
}

// component_inst ::=
//   id [ component_inst_array_or_range ]
//   [ = constant_expression ]
//   [ @ constant_expression ]
//   [ += constant_expression ]
//   [ %= constant_expression ]
fn component_inst(i: &mut Tokens<'_>) -> Result<ComponentInst> {
    let (id, array_or_range, equals, at, plus_equals, percent_equals) = (
        identifier,
        opt(component_inst_array_or_range),
        opt(preceded(TokenKind::Equals, constant_expr)),
        opt(preceded(TokenKind::At, constant_expr)),
        opt(preceded(TokenKind::PlusEqual, constant_expr)),
        opt(preceded(TokenKind::PercentEqual, constant_expr)),
    )
        .parse_next(i)?;

    Ok(ComponentInst {
        id,
        array_or_range,
        equals,
        at,
        plus_equals,
        percent_equals,
    })
}

// component_def ::=
//     component_named_def component_inst_type component_insts ;
fn named_insttype_component(i: &mut Tokens<'_>) -> Result<Component> {
    let (def, inst_type, insts, _) = (
        component_named_def,
        component_inst_type,
        component_insts,
        TokenKind::Semicolon,
    )
        .parse_next(i)?;
    Ok(Component {
        def,
        inst_type: Some(inst_type),
        insts: Some(insts),
    })
}

// component_def ::=
//   | component_anon_def component_inst_type component_insts ;
fn anon_insttype_component(i: &mut Tokens<'_>) -> Result<Component> {
    let (def, inst_type, insts, _) = (
        component_anon_def,
        component_inst_type,
        component_insts,
        TokenKind::Semicolon,
    )
        .parse_next(i)?;
    Ok(Component {
        def,
        inst_type: Some(inst_type),
        insts: Some(insts),
    })
}

// component_def ::=
//   | component_named_def [ component_insts ] ;
fn named_component(i: &mut Tokens<'_>) -> Result<Component> {
    let (def, insts, _) = (
        component_named_def,
        opt(component_insts),
        TokenKind::Semicolon,
    )
        .parse_next(i)?;
    Ok(Component {
        def,
        inst_type: None,
        insts,
    })
}

// component_def ::=
//   | component_anon_def component_insts ;
fn anon_component(i: &mut Tokens<'_>) -> Result<Component> {
    let (def, insts, _) =
        (component_anon_def, component_insts, TokenKind::Semicolon).parse_next(i)?;
    Ok(Component {
        def,
        inst_type: None,
        insts: Some(insts),
    })
}

// component_def ::=
//   | component_inst_type component_named_def component_insts ;
fn insttype_named_component(i: &mut Tokens<'_>) -> Result<Component> {
    let (inst_type, def, insts, _) = (
        component_inst_type,
        component_named_def,
        component_insts,
        TokenKind::Semicolon,
    )
        .parse_next(i)?;
    Ok(Component {
        def,
        inst_type: Some(inst_type),
        insts: Some(insts),
    })
}

// component_def ::=
//   | component_inst_type component_anon_def component_insts ;
fn insttype_anon_component(i: &mut Tokens<'_>) -> Result<Component> {
    let (inst_type, def, insts, _) = (
        component_inst_type,
        component_anon_def,
        component_insts,
        TokenKind::Semicolon,
    )
        .parse_next(i)?;
    Ok(Component {
        def,
        inst_type: Some(inst_type),
        insts: Some(insts),
    })
}

// component_def ::=
//     component_named_def component_inst_type component_insts ;
//   | component_anon_def component_inst_type component_insts ;
//   | component_named_def [ component_insts ] ;
//   | component_anon_def component_insts ;
//   | component_inst_type component_named_def component_insts ;
//   | component_inst_type component_anon_def component_insts ;
fn component_def(i: &mut Tokens<'_>) -> Result<Component> {
    alt((
        named_insttype_component,
        anon_insttype_component,
        named_component,
        anon_component,
        insttype_named_component,
        insttype_anon_component,
    ))
    .parse_next(i)
}

// property_data_type ::=
//     component_primary_type
fn property_data_type_component_primary_type(i: &mut Tokens<'_>) -> Result<PropertyDataType> {
    component_primary_type
        .parse_next(i)
        .map(PropertyDataType::ComponentPrimaryType)
}

// property_data_type ::=
//   | ref
fn property_data_type_ref(i: &mut Tokens<'_>) -> Result<PropertyDataType> {
    TokenKind::Ref.parse_next(i).map(|_| PropertyDataType::Ref)
}

// property_data_type ::=
//   | number
fn property_data_type_number(i: &mut Tokens<'_>) -> Result<PropertyDataType> {
    TokenKind::Number_
        .parse_next(i)
        .map(|_| PropertyDataType::Number)
}

// property_data_type ::=
//   | basic_data_type
fn property_data_type_basic_data_type(i: &mut Tokens<'_>) -> Result<PropertyDataType> {
    basic_data_type
        .parse_next(i)
        .map(PropertyDataType::BasicDataType)
}

// property_data_type ::=
//     component_primary_type
//   | ref
//   | number
//   | basic_data_type
fn property_data_type(i: &mut Tokens<'_>) -> Result<PropertyDataType> {
    alt((
        property_data_type_component_primary_type,
        property_data_type_ref,
        property_data_type_number,
        property_data_type_basic_data_type,
    ))
    .parse_next(i)
}

// property_type ::= type = property_data_type [ array_type ] ;
fn property_type(i: &mut Tokens<'_>) -> Result<PropertyType> {
    let (_, _, property_data_type, array_type, _) = (
        TokenKind::Type,
        TokenKind::Equals,
        property_data_type,
        opt(array_type),
        TokenKind::Semicolon,
    )
        .parse_next(i)?;
    Ok(PropertyType {
        property_data_type,
        array_type,
    })
}

// property_attribute ::=
//     property_type
fn property_attribute_property_type(i: &mut Tokens<'_>) -> Result<PropertyAttribute> {
    property_type
        .parse_next(i)
        .map(PropertyAttribute::PropertyType)
}

// property_comp_type ::=
//     component_type
fn property_comp_type_component_type(i: &mut Tokens<'_>) -> Result<PropertyCompType> {
    component_type
        .parse_next(i)
        .map(PropertyCompType::ComponentType)
}

// property_comp_type ::=
//   | constraint
fn property_comp_type_constraint(i: &mut Tokens<'_>) -> Result<PropertyCompType> {
    TokenKind::Constraint
        .parse_next(i)
        .map(|_| PropertyCompType::Constraint)
}

// property_comp_type ::=
//   | all
fn property_comp_type_all(i: &mut Tokens<'_>) -> Result<PropertyCompType> {
    TokenKind::All.parse_next(i).map(|_| PropertyCompType::All)
}

// property_comp_type ::=
//     component_type
//   | constraint
//   | all
fn property_comp_type(i: &mut Tokens<'_>) -> Result<PropertyCompType> {
    alt((
        property_comp_type_component_type,
        property_comp_type_constraint,
        property_comp_type_all,
        fail,
    ))
    .parse_next(i)
}

// property_comp_types ::= property_comp_type { | property_comp_type }
fn property_comp_types(i: &mut Tokens<'_>) -> Result<Vec<PropertyCompType>> {
    separated(1.., property_comp_type, TokenKind::Or).parse_next(i)
}

// property_usage ::= component = property_comp_types ;
fn property_attribute_property_usage(i: &mut Tokens<'_>) -> Result<PropertyAttribute> {
    let (_, _, property_comp_types, _) = (
        TokenKind::Component,
        TokenKind::Equals,
        property_comp_types,
        TokenKind::Semicolon,
    )
        .parse_next(i)?;
    Ok(PropertyAttribute::PropertyUsage(property_comp_types))
}

// property_default ::= default = constant_expression ;
fn property_attribute_property_default(i: &mut Tokens<'_>) -> Result<PropertyAttribute> {
    let (_, _, constant_expr, _) = (
        TokenKind::Default,
        TokenKind::Equals,
        constant_expr,
        TokenKind::Semicolon,
    )
        .parse_next(i)?;
    Ok(PropertyAttribute::PropertyDefault(constant_expr))
}

// property_constraint_type::= componentwidth
fn property_constraint_type(i: &mut Tokens<'_>) -> Result<()> {
    TokenKind::ComponentWidth.parse_next(i).map(|_| ())
}

// property_constraint::= constraint = property_constraint_type ;
fn property_attribute_property_constraint(i: &mut Tokens<'_>) -> Result<PropertyAttribute> {
    (
        TokenKind::Constraint,
        TokenKind::Equals,
        property_constraint_type,
        TokenKind::Semicolon,
    )
        .parse_next(i)
        .map(|_| PropertyAttribute::PropertyConstraint)
}

// property_attribute ::=
//     property_type
//   | property_usage
//   | property_default
//   | property_constraint
fn property_attribute(i: &mut Tokens<'_>) -> Result<PropertyAttribute> {
    alt((
        property_attribute_property_type,
        property_attribute_property_usage,
        property_attribute_property_default,
        property_attribute_property_constraint,
        fail,
    ))
    .parse_next(i)
}

// property_body ::= property_attribute { property_attribute }
fn property_body(i: &mut Tokens<'_>) -> Result<Vec<PropertyAttribute>> {
    repeat(1.., property_attribute).parse_next(i)
}

// property_definition ::= property id { property_body } ;
fn property_definition(i: &mut Tokens<'_>) -> Result<PropertyDefinition> {
    let (_, id, _, body, _, _) = (
        TokenKind::Property,
        identifier,
        TokenKind::BraceOpen,
        property_body,
        TokenKind::BraceClose,
        TokenKind::Semicolon,
    )
        .parse_next(i)?;
    Ok(PropertyDefinition { id, body })
}

// description ::=
//     component_def
fn description_component_def(i: &mut Tokens<'_>) -> Result<Description> {
    component_def.parse_next(i).map(Description::ComponentDef)
}

// description ::=
//   | enum_def
fn description_enum_def(i: &mut Tokens<'_>) -> Result<Description> {
    enum_def.parse_next(i).map(Description::EnumDef)
}

// description ::=
//   | property_definition
fn description_property_definition(i: &mut Tokens<'_>) -> Result<Description> {
    property_definition
        .parse_next(i)
        .map(Description::PropertyDefinition)
}

// description ::=
//   | struct_def
fn description_struct_def(i: &mut Tokens<'_>) -> Result<Description> {
    struct_def.parse_next(i).map(Description::StructDef)
}

// description ::=
//   | constraint_def
fn description_constraint_def(i: &mut Tokens<'_>) -> Result<Description> {
    constraint_def.parse_next(i).map(Description::ConstraintDef)
}

// description ::=
//   | explicit_component_inst
fn description_explicit_component_inst(i: &mut Tokens<'_>) -> Result<Description> {
    explicit_component_inst
        .parse_next(i)
        .map(Description::ExplicitComponentInst)
}

// description ::=
//   | explicit_component_inst
fn description_property_assignment(i: &mut Tokens<'_>) -> Result<Description> {
    property_assignment
        .parse_next(i)
        .map(Description::PropertyAssignment)
}

// description ::=
//     component_def
//   | enum_def
//   | property_definition
//   | struct_def
//   | constraint_def
//   | explicit_component_inst
//   | property_assignment
fn description(i: &mut Tokens<'_>) -> Result<Description> {
    alt((
        description_component_def,
        description_enum_def,
        description_property_definition,
        description_struct_def,
        description_constraint_def,
        description_explicit_component_inst,
        description_property_assignment,
        fail,
    ))
    .parse_next(i)
}

// root ::= { description }
pub(crate) fn root(i: &mut Tokens<'_>) -> Result<Root> {
    let descriptions = repeat(0.., description).parse_next(i)?;
    Ok(Root { descriptions })
}

/// Lex string to tokens
pub(crate) fn tokens<'s>(i: &mut &'s str) -> Result<Vec<Token<'s>>> {
    repeat(1.., token).parse_next(i)
}

pub(crate) fn token<'s>(i: &mut &'s str) -> Result<Token<'s>> {
    let mut l = Lexer::new(i);
    let x = l.next();
    match x {
        Some(kind) => {
            let r = l.span();
            let token = Token {
                kind,
                raw: &i[l.span()],
            };
            *i = &i[r.end..];
            Ok(token)
        }
        _ => Err(ParserError::from_input(i)),
    }
}

/// Parses a string into a Root RDL object.
pub fn parse(input: &str) -> std::result::Result<Root, anyhow::Error> {
    input.parse::<Root>()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_binary_expr() {
        let tokens = tokens
            .parse("1'b1 & 4'h2")
            .map_err(|e| anyhow::format_err!("{e}"))
            .unwrap();
        println!("tokens: {:?}", tokens);
        let tokens = Tokens::new(&tokens);
        let result = constant_expr
            .parse(tokens)
            .map_err(|e| {
                let t = &e.input()[0];
                anyhow::format_err!("Error parsing input at: `{}` token: {:?}", t.raw, t.kind)
            })
            .unwrap();

        println!("{:?}", result);
    }

    #[test]
    fn test_addr_map() {
        let result = parse(
            r#"
        addrmap {
            reg { field {} f; } a;
        } mcu;"#,
        );
        println!("{:?}", result);
        result.unwrap();
    }

    #[test]
    fn test_mcu_map() {
        let result = parse(
            r#"
        addrmap {
            reg { field {} f; } a;
            I3CCSR I3CCSR @ 0x2000_4000;
            mci_top mci_top @ 0x2100_0000;
        } mcu;
          "#,
        );
        println!("{:?}", result);
        result.unwrap();
    }

    #[test]
    fn test_big() {
        let input = r#"
            addrmap {
                addressing = compact;
                lsb0 = true;

                default regwidth = 32;

                reg { field {} f; } a;

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
            } my_addrmap;"#;
        let result = parse(input).unwrap();
        println!("{:?}", result);
    }
}

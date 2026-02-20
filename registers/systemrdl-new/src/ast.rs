// Licensed under the Apache-2.0 license.

//! Abstract Syntax Tree (AST) for SystemRDL parser.

use crate::parser::{root, tokens};
use crate::{token_iter::TokenIter, Bits, FileSource, Token, TokenKind, Tokens};
use std::path::Path;
use winnow::Parser;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrecedenceType {
    Hw,
    Sw,
}

impl From<&str> for PrecedenceType {
    fn from(s: &str) -> Self {
        match s {
            "hw" => PrecedenceType::Hw,
            "sw" => PrecedenceType::Sw,
            _ => panic!("Invalid precedence type"),
        }
    }
}

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
pub enum AccessType {
    #[default]
    Rw,
    R,
    W,
    Rw1,
    W1,
    Na,
}

impl From<&str> for AccessType {
    fn from(s: &str) -> Self {
        match s {
            "rw" => AccessType::Rw,
            "wr" => AccessType::Rw,
            "r" => AccessType::R,
            "w" => AccessType::W,
            "rw1" => AccessType::Rw1,
            "w1" => AccessType::W1,
            "na" => AccessType::Na,
            _ => panic!("Invalid access type"),
        }
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnReadType {
    RClr,
    RSet,
    RUser,
}

impl From<&str> for OnReadType {
    fn from(s: &str) -> Self {
        match s {
            "rclr" => OnReadType::RClr,
            "rset" => OnReadType::RSet,
            "ruser" => OnReadType::RUser,
            _ => panic!("Invalid on read type"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnWriteType {
    WoSet,
    WoClr,
    Wot,
    Wzs,
    Wzc,
    Wzt,
    WClr,
    WSet,
    WUser,
}

impl From<&str> for OnWriteType {
    fn from(s: &str) -> Self {
        match s {
            "woset" => OnWriteType::WoSet,
            "woclr" => OnWriteType::WoClr,
            "wot" => OnWriteType::Wot,
            "wzs" => OnWriteType::Wzs,
            "wzc" => OnWriteType::Wzc,
            "wzt" => OnWriteType::Wzt,
            "wclr" => OnWriteType::WClr,
            "wset" => OnWriteType::WSet,
            "wuser" => OnWriteType::WUser,
            _ => panic!("Invalid on write type"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressingType {
    Compact,
    RegAlign,
    FullAlign,
}

impl From<&str> for AddressingType {
    fn from(s: &str) -> Self {
        match s {
            "compact" => AddressingType::Compact,
            "regalign" => AddressingType::RegAlign,
            "fullalign" => AddressingType::FullAlign,
            _ => panic!("Invalid addressing type"),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum InterruptType {
    #[default]
    Level,
    PosEdge,
    NegEdge,
    BothEdge,
    NonSticky,
    Sticky,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentType {
    Field,
    Reg,
    RegFile,
    AddrMap,
    Signal,
    Enum,
    EnumVariant,
    Mem,
    Constraint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntegerType {
    Bit,
    Longint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BasicDataType {
    IntegerType(IntegerType),
    UnsignedIntegerType(IntegerType),
    String,
    Boolean,
    Identifier(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Root {
    pub descriptions: Vec<Description>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Description {
    ComponentDef(Component),
    EnumDef(EnumDef),
    PropertyDefinition(PropertyDefinition),
    StructDef(StructDef),
    ConstraintDef(ConstraintDef),
    ExplicitComponentInst(ExplicitComponentInst),
    PropertyAssignment(PropertyAssignment),
}

impl Root {
    pub fn from_file(file_source: &dyn FileSource, name: &Path) -> Result<Self, anyhow::Error> {
        let mut tokens = vec![];
        let mut iter = TokenIter::from_path(file_source, name)?;
        loop {
            let t = iter.next();
            if t == TokenKind::EndOfFile {
                break;
            }
            let span = iter.last_span();
            // TODO: this span could refer to the previous file if the fifo was not empty; we should return the correct string in that case
            tokens.push(Token {
                kind: t,
                raw: &(iter.current_file_contents()[span.start..span.end]),
            });
        }
        let tokens = Tokens::new(&tokens);
        root.parse(tokens).map_err(|e| {
            let t = &e.input()[0];
            anyhow::format_err!("Error parsing input at: `{}` token: {:?}", t.raw, t.kind)
        })
    }
}

impl std::str::FromStr for Root {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let tokens = tokens
            .parse(input.trim_end())
            .map_err(|e| anyhow::format_err!("{e}"))?;
        let tokens = Tokens::new(&tokens);
        root.parse(tokens).map_err(|e| {
            let t = &e.input()[0];
            anyhow::format_err!("Error parsing input at: `{}` token: {:?}", t.raw, t.kind)
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataType {
    BasicDataType(BasicDataType),
    AccessType,
    AddressingType,
    OnReadType,
    OnWriteType,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArrayType {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParamDefElem {
    ParamDefElem(DataType, String, Option<ArrayType>, Option<ConstantExpr>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumEntry {
    pub id: String,
    pub expr: Option<ConstantExpr>,
    pub property_assignments: Vec<ExplicitPropertyAssignment>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExplicitPropertyAssignment {
    Assignment(IdentityOrPropKeyword, Option<PropAssignmentRhs>),
    EncodeAssignment(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PropAssignmentRhs {
    ConstantExpr(ConstantExpr),
    PrecedenceType(PrecedenceType),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumDef {
    pub id: String,
    pub body: Vec<EnumEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructDef {
    pub id: String,
    pub base: Option<String>,
    pub body: Vec<StructElem>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructElem {
    pub struct_type: StructType,
    pub id: String,
    pub array_type: Option<ArrayType>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StructType {
    DataType(DataType),
    ComponentType(ComponentType),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConstraintDef {
    Exp(String, ConstraintBody, Vec<String>),
    Anon(ConstraintBody, Vec<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConstraintLhs {
    This,
    InstanceRef(InstanceRef),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConstraintElem {
    ConstantExpr(ConstantExpr),
    ConstraintPropAssignment(ConstraintPropAssignment),
    ConstraintInsideValues(ConstraintLhs, Vec<ConstraintValue>),
    ConstraintInsideId(ConstraintLhs, String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstraintPropAssignment {
    pub id: String,
    pub expr: ConstantExpr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConstraintValue {
    ConstantExpr(ConstantExpr),
    Range(ConstantExpr, ConstantExpr),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstraintBody {
    pub elements: Vec<ConstraintElem>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplicitComponentInst {
    pub component_inst_type: Option<ComponentInstType>,
    pub component_inst_alias: Option<ComponentInstAlias>,
    pub component_name: String,
    pub component_insts: ComponentInsts,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentInstAlias {
    pub id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PropertyAssignment {
    ExplicitOrDefaultPropAssignment(ExplicitOrDefaultPropAssignment),
    PostPropAssignment(PostPropAssignment),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplicitPropModifier {
    pub prop_mod: PropMod,
    pub id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PropMod {
    PosEdge,
    NegEdge,
    BothEdge,
    Level,
    NonSticky,
}

impl std::fmt::Display for PropMod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            PropMod::PosEdge => "posedge",
            PropMod::NegEdge => "negedge",
            PropMod::BothEdge => "bothedge",
            PropMod::Level => "level",
            PropMod::NonSticky => "nonsticky",
        };
        f.write_str(s)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExplicitOrDefaultPropAssignment {
    ExplicitPropModifier(Option<DefaultKeyword>, ExplicitPropModifier),
    ExplicitPropAssignment(Option<DefaultKeyword>, ExplicitPropertyAssignment),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefaultKeyword {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PostPropAssignment {
    PropRef(PropRef, Option<PropAssignmentRhs>),
    PostEncodeAssignment(PostEncodeAssignment),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PropRef {
    pub iref: InstanceRef,
    pub id_or_prop: IdentityOrPropKeyword,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostEncodeAssignment {
    pub iref: InstanceRef,
    pub id: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComponentBodyElem {
    ComponentDef(Component),
    EnumDef(EnumDef),
    StructDef(StructDef),
    ConstraintDef(ConstraintDef),
    ExplicitComponentInst(ExplicitComponentInst),
    PropertyAssignment(PropertyAssignment),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentBody {
    pub elements: Vec<ComponentBodyElem>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParamDef {
    Params(Vec<ParamDefElem>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentDef {
    pub type_: ComponentType,
    pub name: Option<String>,
    pub param_def: Option<ParamDef>,
    pub body: ComponentBody,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComponentInstType {
    Internal,
    External,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParamElem {
    pub id: String,
    pub param_value: ConstantExpr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentInsts {
    pub param_insts: Vec<ParamElem>,
    pub component_insts: Vec<ComponentInst>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrimaryLiteral {
    Number(u64),
    Bits(Bits),
    StringLiteral(String),
    BooleanLiteral(bool),
    AccessTypeLiteral(AccessType),
    OnReadTypeLiteral(OnReadType),
    OnWriteTypeLiteral(OnWriteType),
    AddressingTypeLiteral(AddressingType),
    EnumeratorLiteral(String, String),
    This,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConstantPrimary {
    Base(ConstantPrimaryBase),
    Cast(ConstantPrimaryBase, Box<ConstantExpr>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConstantPrimaryBase {
    PrimaryLiteral(PrimaryLiteral),
    ConstantConcat(Vec<ConstantExpr>),
    ConstantMultipleConcat(Box<ConstantExpr>, Vec<ConstantExpr>),
    ConstantExpr(Box<ConstantExpr>),
    SimpleTypeCast(IntegerType, Box<ConstantExpr>),
    BooleanCast(Box<ConstantExpr>),
    InstanceOrPropRef(InstanceOrPropRef),
    StructLiteral(String, Vec<StructLiteralElement>),
    ArrayLiteral(Vec<ConstantExpr>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceRef {
    pub elements: Vec<InstanceRefElement>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceRefElement {
    pub id: String,
    pub arrays: Vec<ConstantExpr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityOrPropKeyword {
    Id(String),
    PropKeyword(PropKeyword),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PropKeyword {
    Sw,
    Hw,
    RClr,
    RSet,
    WoClr,
    WoSet,
}

impl std::fmt::Display for PropKeyword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PropKeyword::Sw => f.write_str("sw"),
            PropKeyword::Hw => f.write_str("hw"),
            PropKeyword::RClr => f.write_str("rclr"),
            PropKeyword::RSet => f.write_str("rset"),
            PropKeyword::WoClr => f.write_str("woclr"),
            PropKeyword::WoSet => f.write_str("woset"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceOrPropRef {
    pub iref: InstanceRef,
    pub id_or_prop: Option<IdentityOrPropKeyword>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructLiteralElement {
    pub id: String,
    pub expr: ConstantExpr,
}

#[allow(unused)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnaryOp {
    LogicalNot,
    Plus,
    Minus,
    Not,
    And,
    Nand,
    Or,
    Nor,
    Xor,
    Xnor,
}

#[allow(unused)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BinaryOp {
    AndAnd,
    OrOr,
    LessThan,
    GreaterThan,
    LessThanOrEqual,
    GreaterThanOrEqual,
    EqualsEquals,
    NotEquals,
    RightShift,
    LeftShift,
    And,
    Or,
    Xor,
    Xnor,
    Times,
    Divide,
    Modulus,
    Plus,
    Minus,
    Power,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConstantExpr {
    ConstantPrimary(ConstantPrimary, Option<Box<ConstantExprContinue>>),
    UnaryOp(
        UnaryOp,
        Box<ConstantExpr>,
        Option<Box<ConstantExprContinue>>,
    ),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConstantExprContinue {
    BinaryOp(
        BinaryOp,
        Box<ConstantExpr>,
        Option<Box<ConstantExprContinue>>,
    ),
    TernaryOp(
        Box<ConstantExpr>,
        Box<ConstantExpr>,
        Option<Box<ConstantExprContinue>>,
    ),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArrayOrRange {
    Array(Vec<ConstantExpr>),
    Range(Range),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentInst {
    pub id: String,
    pub array_or_range: Option<ArrayOrRange>,
    pub equals: Option<ConstantExpr>,
    pub at: Option<ConstantExpr>,
    pub plus_equals: Option<ConstantExpr>,
    pub percent_equals: Option<ConstantExpr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Range {
    Range(ConstantExpr, ConstantExpr),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Component {
    pub def: ComponentDef,
    pub inst_type: Option<ComponentInstType>,
    pub insts: Option<ComponentInsts>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PropertyCompType {
    ComponentType(ComponentType),
    Constraint,
    All,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PropertyAttribute {
    PropertyType(PropertyType),
    PropertyUsage(Vec<PropertyCompType>),
    PropertyDefault(ConstantExpr),
    PropertyConstraint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PropertyType {
    pub property_data_type: PropertyDataType,
    pub array_type: Option<ArrayType>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PropertyDataType {
    ComponentPrimaryType(ComponentType),
    Ref,
    Number,
    BasicDataType(BasicDataType),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PropertyDefinition {
    pub id: String,
    pub body: Vec<PropertyAttribute>,
}

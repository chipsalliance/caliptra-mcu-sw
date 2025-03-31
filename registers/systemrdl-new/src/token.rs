// Licensed under the Apache-2.0 license.

use crate::ast::{AccessType, AddressingType, OnReadType, OnWriteType, PrecedenceType};
use crate::Bits;
use std::fmt::Display;
use winnow::Parser;
use winnow::Result;
use winnow::{error::ContextError, stream::TokenSlice, token::literal};

#[derive(Clone, PartialEq, Eq)]
pub struct Token<'s> {
    pub kind: TokenKind<'s>,
    pub raw: &'s str,
}

impl<'a> Display for Token<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.raw)
    }
}
impl<'a> std::fmt::Debug for Token<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} {}", self.kind, self.raw)
    }
}

impl<'s> PartialEq<TokenKind<'s>> for Token<'s> {
    fn eq(&self, other: &TokenKind) -> bool {
        self.kind == *other
    }
}

pub type Tokens<'i> = TokenSlice<'i, Token<'i>>;

impl winnow::stream::ContainsToken<&'_ Token<'_>> for TokenKind<'_> {
    #[inline(always)]
    fn contains_token(&self, token: &'_ Token<'_>) -> bool {
        *self == token.kind
    }
}

impl winnow::stream::ContainsToken<&'_ Token<'_>> for &'_ [TokenKind<'_>] {
    #[inline]
    fn contains_token(&self, token: &'_ Token<'_>) -> bool {
        self.iter().any(|t| *t == token.kind)
    }
}

impl<const LEN: usize> winnow::stream::ContainsToken<&'_ Token<'_>> for &'_ [TokenKind<'_>; LEN] {
    #[inline]
    fn contains_token(&self, token: &'_ Token<'_>) -> bool {
        self.iter().any(|t| *t == token.kind)
    }
}

impl<const LEN: usize> winnow::stream::ContainsToken<&'_ Token<'_>> for [TokenKind<'_>; LEN] {
    #[inline]
    fn contains_token(&self, token: &'_ Token<'_>) -> bool {
        self.iter().any(|t| *t == token.kind)
    }
}

impl<'i> Parser<Tokens<'i>, &'i Token<'i>, ContextError> for TokenKind<'i> {
    fn parse_next(&mut self, input: &mut Tokens<'i>) -> Result<&'i Token<'i>> {
        literal(self.clone()).parse_next(input).map(|t| &t[0])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TokenKind<'a> {
    Field,
    Internal,
    External,
    Reg,
    RegFile,
    AddrMap,
    Signal,
    Enum,
    Mem,
    Constraint,
    All,

    BraceOpen,
    BraceClose,
    BracketOpen,
    BracketClose,
    ParenOpen,
    ParenClose,
    Semicolon,
    Comma,
    Period,
    Equals,
    EqualsEquals,
    NotEquals,
    At,
    Colon,
    Hash,
    Pointer,
    PlusEqual,
    PercentEqual,
    QuestionMark,
    AndAnd,
    OrOr,
    Quote,
    Or,
    And,

    Identifier(&'a str),
    StringLiteral(&'a str),
    AccessTypeLiteral(AccessType),
    OnReadTypeLiteral(OnReadType),
    OnWriteTypeLiteral(OnWriteType),
    AddressingTypeLiteral(AddressingType),
    PrecedenceTypeLiteral(PrecedenceType),
    Number(u64),
    Bits(Bits),
    True,
    False,
    This,
    AccessType,
    AddressingType,
    OnReadType,
    OnWriteType,
    String,
    Boolean,
    Unsigned,
    Bit,
    Longint,
    Encode,
    Struct,
    Abstract,
    Inside,
    Alias,
    Default,
    PosEdge,
    NegEdge,
    BothEdge,
    Level,
    NonSticky,
    Property,
    Type,
    Ref,
    Number_,
    Component,
    ComponentWidth,

    EndOfFile,
    Skip,

    PreprocInclude,
    UnableToOpenFile(&'a str),
    IncludeDepthLimitReached,
    PreprocDefine,
    PreprocIfndef,
    PreprocEndif,

    Error,
}

impl TokenKind<'_> {
    pub fn is_identifier(&self) -> bool {
        matches!(self, Self::Identifier(_))
    }
}

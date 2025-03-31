// Licensed under the Apache-2.0 license.

use crate::{token::TokenKind, Bits};
use std::str::{Chars, FromStr};

pub type Span = std::ops::Range<usize>;

pub struct Lexer<'a> {
    start_ptr: *const u8,
    token_start_ptr: *const u8,
    iter: std::str::Chars<'a>,
}
impl<'a> Lexer<'a> {
    pub fn new(s: &'a str) -> Self {
        Self {
            start_ptr: s.as_bytes().as_ptr(),
            token_start_ptr: s.as_bytes().as_ptr(),
            iter: s.chars(),
        }
    }

    pub fn span(&self) -> Span {
        Span {
            start: self.token_start_ptr as usize - self.start_ptr as usize,
            end: self.iter.as_str().as_ptr() as usize - self.start_ptr as usize,
        }
    }
}
impl<'a> Iterator for Lexer<'a> {
    type Item = TokenKind<'a>;

    fn next(&mut self) -> Option<TokenKind<'a>> {
        let mut iter = self.iter.clone();
        loop {
            let result = match iter.next() {
                Some(' ' | '\t' | '\n' | '\r') => Some(TokenKind::Skip),
                Some('/') => {
                    match iter.next() {
                        Some('*') => {
                            // skip comments
                            loop {
                                match iter.next() {
                                    Some('*') => match iter.next() {
                                        Some('/') => break Some(TokenKind::Skip),
                                        Some(_) => continue,
                                        None => break Some(TokenKind::Error),
                                    },
                                    Some(_) => continue,
                                    None => break Some(TokenKind::Error),
                                }
                            }
                        }
                        Some('/') => loop {
                            match iter.next() {
                                Some('\n') => break Some(TokenKind::Skip),
                                Some(_) => continue,
                                None => break None,
                            }
                        },
                        _ => Some(TokenKind::Error),
                    }
                }
                Some('"') => loop {
                    match iter.next() {
                        Some('"') => {
                            break Some(TokenKind::StringLiteral(str_between(&self.iter, &iter)))
                        }
                        Some('\\') => match iter.next() {
                            Some(_) => continue,
                            None => break Some(TokenKind::Error),
                        },
                        Some(_) => continue,
                        None => break Some(TokenKind::Error),
                    }
                },
                Some(ch) if ch.is_ascii_alphabetic() || ch == '_' => {
                    next_while(&mut iter, |ch| ch.is_ascii_alphanumeric() || ch == '_');
                    let ident = str_between(&self.iter, &iter);
                    match ident {
                        "field" => Some(TokenKind::Field),
                        "internal" => Some(TokenKind::Internal),
                        "external" => Some(TokenKind::External),
                        "reg" => Some(TokenKind::Reg),
                        "regfile" => Some(TokenKind::RegFile),
                        "addrmap" => Some(TokenKind::AddrMap),
                        "signal" => Some(TokenKind::Signal),
                        "enum" => Some(TokenKind::Enum),
                        "mem" => Some(TokenKind::Mem),
                        "constraint" => Some(TokenKind::Constraint),
                        "true" => Some(TokenKind::True),
                        "false" => Some(TokenKind::False),
                        "na" | "rw" | "wr" | "r" | "w" | "rw1" | "w1" => {
                            Some(TokenKind::AccessTypeLiteral(ident.into()))
                        }
                        "rclr" | "rset" | "ruser" => {
                            Some(TokenKind::OnReadTypeLiteral(ident.into()))
                        }
                        "woset" | "woclr" | "wot" | "wzs" | "wzc" | "wzt" | "wclr" | "wset"
                        | "wuser" => Some(TokenKind::OnWriteTypeLiteral(ident.into())),
                        "compact" | "regalign" | "fullalign" => {
                            Some(TokenKind::AddressingTypeLiteral(ident.into()))
                        }
                        "hw" | "sw" => Some(TokenKind::PrecedenceTypeLiteral(ident.into())),
                        "accesstype" => Some(TokenKind::AccessType),
                        "addressingtype" => Some(TokenKind::AddressingType),
                        "onreadtype" => Some(TokenKind::OnReadType),
                        "onwritetype" => Some(TokenKind::OnWriteType),
                        "string" => Some(TokenKind::String),
                        "boolean" => Some(TokenKind::Boolean),
                        "unsigned" => Some(TokenKind::Unsigned),
                        "bit" => Some(TokenKind::Bit),
                        "longint" => Some(TokenKind::Longint),
                        "this" => Some(TokenKind::This),
                        "encode" => Some(TokenKind::Encode),
                        "struct" => Some(TokenKind::Struct),
                        "abstract" => Some(TokenKind::Abstract),
                        "inside" => Some(TokenKind::Inside),
                        "alias" => Some(TokenKind::Alias),
                        "default" => Some(TokenKind::Default),
                        "posedge" => Some(TokenKind::PosEdge),
                        "negedge" => Some(TokenKind::NegEdge),
                        "bothedge" => Some(TokenKind::BothEdge),
                        "level" => Some(TokenKind::Level),
                        "nonsticky" => Some(TokenKind::NonSticky),
                        "property" => Some(TokenKind::Property),
                        "type" => Some(TokenKind::Type),
                        "ref" => Some(TokenKind::Ref),
                        "number" => Some(TokenKind::Number_),
                        "componentwidth" => Some(TokenKind::ComponentWidth),
                        "component" => Some(TokenKind::Component),
                        "all" => Some(TokenKind::All),
                        _ => Some(TokenKind::Identifier(ident)),
                    }
                }
                Some(ch) if ch.is_ascii_digit() => {
                    if ch == '0' && iter.peek() == Some('x') {
                        iter.next();
                        let num_start = iter.clone();
                        next_while(&mut iter, |ch| ch.is_ascii_hexdigit() || ch == '_');
                        Some(parse_num(str_between(&num_start, &iter), 16))
                    } else {
                        next_while(&mut iter, |ch| ch.is_ascii_digit() || ch == '_');
                        let mut peek = iter.clone();
                        if let Some('\'') = peek.next() {
                            iter = peek;
                            next_while(&mut iter, |ch| {
                                ch == 'b' || ch == 'o' || ch == 'd' || ch == 'h'
                            });
                            next_while(&mut iter, |ch| ch.is_ascii_hexdigit() || ch == '_');
                            match Bits::from_str(str_between(&self.iter, &iter)) {
                                Ok(bits) => Some(TokenKind::Bits(bits)),
                                Err(_) => Some(TokenKind::Error),
                            }
                        } else {
                            Some(parse_num(str_between(&self.iter, &iter), 10))
                        }
                    }
                }
                Some('!') => match iter.next() {
                    Some('=') => Some(TokenKind::NotEquals),
                    _ => Some(TokenKind::Error),
                },
                Some('&') => match iter.peek() {
                    Some('&') => {
                        iter.next();
                        Some(TokenKind::AndAnd)
                    }
                    _ => Some(TokenKind::And),
                },
                Some('|') => match iter.peek() {
                    Some('|') => {
                        iter.next();
                        Some(TokenKind::OrOr)
                    }
                    _ => Some(TokenKind::Or),
                },
                Some('{') => Some(TokenKind::BraceOpen),
                Some('}') => Some(TokenKind::BraceClose),
                Some('[') => Some(TokenKind::BracketOpen),
                Some(']') => Some(TokenKind::BracketClose),
                Some('(') => Some(TokenKind::ParenOpen),
                Some(')') => Some(TokenKind::ParenClose),
                Some(';') => Some(TokenKind::Semicolon),
                Some(',') => Some(TokenKind::Comma),
                Some('.') => Some(TokenKind::Period),
                Some('=') => match iter.peek() {
                    Some('=') => {
                        iter.next();
                        Some(TokenKind::EqualsEquals)
                    }
                    _ => Some(TokenKind::Equals),
                },
                Some('@') => Some(TokenKind::At),
                Some('#') => Some(TokenKind::Hash),
                Some(':') => Some(TokenKind::Colon),
                Some('?') => Some(TokenKind::QuestionMark),
                Some('\'') => Some(TokenKind::Quote),
                Some('`') => {
                    let keyword_start = iter.clone();
                    next_while(&mut iter, |ch| ch.is_ascii_alphabetic() || ch == '_');
                    match str_between(&keyword_start, &iter) {
                        "include" => Some(TokenKind::PreprocInclude),
                        "ifndef" => Some(TokenKind::PreprocIfndef),
                        "define" => Some(TokenKind::PreprocDefine),
                        "endif" => Some(TokenKind::PreprocEndif),
                        _ => Some(TokenKind::Error),
                    }
                }
                Some('+') => match iter.next() {
                    Some('=') => Some(TokenKind::PlusEqual),
                    _ => return Some(TokenKind::Error),
                },
                Some('%') => match iter.next() {
                    Some('=') => Some(TokenKind::PercentEqual),
                    _ => Some(TokenKind::Error),
                },
                Some('-') => match iter.next() {
                    Some('>') => Some(TokenKind::Pointer),
                    _ => Some(TokenKind::Error),
                },
                None => None,
                _ => Some(TokenKind::Error),
            };
            match result {
                Some(TokenKind::Skip) => {
                    self.iter = iter.clone();
                    continue;
                }
                Some(token) => {
                    self.token_start_ptr = self.iter.as_str().as_ptr();
                    self.iter = iter;
                    return Some(token);
                }
                None => return None,
            }
        }
    }
}

fn next_while(iter: &mut Chars, mut f: impl FnMut(char) -> bool) {
    loop {
        let mut peek = iter.clone();
        if let Some(ch) = peek.next() {
            if f(ch) {
                *iter = peek;
                continue;
            } else {
                break;
            }
        } else {
            break;
        }
    }
}

fn parse_num(s: &str, radix: u32) -> TokenKind {
    let replaced;
    let s = if s.contains('_') {
        replaced = s.replace('_', "");
        &replaced
    } else {
        s
    };
    if let Ok(val) = u64::from_str_radix(s, radix) {
        TokenKind::Number(val)
    } else {
        TokenKind::Error
    }
}

trait PeekableChar {
    fn peek(&self) -> Option<char>;
}
impl PeekableChar for std::str::Chars<'_> {
    fn peek(&self) -> Option<char> {
        self.clone().next()
    }
}
fn str_between<'a>(start: &Chars<'a>, end: &Chars<'a>) -> &'a str {
    let first_ptr = start.as_str().as_ptr();
    let second_ptr = end.as_str().as_ptr();
    &start.as_str()[0..second_ptr as usize - first_ptr as usize]
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_foo() {
        let tokens: Vec<TokenKind> = Lexer::new("!= && ? __id external field 35\tiDentifier2_ 0x24\n\r 0xf00_bad 100_200 2'b01 5'o27 4'd9 16'h1caf 32'h3CAB_FFB0 /* ignore comment */ %= // line comment\n += \"string 1\" \"string\\\"2\" {}[]();:,.=@#reg field regfile addrmap signal enum mem constraint").take(42).collect();
        assert_eq!(
            tokens,
            vec![
                TokenKind::NotEquals,
                TokenKind::AndAnd,
                TokenKind::QuestionMark,
                TokenKind::Identifier("__id"),
                TokenKind::External,
                TokenKind::Field,
                TokenKind::Number(35),
                TokenKind::Identifier("iDentifier2_"),
                TokenKind::Number(0x24),
                TokenKind::Number(0xf00bad),
                TokenKind::Number(100_200),
                TokenKind::Bits(Bits::new(2, 1)),
                TokenKind::Bits(Bits::new(5, 0o27)),
                TokenKind::Bits(Bits::new(4, 9)),
                TokenKind::Bits(Bits::new(16, 0x1caf)),
                TokenKind::Bits(Bits::new(32, 0x3cab_ffb0)),
                TokenKind::PercentEqual,
                TokenKind::PlusEqual,
                TokenKind::StringLiteral("\"string 1\""),
                TokenKind::StringLiteral("\"string\\\"2\""),
                TokenKind::BraceOpen,
                TokenKind::BraceClose,
                TokenKind::BracketOpen,
                TokenKind::BracketClose,
                TokenKind::ParenOpen,
                TokenKind::ParenClose,
                TokenKind::Semicolon,
                TokenKind::Colon,
                TokenKind::Comma,
                TokenKind::Period,
                TokenKind::Equals,
                TokenKind::At,
                TokenKind::Hash,
                TokenKind::Reg,
                TokenKind::Field,
                TokenKind::RegFile,
                TokenKind::AddrMap,
                TokenKind::Signal,
                TokenKind::Enum,
                TokenKind::Mem,
                TokenKind::Constraint,
            ]
        );
    }
}

// Licensed under the Apache-2.0 license.

use anyhow::bail;

use crate::file_source::FileSource;
use crate::lexer::{Lexer, Span};
use crate::token::TokenKind;
use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};

struct IncludeStackEntry<'a> {
    lex: Lexer<'a>,
    file_path: PathBuf,
    file_contents: &'a str,
}

pub fn parse_str_literal(s: &str) -> Result<String, anyhow::Error> {
    if s.len() < 2 || !s.starts_with('"') || !s.ends_with('"') {
        bail!("Bad string literal: {}", s);
    }
    Ok(s[1..s.len() - 1]
        .replace("\\\"", "\"")
        .replace("\\\\", "\\"))
}

pub struct TokenIter<'a> {
    lex: Lexer<'a>,
    fifo: VecDeque<(TokenKind<'a>, Span)>,
    last_span: Span,

    current_file_contents: &'a str,
    current_file_path: PathBuf,
    file_source: Option<&'a dyn FileSource>,
    iter_stack: Vec<IncludeStackEntry<'a>>,
    defines: HashSet<String>,
}
impl<'a> TokenIter<'a> {
    pub fn from_path(file_source: &'a dyn FileSource, file_path: &Path) -> std::io::Result<Self> {
        let file_contents = file_source.read_to_string(file_path)?;
        let lex = Lexer::new(file_contents);
        Ok(Self {
            lex,
            fifo: VecDeque::new(),
            last_span: 0..0,

            current_file_path: file_path.into(),
            current_file_contents: file_contents,
            iter_stack: Vec::new(),
            file_source: Some(file_source),
            defines: HashSet::new(),
        })
    }

    #[allow(unused)]
    pub fn from_str(s: &'a str) -> Self {
        Self {
            lex: Lexer::new(s),
            fifo: Default::default(),
            last_span: Default::default(),

            current_file_path: Default::default(),
            current_file_contents: s,
            file_source: Default::default(),
            iter_stack: Default::default(),
            defines: Default::default(),
        }
    }

    fn lex_next(&mut self) -> Option<TokenKind<'a>> {
        const INCLUDE_DEPTH_LIMIT: usize = 100;

        loop {
            match self.lex.next() {
                Some(TokenKind::PreprocIfndef) => {
                    let Some(TokenKind::Identifier(name)) = self.lex.next() else {
                        return Some(TokenKind::Error);
                    };
                    if self.defines.contains(name) {
                        // skip to the endif
                        while !matches!(self.lex.next(), Some(TokenKind::PreprocEndif)) {}
                    }
                    continue;
                }
                Some(TokenKind::PreprocDefine) => {
                    let Some(TokenKind::Identifier(name)) = self.lex.next() else {
                        return Some(TokenKind::Error);
                    };
                    self.defines.insert(name.to_string());
                    continue;
                }
                Some(TokenKind::PreprocEndif) => {
                    continue;
                }
                Some(TokenKind::PreprocInclude) => {
                    let Some(TokenKind::StringLiteral(filename)) = self.lex.next() else {
                        return Some(TokenKind::Error);
                    };
                    let Some(file_source) = self.file_source else {
                        return Some(TokenKind::UnableToOpenFile(filename));
                    };
                    let Ok(parsed_filename) = parse_str_literal(filename) else {
                        return Some(TokenKind::UnableToOpenFile(filename));
                    };
                    let file_path = if let Some(parent) = self.current_file_path.parent() {
                        parent.join(parsed_filename)
                    } else {
                        PathBuf::from(parsed_filename)
                    };

                    let Ok(file_contents) = file_source.read_to_string(&file_path) else {
                        return Some(TokenKind::UnableToOpenFile(filename));
                    };
                    if self.iter_stack.len() >= INCLUDE_DEPTH_LIMIT {
                        return Some(TokenKind::IncludeDepthLimitReached);
                    }
                    let old_lex = std::mem::replace(&mut self.lex, Lexer::new(file_contents));
                    let old_file_path =
                        std::mem::replace(&mut self.current_file_path, filename.into());
                    let old_file_contents =
                        std::mem::replace(&mut self.current_file_contents, file_contents);
                    self.iter_stack.push(IncludeStackEntry {
                        lex: old_lex,
                        file_path: old_file_path,
                        file_contents: old_file_contents,
                    });
                    self.current_file_path = file_path;
                    // Retry with new lexer
                    continue;
                }
                None => {
                    let stack_entry = self.iter_stack.pop()?;
                    // this file was included from another file; resume
                    // processing the original file.
                    self.lex = stack_entry.lex;
                    self.current_file_path = stack_entry.file_path;
                    self.current_file_contents = stack_entry.file_contents;
                    continue;
                }
                token => return token,
            }
        }
    }

    fn next_token_raw(&mut self) -> (TokenKind<'a>, Span) {
        match self.lex_next() {
            Some(t) => (t, self.lex.span()),
            None => (TokenKind::EndOfFile, Span::default()),
        }
    }

    pub fn next(&mut self) -> TokenKind<'a> {
        let (next, span) = if self.fifo.is_empty() {
            self.next_token_raw()
        } else {
            self.fifo.pop_front().unwrap()
        };
        self.last_span = span;
        next
    }

    pub fn last_span(&self) -> &Span {
        &self.last_span
    }

    pub fn current_file_contents(&self) -> &'a str {
        self.current_file_contents
    }

    #[allow(unused)]
    pub fn current_file_path(&self) -> &Path {
        &self.current_file_path
    }
}

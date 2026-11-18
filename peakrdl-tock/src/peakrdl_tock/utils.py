# Licensed under the Apache-2.0 license

"""Utility functions for name conversion and formatting."""

import re

# Mixed-case acronyms that are treated as a single word.
_WORD_OVERRIDES = {"SoC": "Soc"}

# Rust keywords that can appear as register or field names.
_RUST_KEYWORDS = frozenset(
    """
    as async await break const continue crate dyn else enum extern false fn
    for if impl in let loop match mod move mut pub ref return self Self
    static struct super trait true type unsafe use where while
    """.split()
)

# A word is an acronym (uppercase letters and digits, ended before the next
# capitalized word), a capitalized or lowercase word, or a run of digits.
_WORD_RE = re.compile(
    r"[A-Z][A-Z0-9]*(?![a-z])|[A-Z]?[a-z][a-z0-9]*|[A-Z]|[0-9]+"
)


def _words(name: str) -> list[str]:
    """Split a name into words on separators and case boundaries."""
    for src, dst in _WORD_OVERRIDES.items():
        name = name.replace(src, dst)
    return _WORD_RE.findall(name)


def _escape(ident: str) -> str:
    """Make a string a valid Rust identifier."""
    if not ident:
        return "_"
    if ident[0].isdigit():
        ident = "_" + ident
    if ident in _RUST_KEYWORDS:
        ident += "_"
    return ident


def snake_case(name: str) -> str:
    """Convert a name to snake_case."""
    return _escape("_".join(w.lower() for w in _words(name)))


def camel_case(name: str) -> str:
    """Convert a name to CamelCase (PascalCase)."""
    return _escape("".join(w[0].upper() + w[1:].lower() for w in _words(name)))


def hex_u32(value: int) -> str:
    """Format a value as a Rust hex literal with an underscore every 4 digits.

    Matches the existing generator output style (e.g., 0x2100_0000).
    """
    raw = f"{value:x}"
    chunks = []
    while raw:
        chunks.append(raw[-4:])
        raw = raw[:-4]
    return "0x" + "_".join(reversed(chunks))

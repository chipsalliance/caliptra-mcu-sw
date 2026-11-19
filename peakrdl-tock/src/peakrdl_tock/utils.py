# Licensed under the Apache-2.0 license

"""Utility functions for name conversion and formatting."""

from __future__ import annotations

import os
import string
from typing import Optional

_SEPARATORS = frozenset(string.punctuation + string.whitespace)

_RUST_KEYWORDS = frozenset(
    """
    as break const continue crate else fn for if impl in let loop match mod
    move mut pub ref return self Self static struct super trait true type
    unsafe use where while async await dyn abstract become box do final macro
    override priv typeof unsized virtual yield
    """.split()
)


def _tweak_keywords(ident: str) -> str:
    """Append an underscore to identifiers that are Rust keywords."""
    return ident + "_" if ident in _RUST_KEYWORDS else ident


def snake_case(name: str) -> str:
    """Convert a name to snake_case.

    An underscore is inserted where an uppercase letter follows a lowercase
    letter or a digit. "I3C" and "SoC" are kept as single words.
    """
    result = []
    if name and name[0] in string.digits:
        result.append("_")
    prev = None
    for c in name:
        if c in _SEPARATORS:
            if prev != "_":
                result.append("_")
            prev = "_"
            continue
        if (
            prev is not None
            and (prev in string.ascii_lowercase or prev in string.digits)
            and c in string.ascii_uppercase
        ):
            result.append("_")
        prev = c
        result.append(c.lower())
    snake = "".join(result)
    snake = snake.replace("so_cmgmt", "soc_mgmt")
    snake = snake.replace("i3_c", "i3c_").replace("__", "_")
    return _tweak_keywords(snake.rstrip("_"))


def camel_case(name: str) -> str:
    """Convert a name to CamelCase.

    Each run of letters and digits between separators is capitalized. Case
    boundaries inside a run are not preserved, so "iTRNG_en" gives "ItrngEn".
    """
    result = []
    if name and name[0] in string.digits:
        result.append("_")
    upper_next = True
    for c in name:
        if c in _SEPARATORS:
            upper_next = True
        else:
            result.append(c.upper() if upper_next else c.lower())
            upper_next = False
    camel = "".join(result).replace("Socmgmt", "SoCMgmt")
    return _tweak_keywords(camel)


def common_name(names: list[str]) -> Optional[str]:
    """Find a name for a type shared by registers with the given names.

    The candidates are the longest common prefix, the longest common suffix,
    and the names overlaid with an X in each position where they differ. The
    candidate that keeps the most characters is used.
    """
    prefix = os.path.commonprefix(names)
    suffix = os.path.commonprefix([n[::-1] for n in names])[::-1]

    shortest = min((len(n) for n in names), default=0)
    chars: list[Optional[str]] = list(names[0][:shortest]) if names else []
    for name in names[1:]:
        for i, c in enumerate(name[:shortest]):
            if chars[i] != c:
                chars[i] = None
    while chars and chars[-1] is None:
        chars.pop()
    placeholder = "X" if any(c and c in string.ascii_uppercase for c in chars) else "x"
    overlaid = "".join(c or placeholder for c in chars)
    overlaid_score = sum(c is not None for c in chars) - 1

    options = [(prefix, len(prefix)), (suffix, len(suffix)), (overlaid, overlaid_score)]
    options.sort(key=lambda option: option[1])
    return options[-1][0] or None


def hex_u32(value: int) -> str:
    """Format a value as a Rust literal: hex with an underscore every 4 digits.

    Matches the existing generator output style (e.g., 0x2100_0000). Values
    below 10 are written in decimal.
    """
    if value <= 9:
        return str(value)
    raw = f"{value:x}"
    chunks = []
    while raw:
        chunks.append(raw[-4:])
        raw = raw[:-4]
    return "0x" + "_".join(reversed(chunks))

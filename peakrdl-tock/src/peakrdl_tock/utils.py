# Licensed under the Apache-2.0 license

"""Utility functions for name conversion and formatting."""

import re


def snake_case(name: str) -> str:
    """Convert a name to snake_case."""
    # Insert underscore before uppercase letters preceded by lowercase
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    # Insert underscore between consecutive uppercase and following lowercase
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s)
    return s.lower().replace(" ", "_").replace("-", "_")


def camel_case(name: str) -> str:
    """Convert a name to CamelCase (PascalCase)."""
    # Split on underscores, hyphens, spaces, and camelCase boundaries
    parts = re.split(r"[_\-\s]+", name)
    result_parts = []
    for part in parts:
        if not part:
            continue
        # If the part is all uppercase and longer than 1 char, title-case it
        if part.isupper() and len(part) > 1:
            result_parts.append(part[0] + part[1:].lower())
        else:
            result_parts.append(part[0].upper() + part[1:])
    return "".join(result_parts)


def hex_u32(value: int) -> str:
    """Format a value as a Rust hex constant with underscore separators.

    Matches the existing generator output style (e.g., 0x2100_0000).
    """
    if value == 0:
        return "0x0"
    raw = f"{value:x}"
    # Pad to even number of digits
    if len(raw) % 2:
        raw = "0" + raw
    # Insert underscores from right, every 4 hex digits
    chunks = []
    while raw:
        chunks.append(raw[-4:] if len(raw) >= 4 else raw)
        raw = raw[: -4 if len(raw) >= 4 else 0]
    chunks = [c for c in chunks if c]
    return "0x" + "_".join(reversed(chunks))

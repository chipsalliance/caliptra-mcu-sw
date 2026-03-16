# Licensed under the Apache-2.0 license

"""RDL tree scanner that builds context dataclasses for template rendering.

Uses systemrdl-compiler's node API to traverse the compiled SystemRDL tree
and extract register, field, and memory information into simple dataclasses
that the generator can consume.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from systemrdl.node import (
    AddrmapNode,
    FieldNode,
    MemNode,
    RegfileNode,
    RegNode,
)

from .utils import camel_case, snake_case


# Default suffixes stripped from addrmap/regfile names (case-insensitive)
DEFAULT_STRIP_SUFFIXES = ["_csr", "_reg", "_top", "_ifc", "_ctrl", "csr"]


@dataclass
class FieldContext:
    """A bitfield within a register."""

    name: str
    offset: int
    width: int
    description: Optional[str] = None
    enum_values: list[tuple[str, int]] = field(default_factory=list)


@dataclass
class RegisterTypeContext:
    """A register type definition (used in register_bitfields!)."""

    name: str
    width: int
    fields: list[FieldContext] = field(default_factory=list)


@dataclass
class RegisterInstContext:
    """A register instance (used in register_structs!)."""

    name: str
    offset: int
    type_name: Optional[str]
    can_read: bool
    can_write: bool
    array_size: Optional[int]
    width: int


@dataclass
class MemoryContext:
    """A memory region."""

    name: str
    offset: int
    size_bytes: int
    description: Optional[str] = None


@dataclass
class AddrmapContext:
    """Complete context for generating one addrmap module."""

    name: str
    base_address: int
    register_types: list[RegisterTypeContext] = field(default_factory=list)
    registers: list[RegisterInstContext] = field(default_factory=list)
    memories: list[MemoryContext] = field(default_factory=list)


def _strip_name(name: str, suffixes: list[str]) -> str:
    """Strip known suffixes from addrmap/type names."""
    lower = name.lower()
    for suffix in suffixes:
        if lower.endswith(suffix.lower()) and len(name) > len(suffix):
            return name[: -len(suffix)]
    return name


def _field_access(node: FieldNode) -> tuple[bool, bool]:
    """Return (can_read, can_write) for a field node."""
    sw = node.get_property("sw")
    sw_str = str(sw).lower()
    can_read = "r" in sw_str
    can_write = "w" in sw_str
    return can_read, can_write


def _reg_access(node: RegNode) -> tuple[bool, bool]:
    """Determine overall register access from its fields."""
    can_read = False
    can_write = False
    for f in node.fields():
        fr, fw = _field_access(f)
        can_read = can_read or fr
        can_write = can_write or fw
    return can_read, can_write


def _get_field_enum_values(node: FieldNode) -> list[tuple[str, int]]:
    """Extract enum encoding from a field, if any."""
    encode = node.get_property("encode")
    if encode is None:
        return []
    result = []
    for member in encode:
        result.append((camel_case(member.name), member.value))
    return result


def _scan_reg(
    node: RegNode,
    name_prefix: str = "",
    strip_suffixes: Optional[list[str]] = None,
) -> tuple[RegisterTypeContext, RegisterInstContext]:
    """Extract register type + instance context from a RegNode."""
    regwidth = node.get_property("regwidth")
    suffixes = strip_suffixes or []

    # Build the register type name from the type if available, else instance name
    if node.orig_type_name:
        type_base = node.orig_type_name
    else:
        type_base = node.inst_name

    type_name = camel_case(_strip_name(name_prefix + type_base, suffixes))
    inst_name = snake_case(name_prefix + node.inst_name)

    fields = []
    for f in node.fields():
        desc = f.get_property("desc")
        fields.append(FieldContext(
            name=camel_case(f.inst_name),
            offset=f.low,
            width=f.width,
            description=desc if desc else None,
            enum_values=_get_field_enum_values(f),
        ))

    reg_type = RegisterTypeContext(name=type_name, width=regwidth, fields=fields)

    can_read, can_write = _reg_access(node)

    array_size = None
    if node.is_array:
        dims = node.array_dimensions
        if dims:
            array_size = 1
            for d in dims:
                array_size *= d

    reg_inst = RegisterInstContext(
        name=inst_name,
        offset=node.raw_address_offset,
        type_name=type_name,
        can_read=can_read,
        can_write=can_write,
        array_size=array_size,
        width=regwidth,
    )

    return reg_type, reg_inst


def _scan_addrmap(
    node: AddrmapNode,
    base_address: int,
    strip_suffixes: Optional[list[str]] = None,
    strip_first_level_prefix: bool = True,
) -> AddrmapContext:
    """Recursively scan an addrmap/regfile and collect all register and memory info.

    The flattening logic mirrors the Rust generator:
    - Addrmaps: prefix accumulates with instance name
    - Regfiles: prefix resets to just the regfile instance name
    - Register type names get suffix-stripped independently
    - Memory names use the full accumulated prefix
    """
    suffixes = strip_suffixes if strip_suffixes is not None else DEFAULT_STRIP_SUFFIXES
    addrmap_name = _strip_name(node.inst_name, suffixes)

    ctx = AddrmapContext(
        name=addrmap_name,
        base_address=base_address,
    )

    seen_types: set[str] = set()

    def visit_addrmap(
        n: AddrmapNode,
        prefix: str = "",
        offset_base: int = 0,
    ) -> None:
        """Visit an addrmap node, accumulating prefix for all children."""
        for child in n.children():
            if not isinstance(child, (RegNode, AddrmapNode, RegfileNode, MemNode)):
                continue

            if isinstance(child, RegNode):
                _add_register(child, prefix, offset_base)
            elif isinstance(child, RegfileNode):
                # Regfiles reset the prefix to just their own name
                rf_name = snake_case(child.inst_name)
                rf_offset = offset_base + child.raw_address_offset
                visit_regfile(child, rf_name, rf_offset, rf_name)
            elif isinstance(child, AddrmapNode):
                child_name = snake_case(child.inst_name)
                child_prefix = f"{prefix}{child_name}_" if prefix else f"{child_name}_"
                child_offset = offset_base + child.raw_address_offset
                visit_addrmap(child, child_prefix, child_offset)
            elif isinstance(child, MemNode):
                _add_memory(child, prefix, offset_base)

    def visit_regfile(
        n: RegfileNode,
        prefix: str,
        offset_base: int,
        first_level_rf: str,
    ) -> None:
        """Visit a regfile node. Prefix is just the regfile name, not accumulated."""
        for child in n.children():
            if not isinstance(child, (RegNode, RegfileNode)):
                continue

            if isinstance(child, RegNode):
                _add_register(child, prefix, offset_base)
            elif isinstance(child, RegfileNode):
                # Nested regfiles: strip first-level prefix if enabled
                nested_name = snake_case(child.inst_name)
                combined = f"{prefix}_{nested_name}"
                if strip_first_level_prefix and combined.startswith(first_level_rf + "_"):
                    combined = combined[len(first_level_rf) + 1:]
                nested_offset = offset_base + child.raw_address_offset
                visit_regfile(child, combined, nested_offset, first_level_rf)

    def _add_register(child: RegNode, prefix: str, offset_base: int) -> None:
        reg_type, reg_inst = _scan_reg(child, "", suffixes)
        # Instance name uses the accumulated prefix
        inst_name = snake_case(child.inst_name)
        reg_inst.name = f"{prefix}{inst_name}" if prefix else inst_name
        reg_inst.offset = offset_base + child.raw_address_offset
        if reg_type.name not in seen_types:
            seen_types.add(reg_type.name)
            ctx.register_types.append(reg_type)
        ctx.registers.append(reg_inst)

    def _add_memory(child: MemNode, prefix: str, offset_base: int) -> None:
        inst_name = snake_case(child.inst_name)
        mem_name = f"{prefix}{inst_name}" if prefix else inst_name
        desc = child.get_property("desc")
        ctx.memories.append(MemoryContext(
            name=mem_name,
            offset=offset_base + child.raw_address_offset,
            size_bytes=child.size,
            description=desc if desc else None,
        ))

    visit_addrmap(node)

    # Sort register types alphabetically for deterministic output
    ctx.register_types.sort(key=lambda rt: rt.name)

    return ctx

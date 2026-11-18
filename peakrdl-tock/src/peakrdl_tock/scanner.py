# Licensed under the Apache-2.0 license

"""RDL tree scanner that builds context dataclasses for template rendering.

Uses systemrdl-compiler's node API to traverse the compiled SystemRDL tree
and extract register, field, and memory information into simple dataclasses
that the generator can consume.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Union

from systemrdl.node import (
    AddrmapNode,
    FieldNode,
    MemNode,
    RegfileNode,
    RegNode,
)

from .utils import camel_case, snake_case


# Default suffixes stripped from the top addrmap name (case-insensitive)
DEFAULT_STRIP_SUFFIXES = ["_csr", "_reg", "_top", "_ifc", "csr"]


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

    def layout(self) -> tuple:
        """The bit layout of the register, ignoring names of the type and descriptions."""
        return (
            self.width,
            tuple((f.name, f.offset, f.width, tuple(f.enum_values)) for f in self.fields),
        )


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
    """Strip known suffixes from an addrmap name until none match."""
    stripped = True
    while stripped:
        stripped = False
        lower = name.lower()
        for suffix in suffixes:
            if lower.endswith(suffix.lower()) and len(name) > len(suffix):
                name = name[: -len(suffix)]
                stripped = True
                break
    return name


def _reg_access(node: RegNode) -> tuple[bool, bool]:
    """Return (can_read, can_write) for a register, from its fields."""
    can_read = any(f.is_sw_readable for f in node.fields())
    can_write = any(f.is_sw_writable for f in node.fields())
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


def _scan_reg(node: RegNode) -> tuple[RegisterTypeContext, RegisterInstContext]:
    """Extract register type + instance context from a RegNode."""
    regwidth = node.get_property("regwidth")

    # Name the register type after the RDL type if available, else the instance
    type_name = camel_case(node.orig_type_name or node.inst_name)
    inst_name = snake_case(node.inst_name)

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
        if node.array_stride != regwidth // 8:
            raise ValueError(
                f"{node.get_path()}: array stride {node.array_stride} differs from "
                f"the register size {regwidth // 8}, which is not supported"
            )
        array_size = 1
        for d in node.array_dimensions:
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
    - Nested regfiles: prefix accumulates, minus the first-level regfile name
    - Memory names use the full accumulated prefix

    Prefixes are either empty or end with an underscore.

    Register types with the same name share one bitfield definition if their
    layouts match. Otherwise the later one is qualified with the names of its
    parents until it is unique.
    """
    suffixes = strip_suffixes if strip_suffixes is not None else DEFAULT_STRIP_SUFFIXES

    ctx = AddrmapContext(
        name=snake_case(_strip_name(node.inst_name, suffixes)),
        base_address=base_address,
    )

    types_by_name: dict[str, RegisterTypeContext] = {}
    paths_by_name: dict[str, str] = {}

    def check_not_array(n: Union[AddrmapNode, RegfileNode]) -> None:
        if n.is_array:
            raise ValueError(f"{n.get_path()}: arrays of addrmaps and regfiles are not supported")

    def visit_addrmap(n: AddrmapNode, prefix: str, offset_base: int) -> None:
        """Visit an addrmap node, accumulating prefix for all children."""
        for child in n.children(unroll=False):
            if isinstance(child, RegNode):
                add_register(child, prefix, offset_base)
            elif isinstance(child, RegfileNode):
                check_not_array(child)
                # Regfiles reset the prefix to just their own name
                rf_name = snake_case(child.inst_name)
                visit_regfile(child, f"{rf_name}_", offset_base + child.raw_address_offset, rf_name)
            elif isinstance(child, AddrmapNode):
                check_not_array(child)
                child_prefix = f"{prefix}{snake_case(child.inst_name)}_"
                visit_addrmap(child, child_prefix, offset_base + child.raw_address_offset)
            elif isinstance(child, MemNode):
                add_memory(child, prefix, offset_base)

    def visit_regfile(n: RegfileNode, prefix: str, offset_base: int, first_level_rf: str) -> None:
        """Visit a regfile node."""
        for child in n.children(unroll=False):
            if isinstance(child, RegNode):
                add_register(child, prefix, offset_base)
            elif isinstance(child, RegfileNode):
                check_not_array(child)
                nested_prefix = f"{prefix}{snake_case(child.inst_name)}_"
                if strip_first_level_prefix and nested_prefix.startswith(f"{first_level_rf}_"):
                    nested_prefix = nested_prefix[len(first_level_rf) + 1:]
                visit_regfile(
                    child, nested_prefix, offset_base + child.raw_address_offset, first_level_rf
                )

    def unique_type_name(child: RegNode, reg_type: RegisterTypeContext) -> str:
        """Find a name for this register type that no other layout uses."""
        candidate = reg_type.name
        parent = child.parent
        while True:
            existing = types_by_name.get(candidate)
            if existing is None or existing.layout() == reg_type.layout():
                return candidate
            if parent is None or parent == node:
                raise ValueError(
                    f"{child.get_path()}: register type {candidate} has a different "
                    f"layout from {paths_by_name[candidate]} and no unique name was found"
                )
            candidate = camel_case(parent.inst_name) + candidate
            parent = parent.parent

    def add_register(child: RegNode, prefix: str, offset_base: int) -> None:
        reg_type, reg_inst = _scan_reg(child)
        if not reg_inst.can_read and not reg_inst.can_write:
            return
        reg_type.name = unique_type_name(child, reg_type)
        reg_inst.type_name = reg_type.name
        reg_inst.name = f"{prefix}{reg_inst.name}"
        reg_inst.offset = offset_base + child.raw_address_offset
        if reg_type.name not in types_by_name:
            types_by_name[reg_type.name] = reg_type
            paths_by_name[reg_type.name] = child.get_path()
            ctx.register_types.append(reg_type)
        ctx.registers.append(reg_inst)

    def add_memory(child: MemNode, prefix: str, offset_base: int) -> None:
        desc = child.get_property("desc")
        ctx.memories.append(MemoryContext(
            name=f"{prefix}{snake_case(child.inst_name)}",
            offset=offset_base + child.raw_address_offset,
            size_bytes=child.size,
            description=desc if desc else None,
        ))

    visit_addrmap(node, "", 0)

    # Sort register types alphabetically for deterministic output
    ctx.register_types.sort(key=lambda rt: rt.name)

    return ctx

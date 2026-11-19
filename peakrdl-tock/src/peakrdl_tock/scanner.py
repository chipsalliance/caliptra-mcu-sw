# Licensed under the Apache-2.0 license

"""RDL tree scanner that builds context dataclasses for template rendering.

Uses systemrdl-compiler's node API to traverse the compiled SystemRDL tree
and extract register, field, and memory information into simple dataclasses
that the generator can consume.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional, Union

from systemrdl.node import (
    AddrmapNode,
    FieldNode,
    MemNode,
    Node,
    RegfileNode,
    RegNode,
)
from systemrdl.rdltypes import OnWriteType

from .utils import camel_case, common_name, snake_case

# Default suffixes stripped from the top addrmap name (case-insensitive)
DEFAULT_STRIP_SUFFIXES = ["_csr", "_reg", "_top", "_ifc", "csr"]

# Returns the name to use for a node in place of its instance name.
RenameFn = Callable[[Node], str]


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
    # The name before conversion to CamelCase. Types are emitted in this order.
    raw_name: str = ""

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
class AddrmapContext:
    """Complete context for generating one addrmap module."""

    name: str
    inst_name: str
    base_address: int
    register_types: list[RegisterTypeContext] = field(default_factory=list)
    registers: list[RegisterInstContext] = field(default_factory=list)


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


def _fields(node: RegNode) -> list[FieldNode]:
    """The fields of a register in declaration order."""

    def position(f: FieldNode) -> tuple:
        ref = f.inst.inst_src_ref
        line = getattr(ref, "line", None)
        selection = getattr(ref, "line_selection", None)
        if line is None or selection is None:
            return (float("inf"), f.low)
        return (line, selection[0])

    return sorted(node.fields(), key=position)


def _unpad_description(desc: str) -> str:
    """Remove the indentation that continuation lines of a description share."""
    lines = [line.rstrip("\r") for line in desc.split("\n")]

    def indent(line: str) -> int:
        return len(line) - len(line.lstrip(" "))

    common = min((indent(line) for line in lines[1:] if line.strip()), default=0)
    lines = [line[min(common, indent(line)) if line.strip(" ") else 0:] for line in lines]
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def _get_field_enum_values(node: FieldNode) -> list[tuple[str, int]]:
    """Extract enum encoding from a field, if any."""
    encode = node.get_property("encode")
    if encode is None:
        return []
    return [(camel_case(member.name), member.value) for member in encode]


def _field_identity(node: FieldNode, name: str) -> tuple:
    """Everything that distinguishes a field of one anonymous register type from another."""
    onwrite = node.get_property("onwrite")
    if onwrite in (OnWriteType.woclr, OnWriteType.woset, OnWriteType.wclr):
        access = onwrite
    else:
        access = (node.is_sw_readable, node.is_sw_writable)
    reset = node.get_property("reset")
    encode = node.get_property("encode")
    return (
        name,
        node.low,
        node.width,
        access,
        reset if isinstance(reset, int) else 0,
        node.get_property("desc") or "",
        tuple((m.name, m.value) for m in encode) if encode is not None else None,
    )


def _array_size(node: RegNode) -> Optional[int]:
    """The number of elements of a register array, or None for a single register."""
    if not node.is_array:
        return None
    regwidth = node.get_property("regwidth")
    if node.array_stride != regwidth // 8:
        raise ValueError(
            f"{node.get_path()}: array stride {node.array_stride} differs from "
            f"the register size {regwidth // 8}, which is not supported"
        )
    size = 1
    for d in node.array_dimensions:
        size *= d
    return size


def _scan_mem(node: MemNode, name: str, offset: int) -> RegisterInstContext:
    """Represent a memory as an array of registers.

    Entries wider than 32 bits are split into 32-bit words.
    """
    memwidth = node.get_property("memwidth")
    entries = node.get_property("mementries")
    if memwidth not in (8, 16, 32, 64, 128):
        raise ValueError(f"{node.get_path()}: unsupported memory width {memwidth}")
    width = min(memwidth, 32)
    return RegisterInstContext(
        name=name,
        offset=offset,
        type_name=None,
        can_read=node.is_sw_readable,
        can_write=node.is_sw_writable,
        array_size=entries * (memwidth // width),
        width=width,
    )


def _scan_addrmap(
    node: AddrmapNode,
    base_address: int,
    strip_suffixes: Optional[list[str]] = None,
    rename: Optional[RenameFn] = None,
) -> AddrmapContext:
    """Recursively scan an addrmap and collect all register and memory info.

    Naming follows the Rust generator in registers/generator:
    - Registers and memories directly in the addrmap keep their names. Those
      in a nested addrmap or regfile are prefixed with the name of the block
      that contains them, and not with the names of blocks further up.
    - A register of a named type uses that type's name for its bitfields.
    - Registers of anonymous types that are identical in every respect share
      one bitfield definition, named after what their names have in common.
    - If two bitfield definitions with different layouts get the same name,
      the later one is prefixed with the names of its parents until it is
      unique.
    - A register name that is already taken gets a numeric suffix.
    """
    suffixes = strip_suffixes if strip_suffixes is not None else DEFAULT_STRIP_SUFFIXES
    if rename is None:
        rename = lambda n: n.inst_name  # noqa: E731

    ctx = AddrmapContext(
        name=snake_case(_strip_name(node.inst_name, suffixes)),
        inst_name=node.inst_name,
        base_address=base_address,
    )

    # (absolute offset, name including the block prefix, node), in visit order
    entries: list[tuple[int, str, Union[RegNode, MemNode]]] = []

    def visit(n: Union[AddrmapNode, RegfileNode], prefix: str, offset_base: int) -> None:
        children = sorted(n.children(unroll=False), key=lambda c: getattr(c, "raw_address_offset", 0))
        for child in children:
            if isinstance(child, (RegNode, MemNode)):
                name = rename(child)
                if prefix and prefix != name:
                    name = f"{prefix}_{name}"
                entries.append((offset_base + child.raw_address_offset, name, child))
        for child in children:
            if isinstance(child, (AddrmapNode, RegfileNode)):
                if child.is_array:
                    raise ValueError(
                        f"{child.get_path()}: arrays of addrmaps and regfiles are not supported"
                    )
                visit(child, rename(child), offset_base + child.raw_address_offset)

    visit(node, "", 0)
    entries.sort(key=lambda e: e[0])

    # Group registers of anonymous types that are identical, and name each
    # group after its registers.
    identities: dict[str, tuple] = {}
    anonymous_groups: dict[tuple, list[str]] = {}
    for _, _, child in entries:
        if isinstance(child, RegNode) and child.orig_type_name is None:
            identity = (
                child.get_property("regwidth"),
                tuple(_field_identity(f, rename(f)) for f in _fields(child)),
            )
            identities[child.get_path()] = identity
            anonymous_groups.setdefault(identity, []).append(rename(child))

    def raw_type_name(child: RegNode) -> str:
        if child.orig_type_name is not None:
            return child.orig_type_name
        names = anonymous_groups[identities[child.get_path()]]
        return common_name(names) or rename(child)

    types_by_name: dict[str, RegisterTypeContext] = {}
    paths_by_name: dict[str, str] = {}

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
            candidate = camel_case(rename(parent)) + candidate
            parent = parent.parent

    def scan_reg(child: RegNode, name: str, offset: int) -> Optional[RegisterInstContext]:
        fields = _fields(child)
        can_read = any(f.is_sw_readable for f in fields)
        can_write = any(f.is_sw_writable for f in fields)
        if not can_read and not can_write:
            return None

        raw_name = raw_type_name(child)
        reg_type = RegisterTypeContext(
            name=camel_case(raw_name),
            raw_name=raw_name,
            width=child.get_property("regwidth"),
            fields=[
                FieldContext(
                    name=camel_case(rename(f)),
                    offset=f.low,
                    width=f.width,
                    description=_unpad_description(f.get_property("desc") or "") or None,
                    enum_values=_get_field_enum_values(f),
                )
                for f in fields
            ],
        )
        reg_type.name = unique_type_name(child, reg_type)
        if reg_type.name not in types_by_name:
            types_by_name[reg_type.name] = reg_type
            paths_by_name[reg_type.name] = child.get_path()
            ctx.register_types.append(reg_type)

        return RegisterInstContext(
            name=name,
            offset=offset,
            type_name=reg_type.name,
            can_read=can_read,
            can_write=can_write,
            array_size=_array_size(child),
            width=reg_type.width,
        )

    used_names: set[str] = set()

    def unique_name(name: str) -> str:
        if name in used_names:
            i = 0
            while f"{name}{i}" in used_names:
                i += 1
            name = f"{name}{i}"
        used_names.add(name)
        return name

    for offset, raw_name, child in entries:
        name = unique_name(snake_case(raw_name))
        if isinstance(child, MemNode):
            ctx.registers.append(_scan_mem(child, name, offset))
        else:
            reg = scan_reg(child, name, offset)
            if reg is not None:
                ctx.registers.append(reg)

    ctx.register_types.sort(key=lambda rt: rt.raw_name)

    return ctx

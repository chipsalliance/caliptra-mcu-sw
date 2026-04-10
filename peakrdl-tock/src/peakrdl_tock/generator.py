# Licensed under the Apache-2.0 license

"""Code generator that produces Tock register files.

Takes AddrmapContext dataclasses from the scanner and produces .rs files
using the tock-registers macro format (register_bitfields! / register_structs!).
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import Optional

from .scanner import AddrmapContext, RegisterTypeContext
from .utils import camel_case, hex_u32, snake_case


def _should_emit_bitfield(rt: RegisterTypeContext) -> bool:
    """Determine whether a register type needs a bitfield definition.

    Skip types with no fields, or types with a single full-width field
    and no enum values (no meaningful bitfield decomposition).
    """
    if not rt.fields:
        return False
    if (
        len(rt.fields) == 1
        and rt.fields[0].offset == 0
        and rt.fields[0].width == rt.width
        and not rt.fields[0].enum_values
    ):
        return False
    return True


def render_module(ctx: AddrmapContext, crate_prefix: str) -> str:
    """Render a single addrmap module to a Rust source string."""
    lines: list[str] = []

    # Address constant
    name_upper = snake_case(ctx.name).upper()
    lines.append(f"pub const {name_upper}_ADDR: u32 = {hex_u32(ctx.base_address)};")

    # Memory region constants
    if ctx.memories:
        lines.append("")
        lines.append("// Memory regions")
        sorted_mems = sorted(ctx.memories, key=lambda m: m.offset)
        for mem in sorted_mems:
            mem_upper = snake_case(mem.name).upper()
            abs_addr = ctx.base_address + mem.offset
            lines.append(f"pub const {mem_upper}_OFFSET: u32 = {hex_u32(mem.offset)};")
            lines.append(f"pub const {mem_upper}_SIZE: usize = {hex_u32(mem.size_bytes)};")
            lines.append(f"pub const {mem_upper}_PTR: *mut u8 = {hex_u32(abs_addr)} as *mut u8;")

    # Group register types by width, filtering trivial ones
    bitfield_groups: OrderedDict[int, list[RegisterTypeContext]] = OrderedDict()
    for rt in ctx.register_types:
        if _should_emit_bitfield(rt):
            bitfield_groups.setdefault(rt.width, []).append(rt)

    bitfield_names = {
        rt.name for rt in ctx.register_types if _should_emit_bitfield(rt)
    }

    # Generate bitfields module
    if bitfield_groups:
        lines.append("pub mod bits {")
        lines.append("    //! Types that represent individual registers (bitfields).")
        lines.append("    use tock_registers::register_bitfields;")
        for width, types in bitfield_groups.items():
            width_type = {8: "u8", 16: "u16", 64: "u64"}.get(width, "u32")
            lines.append("    register_bitfields! {")
            lines.append(f"        {width_type},")
            for rt in types:
                lines.append(f"        pub {rt.name} [")
                for field in rt.fields:
                    if field.description:
                        for desc_line in field.description.splitlines():
                            stripped = desc_line.strip()
                            if stripped:
                                lines.append(f"            /// {stripped}")
                    if field.enum_values:
                        lines.append(f"            {field.name} OFFSET({field.offset}) NUMBITS({field.width}) [")
                        for vname, vval in field.enum_values:
                            lines.append(f"                {vname} = {vval},")
                        lines.append("            ],")
                    else:
                        lines.append(f"            {field.name} OFFSET({field.offset}) NUMBITS({field.width}) [],")
                lines.append("        ],")
            lines.append("    }")
        lines.append("}")

    # Generate register structs module
    if ctx.registers:
        # Sort and deduplicate registers by offset
        sorted_regs = sorted(ctx.registers, key=lambda r: r.offset)
        deduped = []
        for reg in sorted_regs:
            if deduped and deduped[-1].offset == reg.offset:
                prev = deduped[-1]
                deduped[-1] = type(prev)(
                    name=prev.name,
                    offset=prev.offset,
                    type_name=prev.type_name,
                    can_read=prev.can_read or reg.can_read,
                    can_write=prev.can_write or reg.can_write,
                    array_size=prev.array_size,
                    width=prev.width,
                )
            else:
                deduped.append(reg)

        struct_name = camel_case(ctx.name)
        lines.append("pub mod regs {")
        lines.append("    //! Types that represent registers.")
        lines.append("    use tock_registers::register_structs;")
        lines.append("    register_structs! {")
        lines.append(f"        pub {struct_name} {{")

        next_offset = 0
        reserved_count = 0

        for reg in deduped:
            if reg.offset > next_offset:
                lines.append(f"            (0x{next_offset:x} => _reserved{reserved_count}),")
                reserved_count += 1

            access = "ReadWrite" if reg.can_read and reg.can_write else ("ReadOnly" if reg.can_read else "WriteOnly")
            width_type = {8: "u8", 16: "u16", 64: "u64"}.get(reg.width, "u32")

            has_bitfield = reg.type_name is not None and reg.type_name in bitfield_names
            if has_bitfield:
                type_str = f"tock_registers::registers::{access}<{width_type}, {crate_prefix}bits::{reg.type_name}::Register>"
            else:
                type_str = f"tock_registers::registers::{access}<{width_type}>"

            if reg.array_size is not None and reg.array_size > 1:
                type_str = f"[{type_str}; {reg.array_size}]"

            lines.append(f"            (0x{reg.offset:x} => pub {reg.name}: {type_str}),")

            reg_byte_size = (reg.width + 7) // 8
            if reg.array_size is not None:
                next_offset = reg.offset + reg_byte_size * reg.array_size
            else:
                next_offset = reg.offset + reg_byte_size

        lines.append(f"            (0x{next_offset:x} => @END),")
        lines.append("        }")
        lines.append("    }")
        lines.append("}")

    return "\n".join(lines) + "\n"

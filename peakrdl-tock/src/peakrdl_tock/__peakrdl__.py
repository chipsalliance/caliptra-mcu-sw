# Licensed under the Apache-2.0 license

"""PeakRDL CLI plugin descriptor for the Tock exporter."""

from __future__ import annotations

from typing import TYPE_CHECKING

from peakrdl.plugins.exporter import ExporterSubcommandPlugin

from .exporter import TockExporter

if TYPE_CHECKING:
    import argparse

    from systemrdl.node import AddrmapNode


class Exporter(ExporterSubcommandPlugin):
    short_desc = "Generate Tock-style Rust register code (register_bitfields!/register_structs!)"

    def add_exporter_arguments(self, arg_group: "argparse._ActionsContainer") -> None:
        arg_group.add_argument(
            "--base-addr",
            type=lambda x: int(x, 0),
            default=0,
            help="Base address for the addrmap (e.g., 0x20000000).",
        )
        arg_group.add_argument(
            "--output-name",
            default=None,
            help="Output file name (without .rs extension). Defaults to the addrmap name.",
        )
        arg_group.add_argument(
            "--header",
            default="",
            help="Header text to prepend to the generated file.",
        )
        arg_group.add_argument(
            "--fmt",
            action="store_true",
            default=False,
            help="Run rustfmt on the generated code.",
        )

    def do_export(self, top_node: "AddrmapNode", options: "argparse.Namespace") -> None:
        x = TockExporter()
        x.export(
            top_node,
            path=options.output,
            base_addr=options.base_addr,
            output_name=options.output_name,
            header=options.header,
            fmt=options.fmt,
        )

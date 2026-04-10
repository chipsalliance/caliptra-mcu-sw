# Licensed under the Apache-2.0 license

"""TockExporter: public API for generating Tock-style Rust registers from SystemRDL.

This module provides both a standalone Python API and the data flow
used by the PeakRDL CLI plugin.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional, Union

from systemrdl import RDLCompiler
from systemrdl.node import AddrmapNode, RootNode

from .generator import render_module
from .scanner import DEFAULT_STRIP_SUFFIXES, _scan_addrmap


class TockExporter:
    """Generate Tock-style Rust register code from SystemRDL.

    Can be used standalone or via the PeakRDL CLI plugin.
    """

    def export(
        self,
        node: Union[RootNode, AddrmapNode],
        path: str,
        *,
        base_addr: int = 0,
        output_name: Optional[str] = None,
        header: str = "",
        fmt: bool = False,
        strip_suffixes: Optional[list[str]] = None,
        strip_first_level_prefix: bool = True,
    ) -> str:
        """Export a single addrmap node to a Rust source string and optionally write to file.

        Parameters
        ----------
        node : AddrmapNode
            The compiled SystemRDL addrmap node.
        path : str
            Output directory.
        base_addr : int
            Base address override for the addrmap.
        output_name : str, optional
            Output file name (without .rs). Defaults to the addrmap instance name.
        header : str
            Optional header text to prepend (e.g., license).
        fmt : bool
            Run rustfmt on the output.
        strip_suffixes : list[str], optional
            Suffixes to strip from names. Defaults to DEFAULT_STRIP_SUFFIXES.
        strip_first_level_prefix : bool
            Strip the first-level regfile prefix when flattening. Default True.

        Returns
        -------
        str
            The generated Rust source code.
        """
        if isinstance(node, RootNode):
            node = node.top

        suffixes = strip_suffixes if strip_suffixes is not None else DEFAULT_STRIP_SUFFIXES
        ctx = _scan_addrmap(node, base_addr, suffixes, strip_first_level_prefix)
        if output_name:
            crate_prefix = f"crate::{output_name}::"
        else:
            crate_prefix = f"crate::{ctx.name}::"

        code = render_module(ctx, crate_prefix)

        if header:
            code = header + code

        out_dir = Path(path)
        out_dir.mkdir(parents=True, exist_ok=True)
        fname = output_name or ctx.name
        out_file = out_dir / f"{fname}.rs"
        out_file.write_text(code)

        if fmt:
            subprocess.run(["rustfmt", str(out_file)], check=False)

        return code

    def export_from_file(
        self,
        rdl_file: str,
        path: str,
        *,
        top_name: Optional[str] = None,
        base_addr: int = 0,
        output_name: Optional[str] = None,
        header: str = "",
        incl_search_paths: Optional[list[str]] = None,
        fmt: bool = False,
    ) -> str:
        """Compile an RDL file and export the top addrmap.

        Parameters
        ----------
        rdl_file : str
            Path to the .rdl source file.
        path : str
            Output directory.
        top_name : str, optional
            Name of the addrmap to export. If None, uses the root.
        base_addr : int
            Base address for the addrmap.
        output_name : str, optional
            Output file name (without .rs).
        header : str
            Header text to prepend.
        incl_search_paths : list[str], optional
            Additional include search paths for the RDL compiler.
        fmt : bool
            Run rustfmt on the output.

        Returns
        -------
        str
            The generated Rust source code.
        """
        rdlc = RDLCompiler()
        if incl_search_paths:
            for p in incl_search_paths:
                rdlc.compile_file(p)
        rdlc.compile_file(rdl_file)
        root = rdlc.elaborate(top_def_name=top_name)

        return self.export(
            root,
            path,
            base_addr=base_addr,
            output_name=output_name,
            header=header,
            fmt=fmt,
        )

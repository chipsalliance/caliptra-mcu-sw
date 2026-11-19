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
from .scanner import DEFAULT_STRIP_SUFFIXES, RenameFn, _scan_addrmap


class TockExporter:
    """Generate Tock-style Rust register code from SystemRDL.

    Can be used standalone or via the PeakRDL CLI plugin.
    """

    def export(
        self,
        node: Union[RootNode, AddrmapNode],
        path: str,
        *,
        base_addr: Optional[int] = None,
        output_name: Optional[str] = None,
        header: str = "",
        fmt: bool = False,
        strip_suffixes: Optional[list[str]] = None,
        rename: Optional[RenameFn] = None,
        addr_only: bool = False,
    ) -> str:
        """Export a single addrmap node to a Rust module in the output directory.

        The module name is used for the file name and the register struct.
        The address constant is named after the addrmap instance. The
        generated code refers to its own bitfields as
        crate::<module name>::bits, so the file must be a top-level module of
        its crate.

        Parameters
        ----------
        node : AddrmapNode
            The compiled SystemRDL addrmap node.
        path : str
            Output directory.
        base_addr : int, optional
            Base address for the addrmap. Defaults to the absolute address of
            the node.
        output_name : str, optional
            Module name. Defaults to the addrmap instance name in snake case
            with known suffixes stripped.
        header : str
            Optional header text to prepend (e.g., license).
        fmt : bool
            Run rustfmt on the output.
        strip_suffixes : list[str], optional
            Suffixes to strip from the addrmap name to get the default module
            name. Defaults to DEFAULT_STRIP_SUFFIXES.
        rename : callable, optional
            Called with a block, register, memory, or field node. Returns the
            name to use in place of its instance name.
        addr_only : bool
            Only generate the address constant.

        Returns
        -------
        str
            The generated Rust source code.
        """
        if isinstance(node, RootNode):
            node = node.top

        if base_addr is None:
            base_addr = node.absolute_address
        suffixes = strip_suffixes if strip_suffixes is not None else DEFAULT_STRIP_SUFFIXES
        ctx = _scan_addrmap(node, base_addr, suffixes, rename)
        if output_name:
            ctx.name = output_name

        code = header + render_module(ctx, f"crate::{ctx.name}::", addr_only)

        out_dir = Path(path)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{ctx.name}.rs"
        out_file.write_text(code)

        if fmt:
            subprocess.run(["rustfmt", str(out_file)], check=True)
            code = out_file.read_text()

        return code

    def export_from_file(
        self,
        rdl_file: str,
        path: str,
        *,
        top_name: Optional[str] = None,
        base_addr: Optional[int] = None,
        output_name: Optional[str] = None,
        header: str = "",
        incl_search_paths: Optional[list[str]] = None,
        fmt: bool = False,
        **export_args,
    ) -> str:
        """Compile an RDL file and export the top addrmap.

        Keyword arguments not listed here are passed to export().

        Parameters
        ----------
        rdl_file : str
            Path to the .rdl source file.
        path : str
            Output directory.
        top_name : str, optional
            Name of the addrmap to export. If None, uses the root.
        base_addr : int, optional
            Base address for the addrmap. Defaults to 0.
        output_name : str, optional
            Module name.
        header : str
            Header text to prepend.
        incl_search_paths : list[str], optional
            Directories to search for `include files.
        fmt : bool
            Run rustfmt on the output.

        Returns
        -------
        str
            The generated Rust source code.
        """
        rdlc = RDLCompiler()
        rdlc.compile_file(rdl_file, incl_search_paths=incl_search_paths)
        root = rdlc.elaborate(top_def_name=top_name)

        return self.export(
            root,
            path,
            base_addr=base_addr,
            output_name=output_name,
            header=header,
            fmt=fmt,
            **export_args,
        )

# PeakRDL-tock

A [PeakRDL](https://peakrdl.readthedocs.io/) exporter plugin that generates
[Tock](https://www.tockos.org/)-style Rust register definitions from
[SystemRDL](https://www.accellera.org/downloads/standards/systemrdl) descriptions.

The generated code uses the `tock-registers` crate macros:
- `register_bitfields!` for bitfield definitions
- `register_structs!` for memory-mapped register structs

Each addrmap becomes one Rust module containing an address constant, a `bits`
module, and a `regs` module. The module must be a top-level module of its
crate, since the register struct refers to `crate::<module>::bits`.

## Installation

```bash
pip install -e '.[cli]'
```

## Usage

### Command line (via PeakRDL)

```bash
peakrdl tock input.rdl -o output_dir/ --top my_addrmap --base-addr 0x20000000
```

`--output-name` sets the module name, which is used for the file name and the
register struct. It defaults to the addrmap name.

### Python API

```python
from peakrdl_tock import TockExporter

exporter = TockExporter()
exporter.export_from_file("input.rdl", "output_dir/", top_name="my_addrmap", base_addr=0x20000000)
```

`TockExporter.export()` takes an addrmap node from a design compiled with
`systemrdl-compiler`, and by default uses the address the node has in that
design.

## Naming

Names follow the Rust generator that this plugin replaces for the firmware
registers.

- The address constant is named after the addrmap instance. The module name
  is the instance name with the suffixes `_csr`, `_reg`, `_top` and `_ifc`
  removed, and names the file and the register struct.
- Registers and memories directly in the addrmap keep their names. Those in a
  nested addrmap or regfile are prefixed with the name of the block that
  contains them, and not with the names of blocks further up.
- A register of a named type uses that type's name for its bitfields.
- Registers of anonymous types that are identical in fields, access, reset
  values and descriptions share one bitfield definition. It is named after
  what the register names have in common: the common prefix, the common
  suffix, or the names with an `X` where they differ, whichever keeps the
  most characters.
- If two bitfield definitions with different fields get the same name, the
  later one is prefixed with the name of its parent.
- A register name that is already taken gets a numeric suffix.
- Registers that share an offset become one entry with the name and type of
  the first, readable if either is readable and writable if either is
  writable.
- `rename` in the Python API replaces the instance names of blocks,
  registers, memories and fields before any of the above.

## Limitations

- Arrays of addrmaps and regfiles are rejected.
- Register arrays must be contiguous.
- A memory is an array of 8, 16 or 32-bit words in the register struct.
  Entries of 64 or 128 bits are split into 32-bit words.

## Firmware registers

The register modules in `registers/generated-firmware` are this plugin's
output for the SoC and MCU address maps in this repository.
`cargo xtask registers-autogen` regenerates them by running:

```bash
python scripts/generate_registers.py
```

The script needs `systemrdl-compiler` and uses the plugin from this
directory, so the plugin does not have to be installed.

## Tests

```bash
pip install -e '.[cli,test]'
pytest
```

The tests that read the RDL files in `hw/caliptra-ss` are skipped unless the
submodules are checked out. One test checks that
`registers/generated-firmware` matches the generator output.

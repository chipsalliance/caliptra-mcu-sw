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

`--output-name` sets the module name, which is used for the file name, the
address constant, and the register struct. It defaults to the addrmap name.

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

- Registers in a regfile are prefixed with the regfile name. Registers in a
  nested addrmap are prefixed with the names of all enclosing addrmaps.
- Register types are named after the RDL type, or the instance for anonymous
  types. Registers with the same type name and the same fields share one
  bitfield definition. If the fields differ, the later register's type is
  prefixed with the name of its parent.
- Registers that share an offset are merged into one entry with the name and
  type of the first.

## Limitations

- Arrays of addrmaps and regfiles are rejected.
- Register arrays must be contiguous.
- Memories are emitted as offset, size, and pointer constants, and are not
  part of the register struct.

## Example output

`registers/generated-firmware-peakrdl` holds the output for the SoC and MCU
address maps in this repository. To regenerate it:

```bash
python scripts/generate_registers.py
```

## Tests

```bash
pip install -e '.[cli,test]'
pytest
```

The tests that read the RDL files in `hw/caliptra-ss` are skipped unless the
submodules are checked out. One test checks that
`registers/generated-firmware-peakrdl` matches the generator output.

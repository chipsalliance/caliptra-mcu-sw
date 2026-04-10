# PeakRDL-tock

A [PeakRDL](https://peakrdl.readthedocs.io/) exporter plugin that generates
[Tock](https://www.tockos.org/)-style Rust register definitions from
[SystemRDL](https://www.accellera.org/downloads/standards/systemrdl) descriptions.

The generated code uses the `tock-registers` crate macros:
- `register_bitfields!` for bitfield definitions
- `register_structs!` for memory-mapped register structs

## Installation

```bash
pip install -e '.[cli]'
```

## Usage

### Command line (via PeakRDL)

```bash
peakrdl tock input.rdl -o output_dir/ --top my_addrmap --base-addr 0x20000000
```

### Python API

```python
from peakrdl_tock import TockExporter

exporter = TockExporter()
exporter.export("input.rdl", "output_dir/", top_name="my_addrmap", base_addr=0x20000000)
```

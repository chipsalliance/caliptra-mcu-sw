# Caliptra MCU firmware and software

## Building

Install `rustup` to manage your Rust toolchain:

```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

(You may need to open a new shell or source `$HOME/.cargo/env`.)

Do a full clone of the repository

```shell
git clone --recursive https://github.com/chipsalliance/caliptra-mcu-sw.git
```

Now you should be able to run all checks and builds:

```shell
cargo xtask precheckin
```

Commands such as `cargo b` and `cargo t` will also work, but won't execute the extra tests and RISC-V firmware builds.

## Running the emulators

Both the Caliptra Core and MCU emulator will run if you use the `runtime` xtask:

```shell
cargo xtask runtime
```

This uses the full [active, or subsystem, mode boot flow](https://chipsalliance.github.io/caliptra-mcu-sw/rom.html#cold-boot-flow).

## Testing

The primary way to run integration tests with the emulator is using the `test` xtask:

```shell
cargo xtask test
```

For more details on how to run tests locally, how CI works, and how to add new tests, see the [Testing chapter](https://chipsalliance.github.io/caliptra-mcu-sw/testing.html) in the documentation.

## Hardware revisions

`CALIPTRA_HW_REV` selects the hardware inputs and both firmware and emulator
register interfaces. Supported values are `2.1` (default) and `latest`.
Other values, including `2.2`, are rejected; `latest` is not an alias for 2.2.
The repository's Cargo configuration also supplies the 2.1 default to Caliptra
core dependencies, whose upstream default differs.

| Selector | Pinned subsystem | Generated interfaces |
|---|---|---|
| `2.1` | `hw/rev-2_1/caliptra-ss` | `registers/generated-{firmware,emulator}/src/rev_2_1` |
| `latest` | `hw/latest/caliptra-ss` | `registers/generated-{firmware,emulator}/src/latest` |

The 2.1 snapshot pins the validated commit
`3350c70a296bf897abe8c02e5ec0da69cc83ee16`. The latest snapshot pins
`726db5ba926ec523f72962d8703d605fdd479ec9`, including the compound USB hardware
described below. Both use their recorded nested dependencies.
Update a subsystem gitlink and regenerate its interfaces together;
do not independently advance nested RTL/I3C dependencies to branch tips.

Each hardware-input directory (`hw/rev-2_1` or `hw/latest`) also owns its local
RDL files and `fuses.hjson`. Register generation selects `mcu.rdl`, `network.rdl`,
their local includes and the fuse definitions from that same directory.
The directories initially contain identical inputs, but are independent copies:
updating latest's local definitions must not change 2.1. Shared tools and models
remain in `hw/revision` and `hw/model`; the Vivado FPGA flow continues to use the
validated 2.1 subsystem.

```shell
git submodule update --init --recursive
CALIPTRA_HW_REV=2.1 cargo xtask rom-build
CALIPTRA_HW_REV=latest cargo xtask rom-build
CALIPTRA_HW_REV=latest cargo xtask runtime-build
```

Changing the selector rebuilds affected crates without `cargo clean`. New
firmware functionality must still have its own Cargo feature gates: selecting
`latest` does not enable new behavior. The existing `hw-2-1` feature keeps its
firmware semantics and is valid for both current snapshots.

The emulator's `--hw-revision` is the existing emulator/core behavior contract,
not a register selector or a claim of complete 2.2 hardware emulation.
Both snapshots currently require `2.1.0`, now the emulator and
`cargo xtask runtime` default; incompatible runtime revisions are rejected.
This intentionally removes the previous implicit 2.0 emulator behavior.

Default 2.1 firmware/archive filenames remain compatible with existing tooling.
Latest outputs have a `latest-` prefix; explicit output paths remain caller-owned.
Caliptra ROM/FW cache keys always include `rev_2_1-` or `latest-`, including
separately sourced ROM builds. Core source builds run in a child process with
the selected revision explicitly set, preserving upstream's registered firmware
IDs and isolating its in-process firmware cache. ROM/runtime outputs have `.provenance.txt`
sidecars, and firmware/emulator ZIPs include `hardware-provenance.txt`.
These record subsystem and nested hardware commits, the Cargo Caliptra source,
and the separately configured ROM source (`CALIPTRA_ROM_REF`), frozen ROM
selection (`CPTRA_CI_ROM_VERSION`), and prebuilt directory, when applicable.
Explicit externally supplied binaries remain the caller's compatibility responsibility.

**Core integration boundary:** the pinned Caliptra core uses different
subsystem commits (`753308dd...` for 2.1 and `01b0a352...` for latest).
Equal selector names do not prove equivalent hardware. This change preserves
the existing core dependency; core/MCU pin alignment and actual 2.2 validation
remain in #2238. Both current MCU snapshots retain the existing 2.1 ROM contract,
including the CI `CALIPTRA_ROM_REF=rom-2.1.2`. Prebuilt or separately sourced ROMs
must be revalidated before advancing latest. Upstream core Verilator hardware
selection is not fully revision-aware; this change does not claim dual-revision
RTL simulation or FPGA validation.

## Documentation

The specification is published [here](https://chipsalliance.github.io/caliptra-mcu-sw/).

To build the documentation locally, you need to install `mdbook`:

```shell
cargo install --version 0.4.52 mdbook
cargo install --version 0.16.2 mdbook-mermaid
cargo install --version 0.8.0 mdbook-plantuml --no-default-features
wget https://github.com/plantuml/plantuml/releases/download/v1.2025.7/plantuml-asl-1.2025.7.jar -O docs/plantuml-asl-1.2025.7.jar
```

Then you can build the docs with:

```shell
cd docs
mdbook serve --open
```

## Platforms

The MCU can be built for different platforms (e.g., our emulator or for a specific SoC or FPGA).
By default, we provide a default implementation under `platforms/emulator/rom` for our MCU emulator.

Most of the common MCU functionality resides under `rom/`, which relies on the standard Caliptra Subsystem RTL, but otherwise does not rely on anything platform-specific.
Some ROM and runtime shared code resides under `romtime/`.

The general structure of any platform-specific ROM entry point should be:

* At some point, call `caliptra_mcu_rom_common::set_fatal_error_handler()` to set a fatal error handler. (By default, the handler will simply loop forever.)
* At some point, call `caliptra_mcu_romtime::set_printer` if you want the debugging logs to be sent somewhere (by default, the logs will simply be ignored).
* Do any platform-specific initialization
* Call `caliptra_mcu_rom_common::rom_start()`.
* Do any other platform-specific code, including clearing any state.
* Jump to the firmware.

The `caliptra_mcu_rom_common::rom_start()` will handle the standard [MCU ROM boot flow](https://chipsalliance.github.io/caliptra-mcu-sw/rom.html).

Additional callbacks and handlers may be defined in the future for the common MCU ROM to utilize.

Any platform ROM can be developed in tree (in this repository) or out of tree (using the shared crates and tools from this repository, as desired).

The `cargo xtask` commands will default to the `emulator` platform (for now).

## Directory structure

* `emulator/`: Emulator to run the ROM and RT firmware
* `hw/model`: Abstraction for running different platforms for tests.
* `rom/`: ROM code
* `runtime/`: runtime firmware
* `romtime/`: Shared code between ROM and runtime
* `tests/`: firmware and end-to-end tests
* `xtask/`: all of the tooling for building, checking, and running everything.

## Runtime layout

The runtime (or "firmware") uses Tock as the kernel. Any RISC-V code that needs to run in M-mode, e.g., low-level drivers, should run in the Tock board or a capsule loaded by the board.

In Tock, the "board" is the code that runs that does all of the hardware initialization and starts the Tock kernel. The Tock board is essentially a custom a kernel for each SoC.

The applications are higher-level RISC-V code that only interact with the rest of the world through Tock system calls. For instance, an app might be responsible for running a PLDM flow and uses a Tock capsule to interact with the MCTP stack to communicate with the rest of the SoC.

The Tock kernel allows us to run multiple applications at the same time.

Each app and board will be buildable through `xtask`, which will produce ELF, TAB, or raw binaries, as needed.

## `runtime/` directory layout

* `apps/`: Higher-level applications that the firmware runs in U-mode
  * `lib/`: shared code for applications, e.g., the Embassy async executor and Tock `Future` implementation.
* `boards/`: Kernels
* `chips/`: microcontroller-specific drivers
* `capsules/`: kernel modules
* `drivers/`: reusable low-level drivers

## Policies

- `cargo xtask`. All builds, tools, emulators, binaries, etc., should be runnable from `cargo xtask` for consistency.

- **NO bash or Makefiles**. It's Rust / `cargo xtask` or nothing. This is better for cross-platform compatibility and consistency.

- `no_std`-compatible for all ROM / runtime code and libraries

- Run `cargo xtask precheckin` before pushing changes. This can be done, for example, by creating a file `.git/hooks/pre-push` with the contents:

```bash
#!/bin/sh
cargo xtask precheckin
```

## Generating Registers from RDL files

You can run the registers RDL to Rust autogenerator as an `xtask`:

```shell
cargo xtask registers-autogen
```

By default, this generates only the selected snapshot, including its fuse map,
OTP input and MCU definitions. It does not overwrite the other snapshot or the
public register-crate facades.

If you only want to check the output, you can use `--check`.

```shell
cargo xtask registers-autogen --check
CALIPTRA_HW_REV=latest cargo xtask registers-autogen
CALIPTRA_HW_REV=latest cargo xtask registers-autogen --check
```

### Quickly checking new RDL files

For testing and quick development, can also run additional RDL files directly with the command-line flags.
For example, if you want to use the RDL `device.rdl` (which defines a type `devtype`) and mount it to the memory location `0x90000000`, you can do so with:

```shell
cargo xtask registers-autogen --files device.rdl --addrmap devtype@0x90000000
```

### The Autogenerated Root Bus

The register autogenerator generates several pieces of code for each peripheral (corresponding to an RDL instance present in the addrmap):

* A set of Tock register bit fields
* A set of Tock registers (for the firmware to use in drivers)
* A trait used to emulate the peripheral (with default implementations for each method)
* An `emulator_registers_generated::AutoRootBus` that maps reads and writes to each peripheral trait

### Development

When implementing a new emulator peripheral and firmware driver, the workflow will typically be:

* Add the RDL files to `hw/` (or add a new submodule linking to them)
* In `xtask/src/registers.rs`:
  * Add a reference to the new RDL files to parse
  * Create a new `addrmap` if encessary in the `scopes` array (if the new instances are not present in the existing `addrmap`s).
* Run `cargo xtask registers-autogen`
* Implement the new trait for your peripheral in `emulator/periph/src`
* Add your new peripheral as an argument to the `AutoRootBus` in `emulator/app/src/main.rs`.
* Implement your driver in `runtime/src/` using the autogenerated Tock registers.

## FPGA

See [specification](https://chipsalliance.github.io/caliptra-mcu-sw/) for FPGA instructions.

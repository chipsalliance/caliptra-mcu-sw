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

## Hardware revisions

Currently, two hardware revisions are supported: 2.0 and 2.1.

The features added to the 2.1 hardware are, briefly:

* Caliptra ML-KEM support
* I3C AXI recovery bypass

By default, the emulator and firmware use the 2.0 hardware features.

For the emulator, there is a `--hw-revision 2.1.0` flag that can be used to select the 2.1 hardware when running (`cargo xtask runtime` also supports this flag).

For firmware, 2.1 features can be enabled using the `hw-2-1` feature flag when specifying dependencies.

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

* At some point, call `mcu_rom_common::set_fatal_error_handler()` to set a fatal error handler. (By default, the handler will simply loop forever.)
* At some point, call `romtime::set_printer` if you want the debugging logs to be sent somewhere (by default, the logs will simply be ignored).
* Do any platform-specific initialization
* Call `mcu_rom_common::rom_start()`.
* Do any other platform-specific code, including clearing any state.
* Jump to the firmware.

The `mcu_rom_common::rom_start()` will handle the standard [MCU ROM boot flow](https://chipsalliance.github.io/caliptra-mcu-sw/rom.html).

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

By default, this generates Rust register files from the pre-defined RDL files contained in the `hw/` directory.

If you only want to check the output, you can use `--check`.

```shell
cargo xtask registers-autogen --check
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

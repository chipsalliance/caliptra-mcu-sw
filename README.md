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

```sh
cargo xtask precheckin
```

Commands such as `cargo b` and `cargo t` will also work, but won't execute the extra tests and RISC-V firmware builds.

## Documentation

## Directory structure

* `emulator/`: Emulator to run the ROM and RT firmware
* `rom/`: ROM code
* `runtime/`: runtime firmware
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
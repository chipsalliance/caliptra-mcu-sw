# Firmware Bundler

## Overview
The firmware-bundler package is a library for unifying and simplifying the process for building rom and runtime bundles of the subsystem applications for deployment.  As such the bundler is composed of 3 primary functionalities:

1. Generate Linker Scripts - Using a provided Manifest generate linker scripts for the various applications
1. Execute binary Build - Compile the binaries with `rustc` and the linker script generated for a binary
1. Bundle Binaries - Bundle the tockOS runtime applications into a single binary blob for deployment.


The firmware-bundler can either be used directly by platforms within the `caliptra-mcu-sw` repository, or integrated with a Vendor's Out of Tree repository via an `xtask` extension to Cargo.

## Build Patterns

The firmware-bundler supports 2 methods of determining the memory allocation of applications.  The first is a budgeted approach, where each application has a specified instruction and data memory usage within the manifest file.  The other is dynamic sizing, where the size of the memory segments are determined based on the actual memory used by the application.

### Budget

In the budget approach the memory requirements of each application are specified within the manifest, and then the firmware-bundler allocates out portions of the memory hierarchy to match those requirements.  This approach verifies that the application can fit in the specified memory region, and if not the compilation will fail with an appropriate error message.  Since the memory regions are known a priori, the firmware-bundler can use a single pass compilation of each binary.

Pros:
* Requires a single build pass for every application, which can significantly reduce overall build time.
* Memory requirements are explicit, and are verified as part of the compilation process.

Cons:
* Manual adjustment is required if applications grow or change sizes in a way that requires different allocation of the overall memory space.

### Dynamic Sizing

In the dynamic sizing approach the memory requirements of individual applications are not defined, but determined dynamically as part of the bundling process.  While this doesn't effect the ROM binary (since it is the only binary deployed to ROM, it always gets the full memory hieararchy), this does have a significant impact on the runtime applications.  In this model the exec and data memory must not be specified for runtime applications, as it will be dynamically sized by the bundler.

To determine the size of each binary a two pass build process is used.  First all runtime applications are built with the entire memory space of the device dedicated to them.  From this pass the size of each binary is determined.  Once the size of every application is known, the bundler then does a second pass where each binary only receives the amount of memory it requires.

Pros:
* Allows dynamic memory allocation to applications, without manual intervention.

Cons:
* Requires 2 build passes per runtime application.

## Manifest

The principle mechanism for configuring a run of the `firmware-bundler` is a manifest toml file describing the applications to build and the platform to deploy them to.  By describing the memory layout of the bundle, explicit linker files can be generated and budgets can be checked prior executing the build itself, allowing a single pass architecture (See notes for support for 2 pass builds).

The following is a budget (one-pass) sample manifest:

```toml
# The platform describes where the firmware bundle will be deployed to.  It
# should describe hardware characteristics like memory hierarchy and rustc
# target tuple.
[platform]
# The name of this platform.  This is used for naming various binaries, but does
# not effect the contents of the output bundle.
name = "user-recognizable-name"

# The target tuple to compile this bundle for.  If any rustc configuration
# options are required they should be set for this tuple in the `config.toml`
# file.
tuple = "riscv32imc-unknown-none-elf"

# The alignment each binary's intruction and data blocks should match.  If not
# specified defaults to 8.
default_alignment = 4

# The page size for Tock linker scripts.  If not defined the base page size of
# kernel layout linker script is used.
page_size = 256

# The following sections are used to describe the memory layout of the platform
# under build.  The offset describes where in the space the section starts, and
# size indicates its length.
#
# Both are in bytes and can be specified in either decimal or hexadecimal (with
# 0x prefix).

# The ROM memory.  This is where the ROM binary's instructions will reside.
[platform.rom]
offset = 0x0000_0000
size = 0x2_0000

# The ITCM (or ICCM) memory.  This is where the runtime's instructions will
# reside, both kernel and user space applications.
[platform.itcm]
offset = 0x1000_0000
size = 0x4_0000

# The RAM  memory.  This is where the runtime's data will reside, both kernel
# and user space applications.
[platform.ram]
offset = 0x2000_0000
size = 0x4_0000

# An optional memory for ROM code's data.
[platform.dccm]
offset = 0x3000_0000
size = 0x4000

# An optional memory indicating the location within the memory hieararchy of
# flash.
[platform.flash]
offset = 0x3BFE_0000
size = 0x2_0000

# After the platform descriptions are the binaries to include in the bundled
# artifacts.  The 'name' field in each binary should match a package within the
# Cargo workspace the firmware-bundler is being run in.

# The rom binary is an optional application run at power on.  It allocates its
# instructions from the rom memory block and data from dccm.
[rom]
# The name of the rom binary.  It must match a package within the Cargo
# workspace.
name = "rom"
# The instruction memory required for the binary.
exec_mem = {
  # The amount of memory reserved for this application.  It must fit within the
  # given constraint.
  "size" = 0x2000

  # The alignment the offset of the binary must match. If not provided the
  # default alignment of the platform is used.
  "alignment" = 0x10
}

# The data memory required for this binary.
data_mem = {
  "size" = 0x4000
}

# The amount of space within RAM to reserve for the stack.  This, in addition
# to the exception_stack must be less than or equal to the RAM size.
stack = 0x2800

# The amount of space within RAM to reserve for the excption stack.  This will
# used in exception handling to avoid any issues with the application stack,
# like stack overflows.  This is an optional field.
exception_stack = 0x800

# The kernel tockOS binary.  It must be specified and contains the same fields
# as the rom.
[kernel]
name = "kernel"
exec_mem = {
  "size" = 0x2_0000
}
data_mem = {
  "size" = 0x1_0000
}
stack = 0xa000

# After the kernel, an unlimited number of user applications can be specified.
# These will allocate from the ITCM and RAM in the order they are specified.
[[app]]
name = "user-app-1"
exec_mem = {
  "size" = 0x2_0000
}
data_mem = {
  "size" = 0x1_0000
}
stack = 0xa000

[[app]]
name = "user-app-2"
exec_mem = {
  "size" = 0x1_0000
}
data_mem = {
  "size" = 0x3_0000
}
stack = 0x2_0000
```

A dynamic sizing manifest would resemble the following:

```toml
# The platform retains the same configuration as above with the additional
# specification of dynamic sizing.
[platform]
name = "dynamic-sizing-example"
tuple = "riscv32imc-unknown-none-elf"

# This turns on dynamic sizing.  If this is specified the sizes of the
# instruction and data memory for runtime applications will be calculated by
# the bundler.
dynamic_sizing = true

# .... rest of platform configuration as described above ....

# The application specifications, with the exec memory and data memory sections
# removed.  The stack must be defined in this case.
[rom]
name = "rom"
stack = 0x2800
exception_stack = 0x800

[kernel]
name = "kernel"
stack = 0xa000

# After the kernel, an unlimited number of user applications can be specified.
# They will allocate in the order they are specified.
[[app]]
name = "user-app-1"
stack = 0xa000

# The amount of space to reserve in the data allocation in a user space
# application for TockOS grants.  This setting is only applied during dynamic
# sizing, otherwise the `data_mem` budget should account for it.  If not set
# this will default to 4Kb.
grant_space = 0x4000

[[app]]
name = "user-app-2"
stack = 0x2_0000
```

## Integration

It is intended for `mcu-firmware-bundler` to be integrated as an xtask command.  [xtask](https://github.com/matklad/cargo-xtask) is a paradigm for extending Cargo to support additional build commands as required by a project.  Once you've integrated `xtask`, you should be able to add the `mcu-firmware-bundler::Command` as a separate command within your `xtask` match logic.  This will allow a user to invoke the firmware bundler commands from the cli, and easily produce bundled binaries using the same technique used to build and test rust repositories normally.

E.g.

```bash
cargo xtask <firmware-bundler-command> bundle path/to/manifest_file.toml
```

Build outputs from the `mcu-firmware-bundler` are placed within the `target/<target-tuple>` directory for the Cargo workspace.  Linker scripts are placed within the `linker-scripts` directory while binary outputs are placed in the `release` directory.

To get a full understanding of the firmware bundler commands and their various options, invoke the help command, which provides both the arguments and helpful documentation.

```bash
cargo xtask <firmware-bundler-command> --help
```

For an example of integration, take a look at the `caliptra-mcu-sw` integration of the firmware bundler in [caliptra-mcu-sw/xtask/src/main.rs](https://github.com/chipsalliance/caliptra-mcu-sw/blob/3b019a35529002a3d5ccdf9e00a21ec7c4122755/xtask/src/main.rs#L299)

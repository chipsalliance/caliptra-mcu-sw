# Caliptra Subsystem Manufacturing Fuse Provisioning

## Proposal Overview

Fuse provisioning for Caliptra SS, occurs across two distinct manufacturing
stages corresponding to specific Lifecycle (LC) states:

1. **`Test_Unlocked` State**: Programming initial fuses, primarily the Lifecycle
   transition tokens required to advance the state machine throughout the
   manufacturing process.
2. **`Manuf` State**: Programming the remaining production fuses, such as vendor
   public key hashes and revocation fields.

To facilitate provisioning fuses at various manufacturing stages, including
during wafer sort and final test on ATE, we create small, dedicated, bare-metal
binaries to burn fuses that can be loaded into SRAM over JTAG and executed.

For more information on the provisioning process, see [the reference
provisioning
guide](https://chipsalliance.github.io/caliptra-web/docs/2.1/mcu/provisioning.html)


## Technical Implementation

We will create a build system mechanism to generate bare metal binaries that
program a set of fuses from human readable input files (e.g. HJSON, JSON, etc). 

```mermaid graph TD subgraph Offline Phase [Host / Build System] A["Fuse Values
(hjson)"] -->|Read by| B["Fuse Library (build.rs)"] B -->|Generates|
D["Generated Rust Array"] D -->|Compiled into| F["Bare-metal Binary"]
G["runtime/bare-metal"] -->|Template for| F end

    subgraph Online Phase [Manufacturing / Tester] H["Factory Tester"] -->|1.
    Loads via JTAG| F F -->|2. Runs in SRAM| I["Caliptra MCU"] I -->|3. Writes
    to| J["Fuse Controller"] J -->|4. Blows| K["OTP Fuses"] end ```

### Components

1. **Fuse Library** (
[provisioning/fuses](https://github.com/chipsalliance/caliptra-mcu-sw/tree/main/provisioning/fuses)):
In order to signal the bare-metal code which fuse values to burn, we have a
compile-time code generation library that, at build time, takes an `hjson` file
with all the fuse names and values and generates a Rust array of the specific
memory addresses and values that the bare-metal binary can import.

2. **Bare-metal Binary** (Leveraging
[runtime/bare-metal](https://github.com/chipsalliance/caliptra-mcu-sw/tree/main-2.1/runtime/bare-metal)):
This is a small bare-metal program outside of the operating system whose sole
job is to take the list of fuses in the aforementioned library and write them
into the chip's OTP memory. We want to use bare-metal binaries here to keep them
small and thus reduce the necessary time on the tester.
    * There currently exists a base implementation of bare-metal (non-Tock)
      binaries, but some improvements are also proposed:
        * **Centralized Platform Profiles**: Move memory maps and I/O addresses
          out of individual crate manifests and into central platform profiles
          within the `firmware-bundler`. This allows binaries to support FPGA or
          Emulator by simply specifying the target platform in a more minimal
          manifest/config file.
        * **Code-Level Configuration Generation**: Have the `firmware-bundler`
          generate a Rust source file with platform-specific constants (like
          UART addresses) at build time. This removes the need for hardcoded
          values in the bare-metal source code and ensures portability across
          simulation and hardware.

### JTAG Side Loading

The provisioning process relies on loading the bare-metal binary into the MCU's
SRAM and controlling its execution over JTAG. JTAG is used because it is ATE
friendly and relatively fast if the binary size is small.

The key operations and registers involved in this process are:

* **SRAM Mapping**: The tester writes the compiled binary directly into the
  MCU's SRAM using system bus access over JTAG.
* **Execution Control**: The tester halts the CPU and updates the Debug Program
  Counter (**`dpc`** CSR) to point to the start address of the loaded binary in
  SRAM before resuming execution.
* **Completion Signaling**: The tester configures the Debug Control and Status
  Register (**`dcsr`** CSR) to enable `ebreak` in machine mode (via the
  `ebreakm` bit). This allows the sideloaded binary to signal completion by
  executing an `ebreak` instruction, which halts the CPU and yields control back
  to the tester.

This flow is validated by the
[verify_execute_from_sram](https://github.com/chipsalliance/caliptra-mcu-sw/blob/main-2.1/tests/integration/src/jtag/mod.rs#L107)
test helper, which is executed in some of the unlock tests and confirms that we
can successfully load code and jump the program counter to execute it.

## Alternatives Considered

### Separate Data Files (Data Blobs)

Instead of baking the translated fuse configuration directly into the bare-metal
binary, we considered keeping them separate.

In this scenario, we would build a single, generic binary that contains only the
logic for writing to fuses, but no data. The tester would load this generic
program onto the chip, and then load a separate small data file containing the
specific fuse values into another part of the SRAM. The program would then read
that data file to know what to blow.

This approach is more flexible and is well-suited to managing a large number of
SKUs or otherwise scenarios with a large variety in desired fuse values, because
you only need to maintain one version of the binary and many small data files.

However, it adds complexity, as it requires defining a format to store the fuse
values as well as adding to the binary the ability to safely find and read that
separate data file. Compiling the data directly into the program keeps the
binary simpler, even if it means managing a couple of different versions for the
different setup stages.

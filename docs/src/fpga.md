# Running with an FPGA

## Cross compiling

### Linux binaries

You can use [`cross-rs`](https://github.com/cross-rs/cross) to make it easier to cross compile binaries for the FPGA host.

For example,

```shell
CARGO_BUILD_TARGET=aarch64-unknown-linux-gnu CARGO_TARGET_DIR=target/build/aarch64-unknown-linux-gnu cross build -p xtask --features fpga_realtime --bin xtask --target=aarch64-unknown-linux-gnu
```

will build the a binary that runs `xtask` that can be used on the FPGA, which can then be used to install the FPGA kernel modules (assuming the `caliptra-mcu-sw` repository is checked out and the `xtask` binary is renamed to `xtask-bin`):

```shell
./xtask-bin fpga-install-kernel-modules
```

or to run a set of ROMs and firmware:

```shell
./xtask-bin fpga-run --zip all-fw.zip
```

### Firmware files

You can build firmware binaries (ROM, runtime, manifest, etc.) using a combination of:

* `cargo xtask rom-build --platform fpga`
* `cargo xtask runtime-build --platform fpga`
* `cargo xtask all-build --platform fpga`

The `all-build` command will build Caliptra ROM, Caliptra firmware bundle, MCU ROM, MCU runtime, and the SoC manifest and package them all together in a ZIP file, which the `fpga-run` xtask can run.

These commands can be run on any host. It is not recommended to run them on the FPGA host as it is very slow (the build can take over an hour the first time); instead it is better to run the command on a different host and use `scp` or `rsync` to copy the ZIP in.

## Running ROM and firmware

`cargo xtask fpga-run` or `./xtask-bin fpga-run` can be used to run ROMs and firmware, either directly or from a ZIP file, e.g.,

```shell
./xtask-bin fpga-run --zip all-fw.zip
```

It also supports additional command-line options for testing various flows.

## UDS Provisioning

### Preliminaries

1. Build OpenOCD 0.12.0 with `--enable-sysfsgpio`.
2. Install gdb-multiarch
3. Run a ROM flow with a blank OTP memory to transition the lifecycle state to `TestUnlocked0`.
4. Run a ROM to burn lifecycle tokens for the other transitions.
5. Run a ROM flow to transition the lifecycle state to `Dev` (this maps to the Manufacturing device lifecycle for Caliptra).
6. Start a run with the bootfsm_break set to 1.
7. Start the OpenOCD server:

```
sudo openocd --file openocd_caliptra.txt
```

8. Connect to OpenOCD

```
telnet localhost 4444
```

9. Verify connectivity in telnet:

```
> riscv.cpu riscv dmi_read 0x74
0xcccccccc
```

10. Write the request
```
> riscv.cpu riscv dmi_write 0x70 4
> riscv.cpu riscv dmi_write 0x61 1
```

## OTP

There is an example fully provisioned (UDS and FE burned and transitioned into
production) `.vmem` file for loading into the OTP via the `--otp` in the
repository in
[`otp-prod-fe.vmem`](https://github.com/chipsalliance/caliptra-mcu-sw/blob/main/otp-prod-fe.mem).

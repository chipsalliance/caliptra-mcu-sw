# Testing with an FPGA

## Pre Requisites

### Host System 

The machine that is used for development and cross compilation should have:

- Rust
- Docker
- rsync
- git

### FPGA System 

The FPGA should have the following installed:

- rsync
- git
- make
- gcc

**Suggestion**: Download the latest FPGA Image from the Caliptra-SW main-2.x branch's FPGA Image build [job](https://github.com/chipsalliance/caliptra-sw/actions/workflows/fpga-image.yml?query=branch%3Amain-2.x). This ensures you are testing with the same system used in the FPGA CI.

## Suggested Development Flow

Prefer to develop on your main machine and use xtask to test your changes on the FPGA via ssh.

### Setup SSH config

xtask will access the FPGA over SSH. You will need an SSH config to define how to do this.

This config should be added to `~/.ssh/config`.

```
Host <FPGA-NAME> # Update me!
  Hostname <FPGA-IP-ADDRESS> # Update me!
  User ubuntu # Use "root" on CI image.

```

## Cross compiling

### Firmware

Run `cargo xtask-fpga fpga build --target-host $SSH-FPGA-NAME` to create a firmware bundle. Using the `--target-host` flag will automatically copy the firmware to the FPGA host.

This command should be re-run after making any firmware changes.

### Test Binaries

Run `cargo xtask-fpga fpga build-test --target-host $SSH-FPGA-NAME` to create a test archive. Using the `--target-host` flag will automatically copy the test binaries to the FPGA host.

This command should be re-run after making any test changes.

## FPGA bootstrap

The FPGA needs to be bootstrapped each time it is booted. This ensures that the kernel modules we use in this repo are present.

Run `cargo xtask-fpga fpga bootstrap --target-host $SSH-FPGA-NAME` to bootstrap the FPGA.

# Test Workflow

## FPGA Bootstrapping and FW/Test Building

A developer verifying changes against an FPGA should use the following sequence of commands to bootstrap their FPGA board by:
1. downloading the caliptra-mcu-sw repo on their board,
2. building all Caliptra Core and MCU firmware collateral, and
3. building all FPGA tests for the FPGA environment.

```
$ cargo xtask-fpga fpga bootstrap --target-host $SSH-FPGA-NAME # Run this only once per boot.
$ cargo xtask-fpga fpga build --target-host $SSH-FPGA-NAME # Build firmware. Re-run every time firmware changes.
$ cargo xtask-fpga fpga build-test --target-host $SSH-FPGA-NAME # Build test binaries. Re-run every time tests change.
```

## Dispatching all FPGA Tests

A developer verifying changes against an FPGA can dispatch the entire FPGA test in a single shot by running:

```
$ cargo xtask-fpga fpga test --target-host $SSH-FPGA-NAME
```

## Dispatching a Single FPGA Test

A developer that only wishes to run a single test on the FPGA can replace the last command with the following:

```
# For example:
$ cargo xtask-fpga fpga test --target-host $SSH-FPGA-NAME \
    --test-filter="package(mcu-hw-model) and test(test_hash_token)"
```

# Test Caliptra Core on FPGA

The xtask workflow also supports running caliptra-sw tests on a subsystem FPGA.

## Bootstrap and Build Test Binaries / FW

```
$ cargo xtask-fpga fpga bootstrap --target-host $SSH-FPGA-NAME --configuration core-on-subsystem # Run this only once per boot. Re-run bootstrap to change configurations
$ cargo xtask-fpga fpga build --target-host $SSH-FPGA-NAME --caliptra-sw $CALIPTRA_SW_DIR # Build firmware. Re-run every time firmware changes. Must pass path to caliptra-sw repo. Cargo.toml must set the caliptra-sw dependencies to "../caliptra-sw".
$ cargo xtask-fpga fpga build-test --target-host $SSH-FPGA-NAME --caliptra-sw $CALIPTRA_SW_DIR # Build test binaries. Re-run every time tests change. Must pass path to caliptra-sw repo. Cargo.toml must set the caliptra-sw dependencies to "../caliptra-sw".
```

# Running on FPGA

### Firmware files

You can build firmware binaries (ROM, runtime, manifest, etc.) using a combination of:

* `cargo xtask-fpga rom-build --platform fpga`
* `cargo xtask-fpga runtime-build --platform fpga`
* `cargo xtask-fpga all-build --platform fpga`

The `all-build` command will build Caliptra ROM, Caliptra firmware bundle, MCU ROM, MCU runtime, and the SoC manifest and package them all together in a ZIP file, which the `fpga-run` xtask can run.

These commands can be run on any host. It is not recommended to run them on the FPGA host as it is very slow (the build can take over an hour the first time); instead it is better to run the command on a different host and use `scp` or `rsync` to copy the ZIP in.

## Running ROM and firmware

`cargo xtask-fpga fpga-run` or `./xtask-bin fpga-run` can be used to run ROMs and firmware, either directly or from a ZIP file, e.g.,

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

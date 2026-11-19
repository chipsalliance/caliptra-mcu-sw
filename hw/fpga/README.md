<!-- Licensed under the Apache-2.0 license -->

# Caliptra Subsystem FPGA Runtime & JTAG Assets

All Subsystem FPGA RTL wrapper sources, Vivado build scripts (`fpga_configuration.tcl`), bitstream build workflows, and NixOS SD card image definitions have been consolidated into [`chipsalliance/caliptra-infra`](https://github.com/chipsalliance/caliptra-infra):

- **FPGA RTL & Bitstream Builds**: [`chipsalliance/caliptra-infra/hw/2.0/subsystem/`](https://github.com/chipsalliance/caliptra-infra/tree/main/hw)
- **NixOS FPGA SD Card Images**: [`chipsalliance/caliptra-infra/ci-tools/fpga-image/`](https://github.com/chipsalliance/caliptra-infra/tree/main/ci-tools/fpga-image)

## Retained Runtime Files

- **`bitstream_manifests/subsystem.toml`**: Pinned prebuilt subsystem bitstream manifest downloaded by CI and `cargo xtask-fpga`.
- **`launch_openocd.sh`, `openocd_ss.txt`**: OpenOCD JTAG launch script and configuration for Core, MCU, and LCC TAPs.
- **`kernel-modules/`**: Legacy UIO/backdoor kernel module sources for non-NixOS developer setups.

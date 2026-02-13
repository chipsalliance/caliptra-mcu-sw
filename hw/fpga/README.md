_*SPDX-License-Identifier: Apache-2.0<BR>
<BR>
<BR>
Licensed under the Apache License, Version 2.0 (the "License");<BR>
you may not use this file except in compliance with the License.<BR>
You may obtain a copy of the License at<BR>
<BR>
http://www.apache.org/licenses/LICENSE-2.0 <BR>
<BR>
Unless required by applicable law or agreed to in writing, software<BR>
distributed under the License is distributed on an "AS IS" BASIS,<BR>
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.<BR>
See the License for the specific language governing permissions and<BR>
limitations under the License.*_<BR>

# **Caliptra FPGA Guide** #
FPGA provides a fast environment for software development and testing that is built on Caliptra Core and Subsystem RTL.
The ARM CPU takes the place of an SOC manager and can drive stimulus to Caliptra SS over an AXI bus. In addition the Caliptra Core, MCU, and LCC JTAGs are connected to GPIO pins for debug and testing from the ARM CPU.

### FPGA Block Diagram Components ###
- Wrapper Registers
  - Controls resets, straps, and FPGA wrapper utilities such as the log and debug FIFOs.
- AXI Interconnect
  - SS requires the integrator to connect the various SS AXI busses to an interconnect to allow MMIO access both from the SOC manager and SS components with an AXI manager interface.
- Backdoor memory interfaces
  - The Caliptra Core, MCU, and OTP ROMs are implemented as dual port SRAM's to allow them to be reconfigured without rebuilding. These SRAMs are mapped into the ARM CPU to allow them to be written by the hw-model before taking SS out of reset.
- Xilinx I3C
  - The FPGA instantiates an I3C host controller to communicate with the SS I3C. In order for the I3C controllers to reach I3C bus speeds a higher clock is needed. The FPGA modifies caliptra_ss_top to insert CDC logic and run the SS I3C at the same clock.

![](./images/caliptra_ss_fpga_block_diagram.svg)

### Requirements: ###
 - Vivado
   - Version v2022.2 or 2024.2
 - PetaLinux Tools
   - Version must match Vivado
 - FPGA
   - [VCK190](https://www.xilinx.com/products/boards-and-kits/vck190.html)

### Versal ###
#### Processing system one time setup: ####
1. Download Ubuntu VCK190 SD card image and install to a microSD card. The Versal is packaged with a blank microSD card in the box that can be used for the OS.
   - Insert the OS SD card into the slot on top of the board.
     - The slot below the board is for the System Controller and the card there should be left inserted.
   - https://ubuntu.com/download/amd-xilinx
1. Configure SW1 to boot from SD1: [Image](./images/versal_boot_switch.jpg)
   - Mode SW1[4:1]: OFF, OFF, OFF, ON
1. Boot from the SD card.
   - Initial boot requires connecting over serial. The first serial port is for the PS. See below for settings.
   - Initial credentials
     - User: ubuntu Pass: ubuntu
   - Update the date to avoid apt/git failures
     ```
     sudo dpkg-reconfigure tzdata
     sudo date -s 'yyyy-mm-dd hh:mm'
     ```
   - Install software dependencies - *Do not update the system*
     ```shell
     sudo apt update
     sudo apt install make gcc
     ```
   - Install rustup using Unix directions: https://rustup.rs/#
     ```
     curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
     ```
   - [Optional] Assign a hostname for SSH access.
   - [Optional] Save uboot environment variables to avoid the MAC being randomized each boot.
     - When connected to the serial port interrupt uboot at the message "Hit any key to stop autoboot:  0"
     - Issue ```saveenv``` command to uboot, which creates an env file in the boot partition for use in subsequent boots.

#### Serial port configuration: ####
The USB Type-C connecter J207 on the VCK190 provides UART and JTAG access to the board using an FTDI USB to quad UART/Serial converter.
1. VCK190 JTAG chain for waveform capture and management.
2. PS UART (First COM port) is a serial port used to access the operating system running on the ARM core.
3. PL UART (Currently unused)
4. System Controller UART (Third COM port)

Serial port settings for the PS UART:
 - Speed: 115200
 - Data bits: 8
 - Stop bits: 1
 - Parity: None
 - Flow control: None

### FPGA build steps: ###
The FPGA build process uses Vivado's batch mode to procedurally create the Vivado project using fpga_configuration.tcl and optionally create the caliptra_build/caliptra_fpga.xsa needed for the next step.
This script provides a number of configuration options for features that can be enabled using "-tclargs OPTION=VALUE OPTION=VALUE"

`vivado -nolog -nojournal -mode batch -source fpga_configuration.tcl -tclargs BUILD=TRUE`

| Option      | Purpose
| ------      | -------
| BUILD=TRUE  | Automatically start building the FPGA.
| GUI=TRUE    | Open the Vivado GUI.

### Build boot.bin: ###
 - Source PetaLinux tools from the PetaLinux installation directory. *PetaLinux Tools must match Vivado version*
   - `source settings.sh`
 - Execute [create_boot_bin.sh](create_boot_bin.sh) to create a BOOT.BIN
   - `./create_boot_bin.sh caliptra_build/caliptra_fpga.xsa`
 - (Optional) After the BOOT.BIN is created once, update_boot_bin.sh can be used to incorporate a new xsa.
   - `./update_boot_bin.sh caliptra_build/caliptra_fpga.xsa`
 - Copy petalinux_project/images/linux/BOOT.BIN to the boot partition as boot1900.bin
   - If the Ubuntu image is booted, it will mount the boot partition at /boot/firmware/
   - If boot1900.bin fails to boot the system will fallback to the default boot1901.bin
   - [!WARNING]
     ```reboot``` seems to skip the image selector and will load from the same filename as the previous boot. If the fallback image is the last one booted then the proper procedure is ```shutdown``` and to toggle the power switch. In the serial boot log the fallback image uses PLM from 2022 while for any valid Caliptra FPGA image the PLM will be 2024.
   ```shell
   sudo su
   cp BOOT.BIN /boot/firmware/boot1900.bin
   reboot
   # OR
   shutdown
   # Toggle power switch
   ```

- Verify the correct image is loaded by checking FPGA wrapper registers.
   - fpga_magic (0xA4010000) contains 0x52545043.
   - fpga_version (0xA4010004) contains the hash of the git HEAD commit.

### Cross compiling tests for FPGA: ###
```shell
# TODO: Fix these flows: https://github.com/chipsalliance/caliptra-mcu-sw/issues/367
# From an X86 build machine create run collateral
cargo xtask-fpga all-build --platform fpga


# Compile and install the kernel module
cargo xtask fpga-install-kernel-modules
```

### Compiling and running Caliptra tests from the FPGA: ###
```shell
# Install dependencies
sudo apt update
sudo apt install make gcc
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Clone this repo
git clone https://github.com/chipsalliance/caliptra-mcu-sw.git
git submodule init
git submodule update


# Compile and install the kernel module
cargo xtask fpga-install-kernel-modules
```

### Adding registers to the FPGA wrapper. ###
The FPGA wrapper module contains several registers that interface with the
hardware model to enable various test cases to drive signals/data in/out of the
Caliptra Subsystem toplevel. To add additional registers simply:

1. Ensure you have the `peakrdl` and `peakrdl-markdown` python packages installed: `pip install peakrdl peakrdl-markdown`.
2. Modify the RDL file in `hw/fpga/src/caliptra_fpga_realtime_regs.rdl` to add the new register descriptions.
3. rerun the autogeneration script:
    a. `cd hw/fpga/src`
    b. `./gen.sh`
4. [optional]: connect the new registers Caliptra Subsystem toplevel if needed
5. Rebuild the bitstream. 

### Common Issues ###
- Caliptra logic missing or system hang when attempting to access FPGA Wrapper
  - ```sudo shutdown now``` and use power switch to reboot system
- Failures accessing GitHub or package repositories
  - Date incorrect. Fix date using: ```sudo date -s 'yyyy-mm-dd hh::mm'```

### Processing System - Programmable Logic interfaces ###
[FPGA Wrapper Registers](fpga_wrapper_regs.md)

#### Versal Memory Map ####
| IP/Peripheral                       | Accessibility        | Address size | Start address | End address |
| :---------------------------------- | -------------------- | :----------- | :------------ | :---------- |
| Caliptra core ROM Backdoor          | Always               | 96 KiB       | 0xB000_0000   | 0xB001_7FFF |
| MCU ROM Backdoor                    | Always               | 128 KiB      | 0xB002_0000   | 0xB003_FFFF |
| MCU ROM AXI Sub (provided by SS)    | cptra_ss_rst_b       | 128 KiB      | 0xB004_0000   | 0xB005_FFFF |
| MCU SRAM                            | Always               | 96 KiB       | 0xB008_0000   | 0xB005_FFFF |
| FPGA Wrapper Registers              | Always               | 8 KiB        | 0xA401_0000   | 0xA401_1FFF |
| SS I3C                              | cptra_ss_rst_b       | 8 KiB        | 0xA403_0000   | 0xA403_1FFF |
| LCC                                 | cptra_ss_rst_b       | 8 KiB        | 0xA404_0000   | 0xA404_1FFF |
| OTP                                 | cptra_ss_rst_b       | 8 KiB        | 0xA406_0000   | 0xA406_1FFF |
| Xilinx I3C                          | cptra_ss_rst_b       | 4 KiB        | 0xA408_0000   | 0xA408_0FFF |
| AXI Firewall Control                | Always               | 4 KiB        | 0xA409_0000   | 0xA409_0FFF |
| Caliptra                            | SS reset to Caliptra | 1 MiB        | 0xA410_0000   | 0xA41F_FFFF |
| MCI                                 | cptra_ss_rst_b       | 16 MiB       | 0xA800_0000   | 0xA8FF_FFFF |

### Waveform Debug ###
If built with DEBUG=TRUE common signals for debug will be connected to ILAs. In addition images may be built with additional debug signals. This is a general procedure for loading a probes file when consuming an image built by someone else. If the image was built locally, this is unnecessary because the probes file will be loaded automatically.
- Open Vivado 2024.2. Under "Tasks" there is an option for "Open Hardware Manager"
- Open target
  - If the machine running Vivado is directly connected over USB it can be opened automatically. Alternatively Vivado can connect to a remote host running the hw-server that is connected to the FPGA.
- Load the ltx
  - Under the "Hardware Device Properties" menu specify the "Probes file" by selecting the "..." button on the right.
- Open the ILA in the main window to view the waveform window.

### JTAG debug
Requirements:
- Security state must have either debug_locked == false or lifecycle == manuf.
- Set "debug = true" in firmware profile to provide line information to GDB.
- openocd 0.12.0 (must be configured with --enable-sysfsgpio)
- gdb-multiarch

#### Debugger launch procedure ####
JTAG connectivity is provided using EMIO GPIO pins bridging the PS and PL. OpenOCD is run on the ARM core and uses SysFs to interface with the GPIO pins. The Caliptra, MCU, and LCC JTAGs are each connected to their own set of EMIO pins and can be used independently.
1. Invoke OpenOCD server
    - `./caliptra-sw/hw/fpga/launch_openocd.sh [core/mcu/lcc]`
1. Connect client(s) for debug
    - GDB: `gdb-multiarch [bin] -ex 'target remote localhost:3333'`
    - Telnet: `telnet localhost 4444`

#### Caliptra SoC interface registers ####
Over Telnet connection to OpenOCD: `riscv.cpu riscv dmi_read [addr]`

#### JTAG testing ####
Test requirements for both OpenOCD and GDB:
- JTAG port is accessible when debug_locked == true or lifecycle == manufacturing. The port is inaccessible otherwise.
- Read access to ROM space using 8, 16, 32, and 64 bit reads.
- Read and write access to DCCM using 8, 16, 32, and 64 bit accesses.
- Access to ICCM using 32 and 64 bit reads, 32 bit writes.
- Access to VEER core registers.
- HW and SW breakpoints halt the CPU.
- Watchpoints on DCCM and Caliptra register access halt the CPU.
 
Test requirements exclusive to GDB:
- Basic commands all work (step, next, frame, info, bt, ni, si, etc.).
 
Test requirements exclusive to OpenOCD:
- Basic commands all work (reg, step, resume, etc.).
- Access to VEER CSRs.
- Access to Debug Module registers.
- Caliptra registers exposed to JTAG RW/RO status matches.

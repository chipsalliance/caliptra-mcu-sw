# I3C driver board pinout left to right
# SDA_UP
# SDA_EN
# SDA_IN
# SDA
# SCL

# FMC-XM119-PMOD RevB01 pinout

# J1 Header left to right
# L02    - AW24 SDA_UP
# L03    - AV22 SDA_EN
# L04    - AU21 SDA_IN
# L00_CC - BD23 SDA
# L05    - BF24 SCL
# L06    - BC20
# L07    - BC25
# L08    - BC22
# GND

# PMOD connector J4 tops-down
# AW24 CS1   - 1 | 7  - PM1 IO5  BF24
# AV22 MOSI1 - 2 | 8  - PM1 IO6  BC20
# AU21 MISO1 - 3 | 9  - PM1 IO7  BC25
# BD23 SCK1  - 4 | 10 - PM1 IO8  BC22
#      GND   - 5 | 11 - GND
#      3p3   - 6 | 12 - 3p3

# Connect SDA
set_property PACKAGE_PIN AW24 [get_ports EXT_SDA_UP]
set_property PACKAGE_PIN AV22 [get_ports EXT_SDA_EN]
set_property PACKAGE_PIN AU21 [get_ports EXT_SDA_IN]
set_property PACKAGE_PIN BD23 [get_ports EXT_SDA]
# Connect SCL
set_property PACKAGE_PIN BF24 [get_ports EXT_SCL]

# Set IOSTANDARD
set_property IOSTANDARD LVCMOS15 [get_ports EXT_SDA_UP]
set_property IOSTANDARD LVCMOS15 [get_ports EXT_SDA_IN]
set_property IOSTANDARD LVCMOS15 [get_ports EXT_SDA_EN]
set_property IOSTANDARD LVCMOS15 [get_ports EXT_SDA]
set_property IOSTANDARD LVCMOS15 [get_ports EXT_SCL]

# SCL is input-only: I3C targets do not clock-stretch, so the FPGA never drives SCL.

# Timing constraints: External I3C pins are asynchronous to FPGA clocks.
# Inputs are synchronized via xpm_cdc_single in caliptra_wrapper_top.sv.
# Outputs are registered in the i3c_clk domain before reaching the pads.
set_false_path -from [get_ports EXT_SCL]
set_false_path -from [get_ports EXT_SDA]
set_false_path -to   [get_ports EXT_SDA_UP]
set_false_path -to   [get_ports EXT_SDA_IN]
set_false_path -to   [get_ports EXT_SDA_EN]

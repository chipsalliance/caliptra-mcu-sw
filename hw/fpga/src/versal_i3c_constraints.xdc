# Pin mapping for pmod-i3c-driver tops-down
#SDA_UP          -  1 | 2  - SCL
#SDA_PULL/SDA_EN -  3 | 4  - SCL_PUSH
#SDA_PUSH/SDA_IN -  5 | 6  - SCL_PULL
#SDA             -  7 | 8  - SCL_UP
#GND             -  9 | 10 - GND
#3v3             - 11 | 12 - 3v3

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
#set_property PACKAGE_PIN BC20 [get_ports EXT_SCL_PUSH]
#set_property PACKAGE_PIN BC25 [get_ports EXT_SCL_PULL]
#set_property PACKAGE_PIN BC22 [get_ports EXT_SCL_UP]

# Set IOSTANDARD
set_property IOSTANDARD LVCMOS15 [get_ports EXT_SDA_UP]
set_property IOSTANDARD LVCMOS15 [get_ports EXT_SDA_IN]
set_property IOSTANDARD LVCMOS15 [get_ports EXT_SDA_EN]
set_property IOSTANDARD LVCMOS15 [get_ports EXT_SDA]
#set_property IOSTANDARD LVCMOS15 [get_ports EXT_SCL_UP]
#set_property IOSTANDARD LVCMOS15 [get_ports EXT_SCL_PUSH]
#set_property IOSTANDARD LVCMOS15 [get_ports EXT_SCL_PULL]
set_property IOSTANDARD LVCMOS15 [get_ports EXT_SCL]

# GND
# L08 - BC22 SCL_UP
# L07 - BC25 SCL_PULL
# L06 - BC20 SCL_PUSH
# L05 - SCL
# L00_CC - BD23 SDA
# L04 - AU21 SDA_PUSH
# L03 - AV22 SDA_PULL
# L02 - AW24 SDA_UP











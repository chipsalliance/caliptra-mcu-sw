# Licensed under the Apache-2.0 license

# Default settings:
set BUILD FALSE
set GUI   FALSE
set OUTPUT_DIR caliptra_build
set ITRNG TRUE
set CG_EN FALSE
set RTL_VERSION latest
set BOARD VCK190
set ITRNG TRUE
set DEBUG FALSE
set FAST_I3C TRUE
set CORE_CLK_MHZ 18
# Xilinx core requires 100 - 300MHz. Actual clock usually rounds down
set I3C_CLK_MHZ 120
# 1000 - 12500
set I3C_SCL_RATE_KHZ 1000

set I3C_OUTSIDE FALSE
set SEGMENTED FALSE
set SEGMENTED_WRITE_NCR FALSE
# Simplistic processing of command line arguments to override defaults
foreach arg $argv {
  regexp {(.*)=(.*)} $arg fullmatch option value
  set $option "$value"
}
# If VERSION was not set by tclargs, set it from the commit ID.
# This assumes it is run from within caliptra-sw. If building from outside caliptra-sw call with "VERSION=[hex number]"
if {[info exists VERSION] == 0} {
  set VERSION [exec git rev-parse --short HEAD]
}

# Create path variables
set fpgaDir [file dirname [info script]]
set outputDir $fpgaDir/$OUTPUT_DIR
set caliptrapackageDir $outputDir/caliptra_package

# Clean and create output directory.
file delete -force $outputDir
file mkdir $outputDir
file mkdir $caliptrapackageDir

# Path to rtl
set ssrtlDir $fpgaDir/../caliptra-ss
set caliptrartlDir $ssrtlDir/third_party/caliptra-rtl
puts "ITRNG: $ITRNG"
puts "CG_EN: $CG_EN"
puts "RTL_VERSION: $RTL_VERSION"
puts "Using RTL directory $caliptrartlDir"

# Set Verilog defines for:
#     Caliptra clock gating module
#     VEER clock gating module
#     VEER core FPGA optimizations (disables clock gating)
if {$CG_EN} {
  set VERILOG_OPTIONS {TECH_SPECIFIC_ICG USER_ICG=fpga_real_icg TECH_SPECIFIC_EC_RV_ICG USER_EC_RV_ICG=fpga_rv_clkhdr}
  set GATED_CLOCK_CONVERSION auto
} else {
  set VERILOG_OPTIONS {TECH_SPECIFIC_ICG USER_ICG=fpga_fake_icg RV_FPGA_OPTIMIZE TEC_RV_ICG=clockhdr}
  set GATED_CLOCK_CONVERSION off
}
if {$ITRNG} {
  # Add option to use Caliptra's internal TRNG instead of ETRNG
  lappend VERILOG_OPTIONS CALIPTRA_INTERNAL_TRNG
}
if {$I3C_OUTSIDE} {
  lappend VERILOG_OPTIONS I3C_OUTSIDE
}
lappend VERILOG_OPTIONS FPGA_VERSION=32'h$VERSION
lappend VERILOG_OPTIONS DIGITAL_IO_I3C
lappend VERILOG_OPTIONS CALIPTRA_MODE_SUBSYSTEM
# Set CALIPTRA to ABR knows it is being used in Caliptra
lappend VERILOG_OPTIONS CALIPTRA

# Start the Vivado GUI for interactive debug
if {$GUI} {
  start_gui
}

if {$BOARD eq "VCK190"} {
  set PART xcvc1902-vsva2197-2MP-e-S
  set BOARD_PART xilinx.com:vck190:part0:3.1
} elseif {$BOARD eq "VMK180"} {
  set PART xcvm1802-vsva2197-2MP-e-S
  set BOARD_PART xilinx.com:vmk180:part0:3.1
} else {
  puts "Board $BOARD not supported"
  exit
}

##### Caliptra Package #####
source create_caliptra_package.tcl
##### Caliptra Package #####

# Create a project for the SOC connections
create_project caliptra_fpga_project $outputDir -part $PART
set_property board_part $BOARD_PART [current_project]
if {$SEGMENTED} {
  set_property segmented_configuration true [current_project]
}

# Include the packaged IP
set_property  ip_repo_paths "$caliptrapackageDir" [current_project]
update_ip_catalog

# Create SOC block design
create_bd_design "caliptra_fpga_project_bd"

# Add Caliptra package
create_bd_cell -type ip -vlnv design:user:caliptra_package_top:1.0 caliptra_package_top_0

#### Add Versal PS ####
source create_versal_cips.tcl

# Create XDC file with jtag constraints
set xdc_fd [ open $outputDir/jtag_constraints.xdc w ]
puts $xdc_fd {create_clock -period 5000.000 -name {cal_jtag_clk} -waveform {0.000 2500.000} [get_pins {caliptra_fpga_project_bd_i/ps_0/inst/pspmc_0/inst/PS9_inst/EMIOGPIO2O[0]}]}
puts $xdc_fd {create_clock -period 5000.000 -name {lcc_jtag_clk} -waveform {0.000 2500.000} [get_pins {caliptra_fpga_project_bd_i/ps_0/inst/pspmc_0/inst/PS9_inst/EMIOGPIO2O[5]}]}
puts $xdc_fd {create_clock -period 5000.000 -name {mcu_jtag_clk} -waveform {0.000 2500.000} [get_pins {caliptra_fpga_project_bd_i/ps_0/inst/pspmc_0/inst/PS9_inst/EMIOGPIO2O[10]}]}
puts $xdc_fd {set_clock_groups -asynchronous -group [get_clocks {cal_jtag_clk}]}
puts $xdc_fd {set_clock_groups -asynchronous -group [get_clocks {lcc_jtag_clk}]}
puts $xdc_fd {set_clock_groups -asynchronous -group [get_clocks {mcu_jtag_clk}]}
puts $xdc_fd {set_false_path -from [get_clocks {clk_pl_0}] -to [get_clocks {cal_jtag_clk}]}
puts $xdc_fd {set_false_path -from [get_clocks {clk_pl_0}] -to [get_clocks {lcc_jtag_clk}]}
puts $xdc_fd {set_false_path -from [get_clocks {clk_pl_0}] -to [get_clocks {mcu_jtag_clk}]}
puts $xdc_fd {set_false_path -from [get_clocks {cal_jtag_clk}] -to [get_clocks {clk_pl_0}]}
puts $xdc_fd {set_false_path -from [get_clocks {lcc_jtag_clk}] -to [get_clocks {clk_pl_0}]}
puts $xdc_fd {set_false_path -from [get_clocks {mcu_jtag_clk}] -to [get_clocks {clk_pl_0}]}
close $xdc_fd

#### Add AXI Infrastructure
create_bd_cell -type ip -vlnv xilinx.com:ip:smartconnect:1.0 axi_interconnect_0
set_property -dict [list \
  CONFIG.NUM_MI {14} \
  CONFIG.NUM_SI {6} \
  CONFIG.NUM_CLKS {2} \
  ] [get_bd_cells axi_interconnect_0]

proc register_axi_subordinate {src_block src_port address size dst addrseg name debug clock} {
  global axi_subordinates

  incr axi_subordinates(ID)
  set id $axi_subordinates(ID)

  set axi_subordinates($id,src_block) $src_block
  set axi_subordinates($id,src_port)   $src_port
  set axi_subordinates($id,address)    $address
  set axi_subordinates($id,size)       $size
  set axi_subordinates($id,dst)        $dst
  set axi_subordinates($id,addrseg)    $addrseg
  set axi_subordinates($id,name)       $name
  set axi_subordinates($id,debug)      $debug
  set axi_subordinates($id,clock)      $clock
}
global axi_subordinates
set axi_subordinates(ID) 0

#                        src_block          src_port address    size       dst                                    addrseg name               debug  clock
register_axi_subordinate axi_interconnect_0 M00_AXI  0xA4100000 0x00100000 caliptra_package_top_0/S_AXI_CALIPTRA  reg0    S_AXI_CALIPTRA     TRUE   "/ps_0/pl0_ref_clk"
register_axi_subordinate axi_interconnect_0 M01_AXI  0xA4030000 0x00002000 caliptra_package_top_0/S_AXI_I3C       reg0    S_AXI_I3C          TRUE   "/ps_0/pl1_ref_clk"
register_axi_subordinate axi_interconnect_0 M13_AXI  0xA4032000 0x00002000 caliptra_package_top_0/S_AXI_I3C_SPARE reg0    S_AXI_I3C_SPARE    TRUE   "/ps_0/pl1_ref_clk"
register_axi_subordinate axi_interconnect_0 M02_AXI  0xA4040000 0x00002000 caliptra_package_top_0/S_AXI_LCC       reg0    S_AXI_LCC          FALSE  "/ps_0/pl0_ref_clk"
register_axi_subordinate axi_interconnect_0 M03_AXI  0xA8000000 0x01000000 caliptra_package_top_0/S_AXI_MCI       reg0    S_AXI_MCI          TRUE   "/ps_0/pl0_ref_clk"
register_axi_subordinate axi_interconnect_0 M04_AXI  0xB0040000 0x00020000 caliptra_package_top_0/S_AXI_MCU_ROM   reg0    S_AXI_MCU_ROM      TRUE   "/ps_0/pl0_ref_clk"
register_axi_subordinate axi_interconnect_0 M05_AXI  0xA4060000 0x00002000 caliptra_package_top_0/S_AXI_OTP       reg0    S_AXI_OTP          TRUE   "/ps_0/pl0_ref_clk"
register_axi_subordinate axi_interconnect_0 M06_AXI  0xA4010000 0x00004000 caliptra_package_top_0/S_AXI_WRAPPER   reg0    S_AXI_WRAPPER      FALSE  "/ps_0/pl0_ref_clk"
register_axi_subordinate axi_interconnect_0 M07_AXI  0xB0080000 0x00010000 otp_ram_bram_ctrl_0/S_AXI              Mem0    S_AXI_OTP_RAM      TRUE   "/ps_0/pl0_ref_clk"
register_axi_subordinate axi_interconnect_0 M08_AXI  0xB00C0000 0x00040000 staging_sram_bram_ctrl_0/S_AXI         Mem0    S_AXI_STAGING_SRAM FALSE  "/ps_0/pl0_ref_clk"
register_axi_subordinate axi_interconnect_0 M09_AXI  0xA4080000 0x00001000 xilinx_i3c_0/S_AXI                     Reg     S_AXI_XILINX_I3C   FALSE  "/ps_0/pl1_ref_clk"
register_axi_subordinate axi_interconnect_0 M10_AXI  0xA4081000 0x00001000 axi_cdma_0/S_AXI_LITE                  Reg     S_AXI_XILINX_DMA   FALSE  "/ps_0/pl0_ref_clk"
register_axi_subordinate axi_interconnect_0 M11_AXI  0xB0000000 0x00018000 cptra_rom_backdoor_bram_0/S_AXI        Mem0    S_AXI_CALIPTRA_ROM FALSE  "/ps_0/pl0_ref_clk"
register_axi_subordinate axi_interconnect_0 M12_AXI  0xB0020000 0x00020000 mcu_rom_backdoor_bram_0/S_AXI          Mem0    S_AXI_SS_ROM       FALSE  "/ps_0/pl0_ref_clk"

# Create reset block
create_bd_cell -type ip -vlnv xilinx.com:ip:proc_sys_reset:5.0 proc_sys_reset_0

#### Add Devices ####

# Add AXI BRAM Controller for backdoor access to Caliptra ROM
create_bd_cell -type ip -vlnv xilinx.com:ip:axi_bram_ctrl:4.1 cptra_rom_backdoor_bram_0
set_property CONFIG.SINGLE_PORT_BRAM {1} [get_bd_cells cptra_rom_backdoor_bram_0]

# Add AXI BRAM Controller for backdoor access to MCU ROM
create_bd_cell -type ip -vlnv xilinx.com:ip:axi_bram_ctrl:4.1 mcu_rom_backdoor_bram_0
set_property CONFIG.SINGLE_PORT_BRAM {1} [get_bd_cells mcu_rom_backdoor_bram_0]

# Add memory for OTP
create_bd_cell -type ip -vlnv xilinx.com:ip:axi_bram_ctrl:4.1 otp_ram_bram_ctrl_0
set_property CONFIG.SINGLE_PORT_BRAM {1} [get_bd_cells otp_ram_bram_ctrl_0]

# Create AXI I3C to act as external I3C
create_bd_cell -type ip -vlnv xilinx.com:ip:axi_i3c:1.0 xilinx_i3c_0
set_property -dict [list \
  CONFIG.ENABLE_PEC {1} \
  CONFIG.HJ_CAPABLE {1} \
  CONFIG.IBI_CAPABLE {1} \
  CONFIG.CMD_RESP_FIFO_DEPTH {64} \
  CONFIG.WR_FIFO_PROG_FULL_THRESHOLD {125} \
  CONFIG.WR_RD_FIFO_DEPTH {128} \
  CONFIG.RW_TIMEOUT {10000} \
  ] [get_bd_cells xilinx_i3c_0]

# Add memory for Staging SRAM
create_bd_cell -type ip -vlnv xilinx.com:ip:axi_bram_ctrl:4.1 staging_sram_bram_ctrl_0
set_property CONFIG.SINGLE_PORT_BRAM {1} [get_bd_cells staging_sram_bram_ctrl_0]
create_bd_cell -type ip -vlnv xilinx.com:ip:emb_mem_gen:1.0 staging_sram_emb_mem_gen_0
set_property CONFIG.MEMORY_DEPTH {65636} [get_bd_cells staging_sram_emb_mem_gen_0]
connect_bd_intf_net [get_bd_intf_pins staging_sram_bram_ctrl_0/BRAM_PORTA] [get_bd_intf_pins staging_sram_emb_mem_gen_0/BRAM_PORTA]
create_bd_cell -type inline_hdl -vlnv xilinx.com:inline_hdl:ilconstant:1.0 ilconstant_0
connect_bd_net [get_bd_pins ilconstant_0/dout] [get_bd_pins staging_sram_emb_mem_gen_0/regcea]

# Add DMA controller
create_bd_cell -type ip -vlnv xilinx.com:ip:axi_cdma:4.1 axi_cdma_0
set_property CONFIG.C_INCLUDE_SG {0} [get_bd_cells axi_cdma_0]

# Create CDC for AXI I3C reset
create_bd_cell -type ip -vlnv xilinx.com:ip:xpm_cdc_gen:1.0 xpm_cdc_gen_0
set_property CONFIG.CDC_TYPE {xpm_cdc_sync_rst} [get_bd_cells xpm_cdc_gen_0]

#### axi_interconnect_0 ####
# AXI Managers
# PS -> AXI Interconnect
connect_bd_intf_net [get_bd_intf_pins $ps_m_axi] [get_bd_intf_pins axi_interconnect_0/S00_AXI]
set_property name M_AXI_ARM [get_bd_intf_nets ps_0_M_AXI_FPD]
# Caliptra M_AXI
connect_bd_intf_net [get_bd_intf_pins caliptra_package_top_0/M_AXI_CALIPTRA] [get_bd_intf_pins axi_interconnect_0/S01_AXI]
set_property name M_AXI_CALIPTRA [get_bd_intf_nets caliptra_package_top_0_M_AXI_CALIPTRA]
# MCU
connect_bd_intf_net [get_bd_intf_pins caliptra_package_top_0/M_AXI_MCU_IFU]  [get_bd_intf_pins axi_interconnect_0/S02_AXI]
connect_bd_intf_net [get_bd_intf_pins caliptra_package_top_0/M_AXI_MCU_LSU]  [get_bd_intf_pins axi_interconnect_0/S03_AXI]
connect_bd_intf_net [get_bd_intf_pins caliptra_package_top_0/M_AXI_MCU_SB]   [get_bd_intf_pins axi_interconnect_0/S04_AXI]
set_property name M_AXI_MCU_IFU [get_bd_intf_nets caliptra_package_top_0_M_AXI_MCU_IFU]
set_property name M_AXI_MCU_LSU [get_bd_intf_nets caliptra_package_top_0_M_AXI_MCU_LSU]
set_property name M_AXI_MCU_SB [get_bd_intf_nets caliptra_package_top_0_M_AXI_MCU_SB]
# XILINX DMA
connect_bd_intf_net [get_bd_intf_pins axi_cdma_0/M_AXI] [get_bd_intf_pins axi_interconnect_0/S05_AXI]

#### Connect axi subordinates to the interconnects ####
for {set i 1} {$i <= $axi_subordinates(ID)} {incr i} {
  puts "$i $axi_subordinates($i,name)"
  connect_bd_intf_net -intf_net $axi_subordinates($i,name) /$axi_subordinates($i,src_block)/$axi_subordinates($i,src_port) /$axi_subordinates($i,dst)
  if {$axi_subordinates($i,debug)} {
    set_property HDL_ATTRIBUTE.DEBUG true [get_bd_intf_nets "$axi_subordinates($i,name)"]
  }
}

# Create reset connections
connect_bd_net [get_bd_pins $ps_pl_resetn] [get_bd_pins proc_sys_reset_0/ext_reset_in]
connect_bd_net -net proc_sys_reset_0_peripheral_aresetn \
  [get_bd_pins proc_sys_reset_0/peripheral_aresetn] \
  [get_bd_pins axi_apb_bridge_0/s_axi_aresetn] \
  [get_bd_pins axi_interconnect_0/aresetn] \
  [get_bd_pins caliptra_package_top_0/S_AXI_WRAPPER_ARESETN] \
  [get_bd_pins cptra_rom_backdoor_bram_0/s_axi_aresetn] \
  [get_bd_pins mcu_rom_backdoor_bram_0/s_axi_aresetn] \
  [get_bd_pins otp_ram_bram_ctrl_0/s_axi_aresetn] \
  [get_bd_pins axi_cdma_0/s_axi_lite_aresetn] \
  [get_bd_pins staging_sram_bram_ctrl_0/s_axi_aresetn]
# Connect auxillary reset source to package
connect_bd_net [get_bd_pins caliptra_package_top_0/axi_reset] [get_bd_pins proc_sys_reset_0/aux_reset_in]

# Create clock connections
connect_bd_net \
  [get_bd_pins $ps_pl_clk] \
  [get_bd_pins $ps_axi_aclk] \
  [get_bd_pins proc_sys_reset_0/slowest_sync_clk] \
  [get_bd_pins axi_interconnect_0/aclk] \
  [get_bd_pins caliptra_package_top_0/core_clk] \
  [get_bd_pins cptra_rom_backdoor_bram_0/s_axi_aclk] \
  [get_bd_pins mcu_rom_backdoor_bram_0/s_axi_aclk] \
  [get_bd_pins otp_ram_bram_ctrl_0/s_axi_aclk] \
  [get_bd_pins axi_cdma_0/s_axi_lite_aclk] \
  [get_bd_pins axi_cdma_0/m_axi_aclk] \
  [get_bd_pins staging_sram_bram_ctrl_0/s_axi_aclk]
# Create clock connection for I3C
if {$FAST_I3C} {
  # Use faster clock so that I3C bus speed is correct.
  connect_bd_net \
    [get_bd_pins ps_0/pl1_ref_clk] \
    [get_bd_pins axi_interconnect_0/aclk1] \
    [get_bd_pins caliptra_package_top_0/i3c_clk] \
    [get_bd_pins xilinx_i3c_0/s_axi_aclk] \
    [get_bd_pins xpm_cdc_gen_0/dest_clk]
} else {
  # Use regular clock for i3c to avoid timing problems
  connect_bd_net \
    [get_bd_pins $ps_pl_clk] \
    [get_bd_pins axi_interconnect_0/aclk1] \
    [get_bd_pins caliptra_package_top_0/i3c_clk] \
    [get_bd_pins xilinx_i3c_0/s_axi_aclk] \
    [get_bd_pins xpm_cdc_gen_0/dest_clk]
}

### Connect BRAM controllers to FPGA wrapper ###
connect_bd_intf_net [get_bd_intf_pins caliptra_package_top_0/rom_backdoor]     [get_bd_intf_pins cptra_rom_backdoor_bram_0/BRAM_PORTA]
connect_bd_intf_net [get_bd_intf_pins caliptra_package_top_0/mcu_rom_backdoor] [get_bd_intf_pins mcu_rom_backdoor_bram_0/BRAM_PORTA]
connect_bd_intf_net [get_bd_intf_pins caliptra_package_top_0/otp_mem_backdoor] [get_bd_intf_pins otp_ram_bram_ctrl_0/BRAM_PORTA]

#### I3C Connections ####
if {FALSE} {
  # Connections to I3C driver board
  create_bd_port -dir O -type data SDA_UP
  create_bd_port -dir O -type data SDA_PUSH
  create_bd_port -dir O -type data SDA_PULL
  create_bd_port -dir I -type data SDA
  connect_bd_net [get_bd_pins /caliptra_package_top_0/SDA_UP]   [get_bd_ports SDA_UP]
  connect_bd_net [get_bd_pins /caliptra_package_top_0/SDA_PUSH] [get_bd_ports SDA_PUSH]
  connect_bd_net [get_bd_pins /caliptra_package_top_0/SDA_PULL] [get_bd_ports SDA_PULL]
  connect_bd_net [get_bd_pins /caliptra_package_top_0/SDA]      [get_bd_ports SDA]

  create_bd_port -dir O -type data SCL_UP
  create_bd_port -dir O -type data SCL_PUSH
  create_bd_port -dir O -type data SCL_PULL
  create_bd_port -dir I -type data SCL
  connect_bd_net [get_bd_pins /caliptra_package_top_0/SCL_UP]   [get_bd_ports SCL_UP]
  connect_bd_net [get_bd_pins /caliptra_package_top_0/SCL_PUSH] [get_bd_ports SCL_PUSH]
  connect_bd_net [get_bd_pins /caliptra_package_top_0/SCL_PULL] [get_bd_ports SCL_PULL]
  connect_bd_net [get_bd_pins /caliptra_package_top_0/SCL]      [get_bd_ports SCL]
} else {
  connect_bd_net [get_bd_pins /caliptra_package_top_0/SDA]                   [get_bd_pins xilinx_i3c_0/sda_i]
  connect_bd_net [get_bd_pins /caliptra_package_top_0/axi_i3c_sda_o]         [get_bd_pins xilinx_i3c_0/sda_o]
  connect_bd_net [get_bd_pins /caliptra_package_top_0/axi_i3c_sda_t]         [get_bd_pins xilinx_i3c_0/sda_t]
  connect_bd_net [get_bd_pins /caliptra_package_top_0/axi_i3c_sda_pullup_en] [get_bd_pins xilinx_i3c_0/sda_pullup_en]

  connect_bd_net [get_bd_pins /caliptra_package_top_0/SCL]                   [get_bd_pins xilinx_i3c_0/scl_i]
  connect_bd_net [get_bd_pins /caliptra_package_top_0/axi_i3c_scl_o]         [get_bd_pins xilinx_i3c_0/scl_o]
  connect_bd_net [get_bd_pins /caliptra_package_top_0/axi_i3c_scl_t]         [get_bd_pins xilinx_i3c_0/scl_t]
  connect_bd_net [get_bd_pins /caliptra_package_top_0/axi_i3c_scl_pullup_en] [get_bd_pins xilinx_i3c_0/scl_pullup_en]

  connect_bd_net [get_bd_pins xilinx_i3c_0/s_axi_aresetn] [get_bd_pins xpm_cdc_gen_0/dest_rst_out]
  connect_bd_net [get_bd_pins xpm_cdc_gen_0/src_rst] [get_bd_pins caliptra_package_top_0/xilinx_i3c_aresetn]
}

#### ARM Core USER value ####
connect_bd_net [get_bd_pins caliptra_package_top_0/ARM_USER] [get_bd_pins axi_interconnect_0/S00_AXI_awuser]
connect_bd_net [get_bd_pins caliptra_package_top_0/ARM_USER] [get_bd_pins axi_interconnect_0/S00_AXI_aruser]

#### Assign address segments for all AXI managers ####
set managers {ps_0/M_AXI_FPD caliptra_package_top_0/M_AXI_MCU_IFU caliptra_package_top_0/M_AXI_MCU_LSU caliptra_package_top_0/M_AXI_MCU_SB caliptra_package_top_0/M_AXI_CALIPTRA axi_cdma_0/Data}
set base_offsets {0 0 0 0 0}

foreach manager $managers base_offset $base_offsets {
  for {set i 1} {$i <= $axi_subordinates(ID)} {incr i} {
    puts "Assigning address for $axi_subordinates($i,dst)"
    assign_bd_address -offset [expr $base_offset + $axi_subordinates($i,address)] -range $axi_subordinates($i,size) -target_address_space [get_bd_addr_spaces $manager] [get_bd_addr_segs $axi_subordinates($i,dst)/$axi_subordinates($i,addrseg)] -force
  }
}

# Connect JTAG signals to PS GPIO pins
connect_bd_net [get_bd_pins caliptra_package_top_0/jtag_out] [get_bd_pins $ps_gpio_i]
connect_bd_net [get_bd_pins caliptra_package_top_0/jtag_in] [get_bd_pins $ps_gpio_o]

# Add constraints for JTAG signals
add_files -fileset constrs_1 $outputDir/jtag_constraints.xdc

save_bd_design
puts "Fileset when setting defines the second time: [current_fileset]"
set_property verilog_define $VERILOG_OPTIONS [current_fileset]
puts "\n\nVERILOG DEFINES: [get_property verilog_define [current_fileset]]"

# Create the HDL wrapper for the block design and add it. This will be set as top.
make_wrapper -files [get_files $outputDir/caliptra_fpga_project.srcs/sources_1/bd/caliptra_fpga_project_bd/caliptra_fpga_project_bd.bd] -top
add_files -norecurse $outputDir/caliptra_fpga_project.gen/sources_1/bd/caliptra_fpga_project_bd/hdl/caliptra_fpga_project_bd_wrapper.v
set_property top caliptra_fpga_project_bd_wrapper [current_fileset]

update_compile_order -fileset sources_1

# Assign the gated clock conversion setting in the caliptra_package_top out of context run.
create_ip_run [get_files *caliptra_fpga_project_bd.bd]
set_property STEPS.SYNTH_DESIGN.ARGS.GATED_CLOCK_CONVERSION $GATED_CLOCK_CONVERSION [get_runs caliptra_fpga_project_bd_caliptra_package_top_0_0_synth_1]

# Add DDR pin placement constraints
file copy $fpgaDir/src/ddr4_constraints.xdc $outputDir/ddr4_constraints.xdc
add_files -fileset constrs_1 $outputDir/ddr4_constraints.xdc

# Xilinx I3C requires that the AXI clock be > 14 * SCL_CLK_FREQ. This needs to be set late in the script so that Vivado recognizes the higher AXI clock.
set_property CONFIG.SCL_CLK_FREQ "$I3C_SCL_RATE_KHZ" [get_bd_cells xilinx_i3c_0]

if {$DEBUG} {
  #### Set up ILAs for debug signals ####
  # Mark AXI interfaces for debugging
  set_property HDL_ATTRIBUTE.DEBUG true [get_bd_intf_nets { \
    ps_0_M_AXI_FPD \
      M_AXI_ARM \
      S_AXI_CALIPTRA \
      S_AXI_MCI \
      S_AXI_MCU_ROM \
      S_AXI_OTP \
      M_AXI_MCU_LSU \
      S_AXI_I3C \
      S_AXI_I3C_SPARE \
      M_AXI_CALIPTRA}]

  # Mark signals exposed by the package for debug
  connect_bd_net -net caliptra_ifu_i0_pc [get_bd_pins caliptra_package_top_0/caliptra_ifu_i0_pc]
  set_property HDL_ATTRIBUTE.DEBUG true [get_bd_nets {caliptra_ifu_i0_pc}]
  connect_bd_net -net mcu_ifu_i0_pc [get_bd_pins caliptra_package_top_0/mcu_ifu_i0_pc]
  set_property HDL_ATTRIBUTE.DEBUG true [get_bd_nets {mcu_ifu_i0_pc}]
  connect_bd_net -net ifu_i0_instr [get_bd_pins caliptra_package_top_0/ifu_i0_instr]
  set_property HDL_ATTRIBUTE.DEBUG true [get_bd_nets {ifu_i0_instr}]
  connect_bd_net -net mci_boot_fsm [get_bd_pins caliptra_package_top_0/mci_boot_fsm]
  set_property HDL_ATTRIBUTE.DEBUG true [get_bd_nets {mci_boot_fsm}]
  connect_bd_net -net caliptra_log [get_bd_pins caliptra_package_top_0/caliptra_log]
  set_property HDL_ATTRIBUTE.DEBUG true [get_bd_nets {caliptra_log}]
  connect_bd_net -net dbg_log [get_bd_pins caliptra_package_top_0/dbg_log]
  set_property HDL_ATTRIBUTE.DEBUG true [get_bd_nets {dbg_log}]

  # Mark I3C signals for debugging
  set_property HDL_ATTRIBUTE.DEBUG true [get_bd_nets {caliptra_package_top_0_SCL }]
  set_property HDL_ATTRIBUTE.DEBUG true [get_bd_nets {xilinx_i3c_0_scl_o }]
  set_property HDL_ATTRIBUTE.DEBUG true [get_bd_nets {xilinx_i3c_0_scl_t }]
  set_property HDL_ATTRIBUTE.DEBUG true [get_bd_nets {caliptra_package_top_0_SDA }]
  set_property HDL_ATTRIBUTE.DEBUG true [get_bd_nets {xilinx_i3c_0_sda_o }]
  set_property HDL_ATTRIBUTE.DEBUG true [get_bd_nets {xilinx_i3c_0_sda_t }]
  set_property HDL_ATTRIBUTE.DEBUG true [get_bd_nets {xilinx_i3c_0_sda_pullup_en }]
  set_property HDL_ATTRIBUTE.DEBUG true [get_bd_nets {xilinx_i3c_0_scl_pullup_en }]

  apply_bd_automation -rule xilinx.com:bd_rule:debug -dict [list \
      [get_bd_nets caliptra_package_top_0_SCL] {PROBE_TYPE "Data and Trigger" CLK_SRC "/ps_0/pl1_ref_clk" AXIS_ILA "Auto" } \
      [get_bd_nets caliptra_package_top_0_SDA] {PROBE_TYPE "Data and Trigger" CLK_SRC "/ps_0/pl1_ref_clk" AXIS_ILA "Auto" } \
      [get_bd_nets xilinx_i3c_0_scl_o]         {PROBE_TYPE "Data and Trigger" CLK_SRC "/ps_0/pl1_ref_clk" AXIS_ILA "Auto" } \
      [get_bd_nets xilinx_i3c_0_scl_pullup_en] {PROBE_TYPE "Data and Trigger" CLK_SRC "/ps_0/pl1_ref_clk" AXIS_ILA "Auto" } \
      [get_bd_nets xilinx_i3c_0_scl_t]         {PROBE_TYPE "Data and Trigger" CLK_SRC "/ps_0/pl1_ref_clk" AXIS_ILA "Auto" } \
      [get_bd_nets xilinx_i3c_0_sda_o]         {PROBE_TYPE "Data and Trigger" CLK_SRC "/ps_0/pl1_ref_clk" AXIS_ILA "Auto" } \
      [get_bd_nets xilinx_i3c_0_sda_pullup_en] {PROBE_TYPE "Data and Trigger" CLK_SRC "/ps_0/pl1_ref_clk" AXIS_ILA "Auto" } \
      [get_bd_nets xilinx_i3c_0_sda_t]         {PROBE_TYPE "Data and Trigger" CLK_SRC "/ps_0/pl1_ref_clk" AXIS_ILA "Auto" } \
      [get_bd_nets si_r_error]                 {PROBE_TYPE "Data and Trigger" CLK_SRC "/ps_0/pl0_ref_clk" AXIS_ILA "Auto" } \
      [get_bd_nets si_w_error]                 {PROBE_TYPE "Data and Trigger" CLK_SRC "/ps_0/pl0_ref_clk" AXIS_ILA "Auto" } \
      [get_bd_nets caliptra_ifu_i0_pc]         {PROBE_TYPE "Data and Trigger" CLK_SRC "/ps_0/pl0_ref_clk" AXIS_ILA "Auto" } \
      [get_bd_nets mcu_ifu_i0_pc]              {PROBE_TYPE "Data and Trigger" CLK_SRC "/ps_0/pl0_ref_clk" AXIS_ILA "Auto" } \
      [get_bd_nets ifu_i0_instr]               {PROBE_TYPE "Data and Trigger" CLK_SRC "/ps_0/pl0_ref_clk" AXIS_ILA "Auto" } \
      [get_bd_nets mci_boot_fsm]               {PROBE_TYPE "Data and Trigger" CLK_SRC "/ps_0/pl0_ref_clk" AXIS_ILA "Auto" } \
      [get_bd_nets caliptra_log]               {PROBE_TYPE "Data and Trigger" CLK_SRC "/ps_0/pl0_ref_clk" AXIS_ILA "Auto" } \
      [get_bd_nets dbg_log]                    {PROBE_TYPE "Data and Trigger" CLK_SRC "/ps_0/pl0_ref_clk" AXIS_ILA "Auto" } \
    ]
  for {set i 1} {$i <= $axi_subordinates(ID)} {incr i} {
    puts "$i $axi_subordinates($i,name)"
    if {$axi_subordinates($i,debug)} {

      apply_bd_automation -rule xilinx.com:bd_rule:debug -dict [list [get_bd_intf_nets $axi_subordinates($i,name)] [list AXI_R_ADDRESS "Data and Trigger" AXI_R_DATA "Data and Trigger" AXI_W_ADDRESS "Data and Trigger" AXI_W_DATA "Data and Trigger" AXI_W_RESPONSE "Data and Trigger" CLK_SRC $axi_subordinates($i,clock) AXIS_ILA "Auto" APC_EN "0" ]]
    }
  }

  set_property CONFIG.C_DATA_DEPTH {8192} [get_bd_cells axis_ila_0]
  set_property CONFIG.C_INPUT_PIPE_STAGES {2} [get_bd_cells axis_ila_0]
  set_property CONFIG.C_INPUT_PIPE_STAGES {2} [get_bd_cells axis_ila_1]
}
save_bd_design

# Set initial boot property to make the NOC connections part of the boot PDI.
if {$SEGMENTED} {
  set_property initial_boot true [get_noc_logical_paths]
}

# Load a previous NCR
if {$SEGMENTED} {
  read_noc_solution -file $fpgaDir/saved_noc_solution.ncr
}

# Start build
if {$BUILD} {
  set time_start_synth [clock clicks -millisec]
  launch_runs synth_1 -jobs 32
  wait_on_runs synth_1
  set time_finish_synth [clock clicks -millisec]

  set time_start_impl [clock clicks -millisec]
  launch_runs impl_1 -to_step write_device_image -jobs 32
  wait_on_runs impl_1
  set time_finish_impl [clock clicks -millisec]

  set time_start_hw_platform [clock clicks -millisec]
  open_run impl_1
  report_utilization -file $outputDir/utilization.txt
  if {$SEGMENTED} {
    if {$SEGMENTED_WRITE_NCR} {
      # Lock the NoC path segments and save the solution for later builds.
      set_property lock true [get_noc_net_routes -of [get_noc_logical_paths -filter {initial_boot == 1}]]
      write_noc_solution -file $fpgaDir/saved_noc_solution.ncr
      file copy -force $outputDir/caliptra_fpga_project.runs/impl_1/caliptra_fpga_project_bd_wrapper_routed.dcp $fpgaDir/fpga_2px_golden_routed.dcp
      puts stderr "Replace file in GCS bucket: [exec realpath $fpgaDir/fpga_2px_golden_routed.dcp]"
    } else {
      # Verify that the NoC Solutions are identical and the PLD images are compatible.
      exec curl -s -O "https://storage.googleapis.com/caliptra-github-ci-bitstreams/scratch/fpga_2px_golden_routed.dcp"
      pr_verify -initial $fpgaDir/fpga_2px_golden_routed.dcp -additional $outputDir/caliptra_fpga_project.runs/impl_1/caliptra_fpga_project_bd_wrapper_routed.dcp
    }
    # Copy the PDI containing runtime info to a more convenient location.
    file copy $outputDir/caliptra_fpga_project.runs/impl_1/caliptra_fpga_project_bd_wrapper_pld.pdi $outputDir/runtime_$VERSION.pdi
  }

  write_hw_platform -fixed -include_bit -force -file $outputDir/caliptra_fpga.xsa
  set time_finish_hw_platform [clock clicks -millisec]

  puts stderr "FPGA Synthesis      took [expr {($time_finish_synth-$time_start_synth)/60000.}] minutes"
  puts stderr "FPGA Implementation took [expr {($time_finish_impl-$time_start_impl)/60000.}] minutes"
  puts stderr "FPGA Write HW Plat  took [expr {($time_finish_hw_platform-$time_start_hw_platform)/60000.}] minutes"
  puts stderr "FPGA overall build  took [expr {($time_finish_hw_platform-$time_start_synth)/60000.}] minutes"

  set build_time [ open $outputDir/build_time.txt w ]
  puts $build_time "Built from $VERSION"
  puts $build_time "FPGA Synthesis      took [expr {($time_finish_synth-$time_start_synth)/60000.}] minutes"
  puts $build_time "FPGA Implementation took [expr {($time_finish_impl-$time_start_impl)/60000.}] minutes"
  puts $build_time "FPGA Write HW Plat  took [expr {($time_finish_hw_platform-$time_start_hw_platform)/60000.}] minutes"
  puts $build_time "FPGA overall build  took [expr {($time_finish_hw_platform-$time_start_synth)/60000.}] minutes"
  close $build_time
}

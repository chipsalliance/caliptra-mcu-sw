# SPDX-License-Identifier: Apache-2.0
#
# Caliptra-SS FPGA platform for HiTech Global HTG-940 / XCVU13P.
#
# This script is intentionally separate from fpga_configuration.tcl.  The
# original script targets VCK190/VMK180 and depends on Versal CIPS, the ARM PS,
# PS GPIO, the Versal NoC, DDR, and PDI generation.  HTG-940 has no PS, so the
# Caliptra and MCU AXI managers are the only boot-time bus managers.
#
# Board-specific pins are supplied through HTG_XDC. Example:
#   vivado -mode batch -source fpga_configuration_htg940.tcl \
#     -tclargs HTG_XDC=/absolute/path/htg940_vu13p.xdc BUILD=TRUE

# -----------------------------------------------------------------------------
# Defaults (each may be overridden with NAME=value in -tclargs)
# -----------------------------------------------------------------------------
set BUILD               FALSE
set GUI                 FALSE
set OUTPUT_DIR          caliptra_build_htg940_hw
set PART                xcvu13p-fhgb2104-3-e
set BOARD               HTG940
set HTG_XDC             ""
set ITRNG               TRUE
set CG_EN               FALSE
set RTL_VERSION         latest
set DEBUG               FALSE
set FAST_I3C            TRUE
set CORE_CLK_MHZ        18
set I3C_CLK_MHZ         120
set I3C_SCL_RATE_KHZ    1000
set I3C_OUTSIDE         FALSE
set STUB_ADAMS_BRIDGE FALSE
set STUB_ECC FALSE
set MCU_USB_ONLY FALSE
set FW_IMAGE_DIR        ""

foreach arg $argv {
  if {![regexp {^([^=]+)=(.*)$} $arg _ option value]} {
    error "Invalid argument '$arg'; expected NAME=value"
  }
  set $option $value
}

if {$BUILD} {
  error "Hardware preparation only: entropy and remaining board I/O must be completed before BUILD=TRUE."
}

if {$BOARD ne "HTG940"} {
  error "This script supports BOARD=HTG940 only (received '$BOARD')"
}

if {![info exists VERSION]} {
  set VERSION [exec git rev-parse --short HEAD]
}

# -----------------------------------------------------------------------------
# Paths and generated output
# -----------------------------------------------------------------------------
set fpgaDir            [file normalize [file dirname [info script]]]
set outputDir          [file normalize [file join $fpgaDir $OUTPUT_DIR]]
set caliptrapackageDir [file join $outputDir caliptra_package]
set ssrtlDir           [file normalize [file join $fpgaDir .. caliptra-ss]]
set caliptrartlDir     [file join $ssrtlDir third_party caliptra-rtl]

if {$FW_IMAGE_DIR eq ""} {
  set FW_IMAGE_DIR [file normalize \
    [file join $fpgaDir .. .. target htg940-fw-extracted]]
} else {
  set FW_IMAGE_DIR [file normalize $FW_IMAGE_DIR]
}

if {![file isdirectory $ssrtlDir]} {
  error "Caliptra-SS directory not found: $ssrtlDir"
}
if {![file isdirectory $caliptrartlDir]} {
  error "Caliptra RTL directory not found: $caliptrartlDir"
}

file delete -force $outputDir
file mkdir $outputDir
file mkdir $caliptrapackageDir

puts "HTG-940 part:             $PART"
puts "Caliptra-SS directory:    $ssrtlDir"
puts "Caliptra Core directory:  $caliptrartlDir"
puts "Output directory:         $outputDir"
puts "Core clock:               ${CORE_CLK_MHZ} MHz"
puts "I3C clock:                ${I3C_CLK_MHZ} MHz"
puts "Firmware image directory: $FW_IMAGE_DIR"
# HTG940_STANDALONE_FIRMWARE_BRAM
# Build a complete 2 MiB image: Slot A contains flash_image.bin; Slot B and
# service partitions start erased.  The memory remains writable after boot.
set flashImageBin [file join $FW_IMAGE_DIR flash_image.bin]
set flashImageCoe [file join $FW_IMAGE_DIR htg940_firmware_flash_2m.coe]
set flashConverter [file join $fpgaDir bin_to_flash_coe.py]
if {![file isfile $flashImageBin]} {
  error "Missing HTG-940 firmware image: $flashImageBin"
}
if {![file isfile $flashConverter]} {
  error "Missing HTG-940 flash converter: $flashConverter"
}
exec python3 $flashConverter \
  --input $flashImageBin \
  --output $flashImageCoe \
  --capacity 2097152
puts "HTG-940 firmware BRAM image: $flashImageCoe"

# -----------------------------------------------------------------------------
# RTL compile options
# -----------------------------------------------------------------------------
if {$CG_EN} {
  set VERILOG_OPTIONS {
    TECH_SPECIFIC_ICG
    USER_ICG=fpga_real_icg
    TECH_SPECIFIC_EC_RV_ICG
    USER_EC_RV_ICG=fpga_rv_clkhdr
  }
  set GATED_CLOCK_CONVERSION auto
} else {
  set VERILOG_OPTIONS {
    TECH_SPECIFIC_ICG
    USER_ICG=fpga_fake_icg
    RV_FPGA_OPTIMIZE
    TEC_RV_ICG=clockhdr
  }
  set GATED_CLOCK_CONVERSION off
}

if {$ITRNG} {
  lappend VERILOG_OPTIONS CALIPTRA_INTERNAL_TRNG
}
if {$I3C_OUTSIDE} {
  lappend VERILOG_OPTIONS I3C_OUTSIDE
}
lappend VERILOG_OPTIONS FPGA_VERSION=32'h$VERSION
lappend VERILOG_OPTIONS DIGITAL_IO_I3C
lappend VERILOG_OPTIONS CALIPTRA_MODE_SUBSYSTEM
lappend VERILOG_OPTIONS CALIPTRA

if {$GUI} {
  start_gui
}

# create_caliptra_package.tcl consumes PART, BOARD, VERILOG_OPTIONS,
# GATED_CLOCK_CONVERSION, outputDir, and caliptrapackageDir from this scope.
# HTG940_ENTROPY_CONTROL_V1: hardware-only interface, simulation keeps its FIFO.
if {!$ITRNG} {error "Selectable board feeder requires ITRNG=TRUE"}
lappend VERILOG_OPTIONS HTG940_ENTROPY_CONTROL
source [file join $fpgaDir create_caliptra_package.tcl]

# -----------------------------------------------------------------------------
# HTG-940 project and block design
# -----------------------------------------------------------------------------
set projectName caliptra_htg940_project
set bdName      caliptra_htg940_bd

create_project $projectName $outputDir -part $PART -force

# Apply macros before Vivado loads and analyzes the packaged RTL.
set_property verilog_define $VERILOG_OPTIONS [get_filesets sources_1]
set_property verilog_define $VERILOG_OPTIONS [get_filesets sim_1]

set_property target_language Verilog [current_project]
set_property ip_repo_paths [list $caliptrapackageDir] [current_project]
update_ip_catalog

create_bd_design $bdName
create_bd_cell -type ip \
  -vlnv design:user:caliptra_package_top:1.0 \
  caliptra_package_top_0

# Physical HTG940 clock input and clock generation.
create_bd_port -dir I -type clk ref_clock_156p25mhz_clk_p
create_bd_port -dir I -type clk ref_clock_156p25mhz_clk_n
set_property CONFIG.FREQ_HZ 156250000 [get_bd_ports ref_clock_156p25mhz_clk_p]
set_property CONFIG.FREQ_HZ 156250000 [get_bd_ports ref_clock_156p25mhz_clk_n]

create_bd_port -dir I -type rst reset_n
set_property CONFIG.POLARITY ACTIVE_LOW [get_bd_ports reset_n]

create_bd_cell -type ip -vlnv xilinx.com:ip:clk_wiz:6.0 htg940_clocks
set_property -dict [list \
    CONFIG.PRIM_SOURCE {Differential_clock_capable_pin} \
    CONFIG.PRIM_IN_FREQ {156.250} \
    CONFIG.CLKOUT1_REQUESTED_OUT_FREQ $CORE_CLK_MHZ \
    CONFIG.CLKOUT2_USED {true} \
    CONFIG.CLKOUT2_REQUESTED_OUT_FREQ $I3C_CLK_MHZ \
    CONFIG.NUM_OUT_CLKS {2} \
    CONFIG.USE_LOCKED {true} \
    CONFIG.USE_RESET {true} \
    CONFIG.RESET_TYPE {ACTIVE_LOW} \
] [get_bd_cells htg940_clocks]

connect_bd_net [get_bd_ports ref_clock_156p25mhz_clk_p] [get_bd_pins htg940_clocks/clk_in1_p]
connect_bd_net [get_bd_ports ref_clock_156p25mhz_clk_n] [get_bd_pins htg940_clocks/clk_in1_n]
connect_bd_net [get_bd_ports reset_n] [get_bd_pins htg940_clocks/resetn]

# -----------------------------------------------------------------------------
# AXI fabric
# -----------------------------------------------------------------------------
# Managers:
#   S00 Caliptra Core
#   S01 MCU IFU
#   S02 MCU LSU
#   S03 MCU system bus
#   S04 CDMA
# There is no ARM/PS manager on HTG-940.
create_bd_cell -type ip -vlnv xilinx.com:ip:smartconnect:1.0 axi_interconnect_0
set_property -dict [list \
  CONFIG.NUM_MI   {16} \
  CONFIG.NUM_SI   {5}  \
  CONFIG.NUM_CLKS {2}  \
] [get_bd_cells axi_interconnect_0]

create_bd_cell -type ip -vlnv xilinx.com:ip:smartconnect:1.0 usb_interconnect_0
set_property -dict [list \
  CONFIG.NUM_MI   {4} \
  CONFIG.NUM_SI   {1} \
  CONFIG.NUM_CLKS {1} \
] [get_bd_cells usb_interconnect_0]

proc register_axi_subordinate {src_block src_port address size dst addrseg name debug clock} {
  global axi_subordinates
  incr axi_subordinates(ID)
  set id $axi_subordinates(ID)
  set axi_subordinates($id,src_block) $src_block
  set axi_subordinates($id,src_port)  $src_port
  set axi_subordinates($id,address)   $address
  set axi_subordinates($id,size)      $size
  set axi_subordinates($id,dst)       $dst
  set axi_subordinates($id,addrseg)   $addrseg
  set axi_subordinates($id,name)      $name
  set axi_subordinates($id,debug)     $debug
  set axi_subordinates($id,clock)     $clock
}

global axi_subordinates
set axi_subordinates(ID) 0

register_axi_subordinate axi_interconnect_0 M00_AXI 0xA4100000 0x00100000 caliptra_package_top_0/S_AXI_CALIPTRA  reg0 S_AXI_CALIPTRA     TRUE  /htg940_clocks/clk_out1
register_axi_subordinate axi_interconnect_0 M01_AXI 0xA4030000 0x00002000 caliptra_package_top_0/S_AXI_I3C       reg0 S_AXI_I3C         TRUE  /htg940_clocks/clk_out2
register_axi_subordinate axi_interconnect_0 M13_AXI 0xA4032000 0x00002000 caliptra_package_top_0/S_AXI_I3C_SPARE reg0 S_AXI_I3C_SPARE   TRUE  /htg940_clocks/clk_out2
register_axi_subordinate axi_interconnect_0 M02_AXI 0xA4040000 0x00002000 caliptra_package_top_0/S_AXI_LCC       reg0 S_AXI_LCC         FALSE /htg940_clocks/clk_out1
register_axi_subordinate axi_interconnect_0 M03_AXI 0xA8000000 0x01000000 caliptra_package_top_0/S_AXI_MCI       reg0 S_AXI_MCI         TRUE  /htg940_clocks/clk_out1
register_axi_subordinate axi_interconnect_0 M04_AXI 0xB0040000 0x00020000 caliptra_package_top_0/S_AXI_MCU_ROM   reg0 S_AXI_MCU_ROM     TRUE  /htg940_clocks/clk_out1
register_axi_subordinate axi_interconnect_0 M05_AXI 0xA4060000 0x00002000 caliptra_package_top_0/S_AXI_OTP       reg0 S_AXI_OTP         TRUE  /htg940_clocks/clk_out1
register_axi_subordinate axi_interconnect_0 M06_AXI 0xA4010000 0x00004000 caliptra_package_top_0/S_AXI_WRAPPER   reg0 S_AXI_WRAPPER     FALSE /htg940_clocks/clk_out1
register_axi_subordinate axi_interconnect_0 M07_AXI 0xB0080000 0x00010000 otp_ram_bram_ctrl_0/S_AXI              Mem0 S_AXI_OTP_RAM     TRUE  /htg940_clocks/clk_out1
register_axi_subordinate axi_interconnect_0 M08_AXI 0xB00C0000 0x00040000 staging_sram_bram_ctrl_0/S_AXI         Mem0 S_AXI_STAGING_SRAM FALSE /htg940_clocks/clk_out1
register_axi_subordinate axi_interconnect_0 M09_AXI 0xA4080000 0x00001000 xilinx_i3c_0/S_AXI                     Reg  S_AXI_XILINX_I3C  FALSE /htg940_clocks/clk_out2
register_axi_subordinate axi_interconnect_0 M10_AXI 0xA4081000 0x00001000 axi_cdma_0/S_AXI_LITE                  Reg  S_AXI_XILINX_DMA  FALSE /htg940_clocks/clk_out1
register_axi_subordinate axi_interconnect_0 M11_AXI 0xB0000000 0x00020000 cptra_rom_backdoor_bram_0/S_AXI        Mem0 S_AXI_CALIPTRA_ROM FALSE /htg940_clocks/clk_out1
register_axi_subordinate axi_interconnect_0 M12_AXI 0xB0020000 0x00020000 mcu_rom_backdoor_bram_0/S_AXI          Mem0 S_AXI_SS_ROM       FALSE /htg940_clocks/clk_out1
register_axi_subordinate axi_interconnect_0 M15_AXI 0xB0200000 0x00200000 firmware_flash_bram_ctrl_0/S_AXI Mem0 S_AXI_FIRMWARE_FLASH TRUE /htg940_clocks/clk_out1

register_axi_subordinate usb_interconnect_0 M00_AXI 0xA4200000 0x00100000 caliptra_package_top_0/S_AXI_USB_COMBO  reg0 S_AXI_USB_COMBO  TRUE /htg940_clocks/clk_out1
register_axi_subordinate usb_interconnect_0 M01_AXI 0xA4300000 0x00100000 caliptra_package_top_0/S_AXI_USB_DEV0_MEM reg0 S_AXI_USB_DEV0_MEM TRUE /htg940_clocks/clk_out1
register_axi_subordinate usb_interconnect_0 M02_AXI 0xA4400000 0x00100000 caliptra_package_top_0/S_AXI_USB_DEV1_CSR  reg0 S_AXI_USB_DEV1_CSR  TRUE /htg940_clocks/clk_out1
register_axi_subordinate usb_interconnect_0 M03_AXI 0xA4500000 0x00100000 caliptra_package_top_0/S_AXI_USB_DEV1_MEM  reg0 S_AXI_USB_DEV1_MEM  TRUE /htg940_clocks/clk_out1

# -----------------------------------------------------------------------------
# Memories, DMA, I3C host, reset controller
# -----------------------------------------------------------------------------
create_bd_cell -type ip -vlnv xilinx.com:ip:proc_sys_reset:5.0 proc_sys_reset_0
# C_EXT_RESET_HIGH is inferred from the ACTIVE_LOW reset interface.
set_property CONFIG.C_AUX_RESET_HIGH {1} [get_bd_cells proc_sys_reset_0]


create_bd_cell -type ip -vlnv xilinx.com:ip:xlconstant:1.1 aux_reset_const_0
set_property -dict [list CONFIG.CONST_WIDTH {1} CONFIG.CONST_VAL {0}] \
  [get_bd_cells aux_reset_const_0]

create_bd_cell -type ip -vlnv xilinx.com:ip:axi_bram_ctrl:4.1 cptra_rom_backdoor_bram_0
set_property CONFIG.SINGLE_PORT_BRAM {1} [get_bd_cells cptra_rom_backdoor_bram_0]

create_bd_cell -type ip -vlnv xilinx.com:ip:axi_bram_ctrl:4.1 mcu_rom_backdoor_bram_0
set_property CONFIG.SINGLE_PORT_BRAM {1} [get_bd_cells mcu_rom_backdoor_bram_0]

create_bd_cell -type ip -vlnv xilinx.com:ip:axi_bram_ctrl:4.1 otp_ram_bram_ctrl_0
set_property CONFIG.SINGLE_PORT_BRAM {1} [get_bd_cells otp_ram_bram_ctrl_0]

create_bd_cell -type ip -vlnv xilinx.com:ip:axi_bram_ctrl:4.1 staging_sram_bram_ctrl_0
set_property CONFIG.SINGLE_PORT_BRAM {1} [get_bd_cells staging_sram_bram_ctrl_0]

set_property CONFIG.DATA_WIDTH {64} [get_bd_cells staging_sram_bram_ctrl_0]
# HTG940_STANDALONE_FIRMWARE_BRAM: 2 MiB writable firmware memory.
create_bd_cell -type ip -vlnv xilinx.com:ip:axi_bram_ctrl:4.1 firmware_flash_bram_ctrl_0
set_property CONFIG.SINGLE_PORT_BRAM {1} [get_bd_cells firmware_flash_bram_ctrl_0]
set_property CONFIG.DATA_WIDTH {64} [get_bd_cells firmware_flash_bram_ctrl_0]

create_bd_cell -type ip -vlnv xilinx.com:ip:blk_mem_gen:8.4 firmware_flash_mem_0
# Apply the complete 64-bit initialized-RAM configuration atomically.
# Otherwise Vivado can validate the 64-bit COE against a transient default width.
set_property -dict [list \
  CONFIG.use_bram_block {Stand_Alone} \
  CONFIG.Memory_Type {Single_Port_RAM} \
  CONFIG.Write_Width_A {64} \
  CONFIG.Read_Width_A {64} \
  CONFIG.Write_Depth_A {262144} \
  CONFIG.Use_Byte_Write_Enable {true} \
  CONFIG.Byte_Size {8} \
  CONFIG.Register_PortA_Output_of_Memory_Primitives {false} \
  CONFIG.Register_PortA_Output_of_Memory_Core {false} \
  CONFIG.Coe_File $flashImageCoe \
  CONFIG.Load_Init_File {true} \
] [get_bd_cells firmware_flash_mem_0]

puts "Firmware BRAM mode: [get_property CONFIG.use_bram_block [get_bd_cells firmware_flash_mem_0]]"
puts "Firmware BRAM write width: [get_property CONFIG.Write_Width_A [get_bd_cells firmware_flash_mem_0]]"
puts "Firmware BRAM depth: [get_property CONFIG.Write_Depth_A [get_bd_cells firmware_flash_mem_0]]"
puts "Firmware BRAM COE: [get_property CONFIG.Coe_File [get_bd_cells firmware_flash_mem_0]]"


# emb_mem_gen is Versal-only. HTG940/VU13P uses Block Memory Generator.
create_bd_cell -type ip -vlnv xilinx.com:ip:blk_mem_gen:8.4 staging_sram_emb_mem_gen_0
set_property CONFIG.Memory_Type {Single_Port_RAM} [get_bd_cells staging_sram_emb_mem_gen_0]
set_property CONFIG.Write_Width_A {64} [get_bd_cells staging_sram_emb_mem_gen_0]
set_property CONFIG.Read_Width_A {64} [get_bd_cells staging_sram_emb_mem_gen_0]
set_property CONFIG.Write_Depth_A {32768} [get_bd_cells staging_sram_emb_mem_gen_0]

create_bd_cell -type ip -vlnv xilinx.com:ip:axi_cdma:4.1 axi_cdma_0
set_property CONFIG.C_INCLUDE_SG {0} [get_bd_cells axi_cdma_0]

create_bd_cell -type ip -vlnv xilinx.com:ip:axi_i3c:1.0 xilinx_i3c_0
set_property -dict [list \
  CONFIG.ENABLE_PEC                    {1} \
  CONFIG.HJ_CAPABLE                    {1} \
  CONFIG.IBI_CAPABLE                   {1} \
  CONFIG.CMD_RESP_FIFO_DEPTH           {64} \
  CONFIG.WR_FIFO_PROG_FULL_THRESHOLD   {125} \
  CONFIG.WR_RD_FIFO_DEPTH              {128} \
  CONFIG.RW_TIMEOUT                    {10000} \
] [get_bd_cells xilinx_i3c_0]

create_bd_cell -type ip -vlnv xilinx.com:ip:xpm_cdc_gen:1.0 xpm_cdc_gen_0
set_property CONFIG.CDC_TYPE {xpm_cdc_sync_rst} [get_bd_cells xpm_cdc_gen_0]

# -----------------------------------------------------------------------------
# AXI manager connections (no PS/ARM manager)
# -----------------------------------------------------------------------------
connect_bd_intf_net [get_bd_intf_pins caliptra_package_top_0/M_AXI_CALIPTRA] \
                    [get_bd_intf_pins axi_interconnect_0/S00_AXI]
connect_bd_intf_net [get_bd_intf_pins caliptra_package_top_0/M_AXI_MCU_IFU] \
                    [get_bd_intf_pins axi_interconnect_0/S01_AXI]
connect_bd_intf_net [get_bd_intf_pins caliptra_package_top_0/M_AXI_MCU_LSU] \
                    [get_bd_intf_pins axi_interconnect_0/S02_AXI]
connect_bd_intf_net [get_bd_intf_pins caliptra_package_top_0/M_AXI_MCU_SB] \
                    [get_bd_intf_pins axi_interconnect_0/S03_AXI]
connect_bd_intf_net [get_bd_intf_pins axi_cdma_0/M_AXI] \
                    [get_bd_intf_pins axi_interconnect_0/S04_AXI]

connect_bd_intf_net -intf_net M_AXI_USB_BRIDGE \
  [get_bd_intf_pins axi_interconnect_0/M14_AXI] \
  [get_bd_intf_pins usb_interconnect_0/S00_AXI]

for {set i 1} {$i <= $axi_subordinates(ID)} {incr i} {
  connect_bd_intf_net -intf_net $axi_subordinates($i,name) \
    [get_bd_intf_pins $axi_subordinates($i,src_block)/$axi_subordinates($i,src_port)] \
    [get_bd_intf_pins $axi_subordinates($i,dst)]
  if {$axi_subordinates($i,debug)} {
    set_property HDL_ATTRIBUTE.DEBUG true \
      [get_bd_intf_nets $axi_subordinates($i,name)]
  }
}

# -----------------------------------------------------------------------------
# Clock and reset connections
# -----------------------------------------------------------------------------
connect_bd_net [get_bd_ports reset_n] [get_bd_pins proc_sys_reset_0/ext_reset_in]
connect_bd_net [get_bd_pins htg940_clocks/locked] \
               [get_bd_pins proc_sys_reset_0/dcm_locked]
connect_bd_net [get_bd_pins aux_reset_const_0/dout] \
               [get_bd_pins proc_sys_reset_0/aux_reset_in]

connect_bd_net [get_bd_pins htg940_clocks/clk_out1] \
  [get_bd_pins proc_sys_reset_0/slowest_sync_clk] \
  [get_bd_pins axi_interconnect_0/aclk] \
  [get_bd_pins usb_interconnect_0/aclk] \
  [get_bd_pins caliptra_package_top_0/core_clk] \
  [get_bd_pins cptra_rom_backdoor_bram_0/s_axi_aclk] \
  [get_bd_pins mcu_rom_backdoor_bram_0/s_axi_aclk] \
  [get_bd_pins otp_ram_bram_ctrl_0/s_axi_aclk] \
  [get_bd_pins staging_sram_bram_ctrl_0/s_axi_aclk] \
  [get_bd_pins firmware_flash_bram_ctrl_0/s_axi_aclk] \
  [get_bd_pins axi_cdma_0/s_axi_lite_aclk] \
  [get_bd_pins axi_cdma_0/m_axi_aclk]

connect_bd_net [get_bd_pins htg940_clocks/clk_out2] \
  [get_bd_pins axi_interconnect_0/aclk1] \
  [get_bd_pins caliptra_package_top_0/i3c_clk] \
  [get_bd_pins xilinx_i3c_0/s_axi_aclk] \
  [get_bd_pins xpm_cdc_gen_0/dest_clk]

connect_bd_net -net peripheral_aresetn \
  [get_bd_pins proc_sys_reset_0/peripheral_aresetn] \
  [get_bd_pins axi_interconnect_0/aresetn] \
  [get_bd_pins usb_interconnect_0/aresetn] \
  [get_bd_pins caliptra_package_top_0/S_AXI_WRAPPER_ARESETN] \
  [get_bd_pins cptra_rom_backdoor_bram_0/s_axi_aresetn] \
  [get_bd_pins mcu_rom_backdoor_bram_0/s_axi_aresetn] \
  [get_bd_pins otp_ram_bram_ctrl_0/s_axi_aresetn] \
  [get_bd_pins staging_sram_bram_ctrl_0/s_axi_aresetn] \
  [get_bd_pins firmware_flash_bram_ctrl_0/s_axi_aresetn] \
  [get_bd_pins axi_cdma_0/s_axi_lite_aresetn]

# I3C reset crosses from the Caliptra-produced source reset to i3c_clk.
connect_bd_net [get_bd_pins caliptra_package_top_0/xilinx_i3c_aresetn] \
               [get_bd_pins xpm_cdc_gen_0/src_rst]
connect_bd_net [get_bd_pins xpm_cdc_gen_0/dest_rst_out] \
               [get_bd_pins xilinx_i3c_0/s_axi_aresetn]

# -----------------------------------------------------------------------------
# BRAM backdoors and staging memory
# -----------------------------------------------------------------------------
connect_bd_intf_net [get_bd_intf_pins caliptra_package_top_0/rom_backdoor] \
                    [get_bd_intf_pins cptra_rom_backdoor_bram_0/BRAM_PORTA]
connect_bd_intf_net [get_bd_intf_pins caliptra_package_top_0/mcu_rom_backdoor] \
                    [get_bd_intf_pins mcu_rom_backdoor_bram_0/BRAM_PORTA]
connect_bd_intf_net [get_bd_intf_pins caliptra_package_top_0/otp_mem_backdoor] \
                    [get_bd_intf_pins otp_ram_bram_ctrl_0/BRAM_PORTA]

connect_bd_intf_net [get_bd_intf_pins staging_sram_bram_ctrl_0/BRAM_PORTA] \
                    [get_bd_intf_pins staging_sram_emb_mem_gen_0/BRAM_PORTA]
# Firmware BRAM: byte address -> 64-bit word address.
create_bd_cell -type ip -vlnv xilinx.com:ip:xlslice:1.0 firmware_byte_to_word_0

set_property -dict [list \
  CONFIG.DIN_WIDTH {21} \
  CONFIG.DIN_FROM {20} \
  CONFIG.DIN_TO {3} \
  CONFIG.DOUT_WIDTH {18} \
] [get_bd_cells firmware_byte_to_word_0]

connect_bd_net \
  [get_bd_pins firmware_flash_bram_ctrl_0/bram_addr_a] \
  [get_bd_pins firmware_byte_to_word_0/Din]

connect_bd_net \
  [get_bd_pins firmware_byte_to_word_0/Dout] \
  [get_bd_pins firmware_flash_mem_0/addra]

foreach {ctrlPin memPin} {
  bram_clk_a    clka
  bram_en_a     ena
  bram_we_a     wea
  bram_wrdata_a dina
  bram_rddata_a douta
} {
  connect_bd_net \
    [get_bd_pins firmware_flash_bram_ctrl_0/$ctrlPin] \
    [get_bd_pins firmware_flash_mem_0/$memPin]
}

set firmwareMemReset [get_bd_pins -quiet firmware_flash_mem_0/rsta]
if {[llength $firmwareMemReset]} {
  connect_bd_net \
    [get_bd_pins firmware_flash_bram_ctrl_0/bram_rst_a] \
    $firmwareMemReset
}

# -----------------------------------------------------------------------------
# Physical FPGA boundary: USB ULPI, I3C, and JTAG
# -----------------------------------------------------------------------------
create_bd_port -dir I  -type clk USB_ULPI_CLK
create_bd_port -dir IO -from 7 -to 0 USB_ULPI_DATA
create_bd_port -dir I             USB_ULPI_DIR
create_bd_port -dir I             USB_ULPI_NXT
create_bd_port -dir O             USB_ULPI_STP

connect_bd_net [get_bd_ports USB_ULPI_CLK]  [get_bd_pins caliptra_package_top_0/USB_ULPI_CLK]
connect_bd_net [get_bd_ports USB_ULPI_DATA] [get_bd_pins caliptra_package_top_0/USB_ULPI_DATA]
connect_bd_net [get_bd_ports USB_ULPI_DIR]  [get_bd_pins caliptra_package_top_0/USB_ULPI_DIR]
connect_bd_net [get_bd_ports USB_ULPI_NXT]  [get_bd_pins caliptra_package_top_0/USB_ULPI_NXT]
connect_bd_net [get_bd_ports USB_ULPI_STP]  [get_bd_pins caliptra_package_top_0/USB_ULPI_STP]

create_bd_port -dir O EXT_SDA_UP
create_bd_port -dir O EXT_SDA_IN
create_bd_port -dir O EXT_SDA_EN
create_bd_port -dir I EXT_SDA
create_bd_port -dir I EXT_SCL

connect_bd_net [get_bd_ports EXT_SDA_UP] [get_bd_pins caliptra_package_top_0/EXT_SDA_UP]
connect_bd_net [get_bd_ports EXT_SDA_IN] [get_bd_pins caliptra_package_top_0/EXT_SDA_IN]
connect_bd_net [get_bd_ports EXT_SDA_EN] [get_bd_pins caliptra_package_top_0/EXT_SDA_EN]
connect_bd_net [get_bd_ports EXT_SDA]    [get_bd_pins caliptra_package_top_0/EXT_SDA]
connect_bd_net [get_bd_ports EXT_SCL]    [get_bd_pins caliptra_package_top_0/EXT_SCL]

connect_bd_net [get_bd_pins caliptra_package_top_0/xilinx_sda] \
               [get_bd_pins xilinx_i3c_0/sda_i]
connect_bd_net [get_bd_pins caliptra_package_top_0/xilinx_sda_o] \
               [get_bd_pins xilinx_i3c_0/sda_o]
connect_bd_net [get_bd_pins caliptra_package_top_0/xilinx_sda_t] \
               [get_bd_pins xilinx_i3c_0/sda_t]
connect_bd_net [get_bd_pins caliptra_package_top_0/xilinx_sda_pullup_en] \
               [get_bd_pins xilinx_i3c_0/sda_pullup_en]
connect_bd_net [get_bd_pins caliptra_package_top_0/xilinx_scl] \
               [get_bd_pins xilinx_i3c_0/scl_i]
connect_bd_net [get_bd_pins caliptra_package_top_0/xilinx_scl_o] \
               [get_bd_pins xilinx_i3c_0/scl_o]
connect_bd_net [get_bd_pins caliptra_package_top_0/xilinx_scl_t] \
               [get_bd_pins xilinx_i3c_0/scl_t]
connect_bd_net [get_bd_pins caliptra_package_top_0/xilinx_scl_pullup_en] \
               [get_bd_pins xilinx_i3c_0/scl_pullup_en]

create_bd_port -dir I -from 14 -to 0 jtag_in
create_bd_port -dir O -from 14 -to 0 jtag_out
connect_bd_net [get_bd_ports jtag_in]  [get_bd_pins caliptra_package_top_0/jtag_in]
connect_bd_net [get_bd_ports jtag_out] [get_bd_pins caliptra_package_top_0/jtag_out]

# -----------------------------------------------------------------------------
# Address map: every on-chip AXI manager sees the same subsystem map
# -----------------------------------------------------------------------------
set managers [list \
  caliptra_package_top_0/M_AXI_MCU_IFU \
  caliptra_package_top_0/M_AXI_MCU_LSU \
  caliptra_package_top_0/M_AXI_MCU_SB  \
  caliptra_package_top_0/M_AXI_CALIPTRA \
  axi_cdma_0/Data]

foreach manager $managers {
  for {set i 1} {$i <= $axi_subordinates(ID)} {incr i} {
    assign_bd_address \
      -offset $axi_subordinates($i,address) \
      -range  $axi_subordinates($i,size) \
      -target_address_space [get_bd_addr_spaces $manager] \
      [get_bd_addr_segs $axi_subordinates($i,dst)/$axi_subordinates($i,addrseg)] \
      -force
  }
}

set_property CONFIG.SCL_CLK_FREQ $I3C_SCL_RATE_KHZ [get_bd_cells xilinx_i3c_0]

# HTG940_BOARD_IO_V1
source [file join $fpgaDir board connect_htg940_board.tcl]
if {$HTG_XDC eq ""} {
  set HTG_XDC [file join $fpgaDir constraints htg940_board_nxp.xdc]
}

# Add only an explicit HTG-940 XDC.  Versal DDR/I3C/PS constraints are not used.
if {$HTG_XDC ne ""} {
  set normalizedXdc [file normalize $HTG_XDC]
  if {![file exists $normalizedXdc]} {
    error "HTG_XDC does not exist: $normalizedXdc"
  }
  add_files -fileset constrs_1 $normalizedXdc
} elseif {$BUILD} {
  error "BUILD=TRUE requires HTG_XDC=/absolute/path/to/htg940_vu13p.xdc"
} else {
  puts "WARNING: HTG_XDC was not supplied; project/BD generation only."
}

validate_bd_design
# HTG940_PACKAGING_FIX_V1: check inferred polarity after BD propagation.
set inferredResetHigh [get_property CONFIG.C_EXT_RESET_HIGH [get_bd_cells proc_sys_reset_0]]
if {$inferredResetHigh != 0} {
  error "Subsystem reset polarity is not active-low: $inferredResetHigh"
}
puts "HTG940_RESET_POLARITY_PASS: active-low subsystem reset"
save_bd_design

set_property verilog_define $VERILOG_OPTIONS [current_fileset]

set bdFile [get_files -quiet */$bdName.bd]
if {[llength $bdFile] != 1} {
  error "Could not resolve block design file for $bdName"
}
make_wrapper -files $bdFile -top

set wrapperFile [file join $outputDir ${projectName}.gen sources_1 bd $bdName hdl ${bdName}_wrapper.v]
add_files -norecurse $wrapperFile
set_property top htg940_board_top [current_fileset]
update_compile_order -fileset sources_1

create_ip_run $bdFile
set packageRuns [get_runs -quiet *caliptra_package_top_0_0_synth_1]
foreach packageRun $packageRuns {
  set_property STEPS.SYNTH_DESIGN.ARGS.GATED_CLOCK_CONVERSION \
    $GATED_CLOCK_CONVERSION $packageRun
}
set_property STEPS.PLACE_DESIGN.ARGS.DIRECTIVE Explore [get_runs impl_1]

if {$DEBUG} {
  puts "DEBUG=TRUE: AXI interfaces and package debug nets are marked for debug."
  foreach debugPin {caliptra_ifu_i0_pc mcu_ifu_i0_pc ifu_i0_instr mci_boot_fsm caliptra_log dbg_log} {
    set pin [get_bd_pins -quiet caliptra_package_top_0/$debugPin]
    if {[llength $pin]} {
      set_property HDL_ATTRIBUTE.DEBUG true $pin
    }
  }
}

save_bd_design

# -----------------------------------------------------------------------------
# UltraScale+ build: generate a .bit file, not a Versal PDI
# -----------------------------------------------------------------------------
if {$BUILD} {
  set timeStart [clock clicks -millisec]

  launch_runs synth_1 -jobs 32
  wait_on_run synth_1
  if {![string match "*Complete*" [get_property STATUS [get_runs synth_1]]]} {
    error "Synthesis failed: [get_property STATUS [get_runs synth_1]]"
  }

  launch_runs impl_1 -to_step write_bitstream -jobs 32
  wait_on_run impl_1
  if {![string match "*Complete*" [get_property STATUS [get_runs impl_1]]]} {
    error "Implementation/bitstream failed: [get_property STATUS [get_runs impl_1]]"
  }

  open_run impl_1
  report_utilization -hierarchical -file [file join $outputDir utilization_hierarchical.txt]
  report_timing_summary -file [file join $outputDir timing_summary.txt]

  set bitFiles [glob -nocomplain [file join $outputDir ${projectName}.runs impl_1 *.bit]]
  if {[llength $bitFiles] != 1} {
    error "Expected one generated .bit file, found: $bitFiles"
  }
  set finalBit [file join $outputDir caliptra_htg940_${VERSION}.bit]
  file copy -force [lindex $bitFiles 0] $finalBit

  set xsaFile [file join $outputDir caliptra_htg940_${VERSION}.xsa]
  write_hw_platform -fixed -include_bit -force -file $xsaFile

  set elapsedMinutes [expr {([clock clicks -millisec] - $timeStart) / 60000.0}]
  puts "HTG-940 bitstream: $finalBit"
  puts "HTG-940 XSA:       $xsaFile"
  puts "Build time:        $elapsedMinutes minutes"
}

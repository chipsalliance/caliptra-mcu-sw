# Licensed under the Apache-2.0 license

# Create a project to package Caliptra.
# Packaging Caliptra allows Vivado to recognize the APB bus as an endpoint for the memory map.
create_project caliptra_package_project $outputDir -part $PART
if {$BOARD eq "VCK190"} {
  set_property board_part xilinx.com:vck190:part0:3.1 [current_project]
} elseif {$BOARD eq "HTG940"} {
  # No board_part is published for the HTG-940. The part and physical
  # constraints are supplied by fpga_configuration_htg940.tcl.
  lappend VERILOG_OPTIONS HTG940_FPGA
}

# TODO: Check these SS defines: https://github.com/chipsalliance/caliptra-mcu-sw/issues/368
lappend VERILOG_OPTIONS TECH_SPECIFIC_ICG
lappend VERILOG_OPTIONS USER_ICG=fpga_fake_icg
lappend VERILOG_OPTIONS RV_FPGA_OPTIMIZE
lappend VERILOG_OPTIONS css_mcu0_TEC_RV_ICG=css_mcu0_clockhdr
lappend VERILOG_OPTIONS TECH_SPECIFIC_EC_RV_ICG
lappend VERILOG_OPTIONS css_mcu0_USER_EC_RV_ICG=mcu_clockhdr
lappend VERILOG_OPTIONS css_mcu0_RV_BUILD_AXI4
lappend VERILOG_OPTIONS MCU_RV_BUILD_AXI4
lappend VERILOG_OPTIONS I3C_USE_AXI
# TODO: This AXI_ID_WIDTH is probably way larger than needed.
lappend VERILOG_OPTIONS AXI_ID_WIDTH=19 AXI_USER_WIDTH=32 AXI_DATA_WIDTH=32 AXI_ADDR_WIDTH=32
# Might be removed in newer RTL? TLUL has compilation failure
lappend VERILOG_OPTIONS CALIPTRA_AXI_ID_WIDTH=19 CALIPTRA_AXI_USER_WIDTH=32
# Try using xilinx primitives
lappend VERILOG_OPTIONS CALIPTRA_PRIM_DEFAULT_IMPL=caliptra_prim_pkg::ImplXilinx

set_property verilog_define $VERILOG_OPTIONS [current_fileset]
puts "\n\nVERILOG DEFINES: [get_property verilog_define [current_fileset]]"

# Add Caliptra VEER Headers
add_files $caliptrartlDir/src/riscv_core/veer_el2/rtl/el2_param.vh
add_files $caliptrartlDir/src/riscv_core/veer_el2/rtl/pic_map_auto.h
add_files $caliptrartlDir/src/riscv_core/veer_el2/rtl/el2_pdef.vh
add_files [ glob $caliptrartlDir/src/riscv_core/veer_el2/rtl/include/*.svh ]
add_files [ glob $caliptrartlDir/src/riscv_core/veer_el2/rtl/include/*.sv ]

# Add Caliptra VEER sources
add_files [ glob $caliptrartlDir/src/riscv_core/veer_el2/rtl/*.sv ]
add_files [ glob $caliptrartlDir/src/riscv_core/veer_el2/rtl/*/*.sv ]
add_files [ glob $caliptrartlDir/src/riscv_core/veer_el2/rtl/*/*.v ]

# Add Adam's Bridge
#source adams-bridge-files.tcl #fa
# Add Adam's Bridge (or stub for faster builds)
if {$STUB_ADAMS_BRIDGE eq "TRUE"} {
  puts "STUB_ADAMS_BRIDGE=TRUE: skipping full adams-bridge (~354 files), using stub"
  lappend VERILOG_OPTIONS STUB_ADAMS_BRIDGE
  set_property verilog_define $VERILOG_OPTIONS [current_fileset]
  source adams-bridge-files-stub.tcl
} else {
  source adams-bridge-files.tcl
}


# Add Caliptra headers and packages
add_files [ glob $caliptrartlDir/src/*/rtl/*.svh ]
add_files [ glob $caliptrartlDir/src/integration/rtl/caliptra_reg_ss/*.svh ]
add_files [ glob $caliptrartlDir/src/*/rtl/*_pkg.sv ]
# Add Caliptra sources
add_files [ glob $caliptrartlDir/src/*/rtl/*.sv ]
add_files [ glob $caliptrartlDir/src/*/rtl/*.v ]

# Add ss RTL
# Add MCU VEER Headers
add_files $ssrtlDir/src/riscv_core/veer_el2/rtl/defines/css_mcu0_pic_map_auto.h
add_files $ssrtlDir/src/riscv_core/veer_el2/rtl/defines/css_mcu0_el2_pdef.vh
add_files $ssrtlDir/src/riscv_core/veer_el2/rtl/defines/css_mcu0_el2_param.vh
add_files $ssrtlDir/src/riscv_core/veer_el2/rtl/defines/css_mcu0_common_defines.vh
add_files [ glob $ssrtlDir/src/riscv_core/veer_el2/rtl/design/include/*.svh ]
# For SS EL2_IC_DATA_SRAM is defined in testbench
add_files [ glob $ssrtlDir/src/riscv_core/veer_el2/tb/icache_macros.svh ]
# Add MCU VEER sources
add_files [ glob $ssrtlDir/src/riscv_core/veer_el2/rtl/design/*.sv ]
add_files [ glob $ssrtlDir/src/riscv_core/veer_el2/rtl/design/*/*.sv ]
add_files [ glob $ssrtlDir/src/riscv_core/veer_el2/rtl/design/*/*.v ]
# OTP
add_files [ glob $ssrtlDir/src/fuse_ctrl/rtl/*.sv ]
# OTP memory
add_files $ssrtlDir/src/fuse_ctrl/data/otp-img.2048.vmem
set_property file_type {Memory Initialization Files} [get_files $ssrtlDir/src/fuse_ctrl/data/otp-img.2048.vmem]
# OTP from testbench
add_files $ssrtlDir/src/integration/testbench/prim_generic_otp.sv

# HTG-940 has no Versal PS to populate the two boot ROMs after configuration.
# Convert the firmware build's raw binaries into 64-bit little-endian XPM
# initialization files and package them with the custom IP.
if {$BOARD eq "HTG940"} {
  if {![info exists FW_IMAGE_DIR]} {
    error "FW_IMAGE_DIR is required for BOARD=HTG940"
  }

  set romConverter [file join $fpgaDir bin_to_xpm_mem.py]
  if {![file isfile $romConverter]} {
    error "ROM converter not found: $romConverter"
  }

  foreach romSpec {
    {caliptra_rom.bin caliptra_rom.mem 98304 12288}
    {mcu_rom.bin      mcu_rom.mem      131072 16384}
  } {
    lassign $romSpec binName memName expectedBytes expectedWords
    set binPath [file join $FW_IMAGE_DIR $binName]
    set memPath [file join $FW_IMAGE_DIR $memName]

    if {![file isfile $binPath]} {
      error "Missing HTG-940 ROM binary: $binPath. Run cargo xtask-fpga all-build and extract htg940-fw.zip first."
    }

    puts "Generating $memName from $binName"
    exec python3 $romConverter \
      --input $binPath --output $memPath --size $expectedBytes

    set memFile [open $memPath r]
    set memContents [string trim [read $memFile]]
    close $memFile
    set actualWords [llength [split $memContents "\n"]]
    if {$actualWords != $expectedWords} {
      error "$memPath contains $actualWords words; expected $expectedWords"
    }

    add_files -norecurse $memPath
    set_property file_type {Memory Initialization Files} [get_files $memPath]
  }
}

# SS IPs
add_files [ glob $ssrtlDir/src/*/rtl/*.svh ]
add_files [ glob $ssrtlDir/src/*/rtl/*.sv ]

# HTG940_USB_COMPOUND_V1
source [file join $fpgaDir htg940_usb_compound_sources.tcl]

# I3C
set i3cDir $ssrtlDir/third_party/i3c-core
# Include headers and packages first
add_files [ glob $i3cDir/src/*.svh ]
add_files [ glob $i3cDir/src/libs/*.svh ]
add_files [ glob $i3cDir/src/*/*/*_pkg.sv ]

add_files [ glob $i3cDir/src/*/*_pkg.sv ]
add_files [ glob $i3cDir/src/*_pkg.sv ]
# Then the rest of the sv files
add_files [ glob $i3cDir/src/*/*/*.sv ]
add_files [ glob $i3cDir/src/*/*.sv ]
add_files [ glob $i3cDir/src/*.sv ]

# Remove unused spi_host files.
set htgSpiFiles [glob -nocomplain $caliptrartlDir/src/spi_host/rtl/*.sv]
if {[llength $htgSpiFiles] > 0} {
    remove_files $htgSpiFiles
}

# Add FPGA specific sources
add_files [ glob $fpgaDir/src/*.sv]
add_files [ glob $fpgaDir/src/*.v]

# Replace RAM with FPGA block ram
#remove_files [ glob $caliptrartlDir/src/ecc/rtl/ecc_ram_tdp_file.sv ] #fa

# Replace RAM with FPGA block ram (skipped when ECC is stubbed — no RAM to replace)
if {$STUB_ECC eq "TRUE"} {
  puts "STUB_ECC=TRUE: removing full ECC RTL, using stub"
  lappend VERILOG_OPTIONS STUB_ECC
  set_property verilog_define $VERILOG_OPTIONS [current_fileset]
  remove_files [ glob $caliptrartlDir/src/ecc/rtl/*.sv ]
} else {
  remove_files [ glob $caliptrartlDir/src/ecc/rtl/ecc_ram_tdp_file.sv ]
}

# Replace caliptra_ss_top with version modified with faster I3C clocks
file copy [ glob $ssrtlDir/src/integration/rtl/caliptra_ss_top.sv ] $outputDir/caliptra_ss_top.sv
exec patch --batch --forward --fuzz=0 $outputDir/caliptra_ss_top.sv $fpgaDir/src/caliptra_ss_top.patch
remove_files [ glob $ssrtlDir/src/integration/rtl/caliptra_ss_top.sv ]
add_files $outputDir/caliptra_ss_top.sv

# Preserve the hardware revision encoded in the selected Caliptra RTL.

# Add missing include
file copy [ glob $caliptrartlDir/src/ahb_lite_bus/rtl/ahb_lite_address_decoder.sv ] $outputDir/ahb_lite_address_decoder.sv
exec sed -i {1i `include \"config_defines.svh\"} $outputDir/ahb_lite_address_decoder.sv
remove_files [ glob $caliptrartlDir/src/ahb_lite_bus/rtl/ahb_lite_address_decoder.sv ]
add_files $outputDir/ahb_lite_address_decoder.sv

# Change soc_ifc to assign generic_input_wires[1] to CALIPTRA_FUSE_GRANULARITY
file copy [ glob $caliptrartlDir/src/soc_ifc/rtl/soc_ifc_top.sv ] $outputDir/soc_ifc_top.sv
exec sed -i {/`ifdef CALIPTRA_FUSE_GRANULARITY_32/,/`endif/calways_comb soc_ifc_reg_hwif_in.CPTRA_HW_CONFIG.Fuse_Granularity.next = generic_input_wires[0][1];} $outputDir/soc_ifc_top.sv
remove_files [ glob $caliptrartlDir/src/soc_ifc/rtl/soc_ifc_top.sv ]
add_files $outputDir/soc_ifc_top.sv



# Bake the Git version into a generated wrapper copy for IP packaging.
# Keep the original RTL unchanged.
if {![regexp {^[0-9a-fA-F]{1,8}$} $VERSION]} {
  error "VERSION must contain 1-8 hexadecimal digits; got '$VERSION'"
}

set wrapperSource [file normalize \
  [file join $fpgaDir src caliptra_wrapper_top.sv]]
set wrapperGenerated [file join $outputDir caliptra_wrapper_top_versioned.sv]

set wrapperFiles [get_files -quiet $wrapperSource]
if {[llength $wrapperFiles] != 1} {
  error "Expected one wrapper source in project: $wrapperSource"
}

set fh [open $wrapperSource r]
set wrapperText [read $fh]
close $fh

set versionToken {`FPGA_VERSION}
if {[string first $versionToken $wrapperText] < 0} {
  error "FPGA_VERSION token not found in $wrapperSource"
}

set wrapperText [string map \
  [list $versionToken "32'h${VERSION}"] $wrapperText]

set fh [open $wrapperGenerated w]
puts -nonewline $fh $wrapperText
close $fh

remove_files $wrapperFiles
add_files -norecurse $wrapperGenerated
set_property file_type SystemVerilog [get_files $wrapperGenerated]

if {[info exists MCU_USB_ONLY] && $MCU_USB_ONLY} {
  source [file join $fpgaDir htg940_usb_min_ila prepare_mcu_usb_only.tcl]
}

if {[info exists HTG_ULPI_DIAGNOSTICS] && $HTG_ULPI_DIAGNOSTICS} {
  source [file join $fpgaDir htg940_usb_min_ila prepare_debug_sources.tcl]
}

# HTG940_PACKAGING_FIX_V1
# Bake only the hardware interface conditional into generated copies, so IP
# port discovery and OOC compilation cannot disagree about its existence.
set htgInterfaceTop [file join $fpgaDir src caliptra_package_top.v]
if {$BOARD eq "HTG940" && [lsearch -exact $VERILOG_OPTIONS HTG940_ENTROPY_CONTROL] >= 0} {
  set specializer [file join $fpgaDir specialize_htg940_interface.py]
  puts [exec python3 $specializer $wrapperGenerated $wrapperGenerated]
  set originalTop [get_files -quiet $htgInterfaceTop]
  if {[llength $originalTop] != 1} {error "Cannot identify package top source"}
  set topSource $htgInterfaceTop
  set htgInterfaceTop [file join $outputDir caliptra_package_top_hw.v]
  puts [exec python3 $specializer $topSource $htgInterfaceTop]
  remove_files $originalTop
  add_files -norecurse $htgInterfaceTop
}


puts "Generated wrapper with FPGA version: 32'h${VERSION}"
# Mark all Verilog sources as SystemVerilog because some of them have SystemVerilog syntax.
set_property file_type SystemVerilog [get_files *.v]

# Exception: caliptra_package_top.v needs to be Verilog to be included in a Block Diagram.
set_property file_type Verilog [get_files $htgInterfaceTop]
update_compile_order -fileset sources_1

# Set caliptra_package_top as top in case next steps fail so that the top is something useful.
set_property top caliptra_package_axi_top [current_fileset]

# Create block diagram that includes an instance of caliptra_package_top
create_bd_design "caliptra_package_bd"
create_bd_cell -type module -reference caliptra_package_axi_top caliptra_package_top_0

save_bd_design
close_bd_design [get_bd_designs caliptra_package_bd]

# Keep the entropy package before its consumer in one generated source.
# Original caliptra-rtl files remain unchanged.
if {$BOARD eq "HTG940"} {
  set entropyPkg [get_files -quiet */entropy_src_main_sm_pkg.sv]
  set entropyCore [get_files -quiet */entropy_src_core.sv]

  if {[llength $entropyPkg] != 1 || [llength $entropyCore] != 1} {
    error "Expected exactly one entropy package and one entropy core"
  }

  set combinedText ""
  foreach sourceFile [list $entropyPkg $entropyCore] {
    set sourcePath [get_property NAME $sourceFile]
    set fh [open $sourcePath r]
    append combinedText [read $fh] "\n\n"
    close $fh
  }

  set combinedFile [file join $outputDir entropy_src_core_with_pkg.sv]
  set fh [open $combinedFile w]
  puts -nonewline $fh $combinedText
  close $fh

  # Remove the originals from this project only, not from disk.
  remove_files [concat $entropyPkg $entropyCore]
  add_files -norecurse $combinedFile
  set_property file_type SystemVerilog [get_files $combinedFile]

  puts "HTG940: generated entropy source with package before core."
}

update_compile_order -fileset sources_1

# Package IP
puts "Fileset when packaging: [current_fileset]"
puts "\n\nVERILOG DEFINES: [get_property verilog_define [current_fileset]]"
set_property verilog_define $VERILOG_OPTIONS [get_filesets sources_1]
set_property verilog_define $VERILOG_OPTIONS [get_filesets sim_1]
ipx::package_project -root_dir $caliptrapackageDir -vendor design -library user -taxonomy /UserIP -import_files
if {$BOARD eq "HTG940" && [lsearch -exact $VERILOG_OPTIONS HTG940_ENTROPY_CONTROL] >= 0} {
  foreach port {board_entropy_data board_entropy_valid board_entropy_req
                board_mcu_log_valid board_mcu_log_byte board_core_log_valid board_core_log_byte} {
    if {[llength [ipx::get_ports $port -of_objects [ipx::current_core]]] != 1} {
      error "Hardware interface absent from packaged metadata: $port"
    }
  }
  puts "HTG940_INTERFACE_PORTS_PASS: all seven ports packaged"
}


# HTG940_PRESERVE_RELATIVE_HEADERS
foreach {sourceHeader relativeHeader} [list \
    [file join $caliptrartlDir src riscv_core veer_el2 rtl lib el2_assert.sv] \
    src/lib/el2_assert.sv \
    [file join $ssrtlDir third_party usb2 src integration rtl generated usb_ocp_recovery_reg_addr_defs.svh] \
    src/generated/usb_ocp_recovery_reg_addr_defs.svh] {

    if {![file isfile $sourceHeader]} {
        error "Missing source header: $sourceHeader"
    }
    set destination [file join $caliptrapackageDir $relativeHeader]
    file mkdir [file dirname $destination]
    file copy -force $sourceHeader $destination

    foreach groupName {xilinx_anylanguagesynthesis xilinx_anylanguagebehavioralsimulation} {
        set group [ipx::get_file_groups $groupName -of_objects [ipx::current_core]]
        if {[llength $group] != 1} {
            error "Expected IP file group: $groupName"
        }
        set headerFile [ipx::get_files $relativeHeader -of_objects $group]
        if {[llength $headerFile] == 0} {
            set headerFile [ipx::add_file $relativeHeader $group]
        }
        set_property type systemVerilogSource $headerFile
        set_property is_include true $headerFile
    }
}

# Preserve assertion include files needed by simulation.
set assertHeaders [glob \
  $caliptrartlDir/src/caliptra_prim/rtl/caliptra_prim_assert*.svh]

file mkdir [file join $caliptrapackageDir src]

foreach header $assertHeaders {
  set relativeName "src/[file tail $header]"
  file copy -force $header [file join $caliptrapackageDir $relativeName]

  foreach groupName {xilinx_anylanguagesynthesis xilinx_anylanguagebehavioralsimulation} {
    set group [ipx::get_file_groups $groupName -of_objects [ipx::current_core]]
    if {[llength $group] != 1} {
      error "Expected IP file group: $groupName"
    }

    set packagedFile [ipx::get_files $relativeName -of_objects $group]
    if {[llength $packagedFile] == 0} {
      set packagedFile [ipx::add_file $relativeName $group]
    }

    set_property type systemVerilogSource $packagedFile
    set_property is_include true $packagedFile
  }
}
# HTG940 packaging workaround: leave upstream RTL unchanged.
if {$BOARD eq "HTG940"} {
  set headerName caliptra_prim_module_name_macros.svh
  set sourceHeader [file join $caliptrartlDir src caliptra_prim rtl $headerName]

  set fh [open $sourceHeader r]
  set originalHeader [read $fh]
  close $fh

  # Preserve the original license and introductory comments.
  set guard {`ifndef caliptra_prim_module_name_macros_SVH}
  set guardPos [string first $guard $originalHeader]
  if {$guardPos < 0} {
    error "Expected include guard not found in $sourceHeader"
  }
  set generatedHeader [string range $originalHeader 0 [expr {$guardPos - 1}]]

  append generatedHeader {
`ifndef caliptra_prim_module_name_macros_SVH
`define caliptra_prim_module_name_macros_SVH

`define CALIPTRA_PRIM_MODULE_NAME_EXPAND(prefix, name) prefix``_``name

`ifndef CALIPTRA_PRIM_MODULE_PREFIX
`define CALIPTRA_PRIM_MODULE_PREFIX caliptra_prim_generic
`define CALIPTRA_PRIM_MODULE_NAME(__name) caliptra_prim_generic``_``__name
`else
`define CALIPTRA_PRIM_MODULE_NAME(__name) `CALIPTRA_PRIM_MODULE_NAME_EXPAND(`CALIPTRA_PRIM_MODULE_PREFIX, __name)
`endif

`endif
}

  set relativeHeader "src/$headerName"
  file mkdir [file join $caliptrapackageDir src]
  set fh [open [file join $caliptrapackageDir $relativeHeader] w]
  puts -nonewline $fh $generatedHeader
  close $fh

  foreach groupName {xilinx_anylanguagesynthesis xilinx_anylanguagebehavioralsimulation} {
    set group [ipx::get_file_groups $groupName -of_objects [ipx::current_core]]
    if {[llength $group] != 1} {
      error "Expected IP file group: $groupName"
    }

    set headerFile [ipx::get_files $relativeHeader -of_objects $group]
    if {[llength $headerFile] == 0} {
      set headerFile [ipx::add_file $relativeHeader $group]
    }
    set_property type systemVerilogSource $headerFile
    set_property is_include true $headerFile
  }

  puts "HTG940: packaged module-name macro compatibility header."
}


# XSim workaround: explicit sampling clocks in the packaged assertion macro.
if {$BOARD eq "HTG940"} {
  set assertFile [file join $caliptrapackageDir src caliptra_prim_assert.sv]

  if {![file isfile $assertFile]} {
    error "Missing packaged assertion file: $assertFile"
  }

  set fh [open $assertFile r]
  set assertText [read $fh]
  close $fh

  set oldStable {$stable(__state)}
  set newStable {$stable(__state, @(posedge __clk))}
  set oldPast   {$past(__state)}
  set newPast   {$past(__state, 1, 1'b1, @(posedge __clk))}

  foreach old [list $oldStable $oldPast] {
    if {[string first $old $assertText] < 0} {
      error "Expected assertion expression not found: $old"
    }
  }

  set assertText [string map [list \
    $oldStable $newStable \
    $oldPast   $newPast \
  ] $assertText]

  set fh [open $assertFile w]
  puts -nonewline $fh $assertText
  close $fh

  puts "Applied explicit assertion clocks: $assertFile"
}

# Infer interfaces
ipx::infer_bus_interfaces xilinx.com:interface:bram_rtl:1.0 [ipx::current_core]
ipx::add_bus_parameter MASTER_TYPE [ipx::get_bus_interfaces rom_backdoor -of_objects [ipx::current_core]]
ipx::add_bus_parameter MASTER_TYPE [ipx::get_bus_interfaces mcu_rom_backdoor -of_objects [ipx::current_core]]
ipx::add_bus_parameter MASTER_TYPE [ipx::get_bus_interfaces otp_mem_backdoor -of_objects [ipx::current_core]]
# Associate clocks to busses
ipx::associate_bus_interfaces -busif S_AXI_WRAPPER -clock core_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif S_AXI_CALIPTRA -clock core_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif M_AXI_CALIPTRA -clock core_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif rom_backdoor -clock rom_backdoor_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif mcu_rom_backdoor -clock mcu_rom_backdoor_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif otp_mem_backdoor -clock otp_mem_backdoor_clk [ipx::current_core]

ipx::associate_bus_interfaces -busif M_AXI_MCU_IFU -clock core_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif M_AXI_MCU_LSU -clock core_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif M_AXI_MCU_SB -clock core_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif S_AXI_MCI -clock core_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif S_AXI_MCU_ROM -clock core_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif S_AXI_OTP -clock core_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif S_AXI_LCC -clock core_clk [ipx::current_core]

# USB AXI slave interfaces
ipx::associate_bus_interfaces -busif S_AXI_USB_COMBO  -clock core_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif S_AXI_USB_DEV0_MEM -clock core_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif S_AXI_USB_DEV1_CSR  -clock core_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif S_AXI_USB_DEV1_MEM -clock core_clk [ipx::current_core]
# Different clock used for I3C
ipx::associate_bus_interfaces -busif S_AXI_I3C -clock i3c_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif S_AXI_I3C_SPARE -clock i3c_clk [ipx::current_core]

# Other packager settings
set_property name caliptra_package_top [ipx::current_core]
set_property core_revision 1 [ipx::current_core]
set_property PAYMENT_REQUIRED FALSE [ipx::current_core]
ipx::update_source_project_archive -component [ipx::current_core]
ipx::create_xgui_files [ipx::current_core]
ipx::update_checksums [ipx::current_core]
ipx::check_integrity [ipx::current_core]
ipx::save_core [ipx::current_core]

# Close caliptra_package_project
close_project

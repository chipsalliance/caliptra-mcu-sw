# USB source set for usb2 4d4c3d54: compound variants replace legacy units.
set htgUsbRoot [file join $ssrtlDir third_party usb2 src]
set htgUsbVhdl {
    usb_hub_composite_device/RTL/INTERFACE/usb_ep_config_hub_pkg.p.vhdl
    usb_hub_composite_device/RTL/INTERFACE/usb_general_subcmp_pkg.p.vhdl
    usb_hub_composite_device/RTL/RTL/usb_ahb_slave.m.vhdl
    usb_hub_composite_device/RTL/RTL/usb_mux.m.vhdl
    usb_hub_composite_device/RTL/RTL/usb_ocp_recovery_post_sync_arb.m.vhdl
    usb_hub_composite_device/RTL/RTL/usb_synchronizer.m.vhdl
    usb_hub_composite_device/RTL/INTERFACE/ip_xxx_3511_hs_mem_compound.e.vhdl
    usb_hub_composite_device/RTL/INTERFACE/usb_subcmp_pkg.p.vhdl
    usb_hub_composite_device/RTL/RTL/ahb_dma_slave.m.vhdl
    usb_hub_composite_device/RTL/RTL/usb_ep0_handler.m.vhdl
    usb_hub_composite_device/RTL/RTL/usb_ep0_hub_descr.m.vhdl
    usb_hub_composite_device/RTL/RTL/usb_ep_config_handler.m.vhdl
    usb_hub_composite_device/RTL/INTERFACE/usb_configuration_subcmp_pkg.p.vhdl
    usb_hub_composite_device/RTL/RTL/usb_app_hw_hub.m.vhdl
    usb_hub_composite_device/RTL/RTL/usb_dma.m.vhdl
    usb_hub_composite_device/RTL/RTL/usb_pie.m.vhdl
    usb_hub_composite_device/RTL/RTL/usb_reg_if.m.vhdl
    usb_hub_composite_device/RTL/STRUCTURE/ip_xxx_3511_hs_mem_compound_structure.a.vhdl
}
foreach rel $htgUsbVhdl {
    set f [file join $htgUsbRoot $rel]
    if {![file isfile $f]} {error "Missing USB VHDL source: $f"}
    # HTG940_USB_VHDL_COMMENT_FIX
    if {[file tail $f] in {
        ip_xxx_3511_hs_mem_compound.e.vhdl
        ip_xxx_3511_hs_mem_compound_structure.a.vhdl
    }} {
        set fh [open $f r]
        set htgVhdlText [read $fh]
        close $fh

        # Keep legacy debug/PHY comments inactive in synthesis.
        regsub -all -nocase -- \
            {--[ \t]*synthesis[ \t]+read_comments_as_HDL[ \t]+(on|off)} \
            $htgVhdlText \
            {-- HTG940: legacy comment activation disabled} \
            htgVhdlText

        set htgVhdlDir [file join $outputDir htg940_usb_vhdl]
        file mkdir $htgVhdlDir
        set f [file join $htgVhdlDir [file tail $f]]
        set fh [open $f w]
        puts -nonewline $fh $htgVhdlText
        close $fh
    }
    add_files -norecurse $f
    set_property library rtl [get_files $f]
}
set htgUsbSv {
    integration/rtl/generated/usb_ocp_recovery_reg_pkg.sv
    integration/rtl/usb_ocp_recovery_pkg.sv
    integration/rtl/usb_compound_pkg.sv
    integration/rtl/axilite_to_ahb.sv
    integration/rtl/axi_to_ahb.sv
    integration/rtl/generated/usb_ocp_recovery_reg.sv
    integration/rtl/usb_ocp_recovery_ctrl_decode.sv
    integration/rtl/usb_ocp_recovery_rb_adapter.sv
    integration/rtl/usb_ocp_recovery_cms_fifo.sv
    integration/rtl/usb_ocp_recovery_top.sv
    integration/rtl/usb_compound_ahb_decoder.sv
    integration/rtl/ip_xxx_3511_hs_mem_compound_wrapper.sv
}
foreach rel $htgUsbSv {
    set f [file join $htgUsbRoot $rel]
    if {![file isfile $f]} {error "Missing USB SV source: $f"}
    add_files -norecurse $f
}
set_property include_dirs [concat [get_property include_dirs [current_fileset]] \
    [list [file join $htgUsbRoot integration rtl] \
          [file join $htgUsbRoot integration rtl generated]]] [current_fileset]


# HTG940_USB_RECOVERY_HEADER
set htgUsbHeader [file join $htgUsbRoot integration rtl generated usb_ocp_recovery_reg_addr_defs.svh]
if {![file isfile $htgUsbHeader]} {
    error "Missing USB register header: $htgUsbHeader"
}
add_files -norecurse $htgUsbHeader
set_property file_type {Verilog Header} [get_files $htgUsbHeader]

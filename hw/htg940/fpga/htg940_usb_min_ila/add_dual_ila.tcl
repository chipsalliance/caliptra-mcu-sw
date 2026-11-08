# Resolve all dual-domain probes before modifying the synthesized design.
set diagnosticDir [file dirname [file normalize [info script]]]
source [file join $diagnosticDir probe_schema.tcl]
proc min_one {objects label} {
    if {[llength $objects] != 1} {
        error "$label: expected one object, found $objects"
    }
    return [lindex $objects 0]
}
proc min_pin_net {pin} {
    return [min_one [get_nets -quiet -of_objects $pin] "net on $pin"]
}
proc min_pad_buffer {port ref padpin} {
    set portObject [min_one [get_ports -quiet [list $port]] "port $port"]
    set nets [get_nets -quiet -segments -of_objects $portObject]
    set pins [get_pins -quiet -of_objects $nets -filter "REF_PIN_NAME == $padpin"]
    set cells [get_cells -quiet -of_objects $pins -filter "REF_NAME == $ref"]
    return [min_one [lsort -unique $cells] "$port $ref"]
}
proc min_hier_pin_net {pattern} {
    set pins [get_pins -quiet -hier -filter "NAME =~ $pattern"]
    return [min_pin_net [min_one $pins "pin $pattern"]]
}
proc min_signal {instance signal width} {
    set expression [format {^.*/%s/%s(\[[0-9]+\])?$} $instance $signal]
    set nets [lsort -dictionary [get_nets -quiet -hier -regexp $expression]]
    if {[llength $nets] != $width} {
        error "$instance/$signal: expected $width bits, found $nets. Do not continue implementation."
    }
    return $nets
}
proc min_schema_probes {schema} {
    set probes {}
    foreach spec $schema {
        lassign $spec instance signal width
        lappend probes [list "$instance/$signal" [min_signal $instance $signal $width]]
    }
    return $probes
}
proc min_add_ila {name clk probes} {
    create_debug_core $name ila
    set core [get_debug_cores $name]
    set_property C_DATA_DEPTH 1024 $core
    set_property C_ADV_TRIGGER false $core
    set_property C_EN_STRG_QUAL false $core
    connect_debug_port $name/clk [get_nets [list $clk]]
    set index 0
    foreach spec $probes {
        lassign $spec label nets
        if {$index > 0} {create_debug_port $name probe}
        set port "$name/probe$index"
        set_property port_width [llength $nets] [get_debug_ports $port]
        set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports $port]
        set_property MARK_DEBUG true [get_nets $nets]
        connect_debug_port $port [get_nets $nets]
        puts "HTG_ILA $port $label -> $nets"
        incr index
    }
}
set existing [lsearch -all -inline -not -exact [get_debug_cores -quiet] dbg_hub]
if {[llength $existing] != 0} {
    error "Existing ILA found; reopen the clean synthesized design."
}
set rx {}; set tx {}; set tristate {}
for {set k 0} {$k < 8} {incr k} {
    set port [format {cptra_ss_usb_ulpi_data_io[%d]} $k]
    # An OBUF is a functional error, not an acceptable fallback.
    set cell [min_pad_buffer $port IOBUF IO]
    lappend rx [min_pin_net [get_pins [list "$cell/O"]]]
    lappend tx [min_pin_net [get_pins [list "$cell/I"]]]
    lappend tristate [min_pin_net [get_pins [list "$cell/T"]]]
    puts "HTG_IOBUF $port -> $cell"
}
set tnet [min_one [lsort -unique $tristate] "shared ULPI IOBUF tristate"]
set hub */usb_core_i/u_hub_compound
set ulpiClock [min_hier_pin_net $hub/usb_pie_1/pie_clk]
set coreClock [min_hier_pin_net $hub/usb_reg_if_1/hclk]
set dirCell [min_pad_buffer cptra_ss_usb_ulpi_dir_i IBUF I]
set nxtCell [min_pad_buffer cptra_ss_usb_ulpi_nxt_i IBUF I]
set stpCell [min_pad_buffer cptra_ss_usb_ulpi_stp_o OBUF O]
set ulpiProbes [list \
    [list FMC_DATA_RX $rx] \
    [list FMC_DATA_TX $tx] \
    [list FMC_DIR [list [min_pin_net [get_pins "$dirCell/O"]]]] \
    [list FMC_NXT [list [min_pin_net [get_pins "$nxtCell/O"]]]] \
    [list FMC_STP [list [min_pin_net [get_pins "$stpCell/I"]]]] \
    [list FPGA_DATA_RELEASE [list $tnet]] \
    [list USB_ULPI_TXENABLE [list [min_hier_pin_net $hub/ulpi_txenable]]]]
set ulpiProbes [concat $ulpiProbes [min_schema_probes $htg_ulpi_schema]]
set coreProbes [min_schema_probes $htg_core_schema]
set heartbeat [min_one [get_nets -quiet -hier -filter \
    {NAME =~ */cptra_wrapper/htg_ulpi_clock_activity}] "synchronized ULPI activity"]
lappend coreProbes [list ULPI_CLOCK_ACTIVITY_SYNC [list $heartbeat]]
puts "HTG_PROBES_VALIDATED: eight IOBUFs, ULPI and core-domain probes resolved."
if {![info exists htgValidateOnly] || !$htgValidateOnly} {
    min_add_ila ulpi_min_ila $ulpiClock $ulpiProbes
    min_add_ila usb_core_ila $coreClock $coreProbes
    set actual [lsort [lsearch -all -inline -not -exact [get_debug_cores -quiet] dbg_hub]]
    if {$actual ne [list ulpi_min_ila usb_core_ila]} {
        error "Expected exactly the two diagnostic ILAs, got $actual"
    }
    puts "HTG_DUAL_ILA_ONLY_VERIFIED: $actual"
    set debugHub [min_one [get_debug_cores -quiet dbg_hub] "debug hub"]
    connect_debug_port dbg_hub/clk [get_nets [list $coreClock]]
    set_property C_CLK_INPUT_FREQ_HZ 40000000 $debugHub
    puts "HTG_DEBUG_HUB_CLOCK: free-running 40 MHz core clock $coreClock"
}

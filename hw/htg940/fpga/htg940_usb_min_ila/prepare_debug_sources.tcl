# Build-local attributes: do not modify the USB submodule's original sources.
source [file join $fpgaDir htg940_usb_min_ila probe_schema.tcl]
foreach {instance filename} {
    usb_pie_1 usb_pie.m.vhdl
    usb_synchronizer_1 usb_synchronizer.m.vhdl
    usb_reg_if_1 usb_reg_if.m.vhdl
    u_hub_compound ip_xxx_3511_hs_mem_compound_structure.a.vhdl
} {
    set matches {}
    foreach file [get_files -quiet *$filename] {
        if {[string first usb_hub_composite_device $file] >= 0 ||
            [file dirname [file normalize $file]] eq
                [file normalize [file join $outputDir htg940_usb_vhdl]]} {
            lappend matches $file
        }
    }
    if {[llength $matches] != 1} {
        error "Expected one composite-device source $filename; got $matches"
    }
    set original [lindex $matches 0]
    set library [get_property LIBRARY [get_files $original]]
    set fh [open $original r]
    set text [read $fh]
    close $fh
    set attributes "\n"
    if {$instance eq "usb_pie_1"} {
        append attributes "signal htg_ulpi_state : std_logic_vector(4 downto 0);\n"
    }
    append attributes "attribute mark_debug : string;\nattribute keep : string;\n"
    set signals {}
    foreach spec [concat $htg_ulpi_schema $htg_core_schema] {
        lassign $spec owner signal width
        if {$owner eq $instance} {lappend signals $signal}
    }
    foreach signal [lsort -unique $signals] {
        append attributes "attribute mark_debug of $signal : signal is \"true\";\n"
        append attributes "attribute keep of $signal : signal is \"true\";\n"
    }
    switch $instance {
        usb_pie_1 {set anchorSignal pie_success_int}
        usb_synchronizer_1 {set anchorSignal pie_lowpower_n_s}
        usb_reg_if_1 {set anchorSignal reg_dev_force_fullspeed}
        u_hub_compound {set anchorSignal zero7}
    }
    set expression [format {\n[ \t]*signal %s[^\n]*\n} $anchorSignal]
    set anchors [regexp -all -inline $expression $text]
    if {[llength $anchors] != 1} {
        error "Expected one architecture declaration anchor in $original"
    }
    set anchor [lindex $anchors 0]
    set text [string map [list $anchor "$anchor$attributes"] $text]
    if {$instance eq "usb_pie_1"} {
        if {![regexp {end function test_paket_decod;[\r\n \t]*begin} $text anchor]} {
            error "PIE architecture body not found"
        }
        set text [string map [list $anchor \
            "$anchor\nhtg_ulpi_state <= usb_pie_fpga(21 downto 17);\n"] $text]
    }
    set generated [file join $outputDir htg_debug_$filename]
    set fh [open $generated w]
    puts -nonewline $fh $text
    close $fh
    remove_files [get_files $original]
    add_files -norecurse $generated
    set_property LIBRARY $library [get_files $generated]
    set_property file_type {VHDL 2008} [get_files $generated]
}

set fh [open $wrapperGenerated r]
set text [read $fh]
close $fh
set anchor {// USB ULPI signals}
if {[llength [regexp -all -inline $anchor $text]] != 1} {
    error "Expected one ULPI monitor insertion point"
}
set monitor {
// A divided ULPI clock observed through a two-flop core-clock synchronizer.
logic [7:0] htg_ulpi_count;
(* ASYNC_REG = "TRUE", SHREG_EXTRACT = "NO" *)
logic [1:0] htg_ulpi_clock_sync;
(* mark_debug = "true", keep = "true" *)
wire htg_ulpi_clock_activity = htg_ulpi_clock_sync[1];
always_ff @(posedge USB_ULPI_CLK or negedge axi_reset) begin
    if (!axi_reset) htg_ulpi_count <= '0;
    else htg_ulpi_count <= htg_ulpi_count + 1'b1;
end
always_ff @(posedge core_clk or negedge axi_reset) begin
    if (!axi_reset) htg_ulpi_clock_sync <= '0;
    else htg_ulpi_clock_sync <= {htg_ulpi_clock_sync[0], htg_ulpi_count[7]};
end
}
set text [string map [list $anchor "$monitor\n$anchor"] $text]
set fh [open $wrapperGenerated w]
puts -nonewline $fh $text
close $fh

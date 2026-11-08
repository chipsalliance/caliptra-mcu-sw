set boardSource [file normalize [file join $fpgaDir constraints htg940_board_nxp.xdc]]
set localDir [file join [file dirname $project] dual_ila_constraints]
set localBoard [file join $localDir htg940_board_io.xdc]
set localDebug [file join $localDir dual_ila_debug.xdc]
set original [get_files -quiet $boardSource]
if {[llength $original] == 1} {
    set synthUse [get_property USED_IN_SYNTHESIS $original]
    set implUse [get_property USED_IN_IMPLEMENTATION $original]
    set order [get_property PROCESSING_ORDER $original]
    puts [exec python3 [file join $diagnosticDir prepare_dual_ila_constraints.py] \
        $boardSource $localDir]
    remove_files $original
    add_files -fileset constrs_1 -norecurse $localBoard
    set_property USED_IN_SYNTHESIS $synthUse [get_files $localBoard]
    set_property USED_IN_IMPLEMENTATION $implUse [get_files $localBoard]
    set_property PROCESSING_ORDER $order [get_files $localBoard]
} elseif {[llength $original] != 0 || [llength [get_files -quiet $localBoard]] != 1} {
    error "Expected shared board XDC or its isolated build-local replacement"
}
if {![file exists $localDebug]} {error "Missing build-local debug XDC: $localDebug"}
if {[file size $localDebug] > 0} {
    file copy $localDebug "$localDebug.[clock microseconds].previous"
    set fh [open $localDebug w]
    close $fh
}
if {[llength [get_files -quiet $localDebug]] == 0} {
    add_files -fileset constrs_1 -norecurse $localDebug
}
set_property USED_IN_SYNTHESIS false [get_files $localDebug]
set_property USED_IN_IMPLEMENTATION true [get_files $localDebug]
set_property PROCESSING_ORDER LATE [get_files $localDebug]
set_property TARGET_CONSTRS_FILE $localDebug [get_filesets constrs_1]
puts "HTG_DUAL_ILA_CONSTRAINT_TARGET: $localDebug (shared board XDC is not a save target)"

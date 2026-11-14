set VERSION [exec git rev-parse --short=8 HEAD]
set htgReleaseDir [file dirname [file normalize [info script]]]
source [file join $htgReleaseDir python.tcl]
puts [exec {*}$htgPython [file join $htgReleaseDir prepare_sources.py] --check]
if {[llength [lsearch -all -inline -glob $argv FW_IMAGE_DIR=*]] == 0} {
    lappend argv "FW_IMAGE_DIR=[file join $htgReleaseDir firmware]"
}
source [file join $htgReleaseDir .. htg940_usb_min_ila run_dual_ila.tcl]

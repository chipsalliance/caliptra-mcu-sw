# Licensed under the Apache-2.0 license
# Exercise strict net resolution without needing a licensed Vivado installation.
lassign $argv fpga_dir output_dir mode
source [file join $fpga_dir entropy_ila.tcl]
source [file join $output_dir entropy_ila_probes.tcl]
set root {design/caliptra_top[0]}
set mock_nets {}
set mock_ports [dict create]
set mock_connections [dict create]
set mock_core 0
foreach probe $entropy_ila_probes {
  lassign $probe signal width scope
  for {set bit [expr {$width - 1}]} {$bit >= 0} {incr bit -1} {
    lappend mock_nets [format {%s/%s%s[%d]} $root $scope $signal $bit]
  }
}
foreach event $entropy_ila_events {
  lassign $event signal scope
  lappend mock_nets "$root/$scope$signal"
}
# A marked secret-looking net must never be selected by an allowlisted probe.
lappend mock_nets "$root/unrelated_secret_payload"
set mock_clock "$root/fpga_entropy_ila_sample_clk"
switch $mode {
  missing { set mock_nets [lrange $mock_nets 1 end] }
  duplicate { lappend mock_nets [lindex $mock_nets 0] }
  two_roots { lappend mock_nets {other/caliptra_top/fpga_entropy_ila_top[0]} }
  missing_clock { set mock_clock {} }
  missing_event { set mock_nets [lrange $mock_nets 0 end-2] }
}
proc get_property {property object} { return $object }
proc get_nets {args} {
  if {[lsearch -exact $args -regexp] >= 0} {
    if {$::mock_clock eq {}} { return {} }
    if {![regexp [lindex $args end] $::mock_clock]} { error "incorrect clock escaping" }
    return [list $::mock_clock]
  }
  return $::mock_nets
}
proc get_debug_cores {args} {
  if {$::mock_core} { return entropy_ila }
  return {}
}
proc create_debug_core {name kind} {
  if {$name ne "entropy_ila" || $kind ne "ila"} { error "unexpected debug core" }
  set ::mock_core 1
}
proc set_property {name value object} {
  if {$name eq "port_width"} { dict set ::mock_ports $object $value }
}
proc get_debug_ports {name} { return $name }
proc create_debug_port {name kind} {
  if {$name ne "entropy_ila" || $kind ne "probe"} { error "unexpected port" }
}
proc connect_debug_port {name nets} { dict set ::mock_connections $name $nets }
set failed [catch {entropy_ila_insert $output_dir} message]
if {$mode ne "ok"} {
  if {!$failed || $mock_core} { error "negative control did not fail before insertion: $message" }
  puts "PASS $mode"
  exit 0
}
if {$failed} { error $message }
if {[dict size $mock_ports] != [llength $entropy_ila_probes] + 1} { error "wrong port count" }
set index 0
foreach probe $entropy_ila_probes {
  lassign $probe signal width scope
  set port entropy_ila/probe$index
  if {[dict get $mock_ports $port] != $width} { error "wrong probe width" }
  set bits [dict get $mock_connections $port]
  for {set bit 0} {$bit < $width} {incr bit} {
    set expected [format {%s/%s%s[%d]} $root $scope $signal $bit]
    if {[lindex $bits $bit] ne $expected} { error "probe order changed" }
  }
  incr index
}
set event_port entropy_ila/probe$index
if {[dict get $mock_ports $event_port] != [llength $entropy_ila_events]} { error "wrong event width" }
set bit 0
foreach event $entropy_ila_events {
  lassign $event signal scope
  if {[lindex [dict get $mock_connections $event_port] $bit] ne "$root/$scope$signal"} {
    error "wrong event order"
  }
  incr bit
}
puts "PASS $mode"

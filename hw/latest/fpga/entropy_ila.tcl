# Licensed under the Apache-2.0 license
# Implementation opt_design pre-hook. The generated wrapper sets the directory.
# Do not use the broad DEBUG=TRUE bus probes: they can capture secret bus data.

proc entropy_ila_regex_escape {text} {
  return [regsub -all {[][\\.^$*+?(){}|]} $text {\\&}]
}

proc entropy_ila_bits {nets base width} {
  set indexed [dict create]
  foreach net $nets {
    set name [get_property NAME $net]
    if {![regexp {^(.*)\[([0-9]+)\]$} $name -> candidate bit]} {
      continue
    }
    if {$candidate ne $base} { continue }
    if {$bit >= $width || [dict exists $indexed $bit]} {
      error "Unexpected/duplicate entropy ILA bit: $name"
    }
    dict set indexed $bit $net
  }
  if {[dict size $indexed] != $width} {
    error "Entropy ILA requires all $width bits of $base, found [dict size $indexed]"
  }
  set ordered {}
  for {set bit 0} {$bit < $width} {incr bit} {
    if {![dict exists $indexed $bit]} { error "Missing $base bit $bit" }
    lappend ordered [dict get $indexed $bit]
  }
  return $ordered
}

proc entropy_ila_insert {output_dir} {
  source [file join $output_dir entropy_ila_probes.tcl]
  set nets [get_nets -quiet -hierarchical -filter {MARK_DEBUG == 1}]
  set roots {}
  foreach net $nets {
    set name [get_property NAME $net]
    if {[regexp {^(.*)/fpga_entropy_ila_top\[[0-9]+\]$} $name -> root]} {
      lappend roots $root
    }
  }
  set roots [lsort -unique $roots]
  if {[llength $roots] != 1} {
    error "Expected one instrumented Caliptra top, found: $roots"
  }
  set root [lindex $roots 0]
  set clock_path "$root/fpga_entropy_ila_sample_clk"
  set clock [get_nets -quiet -hierarchical -regexp "^[entropy_ila_regex_escape $clock_path]$"]
  if {[llength $clock] != 1} { error "Missing unique entropy ILA sample clock" }
  if {[llength [get_debug_cores -quiet entropy_ila]] != 0} {
    error "entropy_ila already exists"
  }

  # Resolve the complete allowlist before creating a core. No automatic expansion
  # to buses, arbitrary marked nets, or raw entropy storage is permitted.
  set resolved {}
  foreach probe $entropy_ila_probes {
    lassign $probe signal width scope
    set base "$root/$scope$signal"
    lappend resolved [list $width [entropy_ila_bits $nets $base $width]]
  }
  set event_bits {}
  foreach event $entropy_ila_events {
    lassign $event signal scope
    set base "$root/$scope$signal"
    set matches {}
    foreach net $nets {
      if {[get_property NAME $net] eq $base} { lappend matches $net }
    }
    if {[llength $matches] != 1} { error "Missing unique entropy change flag: $base" }
    lappend event_bits [lindex $matches 0]
  }
  lappend resolved [list [llength $event_bits] $event_bits]
  create_debug_core entropy_ila ila
  set core [get_debug_cores entropy_ila]
  set_property C_DATA_DEPTH 8192 $core
  set_property C_ADV_TRIGGER true $core
  set_property C_EN_STRG_QUAL true $core
  set_property C_INPUT_PIPE_STAGES 0 $core
  connect_debug_port entropy_ila/clk $clock

  set report [open [file join $output_dir entropy_ila_connected.txt] w]
  puts $report "Lab-only ES0 entropy ILA; all observation registers add one core cycle."
  puts $report "Clock: $clock_path"
  puts $report "Last probe is change flags; qualify storage on != 0. Cycle timestamp is unqualified."
  set index 0
  foreach probe $resolved {
    lassign $probe width bits
    if {$index > 0} { create_debug_port entropy_ila probe }
    set port "entropy_ila/probe$index"
    set_property port_width $width [get_debug_ports $port]
    connect_debug_port $port $bits
    puts $report "$port: [join $bits { }]"
    incr index
  }
  close $report
}

# Tests can source the helper functions without invoking Vivado.
if {[info exists entropy_ila_output_dir]} {
  entropy_ila_insert $entropy_ila_output_dir
}

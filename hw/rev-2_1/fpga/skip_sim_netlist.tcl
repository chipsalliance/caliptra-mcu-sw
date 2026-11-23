# Licensed under the Apache-2.0 license

# Synthesis post hook that turns the simulation netlist writes of an IP run into no-ops.
foreach cmd {write_vhdl write_verilog} {
  rename ::$cmd ::${cmd}_orig
  proc ::$cmd {args} "
    if {\[lsearch -exact \$args funcsim\] >= 0} {
      puts \"Skipping $cmd -mode funcsim\"
      return
    }
    uplevel 1 \[list ::${cmd}_orig {*}\$args\]
  "
}

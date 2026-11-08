# Licensed under the Apache-2.0 license

# Vivado prepends its bundled Python to PATH; use the caller's interpreter.
if {![info exists ::env(HTG_PYTHON)] || $::env(HTG_PYTHON) eq ""} {
    error "Set HTG_PYTHON to the absolute path of a Python 3.9+ interpreter before launching Vivado"
}
if {[file pathtype $::env(HTG_PYTHON)] ne "absolute" ||
    ![file executable $::env(HTG_PYTHON)]} {
    error "HTG_PYTHON must name an executable absolute path: $::env(HTG_PYTHON)"
}
set htgPython $::env(HTG_PYTHON)
puts [exec $htgPython -c {
import sys
if sys.version_info < (3, 9):
    raise SystemExit("HTG-940 requires Python 3.9 or newer")
print("HTG940_PYTHON_READY:", sys.executable, sys.version.split()[0])
}]

# Licensed under the Apache-2.0 license

import shutil
import subprocess
import unittest
from pathlib import Path


RESOLVER = (
    Path(__file__).resolve().parents[1]
    / "fpga"
    / "htg940_usb_min_ila"
    / "add_dual_ila.tcl"
)


class ProbeResolutionTests(unittest.TestCase):
    def resolve(self, fixture, width=1):
        source = RESOLVER.read_text()
        procedures = "proc min_one" + source.split("proc min_one", 1)[1].split(
            "\nset existing", 1
        )[0]
        script = procedures + r"""
set named_nets {}
set pins {}
array set pin_nets {}
proc get_pins {args} {
    return [lsearch -all -inline -regexp $::pins [lindex $args end]]
}
proc get_nets {args} {
    if {[lsearch -exact $args -of_objects] >= 0} {
        return $::pin_nets([lindex $args end])
    }
    return [lsearch -all -inline -regexp $::named_nets [lindex $args end]]
}
"""
        script += fixture
        script += f"""
if {{[catch {{min_signal u_hub_compound hresetn {width}}} result]}} {{
    puts stderr $result
    exit 1
}}
puts $result
"""
        tclsh = shutil.which("tclsh")
        self.assertIsNotNone(tclsh, "tclsh is required to validate probe resolution")
        return subprocess.run(
            [tclsh], input=script, capture_output=True, text=True
        )

    def test_merged_reset_port_uses_connected_parent_net(self):
        result = self.resolve("""
set pins {top/u_hub_compound/hresetn}
set pin_nets(top/u_hub_compound/hresetn) {top/subsystem_reset_n}
""")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "top/subsystem_reset_n")

    def test_named_internal_net_does_not_require_a_port(self):
        result = self.resolve("set named_nets {top/u_hub_compound/hresetn}\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "top/u_hub_compound/hresetn")

    def test_vector_port_keeps_bit_order_and_repeated_connections(self):
        result = self.resolve("""
set pins {top/u_hub_compound/hresetn[2] top/u_hub_compound/hresetn[0] top/u_hub_compound/hresetn[1]}
set {pin_nets(top/u_hub_compound/hresetn[0])} {top/shared}
set {pin_nets(top/u_hub_compound/hresetn[1])} {top/other}
set {pin_nets(top/u_hub_compound/hresetn[2])} {top/shared}
""", width=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "top/shared top/other top/shared")

    def test_missing_net_and_port_fail(self):
        result = self.resolve("")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected 1 bits, found", result.stderr)

    def test_unrelated_reset_names_are_not_substituted(self):
        result = self.resolve("""
set named_nets {top/u_hub_compound/not_hresetn}
set pins {top/u_hub_compound/other_reset_n}
""")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected 1 bits, found", result.stderr)

    def test_ambiguous_ports_fail(self):
        result = self.resolve("""
set pins {top/a/u_hub_compound/hresetn top/b/u_hub_compound/hresetn}
""")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected 1 port bits, found", result.stderr)

    def test_ambiguous_port_connection_fails(self):
        result = self.resolve("""
set pins {top/u_hub_compound/hresetn}
set pin_nets(top/u_hub_compound/hresetn) {top/reset_a top/reset_b}
""")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected one object", result.stderr)

    def test_partial_named_vector_fails_without_port_fallback(self):
        result = self.resolve("""
set named_nets {top/u_hub_compound/hresetn[0]}
set pins {top/u_hub_compound/hresetn[0] top/u_hub_compound/hresetn[1]}
""", width=2)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected 2 bits, found", result.stderr)

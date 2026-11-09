# Licensed under the Apache-2.0 license

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

FPGA_DIR = Path(__file__).resolve().parents[1]
RTL_DIR = FPGA_DIR.parent / "caliptra-ss/third_party/caliptra-rtl"
spec = importlib.util.spec_from_file_location("entropy_ila", FPGA_DIR / "entropy_ila.py")
ila = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ila)


class ProbeTests(unittest.TestCase):
    def test_layout_widths_and_names(self):
        names = [probe["name"] for probe in ila.PROBES]
        self.assertEqual(len(names), len(set(names)))
        for probe in ila.PROBES:
            self.assertLessEqual(sum(f["width"] for f in probe["fields"]), probe["width"])
            self.assertEqual(probe["scope"].startswith("entropy_src1/"), False)

    def test_observers_are_sampled_without_probe_reset(self):
        text = ila.instrument("module example;\nendmodule\n", [ila.PROBES[0]])
        self.assertEqual(text.count("always_ff"), 3)
        self.assertIn("@(posedge fpga_entropy_ila_sample_clk)", text)
        self.assertIn('dont_touch = "true"', text)
        self.assertNotIn("negedge", text)
        self.assertNotIn("if (", text)

    def test_bad_module_shape_rejected(self):
        for text in ("module x;", "endmodule\nendmodule", "fpga_entropy_ila_top\nendmodule"):
            with self.assertRaises(ValueError):
                ila.instrument(text, [ila.PROBES[0]])

    def test_overflow_rejected(self):
        probe = {**ila.PROBES[0], "width": 1}
        with self.assertRaises(ValueError):
            ila.instrument("endmodule", [probe])

    def test_zero_probes_disclose_predicates_not_payload(self):
        zero = next(p for p in ila.PROBES if p["name"] == "combiner_zero")
        for entry in zero["fields"][:6]:
            self.assertEqual(entry["width"], 1)
            self.assertTrue(entry["expression"].startswith("~(|"))
        expressions = [f["expression"] for p in ila.PROBES for f in p["fields"]]
        self.assertNotIn("itrng0_data", expressions)
        self.assertFalse(any("genbits" in expression for expression in expressions))

    def test_wrong_pin_fails_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated"
            with mock.patch("subprocess.check_output", return_value="wrong-revision\n"):
                with self.assertRaisesRegex(ValueError, "unsupported"):
                    ila.generate(Path(directory), output)
            self.assertFalse(output.exists())

    def test_dirty_pinned_sources_fail_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated"
            with mock.patch("subprocess.check_output", return_value=ila.RTL_REVISION + "\n"):
                with mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1)):
                    with self.assertRaisesRegex(ValueError, "match the pinned commit"):
                        ila.generate(Path(directory), output)
            self.assertFalse(output.exists())

    def test_actual_pin_generation_is_repeatable_and_read_only(self):
        sources = {p["source"] for p in ila.PROBES}
        if not all((RTL_DIR / source).is_file() for source in sources):
            self.skipTest("initialize the pinned RTL submodule for the integration check")
        before = {source: (RTL_DIR / source).read_bytes() for source in sources}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            ila.generate(RTL_DIR, output)
            first = {p.name: p.read_bytes() for p in output.iterdir()}
            ila.generate(RTL_DIR, output)
            self.assertEqual(first, {p.name: p.read_bytes() for p in output.iterdir()})
            layout = json.loads((output / "entropy_ila_layout.json").read_text())
            self.assertEqual(layout["sample_latency_cycles"], 1)
            for source in layout["sources"]:
                self.assertEqual(source["sha256"], hashlib.sha256(before[source["path"]]).hexdigest())
            for probe in layout["probes"]:
                self.assertEqual(probe["fields"][0]["lsb"], 0)
        self.assertEqual(before, {source: (RTL_DIR / source).read_bytes() for source in sources})

    def test_tcl_rejects_unsafe_build_modes(self):
        tclsh = os.environ.get("ENTROPY_ILA_TCLSH") or shutil.which("tclsh")
        if not tclsh:
            self.skipTest("tclsh is required for build-mode guards")
        prefix = (FPGA_DIR / "fpga_configuration.tcl").read_text().split(
            "# If VERSION was not set by tclargs", 1
        )[0]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "guard.tcl"
            for argument in (None, "ITRNG=FALSE", "CG_EN=TRUE", "DEBUG=TRUE", "SEGMENTED=TRUE"):
                args = "ENTROPY_ILA=TRUE" + (" " + argument if argument else "")
                path.write_text("set argv {" + args + "}\n" + prefix)
                result = subprocess.run([tclsh, str(path)], capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode == 0, argument is None, result.stderr)

    def test_tcl_probe_resolution_and_negative_controls(self):
        tclsh = os.environ.get("ENTROPY_ILA_TCLSH") or shutil.which("tclsh")
        if not tclsh:
            self.skipTest("tclsh is required for the Vivado-command mock tests")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            # Generation itself is checked against the actual pin above. These
            # tests exercise only the fail-closed Vivado net/port selection.
            specs = [f"{{fpga_entropy_ila_{p['name']} {p['width']} {{{p['scope']}}}}}" for p in ila.PROBES]
            events = [f"{{fpga_entropy_ila_{p['name']}_changed {{{p['scope']}}}}}" for p in ila.PROBES if p.get("events", True)]
            (output / "entropy_ila_probes.tcl").write_text(
                "set entropy_ila_probes {" + " ".join(specs) + "}\n"
                "set entropy_ila_events {" + " ".join(events) + "}\n"
            )
            for mode in ("ok", "missing", "duplicate", "two_roots", "missing_clock", "missing_event"):
                result = subprocess.run(
                    [tclsh, str(FPGA_DIR / "tests/entropy_ila_mock.tcl"), str(FPGA_DIR), str(output), mode],
                    text=True, capture_output=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("PASS " + mode, result.stdout)


if __name__ == "__main__":
    unittest.main()

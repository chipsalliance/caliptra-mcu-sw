# Licensed under the Apache-2.0 license

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FPGA = ROOT / "fpga"
DEBUG = FPGA / "htg940_usb_min_ila"
USB = ROOT / "caliptra-ss" / "third_party" / "usb2" / "src"
SOURCES = {
    "usb_pie_1": "RTL/usb_pie.m.vhdl",
    "usb_synchronizer_1": "RTL/usb_synchronizer.m.vhdl",
    "u_hub_compound": "STRUCTURE/ip_xxx_3511_hs_mem_compound_structure.a.vhdl",
}


class UlpiDebugTests(unittest.TestCase):
    def generate(self, directory, source_root, prepared=False):
        wrapper = directory / "wrapper.sv"
        wrapper.write_text("// USB ULPI signals\n")
        environment = {
            **os.environ,
            "TEST_FPGA": str(FPGA),
            "TEST_OUTPUT": str(directory),
            "TEST_USB": str(source_root),
            "TEST_PREPARED": str(int(prepared)),
        }
        tclsh = shutil.which("tclsh")
        self.assertIsNotNone(tclsh, "tclsh is required to validate debug generation")
        return subprocess.run(
            [tclsh],
            input=r"""
if {[catch {
    set fpgaDir $::env(TEST_FPGA)
    set outputDir $::env(TEST_OUTPUT)
    set wrapperGenerated [file join $outputDir wrapper.sv]
    set files {}
    proc get_files {args} {
        return [lsearch -all -inline -glob $::files [lindex $args end]]
    }
    proc get_property {property objects} {
        if {$property eq "LIBRARY"} {return rtl}
        return {}
    }
    proc current_fileset {} {return sources_1}
    proc set_property {args} {}
    proc add_files {args} {
        set path [lindex $args end]
        if {![file isfile $path]} {error "Missing source: $path"}
        lappend ::files $path
    }
    proc remove_files {objects} {
        foreach path $objects {
            set ::files [lsearch -all -inline -not -exact $::files $path]
        }
    }
    if {$::env(TEST_PREPARED)} {
        set ssrtlDir [file normalize [file join $::env(TEST_USB) .. .. ..]]
        source [file join $fpgaDir htg940_usb_compound_sources.tcl]
    } else {
        set files [glob [file join $::env(TEST_USB) * *.vhdl]]
    }
    source [file join $fpgaDir htg940_usb_min_ila prepare_debug_sources.tcl]
    foreach spec [concat $htg_ulpi_schema $htg_core_schema] {
        puts "PROBE $spec"
    }
} message]} {
    puts stderr $message
    exit 1
}
""",
            env=environment, capture_output=True, text=True,
        )

    def fixture(self, root):
        sources = root / "usb_hub_composite_device"
        for owner, relative in SOURCES.items():
            path = sources / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            anchor = {
                "usb_pie_1": "pie_success_int",
                "usb_synchronizer_1": "pie_lowpower_n_s",
                "u_hub_compound": "dataline_low_power_en",
            }[owner]
            body = "end function test_paket_decod;\nbegin\n" if owner == "usb_pie_1" else ""
            path.write_text(f"\nsignal {anchor} : std_logic;\n{body}")
        return sources

    def test_generation_uses_live_hub_and_real_enum_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self.generate(root, self.fixture(root))
            self.assertEqual(result.returncode, 0, result.stderr)
            pie = (root / "htg_debug_usb_pie.m.vhdl").read_text()
            self.assertIn("t_ulpi_oper_state'pos(ulpi_oper_state_r)", pie)
            self.assertIn("t_ulpi_oper_state'pos(ulpi_oper_state_nxt)", pie)
            self.assertNotIn("usb_pie_fpga", pie)
            self.assertIn("PROBE u_hub_compound usbreg_phy_start 1", result.stdout)
            self.assertNotIn("PROBE usb_reg_if_1", result.stdout)
            wrapper = (root / "wrapper.sv").read_text()
            self.assertIn("{USB_ULPI_DIR, USB_ULPI_NXT, USB_ULPI_STP}", wrapper)
            self.assertIn("htg_ulpi_pins_sync <= htg_ulpi_pins_meta;", wrapper)

    def test_missing_source_anchor_fails_explicitly(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = self.fixture(root)
            (sources / SOURCES["usb_pie_1"]).write_text("begin\n")
            result = self.generate(root, sources)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Expected one architecture declaration anchor", result.stderr)

    @unittest.skipUnless(USB.is_dir(), "prepare the isolated HTG RTL to test real USB2 sources")
    def test_prepared_sources_generate_and_match_every_probe_width(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = {
                path: path.read_bytes()
                for path in (USB / "usb_hub_composite_device").rglob("*.vhdl")
            }
            result = self.generate(root, USB, prepared=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for path, content in original.items():
                self.assertEqual(path.read_bytes(), content, str(path))
            declarations = {}
            probes = re.findall(r"^PROBE (\S+) (\S+) (\d+)$", result.stdout, re.M)
            for owner, relative in SOURCES.items():
                generated = root / ("htg_debug_" + Path(relative).name)
                text = re.sub(r"--[^\n]*", "", generated.read_text())
                signals = {}
                wanted = {signal.lower() for instance, signal, _ in probes if instance == owner}
                for names, vector in re.findall(
                    r"(?im)^\s*(?:signal\s+)?([a-z]\w*(?:\s*,\s*[a-z]\w*)*)"
                    r"\s*:\s*(?:(?:in|out|inout|buffer)\s+)?"
                    r"std_logic(?:_vector\s*\(([^)]*)\))?\s*;",
                    text,
                ):
                    if not wanted.intersection(name.strip().lower() for name in names.split(",")):
                        continue
                    width = 1
                    if vector:
                        high, low = vector.lower().split("downto")
                        if high.strip() == "c_hub_fifo_addrwidth-1":
                            width = 8  # log2 of the full profile's 196-word hub RAM.
                        else:
                            width = int(high) - int(low) + 1
                    for name in names.split(","):
                        signals[name.strip().lower()] = width
                declarations[owner] = signals
            for owner, signal, width in probes:
                with self.subTest(owner=owner, signal=signal):
                    self.assertEqual(declarations[owner].get(signal.lower()), int(width))
            pie = original[USB / "usb_hub_composite_device" / "RTL" / SOURCES["usb_pie_1"]].decode()
            enum = re.search(r"type t_ulpi_oper_state is\s*\((.*?)\);", pie, re.S)
            self.assertIsNotNone(enum)
            states = [state.strip() for state in enum.group(1).split(",")]
            self.assertEqual(states[5], "ULPI_OPER_RESET_WF_RXCMD_UPDATE")
            self.assertEqual(states[7], "ULPI_OPER_IDLE")
            self.assertEqual(states[9], "ULPI_OPER_XREG_WR_TX_CMD")
            self.assertEqual(states[13], "ULPI_OPER_XREG_RD_TX_CMD")

    @unittest.skipUnless(USB.is_dir(), "prepare the isolated HTG RTL to test the FPGA top patch")
    def test_fpga_top_patch_applies_to_pinned_upstream(self):
        result = subprocess.run(
            ["git", "-C", str(ROOT / "caliptra-ss"), "show",
             "HEAD:src/integration/rtl/caliptra_ss_top.sv"],
            check=True, capture_output=True, text=True,
        )
        with tempfile.TemporaryDirectory() as temporary:
            top = Path(temporary) / "caliptra_ss_top.sv"
            top.write_text(result.stdout)
            result = subprocess.run(
                ["patch", "--batch", "--forward", "--fuzz=0", str(top),
                 str(FPGA / "src" / "caliptra_ss_top.patch")],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            text = top.read_text()
            self.assertIn(".clk_i                          (cptra_i3c_clk_i)", text)
            self.assertIn("assign priv_ids[0] = cptra_ss_strap_caliptra_dma_axi_user_i_synch;", text)


if __name__ == "__main__":
    unittest.main()

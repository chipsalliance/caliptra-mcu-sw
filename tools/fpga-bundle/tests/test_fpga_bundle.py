# Licensed under the Apache-2.0 license

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1]
REVISION = "1" * 40
PROVENANCE = (
    "CALIPTRA_HW_REV=latest\n"
    f"MCU subsystem=hw/latest/caliptra-ss {REVISION}\n"
    f"Caliptra FMC/runtime source={REVISION}\n"
)


def mcu_image():
    payload = b"\0" * (131072 - 48)
    return payload + hashlib.sha384(payload).digest()


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.env = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}")
        self.executable("git", f"print({REVISION!r})\n")

    def executable(self, name, source):
        path = self.bin / name
        path.write_text(f"#!{sys.executable}\n" + source)
        path.chmod(0o755)
        return path

    def command(self, name, *args, expected=0):
        result = subprocess.run(
            ["bash", str(SCRIPTS / name), *map(str, args)],
            env=self.env, text=True, capture_output=True, timeout=15,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def artifacts(self):
        directory = self.root / "build"
        directory.mkdir()
        for name, contents in {
            "caliptra_rom.bin": b"core",
            "mcu_rom.bin": mcu_image(),
            "caliptra_fw.bin": b"firmware",
            "soc_manifest.bin": b"manifest",
            "mcu_runtime.bin": b"runtime",
            "hardware-provenance.txt": PROVENANCE.encode(),
            "mcu-rom-provenance.txt": PROVENANCE.encode(),
        }.items():
            (directory / name).write_bytes(contents)
        return directory

    def package(self):
        directory = self.artifacts()
        bundle = self.root / "bundle.zip"
        self.command("create-htg940-fpga-bundle.sh", "--build-dir", directory, "--output", bundle)
        return bundle

    def test_build_uses_workspace_all_build_and_current_htg_feature(self):
        repo = self.root / "workspace"
        (repo / "core/caliptra-sw").mkdir(parents=True)
        (repo / "core/versions.toml").write_text("[versions]\n")
        calls = self.root / "calls.jsonl"
        self.env["TEST_CALLS"] = str(calls)
        self.executable("cargo", f"""
import hashlib, json, os, sys, zipfile
from pathlib import Path
with open(os.environ["TEST_CALLS"], "a") as out:
    out.write(json.dumps({{"args": sys.argv[1:], "env": {{
        k: os.environ[k] for k in ("CALIPTRA_HW_REV", "CALIPTRA_MCU_FUSES_HJSON",
                                  "CALIPTRA_MCU_OTP_MMAP_HJSON")}}}}) + "\\n")
if "all-build" in sys.argv or "rom-build" in sys.argv:
    payload = b"\\0" * (131072 - 48)
    image = payload + hashlib.sha384(payload).digest()
    rom = Path("target/riscv32imc-unknown-none-elf/release/latest-caliptra-mcu-rom-fpga-htg940.bin")
    rom.parent.mkdir(parents=True, exist_ok=True)
    rom.write_bytes(image)
    Path(str(rom) + ".provenance.txt").write_text({PROVENANCE!r})
    if "all-build" in sys.argv:
        output = Path(sys.argv[sys.argv.index("--output") + 1])
        with zipfile.ZipFile(output, "w") as archive:
            for name in ("caliptra_rom.bin", "caliptra_fw.bin", "soc_manifest.bin", "mcu_runtime.bin"):
                archive.writestr(name, b"data")
            archive.writestr("hardware-provenance.txt", {PROVENANCE!r})
""")
        output = self.root / "artifacts"
        self.command("build-htg940-fpga-artifacts.sh", "--mcu-repo", repo, "--output-dir", output)
        entries = [json.loads(line) for line in calls.read_text().splitlines()]
        self.assertEqual(entries[0]["args"], ["xtask", "switch-version", "latest"])
        build = entries[1]
        self.assertEqual(build["args"][:2], ["xtask", "all-build"])
        self.assertEqual(build["args"][build["args"].index("--rom-features") + 1], "htg940")
        self.assertEqual(build["env"]["CALIPTRA_MCU_OTP_MMAP_HJSON"],
                         str(repo / "hw/latest/caliptra-ss/src/fuse_ctrl/data/otp_ctrl_mmap.hjson"))
        self.assertEqual((output / "mcu_rom.bin").read_bytes(), mcu_image())
        before = (output / "caliptra_fw.bin").read_bytes()
        self.command("build-htg940-fpga-artifacts.sh", "--mcu-repo", repo,
                     "--output-dir", output, "--mcu-rom-only")
        self.assertEqual((output / "caliptra_fw.bin").read_bytes(), before)

    def test_bundle_verification_needs_no_windows_tools(self):
        bundle = self.package()
        self.command("test-htg940-fpga-bundle.sh", bundle, "--verify-only")
        with zipfile.ZipFile(bundle) as archive:
            self.assertEqual(archive.read("mcu_rom.bin"), mcu_image())
            self.assertIn(b"mcu_rom_feature=htg940", archive.read("BUNDLE_INFO.txt"))

    def test_changed_recovery_payload_is_rejected(self):
        bundle = self.package()
        changed = self.root / "changed.zip"
        with zipfile.ZipFile(bundle) as source, zipfile.ZipFile(changed, "w") as dest:
            for name in source.namelist():
                dest.writestr(name, b"changed" if name == "soc_manifest.bin" else source.read(name))
        self.command("test-htg940-fpga-bundle.sh", changed, "--verify-only", expected=1)

    def test_invalid_mcu_rom_digest_is_rejected_before_packaging(self):
        directory = self.artifacts()
        (directory / "mcu_rom.bin").write_bytes(b"x" * 131072)
        self.command("create-htg940-fpga-bundle.sh", "--build-dir", directory,
                     "--output", self.root / "bad.zip", expected=1)
        self.assertFalse((self.root / "bad.zip").exists())

    def updater_helpers(self):
        helper = self.root / "Windows helper with spaces"
        helper.mkdir()
        for name in ("htg940_board_top_forced_ulpi.bit",
                     "htg940_board_top_forced_ulpi.mmi", "update-htg940-roms.ps1"):
            (helper / name).write_text("input")
        (helper / "htg940_update_roms.py").write_text("print('validated')\n")
        calls = self.root / "powershell.json"
        self.env["TEST_POWERSHELL"] = str(calls)
        self.executable("wslpath", "import sys\nprint(sys.argv[-1])\n")
        self.executable("powershell.exe", """
import json, os, sys
from pathlib import Path
Path(os.environ["TEST_POWERSHELL"]).write_text(json.dumps(sys.argv[1:]))
output = Path(sys.argv[sys.argv.index("-OutputBitstream") + 1])
output.write_bytes(b"patched")
Path(str(output) + ".json").write_text("{}")
""")
        return helper, calls

    def test_forced_pair_is_forwarded_and_existing_output_is_preserved(self):
        helper, calls = self.updater_helpers()
        core = self.root / "core.bin"
        mcu = self.root / "mcu.bin"
        core.write_bytes(b"core")
        mcu.write_bytes(mcu_image())
        output = helper / "new.bit"
        self.command("update-htg940-roms.sh", core, mcu, output, helper)
        args = json.loads(calls.read_text())
        self.assertEqual(args[args.index("-BaseBitstream") + 1],
                         str(helper / "htg940_board_top_forced_ulpi.bit"))
        self.assertEqual(args[args.index("-MemoryMap") + 1],
                         str(helper / "htg940_board_top_forced_ulpi.mmi"))
        self.command("update-htg940-roms.sh", core, mcu, output, helper, expected=1)
        self.assertEqual(output.read_bytes(), b"patched")

    def test_program_flow_uses_global_python_forced_probes_and_propagates_failure(self):
        bundle = self.package()
        helper, _ = self.updater_helpers()
        (helper / "htg940_usb_dual_ila_forced_ulpi.ltx").write_text("probes")
        (helper / "program-htg940.sh").write_text(
            '#!/bin/bash\nprintf "%s\\n" "$@" > "$TEST_PROGRAM"\n'
        )
        recovery_dir = self.root / "recovery"
        recovery_dir.mkdir()
        for name in ("usb_recovery.py", "htg940_console_updated.py", "entropy_host.py"):
            (recovery_dir / name).write_text("# fixture\n")
        self.env["TEST_PROGRAM"] = str(self.root / "program.txt")
        self.env["TEST_RUN"] = str(self.root / "run.json")
        python = self.executable("windows-python.exe", """
import json, os, sys
from pathlib import Path
if "--preflight" not in sys.argv:
    Path(os.environ["TEST_RUN"]).write_text(json.dumps(sys.argv[1:]))
    sys.exit(7)
""")
        self.executable("py.exe", f"print({str(python)!r})\n")
        self.command("test-htg940-fpga-bundle.sh", bundle, "--program",
                     "--helper-dir", helper, "--recovery-dir", recovery_dir,
                     "--output-bitstream", helper / "programmed.bit",
                     "--diagnostic-seconds", "6", expected=7)
        program = (self.root / "program.txt").read_text().splitlines()
        self.assertEqual(len(program), 3)
        self.assertEqual(program[1], str(helper / "htg940_usb_dual_ila_forced_ulpi.ltx"))
        args = json.loads((self.root / "run.json").read_text())
        self.assertEqual(args[args.index("--startup-timeout") + 1], "90")
        self.assertEqual(args[args.index("--state-timeout") + 1], "15")
        self.assertEqual(args[args.index("--diagnostic-seconds") + 1], "6")


class RecoveryRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env = dict(os.environ, TEST_PID=str(self.root / "console.pid"),
                        TEST_ARGS=str(self.root / "recovery-args.json"),
                        TEST_EMIT_RUNTIME="1", TEST_RESULT="0",
                        TEST_USB_OPS=str(self.root / "usb-operations.json"),
                        PYTHONPATH=str(self.root))
        (self.root / "usb").mkdir()
        (self.root / "usb/__init__.py").write_text("")
        (self.root / "usb/core.py").write_text("class USBError(Exception): pass\n")
        (self.root / "usb/util.py").write_text(
            "def claim_interface(device, interface): pass\n"
            "def dispose_resources(device): pass\n"
        )
        (self.root / "libusb_package.py").write_text("""
import json, os
from pathlib import Path
from usb.core import USBError
class Device:
    def ctrl_transfer(self, *args, **kwargs):
        Path(os.environ["TEST_USB_OPS"]).write_text(json.dumps(list(args)))
        if os.environ.get("TEST_USB_NOT_READY") == "1":
            raise USBError("not ready")
        result = bytearray(18)
        result[0:2] = bytes([18, 1])
        result[8:12] = bytes.fromhex("24040700")
        if os.environ.get("TEST_BAD_DESCRIPTOR") == "1":
            result[8] = 0
        return result
def find(**kwargs):
    return Device()
""")
        (self.root / "entropy_host.py").write_text("# fixture\n")
        (self.root / "htg940_console_updated.py").write_text("""
import os, time
from pathlib import Path
Path(os.environ["TEST_PID"]).write_text(str(os.getpid()))
time.sleep(float(os.environ.get("TEST_READY_DELAY", "0")))
Path(os.environ["TEST_PID"] + ".ready").write_text("ready")
print("[HOST] Monitoring MCU/Caliptra logs.", flush=True)
if os.environ["TEST_EMIT_RUNTIME"] == "1":
    print("[mcu-runtime] Hello from MCU runtime", flush=True)
while True:
    time.sleep(0.1)
""")
        (self.root / "usb_recovery.py").write_text("""
import json, os, sys, time
from pathlib import Path
if not Path(os.environ["TEST_PID"] + ".ready").exists():
    sys.exit(9)
Path(os.environ["TEST_ARGS"]).write_text(json.dumps(sys.argv[1:]))
if os.environ["TEST_RESULT"] == "timeout":
    time.sleep(20)
else:
    sys.exit(int(os.environ["TEST_RESULT"]))
""")
        self.images = [self.root / name for name in ("core.bin", "manifest.bin", "runtime.bin")]
        for path in self.images:
            path.write_bytes(b"image")

    def run_recovery(self, expected):
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / "run-htg940-recovery.py"),
             "--recovery-dir", str(self.root), "--log-prefix", str(self.root / "run"),
             "--caliptra-fmc-rt", str(self.images[0]), "--soc-manifest", str(self.images[1]),
             "--mcu-runtime", str(self.images[2]), "--boot-timeout", "0.3",
             "--recovery-timeout", "0.5", "--startup-timeout", "2",
             "--usb-ready-timeout", "0.3", "--diagnostic-seconds", "0"],
            env=self.env, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        pid = int((self.root / "console.pid").read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        self.assertTrue((self.root / "run.uart.log").is_file())
        self.assertTrue((self.root / "run.recovery.log").is_file())
        return result

    def test_success_requires_runtime_and_disables_retries(self):
        result = self.run_recovery(0)
        self.assertIn("HTG940_TEST_PASS", result.stdout)
        args = json.loads((self.root / "recovery-args.json").read_text())
        self.assertEqual(args[args.index("--retries") + 1], "0")
        self.assertEqual(json.loads((self.root / "usb-operations.json").read_text()),
                         [0x80, 6, 0x0100, 0, 18])

    def test_recovery_failure_preserves_exit_code_and_logs(self):
        self.env["TEST_RESULT"] = "7"
        self.run_recovery(7)

    def test_slow_console_startup_does_not_start_recovery_early(self):
        self.env["TEST_READY_DELAY"] = "0.4"
        self.run_recovery(0)

    def test_successful_usb_without_runtime_is_failure(self):
        self.env["TEST_EMIT_RUNTIME"] = "0"
        self.run_recovery(1)

    def test_hung_recovery_is_bounded_and_owned_console_stops(self):
        self.env["TEST_RESULT"] = "timeout"
        self.run_recovery(1)

    def test_unready_usb_never_starts_recovery(self):
        self.env["TEST_USB_NOT_READY"] = "1"
        self.run_recovery(1)
        self.assertFalse((self.root / "recovery-args.json").exists())

    def test_wrong_device_descriptor_never_starts_recovery(self):
        self.env["TEST_BAD_DESCRIPTOR"] = "1"
        self.run_recovery(1)
        self.assertFalse((self.root / "recovery-args.json").exists())


if __name__ == "__main__":
    unittest.main()

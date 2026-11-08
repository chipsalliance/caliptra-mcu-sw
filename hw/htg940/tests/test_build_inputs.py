# Licensed under the Apache-2.0 license

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


FPGA = Path(__file__).resolve().parents[1] / "fpga"


class SnapshotTests(unittest.TestCase):
    def test_pin_manifest_is_not_ignored(self):
        result = subprocess.run(
            [
                "git", "check-ignore", "--no-index", "-q",
                str(FPGA / "htg940" / "submodule_pins.json"),
            ],
            cwd=FPGA.parents[2], capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_pins_stay_in_isolated_hardware_tree_and_match_patch_checksums(self):
        pins = json.loads((FPGA / "htg940" / "submodule_pins.json").read_text())
        paths = [pin["path"] for pin in pins]
        self.assertEqual(len(paths), len(set(paths)))
        self.assertEqual(paths[0], "caliptra-ss")
        for pin in pins:
            path = Path(pin["path"])
            self.assertFalse(path.is_absolute())
            self.assertNotIn("..", path.parts)
            self.assertEqual(path.parts[0], "caliptra-ss")
            if "patch" in pin:
                patch_file = FPGA / "htg940" / "submodule_patches" / pin["patch"]
                self.assertEqual(
                    hashlib.sha256(patch_file.read_bytes()).hexdigest(),
                    pin["patch_sha256"],
                )


class FirmwareConversionTests(unittest.TestCase):
    def test_all_zero_roms_and_entire_flash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, size in (("caliptra_rom", 98304), ("mcu_rom", 131072)):
                binary = root / f"{name}.bin"
                output = root / f"{name}.mem"
                binary.write_bytes(bytes(size))
                subprocess.run(
                    [
                        sys.executable, str(FPGA / "bin_to_xpm_mem.py"),
                        "--input", str(binary), "--output", str(output),
                        "--size", str(size),
                    ],
                    check=True, capture_output=True, text=True,
                )
                self.assertEqual(output.read_text(), "0000000000000000\n" * (size // 8))

            binary = root / "flash_image.bin"
            output = root / "flash.coe"
            binary.write_bytes(bytes(2097152))
            subprocess.run(
                [
                    sys.executable, str(FPGA / "bin_to_flash_coe.py"),
                    "--input", str(binary), "--output", str(output),
                    "--capacity", "2097152",
                ],
                check=True, capture_output=True, text=True,
            )
            self.assertEqual(
                output.read_text(),
                "memory_initialization_radix=16;\nmemory_initialization_vector=\n"
                + "0000000000000000,\n" * (2097152 // 8 - 1)
                + "0000000000000000;\n",
            )

    def test_wrong_rom_size_and_oversized_flash_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "input.bin"
            binary.write_bytes(bytes(9))
            for converter, option, message in (
                ("bin_to_xpm_mem.py", "--size", "expected 8 bytes"),
                ("bin_to_flash_coe.py", "--capacity", "exceeds"),
            ):
                result = subprocess.run(
                    [
                        sys.executable, str(FPGA / converter),
                        "--input", str(binary), "--output", str(root / "output"),
                        option, "8",
                    ],
                    capture_output=True, text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertFalse((root / "output").exists())


class SourcePreparationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.config = self.root / "fpga" / "htg940"
        patches = self.config / "submodule_patches"
        patches.mkdir(parents=True)
        self.repository = self.root / "caliptra-ss"
        self.repository.mkdir()
        self.git("init")
        self.git("config", "user.name", "HTG test")
        self.git("config", "user.email", "htg-test@example.invalid")
        self.source = self.repository / "source.txt"
        self.source.write_text("before\n")
        self.git("add", "source.txt")
        self.git("commit", "-m", "base")
        self.commit = self.git("rev-parse", "HEAD")
        self.source.write_text("after\n")
        patch_file = patches / "source.patch"
        patch_file.write_text(self.git("diff") + "\n")
        self.source.write_text("before\n")
        self.pin = {
            "path": "caliptra-ss",
            "commit": self.commit,
            "patch": "source.patch",
            "patch_sha256": hashlib.sha256(patch_file.read_bytes()).hexdigest(),
        }
        self.write_pins()
        spec = importlib.util.spec_from_file_location(
            "htg_prepare_sources", FPGA / "htg940" / "prepare_sources.py"
        )
        assert spec is not None and spec.loader is not None
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)

    def git(self, *arguments):
        return subprocess.run(
            ["git", "-C", str(self.repository), *arguments],
            check=True, capture_output=True, text=True,
        ).stdout.strip()

    def write_pins(self):
        (self.config / "submodule_pins.json").write_text(json.dumps([self.pin]))

    def prepare(self, mode):
        with (
            patch.object(self.helper, "__file__", str(self.config / "prepare_sources.py")),
            patch.object(sys, "argv", ["prepare_sources.py", mode]),
        ):
            self.helper.main()

    def test_isolated_root_apply_and_check_are_idempotent(self):
        self.prepare("--apply")
        self.assertEqual(self.source.read_text(), "after\n")
        self.prepare("--apply")
        self.prepare("--check")
        self.assertEqual(self.git("rev-parse", "HEAD"), self.commit)

    def test_check_rejects_unpatched_source(self):
        with self.assertRaisesRegex(RuntimeError, "Required patch not applied"):
            self.prepare("--check")

    def test_patch_checksum_is_verified(self):
        self.pin["patch_sha256"] = "0" * 64
        self.write_pins()
        with self.assertRaisesRegex(RuntimeError, "Patch checksum mismatch"):
            self.prepare("--apply")
        self.assertEqual(self.source.read_text(), "before\n")

    def test_conflicting_patch_is_rejected_without_overwrite(self):
        self.source.write_text("conflict\n")
        with self.assertRaisesRegex(RuntimeError, "Patch conflicts"):
            self.prepare("--apply")
        self.assertEqual(self.source.read_text(), "conflict\n")

    def test_wrong_commit_is_rejected_by_check(self):
        self.source.write_text("second\n")
        self.git("commit", "-am", "second")
        with self.assertRaisesRegex(RuntimeError, "expected .* found"):
            self.prepare("--check")

    def test_dirty_checkout_is_preserved_when_switching_commits(self):
        self.source.write_text("second\n")
        self.git("commit", "-am", "second")
        self.source.write_text("local changes\n")
        with self.assertRaisesRegex(RuntimeError, "Refusing to change a dirty submodule"):
            self.prepare("--apply")
        self.assertEqual(self.source.read_text(), "local changes\n")


if __name__ == "__main__":
    unittest.main()

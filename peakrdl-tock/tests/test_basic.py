# Licensed under the Apache-2.0 license

"""Tests for peakrdl-tock: generates Tock-style register code from SystemRDL."""

import os
import tempfile

import pytest

from peakrdl_tock.exporter import TockExporter


# Find project root (look for Cargo.toml)
def _find_project_root():
    d = os.path.dirname(os.path.abspath(__file__))
    while d != "/":
        if os.path.exists(os.path.join(d, "peakrdl-tock", "pyproject.toml")):
            return d
        d = os.path.dirname(d)
    return None


PROJECT_ROOT = _find_project_root()


def _rdl_path(rel_path):
    """Get absolute path to an RDL file relative to project root."""
    assert PROJECT_ROOT, "Could not find project root"
    path = os.path.join(PROJECT_ROOT, rel_path)
    if not os.path.exists(path):
        pytest.skip(f"RDL file not found: {rel_path}")
    return path


class TestBasicExport:
    """Test basic export functionality with simple RDL files."""

    def test_doe_mbox(self):
        """Test generating doe_mbox registers."""
        with tempfile.TemporaryDirectory() as tmpdir:
            e = TockExporter()
            code = e.export_from_file(
                _rdl_path("hw/doe_mbox.rdl"),
                tmpdir,
                top_name="doe_mbox",
                base_addr=0x2F000000,
                output_name="doe_mbox",
            )

            # Check address constant
            assert "pub const DOE_MBOX_ADDR: u32 = 0x2f00_0000;" in code

            # Check memory region
            assert "pub const DOE_MBOX_SRAM_OFFSET: u32 = 0x1000;" in code
            assert "pub const DOE_MBOX_SRAM_SIZE: usize = 0x10_0000;" in code
            assert "pub const DOE_MBOX_SRAM_PTR: *mut u8 = 0x2f00_1000 as *mut u8;" in code

            # Check bitfield definitions
            assert "pub DoeMboxLock [" in code
            assert "Lock OFFSET(0) NUMBITS(1) []," in code
            assert "pub DoeMboxStatus [" in code
            assert "pub DoeMboxEvent [" in code

            # Check register struct
            assert "pub DoeMbox {" in code
            assert "pub doe_mbox_lock: tock_registers::registers::ReadOnly<u32" in code
            assert "pub doe_mbox_dlen: tock_registers::registers::ReadWrite<u32>" in code
            assert "@END" in code

    def test_el2_pic(self):
        """Test generating el2_pic_ctrl with register arrays."""
        with tempfile.TemporaryDirectory() as tmpdir:
            e = TockExporter()
            code = e.export_from_file(
                _rdl_path("hw/el2_pic_ctrl.rdl"),
                tmpdir,
                top_name="el2_pic_ctrl",
                base_addr=0x60000000,
                output_name="el2_pic_ctrl",
            )

            # Check address
            assert "pub const EL2_PIC_ADDR: u32 = 0x6000_0000;" in code

            # Check array registers
            assert "; 256]" in code  # Arrays of 256 elements

            # Check ReadOnly for meip
            assert "ReadOnly<u32" in code

    def test_mbox_csr(self):
        """Test generating mbox_csr with enum values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            e = TockExporter()
            code = e.export_from_file(
                _rdl_path("hw/caliptra-ss/third_party/caliptra-rtl/src/soc_ifc/rtl/mbox_csr.rdl"),
                tmpdir,
                top_name="mbox_csr",
                base_addr=0xa0020000,
                output_name="mbox",
            )

            # Check enum values in MboxStatus
            assert "CmdBusy = 0," in code
            assert "DataReady = 1," in code
            assert "CmdComplete = 2," in code
            assert "CmdFailure = 3," in code

    def test_axicdma(self):
        """Test axicdma generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            e = TockExporter()
            code = e.export_from_file(
                _rdl_path("hw/axicdma.rdl"),
                tmpdir,
                top_name="axicdma",
                base_addr=0xa4081000,
                output_name="axicdma",
            )
            assert "pub const AXICDMA_ADDR: u32 = 0xa408_1000;" in code
            assert "pub Axicdma {" in code


class TestComplexStructures:
    """Test complex RDL structures."""

    def test_mci_nested_addrmaps(self):
        """Test MCI with nested addrmaps, regfiles, and memory regions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            e = TockExporter()
            code = e.export_from_file(
                _rdl_path("hw/caliptra-ss/src/mci/rtl/mci_top.rdl"),
                tmpdir,
                top_name="mci_top",
                base_addr=0x21000000,
                output_name="mci",
            )

            # Check memory regions are correctly nested
            assert "MCU_MBOX0_CSR_MBOX_SRAM_OFFSET" in code
            assert "MCU_MBOX1_CSR_MBOX_SRAM_OFFSET" in code
            assert "MCU_SRAM_OFFSET" in code

            # Check register prefixes from nested addrmaps
            assert "pub mci_reg_hw_capabilities" in code
            assert "pub mcu_mbox0_csr_" in code

    def test_otp_ctrl(self):
        """Test OTP controller with many register types."""
        with tempfile.TemporaryDirectory() as tmpdir:
            e = TockExporter()
            code = e.export_from_file(
                _rdl_path("hw/caliptra-ss/src/fuse_ctrl/rtl/otp_ctrl.rdl"),
                tmpdir,
                top_name="otp_ctrl",
                base_addr=0x70000000,
                output_name="otp_ctrl",
            )
            assert "pub const OTP_ADDR: u32 = 0x7000_0000;" in code
            assert "pub Otp {" in code


class TestExactMatch:
    """Test exact match with reference output for simple files."""

    def _strip_header(self, content):
        """Remove license header and generated-by comment."""
        lines = content.splitlines()
        result = []
        in_header = False
        for line in lines:
            if line.startswith("/*"):
                in_header = True
                continue
            if in_header:
                if line.startswith("*/"):
                    in_header = False
                continue
            if line.startswith("// Generated"):
                continue
            if line.strip() == "":
                continue
            result.append(line)
        return "\n".join(result)

    def test_doe_mbox_exact(self):
        """doe_mbox should exactly match the reference output."""
        ref_path = os.path.join(
            PROJECT_ROOT, "registers/generated-firmware-new/src/doe_mbox.rs"
        )
        if not os.path.exists(ref_path):
            pytest.skip("Reference file not found")

        with open(ref_path) as f:
            ref_content = self._strip_header(f.read())

        with tempfile.TemporaryDirectory() as tmpdir:
            e = TockExporter()
            code = e.export_from_file(
                _rdl_path("hw/doe_mbox.rdl"),
                tmpdir,
                top_name="doe_mbox",
                base_addr=0x2F000000,
                output_name="doe_mbox",
            )
            new_content = self._strip_header(code)
            assert new_content == ref_content

    def test_mbox_exact(self):
        """mbox should exactly match the reference output."""
        ref_path = os.path.join(
            PROJECT_ROOT, "registers/generated-firmware-new/src/mbox.rs"
        )
        if not os.path.exists(ref_path):
            pytest.skip("Reference file not found")

        with open(ref_path) as f:
            ref_content = self._strip_header(f.read())

        with tempfile.TemporaryDirectory() as tmpdir:
            e = TockExporter()
            code = e.export_from_file(
                _rdl_path("hw/caliptra-ss/third_party/caliptra-rtl/src/soc_ifc/rtl/mbox_csr.rdl"),
                tmpdir,
                top_name="mbox_csr",
                base_addr=0xa0020000,
                output_name="mbox",
            )
            new_content = self._strip_header(code)
            assert new_content == ref_content

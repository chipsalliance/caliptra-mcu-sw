# Licensed under the Apache-2.0 license

"""Tests for peakrdl-tock: generates Tock-style register code from SystemRDL."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from systemrdl import RDLCompiler

from peakrdl_tock.exporter import TockExporter
from peakrdl_tock.utils import camel_case, hex_u32, snake_case

PROJECT_ROOT = Path(__file__).resolve().parents[2]
GENERATE_SCRIPT = PROJECT_ROOT / "peakrdl-tock" / "scripts" / "generate_registers.py"


def _rdl_path(rel_path):
    """Get the path to an RDL file relative to the project root."""
    path = PROJECT_ROOT / rel_path
    if not path.exists():
        pytest.skip(f"RDL file not found: {rel_path}")
    return str(path)


def _export(tmp_path, rdl, top_name, **kwargs):
    """Compile RDL source text and export its top addrmap."""
    rdl_file = tmp_path / "input.rdl"
    rdl_file.write_text(rdl)
    return TockExporter().export_from_file(
        str(rdl_file), str(tmp_path / "out"), top_name=top_name, **kwargs
    )


class TestNames:
    """Test name conversion."""

    @pytest.mark.parametrize(
        "name, snake, camel",
        [
            ("I3CCSR", "i3ccsr", "I3ccsr"),
            ("I3CBase", "i3c_base", "I3cBase"),
            ("I3C_EC", "i3c_ec", "I3cEc"),
            ("PIOControl", "pio_control", "PioControl"),
            ("SoCMgmtIf", "soc_mgmt_if", "SocMgmtIf"),
            ("QUEUE_THLD_CTRL", "queue_thld_ctrl", "QueueThldCtrl"),
            ("REC_INTF_REG_W1C_ACCESS", "rec_intf_reg_w1c_access", "RecIntfRegW1cAccess"),
            ("mcu_mbox0_csr", "mcu_mbox0_csr", "McuMbox0Csr"),
            ("fooBarBaz", "foo_bar_baz", "FooBarBaz"),
            ("16Bits", "_16_bits", "_16Bits"),
            ("type", "type_", "Type"),
        ],
    )
    def test_case_conversion(self, name, snake, camel):
        assert snake_case(name) == snake
        assert camel_case(name) == camel

    def test_hex(self):
        assert hex_u32(0) == "0x0"
        assert hex_u32(0x400) == "0x400"
        assert hex_u32(0x10_0000) == "0x10_0000"
        assert hex_u32(0x2F00_1000) == "0x2f00_1000"


class TestStructure:
    """Test how the RDL hierarchy maps to names and types."""

    def test_regfile_prefix(self, tmp_path):
        """Registers in a regfile are prefixed with the regfile name."""
        code = _export(
            tmp_path,
            """
            addrmap top {
                reg { field { sw = rw; } A[0:0]; field { sw = rw; } B[1:1]; } ctrl @ 0x0;
                regfile {
                    reg { field { sw = r; } EN[0:0]; field { sw = r; } GO[1:1]; } global_en @ 0x0;
                    regfile {
                        reg { field { sw = w; } X[3:0]; field { sw = w; } Y[7:4]; } status @ 0x0;
                    } inner @ 0x10;
                } intr_block_rf @ 0x100;
            };
            """,
            "top",
        )
        assert "(0x0 => pub ctrl: tock_registers::registers::ReadWrite<u32, crate::top::bits::Ctrl::Register>)" in code
        assert "(0x100 => pub intr_block_rf_global_en: tock_registers::registers::ReadOnly<u32," in code
        assert "(0x110 => pub inner_status: tock_registers::registers::WriteOnly<u32," in code

    def test_same_layout_shares_type(self, tmp_path):
        """Registers of the same type share one bitfield definition."""
        code = _export(
            tmp_path,
            """
            reg lock_t { field { sw = rw; } LOCK[0:0]; field { sw = r; } BUSY[1:1]; };
            addrmap top {
                lock_t a @ 0x0;
                lock_t b @ 0x4;
            };
            """,
            "top",
        )
        assert code.count("pub LockT [") == 1
        assert "pub a: tock_registers::registers::ReadWrite<u32, crate::top::bits::LockT::Register>" in code
        assert "pub b: tock_registers::registers::ReadWrite<u32, crate::top::bits::LockT::Register>" in code

    def test_different_layout_gets_own_type(self, tmp_path):
        """Registers with the same name and different fields get separate types."""
        code = _export(
            tmp_path,
            """
            addrmap top {
                regfile {
                    reg { field { sw = rw; } CMD[7:0]; field { sw = rw; } RESP[15:8]; } THLD_CTRL @ 0x0;
                } pio @ 0x0;
                regfile {
                    reg { field { sw = rw; } TX[7:0]; field { sw = rw; } RX[15:8]; } THLD_CTRL @ 0x0;
                } tti @ 0x100;
            };
            """,
            "top",
        )
        assert "pub ThldCtrl [" in code
        assert "pub TtiThldCtrl [" in code
        assert "pub pio_thld_ctrl: tock_registers::registers::ReadWrite<u32, crate::top::bits::ThldCtrl::Register>" in code
        assert "pub tti_thld_ctrl: tock_registers::registers::ReadWrite<u32, crate::top::bits::TtiThldCtrl::Register>" in code
        pio_bits = code.split("pub ThldCtrl [")[1].split("],")[0]
        tti_bits = code.split("pub TtiThldCtrl [")[1].split("],")[0]
        assert "Cmd OFFSET(0) NUMBITS(8)" in pio_bits
        assert "Tx OFFSET(0) NUMBITS(8)" in tti_bits

    def test_unresolvable_type_collision(self, tmp_path):
        """Two top-level registers whose names map to the same type name are rejected."""
        with pytest.raises(ValueError, match="different layout"):
            _export(
                tmp_path,
                """
                addrmap top {
                    reg { field { sw = rw; } A[0:0]; field { sw = rw; } B[1:1]; } foo_bar @ 0x0;
                    reg { field { sw = rw; } C[0:0]; field { sw = rw; } D[1:1]; } fooBar @ 0x4;
                };
                """,
                "top",
            )

    def test_regfile_array_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="arrays of addrmaps and regfiles"):
            _export(
                tmp_path,
                """
                addrmap top {
                    regfile { reg { field { sw = rw; } A[31:0]; } data @ 0x0; } rf[2] @ 0x0;
                };
                """,
                "top",
            )

    def test_module_name(self, tmp_path):
        """The module name sets the address constant, struct, and bitfield path."""
        rdl = """
            addrmap flash_ctrl {
                reg { field { sw = rw; } A[0:0]; field { sw = rw; } B[1:1]; } ctrl @ 0x0;
            };
            """
        code = _export(tmp_path, rdl, "flash_ctrl", base_addr=0x2000_8000)
        assert "pub const FLASH_CTRL_ADDR: u32 = 0x2000_8000;" in code
        assert "pub FlashCtrl {" in code

        code = _export(tmp_path, rdl, "flash_ctrl", output_name="primary_flash_ctrl")
        assert "pub const PRIMARY_FLASH_CTRL_ADDR: u32 = 0x0;" in code
        assert "pub PrimaryFlashCtrl {" in code
        assert "crate::primary_flash_ctrl::bits::Ctrl::Register" in code
        assert (tmp_path / "out" / "primary_flash_ctrl.rs").read_text() == code

    def test_child_addrmap_uses_its_address(self, tmp_path):
        """Exporting an addrmap from a larger design uses its address and instance name."""
        rdl_file = tmp_path / "input.rdl"
        rdl_file.write_text(
            """
            addrmap block_csr {
                reg { field { sw = rw; } A[31:0]; } data @ 0x0;
            };
            addrmap soc {
                block_csr block0_csr @ 0x1000_0000;
                block_csr block1_csr @ 0x2000_0000;
            };
            """
        )
        rdlc = RDLCompiler()
        rdlc.compile_file(str(rdl_file))
        root = rdlc.elaborate(top_def_name="soc")
        block1 = root.top.get_child_by_name("block1_csr")
        code = TockExporter().export(block1, str(tmp_path / "out"))
        assert "pub const BLOCK1_ADDR: u32 = 0x2000_0000;" in code
        assert "pub Block1 {" in code
        assert (tmp_path / "out" / "block1.rs").exists()

    def test_include_search_paths(self, tmp_path):
        inc = tmp_path / "inc"
        inc.mkdir()
        (inc / "types.rdl").write_text("reg data_t { field { sw = r; } D[31:0]; };\n")
        code = _export(
            tmp_path,
            '`include "types.rdl"\naddrmap top { data_t data @ 0x0; };\n',
            "top",
            incl_search_paths=[str(inc)],
        )
        assert "(0x0 => pub data: tock_registers::registers::ReadOnly<u32>)" in code


class TestProjectRdl:
    """Test export of the RDL files in this repository."""

    def test_doe_mbox(self, tmp_path):
        """Test generating doe_mbox registers."""
        code = TockExporter().export_from_file(
            _rdl_path("hw/doe_mbox.rdl"),
            str(tmp_path),
            top_name="doe_mbox",
            base_addr=0x2F000000,
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

    def test_el2_pic(self, tmp_path):
        """Test generating el2_pic_ctrl with register arrays."""
        code = TockExporter().export_from_file(
            _rdl_path("hw/el2_pic_ctrl.rdl"),
            str(tmp_path),
            top_name="el2_pic_ctrl",
            base_addr=0x60000000,
        )
        assert "pub const EL2_PIC_CTRL_ADDR: u32 = 0x6000_0000;" in code
        assert "pub El2PicCtrl {" in code
        assert "; 256]" in code
        assert "ReadOnly<u32" in code

    def test_mbox_csr(self, tmp_path):
        """Test generating mbox_csr with enum values."""
        code = TockExporter().export_from_file(
            _rdl_path("hw/caliptra-ss/third_party/caliptra-rtl/src/soc_ifc/rtl/mbox_csr.rdl"),
            str(tmp_path),
            top_name="mbox_csr",
            base_addr=0xA0020000,
        )
        assert "pub const MBOX_ADDR: u32 = 0xa002_0000;" in code
        assert "CmdBusy = 0," in code
        assert "DataReady = 1," in code
        assert "CmdComplete = 2," in code
        assert "CmdFailure = 3," in code

    def test_mci_nested_addrmaps(self, tmp_path):
        """Test MCI with nested addrmaps, regfiles, and memory regions."""
        code = TockExporter().export_from_file(
            _rdl_path("hw/caliptra-ss/src/mci/rtl/mci_top.rdl"),
            str(tmp_path),
            top_name="mci_top",
            base_addr=0x21000000,
        )
        assert "pub const MCI_ADDR: u32 = 0x2100_0000;" in code

        # Check memory regions are correctly nested
        assert "MCU_MBOX0_CSR_MBOX_SRAM_OFFSET" in code
        assert "MCU_MBOX1_CSR_MBOX_SRAM_OFFSET" in code
        assert "MCU_SRAM_OFFSET" in code

        # Check register prefixes from nested addrmaps and regfiles
        assert "pub mci_reg_hw_capabilities" in code
        assert "pub mcu_mbox0_csr_" in code
        assert "pub intr_block_rf_global_intr_en_r" in code

    def test_i3c(self, tmp_path):
        """The PIO and TTI registers with the same names have their own bitfields."""
        code = TockExporter().export_from_file(
            _rdl_path("hw/caliptra-ss/third_party/i3c-core/src/rdl/registers.rdl"),
            str(tmp_path),
            top_name="I3CCSR",
            base_addr=0x20004000,
        )
        assert "pub const I3C_ADDR: u32 = 0x2000_4000;" in code
        assert "pub I3c {" in code
        assert "pub i3c_base_hci_version" in code
        assert (
            "pub pio_control_queue_thld_ctrl: tock_registers::registers::ReadWrite"
            "<u32, crate::i3c::bits::QueueThldCtrl::Register>" in code
        )
        assert (
            "pub tti_queue_thld_ctrl: tock_registers::registers::ReadWrite"
            "<u32, crate::i3c::bits::TtiQueueThldCtrl::Register>" in code
        )
        tti_bits = code.split("pub TtiQueueThldCtrl [")[1].split("],")[0]
        assert "TxDescThld OFFSET(0) NUMBITS(8)" in tti_bits

    def test_generated_crate_is_current(self):
        """registers/generated-firmware-peakrdl matches the generator output."""
        _rdl_path("hw/caliptra-ss/src/integration/rtl/soc_address_map.rdl")
        src = str(PROJECT_ROOT / "peakrdl-tock" / "src")
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(filter(None, [src, env.get("PYTHONPATH")]))
        result = subprocess.run(
            [sys.executable, str(GENERATE_SCRIPT), "--check"],
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0, result.stderr

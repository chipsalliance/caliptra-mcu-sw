import unittest

from prepare_dual_ila_constraints import board_constraints


class BoardConstraintsTest(unittest.TestCase):
    def test_preserves_board_and_timing_removes_only_debug(self):
        board = (
            "# Board pins and timing\n"
            "set_property PACKAGE_PIN AW16 [get_ports cptra_ss_usb_ulpi_clk_i]\n"
            "create_clock -period 16.667 -name usb_clk [get_ports cptra_ss_usb_ulpi_clk_i]\n"
            "set_input_delay -clock usb_clk -max 3.650 [get_ports cptra_ss_usb_ulpi_dir_i]\n"
        )
        debug = (
            "set_property MARK_DEBUG true [get_nets stp]\n"
            "create_debug_core ulpi_ila ila\n"
            "set_property C_DATA_DEPTH 4096 [get_debug_cores ulpi_ila]\n"
            "create_debug_port ulpi_ila probe\n"
            "set_property port_width 1 [get_debug_ports ulpi_ila/probe5]\n"
            "connect_debug_port ulpi_ila/probe5 [get_nets [list stp]]\n"
        )
        trailing_pin = "set_property IOSTANDARD LVCMOS18 [get_ports host_uart_rx_i]\n"
        clean, removed = board_constraints(board + debug + trailing_pin)
        self.assertEqual(clean, board + trailing_pin)
        self.assertEqual(removed, 6)

    def test_rejects_unrecognized_debug_command(self):
        with self.assertRaisesRegex(ValueError, "Unsupported debug constraint at line 1"):
            board_constraints("disconnect_debug_port ulpi_ila/probe5\n")

    def test_rejects_multiline_debug_command(self):
        with self.assertRaisesRegex(ValueError, "Unsupported debug constraint at line 1"):
            board_constraints("connect_debug_port ulpi_ila/probe5 \\\n[get_nets stp]\n")


if __name__ == "__main__":
    unittest.main()

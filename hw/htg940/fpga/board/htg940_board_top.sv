// HTG940 physical boundary, NXP connector profile: USB FMC D; I3C FMC C; no external processor JTAG.
// This module supplies board I/O only; it does not supply entropy or host software.
module htg940_board_top (
    input wire ref_clock_156p25mhz_clk_p,
    input wire ref_clock_156p25mhz_clk_n,
    // HTG940_ENTROPY_CONTROL_V1; CP2103 TXD->FPGA RX, FPGA TX->CP2103 RXD.
    input wire host_uart_rx_i,
    output wire host_uart_tx_o,
    input wire resetn_i,
    input wire usb_phy_resetn_i,
    output wire usb_phy_resetn_o,
    output wire [2:0] GPIO_o,
    input wire cptra_ss_usb_ulpi_clk_i,
    inout wire [7:0] cptra_ss_usb_ulpi_data_io,
    input wire cptra_ss_usb_ulpi_dir_i,
    input wire cptra_ss_usb_ulpi_nxt_i,
    output wire cptra_ss_usb_ulpi_stp_o,
    input wire cptra_ss_i3c_scl_io,
    inout wire cptra_ss_i3c_sda_io
);
    wire board_core_clk, board_reset_n, board_clock_locked;
    wire subsystem_run, host_mode;
    wire [3:0] host_entropy_data;
    wire host_entropy_valid, host_entropy_req;
    wire cmd_valid, reply_valid;
    wire [7:0] cmd, reply_code;
    wire [31:0] cmd_data, reply_data;
    wire controller_async_reset_n = resetn_i & board_clock_locked;
    (* ASYNC_REG="TRUE" *) reg [1:0] controller_reset_sync = 2'b00;
    always @(posedge board_core_clk or negedge controller_async_reset_n) begin
        if (!controller_async_reset_n) controller_reset_sync <= 2'b00;
        else controller_reset_sync <= {controller_reset_sync[0],1'b1};
    end
    // Independent reset: stays alive when the host holds Caliptra in reset.
    htg940_entropy_uart u_entropy_uart (
        .clk(board_core_clk), .reset_n(controller_reset_sync[1]),
        .uart_rx(host_uart_rx_i), .uart_tx(host_uart_tx_o),
        .cmd_valid(cmd_valid), .cmd(cmd), .cmd_data(cmd_data),
        .reply_valid(reply_valid), .reply_code(reply_code), .reply_data(reply_data)
    );
    // HTG940_UART_LOGS_V1
    wire entropy_cmd_valid, entropy_reply_valid;
    wire [7:0] entropy_reply_code;
    wire [31:0] entropy_reply_data;
    wire board_mcu_log_valid, board_core_log_valid;
    wire [7:0] board_mcu_log_byte, board_core_log_byte;
    htg940_log_bridge u_log_bridge (
        .clk(board_core_clk), .reset_n(controller_reset_sync[1]),
        .mcu_valid(board_mcu_log_valid), .mcu_byte(board_mcu_log_byte),
        .core_valid(board_core_log_valid), .core_byte(board_core_log_byte),
        .cmd_valid(cmd_valid), .cmd(cmd), .cmd_data(cmd_data),
        .entropy_cmd_valid(entropy_cmd_valid),
        .entropy_reply_valid(entropy_reply_valid),
        .entropy_reply_code(entropy_reply_code), .entropy_reply_data(entropy_reply_data),
        .reply_valid(reply_valid), .reply_code(reply_code), .reply_data(reply_data)
    );
    htg940_entropy_control u_entropy_control (
        .clk(board_core_clk), .reset_n(controller_reset_sync[1]),
        .cmd_valid(entropy_cmd_valid), .cmd(cmd), .cmd_data(cmd_data),
        .reply_valid(entropy_reply_valid), .reply_code(entropy_reply_code), .reply_data(entropy_reply_data),
        .entropy_request(host_entropy_req), .subsystem_ready(board_reset_n),
        .entropy_data(host_entropy_data), .entropy_valid(host_entropy_valid),
        .subsystem_run(subsystem_run), .host_mode(host_mode)
    );
    wire sda_invert, sda_disable, sda_pullup_request, sda_sample;
    wire [14:0] jtag_out;
    wire [14:0] jtag_in;
    // HTG940_NO_FMC_JTAG_V1
    // Each group: {unused, TRST_N, TDI, TMS, TCK}.
    // Hold all processor TAPs in reset; FPGA configuration JTAG is dedicated.
    assign jtag_in = {3{5'b00010}};

    // Existing wrapper truth table:
    // IN/EN/UP = 100 or 101: drive 0; 001: drive 1; 010/011: release.
    // Board pull-ups are required for open-drain operation. FPGA weak pull-ups
    // are not a replacement for the original external 2k pull-up driver.
    IOBUF u_i3c_sda (.IO(cptra_ss_i3c_sda_io), .O(sda_sample),
                    .I(~sda_invert), .T(sda_disable | ~board_reset_n));

    // Hold PHY reset for ~10 ms at the requested 18 MHz core clock.
    // Actual hold time is 180000 / actual generated core frequency.
    wire phy_reset_async_n = board_reset_n & usb_phy_resetn_i;
    (* ASYNC_REG = "TRUE" *) reg [1:0] phy_reset_sync = 2'b00;
    reg [17:0] phy_hold_count = 18'd0;
    reg [25:0] heartbeat = 26'd0;
    always @(posedge board_core_clk or negedge phy_reset_async_n) begin
        if (!phy_reset_async_n) phy_reset_sync <= 2'b00;
        else phy_reset_sync <= {phy_reset_sync[0], 1'b1};
    end
    always @(posedge board_core_clk or negedge phy_reset_async_n) begin
        if (!phy_reset_async_n) phy_hold_count <= 18'd0;
        else if (!phy_reset_sync[1]) phy_hold_count <= 18'd0;
        else if (phy_hold_count != 18'd180000)
            phy_hold_count <= phy_hold_count + 1'b1;
    end
    assign usb_phy_resetn_o = phy_reset_async_n & (phy_hold_count == 18'd180000);
    always @(posedge board_core_clk or negedge board_reset_n) begin
        if (!board_reset_n) heartbeat <= 26'd0;
        else heartbeat <= heartbeat + 1'b1;
    end
    // These LEDs indicate clocks/reset only, not firmware boot success.
    assign GPIO_o = {usb_phy_resetn_o, heartbeat[23], board_clock_locked};

    caliptra_htg940_bd_wrapper u_system (
        .board_mcu_log_valid(board_mcu_log_valid), .board_mcu_log_byte(board_mcu_log_byte),
        .board_core_log_valid(board_core_log_valid), .board_core_log_byte(board_core_log_byte),
        // HTG940_PACKAGING_FIX_V1
        .subsystem_reset_n(resetn_i & subsystem_run),
        .host_entropy_data(host_entropy_data),
        .host_entropy_valid(host_entropy_valid),
        .host_entropy_req(host_entropy_req),
        .ref_clock_156p25mhz_clk_p(ref_clock_156p25mhz_clk_p),
        .ref_clock_156p25mhz_clk_n(ref_clock_156p25mhz_clk_n),
        .reset_n(resetn_i),
        .board_core_clk(board_core_clk),
        .board_reset_n(board_reset_n),
        .board_clock_locked(board_clock_locked),
        .USB_ULPI_CLK(cptra_ss_usb_ulpi_clk_i),
        .USB_ULPI_DATA(cptra_ss_usb_ulpi_data_io),
        .USB_ULPI_DIR(cptra_ss_usb_ulpi_dir_i),
        .USB_ULPI_NXT(cptra_ss_usb_ulpi_nxt_i),
        .USB_ULPI_STP(cptra_ss_usb_ulpi_stp_o),
        .EXT_SCL(cptra_ss_i3c_scl_io), .EXT_SDA(sda_sample),
        .EXT_SDA_IN(sda_invert), .EXT_SDA_EN(sda_disable),
        .EXT_SDA_UP(sda_pullup_request),
        .jtag_in(jtag_in), .jtag_out(jtag_out)
    );
endmodule

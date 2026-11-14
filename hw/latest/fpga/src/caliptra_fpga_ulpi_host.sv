// SPDX-License-Identifier: Apache-2.0
//
// Internal FPGA ULPI USB3320 PHY + USB 2.0 High-Speed Host Transceiver
// ("Architecture B" zero-cable fabric loopback for Caliptra 2.2 USB).
//
// Connects directly to caliptra_ss_top's synchronous ULPI interface and
// exposes an AXI4-Lite MMIO control/buffer aperture to the Versal ARM PS
// at S_AXI_WRAPPER + 0x4000 (0xA401_4000).
//
// Clocking: the whole module (AXI4-Lite subordinate, ULPI bus engine and
// host sequencer) runs on `clk`, which is the ULPI PHY clock. Per the ULPI
// specification this is 60 MHz, which is also the frequency every
// `usb_pie.m.vhdl` timer constant is written for. The wrapper bridges the
// ARM-side AXI4-Lite (core_clk) into this domain with `axil_cdc_bridge`.
// `CLK_HZ` scales every wall-clock-derived timer (SOF period, Chirp K/J
// hold, end-of-reset SE0) so the host stays USB 2.0 spec-compliant at
// any PHY clock.

`default_nettype wire

module caliptra_fpga_ulpi_host #(
    parameter int unsigned CLK_HZ      = 60_000_000,
    parameter int unsigned CORE_CLK_HZ = 18_000_000
) (
    input  logic        clk,
    input  logic        rst_n,

    // AXI4-Lite subordinate interface (local offset 0x000..0xFFF)
    input  logic        s_axil_awvalid,
    output logic        s_axil_awready,
    input  logic [11:0] s_axil_awaddr,
    input  logic        s_axil_wvalid,
    output logic        s_axil_wready,
    input  logic [31:0] s_axil_wdata,
    input  logic [3:0]  s_axil_wstrb,
    output logic        s_axil_bvalid,
    input  logic        s_axil_bready,
    output logic [1:0]  s_axil_bresp,
    input  logic        s_axil_arvalid,
    output logic        s_axil_arready,
    input  logic [11:0] s_axil_araddr,
    output logic        s_axil_rvalid,
    input  logic        s_axil_rready,
    output logic [31:0] s_axil_rdata,
    output logic [1:0]  s_axil_rresp,

    // ULPI interface to/from caliptra_ss_top (usb_pie)
    input  logic [7:0]  ulpi_txdata_i,
    input  logic        ulpi_txenable_i,
    input  logic        ulpi_stp_i,
    output logic [7:0]  ulpi_rxdata_o,
    output logic        ulpi_dir_o,
    output logic        ulpi_nxt_o,

    // Sideband status inputs from caliptra_ss_top (core_clk domain, synchronized here)
    input  logic        usb_recovery_payload_available_i,
    input  logic        usb_recovery_image_activated_i
);

    // -------------------------------------------------------------------------
    // Wall-clock derived timing (USB 2.0 §7.1.7.5 High-Speed Detection Handshake)
    // -------------------------------------------------------------------------
    // SOF / microframe period: 125 us.
    localparam int unsigned SOF_INTERVAL_CYC   = CLK_HZ / 8_000;
    // Host Chirp K / Chirp J hold: 40..60 us each (we use 50 us). usb_pie only
    // needs > MAX_LINESTATE_DBC_CNT (192 cycles) so clamp to a safe minimum.
    localparam int unsigned CHIRP_KJ_HOLD_CALC = CLK_HZ / 20_000;
    localparam int unsigned CHIRP_KJ_HOLD_CYC  = (CHIRP_KJ_HOLD_CALC < 256) ? 256 : CHIRP_KJ_HOLD_CALC;
    // SE0 after the last Chirp J before HS idle: 100..500 us (we use 200 us).
    localparam int unsigned RST_END_SE0_CALC   = CLK_HZ / 5_000;
    localparam int unsigned RST_END_SE0_CYC    = (RST_END_SE0_CALC < 300) ? 300 : RST_END_SE0_CALC;
    // Wait for the device Chirp K to start+end: T_CHIRP_DELAY (125 us) +
    // T_UCH (up to 7 ms, 3.072 ms in usb_pie). Allow 20 ms.
    localparam int unsigned RST_CHIRP_WAIT_CYC = CLK_HZ / 50;

    // When the ULPI PHY clock runs faster than the subsystem AHB/DMA clock
    // (`hclk` = CORE_CLK_HZ = 18 MHz on VCK-190), `usb_pie` exchanges 64-bit
    // (8-byte) words with `usb_dma` across `usb_synchronizer` (~4.5 hclk
    // cycles per 8-byte word). Standard ULPI 1.1 `NXT` flow control paces
    // multi-byte DATA packets at 1 byte per 4 ULPI clocks (32 ulpi_clk cycles
    // = 9.6 hclk cycles per 8 bytes at 60/18 MHz) and allows 16 ULPI clocks
    // before consuming the first DATAx PID byte so `epinfo_txdata_valid` is
    // always ready without DMA underrun/overrun.
    localparam int unsigned RX_PID_STARTUP_CYC       = (CLK_HZ > CORE_CLK_HZ) ? 16 : 0;
    localparam int unsigned BYTE_PACE_WAIT_CYC       = (CLK_HZ > CORE_CLK_HZ) ? 3  : 0;
    localparam int unsigned TOK_TO_DATA_GAP_CYC      = (CLK_HZ > CORE_CLK_HZ) ? 40 : 24;
    localparam int unsigned DEFAULT_RESP_TIMEOUT_CYC = (CLK_HZ > CORE_CLK_HZ) ? 600_000 : 200_000;
    localparam logic [15:0] CRC16_RESIDUAL_OK        = 16'h800D;

    // Sideband inputs cross from core_clk into the ULPI clock domain.
    (* ASYNC_REG = "TRUE" *) logic [1:0] payload_available_sync;
    (* ASYNC_REG = "TRUE" *) logic [1:0] image_activated_sync;
    wire usb_recovery_payload_available = payload_available_sync[1];
    wire usb_recovery_image_activated   = image_activated_sync[1];

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            payload_available_sync <= 2'b00;
            image_activated_sync   <= 2'b00;
        end else begin
            payload_available_sync <= {payload_available_sync[0], usb_recovery_payload_available_i};
            image_activated_sync   <= {image_activated_sync[0],   usb_recovery_image_activated_i};
        end
    end

    // -------------------------------------------------------------------------
    // Constants & Helper Functions (matching usb_pie.m.vhdl bit ordering)
    // -------------------------------------------------------------------------
    localparam logic [31:0] HOST_MAGIC_VALUE = 32'h5553_4248; // "USBH"

    localparam logic [2:0] OP_NOP          = 3'd0;
    localparam logic [2:0] OP_BUS_RESET_HS = 3'd1;
    localparam logic [2:0] OP_SETUP        = 3'd2;
    localparam logic [2:0] OP_OUT          = 3'd3;
    localparam logic [2:0] OP_IN           = 3'd4;
    localparam logic [2:0] OP_SEND_RXCMD   = 3'd5;

    localparam logic [7:0] PID_BYTE_OUT    = 8'hE1;
    localparam logic [7:0] PID_BYTE_IN     = 8'h69;
    localparam logic [7:0] PID_BYTE_SOF    = 8'hA5;
    localparam logic [7:0] PID_BYTE_SETUP  = 8'h2D;
    localparam logic [7:0] PID_BYTE_DATA0  = 8'hC3;
    localparam logic [7:0] PID_BYTE_DATA1  = 8'h4B;
    localparam logic [7:0] PID_BYTE_ACK    = 8'hD2;

    localparam logic [3:0] PID_NIB_DATA0   = 4'b0011;
    localparam logic [3:0] PID_NIB_DATA1   = 4'b1011;

    function automatic logic [7:0] bit_rev8(input logic [7:0] d);
        logic [7:0] r;
        for (int i = 0; i < 8; i++) begin
            r[i] = d[7 - i];
        end
        return r;
    endfunction

    function automatic logic [4:0] calc_crc5(input logic [10:0] tok11);
        logic [4:0] crc;
        logic       fb;
        logic [4:0] inv;
        logic [4:0] rev;
        crc = 5'h1f;
        for (int i = 0; i < 11; i++) begin
            fb  = tok11[i] ^ crc[4];
            crc = {crc[3:0], 1'b0} ^ (fb ? 5'h05 : 5'h00);
        end
        inv = ~crc;
        for (int i = 0; i < 5; i++) begin
            rev[i] = inv[4 - i];
        end
        return rev;
    endfunction

    // Matches usb_pie.m.vhdl crc16_data8(bit_reverse8(data8), last_crc16)
    function automatic logic [15:0] step_crc16(
        input logic [7:0]  data8,
        input logic [15:0] c
    );
        logic [7:0]  d;
        logic [15:0] n;
        d = bit_rev8(data8);
        n[0]  = d[7]^d[6]^d[5]^d[4]^d[3]^d[2]^d[1]^d[0]^c[8]^c[9]^c[10]^c[11]^c[12]^c[13]^c[14]^c[15];
        n[1]  = d[7]^d[6]^d[5]^d[4]^d[3]^d[2]^d[1]^c[9]^c[10]^c[11]^c[12]^c[13]^c[14]^c[15];
        n[2]  = d[1]^d[0]^c[8]^c[9];
        n[3]  = d[2]^d[1]^c[9]^c[10];
        n[4]  = d[3]^d[2]^c[10]^c[11];
        n[5]  = d[4]^d[3]^c[11]^c[12];
        n[6]  = d[5]^d[4]^c[12]^c[13];
        n[7]  = d[6]^d[5]^c[13]^c[14];
        n[8]  = d[7]^d[6]^c[0]^c[14]^c[15];
        n[9]  = d[7]^c[1]^c[15];
        n[10] = c[2];
        n[11] = c[3];
        n[12] = c[4];
        n[13] = c[5];
        n[14] = c[6];
        n[15] = d[7]^d[6]^d[5]^d[4]^d[3]^d[2]^d[1]^d[0]^c[7]^c[8]^c[9]^c[10]^c[11]^c[12]^c[13]^c[14]^c[15];
        return n;
    endfunction

    // -------------------------------------------------------------------------
    // Emulated USB3320 ULPI Register Set
    // -------------------------------------------------------------------------
    logic [7:0] ulpi_func_ctrl;
    logic [7:0] ulpi_ifc_ctrl;
    logic [7:0] ulpi_otg_ctrl;
    logic [7:0] ulpi_scratch;
    logic       ctrl_vbus_valid;
    logic       ctrl_auto_sof_en;
    logic [1:0] cur_linestate;

    function automatic logic [7:0] ulpi_reg_read(input logic [7:0] addr);
        case (addr)
            8'h00: return 8'h24; // USB3320 VID L
            8'h01: return 8'h04; // USB3320 VID H
            8'h02: return 8'h07; // USB3320 PID L
            8'h03: return 8'h00; // USB3320 PID H
            8'h04, 8'h05, 8'h06: return ulpi_func_ctrl;
            8'h07, 8'h08, 8'h09: return ulpi_ifc_ctrl;
            8'h0A, 8'h0B, 8'h0C: return ulpi_otg_ctrl;
            8'h13: return {4'b0000, ctrl_vbus_valid, ctrl_vbus_valid, ctrl_vbus_valid, 1'b0};
            8'h15: return {6'b000000, cur_linestate};
            8'h16, 8'h17, 8'h18: return ulpi_scratch;
            default: return 8'h00;
        endcase
    endfunction

    // -------------------------------------------------------------------------
    // Low-Level ULPI Bus Engine State Machine
    // -------------------------------------------------------------------------
    typedef enum logic [4:0] {
        LL_IDLE             = 5'd0,
        LL_IREGW_CMD_ACK    = 5'd1,
        LL_EXTW_ADDR        = 5'd2,
        LL_EXTW_CAP_ADDR    = 5'd3,
        LL_REGW_DATA        = 5'd4,
        LL_REGW_STP         = 5'd5,
        LL_PHY_RST_DIR_HI   = 5'd6,
        LL_PHY_RST_DIR_LO   = 5'd7,
        LL_IREGR_CMD_ACK    = 5'd8,
        LL_EXTR_CMD_ACK     = 5'd9,
        LL_EXTR_CAP_ADDR    = 5'd10,
        LL_REGR_TURN        = 5'd11,
        LL_REGR_DATA        = 5'd12,
        LL_REGR_END1        = 5'd13,
        LL_REGR_END2        = 5'd14,
        LL_NOPID_TX         = 5'd15,
        LL_PKT_RX_PID_ACK   = 5'd16,
        LL_PKT_RX_DATA      = 5'd17,
        LL_TX_RXCMD_1       = 5'd18,
        LL_TX_RXCMD_2       = 5'd19,
        LL_TX_RXCMD_END1    = 5'd20,
        LL_TX_RXCMD_END2    = 5'd21,
        LL_TX_PKT_TURN      = 5'd22,
        LL_TX_PKT_BYTE      = 5'd23,
        LL_TX_PKT_END1      = 5'd24,
        LL_TX_PKT_END2      = 5'd25,
        LL_PKT_RX_PID_WAIT  = 5'd26,
        LL_TX_PKT_PACE      = 5'd27,
        LL_LP_ENTER         = 5'd28,
        LL_LOW_POWER        = 5'd29
    } ll_state_t;

    ll_state_t  ll_state;
    logic [7:0] ll_reg_addr;
    logic [7:0] ll_reg_wdata;
    logic [7:0] ll_reg_rdata;
    logic [2:0] ll_cnt;
    logic [4:0] ll_pace_cnt;
    logic       ll_auto_rxcmd;
    logic       host_driving_ls;

    logic        ulpi_init_done;
    logic [7:0]  ulpi_reg_op_count;
    logic [7:0]  last_ulpi_cmd;
    logic        chirp_k_seen;
    logic        dev_pkt_received;
    logic        dev_pkt_crc_err;
    logic [15:0] rx_crc16;
    logic [3:0]  rx_pid;
    logic [7:0]  rx_len;
    logic [6:0]  rx_raw_cnt;
    logic [31:0] rx_buf [0:15];

    // One-cycle staging of received bytes (timing: keeps the usb_pie -> host
    // ULPI data path to a handful of flops).
    logic        rx_cap_valid;
    logic [7:0]  rx_cap_byte;
    logic [5:0]  rx_cap_idx;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (int i = 0; i < 16; i++) begin
                rx_buf[i] <= 32'h0;
            end
        end else if (rx_cap_valid) begin
            rx_buf[rx_cap_idx[5:2]][(rx_cap_idx[1:0] * 8) +: 8] <= rx_cap_byte;
        end
    end

    // High-level -> Low-level requests
    logic        ll_req_rxcmd;
    logic        ll_req_txpkt;
    logic        ll_op_done;
    logic [7:0]  ll_tx_pkt [0:67]; // Max: 1 PID + 64 data + 2 CRC16 = 67 bytes
    logic [6:0]  ll_tx_len;
    logic [6:0]  ll_tx_idx;

    wire link_presenting_cmd = ulpi_txenable_i && (ulpi_txdata_i != 8'h00);
    wire [7:0] rxcmd_byte          = {2'b00, 2'b00, ctrl_vbus_valid, 1'b0, cur_linestate};
    wire [7:0] rxcmd_rxactive_byte = {2'b00, 2'b01, ctrl_vbus_valid, 1'b0, cur_linestate};
    wire       ll_tx_paced         = (BYTE_PACE_WAIT_CYC > 0) && (ll_tx_len > 7'd3);

    // -------------------------------------------------------------------------
    // High-Level Host Sequencer State Machine
    // -------------------------------------------------------------------------
    typedef enum logic [3:0] {
        HL_IDLE              = 4'd0,
        HL_RST_SEND_SE0      = 4'd1,
        HL_RST_WAIT_CHIRP_K  = 4'd2,
        HL_RST_CHIRP_SEND    = 4'd3,
        HL_RST_CHIRP_WAIT    = 4'd4,
        HL_RST_END_SE0       = 4'd5,
        HL_RST_END_WAIT      = 4'd6,
        HL_PREP_CRC          = 4'd7,
        HL_XFER_SEND_TOK     = 4'd8,
        HL_XFER_TOK_GAP      = 4'd9,
        HL_XFER_SEND_DATA    = 4'd10,
        HL_XFER_WAIT_RESP    = 4'd11,
        HL_IN_PRE_ACK_GAP    = 4'd12,
        HL_IN_SEND_ACK       = 4'd13,
        HL_POST_GAP          = 4'd14,
        HL_AUTO_SOF          = 4'd15
    } hl_state_t;

    hl_state_t   hl_state;
    logic        hl_done;
    logic        hl_timeout_err;
    logic        hs_active;

    logic        cmd_pending;
    logic [2:0]  cmd_op;
    logic        cmd_data_toggle;
    logic [6:0]  cmd_addr;
    logic [3:0]  cmd_endp;
    logic [6:0]  cmd_tx_len;
    logic [1:0]  cmd_rxcmd_ls;

    logic [31:0] resp_timeout_cycles;
    logic [31:0] hl_timer;
    logic [2:0]  chirp_idx;
    logic [6:0]  crc_idx;
    logic [15:0] crc16_acc;

    logic [31:0] sof_timer;
    logic [10:0] sof_frame_num;
    logic [15:0] sof_count;

    logic [31:0] tx_buf [0:15];

    function automatic logic [7:0] get_tx_byte(input logic [6:0] idx);
        return tx_buf[idx[5:2]][(idx[1:0] * 8) +: 8];
    endfunction

    // -------------------------------------------------------------------------
    // AXI4-Lite Slave Interface
    // -------------------------------------------------------------------------
    logic        aw_latched;
    logic [11:0] awaddr_q;
    logic        w_latched;
    logic [31:0] wdata_q;
    logic [3:0]  wstrb_q;

    wire host_busy = (hl_state != HL_IDLE) || cmd_pending;
    wire dev_connected = ulpi_func_ctrl[2] || hs_active;

    wire [31:0] status_word = {
        hl_state,                         // [31:28]
        ulpi_func_ctrl,                   // [27:20]
        rx_len,                           // [19:12]
        rx_pid,                           // [11:8]
        usb_recovery_image_activated,     // [7]
        usb_recovery_payload_available,   // [6]
        hs_active,                        // [5]
        dev_connected,                    // [4]
        ulpi_init_done,                   // [3]
        hl_timeout_err,                   // [2]
        hl_done,                          // [1]
        host_busy                         // [0]
    };

    wire [31:0] diag_word = {
        last_ulpi_cmd,     // [31:24]
        ulpi_reg_op_count, // [23:16]
        sof_count          // [15:0]
    };

    assign s_axil_awready = !aw_latched && !s_axil_bvalid;
    assign s_axil_wready  = !w_latched  && !s_axil_bvalid;
    assign s_axil_bresp   = 2'b00;
    assign s_axil_rresp   = 2'b00;

    // Read channel
    logic ar_ready_q;
    assign s_axil_arready = !s_axil_rvalid;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            s_axil_rvalid <= 1'b0;
            s_axil_rdata  <= 32'h0;
        end else begin
            if (s_axil_arvalid && s_axil_arready) begin
                s_axil_rvalid <= 1'b1;
                case (s_axil_araddr[7:2])
                    6'h00: s_axil_rdata <= HOST_MAGIC_VALUE;
                    6'h01: s_axil_rdata <= {30'd0, ctrl_auto_sof_en, ctrl_vbus_valid};
                    6'h02: s_axil_rdata <= status_word;
                    6'h03: s_axil_rdata <= {5'd0, cmd_tx_len, cmd_endp, 1'b0, cmd_addr, 4'd0, cmd_data_toggle, cmd_op};
                    6'h04: s_axil_rdata <= resp_timeout_cycles;
                    6'h05: s_axil_rdata <= diag_word;
                    default: begin
                        if (s_axil_araddr[7:6] == 2'b01) begin
                            s_axil_rdata <= tx_buf[s_axil_araddr[5:2]];
                        end else if (s_axil_araddr[7:6] == 2'b10) begin
                            s_axil_rdata <= rx_buf[s_axil_araddr[5:2]];
                        end else begin
                            s_axil_rdata <= 32'h0;
                        end
                    end
                endcase
            end else if (s_axil_rvalid && s_axil_rready) begin
                s_axil_rvalid <= 1'b0;
            end
        end
    end

    // Write channel + Low-Level & High-Level FSMs
    logic soft_reset_req;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            aw_latched          <= 1'b0;
            awaddr_q            <= 12'h0;
            w_latched           <= 1'b0;
            wdata_q             <= 32'h0;
            wstrb_q             <= 4'h0;
            s_axil_bvalid       <= 1'b0;

            ctrl_vbus_valid     <= 1'b1;
            ctrl_auto_sof_en    <= 1'b0;
            soft_reset_req      <= 1'b0;
            resp_timeout_cycles <= DEFAULT_RESP_TIMEOUT_CYC;

            cmd_pending         <= 1'b0;
            cmd_op              <= OP_NOP;
            cmd_data_toggle     <= 1'b0;
            cmd_addr            <= 7'd0;
            cmd_endp            <= 4'd0;
            cmd_tx_len          <= 7'd0;
            cmd_rxcmd_ls        <= 2'b01;

            for (int i = 0; i < 16; i++) begin
                tx_buf[i] <= 32'h0;
            end
            rx_cap_valid <= 1'b0;
            rx_cap_byte  <= 8'h00;
            rx_cap_idx   <= 6'd0;

            // ULPI PHY state
            ulpi_func_ctrl      <= 8'h41;
            ulpi_ifc_ctrl       <= 8'h00;
            ulpi_otg_ctrl       <= 8'h06;
            ulpi_scratch        <= 8'h00;
            cur_linestate       <= 2'b01; // FS Idle J
            ulpi_init_done      <= 1'b0;
            ulpi_reg_op_count   <= 8'd0;
            last_ulpi_cmd       <= 8'h00;

            ulpi_rxdata_o       <= 8'h00;
            ulpi_dir_o          <= 1'b0;
            ulpi_nxt_o          <= 1'b0;

            ll_state            <= LL_IDLE;
            ll_reg_addr         <= 8'h00;
            ll_reg_wdata        <= 8'h00;
            ll_reg_rdata        <= 8'h00;
            ll_cnt              <= 3'd0;
            ll_pace_cnt         <= 5'd0;
            ll_auto_rxcmd       <= 1'b0;
            host_driving_ls     <= 1'b0;
            ll_op_done          <= 1'b0;
            ll_tx_idx           <= 7'd0;

            chirp_k_seen        <= 1'b0;
            dev_pkt_received    <= 1'b0;
            dev_pkt_crc_err     <= 1'b0;
            rx_crc16            <= 16'hffff;
            rx_pid              <= 4'h0;
            rx_len              <= 8'd0;
            rx_raw_cnt          <= 7'd0;

            hl_state            <= HL_IDLE;
            hl_done             <= 1'b0;
            hl_timeout_err      <= 1'b0;
            hs_active           <= 1'b0;
            hl_timer            <= 32'd0;
            chirp_idx           <= 3'd0;
            crc_idx             <= 7'd0;
            crc16_acc           <= 16'hffff;
            ll_req_rxcmd        <= 1'b0;
            ll_req_txpkt        <= 1'b0;
            ll_tx_len           <= 7'd0;
            for (int i = 0; i < 68; i++) begin
                ll_tx_pkt[i] <= 8'h00;
            end

            sof_timer           <= 32'd0;
            sof_frame_num       <= 11'd0;
            sof_count           <= 16'd0;
        end else begin
            ll_op_done     <= 1'b0;
            soft_reset_req <= 1'b0;
            rx_cap_valid   <= 1'b0;

            // -----------------------------------------------------------------
            // AXI4-Lite Write Capture & Register Updates
            // -----------------------------------------------------------------
            if (s_axil_awvalid && s_axil_awready) begin
                aw_latched <= 1'b1;
                awaddr_q   <= s_axil_awaddr;
            end
            if (s_axil_wvalid && s_axil_wready) begin
                w_latched <= 1'b1;
                wdata_q   <= s_axil_wdata;
                wstrb_q   <= s_axil_wstrb;
            end

            if (s_axil_bvalid && s_axil_bready) begin
                s_axil_bvalid <= 1'b0;
            end

            if ((aw_latched || (s_axil_awvalid && s_axil_awready)) &&
                (w_latched  || (s_axil_wvalid  && s_axil_wready))) begin
                automatic logic [11:0] waddr = aw_latched ? awaddr_q : s_axil_awaddr;
                automatic logic [31:0] wdat  = w_latched  ? wdata_q  : s_axil_wdata;
                automatic logic [3:0]  wstrb = w_latched  ? wstrb_q  : s_axil_wstrb;

                aw_latched    <= 1'b0;
                w_latched     <= 1'b0;
                s_axil_bvalid <= 1'b1;

                case (waddr[7:2])
                    6'h01: begin // HOST_CTRL (0x04)
                        if (wstrb[0]) begin
                            ctrl_vbus_valid  <= wdat[0];
                            ctrl_auto_sof_en <= wdat[1];
                            soft_reset_req   <= wdat[2];
                        end
                    end
                    6'h03: begin // HOST_CMD (0x0C)
                        if (!host_busy && (wdat[2:0] != OP_NOP)) begin
                            cmd_op          <= wdat[2:0];
                            cmd_data_toggle <= wdat[3];
                            cmd_rxcmd_ls    <= wdat[5:4];
                            cmd_addr        <= wdat[14:8];
                            cmd_endp        <= wdat[19:16];
                            cmd_tx_len      <= (wdat[26:20] > 7'd64) ? 7'd64 : wdat[26:20];
                            cmd_pending     <= 1'b1;
                            hl_done         <= 1'b0;
                            hl_timeout_err  <= 1'b0;
                        end
                    end
                    6'h04: begin // HOST_TIMEOUT (0x10)
                        for (int b = 0; b < 4; b++) begin
                            if (wstrb[b]) resp_timeout_cycles[b*8 +: 8] <= wdat[b*8 +: 8];
                        end
                    end
                    default: begin
                        if (waddr[7:6] == 2'b01) begin // TX_BUF (0x40..0x7C)
                            for (int b = 0; b < 4; b++) begin
                                if (wstrb[b]) tx_buf[waddr[5:2]][b*8 +: 8] <= wdat[b*8 +: 8];
                            end
                        end
                    end
                endcase
            end

            // -----------------------------------------------------------------
            // Soft Reset Handling
            // -----------------------------------------------------------------
            if (soft_reset_req) begin
                hl_state         <= HL_IDLE;
                ll_state         <= LL_IDLE;
                ulpi_dir_o       <= 1'b0;
                ulpi_nxt_o       <= 1'b0;
                ulpi_rxdata_o    <= 8'h00;
                cmd_pending      <= 1'b0;
                ll_req_rxcmd     <= 1'b0;
                ll_req_txpkt     <= 1'b0;
                ll_auto_rxcmd    <= 1'b0;
                host_driving_ls  <= 1'b0;
                ll_pace_cnt      <= 5'd0;
                hl_done          <= 1'b0;
                hl_timeout_err   <= 1'b0;
                hs_active        <= 1'b0;
                chirp_k_seen     <= 1'b0;
                dev_pkt_received <= 1'b0;
                dev_pkt_crc_err  <= 1'b0;
                rx_crc16         <= 16'hffff;
                cur_linestate    <= 2'b01;
                ulpi_func_ctrl   <= 8'h41;
                ulpi_ifc_ctrl    <= 8'h00;
                ulpi_otg_ctrl    <= 8'h06;
                ulpi_init_done   <= 1'b0;
            end else begin
                // -------------------------------------------------------------
                // Auto-SOF Timer
                // -------------------------------------------------------------
                if (ctrl_auto_sof_en && hs_active) begin
                    if (sof_timer != 32'hFFFF_FFFF) begin
                        sof_timer <= sof_timer + 32'd1;
                    end
                end else begin
                    sof_timer <= 32'd0;
                end

                // -------------------------------------------------------------
                // Low-Level ULPI Bus Engine
                // -------------------------------------------------------------
                case (ll_state)
                    LL_IDLE: begin
                        ulpi_dir_o    <= 1'b0;
                        ulpi_nxt_o    <= 1'b0;
                        ulpi_rxdata_o <= 8'h00;

                        // Priority 1: Service Link-initiated ULPI TXCMD
                        if (link_presenting_cmd) begin
                            last_ulpi_cmd <= ulpi_txdata_i;
                            if (ulpi_txdata_i == 8'hAF) begin
                                // Extended Register Write
                                ulpi_nxt_o <= 1'b1;
                                ll_state   <= LL_EXTW_ADDR;
                            end else if (ulpi_txdata_i[7:6] == 2'b10) begin
                                // Immediate Register Write
                                ll_reg_addr <= {2'b00, ulpi_txdata_i[5:0]};
                                ulpi_nxt_o  <= 1'b1;
                                ll_state    <= LL_IREGW_CMD_ACK;
                            end else if (ulpi_txdata_i == 8'hEF) begin
                                // Extended Register Read
                                ulpi_nxt_o <= 1'b1;
                                ll_state   <= LL_EXTR_CMD_ACK;
                            end else if (ulpi_txdata_i[7:6] == 2'b11) begin
                                // Immediate Register Read
                                ll_reg_addr <= {2'b00, ulpi_txdata_i[5:0]};
                                ulpi_nxt_o  <= 1'b1;
                                ll_state    <= LL_IREGR_CMD_ACK;
                            end else if (ulpi_txdata_i == 8'h40) begin
                                // NOPID TX (Chirp K / Resume)
                                ulpi_nxt_o <= 1'b1;
                                ll_state   <= LL_NOPID_TX;
                            end else if (ulpi_txdata_i[7:4] == 4'b0100) begin
                                // PID Packet TX (Handshake or DATA0/1)
                                rx_pid          <= ulpi_txdata_i[3:0];
                                rx_raw_cnt      <= 7'd0;
                                rx_crc16        <= 16'hffff;
                                dev_pkt_crc_err <= 1'b0;
                                if ((ulpi_txdata_i[1:0] == 2'b11) && (RX_PID_STARTUP_CYC > 0)) begin
                                    // Hold NXT=0 briefly on DATA0/DATA1 so usb_pie's
                                    // epinfo_txdata_valid from 18 MHz hclk settles
                                    // before USB_PROT_IN_TX_DATA_PID_1 sees txready=1.
                                    ulpi_nxt_o  <= 1'b0;
                                    ll_pace_cnt <= 5'(RX_PID_STARTUP_CYC - 1);
                                    ll_state    <= LL_PKT_RX_PID_WAIT;
                                end else begin
                                    ulpi_nxt_o <= 1'b1;
                                    ll_state   <= LL_PKT_RX_PID_ACK;
                                end
                            end
                        end else if (ll_req_rxcmd) begin
                            ll_req_rxcmd  <= 1'b0;
                            ll_auto_rxcmd <= 1'b0;
                            ulpi_dir_o    <= 1'b1;
                            ulpi_nxt_o    <= 1'b0;
                            ulpi_rxdata_o <= rxcmd_byte;
                            ll_state      <= LL_TX_RXCMD_1;
                        end else if (ll_req_txpkt) begin
                            ll_req_txpkt  <= 1'b0;
                            ll_tx_idx     <= 7'd0;
                            ulpi_dir_o    <= 1'b1;
                            ulpi_nxt_o    <= 1'b1;
                            ulpi_rxdata_o <= 8'h00; // Turnaround cycle
                            ll_state      <= LL_TX_PKT_TURN;
                        end else if (ll_auto_rxcmd && (hl_state == HL_IDLE) && !cmd_pending) begin
                            ll_auto_rxcmd <= 1'b0;
                            ulpi_dir_o    <= 1'b1;
                            ulpi_nxt_o    <= 1'b0;
                            ulpi_rxdata_o <= rxcmd_byte;
                            ll_state      <= LL_TX_RXCMD_1;
                        end
                    end

                    // --- Immediate / Extended Register Write ---
                    LL_IREGW_CMD_ACK: begin
                        // Link transitions IREG_WR_TX_CMD -> REG_WR_TX_DATA
                        ulpi_nxt_o <= 1'b1;
                        ll_state   <= LL_REGW_DATA;
                    end

                    LL_EXTW_ADDR: begin
                        // Link transitions XREG_WR_TX_CMD -> XREG_WR_TX_ADD
                        ulpi_nxt_o <= 1'b1;
                        ll_state   <= LL_EXTW_CAP_ADDR;
                    end

                    LL_EXTW_CAP_ADDR: begin
                        // Capture extended address; Link transitions -> REG_WR_TX_DATA
                        ll_reg_addr <= ulpi_txdata_i;
                        ulpi_nxt_o  <= 1'b1;
                        ll_state    <= LL_REGW_DATA;
                    end

                    LL_REGW_DATA: begin
                        // Capture write data; Link transitions -> REG_END_CYCLE / WF_START_RESET_PHY and sets STP
                        ll_reg_wdata <= ulpi_txdata_i;
                        ulpi_nxt_o   <= 1'b0;
                        ll_state     <= LL_REGW_STP;
                    end

                    LL_REGW_STP: begin
                        if (ulpi_stp_i) begin
                            automatic logic       is_phy_rst;
                            automatic logic       fc_updated;
                            automatic logic [7:0] next_fc;
                            is_phy_rst = 1'b0;
                            fc_updated = 1'b0;
                            next_fc    = ulpi_func_ctrl;
                            ulpi_reg_op_count <= ulpi_reg_op_count + 8'd1;

                            case (ll_reg_addr)
                                8'h04: begin
                                    fc_updated = 1'b1;
                                    if (ll_reg_wdata[5]) begin
                                        is_phy_rst = 1'b1;
                                        next_fc    = (ll_reg_wdata & 8'hDF) | 8'h40;
                                    end else begin
                                        next_fc    = ll_reg_wdata;
                                    end
                                    ulpi_func_ctrl <= next_fc;
                                end
                                8'h05: begin
                                    fc_updated = 1'b1;
                                    if (ll_reg_wdata[5]) begin
                                        is_phy_rst     = 1'b1;
                                        next_fc        = 8'h41;
                                        ulpi_ifc_ctrl  <= 8'h00;
                                        ulpi_otg_ctrl  <= 8'h06;
                                    end else begin
                                        next_fc        = ulpi_func_ctrl | ll_reg_wdata;
                                    end
                                    ulpi_func_ctrl <= next_fc;
                                end
                                8'h06: begin
                                    fc_updated     = 1'b1;
                                    next_fc        = ulpi_func_ctrl & ~ll_reg_wdata;
                                    ulpi_func_ctrl <= next_fc;
                                end
                                8'h07: ulpi_ifc_ctrl  <= ll_reg_wdata;
                                8'h08: ulpi_ifc_ctrl  <= ulpi_ifc_ctrl | ll_reg_wdata;
                                8'h09: ulpi_ifc_ctrl  <= ulpi_ifc_ctrl & ~ll_reg_wdata;
                                8'h0A: ulpi_otg_ctrl  <= ll_reg_wdata;
                                8'h0B: ulpi_otg_ctrl  <= ulpi_otg_ctrl | ll_reg_wdata;
                                8'h0C: ulpi_otg_ctrl  <= ulpi_otg_ctrl & ~ll_reg_wdata;
                                8'h16: ulpi_scratch   <= ll_reg_wdata;
                                8'h17: ulpi_scratch   <= ulpi_scratch | ll_reg_wdata;
                                8'h18: ulpi_scratch   <= ulpi_scratch & ~ll_reg_wdata;
                                default: ;
                            endcase

                            // Emulated USB3320 passive bus comparator: when the
                            // host is not actively driving reset/chirp, reflect
                            // Full-Speed 1.5k pull-up J (2'b01) when TermSelect=1
                            // and SE0 (2'b00) when TermSelect=0.
                            if (fc_updated && !is_phy_rst && !host_driving_ls) begin
                                automatic logic [1:0] idle_ls = next_fc[2] ? 2'b01 : 2'b00;
                                if (idle_ls != cur_linestate) begin
                                    cur_linestate <= idle_ls;
                                    ll_auto_rxcmd <= 1'b1;
                                end
                                if (next_fc[2]) begin
                                    hs_active <= 1'b0;
                                end
                            end

                            if (is_phy_rst) begin
                                ulpi_dir_o <= 1'b1;
                                ulpi_nxt_o <= 1'b0;
                                ll_cnt     <= 3'd4;
                                ll_state   <= LL_PHY_RST_DIR_HI;
                            end else if (fc_updated && !next_fc[6]) begin
                                // ULPI 1.1 §3.9 Low Power Mode (SuspendM=0):
                                // let usb_pie enter ULPI_OPER_LOW_POWER, then
                                // assert DIR=1 until Link drives STP=1 to wake.
                                ll_cnt   <= 3'd2;
                                ll_state <= LL_LP_ENTER;
                            end else begin
                                ll_state <= LL_IDLE;
                            end
                        end
                    end

                    LL_LP_ENTER: begin
                        if (ll_cnt == 3'd0) begin
                            ulpi_dir_o    <= 1'b1;
                            ulpi_nxt_o    <= 1'b0;
                            ulpi_rxdata_o <= {5'b00000, ctrl_vbus_valid, cur_linestate};
                            ll_state      <= LL_LOW_POWER;
                        end else begin
                            ll_cnt <= ll_cnt - 3'd1;
                        end
                    end

                    LL_LOW_POWER: begin
                        if (ulpi_stp_i) begin
                            // Link asserted STP to exit Low Power Mode
                            ulpi_func_ctrl[6] <= 1'b1;
                            ulpi_dir_o        <= 1'b0;
                            ulpi_nxt_o        <= 1'b0;
                            ulpi_rxdata_o     <= 8'h00;
                            ll_state          <= LL_REGR_END1;
                        end else begin
                            ulpi_dir_o    <= 1'b1;
                            ulpi_nxt_o    <= 1'b0;
                            ulpi_rxdata_o <= {5'b00000, ctrl_vbus_valid, cur_linestate};
                        end
                    end

                    LL_PHY_RST_DIR_HI: begin
                        if (ll_cnt == 3'd0) begin
                            ulpi_dir_o <= 1'b0;
                            ll_cnt     <= 3'd2;
                            ll_state   <= LL_PHY_RST_DIR_LO;
                        end else begin
                            ll_cnt <= ll_cnt - 3'd1;
                        end
                    end

                    LL_PHY_RST_DIR_LO: begin
                        if (ll_cnt == 3'd0) begin
                            // Send post-reset RXCMD update so usb_pie leaves ULPI_OPER_RESET_WF_RXCMD_UPDATE
                            ulpi_init_done <= 1'b1;
                            ulpi_dir_o     <= 1'b1;
                            ulpi_nxt_o     <= 1'b0;
                            ulpi_rxdata_o  <= rxcmd_byte;
                            ll_state       <= LL_TX_RXCMD_1;
                        end else begin
                            ll_cnt <= ll_cnt - 3'd1;
                        end
                    end

                    // --- Immediate / Extended Register Read ---
                    LL_IREGR_CMD_ACK: begin
                        // Link transitions IREG_RD_TX_CMD -> REG_RD_TX_DATA
                        ll_reg_rdata  <= ulpi_reg_read(ll_reg_addr);
                        ulpi_nxt_o    <= 1'b0;
                        ulpi_dir_o    <= 1'b1;
                        ulpi_rxdata_o <= ulpi_reg_read(ll_reg_addr);
                        ll_state      <= LL_REGR_TURN;
                    end

                    LL_EXTR_CMD_ACK: begin
                        // Link transitions XREG_RD_TX_CMD -> XREG_RD_TX_ADD
                        ulpi_nxt_o <= 1'b1;
                        ll_state   <= LL_EXTR_CAP_ADDR;
                    end

                    LL_EXTR_CAP_ADDR: begin
                        // Capture extended address; Link transitions -> REG_RD_TX_DATA
                        automatic logic [7:0] rval = ulpi_reg_read(ulpi_txdata_i);
                        ll_reg_addr   <= ulpi_txdata_i;
                        ll_reg_rdata  <= rval;
                        ulpi_nxt_o    <= 1'b0;
                        ulpi_dir_o    <= 1'b1;
                        ulpi_rxdata_o <= rval;
                        ll_state      <= LL_REGR_TURN;
                    end

                    LL_REGR_TURN: begin
                        // Cycle 1 of dir=1 (turnaround)
                        ulpi_dir_o    <= 1'b1;
                        ulpi_nxt_o    <= 1'b0;
                        ulpi_rxdata_o <= ll_reg_rdata;
                        ll_state      <= LL_REGR_DATA;
                    end

                    LL_REGR_DATA: begin
                        // Cycle 2 of dir=1 (data); deassert dir for next cycle!
                        ulpi_reg_op_count <= ulpi_reg_op_count + 8'd1;
                        ulpi_dir_o        <= 1'b0;
                        ulpi_nxt_o        <= 1'b0;
                        ulpi_rxdata_o     <= 8'h00;
                        ll_state          <= LL_REGR_END1;
                    end

                    LL_REGR_END1: begin
                        // usb_pie latches ulpi_rxdata_r and enters REG_END_CYCLE
                        ll_state <= LL_REGR_END2;
                    end

                    LL_REGR_END2: begin
                        // usb_pie transitions REG_END_CYCLE -> ULPI_OPER_IDLE
                        ll_state <= LL_IDLE;
                    end

                    // --- Device Chirp K / Resume NOPID TX ---
                    LL_NOPID_TX: begin
                        if (ulpi_stp_i) begin
                            ulpi_nxt_o   <= 1'b0;
                            chirp_k_seen <= 1'b1;
                            ll_state     <= LL_IDLE;
                        end else begin
                            ulpi_nxt_o <= 1'b1;
                        end
                    end

                    // --- Device -> Host Packet RX (Handshake or DATA0/1) ---
                    LL_PKT_RX_PID_WAIT: begin
                        if (ulpi_stp_i) begin
                            ulpi_nxt_o       <= 1'b0;
                            rx_len           <= 8'd0;
                            dev_pkt_received <= 1'b1;
                            ll_state         <= LL_IDLE;
                        end else if (ll_pace_cnt == 5'd0) begin
                            ulpi_nxt_o <= 1'b1;
                            ll_state   <= LL_PKT_RX_PID_ACK;
                        end else begin
                            ulpi_nxt_o  <= 1'b0;
                            ll_pace_cnt <= ll_pace_cnt - 5'd1;
                        end
                    end

                    LL_PKT_RX_PID_ACK: begin
                        // Cycle where usb_pie sees txready=1 on PID byte
                        if (ulpi_stp_i) begin
                            ulpi_nxt_o       <= 1'b0;
                            rx_len           <= 8'd0;
                            dev_pkt_received <= 1'b1;
                            ll_state         <= LL_IDLE;
                        end else if (BYTE_PACE_WAIT_CYC > 0) begin
                            ulpi_nxt_o  <= 1'b0;
                            ll_pace_cnt <= 5'(BYTE_PACE_WAIT_CYC - 1);
                            ll_state    <= LL_PKT_RX_DATA;
                        end else begin
                            ulpi_nxt_o <= 1'b1;
                            ll_state   <= LL_PKT_RX_DATA;
                        end
                    end

                    LL_PKT_RX_DATA: begin
                        if (ulpi_stp_i) begin
                            ulpi_nxt_o       <= 1'b0;
                            rx_len           <= (rx_raw_cnt >= 7'd2) ? {1'b0, rx_raw_cnt - 7'd2} : 8'd0;
                            dev_pkt_crc_err  <= (rx_raw_cnt < 7'd2) || (rx_crc16 != CRC16_RESIDUAL_OK);
                            dev_pkt_received <= 1'b1;
                            ll_state         <= LL_IDLE;
                        end else if (ulpi_nxt_o) begin
                            // Capture into a small staging register; the 16x32
                            // rx_buf write happens one cycle later so the
                            // device -> host ULPI path does not fan out into
                            // 512 clock enables at 60 MHz.
                            if (rx_raw_cnt < 7'd64) begin
                                rx_cap_valid <= 1'b1;
                                rx_cap_byte  <= ulpi_txdata_i;
                                rx_cap_idx   <= rx_raw_cnt[5:0];
                            end
                            rx_crc16 <= step_crc16(ulpi_txdata_i, rx_crc16);
                            if (rx_raw_cnt < 7'd67) begin
                                rx_raw_cnt <= rx_raw_cnt + 7'd1;
                            end
                            if (BYTE_PACE_WAIT_CYC > 0) begin
                                ulpi_nxt_o  <= 1'b0;
                                ll_pace_cnt <= 5'(BYTE_PACE_WAIT_CYC - 1);
                            end else begin
                                ulpi_nxt_o <= 1'b1;
                            end
                        end else begin
                            if (ll_pace_cnt == 5'd0) begin
                                ulpi_nxt_o <= 1'b1;
                            end else begin
                                ll_pace_cnt <= ll_pace_cnt - 5'd1;
                            end
                        end
                    end

                    // --- Host -> Device RXCMD Update (exact 2 cycles dir=1, nxt=0) ---
                    LL_TX_RXCMD_1: begin
                        ulpi_dir_o    <= 1'b1;
                        ulpi_nxt_o    <= 1'b0;
                        ulpi_rxdata_o <= rxcmd_byte;
                        ll_state      <= LL_TX_RXCMD_2;
                    end

                    LL_TX_RXCMD_2: begin
                        ulpi_dir_o    <= 1'b0;
                        ulpi_nxt_o    <= 1'b0;
                        ulpi_rxdata_o <= 8'h00;
                        ll_state      <= LL_TX_RXCMD_END1;
                    end

                    LL_TX_RXCMD_END1: begin
                        ll_state <= LL_TX_RXCMD_END2;
                    end

                    LL_TX_RXCMD_END2: begin
                        ll_op_done <= 1'b1;
                        ll_state   <= LL_IDLE;
                    end

                    // --- Host -> Device Packet TX (1 turnaround + N data bytes, ULPI 1.1 NXT pacing) ---
                    LL_TX_PKT_TURN: begin
                        ulpi_dir_o    <= 1'b1;
                        ulpi_nxt_o    <= 1'b1;
                        ulpi_rxdata_o <= ll_tx_pkt[0];
                        ll_tx_idx     <= 7'd1;
                        ll_state      <= LL_TX_PKT_BYTE;
                    end

                    LL_TX_PKT_BYTE: begin
                        if (ll_tx_idx >= ll_tx_len) begin
                            ulpi_dir_o    <= 1'b0;
                            ulpi_nxt_o    <= 1'b0;
                            ulpi_rxdata_o <= 8'h00;
                            ll_state      <= LL_TX_PKT_END1;
                        end else if (ll_tx_paced) begin
                            // ULPI 1.1 §3.8.2.2: hold DIR=1, NXT=0 with RXCMD
                            // RxActive=1 while pacing multi-byte DATA packets.
                            ulpi_dir_o    <= 1'b1;
                            ulpi_nxt_o    <= 1'b0;
                            ulpi_rxdata_o <= rxcmd_rxactive_byte;
                            ll_pace_cnt   <= 5'(BYTE_PACE_WAIT_CYC - 1);
                            ll_state      <= LL_TX_PKT_PACE;
                        end else begin
                            ulpi_dir_o    <= 1'b1;
                            ulpi_nxt_o    <= 1'b1;
                            ulpi_rxdata_o <= ll_tx_pkt[ll_tx_idx];
                            ll_tx_idx     <= ll_tx_idx + 7'd1;
                        end
                    end

                    LL_TX_PKT_PACE: begin
                        if (ll_pace_cnt == 5'd0) begin
                            ulpi_dir_o    <= 1'b1;
                            ulpi_nxt_o    <= 1'b1;
                            ulpi_rxdata_o <= ll_tx_pkt[ll_tx_idx];
                            ll_tx_idx     <= ll_tx_idx + 7'd1;
                            ll_state      <= LL_TX_PKT_BYTE;
                        end else begin
                            ulpi_dir_o    <= 1'b1;
                            ulpi_nxt_o    <= 1'b0;
                            ulpi_rxdata_o <= rxcmd_rxactive_byte;
                            ll_pace_cnt   <= ll_pace_cnt - 5'd1;
                        end
                    end

                    LL_TX_PKT_END1: begin
                        ll_state <= LL_TX_PKT_END2;
                    end

                    LL_TX_PKT_END2: begin
                        ll_op_done <= 1'b1;
                        ll_state   <= LL_IDLE;
                    end

                    default: ll_state <= LL_IDLE;
                endcase

                // -------------------------------------------------------------
                // High-Level Sequencer (Reset, Enumeration/OCP Transfers, SOF)
                // -------------------------------------------------------------
                case (hl_state)
                    HL_IDLE: begin
                        if (cmd_pending) begin
                            cmd_pending <= 1'b0;
                            case (cmd_op)
                                OP_BUS_RESET_HS: begin
                                    chirp_k_seen    <= 1'b0;
                                    hs_active       <= 1'b0;
                                    host_driving_ls <= 1'b1;
                                    ll_auto_rxcmd   <= 1'b0;
                                    cur_linestate   <= 2'b00; // SE0
                                    ll_req_rxcmd    <= 1'b1;
                                    hl_state        <= HL_RST_SEND_SE0;
                                end
                                OP_SEND_RXCMD: begin
                                    cur_linestate <= cmd_rxcmd_ls;
                                    ll_req_rxcmd  <= 1'b1;
                                    hl_timer      <= 32'd8;
                                    hl_state      <= HL_POST_GAP;
                                end
                                OP_SETUP, OP_OUT: begin
                                    crc_idx   <= 7'd0;
                                    crc16_acc <= 16'hffff;
                                    ll_tx_pkt[0] <= (cmd_op == OP_SETUP) ? PID_BYTE_DATA0 :
                                                    (cmd_data_toggle ? PID_BYTE_DATA1 : PID_BYTE_DATA0);
                                    hl_state  <= HL_PREP_CRC;
                                end
                                OP_IN: begin
                                    automatic logic [10:0] tok11 = {cmd_endp, cmd_addr};
                                    automatic logic [4:0]  c5    = calc_crc5(tok11);
                                    ll_tx_pkt[0]     <= PID_BYTE_IN;
                                    ll_tx_pkt[1]     <= tok11[7:0];
                                    ll_tx_pkt[2]     <= {c5, tok11[10:8]};
                                    ll_tx_len        <= 7'd3;
                                    dev_pkt_received <= 1'b0;
                                    ll_req_txpkt     <= 1'b1;
                                    hl_state         <= HL_XFER_SEND_TOK;
                                end
                                default: begin
                                    hl_done <= 1'b1;
                                end
                            endcase
                        end else if (ctrl_auto_sof_en && hs_active && (sof_timer >= SOF_INTERVAL_CYC) &&
                                     (ll_state == LL_IDLE) && !link_presenting_cmd) begin
                            automatic logic [4:0] sc5 = calc_crc5(sof_frame_num);
                            sof_timer     <= 32'd0;
                            sof_frame_num <= sof_frame_num + 11'd1;
                            sof_count     <= sof_count + 16'd1;
                            ll_tx_pkt[0]  <= PID_BYTE_SOF;
                            ll_tx_pkt[1]  <= sof_frame_num[7:0];
                            ll_tx_pkt[2]  <= {sc5, sof_frame_num[10:8]};
                            ll_tx_len     <= 7'd3;
                            ll_req_txpkt  <= 1'b1;
                            hl_state      <= HL_AUTO_SOF;
                        end
                    end

                    // --- High-Speed Bus Reset & K-J-K-J-K-J Chirp ---
                    HL_RST_SEND_SE0: begin
                        if (ll_op_done) begin
                            hl_timer <= RST_CHIRP_WAIT_CYC;
                            hl_state <= HL_RST_WAIT_CHIRP_K;
                        end
                    end

                    HL_RST_WAIT_CHIRP_K: begin
                        // chirp_k_seen is set when the device *ends* its Chirp K
                        // (ULPI STP after the NOPID TX), i.e. at T_UCH end. The
                        // host must then begin its K-J sequence within 100 us.
                        if (chirp_k_seen) begin
                            chirp_idx <= 3'd0;
                            hl_timer  <= 32'd32;
                            hl_state  <= HL_RST_CHIRP_WAIT;
                        end else if (hl_timer == 32'd0) begin
                            host_driving_ls <= 1'b0;
                            if (ulpi_func_ctrl[2]) begin
                                cur_linestate <= 2'b01; // FS pull-up J
                                ll_req_rxcmd  <= 1'b1;
                            end
                            hl_timeout_err <= 1'b1;
                            hl_timer       <= 32'd8;
                            hl_state       <= HL_POST_GAP;
                        end else begin
                            hl_timer <= hl_timer - 32'd1;
                        end
                    end

                    HL_RST_CHIRP_SEND: begin
                        if (ll_op_done) begin
                            chirp_idx <= chirp_idx + 3'd1;
                            hl_timer  <= CHIRP_KJ_HOLD_CYC; // 50 us; > MAX_LINESTATE_DBC_CNT (192)
                            hl_state  <= HL_RST_CHIRP_WAIT;
                        end
                    end

                    HL_RST_CHIRP_WAIT: begin
                        if (hl_timer == 32'd0) begin
                            if (chirp_idx < 3'd6) begin
                                cur_linestate <= chirp_idx[0] ? 2'b01 : 2'b10; // Even=K(10), Odd=J(01)
                                ll_req_rxcmd  <= 1'b1;
                                hl_state      <= HL_RST_CHIRP_SEND;
                            end else begin
                                cur_linestate <= 2'b00; // SE0 to complete HS reset
                                ll_req_rxcmd  <= 1'b1;
                                hl_state      <= HL_RST_END_SE0;
                            end
                        end else begin
                            hl_timer <= hl_timer - 32'd1;
                        end
                    end

                    HL_RST_END_SE0: begin
                        if (ll_op_done) begin
                            hl_timer <= RST_END_SE0_CYC; // 200 us; spec 100..500 us
                            hl_state <= HL_RST_END_WAIT;
                        end
                    end

                    HL_RST_END_WAIT: begin
                        if (hl_timer == 32'd0) begin
                            host_driving_ls <= 1'b0;
                            sof_timer       <= 32'd0;
                            if (ulpi_func_ctrl[2]) begin
                                // Device reverted to Full-Speed (TermSelect=1):
                                // report FS idle J so usb_pie leaves WF_EOR_FS.
                                hs_active     <= 1'b0;
                                cur_linestate <= 2'b01;
                                ll_req_rxcmd  <= 1'b1;
                                hl_timer      <= 32'd8;
                                hl_state      <= HL_POST_GAP;
                            end else begin
                                hs_active <= 1'b1;
                                hl_done   <= 1'b1;
                                hl_state  <= HL_IDLE;
                            end
                        end else begin
                            hl_timer <= hl_timer - 32'd1;
                        end
                    end

                    // --- Sequential CRC16 Preparation & SETUP/OUT/IN ---
                    HL_PREP_CRC: begin
                        if (crc_idx < cmd_tx_len) begin
                            automatic logic [7:0] b = get_tx_byte(crc_idx);
                            crc16_acc <= step_crc16(b, crc16_acc);
                            crc_idx   <= crc_idx + 7'd1;
                        end else begin
                            automatic logic [10:0] tok11 = {cmd_endp, cmd_addr};
                            automatic logic [4:0]  c5    = calc_crc5(tok11);
                            ll_tx_pkt[0]     <= (cmd_op == OP_SETUP) ? PID_BYTE_SETUP : PID_BYTE_OUT;
                            ll_tx_pkt[1]     <= tok11[7:0];
                            ll_tx_pkt[2]     <= {c5, tok11[10:8]};
                            ll_tx_len        <= 7'd3;
                            dev_pkt_received <= 1'b0;
                            ll_req_txpkt     <= 1'b1;
                            hl_state         <= HL_XFER_SEND_TOK;
                        end
                    end

                    HL_XFER_SEND_TOK: begin
                        if (ll_op_done) begin
                            if (cmd_op == OP_IN) begin
                                hl_timer <= resp_timeout_cycles;
                                hl_state <= HL_XFER_WAIT_RESP;
                            end else begin
                                // Populate ll_tx_pkt with PID + TX_BUF[0..cmd_tx_len-1] + precomputed CRC16!
                                ll_tx_pkt[0] <= (cmd_op == OP_SETUP) ? PID_BYTE_DATA0 :
                                                (cmd_data_toggle ? PID_BYTE_DATA1 : PID_BYTE_DATA0);
                                for (int i = 0; i < 64; i++) begin
                                    if (i < int'(cmd_tx_len)) begin
                                        ll_tx_pkt[1 + i] <= tx_buf[i >> 2][((i & 3) * 8) +: 8];
                                    end
                                end
                                ll_tx_pkt[7'd1 + cmd_tx_len] <= ~bit_rev8(crc16_acc[15:8]);
                                ll_tx_pkt[7'd2 + cmd_tx_len] <= ~bit_rev8(crc16_acc[7:0]);
                                ll_tx_len                    <= cmd_tx_len + 7'd3;
                                hl_timer                     <= TOK_TO_DATA_GAP_CYC; // > epinfo_valid latency, < HS turnaround (96)
                                hl_state                     <= HL_XFER_TOK_GAP;
                            end
                        end
                    end

                    HL_XFER_TOK_GAP: begin
                        if (hl_timer == 32'd0) begin
                            dev_pkt_received <= 1'b0;
                            ll_req_txpkt     <= 1'b1;
                            hl_state         <= HL_XFER_SEND_DATA;
                        end else begin
                            hl_timer <= hl_timer - 32'd1;
                        end
                    end

                    HL_XFER_SEND_DATA: begin
                        if (ll_op_done) begin
                            hl_timer <= resp_timeout_cycles;
                            hl_state <= HL_XFER_WAIT_RESP;
                        end
                    end

                    HL_XFER_WAIT_RESP: begin
                        if (dev_pkt_received) begin
                            if ((cmd_op == OP_IN) &&
                                ((rx_pid == PID_NIB_DATA0) || (rx_pid == PID_NIB_DATA1))) begin
                                if (dev_pkt_crc_err) begin
                                    // USB 2.0 §8.5.2: discard CRC-corrupted IN packet without ACKing
                                    hl_timeout_err <= 1'b1;
                                    hl_timer       <= 32'd8;
                                    hl_state       <= HL_POST_GAP;
                                end else begin
                                    hl_timer <= 32'd8;
                                    hl_state <= HL_IN_PRE_ACK_GAP;
                                end
                            end else begin
                                hl_timer <= 32'd8;
                                hl_state <= HL_POST_GAP;
                            end
                        end else if (hl_timer == 32'd0) begin
                            hl_timeout_err <= 1'b1;
                            hl_done        <= 1'b1;
                            hl_state       <= HL_IDLE;
                        end else begin
                            hl_timer <= hl_timer - 32'd1;
                        end
                    end

                    HL_IN_PRE_ACK_GAP: begin
                        if (hl_timer == 32'd0) begin
                            ll_tx_pkt[0] <= PID_BYTE_ACK;
                            ll_tx_len    <= 7'd1;
                            ll_req_txpkt <= 1'b1;
                            hl_state     <= HL_IN_SEND_ACK;
                        end else begin
                            hl_timer <= hl_timer - 32'd1;
                        end
                    end

                    HL_IN_SEND_ACK: begin
                        if (ll_op_done) begin
                            hl_timer <= 32'd8;
                            hl_state <= HL_POST_GAP;
                        end
                    end

                    HL_POST_GAP: begin
                        if ((hl_timer == 32'd0) && (ll_state == LL_IDLE)) begin
                            sof_timer <= 32'd0;
                            hl_done   <= 1'b1;
                            hl_state  <= HL_IDLE;
                        end else if (hl_timer != 32'd0) begin
                            hl_timer <= hl_timer - 32'd1;
                        end
                    end

                    HL_AUTO_SOF: begin
                        if (ll_op_done) begin
                            hl_state <= HL_IDLE;
                        end
                    end

                    default: hl_state <= HL_IDLE;
                endcase
            end
        end
    end

endmodule

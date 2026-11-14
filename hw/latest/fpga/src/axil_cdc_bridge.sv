// SPDX-License-Identifier: Apache-2.0
//
// Minimal single-outstanding AXI4-Lite clock-domain-crossing bridge.
//
// The subordinate side (s_*) lives in `s_clk` (Versal PS / core_clk) and the
// manager side (m_*) lives in `m_clk` (e.g. the 60 MHz ULPI PHY clock that
// `caliptra_fpga_ulpi_host` runs on). One transaction (read or write) is in
// flight at a time; the request and response are carried across the domains
// with toggle-synchronizer handshakes. All address / data payload registers
// are quasi-static: they are written strictly before the request toggle
// flips and are not modified again until the response toggle returns, so a
// `set_clock_groups -asynchronous` (or `set_false_path`) between the two
// clocks is sufficient and no payload synchronizer is required.
//
// Both resets are asynchronous-assert; the wrapper is expected to provide an
// `m_rst_n` that is already synchronized to `m_clk`.

`default_nettype wire

module axil_cdc_bridge #(
    parameter int unsigned ADDR_WIDTH = 12
) (
    // ---------------- Subordinate side (s_clk) ----------------
    input  logic                  s_clk,
    input  logic                  s_rst_n,
    input  logic                  s_axil_awvalid,
    output logic                  s_axil_awready,
    input  logic [ADDR_WIDTH-1:0] s_axil_awaddr,
    input  logic                  s_axil_wvalid,
    output logic                  s_axil_wready,
    input  logic [31:0]           s_axil_wdata,
    input  logic [3:0]            s_axil_wstrb,
    output logic                  s_axil_bvalid,
    input  logic                  s_axil_bready,
    output logic [1:0]            s_axil_bresp,
    input  logic                  s_axil_arvalid,
    output logic                  s_axil_arready,
    input  logic [ADDR_WIDTH-1:0] s_axil_araddr,
    output logic                  s_axil_rvalid,
    input  logic                  s_axil_rready,
    output logic [31:0]           s_axil_rdata,
    output logic [1:0]            s_axil_rresp,

    // ---------------- Manager side (m_clk) --------------------
    input  logic                  m_clk,
    input  logic                  m_rst_n,
    output logic                  m_axil_awvalid,
    input  logic                  m_axil_awready,
    output logic [ADDR_WIDTH-1:0] m_axil_awaddr,
    output logic                  m_axil_wvalid,
    input  logic                  m_axil_wready,
    output logic [31:0]           m_axil_wdata,
    output logic [3:0]            m_axil_wstrb,
    input  logic                  m_axil_bvalid,
    output logic                  m_axil_bready,
    input  logic [1:0]            m_axil_bresp,
    output logic                  m_axil_arvalid,
    input  logic                  m_axil_arready,
    output logic [ADDR_WIDTH-1:0] m_axil_araddr,
    input  logic                  m_axil_rvalid,
    output logic                  m_axil_rready,
    input  logic [31:0]           m_axil_rdata,
    input  logic [1:0]            m_axil_rresp
);

    // =========================================================================
    // s_clk domain: capture one request, raise req toggle, wait for ack toggle
    // =========================================================================
    logic                  s_busy;        // request captured, response not yet delivered
    logic                  s_aw_got, s_w_got;
    logic [ADDR_WIDTH-1:0] s_awaddr_q;
    logic [31:0]           s_wdata_q;
    logic [3:0]            s_wstrb_q;
    logic                  s_is_write;    // quasi-static payload
    logic [ADDR_WIDTH-1:0] s_addr_q;      // quasi-static payload
    logic                  s_req_toggle;

    (* ASYNC_REG = "TRUE" *) logic [1:0] s_ack_sync;
    logic                  s_ack_seen;
    wire                   s_ack_edge = s_ack_sync[1] ^ s_ack_seen;

    // Response payload captured in m_clk, quasi-static when s_ack_edge fires.
    logic [31:0]           m_rdata_q;
    logic [1:0]            m_resp_q;
    logic                  m_ack_toggle;

    assign s_axil_awready = !s_busy && !s_aw_got && !s_axil_bvalid && !s_axil_rvalid;
    assign s_axil_wready  = !s_busy && !s_w_got  && !s_axil_bvalid && !s_axil_rvalid;
    // Reads are only accepted when no write half has been captured, so a
    // partially-captured write can never be overtaken by a read.
    assign s_axil_arready = !s_busy && !s_aw_got && !s_w_got && !s_axil_bvalid && !s_axil_rvalid;

    always_ff @(posedge s_clk or negedge s_rst_n) begin
        if (!s_rst_n) begin
            s_busy        <= 1'b0;
            s_aw_got      <= 1'b0;
            s_w_got       <= 1'b0;
            s_awaddr_q    <= '0;
            s_wdata_q     <= '0;
            s_wstrb_q     <= '0;
            s_is_write    <= 1'b0;
            s_addr_q      <= '0;
            s_req_toggle  <= 1'b0;
            s_ack_sync    <= 2'b00;
            s_ack_seen    <= 1'b0;
            s_axil_bvalid <= 1'b0;
            s_axil_bresp  <= 2'b00;
            s_axil_rvalid <= 1'b0;
            s_axil_rdata  <= 32'h0;
            s_axil_rresp  <= 2'b00;
        end else begin
            s_ack_sync <= {s_ack_sync[0], m_ack_toggle};

            // Retire responses
            if (s_axil_bvalid && s_axil_bready) s_axil_bvalid <= 1'b0;
            if (s_axil_rvalid && s_axil_rready) s_axil_rvalid <= 1'b0;

            if (!s_busy) begin
                // ---- Write capture (AW / W may arrive in either order) ----
                if (s_axil_awvalid && s_axil_awready) begin
                    s_aw_got   <= 1'b1;
                    s_awaddr_q <= s_axil_awaddr;
                end
                if (s_axil_wvalid && s_axil_wready) begin
                    s_w_got   <= 1'b1;
                    s_wdata_q <= s_axil_wdata;
                    s_wstrb_q <= s_axil_wstrb;
                end
                begin : launch
                    automatic logic have_aw = s_aw_got || (s_axil_awvalid && s_axil_awready);
                    automatic logic have_w  = s_w_got  || (s_axil_wvalid  && s_axil_wready);
                    if (have_aw && have_w) begin
                        s_aw_got     <= 1'b0;
                        s_w_got      <= 1'b0;
                        s_is_write   <= 1'b1;
                        s_addr_q     <= s_aw_got ? s_awaddr_q : s_axil_awaddr;
                        if (!s_w_got) begin
                            s_wdata_q <= s_axil_wdata;
                            s_wstrb_q <= s_axil_wstrb;
                        end
                        s_busy       <= 1'b1;
                        s_req_toggle <= ~s_req_toggle;
                    end else if (s_axil_arvalid && s_axil_arready) begin
                        // ---- Read capture ----
                        s_is_write   <= 1'b0;
                        s_addr_q     <= s_axil_araddr;
                        s_busy       <= 1'b1;
                        s_req_toggle <= ~s_req_toggle;
                    end
                end
            end else if (s_ack_edge) begin
                // Response has crossed back: payload is stable in m_rdata_q/m_resp_q.
                s_ack_seen <= s_ack_sync[1];
                s_busy     <= 1'b0;
                if (s_is_write) begin
                    s_axil_bvalid <= 1'b1;
                    s_axil_bresp  <= m_resp_q;
                end else begin
                    s_axil_rvalid <= 1'b1;
                    s_axil_rdata  <= m_rdata_q;
                    s_axil_rresp  <= m_resp_q;
                end
            end
        end
    end

    // =========================================================================
    // m_clk domain: detect req toggle, run one AXI4-Lite transaction, ack
    // =========================================================================
    (* ASYNC_REG = "TRUE" *) logic [1:0] m_req_sync;
    logic m_req_seen;
    wire  m_req_edge = m_req_sync[1] ^ m_req_seen;

    typedef enum logic [1:0] {
        M_IDLE   = 2'd0,
        M_WRITE  = 2'd1,   // drive AW + W until both accepted, then wait B
        M_READ   = 2'd2    // drive AR until accepted, then wait R
    } m_state_t;

    m_state_t m_state;
    logic     m_aw_done, m_w_done;

    assign m_axil_awaddr = s_addr_q;
    assign m_axil_araddr = s_addr_q;
    assign m_axil_wdata  = s_wdata_q;
    assign m_axil_wstrb  = s_wstrb_q;
    assign m_axil_bready = (m_state == M_WRITE);
    assign m_axil_rready = (m_state == M_READ);

    always_ff @(posedge m_clk or negedge m_rst_n) begin
        if (!m_rst_n) begin
            m_req_sync     <= 2'b00;
            m_req_seen     <= 1'b0;
            m_ack_toggle   <= 1'b0;
            m_state        <= M_IDLE;
            m_aw_done      <= 1'b0;
            m_w_done       <= 1'b0;
            m_axil_awvalid <= 1'b0;
            m_axil_wvalid  <= 1'b0;
            m_axil_arvalid <= 1'b0;
            m_rdata_q      <= 32'h0;
            m_resp_q       <= 2'b00;
        end else begin
            m_req_sync <= {m_req_sync[0], s_req_toggle};

            case (m_state)
                M_IDLE: begin
                    if (m_req_edge) begin
                        m_req_seen <= m_req_sync[1];
                        m_aw_done  <= 1'b0;
                        m_w_done   <= 1'b0;
                        if (s_is_write) begin
                            m_axil_awvalid <= 1'b1;
                            m_axil_wvalid  <= 1'b1;
                            m_state        <= M_WRITE;
                        end else begin
                            m_axil_arvalid <= 1'b1;
                            m_state        <= M_READ;
                        end
                    end
                end

                M_WRITE: begin
                    if (m_axil_awvalid && m_axil_awready) begin
                        m_axil_awvalid <= 1'b0;
                        m_aw_done      <= 1'b1;
                    end
                    if (m_axil_wvalid && m_axil_wready) begin
                        m_axil_wvalid <= 1'b0;
                        m_w_done      <= 1'b1;
                    end
                    if (m_axil_bvalid && m_axil_bready) begin
                        m_resp_q     <= m_axil_bresp;
                        m_ack_toggle <= ~m_ack_toggle;
                        m_state      <= M_IDLE;
                    end
                end

                M_READ: begin
                    if (m_axil_arvalid && m_axil_arready) begin
                        m_axil_arvalid <= 1'b0;
                    end
                    if (m_axil_rvalid && m_axil_rready) begin
                        m_rdata_q    <= m_axil_rdata;
                        m_resp_q     <= m_axil_rresp;
                        m_ack_toggle <= ~m_ack_toggle;
                        m_state      <= M_IDLE;
                    end
                end

                default: m_state <= M_IDLE;
            endcase
        end
    end

endmodule

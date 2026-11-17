// SPDX-License-Identifier: Apache-2.0

module usb_bram_64x512 #(
    parameter int ADDR_WIDTH = 9
) (
    input  logic                  usb_clk,
    input  logic                  usb_cs,
    input  logic [ADDR_WIDTH-1:0] usb_addr,
    input  logic                  usb_we_n,
    input  logic [63:0]           usb_bsel,
    input  logic [63:0]           usb_wdata,
    output logic [63:0]           usb_rdata
);

    localparam int DEPTH = 1 << ADDR_WIDTH;

    for (genvar lane = 0; lane < 8; lane++) begin : g_usb_bram_lane

        (* ram_style = "block" *)
        logic [7:0] ram [0:DEPTH-1];

        logic [7:0] rdata_q;

        wire [7:0] lane_bsel;
        wire       lane_we;

        assign lane_bsel = usb_bsel[lane*8 +: 8];

        // mem_web_out is active-low.
        // mem_bsel enables a complete byte lane with 8'hFF.
        assign lane_we =
            usb_cs &&
            !usb_we_n &&
            (lane_bsel == 8'hFF);

        always @(posedge usb_clk) begin
            if (usb_cs) begin
                rdata_q <= ram[usb_addr];

                if (lane_we) begin
                    ram[usb_addr] <= usb_wdata[lane*8 +: 8];
                end
            end
        end

        assign usb_rdata[lane*8 +: 8] = rdata_q;

    end

endmodule

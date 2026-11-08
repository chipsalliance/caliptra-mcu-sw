module htg940_disabled_axi (
    input logic clk,
    input logic reset_n,
    axi_if.w_sub bus_w,
    axi_if.r_sub bus_r
);
    logic write_active, read_active;
    logic [7:0] write_remaining, read_remaining;
    logic [$bits(bus_w.awid)-1:0] write_id;
    logic [$bits(bus_r.arid)-1:0] read_id;
    logic write_response;

    assign bus_w.awready = !write_active && !write_response;
    assign bus_w.wready = write_active;
    assign bus_w.bvalid = write_response;
    assign bus_w.bid = write_id;
    assign bus_w.bresp = 2'b11;
    assign bus_w.buser = '0;
    assign bus_r.arready = !read_active;
    assign bus_r.rvalid = read_active;
    assign bus_r.rid = read_id;
    assign bus_r.rdata = '0;
    assign bus_r.rresp = 2'b11;
    assign bus_r.ruser = '0;
    assign bus_r.rlast = read_remaining == 0;

    always_ff @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            write_active <= 0;
            read_active <= 0;
            write_response <= 0;
            write_remaining <= 0;
            read_remaining <= 0;
            write_id <= 0;
            read_id <= 0;
        end else begin
            if (bus_w.awvalid && bus_w.awready) begin
                write_active <= 1;
                write_remaining <= bus_w.awlen;
                write_id <= bus_w.awid;
            end
            if (bus_w.wvalid && bus_w.wready) begin
                if (write_remaining == 0) begin
                    write_active <= 0;
                    write_response <= 1;
                end else write_remaining <= write_remaining - 1'b1;
            end
            if (bus_w.bvalid && bus_w.bready) write_response <= 0;
            if (bus_r.arvalid && bus_r.arready) begin
                read_active <= 1;
                read_remaining <= bus_r.arlen;
                read_id <= bus_r.arid;
            end
            if (bus_r.rvalid && bus_r.rready) begin
                if (read_remaining == 0) read_active <= 0;
                else read_remaining <= read_remaining - 1'b1;
            end
        end
    end
endmodule

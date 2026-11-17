`timescale 1ns/1ps
// DEVELOPMENT configuration. Local xorshift data is NOT physical/secure entropy.
// All logic stays alive while subsystem_run=0. Host never falls back to local.
module htg940_entropy_control #(
    parameter integer FIFO_WORDS = 1024,
    parameter integer PTR_W = $clog2(FIFO_WORDS)
)(
    input wire clk, reset_n,
    input wire cmd_valid,
    input wire [7:0] cmd,
    input wire [31:0] cmd_data,
    output reg reply_valid,
    output reg [7:0] reply_code,
    output reg [31:0] reply_data,
    input wire entropy_request,
    input wire subsystem_ready,
    output reg [3:0] entropy_data,
    output reg entropy_valid,
    output reg subsystem_run,
    output reg host_mode
);
    (* ram_style="block" *) reg [31:0] fifo [0:FIFO_WORDS-1];
    reg [PTR_W-1:0] wr_ptr, rd_ptr;
    reg [PTR_W:0] count;
    reg [31:0] host_word, rng;
    reg [3:0] nibbles_left;
    reg starved;
    wire hold_cmd = cmd_valid && cmd==8'h02 && cmd_data<=1;
    wire push = cmd_valid && cmd==8'h03 && host_mode && count<FIFO_WORDS;
    // Read memory synchronously. A word is prefetched even while held in reset.
    wire pop = host_mode && nibbles_left==0 && count!=0 && !hold_cmd;
    wire take = subsystem_run && subsystem_ready && entropy_request;
    wire [31:0] rng_a = rng ^ (rng << 13);
    wire [31:0] rng_b = rng_a ^ (rng_a >> 17);
    wire [31:0] rng_next = rng_b ^ (rng_b << 5);
    wire [15:0] free_words = 16'(FIFO_WORDS) - 16'(count);
    wire [31:0] status_word = {free_words, 11'b0, starved,
        (count==FIFO_WORDS), (count==0 && nibbles_left==0), subsystem_run, host_mode};

    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            wr_ptr<=0; rd_ptr<=0; count<=0; host_word<=0; nibbles_left<=0;
            rng<=32'h6d2b79f5; host_mode<=0; subsystem_run<=1;
            starved<=0; entropy_data<=0; entropy_valid<=0;
            reply_valid<=0; reply_code<=0; reply_data<=0;
        end else begin
            reply_valid<=0;
            entropy_valid<=0;
            if (hold_cmd) begin
                subsystem_run<=0; host_mode<=cmd_data[0];
                wr_ptr<=0; rd_ptr<=0; count<=0; nibbles_left<=0;
                host_word<=0; starved<=0; rng<=32'h6d2b79f5;
            end else begin
                case ({push,pop})
                    2'b10: count<=count+1'b1;
                    2'b01: count<=count-1'b1;
                    default: ;
                endcase
                if (push) begin fifo[wr_ptr]<=cmd_data; wr_ptr<=wr_ptr+1'b1; end
                if (pop) begin
                    host_word<=fifo[rd_ptr]; rd_ptr<=rd_ptr+1'b1; nibbles_left<=8;
                end
                if (take) begin
                    if (!host_mode) begin
                        rng<=rng_next; entropy_data<=rng_next[3:0]; entropy_valid<=1;
                    end else if (nibbles_left!=0) begin
                        entropy_data<=host_word[3:0]; entropy_valid<=1;
                        host_word<=host_word>>4; nibbles_left<=nibbles_left-1'b1;
                    end else if (count==0) starved<=1;
                end
            end
            if (cmd_valid) begin
                reply_valid<=1; reply_code<=0; reply_data<=status_word;
                case (cmd)
                    8'h01: ; // STATUS
                    8'h02: if (cmd_data>1) reply_code<=1; // HOLD+SELECT+CLEAR
                    8'h03: begin
                        if (!host_mode) reply_code<=4;
                        else if (count==FIFO_WORDS) reply_code<=2;
                    end
                    8'h04: begin // RUN; mode cannot change here.
                        if (host_mode && count==0 && nibbles_left==0) reply_code<=3;
                        else subsystem_run<=1;
                    end
                    default: reply_code<=1;
                endcase
            end
        end
    end
endmodule

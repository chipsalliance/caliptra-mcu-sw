`timescale 1ns/1ps
// Development log transport; all inputs are synchronous to clk.
module htg940_log_fifo #(parameter integer DEPTH=4096, AW=$clog2(DEPTH)) (
 input wire clk, reset_n, push, pop,
 input wire [7:0] in_byte,
 output reg [7:0] out_byte,
 output reg out_valid,
 output wire empty,
 output reg [31:0] dropped
);
 (* ram_style="block" *) reg [7:0] mem [0:DEPTH-1];
 reg [AW-1:0] wr_ptr, rd_ptr;
 reg [AW:0] count;
 wire take=pop && count!=0;
 wire put=push && (count<DEPTH || take);
 assign empty=(count==0);
 // No RAM reset; only pointers/count reset. Synchronous read for BRAM inference.
 always @(posedge clk) begin
   if(put) mem[wr_ptr]<=in_byte;
   if(take) out_byte<=mem[rd_ptr];
 end
 always @(posedge clk or negedge reset_n) begin
   if(!reset_n) begin
     wr_ptr<=0;rd_ptr<=0;count<=0;out_valid<=0;dropped<=0;
   end else begin
     out_valid<=take;
     if(put) wr_ptr <= wr_ptr==DEPTH-1 ? 0 : wr_ptr+1'b1;
     if(take) rd_ptr <= rd_ptr==DEPTH-1 ? 0 : rd_ptr+1'b1;
     case({put,take})
       2'b10:count<=count+1'b1;
       2'b01:count<=count-1'b1;
       default:;
     endcase
     if(push && !put && dropped!=32'hffffffff) dropped<=dropped+1'b1;
   end
 end
endmodule

module htg940_log_bridge #(parameter integer DEPTH=4096)(
 input wire clk, reset_n,
 input wire mcu_valid, core_valid,
 input wire [7:0] mcu_byte, core_byte,
 input wire cmd_valid,
 input wire [7:0] cmd,
 input wire [31:0] cmd_data,
 output wire entropy_cmd_valid,
 input wire entropy_reply_valid,
 input wire [7:0] entropy_reply_code,
 input wire [31:0] entropy_reply_data,
 output wire reply_valid,
 output wire [7:0] reply_code,
 output wire [31:0] reply_data
);
 // 10/11: pop MCU/Core (data[31:24]=0..3 byte count, low byte first).
 // 12/13: cumulative MCU/Core drop counts since board reset.
 wire is_log=(cmd>=8'h10 && cmd<=8'h13);
 assign entropy_cmd_valid=cmd_valid && !is_log;
 reg log_reply;
 reg [7:0] log_code;
 reg [31:0] log_data;
 assign reply_valid=log_reply || entropy_reply_valid;
 assign reply_code=log_reply ? log_code : entropy_reply_code;
 assign reply_data=log_reply ? log_data : entropy_reply_data;
 reg [1:0] state;
 reg channel;
 reg [1:0] n;
 reg [23:0] bytes_acc;
 wire [1:0] empty, valid;
 wire [7:0] mbyte,cbyte;
 wire [31:0] mdrop,cdrop;
 wire pop=(state==1 && !empty[channel]);
 htg940_log_fifo #(.DEPTH(DEPTH)) m (
  .clk(clk),.reset_n(reset_n),.push(mcu_valid),.in_byte(mcu_byte),
  .pop(pop && !channel),.out_byte(mbyte),.out_valid(valid[0]),.empty(empty[0]),.dropped(mdrop));
 htg940_log_fifo #(.DEPTH(DEPTH)) c (
  .clk(clk),.reset_n(reset_n),.push(core_valid),.in_byte(core_byte),
  .pop(pop && channel),.out_byte(cbyte),.out_valid(valid[1]),.empty(empty[1]),.dropped(cdrop));
 always @(posedge clk or negedge reset_n) begin
  if(!reset_n) begin state<=0;channel<=0;n<=0;bytes_acc<=0;log_reply<=0;log_code<=0;log_data<=0;end
  else begin
   log_reply<=0;
   case(state)
    0:if(cmd_valid && is_log) begin
      log_code<=0;
      if(cmd_data!=0) begin log_code<=1;log_data<=0;log_reply<=1;end
      else if(cmd[1]) begin log_data<=cmd[0] ? cdrop : mdrop;log_reply<=1;end
      else begin channel<=cmd[0];n<=0;bytes_acc<=0;state<=1;end
    end
    1:if(empty[channel]) begin log_data<={6'b0,n,bytes_acc};log_reply<=1;state<=0;end
      else state<=2;
    2:if(valid[channel]) begin
      bytes_acc[n*8 +: 8]<=channel ? cbyte : mbyte;
      n<=n+1'b1;
      if(n==2) state<=3;else state<=1;
    end
    3:begin log_data<={6'b0,n,bytes_acc};log_reply<=1;state<=0;end
   endcase
  end
 end
endmodule

`timescale 1ns/1ps
// 8N1 request/response UART, one outstanding request, no flow control.
// Frame: A5 OP CODE D0 D1 D2 D3 XOR 5A; request CODE=0.
// XOR covers bytes 0..6. Reply OP=request OP|80, CODE=controller result.
// This is a debug transport, not an authenticated production protocol.
module htg940_entropy_uart #(
    parameter integer CLK_HZ=40000000, BAUD=115200,
    parameter integer DIV=(CLK_HZ+BAUD/2)/BAUD
)(
    input wire clk, reset_n, uart_rx,
    output wire uart_tx,
    output reg cmd_valid,
    output reg [7:0] cmd,
    output reg [31:0] cmd_data,
    input wire reply_valid,
    input wire [7:0] reply_code,
    input wire [31:0] reply_data
);
    (* ASYNC_REG="TRUE" *) reg [1:0] rx_sync;
    reg [1:0] rx_state;
    integer rx_timer;
    reg [2:0] rx_bit;
    reg [7:0] rx_shift, rx_byte;
    reg rx_valid;
    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            rx_sync<=2'b11;rx_state<=0;rx_timer<=0;rx_bit<=0;
            rx_shift<=0;rx_byte<=0;rx_valid<=0;
        end else begin
            rx_sync<={rx_sync[0],uart_rx};rx_valid<=0;
            case (rx_state)
                0: if (!rx_sync[1]) begin rx_state<=1;rx_timer<=DIV/2-1;end
                1: if(rx_timer!=0) rx_timer<=rx_timer-1;
                   else if(rx_sync[1]) rx_state<=0;
                   else begin rx_state<=2;rx_timer<=DIV-1;rx_bit<=0;end
                2: if(rx_timer!=0) rx_timer<=rx_timer-1;
                   else begin
                       rx_shift[rx_bit]<=rx_sync[1];rx_timer<=DIV-1;
                       if(rx_bit==7) rx_state<=3;else rx_bit<=rx_bit+1'b1;
                   end
                3: if(rx_timer!=0) rx_timer<=rx_timer-1;
                   else begin
                       rx_state<=0;
                       if(rx_sync[1]) begin rx_valid<=1;rx_byte<=rx_shift;end
                   end
            endcase
        end
    end
    reg [3:0] frame_index;
    reg [7:0] checksum, frame_op, frame_code, frame_check;
    reg [31:0] frame_data;
    integer frame_timer;
    reg busy;
    reg [71:0] tx_frame;
    reg [3:0] tx_byte_index;
    reg [3:0] tx_bit_index;
    integer tx_timer;
    reg tx_active, tx_line;
    assign uart_tx=tx_line;
    always @(posedge clk or negedge reset_n) begin
        if(!reset_n) begin
            frame_index<=0;checksum<=0;frame_op<=0;frame_code<=0;
            frame_check<=0;frame_data<=0;frame_timer<=0;
            cmd_valid<=0;cmd<=0;cmd_data<=0;busy<=0;
            tx_frame<=0;tx_byte_index<=0;tx_bit_index<=0;
            tx_timer<=0;tx_active<=0;tx_line<=1;
        end else begin
            cmd_valid<=0;
            if(frame_index!=0) begin
                if(frame_timer==DIV*30) begin frame_index<=0;frame_timer<=0;end
                else frame_timer<=frame_timer+1;
            end
            if(rx_valid && !busy) begin
                frame_timer<=0;
                if(frame_index==0) begin
                    if(rx_byte==8'ha5) begin frame_index<=1;checksum<=8'ha5;end
                end else begin
                    frame_index<=frame_index+1'b1;
                    if(frame_index<=6) checksum<=checksum^rx_byte;
                    case(frame_index)
                        1:frame_op<=rx_byte;
                        2:frame_code<=rx_byte;
                        3:frame_data[7:0]<=rx_byte;
                        4:frame_data[15:8]<=rx_byte;
                        5:frame_data[23:16]<=rx_byte;
                        6:frame_data[31:24]<=rx_byte;
                        7:frame_check<=rx_byte;
                        8:begin
                            frame_index<=0;
                            if(rx_byte==8'h5a && frame_check==checksum && frame_code==0) begin
                                cmd<=frame_op;cmd_data<=frame_data;cmd_valid<=1;busy<=1;
                            end
                        end
                        default:frame_index<=0;
                    endcase
                end
            end
            if(reply_valid && busy && !tx_active) begin
                tx_frame<={8'h5a,
                    (8'ha5 ^ (cmd|8'h80) ^ reply_code ^ reply_data[7:0] ^
                     reply_data[15:8] ^ reply_data[23:16] ^ reply_data[31:24]),
                    reply_data,reply_code,(cmd|8'h80),8'ha5};
                tx_active<=1;tx_byte_index<=0;tx_bit_index<=0;
                tx_timer<=DIV-1;tx_line<=0;
            end else if(tx_active) begin
                if(tx_timer!=0) tx_timer<=tx_timer-1;
                else begin
                    tx_timer<=DIV-1;
                    if(tx_bit_index<8) begin
                        tx_line<=tx_frame[tx_byte_index*8+tx_bit_index];
                        tx_bit_index<=tx_bit_index+1'b1;
                    end else if(tx_bit_index==8) begin tx_line<=1;tx_bit_index<=9;end
                    else if(tx_byte_index==8) begin tx_active<=0;busy<=0;tx_line<=1;end
                    else begin tx_byte_index<=tx_byte_index+1'b1;tx_bit_index<=0;tx_line<=0;end
                end
            end
        end
    end
endmodule

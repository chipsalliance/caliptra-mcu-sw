// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Caliptra ICG that disables clock gating
module fpga_fake_icg (
    input logic clk,
    input logic en,
    output clk_cg
);
    // No clock gating
    assign clk_cg = clk;

endmodule

// Caliptra ICG that uses gated clock conversion for clock gating
module fpga_real_icg (
    (* gated_clock = "yes" *) input logic clk,
    input logic en,
    output clk_cg
);
    logic en_lat;

    always @(negedge clk) begin
        en_lat <= en;
    end

    // Gate clk
    assign clk_cg = clk && en_lat;

endmodule

// VEER ICG that uses gated clock conversion for clock gating
module fpga_rv_clkhdr
  (
   (* gated_clock = "yes" *) input logic CK,
   input logic SE, EN,
   output Q
   );
   logic  enable;
   assign enable = EN | SE;
   logic  en_ff;

   always @(negedge CK) begin
      en_ff <= enable;
   end

   assign Q = CK & en_ff;

endmodule

(* DONT_TOUCH = "yes" *)
module caliptra_prim_xilinx_buf #(
  parameter int Width = 1
) (
  input        [Width-1:0] in_i,
  output logic [Width-1:0] out_o
);

  logic [Width-1:0] inv;
  assign inv = ~in_i;
  assign out_o = ~inv;

endmodule

(* DONT_TOUCH = "yes" *)
module caliptra_prim_xilinx_flop #(
  parameter int               Width      = 1,
  parameter logic [Width-1:0] ResetValue = 0
) (
  input                    clk_i,
  input                    rst_ni,
  input        [Width-1:0] d_i,
  output logic [Width-1:0] q_o
);

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      q_o <= ResetValue;
    end else begin
      q_o <= d_i;
    end
  end

endmodule

(* DONT_TOUCH = "yes" *)
module caliptra_prim_xilinx_flop_en #(
  parameter int               Width      = 1,
  parameter bit               EnSecBuf   = 0,
  parameter logic [Width-1:0] ResetValue = 0
) (
  input                    clk_i,
  input                    rst_ni,
  input                    en_i,
  input        [Width-1:0] d_i,
  output logic [Width-1:0] q_o
);

  logic en;
  if (EnSecBuf) begin : gen_en_sec_buf
    caliptra_prim_sec_anchor_buf #(
      .Width(1)
    ) u_en_buf (
      .in_i(en_i),
      .out_o(en)
    );
  end else begin : gen_en_no_sec_buf
    assign en = en_i;
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      q_o <= ResetValue;
    end else if (en) begin
      q_o <= d_i;
    end
  end

endmodule
// Licensed under the Apache-2.0 license
//
// Stub replacement for Adams Bridge (abr_top + abr_mem_top + abr_mem_if).
// Used when STUB_ADAMS_BRIDGE is defined to skip compiling the full
// adams-bridge submodule (~354 source files) for faster FPGA builds.
// The MLDSA accelerator is non-functional; AHB reads return 0 / OKAY.
//
// Ports that use KV/PCR package types are flattened to plain logic so this
// file compiles independently of package elaboration order.
//   kv_read_t       = 9b  (KV_ENTRY_ADDR_W=5 + KV_ENTRY_SIZE_W=4)
//   kv_write_t      = 51b (1+5+4+32+9)
//   kv_wr_resp_t    = 1b
//   kv_rd_resp_t    = 34b (1+1+32)
//   pcr_signing_t   = 1152b ((16+12+8)*32)

`ifdef STUB_ADAMS_BRIDGE

// Minimal copies of the package parameters needed to size the interface.
// Keep in sync with abr_params_pkg.sv if the real widths ever change.
package abr_stub_params_pkg;
  localparam ABR_MEM_W1_ADDR_W    = 9;   // $clog2(512)
  localparam ABR_MEM_W1_DATA_W    = 4;
  localparam ABR_MEM_INST0_ADDR_W = 10;  // $clog2(832)
  localparam ABR_MEM_INST0_DATA_W = 96;
  localparam ABR_MEM_INST1_ADDR_W = 10;  // $clog2(576)
  localparam ABR_MEM_INST1_DATA_W = 96;
  localparam ABR_MEM_INST2_ADDR_W = 11;  // $clog2(1472)
  localparam ABR_MEM_INST2_DATA_W = 96;
  localparam ABR_MEM_INST3_ADDR_W = 6;   // $clog2(64)
  localparam ABR_MEM_INST3_DATA_W = 384;
  localparam SK_MEM_BANK_ADDR_W   = 12;
  localparam SK_MEM_BANK_DATA_W   = 32;
  localparam SIG_Z_MEM_ADDR_W     = 10;
  localparam SIG_Z_MEM_DATA_W     = 64;
  localparam SIG_Z_MEM_WSTROBE_W  = 8;
  localparam PK_MEM_ADDR_W        = 10;
  localparam PK_MEM_DATA_W        = 64;
  localparam PK_MEM_WSTROBE_W     = 8;
endpackage

interface abr_mem_if;
  import abr_stub_params_pkg::*;

  logic                         w1_mem_we_i;
  logic [ABR_MEM_W1_ADDR_W-1:0]    w1_mem_waddr_i;
  logic [ABR_MEM_W1_DATA_W-1:0]    w1_mem_wdata_i;
  logic                         w1_mem_re_i;
  logic [ABR_MEM_W1_ADDR_W-1:0]    w1_mem_raddr_i;
  logic [ABR_MEM_W1_DATA_W-1:0]    w1_mem_rdata_o;

  logic                             mem_inst0_bank0_we_i;
  logic [ABR_MEM_INST0_ADDR_W-1:0] mem_inst0_bank0_waddr_i;
  logic [ABR_MEM_INST0_DATA_W-1:0] mem_inst0_bank0_wdata_i;
  logic                             mem_inst0_bank0_re_i;
  logic [ABR_MEM_INST0_ADDR_W-1:0] mem_inst0_bank0_raddr_i;
  logic [ABR_MEM_INST0_DATA_W-1:0] mem_inst0_bank0_rdata_o;

  logic                             mem_inst0_bank1_we_i;
  logic [ABR_MEM_INST0_ADDR_W-1:0] mem_inst0_bank1_waddr_i;
  logic [ABR_MEM_INST0_DATA_W-1:0] mem_inst0_bank1_wdata_i;
  logic                             mem_inst0_bank1_re_i;
  logic [ABR_MEM_INST0_ADDR_W-1:0] mem_inst0_bank1_raddr_i;
  logic [ABR_MEM_INST0_DATA_W-1:0] mem_inst0_bank1_rdata_o;

  logic                             mem_inst1_we_i;
  logic [ABR_MEM_INST1_ADDR_W-1:0] mem_inst1_waddr_i;
  logic [ABR_MEM_INST1_DATA_W-1:0] mem_inst1_wdata_i;
  logic                             mem_inst1_re_i;
  logic [ABR_MEM_INST1_ADDR_W-1:0] mem_inst1_raddr_i;
  logic [ABR_MEM_INST1_DATA_W-1:0] mem_inst1_rdata_o;

  logic                             mem_inst2_we_i;
  logic [ABR_MEM_INST2_ADDR_W-1:0] mem_inst2_waddr_i;
  logic [ABR_MEM_INST2_DATA_W-1:0] mem_inst2_wdata_i;
  logic                             mem_inst2_re_i;
  logic [ABR_MEM_INST2_ADDR_W-1:0] mem_inst2_raddr_i;
  logic [ABR_MEM_INST2_DATA_W-1:0] mem_inst2_rdata_o;

  logic                             mem_inst3_we_i;
  logic [ABR_MEM_INST3_ADDR_W-1:0] mem_inst3_waddr_i;
  logic [ABR_MEM_INST3_DATA_W-1:0] mem_inst3_wdata_i;
  logic                             mem_inst3_re_i;
  logic [ABR_MEM_INST3_ADDR_W-1:0] mem_inst3_raddr_i;
  logic [ABR_MEM_INST3_DATA_W-1:0] mem_inst3_rdata_o;

  logic                             sk_mem_bank0_we_i;
  logic [SK_MEM_BANK_ADDR_W-1:0]   sk_mem_bank0_waddr_i;
  logic [SK_MEM_BANK_DATA_W-1:0]   sk_mem_bank0_wdata_i;
  logic                             sk_mem_bank0_re_i;
  logic [SK_MEM_BANK_ADDR_W-1:0]   sk_mem_bank0_raddr_i;
  logic [SK_MEM_BANK_DATA_W-1:0]   sk_mem_bank0_rdata_o;

  logic                             sk_mem_bank1_we_i;
  logic [SK_MEM_BANK_ADDR_W-1:0]   sk_mem_bank1_waddr_i;
  logic [SK_MEM_BANK_DATA_W-1:0]   sk_mem_bank1_wdata_i;
  logic                             sk_mem_bank1_re_i;
  logic [SK_MEM_BANK_ADDR_W-1:0]   sk_mem_bank1_raddr_i;
  logic [SK_MEM_BANK_DATA_W-1:0]   sk_mem_bank1_rdata_o;

  logic                             sig_z_mem_we_i;
  logic [SIG_Z_MEM_ADDR_W-1:0]     sig_z_mem_waddr_i;
  logic [SIG_Z_MEM_DATA_W-1:0]     sig_z_mem_wdata_i;
  logic [SIG_Z_MEM_WSTROBE_W-1:0]  sig_z_mem_wstrobe_i;
  logic                             sig_z_mem_re_i;
  logic [SIG_Z_MEM_ADDR_W-1:0]     sig_z_mem_raddr_i;
  logic [SIG_Z_MEM_DATA_W-1:0]     sig_z_mem_rdata_o;

  logic                             pk_mem_we_i;
  logic [PK_MEM_ADDR_W-1:0]        pk_mem_waddr_i;
  logic [PK_MEM_DATA_W-1:0]        pk_mem_wdata_i;
  logic [PK_MEM_WSTROBE_W-1:0]     pk_mem_wstrobe_i;
  logic                             pk_mem_re_i;
  logic [PK_MEM_ADDR_W-1:0]        pk_mem_raddr_i;
  logic [PK_MEM_DATA_W-1:0]        pk_mem_rdata_o;

  modport req (
    output w1_mem_we_i, w1_mem_waddr_i, w1_mem_wdata_i, w1_mem_re_i, w1_mem_raddr_i,
    input  w1_mem_rdata_o,
    output mem_inst0_bank0_we_i, mem_inst0_bank0_waddr_i, mem_inst0_bank0_wdata_i,
           mem_inst0_bank0_re_i, mem_inst0_bank0_raddr_i,
    input  mem_inst0_bank0_rdata_o,
    output mem_inst0_bank1_we_i, mem_inst0_bank1_waddr_i, mem_inst0_bank1_wdata_i,
           mem_inst0_bank1_re_i, mem_inst0_bank1_raddr_i,
    input  mem_inst0_bank1_rdata_o,
    output mem_inst1_we_i, mem_inst1_waddr_i, mem_inst1_wdata_i, mem_inst1_re_i, mem_inst1_raddr_i,
    input  mem_inst1_rdata_o,
    output mem_inst2_we_i, mem_inst2_waddr_i, mem_inst2_wdata_i, mem_inst2_re_i, mem_inst2_raddr_i,
    input  mem_inst2_rdata_o,
    output mem_inst3_we_i, mem_inst3_waddr_i, mem_inst3_wdata_i, mem_inst3_re_i, mem_inst3_raddr_i,
    input  mem_inst3_rdata_o,
    output sk_mem_bank0_we_i, sk_mem_bank0_waddr_i, sk_mem_bank0_wdata_i,
           sk_mem_bank0_re_i, sk_mem_bank0_raddr_i,
    input  sk_mem_bank0_rdata_o,
    output sk_mem_bank1_we_i, sk_mem_bank1_waddr_i, sk_mem_bank1_wdata_i,
           sk_mem_bank1_re_i, sk_mem_bank1_raddr_i,
    input  sk_mem_bank1_rdata_o,
    output sig_z_mem_we_i, sig_z_mem_waddr_i, sig_z_mem_wdata_i, sig_z_mem_wstrobe_i,
           sig_z_mem_re_i, sig_z_mem_raddr_i,
    input  sig_z_mem_rdata_o,
    output pk_mem_we_i, pk_mem_waddr_i, pk_mem_wdata_i, pk_mem_wstrobe_i,
           pk_mem_re_i, pk_mem_raddr_i,
    input  pk_mem_rdata_o
  );

  modport resp (
    input  w1_mem_we_i, w1_mem_waddr_i, w1_mem_wdata_i, w1_mem_re_i, w1_mem_raddr_i,
    output w1_mem_rdata_o,
    input  mem_inst0_bank0_we_i, mem_inst0_bank0_waddr_i, mem_inst0_bank0_wdata_i,
           mem_inst0_bank0_re_i, mem_inst0_bank0_raddr_i,
    output mem_inst0_bank0_rdata_o,
    input  mem_inst0_bank1_we_i, mem_inst0_bank1_waddr_i, mem_inst0_bank1_wdata_i,
           mem_inst0_bank1_re_i, mem_inst0_bank1_raddr_i,
    output mem_inst0_bank1_rdata_o,
    input  mem_inst1_we_i, mem_inst1_waddr_i, mem_inst1_wdata_i, mem_inst1_re_i, mem_inst1_raddr_i,
    output mem_inst1_rdata_o,
    input  mem_inst2_we_i, mem_inst2_waddr_i, mem_inst2_wdata_i, mem_inst2_re_i, mem_inst2_raddr_i,
    output mem_inst2_rdata_o,
    input  mem_inst3_we_i, mem_inst3_waddr_i, mem_inst3_wdata_i, mem_inst3_re_i, mem_inst3_raddr_i,
    output mem_inst3_rdata_o,
    input  sk_mem_bank0_we_i, sk_mem_bank0_waddr_i, sk_mem_bank0_wdata_i,
           sk_mem_bank0_re_i, sk_mem_bank0_raddr_i,
    output sk_mem_bank0_rdata_o,
    input  sk_mem_bank1_we_i, sk_mem_bank1_waddr_i, sk_mem_bank1_wdata_i,
           sk_mem_bank1_re_i, sk_mem_bank1_raddr_i,
    output sk_mem_bank1_rdata_o,
    input  sig_z_mem_we_i, sig_z_mem_waddr_i, sig_z_mem_wdata_i, sig_z_mem_wstrobe_i,
           sig_z_mem_re_i, sig_z_mem_raddr_i,
    output sig_z_mem_rdata_o,
    input  pk_mem_we_i, pk_mem_waddr_i, pk_mem_wdata_i, pk_mem_wstrobe_i,
           pk_mem_re_i, pk_mem_raddr_i,
    output pk_mem_rdata_o
  );

endinterface

module abr_mem_top #(
    parameter SRAM_LATENCY = 1
) (
    input  logic clk_i,
    abr_mem_if.resp abr_memory_export
);
    assign abr_memory_export.w1_mem_rdata_o          = '0;
    assign abr_memory_export.mem_inst0_bank0_rdata_o = '0;
    assign abr_memory_export.mem_inst0_bank1_rdata_o = '0;
    assign abr_memory_export.mem_inst1_rdata_o       = '0;
    assign abr_memory_export.mem_inst2_rdata_o       = '0;
    assign abr_memory_export.mem_inst3_rdata_o       = '0;
    assign abr_memory_export.sk_mem_bank0_rdata_o    = '0;
    assign abr_memory_export.sk_mem_bank1_rdata_o    = '0;
    assign abr_memory_export.sig_z_mem_rdata_o       = '0;
    assign abr_memory_export.pk_mem_rdata_o          = '0;
endmodule

// Flat port widths (no package imports needed):
//   kv_read_t [2:0]   -> 3 * 9  = 27b
//   kv_rd_resp_t [2:0]-> 3 * 34 = 102b
//   kv_write_t        -> 51b
//   kv_wr_resp_t      -> 1b
//   pcr_signing_t     -> 1152b
module abr_top #(
    parameter bit MASKING_EN        = 1,
    parameter     SRAM_LATENCY      = 1,
    parameter     AHB_ADDR_WIDTH    = 32,
    parameter     AHB_DATA_WIDTH    = 64,
    parameter     CLIENT_DATA_WIDTH = 32
) (
    input  logic clk,
    input  logic rst_b,

    output wire NTT_trigger,
    output wire PWM_trigger,
    output wire PWA_trigger,
    output wire INTT_trigger,

    input  logic [AHB_ADDR_WIDTH-1:0] haddr_i,
    input  logic [AHB_DATA_WIDTH-1:0] hwdata_i,
    input  logic                       hsel_i,
    input  logic                       hwrite_i,
    input  logic                       hready_i,
    input  logic [1:0]                 htrans_i,
    input  logic [2:0]                 hsize_i,

    output logic                       hresp_o,
    output logic                       hreadyout_o,
    output logic [AHB_DATA_WIDTH-1:0]  hrdata_o,

    output logic [26:0]   kv_read,       // kv_read_t [2:0]
    input  logic [101:0]  kv_rd_resp,    // kv_rd_resp_t [2:0]
    output logic [50:0]   kv_write,      // kv_write_t
    input  logic          kv_wr_resp,    // kv_wr_resp_t

    input  logic [1151:0] pcr_signing_data, // pcr_signing_t
    input  logic          ocp_lock_in_progress,

    input  logic          debugUnlock_or_scan_mode_switch,

    output logic          busy_o,
    output logic          error_intr,
    output logic          notif_intr,

    abr_mem_if.req        abr_memory_export
);
    assign NTT_trigger   = '0;
    assign PWM_trigger   = '0;
    assign PWA_trigger   = '0;
    assign INTT_trigger  = '0;

    assign hresp_o       = '0;
    assign hreadyout_o   = 1'b1;
    assign hrdata_o      = '0;

    assign kv_read       = '0;
    assign kv_write      = '0;

    assign busy_o        = '0;
    assign error_intr    = '0;
    assign notif_intr    = '0;
endmodule

`endif // STUB_ADAMS_BRIDGE

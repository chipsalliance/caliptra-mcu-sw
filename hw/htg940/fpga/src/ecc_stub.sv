// Licensed under the Apache-2.0 license
//
// Stub replacement for ecc_top (~24 source files, ~57K LUTs at synthesis).
// Used when STUB_ECC is defined to skip compiling the full ECC (P-384)
// accelerator for faster FPGA builds. AHB reads return 0 / OKAY.
//
// Ports that use KV/PCR package types are flattened to plain logic so this
// file compiles independently of package elaboration order.
//   kv_read_t [1:0]   -> 2 * 9  = 18b
//   kv_rd_resp_t [1:0]-> 2 * 34 = 68b
//   kv_write_t        -> 51b
//   kv_wr_resp_t      -> 1b
//   pcr_signing_t     -> 1152b

`ifdef STUB_ECC

module ecc_top #(
    parameter AHB_ADDR_WIDTH    = 32,
    parameter AHB_DATA_WIDTH    = 32,
    parameter CLIENT_DATA_WIDTH = 32
) (
    input  wire                        clk,
    input  wire                        reset_n,
    input  wire                        cptra_pwrgood,

    input  wire  [AHB_ADDR_WIDTH-1:0]  haddr_i,
    input  wire  [AHB_DATA_WIDTH-1:0]  hwdata_i,
    input  wire                        hsel_i,
    input  wire                        hwrite_i,
    input  wire                        hready_i,
    input  wire  [1:0]                 htrans_i,
    input  wire  [2:0]                 hsize_i,

    output logic                       hresp_o,
    output logic                       hreadyout_o,
    output logic [AHB_DATA_WIDTH-1:0]  hrdata_o,

    output logic [17:0]   kv_read,       // kv_read_t [1:0]
    output logic [50:0]   kv_write,      // kv_write_t
    input  logic [67:0]   kv_rd_resp,    // kv_rd_resp_t [1:0]
    input  logic          kv_wr_resp,    // kv_wr_resp_t

    input  logic [1151:0] pcr_signing_data, // pcr_signing_t

    input  logic          ocp_lock_in_progress,
    output logic          busy_o,

    output logic          error_intr,
    output logic          notif_intr,
    input  logic          debugUnlock_or_scan_mode_switch
);
    assign hresp_o      = '0;
    assign hreadyout_o  = 1'b1;
    assign hrdata_o     = '0;
    assign kv_read      = '0;
    assign kv_write     = '0;
    assign busy_o       = '0;
    assign error_intr   = '0;
    assign notif_intr   = '0;
endmodule

`endif // STUB_ECC

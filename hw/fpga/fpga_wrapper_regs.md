<!---
Markdown description for SystemRDL register map.

Don't override. Generated from: caliptra_fpga_realtime_regs
  - rdl_properties.rdl
  - caliptra_fpga_realtime_regs.rdl
-->

## caliptra_fpga_realtime_regs address map

- Absolute Address: 0x0
- Base Offset: 0x0
- Size: 0xA4013200

|  Offset  |        Identifier       |Name|
|----------|-------------------------|----|
|0xA4010000|      interface_regs     |  — |
|0xA4011000|        fifo_regs        |  — |
|0xA4012000| primary_flash_ctrl_regs |  — |
|0xA4013000|secondary_flash_ctrl_regs|  — |

## interface_regs register file

- Absolute Address: 0xA4010000
- Base Offset: 0xA4010000
- Size: 0x284

|Offset|                  Identifier                  |Name|
|------|----------------------------------------------|----|
| 0x000|                  fpga_magic                  |  — |
| 0x004|                 fpga_version                 |  — |
| 0x008|                    control                   |  — |
| 0x00C|                    status                    |  — |
| 0x010|                   arm_user                   |  — |
| 0x014|                 itrng_divisor                |  — |
| 0x018|                  cycle_count                 |  — |
| 0x030|            generic_input_wires[0]            |  — |
| 0x034|            generic_input_wires[1]            |  — |
| 0x038|            generic_output_wires[0]           |  — |
| 0x03C|            generic_output_wires[1]           |  — |
| 0x040|               cptra_obf_key[0]               |  — |
| 0x044|               cptra_obf_key[1]               |  — |
| 0x048|               cptra_obf_key[2]               |  — |
| 0x04C|               cptra_obf_key[3]               |  — |
| 0x050|               cptra_obf_key[4]               |  — |
| 0x054|               cptra_obf_key[5]               |  — |
| 0x058|               cptra_obf_key[6]               |  — |
| 0x05C|               cptra_obf_key[7]               |  — |
| 0x060|             cptra_csr_hmac_key[0]            |  — |
| 0x064|             cptra_csr_hmac_key[1]            |  — |
| 0x068|             cptra_csr_hmac_key[2]            |  — |
| 0x06C|             cptra_csr_hmac_key[3]            |  — |
| 0x070|             cptra_csr_hmac_key[4]            |  — |
| 0x074|             cptra_csr_hmac_key[5]            |  — |
| 0x078|             cptra_csr_hmac_key[6]            |  — |
| 0x07C|             cptra_csr_hmac_key[7]            |  — |
| 0x080|             cptra_csr_hmac_key[8]            |  — |
| 0x084|             cptra_csr_hmac_key[9]            |  — |
| 0x088|            cptra_csr_hmac_key[10]            |  — |
| 0x08C|            cptra_csr_hmac_key[11]            |  — |
| 0x090|            cptra_csr_hmac_key[12]            |  — |
| 0x094|            cptra_csr_hmac_key[13]            |  — |
| 0x098|            cptra_csr_hmac_key[14]            |  — |
| 0x09C|            cptra_csr_hmac_key[15]            |  — |
| 0x0A0|             cptra_obf_uds_seed[0]            |  — |
| 0x0A4|             cptra_obf_uds_seed[1]            |  — |
| 0x0A8|             cptra_obf_uds_seed[2]            |  — |
| 0x0AC|             cptra_obf_uds_seed[3]            |  — |
| 0x0B0|             cptra_obf_uds_seed[4]            |  — |
| 0x0B4|             cptra_obf_uds_seed[5]            |  — |
| 0x0B8|             cptra_obf_uds_seed[6]            |  — |
| 0x0BC|             cptra_obf_uds_seed[7]            |  — |
| 0x0C0|             cptra_obf_uds_seed[8]            |  — |
| 0x0C4|             cptra_obf_uds_seed[9]            |  — |
| 0x0C8|            cptra_obf_uds_seed[10]            |  — |
| 0x0CC|            cptra_obf_uds_seed[11]            |  — |
| 0x0D0|            cptra_obf_uds_seed[12]            |  — |
| 0x0D4|            cptra_obf_uds_seed[13]            |  — |
| 0x0D8|            cptra_obf_uds_seed[14]            |  — |
| 0x0DC|            cptra_obf_uds_seed[15]            |  — |
| 0x0E0|          cptra_obf_field_entropy[0]          |  — |
| 0x0E4|          cptra_obf_field_entropy[1]          |  — |
| 0x0E8|          cptra_obf_field_entropy[2]          |  — |
| 0x0EC|          cptra_obf_field_entropy[3]          |  — |
| 0x0F0|          cptra_obf_field_entropy[4]          |  — |
| 0x0F4|          cptra_obf_field_entropy[5]          |  — |
| 0x0F8|          cptra_obf_field_entropy[6]          |  — |
| 0x0FC|          cptra_obf_field_entropy[7]          |  — |
| 0x100|                   lsu_user                   |  — |
| 0x104|                   ifu_user                   |  — |
| 0x108|                 dma_axi_user                 |  — |
| 0x10C|                soc_config_user               |  — |
| 0x110|               sram_config_user               |  — |
| 0x114|               mcu_reset_vector               |  — |
| 0x118|                 ss_all_error                 |  — |
| 0x11C|                  mcu_config                  |  — |
| 0x120|              uds_seed_base_addr              |  — |
| 0x124|prod_debug_unlock_auth_pk_hash_reg_bank_offset|  — |
| 0x128|    num_of_prod_debug_unlock_auth_pk_hashes   |  — |
| 0x12C|          mci_generic_input_wires[0]          |  — |
| 0x130|          mci_generic_input_wires[1]          |  — |
| 0x134|          mci_generic_output_wires[0]         |  — |
| 0x138|          mci_generic_output_wires[1]         |  — |
| 0x13C|           ss_key_release_base_addr           |  — |
| 0x140|            ss_key_release_key_size           |  — |
| 0x144|      ss_external_staging_area_base_addr      |  — |
| 0x148|             cptra_ss_mcu_ext_int             |  — |
| 0x14C|       cptra_ss_raw_unlock_token_hash[0]      |  — |
| 0x150|       cptra_ss_raw_unlock_token_hash[1]      |  — |
| 0x154|       cptra_ss_raw_unlock_token_hash[2]      |  — |
| 0x158|       cptra_ss_raw_unlock_token_hash[3]      |  — |
| 0x15C|             spare_i3c_control_sts            |  — |
| 0x200|          ocp_lock_key_release_reg[0]         |  — |
| 0x204|          ocp_lock_key_release_reg[1]         |  — |
| 0x208|          ocp_lock_key_release_reg[2]         |  — |
| 0x20C|          ocp_lock_key_release_reg[3]         |  — |
| 0x210|          ocp_lock_key_release_reg[4]         |  — |
| 0x214|          ocp_lock_key_release_reg[5]         |  — |
| 0x218|          ocp_lock_key_release_reg[6]         |  — |
| 0x21C|          ocp_lock_key_release_reg[7]         |  — |
| 0x220|          ocp_lock_key_release_reg[8]         |  — |
| 0x224|          ocp_lock_key_release_reg[9]         |  — |
| 0x228|         ocp_lock_key_release_reg[10]         |  — |
| 0x22C|         ocp_lock_key_release_reg[11]         |  — |
| 0x230|         ocp_lock_key_release_reg[12]         |  — |
| 0x234|         ocp_lock_key_release_reg[13]         |  — |
| 0x238|         ocp_lock_key_release_reg[14]         |  — |
| 0x23C|         ocp_lock_key_release_reg[15]         |  — |
| 0x240|           ocp_lock_metadata_reg[0]           |  — |
| 0x244|           ocp_lock_metadata_reg[1]           |  — |
| 0x248|           ocp_lock_metadata_reg[2]           |  — |
| 0x24C|           ocp_lock_metadata_reg[3]           |  — |
| 0x250|           ocp_lock_metadata_reg[4]           |  — |
| 0x260|        ocp_lock_auxiliary_data_reg[0]        |  — |
| 0x264|        ocp_lock_auxiliary_data_reg[1]        |  — |
| 0x268|        ocp_lock_auxiliary_data_reg[2]        |  — |
| 0x26C|        ocp_lock_auxiliary_data_reg[3]        |  — |
| 0x270|        ocp_lock_auxiliary_data_reg[4]        |  — |
| 0x274|        ocp_lock_auxiliary_data_reg[5]        |  — |
| 0x278|        ocp_lock_auxiliary_data_reg[6]        |  — |
| 0x27C|        ocp_lock_auxiliary_data_reg[7]        |  — |
| 0x280|             ocp_lock_control_reg             |  — |

### fpga_magic register

- Absolute Address: 0xA4010000
- Base Offset: 0x0
- Size: 0x4

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0|fpga_magic|   r  |0x52545043|  — |

#### fpga_magic field

<p>Ascii "CPTR" to check that the image is valid.</p>

### fpga_version register

- Absolute Address: 0xA4010004
- Base Offset: 0x4
- Size: 0x4

|Bits| Identifier |Access|Reset|Name|
|----|------------|------|-----|----|
|31:0|fpga_version|   r  | 0x0 |  — |

#### fpga_version field

<p>Git commit of HEAD the FPGA was built with.</p>

### control register

- Absolute Address: 0xA4010008
- Base Offset: 0x8
- Size: 0x4

|Bits|         Identifier         |Access|Reset|Name|
|----|----------------------------|------|-----|----|
|  0 |        cptra_pwrgood       |  rw  | 0x0 |  — |
|  1 |       cptra_ss_rst_b       |  rw  | 0x0 |  — |
|  2 |   cptra_obf_uds_seed_vld   |  rw  | 0x0 |  — |
|  3 | cptra_obf_field_entropy_vld|  rw  | 0x0 |  — |
|  4 |        debug_locked        |  rw  | 0x0 |  — |
| 6:5|      device_lifecycle      |  rw  | 0x0 |  — |
|  7 |      bootfsm_brkpoint      |  rw  | 0x1 |  — |
|  8 |          scan_mode         |  rw  | 0x0 |  — |
| 16 |       ss_debug_intent      |  rw  | 0x0 |  — |
| 17 |  i3c_axi_user_id_filtering |  rw  | 0x0 |  — |
| 18 |         ocp_lock_en        |  rw  | 0x1 |  — |
| 19 |lc_Allow_RMA_or_SCRAP_on_PPD|  rw  | 0x0 |  — |
| 20 |    FIPS_ZEROIZATION_PPD    |  rw  | 0x0 |  — |
| 31 |      trigger_axi_reset     |  rw  | 0x0 |  — |

#### cptra_obf_uds_seed_vld field

<p>RSVD in SS</p>

#### cptra_obf_field_entropy_vld field

<p>RSVD in SS</p>

#### debug_locked field

<p>RSVD in SS</p>

#### device_lifecycle field

<p>RSVD in SS</p>

#### scan_mode field

<p>Scan mode for Caliptra Core</p>

#### ss_debug_intent field

<p>RSVD in core</p>

#### i3c_axi_user_id_filtering field

<p>RSVD in core</p>

#### ocp_lock_en field

<p>RSVD in core</p>

#### lc_Allow_RMA_or_SCRAP_on_PPD field

<p>RSVD in core</p>

#### FIPS_ZEROIZATION_PPD field

<p>RSVD in core</p>

#### trigger_axi_reset field

<p>RSVD in core</p>

### status register

- Absolute Address: 0xA401000C
- Base Offset: 0xC
- Size: 0x4

|Bits|       Identifier      |Access|Reset|Name|
|----|-----------------------|------|-----|----|
|  0 |   cptra_error_fatal   |   r  | 0x0 |  — |
|  1 | cptra_error_non_fatal |   r  | 0x0 |  — |
|  2 |    ready_for_fuses    |   r  | 0x0 |  — |
|  3 |ready_for_mb_processing|   r  | 0x0 |  — |
|  4 |   ready_for_runtime   |   r  | 0x0 |  — |
|  5 |   mailbox_data_avail  |   r  | 0x0 |  — |
|  6 |   mailbox_flow_done   |   r  | 0x0 |  — |

#### cptra_error_fatal field

<p>RSVD in SS</p>

#### cptra_error_non_fatal field

<p>RSVD in SS</p>

#### ready_for_fuses field

<p>RSVD in SS</p>

#### ready_for_mb_processing field

<p>RSVD in SS</p>

#### ready_for_runtime field

<p>RSVD in SS</p>

#### mailbox_data_avail field

<p>RSVD in SS</p>

#### mailbox_flow_done field

<p>RSVD in SS</p>

### arm_user register

- Absolute Address: 0xA4010010
- Base Offset: 0x10
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0| arm_user |  rw  | 0x0 |  — |

#### arm_user field

<p>USER Value passed to AXI Interconnect for transactions initiated from the ARM core</p>

### itrng_divisor register

- Absolute Address: 0xA4010014
- Base Offset: 0x14
- Size: 0x4

|Bits|  Identifier |Access|Reset|Name|
|----|-------------|------|-----|----|
|31:0|itrng_divisor|  rw  | 0x0 |  — |

### cycle_count register

- Absolute Address: 0xA4010018
- Base Offset: 0x18
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|cycle_count|   r  | 0x0 |  — |

### generic_input_wires register

- Absolute Address: 0xA4010030
- Base Offset: 0x30
- Size: 0x4
- Array Dimensions: [2]
- Array Stride: 0x4
- Total Size: 0x8

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### generic_input_wires register

- Absolute Address: 0xA4010034
- Base Offset: 0x30
- Size: 0x4
- Array Dimensions: [2]
- Array Stride: 0x4
- Total Size: 0x8

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### generic_output_wires register

- Absolute Address: 0xA4010038
- Base Offset: 0x38
- Size: 0x4
- Array Dimensions: [2]
- Array Stride: 0x4
- Total Size: 0x8

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |   r  | 0x0 |  — |

### generic_output_wires register

- Absolute Address: 0xA401003C
- Base Offset: 0x38
- Size: 0x4
- Array Dimensions: [2]
- Array Stride: 0x4
- Total Size: 0x8

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |   r  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA4010040
- Base Offset: 0x40
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA4010044
- Base Offset: 0x40
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA4010048
- Base Offset: 0x40
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA401004C
- Base Offset: 0x40
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA4010050
- Base Offset: 0x40
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA4010054
- Base Offset: 0x40
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA4010058
- Base Offset: 0x40
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA401005C
- Base Offset: 0x40
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010060
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010064
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010068
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA401006C
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010070
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010074
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010078
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA401007C
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010080
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010084
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010088
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA401008C
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010090
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010094
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010098
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA401009C
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100A0
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100A4
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100A8
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100AC
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100B0
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100B4
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100B8
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100BC
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100C0
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100C4
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100C8
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100CC
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100D0
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100D4
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100D8
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100DC
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_field_entropy register

- Absolute Address: 0xA40100E0
- Base Offset: 0xE0
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_field_entropy register

- Absolute Address: 0xA40100E4
- Base Offset: 0xE0
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_field_entropy register

- Absolute Address: 0xA40100E8
- Base Offset: 0xE0
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_field_entropy register

- Absolute Address: 0xA40100EC
- Base Offset: 0xE0
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_field_entropy register

- Absolute Address: 0xA40100F0
- Base Offset: 0xE0
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_field_entropy register

- Absolute Address: 0xA40100F4
- Base Offset: 0xE0
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_field_entropy register

- Absolute Address: 0xA40100F8
- Base Offset: 0xE0
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_field_entropy register

- Absolute Address: 0xA40100FC
- Base Offset: 0xE0
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### lsu_user register

- Absolute Address: 0xA4010100
- Base Offset: 0x100
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0| lsu_user |  rw  | 0x0 |  — |

#### lsu_user field

<p>SS USER Strap</p>

### ifu_user register

- Absolute Address: 0xA4010104
- Base Offset: 0x104
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0| ifu_user |  rw  | 0x0 |  — |

#### ifu_user field

<p>SS USER Strap</p>

### dma_axi_user register

- Absolute Address: 0xA4010108
- Base Offset: 0x108
- Size: 0x4

|Bits| Identifier |Access|Reset|Name|
|----|------------|------|-----|----|
|31:0|dma_axi_user|  rw  | 0x0 |  — |

#### dma_axi_user field

<p>SS USER Strap</p>

### soc_config_user register

- Absolute Address: 0xA401010C
- Base Offset: 0x10C
- Size: 0x4

|Bits|   Identifier  |Access|Reset|Name|
|----|---------------|------|-----|----|
|31:0|soc_config_user|  rw  | 0x0 |  — |

#### soc_config_user field

<p>SS USER Strap</p>

### sram_config_user register

- Absolute Address: 0xA4010110
- Base Offset: 0x110
- Size: 0x4

|Bits|   Identifier   |Access|Reset|Name|
|----|----------------|------|-----|----|
|31:0|sram_config_user|  rw  | 0x0 |  — |

#### sram_config_user field

<p>SS USER Strap</p>

### mcu_reset_vector register

- Absolute Address: 0xA4010114
- Base Offset: 0x114
- Size: 0x4

|Bits|   Identifier   |Access|Reset|Name|
|----|----------------|------|-----|----|
|31:0|mcu_reset_vector|  rw  | 0x0 |  — |

#### mcu_reset_vector field

<p>MCU Reset Vector Strap</p>

### ss_all_error register

- Absolute Address: 0xA4010118
- Base Offset: 0x118
- Size: 0x4

|Bits|      Identifier      |Access|Reset|Name|
|----|----------------------|------|-----|----|
|  0 |  ss_all_error_fatal  |   r  | 0x0 |  — |
|  1 |ss_all_error_non_fatal|   r  | 0x0 |  — |

#### ss_all_error_fatal field

<p>RSVD in core</p>

#### ss_all_error_non_fatal field

<p>RSVD in core</p>

### mcu_config register

- Absolute Address: 0xA401011C
- Base Offset: 0x11C
- Size: 0x4

|Bits|            Identifier            |Access|Reset|Name|
|----|----------------------------------|------|-----|----|
|  0 |         mcu_no_rom_config        |  rw  | 0x0 |  — |
|  1 | cptra_ss_mci_boot_seq_brkpoint_i |  rw  | 0x0 |  — |
|  2 |  cptra_ss_lc_Allow_RMA_on_PPD_i  |  rw  | 0x0 |  — |
|  3 |  cptra_ss_lc_ctrl_scan_rst_ni_i  |  rw  | 0x0 |  — |
|  4 |cptra_ss_lc_esclate_scrap_state0_i|  rw  | 0x0 |  — |
|  5 |cptra_ss_lc_esclate_scrap_state1_i|  rw  | 0x0 |  — |

### uds_seed_base_addr register

- Absolute Address: 0xA4010120
- Base Offset: 0x120
- Size: 0x4

|Bits|    Identifier    |Access|Reset|Name|
|----|------------------|------|-----|----|
|31:0|uds_seed_base_addr|  rw  | 0x0 |  — |

### prod_debug_unlock_auth_pk_hash_reg_bank_offset register

- Absolute Address: 0xA4010124
- Base Offset: 0x124
- Size: 0x4

|Bits|                  Identifier                  |Access|Reset|Name|
|----|----------------------------------------------|------|-----|----|
|31:0|prod_debug_unlock_auth_pk_hash_reg_bank_offset|  rw  | 0x0 |  — |

### num_of_prod_debug_unlock_auth_pk_hashes register

- Absolute Address: 0xA4010128
- Base Offset: 0x128
- Size: 0x4

|Bits|               Identifier              |Access|Reset|Name|
|----|---------------------------------------|------|-----|----|
|31:0|num_of_prod_debug_unlock_auth_pk_hashes|  rw  | 0x0 |  — |

### mci_generic_input_wires register

- Absolute Address: 0xA401012C
- Base Offset: 0x12C
- Size: 0x4
- Array Dimensions: [2]
- Array Stride: 0x4
- Total Size: 0x8

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### mci_generic_input_wires register

- Absolute Address: 0xA4010130
- Base Offset: 0x12C
- Size: 0x4
- Array Dimensions: [2]
- Array Stride: 0x4
- Total Size: 0x8

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### mci_generic_output_wires register

- Absolute Address: 0xA4010134
- Base Offset: 0x134
- Size: 0x4
- Array Dimensions: [2]
- Array Stride: 0x4
- Total Size: 0x8

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |   r  | 0x0 |  — |

### mci_generic_output_wires register

- Absolute Address: 0xA4010138
- Base Offset: 0x134
- Size: 0x4
- Array Dimensions: [2]
- Array Stride: 0x4
- Total Size: 0x8

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |   r  | 0x0 |  — |

### ss_key_release_base_addr register

- Absolute Address: 0xA401013C
- Base Offset: 0x13C
- Size: 0x4

|Bits|       Identifier       |Access|Reset|Name|
|----|------------------------|------|-----|----|
|31:0|ss_key_release_base_addr|   r  | 0x0 |  — |

#### ss_key_release_base_addr field

<p>RSVD in core</p>

### ss_key_release_key_size register

- Absolute Address: 0xA4010140
- Base Offset: 0x140
- Size: 0x4

|Bits|       Identifier      |Access|Reset|Name|
|----|-----------------------|------|-----|----|
|15:0|ss_key_release_key_size|   r  | 0x0 |  — |

#### ss_key_release_key_size field

<p>RSVD in core</p>

### ss_external_staging_area_base_addr register

- Absolute Address: 0xA4010144
- Base Offset: 0x144
- Size: 0x4

|Bits|            Identifier            |Access|Reset|Name|
|----|----------------------------------|------|-----|----|
|31:0|ss_external_staging_area_base_addr|   r  | 0x0 |  — |

#### ss_external_staging_area_base_addr field

<p>RSVD in core</p>

### cptra_ss_mcu_ext_int register

- Absolute Address: 0xA4010148
- Base Offset: 0x148
- Size: 0x4

|Bits|     Identifier     |Access|Reset|Name|
|----|--------------------|------|-----|----|
|31:3|cptra_ss_mcu_ext_int|  rw  | 0x0 |  — |

#### cptra_ss_mcu_ext_int field

<p>RSVD in core</p>

### cptra_ss_raw_unlock_token_hash register

- Absolute Address: 0xA401014C
- Base Offset: 0x14C
- Size: 0x4
- Array Dimensions: [4]
- Array Stride: 0x4
- Total Size: 0x10

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_ss_raw_unlock_token_hash register

- Absolute Address: 0xA4010150
- Base Offset: 0x14C
- Size: 0x4
- Array Dimensions: [4]
- Array Stride: 0x4
- Total Size: 0x10

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_ss_raw_unlock_token_hash register

- Absolute Address: 0xA4010154
- Base Offset: 0x14C
- Size: 0x4
- Array Dimensions: [4]
- Array Stride: 0x4
- Total Size: 0x10

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_ss_raw_unlock_token_hash register

- Absolute Address: 0xA4010158
- Base Offset: 0x14C
- Size: 0x4
- Array Dimensions: [4]
- Array Stride: 0x4
- Total Size: 0x10

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### spare_i3c_control_sts register

- Absolute Address: 0xA401015C
- Base Offset: 0x15C
- Size: 0x4

|Bits|         Identifier         |Access|Reset|Name|
|----|----------------------------|------|-----|----|
|  0 |     use_spare_i3c_core     |  rw  | 0x0 |  — |
|  1 |            irq_o           |   r  | 0x0 |  — |
|  2 |recovery_payload_available_o|   r  | 0x0 |  — |
|  3 | recovery_image_activated_o |   r  | 0x0 |  — |

#### use_spare_i3c_core field

<p>RSVD in core</p>

#### irq_o field

<p>RSVD in core</p>

#### recovery_payload_available_o field

<p>RSVD in core</p>

#### recovery_image_activated_o field

<p>RSVD in core</p>

### ocp_lock_key_release_reg register

- Absolute Address: 0xA4010200
- Base Offset: 0x200
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|    key   |  rw  | 0x0 |  — |

#### key field

<p>OCP LOCK Media Encryption Key (MEK)</p>

### ocp_lock_key_release_reg register

- Absolute Address: 0xA4010204
- Base Offset: 0x200
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|    key   |  rw  | 0x0 |  — |

#### key field

<p>OCP LOCK Media Encryption Key (MEK)</p>

### ocp_lock_key_release_reg register

- Absolute Address: 0xA4010208
- Base Offset: 0x200
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|    key   |  rw  | 0x0 |  — |

#### key field

<p>OCP LOCK Media Encryption Key (MEK)</p>

### ocp_lock_key_release_reg register

- Absolute Address: 0xA401020C
- Base Offset: 0x200
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|    key   |  rw  | 0x0 |  — |

#### key field

<p>OCP LOCK Media Encryption Key (MEK)</p>

### ocp_lock_key_release_reg register

- Absolute Address: 0xA4010210
- Base Offset: 0x200
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|    key   |  rw  | 0x0 |  — |

#### key field

<p>OCP LOCK Media Encryption Key (MEK)</p>

### ocp_lock_key_release_reg register

- Absolute Address: 0xA4010214
- Base Offset: 0x200
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|    key   |  rw  | 0x0 |  — |

#### key field

<p>OCP LOCK Media Encryption Key (MEK)</p>

### ocp_lock_key_release_reg register

- Absolute Address: 0xA4010218
- Base Offset: 0x200
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|    key   |  rw  | 0x0 |  — |

#### key field

<p>OCP LOCK Media Encryption Key (MEK)</p>

### ocp_lock_key_release_reg register

- Absolute Address: 0xA401021C
- Base Offset: 0x200
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|    key   |  rw  | 0x0 |  — |

#### key field

<p>OCP LOCK Media Encryption Key (MEK)</p>

### ocp_lock_key_release_reg register

- Absolute Address: 0xA4010220
- Base Offset: 0x200
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|    key   |  rw  | 0x0 |  — |

#### key field

<p>OCP LOCK Media Encryption Key (MEK)</p>

### ocp_lock_key_release_reg register

- Absolute Address: 0xA4010224
- Base Offset: 0x200
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|    key   |  rw  | 0x0 |  — |

#### key field

<p>OCP LOCK Media Encryption Key (MEK)</p>

### ocp_lock_key_release_reg register

- Absolute Address: 0xA4010228
- Base Offset: 0x200
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|    key   |  rw  | 0x0 |  — |

#### key field

<p>OCP LOCK Media Encryption Key (MEK)</p>

### ocp_lock_key_release_reg register

- Absolute Address: 0xA401022C
- Base Offset: 0x200
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|    key   |  rw  | 0x0 |  — |

#### key field

<p>OCP LOCK Media Encryption Key (MEK)</p>

### ocp_lock_key_release_reg register

- Absolute Address: 0xA4010230
- Base Offset: 0x200
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|    key   |  rw  | 0x0 |  — |

#### key field

<p>OCP LOCK Media Encryption Key (MEK)</p>

### ocp_lock_key_release_reg register

- Absolute Address: 0xA4010234
- Base Offset: 0x200
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|    key   |  rw  | 0x0 |  — |

#### key field

<p>OCP LOCK Media Encryption Key (MEK)</p>

### ocp_lock_key_release_reg register

- Absolute Address: 0xA4010238
- Base Offset: 0x200
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|    key   |  rw  | 0x0 |  — |

#### key field

<p>OCP LOCK Media Encryption Key (MEK)</p>

### ocp_lock_key_release_reg register

- Absolute Address: 0xA401023C
- Base Offset: 0x200
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|    key   |  rw  | 0x0 |  — |

#### key field

<p>OCP LOCK Media Encryption Key (MEK)</p>

### ocp_lock_metadata_reg register

- Absolute Address: 0xA4010240
- Base Offset: 0x240
- Size: 0x4
- Array Dimensions: [5]
- Array Stride: 0x4
- Total Size: 0x14

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0| metadata |  rw  | 0x0 |  — |

#### metadata field

<p>OCP LOCK Metadata (METD)</p>

### ocp_lock_metadata_reg register

- Absolute Address: 0xA4010244
- Base Offset: 0x240
- Size: 0x4
- Array Dimensions: [5]
- Array Stride: 0x4
- Total Size: 0x14

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0| metadata |  rw  | 0x0 |  — |

#### metadata field

<p>OCP LOCK Metadata (METD)</p>

### ocp_lock_metadata_reg register

- Absolute Address: 0xA4010248
- Base Offset: 0x240
- Size: 0x4
- Array Dimensions: [5]
- Array Stride: 0x4
- Total Size: 0x14

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0| metadata |  rw  | 0x0 |  — |

#### metadata field

<p>OCP LOCK Metadata (METD)</p>

### ocp_lock_metadata_reg register

- Absolute Address: 0xA401024C
- Base Offset: 0x240
- Size: 0x4
- Array Dimensions: [5]
- Array Stride: 0x4
- Total Size: 0x14

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0| metadata |  rw  | 0x0 |  — |

#### metadata field

<p>OCP LOCK Metadata (METD)</p>

### ocp_lock_metadata_reg register

- Absolute Address: 0xA4010250
- Base Offset: 0x240
- Size: 0x4
- Array Dimensions: [5]
- Array Stride: 0x4
- Total Size: 0x14

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0| metadata |  rw  | 0x0 |  — |

#### metadata field

<p>OCP LOCK Metadata (METD)</p>

### ocp_lock_auxiliary_data_reg register

- Absolute Address: 0xA4010260
- Base Offset: 0x260
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   data   |  rw  | 0x0 |  — |

#### data field

<p>OCP LOCK Auxiliary Data (AUX)</p>

### ocp_lock_auxiliary_data_reg register

- Absolute Address: 0xA4010264
- Base Offset: 0x260
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   data   |  rw  | 0x0 |  — |

#### data field

<p>OCP LOCK Auxiliary Data (AUX)</p>

### ocp_lock_auxiliary_data_reg register

- Absolute Address: 0xA4010268
- Base Offset: 0x260
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   data   |  rw  | 0x0 |  — |

#### data field

<p>OCP LOCK Auxiliary Data (AUX)</p>

### ocp_lock_auxiliary_data_reg register

- Absolute Address: 0xA401026C
- Base Offset: 0x260
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   data   |  rw  | 0x0 |  — |

#### data field

<p>OCP LOCK Auxiliary Data (AUX)</p>

### ocp_lock_auxiliary_data_reg register

- Absolute Address: 0xA4010270
- Base Offset: 0x260
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   data   |  rw  | 0x0 |  — |

#### data field

<p>OCP LOCK Auxiliary Data (AUX)</p>

### ocp_lock_auxiliary_data_reg register

- Absolute Address: 0xA4010274
- Base Offset: 0x260
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   data   |  rw  | 0x0 |  — |

#### data field

<p>OCP LOCK Auxiliary Data (AUX)</p>

### ocp_lock_auxiliary_data_reg register

- Absolute Address: 0xA4010278
- Base Offset: 0x260
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   data   |  rw  | 0x0 |  — |

#### data field

<p>OCP LOCK Auxiliary Data (AUX)</p>

### ocp_lock_auxiliary_data_reg register

- Absolute Address: 0xA401027C
- Base Offset: 0x260
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   data   |  rw  | 0x0 |  — |

#### data field

<p>OCP LOCK Auxiliary Data (AUX)</p>

### ocp_lock_control_reg register

- Absolute Address: 0xA4010280
- Base Offset: 0x280
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   ctrl   |  rw  | 0x0 |  — |

#### ctrl field

<p>OCP LOCK Control</p>

## fifo_regs register file

- Absolute Address: 0xA4011000
- Base Offset: 0xA4011000
- Size: 0x28

|Offset|    Identifier   |Name|
|------|-----------------|----|
| 0x00 |  log_fifo_data  |  — |
| 0x04 | log_fifo_status |  — |
| 0x08 | itrng_fifo_data |  — |
| 0x0C |itrng_fifo_status|  — |
| 0x10 |   dbg_fifo_pop  |  — |
| 0x14 |  dbg_fifo_push  |  — |
| 0x18 | dbg_fifo_status |  — |
| 0x1C |   msg_fifo_pop  |  — |
| 0x20 |  msg_fifo_push  |  — |
| 0x24 | msg_fifo_status |  — |

### log_fifo_data register

- Absolute Address: 0xA4011000
- Base Offset: 0x0
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
| 7:0| next_char|   r  | 0x0 |  — |
|  8 |char_valid|   r  | 0x0 |  — |

### log_fifo_status register

- Absolute Address: 0xA4011004
- Base Offset: 0x4
- Size: 0x4

|Bits|  Identifier  |Access|Reset|Name|
|----|--------------|------|-----|----|
|  0 |log_fifo_empty|   r  | 0x0 |  — |
|  1 | log_fifo_full|   r  | 0x0 |  — |

### itrng_fifo_data register

- Absolute Address: 0xA4011008
- Base Offset: 0x8
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|itrng_data|  rw  | 0x0 |  — |

### itrng_fifo_status register

- Absolute Address: 0xA401100C
- Base Offset: 0xC
- Size: 0x4

|Bits|   Identifier   |Access|Reset|Name|
|----|----------------|------|-----|----|
|  0 |itrng_fifo_empty|   r  | 0x0 |  — |
|  1 | itrng_fifo_full|   r  | 0x0 |  — |
|  2 |itrng_fifo_reset|  rw  | 0x0 |  — |

### dbg_fifo_pop register

- Absolute Address: 0xA4011010
- Base Offset: 0x10
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0| out_data |   r  | 0x0 |  — |

#### out_data field

<p>RSVD in core</p>

### dbg_fifo_push register

- Absolute Address: 0xA4011014
- Base Offset: 0x14
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|  in_data |  rw  | 0x0 |  — |

#### in_data field

<p>RSVD in core</p>

### dbg_fifo_status register

- Absolute Address: 0xA4011018
- Base Offset: 0x18
- Size: 0x4

|Bits|  Identifier  |Access|Reset|Name|
|----|--------------|------|-----|----|
|  0 |dbg_fifo_empty|   r  | 0x0 |  — |
|  1 | dbg_fifo_full|   r  | 0x0 |  — |

#### dbg_fifo_empty field

<p>RSVD in core</p>

#### dbg_fifo_full field

<p>RSVD in core</p>

### msg_fifo_pop register

- Absolute Address: 0xA401101C
- Base Offset: 0x1C
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0| out_data |   r  | 0x0 |  — |

#### out_data field

<p>RSVD in core</p>

### msg_fifo_push register

- Absolute Address: 0xA4011020
- Base Offset: 0x20
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|  in_data |  rw  | 0x0 |  — |

#### in_data field

<p>RSVD in core</p>

### msg_fifo_status register

- Absolute Address: 0xA4011024
- Base Offset: 0x24
- Size: 0x4

|Bits|  Identifier  |Access|Reset|Name|
|----|--------------|------|-----|----|
|  0 |msg_fifo_empty|   r  | 0x0 |  — |
|  1 | msg_fifo_full|   r  | 0x0 |  — |

#### msg_fifo_empty field

<p>RSVD in core</p>

#### msg_fifo_full field

<p>RSVD in core</p>

## primary_flash_ctrl_regs register file

- Absolute Address: 0xA4012000
- Base Offset: 0xA4012000
- Size: 0x200

|Offset|     Identifier    |Name|
|------|-------------------|----|
| 0x000| FL_INTERRUPT_STATE|  — |
| 0x004|FL_INTERRUPT_ENABLE|  — |
| 0x008|     PAGE_SIZE     |  — |
| 0x00C|      PAGE_NUM     |  — |
| 0x010|     PAGE_ADDR     |  — |
| 0x014|     FL_CONTROL    |  — |
| 0x018|     OP_STATUS     |  — |
| 0x01C|    CTRL_REGWEN    |  — |
| 0x020|     FLASH_SIZE    |  — |
| 0x100|    FLASH_BUF[0]   |  — |
| 0x104|    FLASH_BUF[1]   |  — |
| 0x108|    FLASH_BUF[2]   |  — |
| 0x10C|    FLASH_BUF[3]   |  — |
| 0x110|    FLASH_BUF[4]   |  — |
| 0x114|    FLASH_BUF[5]   |  — |
| 0x118|    FLASH_BUF[6]   |  — |
| 0x11C|    FLASH_BUF[7]   |  — |
| 0x120|    FLASH_BUF[8]   |  — |
| 0x124|    FLASH_BUF[9]   |  — |
| 0x128|   FLASH_BUF[10]   |  — |
| 0x12C|   FLASH_BUF[11]   |  — |
| 0x130|   FLASH_BUF[12]   |  — |
| 0x134|   FLASH_BUF[13]   |  — |
| 0x138|   FLASH_BUF[14]   |  — |
| 0x13C|   FLASH_BUF[15]   |  — |
| 0x140|   FLASH_BUF[16]   |  — |
| 0x144|   FLASH_BUF[17]   |  — |
| 0x148|   FLASH_BUF[18]   |  — |
| 0x14C|   FLASH_BUF[19]   |  — |
| 0x150|   FLASH_BUF[20]   |  — |
| 0x154|   FLASH_BUF[21]   |  — |
| 0x158|   FLASH_BUF[22]   |  — |
| 0x15C|   FLASH_BUF[23]   |  — |
| 0x160|   FLASH_BUF[24]   |  — |
| 0x164|   FLASH_BUF[25]   |  — |
| 0x168|   FLASH_BUF[26]   |  — |
| 0x16C|   FLASH_BUF[27]   |  — |
| 0x170|   FLASH_BUF[28]   |  — |
| 0x174|   FLASH_BUF[29]   |  — |
| 0x178|   FLASH_BUF[30]   |  — |
| 0x17C|   FLASH_BUF[31]   |  — |
| 0x180|   FLASH_BUF[32]   |  — |
| 0x184|   FLASH_BUF[33]   |  — |
| 0x188|   FLASH_BUF[34]   |  — |
| 0x18C|   FLASH_BUF[35]   |  — |
| 0x190|   FLASH_BUF[36]   |  — |
| 0x194|   FLASH_BUF[37]   |  — |
| 0x198|   FLASH_BUF[38]   |  — |
| 0x19C|   FLASH_BUF[39]   |  — |
| 0x1A0|   FLASH_BUF[40]   |  — |
| 0x1A4|   FLASH_BUF[41]   |  — |
| 0x1A8|   FLASH_BUF[42]   |  — |
| 0x1AC|   FLASH_BUF[43]   |  — |
| 0x1B0|   FLASH_BUF[44]   |  — |
| 0x1B4|   FLASH_BUF[45]   |  — |
| 0x1B8|   FLASH_BUF[46]   |  — |
| 0x1BC|   FLASH_BUF[47]   |  — |
| 0x1C0|   FLASH_BUF[48]   |  — |
| 0x1C4|   FLASH_BUF[49]   |  — |
| 0x1C8|   FLASH_BUF[50]   |  — |
| 0x1CC|   FLASH_BUF[51]   |  — |
| 0x1D0|   FLASH_BUF[52]   |  — |
| 0x1D4|   FLASH_BUF[53]   |  — |
| 0x1D8|   FLASH_BUF[54]   |  — |
| 0x1DC|   FLASH_BUF[55]   |  — |
| 0x1E0|   FLASH_BUF[56]   |  — |
| 0x1E4|   FLASH_BUF[57]   |  — |
| 0x1E8|   FLASH_BUF[58]   |  — |
| 0x1EC|   FLASH_BUF[59]   |  — |
| 0x1F0|   FLASH_BUF[60]   |  — |
| 0x1F4|   FLASH_BUF[61]   |  — |
| 0x1F8|   FLASH_BUF[62]   |  — |
| 0x1FC|   FLASH_BUF[63]   |  — |

### FL_INTERRUPT_STATE register

- Absolute Address: 0xA4012000
- Base Offset: 0x0
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|  0 |   ERROR  |  rw  | 0x0 |  — |
|  1 |   EVENT  |  rw  | 0x0 |  — |

#### ERROR field

<p>Error-related interrupts</p>

#### EVENT field

<p>Event-related interrupts</p>

### FL_INTERRUPT_ENABLE register

- Absolute Address: 0xA4012004
- Base Offset: 0x4
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|  0 |   ERROR  |  rw  | 0x0 |  — |
|  1 |   EVENT  |  rw  | 0x0 |  — |

#### ERROR field

<p>Enable error interrupt</p>

#### EVENT field

<p>Enable event interrupt</p>

### PAGE_SIZE register

- Absolute Address: 0xA4012008
- Base Offset: 0x8
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0| PAGE_SIZE|  rw  |0x100|  — |

#### PAGE_SIZE field

<p>Page size in bytes (default 256)</p>

### PAGE_NUM register

- Absolute Address: 0xA401200C
- Base Offset: 0xC
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0| PAGE_NUM |  rw  | 0x0 |  — |

#### PAGE_NUM field

<p>The page number for read, write, erase operations</p>

### PAGE_ADDR register

- Absolute Address: 0xA4012010
- Base Offset: 0x10
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0| PAGE_ADDR|  rw  | 0x0 |  — |

#### PAGE_ADDR field

<p>The page buffer address for read/write operations (driver-provided memory address)</p>

### FL_CONTROL register

- Absolute Address: 0xA4012014
- Base Offset: 0x14
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|  0 |   START  |  rw  | 0x0 |  — |
| 2:1|    OP    |  rw  | 0x0 |  — |

#### START field

<p>Start the operation. HW clears when done.</p>

#### OP field

<p>"0" = Read page, "1" = Write Page, "2" = Erase Page</p>

### OP_STATUS register

- Absolute Address: 0xA4012018
- Base Offset: 0x18
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|  0 |   DONE   |  rw  | 0x0 |  — |
| 3:1|    ERR   |  rw  | 0x0 |  — |

#### DONE field

<p>Flash operation done. Set by HW, cleared by SW</p>

#### ERR field

<p>Flash operation error. "1" = Read Error, "2" = Write Error, "4" = Erase Error</p>

### CTRL_REGWEN register

- Absolute Address: 0xA401201C
- Base Offset: 0x1C
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|  0 |    EN    |  rw  | 0x1 |  — |

#### EN field

<p>Control register write enable. 1=unlocked, 0=locked during operation</p>

### FLASH_SIZE register

- Absolute Address: 0xA4012020
- Base Offset: 0x20
- Size: 0x4

|Bits|Identifier|Access|  Reset  |Name|
|----|----------|------|---------|----|
|31:0|FLASH_SIZE|  rw  |0x1000000|  — |

#### FLASH_SIZE field

<p>Total flash size in bytes</p>

### FLASH_BUF register

- Absolute Address: 0xA4012100
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012104
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012108
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401210C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012110
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012114
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012118
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401211C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012120
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012124
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012128
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401212C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012130
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012134
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012138
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401213C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012140
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012144
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012148
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401214C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012150
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012154
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012158
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401215C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012160
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012164
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012168
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401216C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012170
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012174
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012178
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401217C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012180
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012184
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012188
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401218C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012190
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012194
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4012198
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401219C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121A0
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121A4
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121A8
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121AC
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121B0
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121B4
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121B8
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121BC
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121C0
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121C4
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121C8
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121CC
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121D0
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121D4
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121D8
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121DC
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121E0
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121E4
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121E8
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121EC
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121F0
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121F4
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121F8
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40121FC
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

## secondary_flash_ctrl_regs register file

- Absolute Address: 0xA4013000
- Base Offset: 0xA4013000
- Size: 0x200

|Offset|     Identifier    |Name|
|------|-------------------|----|
| 0x000| FL_INTERRUPT_STATE|  — |
| 0x004|FL_INTERRUPT_ENABLE|  — |
| 0x008|     PAGE_SIZE     |  — |
| 0x00C|      PAGE_NUM     |  — |
| 0x010|     PAGE_ADDR     |  — |
| 0x014|     FL_CONTROL    |  — |
| 0x018|     OP_STATUS     |  — |
| 0x01C|    CTRL_REGWEN    |  — |
| 0x020|     FLASH_SIZE    |  — |
| 0x100|    FLASH_BUF[0]   |  — |
| 0x104|    FLASH_BUF[1]   |  — |
| 0x108|    FLASH_BUF[2]   |  — |
| 0x10C|    FLASH_BUF[3]   |  — |
| 0x110|    FLASH_BUF[4]   |  — |
| 0x114|    FLASH_BUF[5]   |  — |
| 0x118|    FLASH_BUF[6]   |  — |
| 0x11C|    FLASH_BUF[7]   |  — |
| 0x120|    FLASH_BUF[8]   |  — |
| 0x124|    FLASH_BUF[9]   |  — |
| 0x128|   FLASH_BUF[10]   |  — |
| 0x12C|   FLASH_BUF[11]   |  — |
| 0x130|   FLASH_BUF[12]   |  — |
| 0x134|   FLASH_BUF[13]   |  — |
| 0x138|   FLASH_BUF[14]   |  — |
| 0x13C|   FLASH_BUF[15]   |  — |
| 0x140|   FLASH_BUF[16]   |  — |
| 0x144|   FLASH_BUF[17]   |  — |
| 0x148|   FLASH_BUF[18]   |  — |
| 0x14C|   FLASH_BUF[19]   |  — |
| 0x150|   FLASH_BUF[20]   |  — |
| 0x154|   FLASH_BUF[21]   |  — |
| 0x158|   FLASH_BUF[22]   |  — |
| 0x15C|   FLASH_BUF[23]   |  — |
| 0x160|   FLASH_BUF[24]   |  — |
| 0x164|   FLASH_BUF[25]   |  — |
| 0x168|   FLASH_BUF[26]   |  — |
| 0x16C|   FLASH_BUF[27]   |  — |
| 0x170|   FLASH_BUF[28]   |  — |
| 0x174|   FLASH_BUF[29]   |  — |
| 0x178|   FLASH_BUF[30]   |  — |
| 0x17C|   FLASH_BUF[31]   |  — |
| 0x180|   FLASH_BUF[32]   |  — |
| 0x184|   FLASH_BUF[33]   |  — |
| 0x188|   FLASH_BUF[34]   |  — |
| 0x18C|   FLASH_BUF[35]   |  — |
| 0x190|   FLASH_BUF[36]   |  — |
| 0x194|   FLASH_BUF[37]   |  — |
| 0x198|   FLASH_BUF[38]   |  — |
| 0x19C|   FLASH_BUF[39]   |  — |
| 0x1A0|   FLASH_BUF[40]   |  — |
| 0x1A4|   FLASH_BUF[41]   |  — |
| 0x1A8|   FLASH_BUF[42]   |  — |
| 0x1AC|   FLASH_BUF[43]   |  — |
| 0x1B0|   FLASH_BUF[44]   |  — |
| 0x1B4|   FLASH_BUF[45]   |  — |
| 0x1B8|   FLASH_BUF[46]   |  — |
| 0x1BC|   FLASH_BUF[47]   |  — |
| 0x1C0|   FLASH_BUF[48]   |  — |
| 0x1C4|   FLASH_BUF[49]   |  — |
| 0x1C8|   FLASH_BUF[50]   |  — |
| 0x1CC|   FLASH_BUF[51]   |  — |
| 0x1D0|   FLASH_BUF[52]   |  — |
| 0x1D4|   FLASH_BUF[53]   |  — |
| 0x1D8|   FLASH_BUF[54]   |  — |
| 0x1DC|   FLASH_BUF[55]   |  — |
| 0x1E0|   FLASH_BUF[56]   |  — |
| 0x1E4|   FLASH_BUF[57]   |  — |
| 0x1E8|   FLASH_BUF[58]   |  — |
| 0x1EC|   FLASH_BUF[59]   |  — |
| 0x1F0|   FLASH_BUF[60]   |  — |
| 0x1F4|   FLASH_BUF[61]   |  — |
| 0x1F8|   FLASH_BUF[62]   |  — |
| 0x1FC|   FLASH_BUF[63]   |  — |

### FL_INTERRUPT_STATE register

- Absolute Address: 0xA4013000
- Base Offset: 0x0
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|  0 |   ERROR  |  rw  | 0x0 |  — |
|  1 |   EVENT  |  rw  | 0x0 |  — |

#### ERROR field

<p>Error-related interrupts</p>

#### EVENT field

<p>Event-related interrupts</p>

### FL_INTERRUPT_ENABLE register

- Absolute Address: 0xA4013004
- Base Offset: 0x4
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|  0 |   ERROR  |  rw  | 0x0 |  — |
|  1 |   EVENT  |  rw  | 0x0 |  — |

#### ERROR field

<p>Enable error interrupt</p>

#### EVENT field

<p>Enable event interrupt</p>

### PAGE_SIZE register

- Absolute Address: 0xA4013008
- Base Offset: 0x8
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0| PAGE_SIZE|  rw  |0x100|  — |

#### PAGE_SIZE field

<p>Page size in bytes (default 256)</p>

### PAGE_NUM register

- Absolute Address: 0xA401300C
- Base Offset: 0xC
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0| PAGE_NUM |  rw  | 0x0 |  — |

#### PAGE_NUM field

<p>The page number for read, write, erase operations</p>

### PAGE_ADDR register

- Absolute Address: 0xA4013010
- Base Offset: 0x10
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0| PAGE_ADDR|  rw  | 0x0 |  — |

#### PAGE_ADDR field

<p>The page buffer address for read/write operations (driver-provided memory address)</p>

### FL_CONTROL register

- Absolute Address: 0xA4013014
- Base Offset: 0x14
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|  0 |   START  |  rw  | 0x0 |  — |
| 2:1|    OP    |  rw  | 0x0 |  — |

#### START field

<p>Start the operation. HW clears when done.</p>

#### OP field

<p>"0" = Read page, "1" = Write Page, "2" = Erase Page</p>

### OP_STATUS register

- Absolute Address: 0xA4013018
- Base Offset: 0x18
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|  0 |   DONE   |  rw  | 0x0 |  — |
| 3:1|    ERR   |  rw  | 0x0 |  — |

#### DONE field

<p>Flash operation done. Set by HW, cleared by SW</p>

#### ERR field

<p>Flash operation error. "1" = Read Error, "2" = Write Error, "4" = Erase Error</p>

### CTRL_REGWEN register

- Absolute Address: 0xA401301C
- Base Offset: 0x1C
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|  0 |    EN    |  rw  | 0x1 |  — |

#### EN field

<p>Control register write enable. 1=unlocked, 0=locked during operation</p>

### FLASH_SIZE register

- Absolute Address: 0xA4013020
- Base Offset: 0x20
- Size: 0x4

|Bits|Identifier|Access|  Reset  |Name|
|----|----------|------|---------|----|
|31:0|FLASH_SIZE|  rw  |0x1000000|  — |

#### FLASH_SIZE field

<p>Total flash size in bytes</p>

### FLASH_BUF register

- Absolute Address: 0xA4013100
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013104
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013108
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401310C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013110
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013114
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013118
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401311C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013120
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013124
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013128
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401312C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013130
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013134
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013138
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401313C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013140
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013144
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013148
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401314C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013150
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013154
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013158
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401315C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013160
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013164
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013168
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401316C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013170
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013174
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013178
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401317C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013180
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013184
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013188
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401318C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013190
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013194
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA4013198
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA401319C
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131A0
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131A4
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131A8
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131AC
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131B0
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131B4
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131B8
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131BC
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131C0
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131C4
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131C8
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131CC
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131D0
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131D4
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131D8
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131DC
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131E0
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131E4
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131E8
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131EC
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131F0
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131F4
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131F8
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

### FLASH_BUF register

- Absolute Address: 0xA40131FC
- Base Offset: 0x100
- Size: 0x4
- Array Dimensions: [64]
- Array Stride: 0x4
- Total Size: 0x100

<p>Flash buffer</p>

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0| FLASH_BUF|  rw  |0xFFFFFFFF|  — |

// Based on the RISC-V Disassembler by Michael Clark and SiFive:
// https://github.com/michaeljclark/riscv-disassembler/
/*
 * Copyright (c) 2016-2017 Michael Clark <michaeljclark@mac.com>
 * Copyright (c) 2017-2018 SiFive, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#![allow(non_upper_case_globals)]

const TAB_SIZE: usize = 32;

#[allow(dead_code)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum RvIsa {
    Rv32,
    Rv64,
    Rv128,
}

type RvInst = u64;
enum RvFence {
    W = 1,
    R = 2,
    O = 4,
    I = 8,
}

enum RvIreg {
    Sp = 2,
    Ra = 1,
    Zero = 0,
}

#[derive(Clone, Copy, PartialEq)]
enum RvcConstraint {
    CsrEq0xc82,
    CsrEq0xc81,
    CsrRq0xc80,
    CsrEq0xc02,
    CsrEq0xc01,
    CsrEq0xc00,
    CsrEq0x003,
    CsrEq0x002,
    CsrEq0x001,
    ImmEqP1,
    ImmEqN1,
    ImmEqZero,
    Rs1EqRa,
    Rs2EqRs1,
    Rs2EqX0,
    Rs1EqX0,
    RdEqX0,
    RdEqRa,
}

#[derive(PartialEq, Clone, Copy)]
enum RvCodec {
    Li,
    CssSqsp,
    CssSdsp,
    CssSwsp,
    CsSq,
    CsSd,
    CsSw,
    Cs,
    CrJr,
    CrJalr,
    CrMv,
    Cr,
    ClLq,
    ClLd,
    ClLw,
    CjJal,
    Cj,
    Ciw4spn,
    CiNone,
    CiLui,
    CiLi,
    CiLqsp,
    CiLdsp,
    CiLwsp,
    Ci16sp,
    CiSh6,
    //CiSh5,
    Ci,
    CbSh6,
    //CbSh5,
    CbImm,
    Cb,
    RF,
    RL,
    RA,
    R4M,
    RM,
    R,
    SB,
    S,
    ICsr,
    ISh7,
    ISh6,
    ISh5,
    I,
    Uj,
    U,
    None,
    Illegal,
}

type RvOpcode = &'static RvOpcodeData;

#[derive(Copy, Clone)]
struct RvDecode {
    pc: u64,
    inst: u64,
    imm: i32,
    op: Option<RvOpcode>,
    codec: RvCodec,
    rd: u8,
    rs1: u8,
    rs2: u8,
    rs3: u8,
    rm: u8,
    pred: u8,
    succ: u8,
    aq: u8,
    rl: u8,
}
#[derive(Copy, Clone)]
struct RvOpcodeData {
    name: &'static str,
    codec: RvCodec,
    format: &'static str,
    pseudo: Option<&'static [RvCompData]>,
    decomp_rv32: Option<RvOpcode>,
    decomp_rv64: Option<RvOpcode>,
    decomp_rv128: Option<RvOpcode>,
    check_imm_nz: bool,
}
#[derive(Copy, Clone)]
struct RvCompData {
    op: RvOpcode,
    constraints: &'static [RvcConstraint],
}
static rv_ireg_name_sym: [&str; 32] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
    "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
    "t5", "t6",
];
static rv_freg_name_sym: [&str; 32] = [
    "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "fs0", "fs1", "fa0", "fa1", "fa2",
    "fa3", "fa4", "fa5", "fa6", "fa7", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9",
    "fs10", "fs11", "ft8", "ft9", "ft10", "ft11",
];

static RV_FMT_NONE: &str = "O";
static RV_FMT_RS1: &str = "O\t1";
static RV_FMT_OFFSET: &str = "O\to";
static RV_FMT_PRED_SUCC: &str = "O\tp,s";
static RV_FMT_RS1_RS2: &str = "O\t1,2";
static RV_FMT_RD_IMM: &str = "O\t0,i";
static RV_FMT_RD_OFFSET: &str = "O\t0,o";
static RV_FMT_RD_RS1_RS2: &str = "O\t0,1,2";
static RV_FMT_FRD_RS1: &str = "O\t3,1";
static RV_FMT_RD_FRS1: &str = "O\t0,4";
static RV_FMT_RD_FRS1_FRS2: &str = "O\t0,4,5";
static RV_FMT_FRD_FRS1_FRS2: &str = "O\t3,4,5";
static RV_FMT_RM_FRD_FRS1: &str = "O\tr,3,4";
static RV_FMT_RM_FRD_RS1: &str = "O\tr,3,1";
static RV_FMT_RM_RD_FRS1: &str = "O\tr,0,4";
static RV_FMT_RM_FRD_FRS1_FRS2: &str = "O\tr,3,4,5";
static RV_FMT_RM_FRD_FRS1_FRS2_FRS3: &str = "O\tr,3,4,5,6";
static RV_FMT_RD_RS1_IMM: &str = "O\t0,1,i";
static RV_FMT_RD_RS1_OFFSET: &str = "O\t0,1,i";
static RV_FMT_RD_OFFSET_RS1: &str = "O\t0,i(1)";
static RV_FMT_FRD_OFFSET_RS1: &str = "O\t3,i(1)";
static RV_FMT_RD_CSR_RS1: &str = "O\t0,c,1";
static RV_FMT_RD_CSR_ZIMM: &str = "O\t0,c,7";
static RV_FMT_RS2_OFFSET_RS1: &str = "O\t2,i(1)";
static RV_FMT_FRS2_OFFSET_RS1: &str = "O\t5,i(1)";
static RV_FMT_RS1_RS2_OFFSET: &str = "O\t1,2,o";
static RV_FMT_RS2_RS1_OFFSET: &str = "O\t2,1,o";
static RV_FMT_AQRL_RD_RS2_RS1: &str = "OAR\t0,2,(1)";
static RV_FMT_AQRL_RD_RS1: &str = "OAR\t0,(1)";
static RV_FMT_RD: &str = "O\t0";
static RV_FMT_RD_ZIMM: &str = "O\t0,7";
static RV_FMT_RD_RS1: &str = "O\t0,1";
static RV_FMT_RD_RS2: &str = "O\t0,2";
static RV_FMT_RS1_OFFSET: &str = "O\t1,o";
static RV_FMT_RS2_OFFSET: &str = "O\t2,o";

use RvcConstraint::*;
static RVCC_LAST: [RvcConstraint; 0] = [];
static RVCC_IMM_EQ_ZERO: [RvcConstraint; 1] = [ImmEqZero];
static RVCC_IMM_EQ_N1: [RvcConstraint; 1] = [ImmEqN1];
static RVCC_IMM_EQ_P1: [RvcConstraint; 1] = [ImmEqP1];
static RVCC_RS1_EQ_X0: [RvcConstraint; 1] = [Rs1EqX0];
static RVCC_RS2_EQ_X0: [RvcConstraint; 1] = [Rs2EqX0];
static RVCC_RS2_EQ_RS1: [RvcConstraint; 1] = [Rs2EqRs1];
static RVCC_JAL_J: [RvcConstraint; 1] = [RdEqX0];
static RVCC_JAL_JAL: [RvcConstraint; 1] = [RdEqRa];
static RVCC_JALR_JR: [RvcConstraint; 2] = [RdEqX0, ImmEqZero];
static RVCC_JALR_JALR: [RvcConstraint; 2] = [RdEqRa, ImmEqZero];
static RVCC_JALR_RET: [RvcConstraint; 2] = [RdEqX0, Rs1EqRa];
static RVCC_ADDI_NOP: [RvcConstraint; 3] = [RdEqX0, Rs1EqX0, ImmEqZero];
static RVCC_RDCYCLE: [RvcConstraint; 2] = [Rs1EqX0, CsrEq0xc00];
static RVCC_RDTIME: [RvcConstraint; 2] = [Rs1EqX0, CsrEq0xc01];
static RVCC_RDINSTRET: [RvcConstraint; 2] = [Rs1EqX0, CsrEq0xc02];
static RVCC_RDCYCLEH: [RvcConstraint; 2] = [Rs1EqX0, CsrRq0xc80];
static RVCC_RDTIMEH: [RvcConstraint; 2] = [Rs1EqX0, CsrEq0xc81];
static RVCC_RDINSTRETH: [RvcConstraint; 2] = [Rs1EqX0, CsrEq0xc82];
static RVCC_FRCSR: [RvcConstraint; 2] = [Rs1EqX0, CsrEq0x003];
static RVCC_FRRM: [RvcConstraint; 2] = [Rs1EqX0, CsrEq0x002];
static RVCC_FRFLAGS: [RvcConstraint; 2] = [Rs1EqX0, CsrEq0x001];
static RVCC_FSCSR: [RvcConstraint; 1] = [CsrEq0x003];
static RVCC_FSRM: [RvcConstraint; 1] = [CsrEq0x002];
static RVCC_FSFLAGS: [RvcConstraint; 1] = [CsrEq0x001];
static RVCC_FSRMI: [RvcConstraint; 1] = [CsrEq0x002];
static RVCC_FSFLAGSI: [RvcConstraint; 1] = [CsrEq0x001];
static RVCP_JAL: [RvCompData; 2] = [
    RvCompData {
        op: &RV_OPCODE_DATA_j,
        constraints: &RVCC_JAL_J,
    },
    RvCompData {
        op: &RV_OPCODE_DATA_jal,
        constraints: &RVCC_JAL_JAL,
    },
];
static RVCP_JALR: [RvCompData; 3] = [
    RvCompData {
        op: &RV_OPCODE_DATA_ret,
        constraints: &RVCC_JALR_RET,
    },
    RvCompData {
        op: &RV_OPCODE_DATA_jr,
        constraints: &RVCC_JALR_JR,
    },
    RvCompData {
        op: &RV_OPCODE_DATA_jalr,
        constraints: &RVCC_JALR_JALR,
    },
];
static RVCP_BEQ: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_beqz,
    constraints: &RVCC_RS2_EQ_X0,
}];
static RVCP_BNE: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_bnez,
    constraints: &RVCC_RS2_EQ_X0,
}];
static RVCP_BLT: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_bltz,
    constraints: &RVCC_RS2_EQ_X0,
}];
static RVCP_BGE: [RvCompData; 3] = [
    RvCompData {
        op: &RV_OPCODE_DATA_blez,
        constraints: &RVCC_RS1_EQ_X0,
    },
    RvCompData {
        op: &RV_OPCODE_DATA_bgez,
        constraints: &RVCC_RS2_EQ_X0,
    },
    RvCompData {
        op: &RV_OPCODE_DATA_ble,
        constraints: &RVCC_LAST,
    },
];
static RVCP_BLTU: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_bgtu,
    constraints: &RVCC_LAST,
}];
static RVCP_BGEU: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_bleu,
    constraints: &RVCC_LAST,
}];
static RVCP_ADDI: [RvCompData; 3] = [
    RvCompData {
        op: &RV_OPCODE_DATA_nop,
        constraints: &RVCC_ADDI_NOP,
    },
    RvCompData {
        op: &RV_OPCODE_DATA_mv,
        constraints: &RVCC_IMM_EQ_ZERO,
    },
    RvCompData {
        op: &RV_OPCODE_DATA_LI,
        constraints: &RVCC_RS1_EQ_X0,
    },
];
static RVCP_SLTIU: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_seqz,
    constraints: &RVCC_IMM_EQ_P1,
}];
static RVCP_XORI: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_not,
    constraints: &RVCC_IMM_EQ_N1,
}];
static RVCP_SUB: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_neg,
    constraints: &RVCC_RS1_EQ_X0,
}];
static RVCP_SLT: [RvCompData; 2] = [
    RvCompData {
        op: &RV_OPCODE_DATA_sltz,
        constraints: &RVCC_RS2_EQ_X0,
    },
    RvCompData {
        op: &RV_OPCODE_DATA_sgtz,
        constraints: &RVCC_RS1_EQ_X0,
    },
];
static RVCP_SLTU: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_snez,
    constraints: &RVCC_RS1_EQ_X0,
}];
static RVCP_ADDIW: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_sext_w,
    constraints: &RVCC_IMM_EQ_ZERO,
}];
static RVCP_SUBW: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_negw,
    constraints: &RVCC_RS1_EQ_X0,
}];
static RVCP_ADDUW: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_zextw,
    constraints: &RVCC_RS2_EQ_X0,
}];
static RVCP_CSRRW: [RvCompData; 3] = [
    RvCompData {
        op: &RV_OPCODE_DATA_FSCSR,
        constraints: &RVCC_FSCSR,
    },
    RvCompData {
        op: &RV_OPCODE_DATA_FSRM,
        constraints: &RVCC_FSRM,
    },
    RvCompData {
        op: &RV_OPCODE_DATA_FSFLAGS,
        constraints: &RVCC_FSFLAGS,
    },
];
static RVCP_CSRRS: [RvCompData; 9] = [
    RvCompData {
        op: &RV_OPCODE_DATA_rdcycle,
        constraints: &RVCC_RDCYCLE,
    },
    RvCompData {
        op: &RV_OPCODE_DATA_rdtime,
        constraints: &RVCC_RDTIME,
    },
    RvCompData {
        op: &RV_OPCODE_DATA_rdinstret,
        constraints: &RVCC_RDINSTRET,
    },
    RvCompData {
        op: &RV_OPCODE_DATA_rdcycleh,
        constraints: &RVCC_RDCYCLEH,
    },
    RvCompData {
        op: &RV_OPCODE_DATA_rdtimeh,
        constraints: &RVCC_RDTIMEH,
    },
    RvCompData {
        op: &RV_OPCODE_DATA_rdinstreth,
        constraints: &RVCC_RDINSTRETH,
    },
    RvCompData {
        op: &RV_OPCODE_DATA_frcsr,
        constraints: &RVCC_FRCSR,
    },
    RvCompData {
        op: &RV_OPCODE_DATA_frrm,
        constraints: &RVCC_FRRM,
    },
    RvCompData {
        op: &RV_OPCODE_DATA_FRFLAGS,
        constraints: &RVCC_FRFLAGS,
    },
];
static RVCP_CSRRWI: [RvCompData; 2] = [
    RvCompData {
        op: &RV_OPCODE_DATA_FSRMI,
        constraints: &RVCC_FSRMI,
    },
    RvCompData {
        op: &RV_OPCODE_DATA_FSFLAGSI,
        constraints: &RVCC_FSFLAGSI,
    },
];
static RVCP_FSGNJ_S: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_fmvs,
    constraints: &RVCC_RS2_EQ_RS1,
}];
static RVCP_FSGNJN_S: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_fneg_s,
    constraints: &RVCC_RS2_EQ_RS1,
}];
static RVCP_FSGNJX_S: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_fabss,
    constraints: &RVCC_RS2_EQ_RS1,
}];
static RVCP_FSGNJ_D: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_fmvd,
    constraints: &RVCC_RS2_EQ_RS1,
}];
static RVCP_FSGNJN_D: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_fnegd,
    constraints: &RVCC_RS2_EQ_RS1,
}];
static RVCP_FSGNJX_D: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_fabsd,
    constraints: &RVCC_RS2_EQ_RS1,
}];
static RVCP_FSGNJ_Q: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_fmvq,
    constraints: &RVCC_RS2_EQ_RS1,
}];
static RVCP_FSGNJN_Q: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_fnegq,
    constraints: &RVCC_RS2_EQ_RS1,
}];
static RVCP_FSGNJX_Q: [RvCompData; 1] = [RvCompData {
    op: &RV_OPCODE_DATA_fabsq,
    constraints: &RVCC_RS2_EQ_RS1,
}];

static RV_OPCODE_DATA_ILLEGAL: RvOpcodeData = RvOpcodeData {
    name: "illegal",
    codec: RvCodec::Illegal,
    format: RV_FMT_NONE,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_lui: RvOpcodeData = RvOpcodeData {
    name: "lui",
    codec: RvCodec::U,
    format: RV_FMT_RD_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_auipc: RvOpcodeData = RvOpcodeData {
    name: "auipc",
    codec: RvCodec::U,
    format: RV_FMT_RD_OFFSET,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_jal: RvOpcodeData = RvOpcodeData {
    name: "jal",
    codec: RvCodec::Uj,
    format: RV_FMT_RD_OFFSET,
    pseudo: Some(&RVCP_JAL),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_jalr: RvOpcodeData = RvOpcodeData {
    name: "jalr",
    codec: RvCodec::I,
    format: RV_FMT_RD_RS1_OFFSET,
    pseudo: Some(&RVCP_JALR),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_beq: RvOpcodeData = RvOpcodeData {
    name: "beq",
    codec: RvCodec::SB,
    format: RV_FMT_RS1_RS2_OFFSET,
    pseudo: Some(&RVCP_BEQ),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_bne: RvOpcodeData = RvOpcodeData {
    name: "bne",
    codec: RvCodec::SB,
    format: RV_FMT_RS1_RS2_OFFSET,
    pseudo: Some(&RVCP_BNE),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_blt: RvOpcodeData = RvOpcodeData {
    name: "blt",
    codec: RvCodec::SB,
    format: RV_FMT_RS1_RS2_OFFSET,
    pseudo: Some(&RVCP_BLT),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_bge: RvOpcodeData = RvOpcodeData {
    name: "bge",
    codec: RvCodec::SB,
    format: RV_FMT_RS1_RS2_OFFSET,
    pseudo: Some(&RVCP_BGE),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_bltu: RvOpcodeData = RvOpcodeData {
    name: "bltu",
    codec: RvCodec::SB,
    format: RV_FMT_RS1_RS2_OFFSET,
    pseudo: Some(&RVCP_BLTU),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_bgeu: RvOpcodeData = RvOpcodeData {
    name: "bgeu",
    codec: RvCodec::SB,
    format: RV_FMT_RS1_RS2_OFFSET,
    pseudo: Some(&RVCP_BGEU),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_lb: RvOpcodeData = RvOpcodeData {
    name: "lb",
    codec: RvCodec::I,
    format: RV_FMT_RD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_lh: RvOpcodeData = RvOpcodeData {
    name: "lh",
    codec: RvCodec::I,
    format: RV_FMT_RD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_lw: RvOpcodeData = RvOpcodeData {
    name: "lw",
    codec: RvCodec::I,
    format: RV_FMT_RD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_lbu: RvOpcodeData = RvOpcodeData {
    name: "lbu",
    codec: RvCodec::I,
    format: RV_FMT_RD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_lhu: RvOpcodeData = RvOpcodeData {
    name: "lhu",
    codec: RvCodec::I,
    format: RV_FMT_RD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sb: RvOpcodeData = RvOpcodeData {
    name: "sb",
    codec: RvCodec::S,
    format: RV_FMT_RS2_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sh: RvOpcodeData = RvOpcodeData {
    name: "sh",
    codec: RvCodec::S,
    format: RV_FMT_RS2_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sw: RvOpcodeData = RvOpcodeData {
    name: "sw",
    codec: RvCodec::S,
    format: RV_FMT_RS2_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_addi: RvOpcodeData = RvOpcodeData {
    name: "addi",
    codec: RvCodec::I,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: Some(&RVCP_ADDI),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_slti: RvOpcodeData = RvOpcodeData {
    name: "slti",
    codec: RvCodec::I,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sltiu: RvOpcodeData = RvOpcodeData {
    name: "sltiu",
    codec: RvCodec::I,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: Some(&RVCP_SLTIU),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_xori: RvOpcodeData = RvOpcodeData {
    name: "xori",
    codec: RvCodec::I,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: Some(&RVCP_XORI),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_ori: RvOpcodeData = RvOpcodeData {
    name: "ori",
    codec: RvCodec::I,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_andi: RvOpcodeData = RvOpcodeData {
    name: "andi",
    codec: RvCodec::I,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_slli: RvOpcodeData = RvOpcodeData {
    name: "slli",
    codec: RvCodec::ISh7,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_srli: RvOpcodeData = RvOpcodeData {
    name: "srli",
    codec: RvCodec::ISh7,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_srai: RvOpcodeData = RvOpcodeData {
    name: "srai",
    codec: RvCodec::ISh7,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_add: RvOpcodeData = RvOpcodeData {
    name: "add",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sub: RvOpcodeData = RvOpcodeData {
    name: "sub",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: Some(&RVCP_SUB),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sll: RvOpcodeData = RvOpcodeData {
    name: "sll",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_slt: RvOpcodeData = RvOpcodeData {
    name: "slt",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: Some(&RVCP_SLT),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sltu: RvOpcodeData = RvOpcodeData {
    name: "sltu",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: Some(&RVCP_SLTU),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_xor: RvOpcodeData = RvOpcodeData {
    name: "xor",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_srl: RvOpcodeData = RvOpcodeData {
    name: "srl",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sra: RvOpcodeData = RvOpcodeData {
    name: "sra",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_or: RvOpcodeData = RvOpcodeData {
    name: "or",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_and: RvOpcodeData = RvOpcodeData {
    name: "and",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fence: RvOpcodeData = RvOpcodeData {
    name: "fence",
    codec: RvCodec::RF,
    format: RV_FMT_PRED_SUCC,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fencei: RvOpcodeData = RvOpcodeData {
    name: "fence.i",
    codec: RvCodec::None,
    format: RV_FMT_NONE,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_lwu: RvOpcodeData = RvOpcodeData {
    name: "lwu",
    codec: RvCodec::I,
    format: RV_FMT_RD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_ld: RvOpcodeData = RvOpcodeData {
    name: "ld",
    codec: RvCodec::I,
    format: RV_FMT_RD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sd: RvOpcodeData = RvOpcodeData {
    name: "sd",
    codec: RvCodec::S,
    format: RV_FMT_RS2_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_addiw: RvOpcodeData = RvOpcodeData {
    name: "addiw",
    codec: RvCodec::I,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: Some(&RVCP_ADDIW),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_slliw: RvOpcodeData = RvOpcodeData {
    name: "slliw",
    codec: RvCodec::ISh5,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_srliw: RvOpcodeData = RvOpcodeData {
    name: "srliw",
    codec: RvCodec::ISh5,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sraiw: RvOpcodeData = RvOpcodeData {
    name: "sraiw",
    codec: RvCodec::ISh5,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_addw: RvOpcodeData = RvOpcodeData {
    name: "addw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_subw: RvOpcodeData = RvOpcodeData {
    name: "subw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: Some(&RVCP_SUBW),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sllw: RvOpcodeData = RvOpcodeData {
    name: "sllw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_srlw: RvOpcodeData = RvOpcodeData {
    name: "srlw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sraw: RvOpcodeData = RvOpcodeData {
    name: "sraw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_ldu: RvOpcodeData = RvOpcodeData {
    name: "ldu",
    codec: RvCodec::I,
    format: RV_FMT_RD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_lq: RvOpcodeData = RvOpcodeData {
    name: "lq",
    codec: RvCodec::I,
    format: RV_FMT_RD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sq: RvOpcodeData = RvOpcodeData {
    name: "sq",
    codec: RvCodec::S,
    format: RV_FMT_RS2_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_addid: RvOpcodeData = RvOpcodeData {
    name: "addid",
    codec: RvCodec::I,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sllid: RvOpcodeData = RvOpcodeData {
    name: "sllid",
    codec: RvCodec::ISh6,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_srlid: RvOpcodeData = RvOpcodeData {
    name: "srlid",
    codec: RvCodec::ISh6,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sraid: RvOpcodeData = RvOpcodeData {
    name: "sraid",
    codec: RvCodec::ISh6,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_addd: RvOpcodeData = RvOpcodeData {
    name: "addd",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_subd: RvOpcodeData = RvOpcodeData {
    name: "subd",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_slld: RvOpcodeData = RvOpcodeData {
    name: "slld",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_srld: RvOpcodeData = RvOpcodeData {
    name: "srld",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_srad: RvOpcodeData = RvOpcodeData {
    name: "srad",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_mul: RvOpcodeData = RvOpcodeData {
    name: "mul",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_mulh: RvOpcodeData = RvOpcodeData {
    name: "mulh",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_mulhsu: RvOpcodeData = RvOpcodeData {
    name: "mulhsu",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_mulhu: RvOpcodeData = RvOpcodeData {
    name: "mulhu",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_div: RvOpcodeData = RvOpcodeData {
    name: "div",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_divu: RvOpcodeData = RvOpcodeData {
    name: "divu",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_rem: RvOpcodeData = RvOpcodeData {
    name: "rem",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_remu: RvOpcodeData = RvOpcodeData {
    name: "remu",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_mulw: RvOpcodeData = RvOpcodeData {
    name: "mulw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_divw: RvOpcodeData = RvOpcodeData {
    name: "divw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_divuw: RvOpcodeData = RvOpcodeData {
    name: "divuw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_remw: RvOpcodeData = RvOpcodeData {
    name: "remw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_remuw: RvOpcodeData = RvOpcodeData {
    name: "remuw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_muld: RvOpcodeData = RvOpcodeData {
    name: "muld",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_divd: RvOpcodeData = RvOpcodeData {
    name: "divd",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_divud: RvOpcodeData = RvOpcodeData {
    name: "divud",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_remd: RvOpcodeData = RvOpcodeData {
    name: "remd",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_remud: RvOpcodeData = RvOpcodeData {
    name: "remud",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_lrw: RvOpcodeData = RvOpcodeData {
    name: "lr.w",
    codec: RvCodec::RL,
    format: RV_FMT_AQRL_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_scw: RvOpcodeData = RvOpcodeData {
    name: "sc.w",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amoswapw: RvOpcodeData = RvOpcodeData {
    name: "amoswap.w",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amoaddw: RvOpcodeData = RvOpcodeData {
    name: "amoadd.w",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amoxorw: RvOpcodeData = RvOpcodeData {
    name: "amoxor.w",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amoorw: RvOpcodeData = RvOpcodeData {
    name: "amoor.w",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amoandw: RvOpcodeData = RvOpcodeData {
    name: "amoand.w",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amominw: RvOpcodeData = RvOpcodeData {
    name: "amomin.w",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amomaxw: RvOpcodeData = RvOpcodeData {
    name: "amomax.w",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amominuw: RvOpcodeData = RvOpcodeData {
    name: "amominu.w",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amomaxuw: RvOpcodeData = RvOpcodeData {
    name: "amomaxu.w",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_lrd: RvOpcodeData = RvOpcodeData {
    name: "lr.d",
    codec: RvCodec::RL,
    format: RV_FMT_AQRL_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_scd: RvOpcodeData = RvOpcodeData {
    name: "sc.d",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amoswapd: RvOpcodeData = RvOpcodeData {
    name: "amoswap.d",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amoaddd: RvOpcodeData = RvOpcodeData {
    name: "amoadd.d",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amoxord: RvOpcodeData = RvOpcodeData {
    name: "amoxor.d",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amoord: RvOpcodeData = RvOpcodeData {
    name: "amoor.d",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amoandd: RvOpcodeData = RvOpcodeData {
    name: "amoand.d",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amomind: RvOpcodeData = RvOpcodeData {
    name: "amomin.d",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amomaxd: RvOpcodeData = RvOpcodeData {
    name: "amomax.d",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amominud: RvOpcodeData = RvOpcodeData {
    name: "amominu.d",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amomaxud: RvOpcodeData = RvOpcodeData {
    name: "amomaxu.d",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_lrq: RvOpcodeData = RvOpcodeData {
    name: "lr.q",
    codec: RvCodec::RL,
    format: RV_FMT_AQRL_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_scq: RvOpcodeData = RvOpcodeData {
    name: "sc.q",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amoswapq: RvOpcodeData = RvOpcodeData {
    name: "amoswap.q",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amoaddq: RvOpcodeData = RvOpcodeData {
    name: "amoadd.q",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amoxorq: RvOpcodeData = RvOpcodeData {
    name: "amoxor.q",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amoorq: RvOpcodeData = RvOpcodeData {
    name: "amoor.q",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amoandq: RvOpcodeData = RvOpcodeData {
    name: "amoand.q",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amominq: RvOpcodeData = RvOpcodeData {
    name: "amomin.q",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amomaxq: RvOpcodeData = RvOpcodeData {
    name: "amomax.q",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amominuq: RvOpcodeData = RvOpcodeData {
    name: "amominu.q",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_amomaxuq: RvOpcodeData = RvOpcodeData {
    name: "amomaxu.q",
    codec: RvCodec::RA,
    format: RV_FMT_AQRL_RD_RS2_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_ecall: RvOpcodeData = RvOpcodeData {
    name: "ecall",
    codec: RvCodec::None,
    format: RV_FMT_NONE,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_ebreak: RvOpcodeData = RvOpcodeData {
    name: "ebreak",
    codec: RvCodec::None,
    format: RV_FMT_NONE,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_uret: RvOpcodeData = RvOpcodeData {
    name: "uret",
    codec: RvCodec::None,
    format: RV_FMT_NONE,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sret: RvOpcodeData = RvOpcodeData {
    name: "sret",
    codec: RvCodec::None,
    format: RV_FMT_NONE,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_hret: RvOpcodeData = RvOpcodeData {
    name: "hret",
    codec: RvCodec::None,
    format: RV_FMT_NONE,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_mret: RvOpcodeData = RvOpcodeData {
    name: "mret",
    codec: RvCodec::None,
    format: RV_FMT_NONE,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_dret: RvOpcodeData = RvOpcodeData {
    name: "dret",
    codec: RvCodec::None,
    format: RV_FMT_NONE,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sfencevm: RvOpcodeData = RvOpcodeData {
    name: "sfence.vm",
    codec: RvCodec::R,
    format: RV_FMT_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sfencevma: RvOpcodeData = RvOpcodeData {
    name: "sfence.vma",
    codec: RvCodec::R,
    format: RV_FMT_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_wfi: RvOpcodeData = RvOpcodeData {
    name: "wfi",
    codec: RvCodec::None,
    format: RV_FMT_NONE,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_csrrw: RvOpcodeData = RvOpcodeData {
    name: "csrrw",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD_CSR_RS1,
    pseudo: Some(&RVCP_CSRRW),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_csrrs: RvOpcodeData = RvOpcodeData {
    name: "csrrs",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD_CSR_RS1,
    pseudo: Some(&RVCP_CSRRS),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_csrrc: RvOpcodeData = RvOpcodeData {
    name: "csrrc",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD_CSR_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_csrrwi: RvOpcodeData = RvOpcodeData {
    name: "csrrwi",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD_CSR_ZIMM,
    pseudo: Some(&RVCP_CSRRWI),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_csrrsi: RvOpcodeData = RvOpcodeData {
    name: "csrrsi",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD_CSR_ZIMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_csrrci: RvOpcodeData = RvOpcodeData {
    name: "csrrci",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD_CSR_ZIMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_flw: RvOpcodeData = RvOpcodeData {
    name: "flw",
    codec: RvCodec::I,
    format: RV_FMT_FRD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fsw: RvOpcodeData = RvOpcodeData {
    name: "fsw",
    codec: RvCodec::S,
    format: RV_FMT_FRS2_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmadds: RvOpcodeData = RvOpcodeData {
    name: "fmadd.s",
    codec: RvCodec::R4M,
    format: RV_FMT_RM_FRD_FRS1_FRS2_FRS3,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmsubs: RvOpcodeData = RvOpcodeData {
    name: "fmsub.s",
    codec: RvCodec::R4M,
    format: RV_FMT_RM_FRD_FRS1_FRS2_FRS3,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fnmsubs: RvOpcodeData = RvOpcodeData {
    name: "fnmsub.s",
    codec: RvCodec::R4M,
    format: RV_FMT_RM_FRD_FRS1_FRS2_FRS3,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fnmadds: RvOpcodeData = RvOpcodeData {
    name: "fnmadd.s",
    codec: RvCodec::R4M,
    format: RV_FMT_RM_FRD_FRS1_FRS2_FRS3,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fadds: RvOpcodeData = RvOpcodeData {
    name: "fadd.s",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fsubs: RvOpcodeData = RvOpcodeData {
    name: "fsub.s",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmuls: RvOpcodeData = RvOpcodeData {
    name: "fmul.s",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fdivs: RvOpcodeData = RvOpcodeData {
    name: "fdiv.s",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fsgnjs: RvOpcodeData = RvOpcodeData {
    name: "fsgnj.s",
    codec: RvCodec::R,
    format: RV_FMT_FRD_FRS1_FRS2,
    pseudo: Some(&RVCP_FSGNJ_S),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fsgnjns: RvOpcodeData = RvOpcodeData {
    name: "fsgnjn.s",
    codec: RvCodec::R,
    format: RV_FMT_FRD_FRS1_FRS2,
    pseudo: Some(&RVCP_FSGNJN_S),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fsgnjxs: RvOpcodeData = RvOpcodeData {
    name: "fsgnjx.s",
    codec: RvCodec::R,
    format: RV_FMT_FRD_FRS1_FRS2,
    pseudo: Some(&RVCP_FSGNJX_S),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmins: RvOpcodeData = RvOpcodeData {
    name: "fmin.s",
    codec: RvCodec::R,
    format: RV_FMT_FRD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmaxs: RvOpcodeData = RvOpcodeData {
    name: "fmax.s",
    codec: RvCodec::R,
    format: RV_FMT_FRD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fsqrts: RvOpcodeData = RvOpcodeData {
    name: "fsqrt.s",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fles: RvOpcodeData = RvOpcodeData {
    name: "fle.s",
    codec: RvCodec::R,
    format: RV_FMT_RD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_flts: RvOpcodeData = RvOpcodeData {
    name: "flt.s",
    codec: RvCodec::R,
    format: RV_FMT_RD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_feqs: RvOpcodeData = RvOpcodeData {
    name: "feq.s",
    codec: RvCodec::R,
    format: RV_FMT_RD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtws: RvOpcodeData = RvOpcodeData {
    name: "fcvt.w.s",
    codec: RvCodec::RM,
    format: RV_FMT_RM_RD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtwus: RvOpcodeData = RvOpcodeData {
    name: "fcvt.wu.s",
    codec: RvCodec::RM,
    format: RV_FMT_RM_RD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtsw: RvOpcodeData = RvOpcodeData {
    name: "fcvt.s.w",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtswu: RvOpcodeData = RvOpcodeData {
    name: "fcvt.s.wu",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmvxs: RvOpcodeData = RvOpcodeData {
    name: "fmv.x.s",
    codec: RvCodec::R,
    format: RV_FMT_RD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fclasss: RvOpcodeData = RvOpcodeData {
    name: "fclass.s",
    codec: RvCodec::R,
    format: RV_FMT_RD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmvsx: RvOpcodeData = RvOpcodeData {
    name: "fmv.s.x",
    codec: RvCodec::R,
    format: RV_FMT_FRD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtls: RvOpcodeData = RvOpcodeData {
    name: "fcvt.l.s",
    codec: RvCodec::RM,
    format: RV_FMT_RM_RD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtlus: RvOpcodeData = RvOpcodeData {
    name: "fcvt.lu.s",
    codec: RvCodec::RM,
    format: RV_FMT_RM_RD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtsl: RvOpcodeData = RvOpcodeData {
    name: "fcvt.s.l",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtslu: RvOpcodeData = RvOpcodeData {
    name: "fcvt.s.lu",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_FLD: RvOpcodeData = RvOpcodeData {
    name: "fld",
    codec: RvCodec::I,
    format: RV_FMT_FRD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fsd: RvOpcodeData = RvOpcodeData {
    name: "fsd",
    codec: RvCodec::S,
    format: RV_FMT_FRS2_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmaddd: RvOpcodeData = RvOpcodeData {
    name: "fmadd.d",
    codec: RvCodec::R4M,
    format: RV_FMT_RM_FRD_FRS1_FRS2_FRS3,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmsubd: RvOpcodeData = RvOpcodeData {
    name: "fmsub.d",
    codec: RvCodec::R4M,
    format: RV_FMT_RM_FRD_FRS1_FRS2_FRS3,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fnmsubd: RvOpcodeData = RvOpcodeData {
    name: "fnmsub.d",
    codec: RvCodec::R4M,
    format: RV_FMT_RM_FRD_FRS1_FRS2_FRS3,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fnmaddd: RvOpcodeData = RvOpcodeData {
    name: "fnmadd.d",
    codec: RvCodec::R4M,
    format: RV_FMT_RM_FRD_FRS1_FRS2_FRS3,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_faddd: RvOpcodeData = RvOpcodeData {
    name: "fadd.d",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fsubd: RvOpcodeData = RvOpcodeData {
    name: "fsub.d",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmuld: RvOpcodeData = RvOpcodeData {
    name: "fmul.d",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fdivd: RvOpcodeData = RvOpcodeData {
    name: "fdiv.d",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fsgnjd: RvOpcodeData = RvOpcodeData {
    name: "fsgnj.d",
    codec: RvCodec::R,
    format: RV_FMT_FRD_FRS1_FRS2,
    pseudo: Some(&RVCP_FSGNJ_D),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fsgnjnd: RvOpcodeData = RvOpcodeData {
    name: "fsgnjn.d",
    codec: RvCodec::R,
    format: RV_FMT_FRD_FRS1_FRS2,
    pseudo: Some(&RVCP_FSGNJN_D),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fsgnjxd: RvOpcodeData = RvOpcodeData {
    name: "fsgnjx.d",
    codec: RvCodec::R,
    format: RV_FMT_FRD_FRS1_FRS2,
    pseudo: Some(&RVCP_FSGNJX_D),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmind: RvOpcodeData = RvOpcodeData {
    name: "fmin.d",
    codec: RvCodec::R,
    format: RV_FMT_FRD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmaxd: RvOpcodeData = RvOpcodeData {
    name: "fmax.d",
    codec: RvCodec::R,
    format: RV_FMT_FRD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtsd: RvOpcodeData = RvOpcodeData {
    name: "fcvt.s.d",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtds: RvOpcodeData = RvOpcodeData {
    name: "fcvt.d.s",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fsqrtd: RvOpcodeData = RvOpcodeData {
    name: "fsqrt.d",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fled: RvOpcodeData = RvOpcodeData {
    name: "fle.d",
    codec: RvCodec::R,
    format: RV_FMT_RD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fltd: RvOpcodeData = RvOpcodeData {
    name: "flt.d",
    codec: RvCodec::R,
    format: RV_FMT_RD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_feqd: RvOpcodeData = RvOpcodeData {
    name: "feq.d",
    codec: RvCodec::R,
    format: RV_FMT_RD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtwd: RvOpcodeData = RvOpcodeData {
    name: "fcvt.w.d",
    codec: RvCodec::RM,
    format: RV_FMT_RM_RD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtwud: RvOpcodeData = RvOpcodeData {
    name: "fcvt.wu.d",
    codec: RvCodec::RM,
    format: RV_FMT_RM_RD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtdw: RvOpcodeData = RvOpcodeData {
    name: "fcvt.d.w",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtdwu: RvOpcodeData = RvOpcodeData {
    name: "fcvt.d.wu",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fclassd: RvOpcodeData = RvOpcodeData {
    name: "fclass.d",
    codec: RvCodec::R,
    format: RV_FMT_RD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtld: RvOpcodeData = RvOpcodeData {
    name: "fcvt.l.d",
    codec: RvCodec::RM,
    format: RV_FMT_RM_RD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtlud: RvOpcodeData = RvOpcodeData {
    name: "fcvt.lu.d",
    codec: RvCodec::RM,
    format: RV_FMT_RM_RD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmvxd: RvOpcodeData = RvOpcodeData {
    name: "fmv.x.d",
    codec: RvCodec::R,
    format: RV_FMT_RD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtdl: RvOpcodeData = RvOpcodeData {
    name: "fcvt.d.l",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtdlu: RvOpcodeData = RvOpcodeData {
    name: "fcvt.d.lu",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmvdx: RvOpcodeData = RvOpcodeData {
    name: "fmv.d.x",
    codec: RvCodec::R,
    format: RV_FMT_FRD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_flq: RvOpcodeData = RvOpcodeData {
    name: "flq",
    codec: RvCodec::I,
    format: RV_FMT_FRD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fsq: RvOpcodeData = RvOpcodeData {
    name: "fsq",
    codec: RvCodec::S,
    format: RV_FMT_FRS2_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmaddq: RvOpcodeData = RvOpcodeData {
    name: "fmadd.q",
    codec: RvCodec::R4M,
    format: RV_FMT_RM_FRD_FRS1_FRS2_FRS3,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmsubq: RvOpcodeData = RvOpcodeData {
    name: "fmsub.q",
    codec: RvCodec::R4M,
    format: RV_FMT_RM_FRD_FRS1_FRS2_FRS3,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fnmsubq: RvOpcodeData = RvOpcodeData {
    name: "fnmsub.q",
    codec: RvCodec::R4M,
    format: RV_FMT_RM_FRD_FRS1_FRS2_FRS3,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fnmaddq: RvOpcodeData = RvOpcodeData {
    name: "fnmadd.q",
    codec: RvCodec::R4M,
    format: RV_FMT_RM_FRD_FRS1_FRS2_FRS3,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_faddq: RvOpcodeData = RvOpcodeData {
    name: "fadd.q",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fsubq: RvOpcodeData = RvOpcodeData {
    name: "fsub.q",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmulq: RvOpcodeData = RvOpcodeData {
    name: "fmul.q",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fdivq: RvOpcodeData = RvOpcodeData {
    name: "fdiv.q",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fsgnjq: RvOpcodeData = RvOpcodeData {
    name: "fsgnj.q",
    codec: RvCodec::R,
    format: RV_FMT_FRD_FRS1_FRS2,
    pseudo: Some(&RVCP_FSGNJ_Q),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fsgnjnq: RvOpcodeData = RvOpcodeData {
    name: "fsgnjn.q",
    codec: RvCodec::R,
    format: RV_FMT_FRD_FRS1_FRS2,
    pseudo: Some(&RVCP_FSGNJN_Q),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fsgnjxq: RvOpcodeData = RvOpcodeData {
    name: "fsgnjx.q",
    codec: RvCodec::R,
    format: RV_FMT_FRD_FRS1_FRS2,
    pseudo: Some(&RVCP_FSGNJX_Q),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fminq: RvOpcodeData = RvOpcodeData {
    name: "fmin.q",
    codec: RvCodec::R,
    format: RV_FMT_FRD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmaxq: RvOpcodeData = RvOpcodeData {
    name: "fmax.q",
    codec: RvCodec::R,
    format: RV_FMT_FRD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtsq: RvOpcodeData = RvOpcodeData {
    name: "fcvt.s.q",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtqs: RvOpcodeData = RvOpcodeData {
    name: "fcvt.q.s",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtdq: RvOpcodeData = RvOpcodeData {
    name: "fcvt.d.q",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtqd: RvOpcodeData = RvOpcodeData {
    name: "fcvt.q.d",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fsqrtq: RvOpcodeData = RvOpcodeData {
    name: "fsqrt.q",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fleq: RvOpcodeData = RvOpcodeData {
    name: "fle.q",
    codec: RvCodec::R,
    format: RV_FMT_RD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fltq: RvOpcodeData = RvOpcodeData {
    name: "flt.q",
    codec: RvCodec::R,
    format: RV_FMT_RD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_feqq: RvOpcodeData = RvOpcodeData {
    name: "feq.q",
    codec: RvCodec::R,
    format: RV_FMT_RD_FRS1_FRS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtwq: RvOpcodeData = RvOpcodeData {
    name: "fcvt.w.q",
    codec: RvCodec::RM,
    format: RV_FMT_RM_RD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtwuq: RvOpcodeData = RvOpcodeData {
    name: "fcvt.wu.q",
    codec: RvCodec::RM,
    format: RV_FMT_RM_RD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtqw: RvOpcodeData = RvOpcodeData {
    name: "fcvt.q.w",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtqwu: RvOpcodeData = RvOpcodeData {
    name: "fcvt.q.wu",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fclassq: RvOpcodeData = RvOpcodeData {
    name: "fclass.q",
    codec: RvCodec::R,
    format: RV_FMT_RD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtlq: RvOpcodeData = RvOpcodeData {
    name: "fcvt.l.q",
    codec: RvCodec::RM,
    format: RV_FMT_RM_RD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtluq: RvOpcodeData = RvOpcodeData {
    name: "fcvt.lu.q",
    codec: RvCodec::RM,
    format: RV_FMT_RM_RD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtql: RvOpcodeData = RvOpcodeData {
    name: "fcvt.q.l",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fcvtqlu: RvOpcodeData = RvOpcodeData {
    name: "fcvt.q.lu",
    codec: RvCodec::RM,
    format: RV_FMT_RM_FRD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmvxq: RvOpcodeData = RvOpcodeData {
    name: "fmv.x.q",
    codec: RvCodec::R,
    format: RV_FMT_RD_FRS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmvqx: RvOpcodeData = RvOpcodeData {
    name: "fmv.q.x",
    codec: RvCodec::R,
    format: RV_FMT_FRD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_caddi4spn: RvOpcodeData = RvOpcodeData {
    name: "c.addi4spn",
    codec: RvCodec::Ciw4spn,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_addi),
    decomp_rv64: Some(&RV_OPCODE_DATA_addi),
    decomp_rv128: Some(&RV_OPCODE_DATA_addi),
    check_imm_nz: true,
};
static RV_OPCODE_DATA_cfld: RvOpcodeData = RvOpcodeData {
    name: "c.fld",
    codec: RvCodec::ClLd,
    format: RV_FMT_FRD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_FLD),
    decomp_rv64: Some(&RV_OPCODE_DATA_FLD),
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_clw: RvOpcodeData = RvOpcodeData {
    name: "c.lw",
    codec: RvCodec::ClLw,
    format: RV_FMT_RD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_lw),
    decomp_rv64: Some(&RV_OPCODE_DATA_lw),
    decomp_rv128: Some(&RV_OPCODE_DATA_lw),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cflw: RvOpcodeData = RvOpcodeData {
    name: "c.flw",
    codec: RvCodec::ClLw,
    format: RV_FMT_FRD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_flw),
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cfsd: RvOpcodeData = RvOpcodeData {
    name: "c.fsd",
    codec: RvCodec::CsSd,
    format: RV_FMT_FRS2_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_fsd),
    decomp_rv64: Some(&RV_OPCODE_DATA_fsd),
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_csw: RvOpcodeData = RvOpcodeData {
    name: "c.sw",
    codec: RvCodec::CsSw,
    format: RV_FMT_RS2_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_sw),
    decomp_rv64: Some(&RV_OPCODE_DATA_sw),
    decomp_rv128: Some(&RV_OPCODE_DATA_sw),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cfsw: RvOpcodeData = RvOpcodeData {
    name: "c.fsw",
    codec: RvCodec::CsSw,
    format: RV_FMT_FRS2_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_fsw),
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cnop: RvOpcodeData = RvOpcodeData {
    name: "c.nop",
    codec: RvCodec::CiNone,
    format: RV_FMT_NONE,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_addi),
    decomp_rv64: Some(&RV_OPCODE_DATA_addi),
    decomp_rv128: Some(&RV_OPCODE_DATA_addi),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_caddi: RvOpcodeData = RvOpcodeData {
    name: "c.addi",
    codec: RvCodec::Ci,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_addi),
    decomp_rv64: Some(&RV_OPCODE_DATA_addi),
    decomp_rv128: Some(&RV_OPCODE_DATA_addi),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cjal: RvOpcodeData = RvOpcodeData {
    name: "c.jal",
    codec: RvCodec::CjJal,
    format: RV_FMT_RD_OFFSET,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_jal),
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cli: RvOpcodeData = RvOpcodeData {
    name: "c.li",
    codec: RvCodec::CiLi,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_addi),
    decomp_rv64: Some(&RV_OPCODE_DATA_addi),
    decomp_rv128: Some(&RV_OPCODE_DATA_addi),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_caddi16sp: RvOpcodeData = RvOpcodeData {
    name: "c.addi16sp",
    codec: RvCodec::Ci16sp,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_addi),
    decomp_rv64: Some(&RV_OPCODE_DATA_addi),
    decomp_rv128: Some(&RV_OPCODE_DATA_addi),
    check_imm_nz: true,
};
static RV_OPCODE_DATA_clui: RvOpcodeData = RvOpcodeData {
    name: "c.lui",
    codec: RvCodec::CiLui,
    format: RV_FMT_RD_IMM,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_lui),
    decomp_rv64: Some(&RV_OPCODE_DATA_lui),
    decomp_rv128: Some(&RV_OPCODE_DATA_lui),
    check_imm_nz: true,
};
static RV_OPCODE_DATA_csrli: RvOpcodeData = RvOpcodeData {
    name: "c.srli",
    codec: RvCodec::CbSh6,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_srli),
    decomp_rv64: Some(&RV_OPCODE_DATA_srli),
    decomp_rv128: Some(&RV_OPCODE_DATA_srli),
    check_imm_nz: true,
};
static RV_OPCODE_DATA_csrai: RvOpcodeData = RvOpcodeData {
    name: "c.srai",
    codec: RvCodec::CbSh6,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_srai),
    decomp_rv64: Some(&RV_OPCODE_DATA_srai),
    decomp_rv128: Some(&RV_OPCODE_DATA_srai),
    check_imm_nz: true,
};
static RV_OPCODE_DATA_candi: RvOpcodeData = RvOpcodeData {
    name: "c.andi",
    codec: RvCodec::CbImm,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_andi),
    decomp_rv64: Some(&RV_OPCODE_DATA_andi),
    decomp_rv128: Some(&RV_OPCODE_DATA_andi),
    check_imm_nz: true,
};
static RV_OPCODE_DATA_csub: RvOpcodeData = RvOpcodeData {
    name: "c.sub",
    codec: RvCodec::Cs,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_sub),
    decomp_rv64: Some(&RV_OPCODE_DATA_sub),
    decomp_rv128: Some(&RV_OPCODE_DATA_sub),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cxor: RvOpcodeData = RvOpcodeData {
    name: "c.xor",
    codec: RvCodec::Cs,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_xor),
    decomp_rv64: Some(&RV_OPCODE_DATA_xor),
    decomp_rv128: Some(&RV_OPCODE_DATA_xor),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cor: RvOpcodeData = RvOpcodeData {
    name: "c.or",
    codec: RvCodec::Cs,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_or),
    decomp_rv64: Some(&RV_OPCODE_DATA_or),
    decomp_rv128: Some(&RV_OPCODE_DATA_or),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cand: RvOpcodeData = RvOpcodeData {
    name: "c.and",
    codec: RvCodec::Cs,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_and),
    decomp_rv64: Some(&RV_OPCODE_DATA_and),
    decomp_rv128: Some(&RV_OPCODE_DATA_and),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_csubw: RvOpcodeData = RvOpcodeData {
    name: "c.subw",
    codec: RvCodec::Cs,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_subw),
    decomp_rv64: Some(&RV_OPCODE_DATA_subw),
    decomp_rv128: Some(&RV_OPCODE_DATA_subw),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_caddw: RvOpcodeData = RvOpcodeData {
    name: "c.addw",
    codec: RvCodec::Cs,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_addw),
    decomp_rv64: Some(&RV_OPCODE_DATA_addw),
    decomp_rv128: Some(&RV_OPCODE_DATA_addw),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cj: RvOpcodeData = RvOpcodeData {
    name: "c.j",
    codec: RvCodec::Cj,
    format: RV_FMT_RD_OFFSET,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_jal),
    decomp_rv64: Some(&RV_OPCODE_DATA_jal),
    decomp_rv128: Some(&RV_OPCODE_DATA_jal),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cbeqz: RvOpcodeData = RvOpcodeData {
    name: "c.beqz",
    codec: RvCodec::Cb,
    format: RV_FMT_RS1_RS2_OFFSET,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_beq),
    decomp_rv64: Some(&RV_OPCODE_DATA_beq),
    decomp_rv128: Some(&RV_OPCODE_DATA_beq),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cbnez: RvOpcodeData = RvOpcodeData {
    name: "c.bnez",
    codec: RvCodec::Cb,
    format: RV_FMT_RS1_RS2_OFFSET,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_bne),
    decomp_rv64: Some(&RV_OPCODE_DATA_bne),
    decomp_rv128: Some(&RV_OPCODE_DATA_bne),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cslli: RvOpcodeData = RvOpcodeData {
    name: "c.slli",
    codec: RvCodec::CiSh6,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_slli),
    decomp_rv64: Some(&RV_OPCODE_DATA_slli),
    decomp_rv128: Some(&RV_OPCODE_DATA_slli),
    check_imm_nz: true,
};
static RV_OPCODE_DATA_cfldsp: RvOpcodeData = RvOpcodeData {
    name: "c.fldsp",
    codec: RvCodec::CiLdsp,
    format: RV_FMT_FRD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_FLD),
    decomp_rv64: Some(&RV_OPCODE_DATA_FLD),
    decomp_rv128: Some(&RV_OPCODE_DATA_FLD),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_clwsp: RvOpcodeData = RvOpcodeData {
    name: "c.lwsp",
    codec: RvCodec::CiLwsp,
    format: RV_FMT_RD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_lw),
    decomp_rv64: Some(&RV_OPCODE_DATA_lw),
    decomp_rv128: Some(&RV_OPCODE_DATA_lw),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cflwsp: RvOpcodeData = RvOpcodeData {
    name: "c.flwsp",
    codec: RvCodec::CiLwsp,
    format: RV_FMT_FRD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_flw),
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cjr: RvOpcodeData = RvOpcodeData {
    name: "c.jr",
    codec: RvCodec::CrJr,
    format: RV_FMT_RD_RS1_OFFSET,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_jalr),
    decomp_rv64: Some(&RV_OPCODE_DATA_jalr),
    decomp_rv128: Some(&RV_OPCODE_DATA_jalr),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cmv: RvOpcodeData = RvOpcodeData {
    name: "c.mv",
    codec: RvCodec::CrMv,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_addi),
    decomp_rv64: Some(&RV_OPCODE_DATA_addi),
    decomp_rv128: Some(&RV_OPCODE_DATA_addi),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cebreak: RvOpcodeData = RvOpcodeData {
    name: "c.ebreak",
    codec: RvCodec::CiNone,
    format: RV_FMT_NONE,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_ebreak),
    decomp_rv64: Some(&RV_OPCODE_DATA_ebreak),
    decomp_rv128: Some(&RV_OPCODE_DATA_ebreak),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cjalr: RvOpcodeData = RvOpcodeData {
    name: "c.jalr",
    codec: RvCodec::CrJalr,
    format: RV_FMT_RD_RS1_OFFSET,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_jalr),
    decomp_rv64: Some(&RV_OPCODE_DATA_jalr),
    decomp_rv128: Some(&RV_OPCODE_DATA_jalr),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cadd: RvOpcodeData = RvOpcodeData {
    name: "c.add",
    codec: RvCodec::Cr,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_add),
    decomp_rv64: Some(&RV_OPCODE_DATA_add),
    decomp_rv128: Some(&RV_OPCODE_DATA_add),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cfsdsp: RvOpcodeData = RvOpcodeData {
    name: "c.fsdsp",
    codec: RvCodec::CssSdsp,
    format: RV_FMT_FRS2_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_fsd),
    decomp_rv64: Some(&RV_OPCODE_DATA_fsd),
    decomp_rv128: Some(&RV_OPCODE_DATA_fsd),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cswsp: RvOpcodeData = RvOpcodeData {
    name: "c.swsp",
    codec: RvCodec::CssSwsp,
    format: RV_FMT_RS2_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_sw),
    decomp_rv64: Some(&RV_OPCODE_DATA_sw),
    decomp_rv128: Some(&RV_OPCODE_DATA_sw),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cfswsp: RvOpcodeData = RvOpcodeData {
    name: "c.fswsp",
    codec: RvCodec::CssSwsp,
    format: RV_FMT_FRS2_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: Some(&RV_OPCODE_DATA_fsw),
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cld: RvOpcodeData = RvOpcodeData {
    name: "c.ld",
    codec: RvCodec::ClLd,
    format: RV_FMT_RD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: Some(&RV_OPCODE_DATA_ld),
    decomp_rv128: Some(&RV_OPCODE_DATA_ld),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_csd: RvOpcodeData = RvOpcodeData {
    name: "c.sd",
    codec: RvCodec::CsSd,
    format: RV_FMT_RS2_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: Some(&RV_OPCODE_DATA_sd),
    decomp_rv128: Some(&RV_OPCODE_DATA_sd),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_caddiw: RvOpcodeData = RvOpcodeData {
    name: "c.addiw",
    codec: RvCodec::Ci,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: Some(&RV_OPCODE_DATA_addiw),
    decomp_rv128: Some(&RV_OPCODE_DATA_addiw),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cldsp: RvOpcodeData = RvOpcodeData {
    name: "c.ldsp",
    codec: RvCodec::CiLdsp,
    format: RV_FMT_RD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: Some(&RV_OPCODE_DATA_ld),
    decomp_rv128: Some(&RV_OPCODE_DATA_ld),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_csdsp: RvOpcodeData = RvOpcodeData {
    name: "c.sdsp",
    codec: RvCodec::CssSdsp,
    format: RV_FMT_RS2_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: Some(&RV_OPCODE_DATA_sd),
    decomp_rv128: Some(&RV_OPCODE_DATA_sd),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_clq: RvOpcodeData = RvOpcodeData {
    name: "c.lq",
    codec: RvCodec::ClLq,
    format: RV_FMT_RD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: Some(&RV_OPCODE_DATA_lq),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_csq: RvOpcodeData = RvOpcodeData {
    name: "c.sq",
    codec: RvCodec::CsSq,
    format: RV_FMT_RS2_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: Some(&RV_OPCODE_DATA_sq),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_clqsp: RvOpcodeData = RvOpcodeData {
    name: "c.lqsp",
    codec: RvCodec::CiLqsp,
    format: RV_FMT_RD_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: Some(&RV_OPCODE_DATA_lq),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_csqsp: RvOpcodeData = RvOpcodeData {
    name: "c.sqsp",
    codec: RvCodec::CssSqsp,
    format: RV_FMT_RS2_OFFSET_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: Some(&RV_OPCODE_DATA_sq),
    check_imm_nz: false,
};
static RV_OPCODE_DATA_nop: RvOpcodeData = RvOpcodeData {
    name: "nop",
    codec: RvCodec::I,
    format: RV_FMT_NONE,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_mv: RvOpcodeData = RvOpcodeData {
    name: "mv",
    codec: RvCodec::I,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_not: RvOpcodeData = RvOpcodeData {
    name: "not",
    codec: RvCodec::I,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_neg: RvOpcodeData = RvOpcodeData {
    name: "neg",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_negw: RvOpcodeData = RvOpcodeData {
    name: "negw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sext_w: RvOpcodeData = RvOpcodeData {
    name: "sext.w",
    codec: RvCodec::I,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_seqz: RvOpcodeData = RvOpcodeData {
    name: "seqz",
    codec: RvCodec::I,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_snez: RvOpcodeData = RvOpcodeData {
    name: "snez",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sltz: RvOpcodeData = RvOpcodeData {
    name: "sltz",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sgtz: RvOpcodeData = RvOpcodeData {
    name: "sgtz",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmvs: RvOpcodeData = RvOpcodeData {
    name: "fmv.s",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fabss: RvOpcodeData = RvOpcodeData {
    name: "fabs.s",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fneg_s: RvOpcodeData = RvOpcodeData {
    name: "fneg.s",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmvd: RvOpcodeData = RvOpcodeData {
    name: "fmv.d",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fabsd: RvOpcodeData = RvOpcodeData {
    name: "fabs.d",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fnegd: RvOpcodeData = RvOpcodeData {
    name: "fneg.d",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fmvq: RvOpcodeData = RvOpcodeData {
    name: "fmv.q",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fabsq: RvOpcodeData = RvOpcodeData {
    name: "fabs.q",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_fnegq: RvOpcodeData = RvOpcodeData {
    name: "fneg.q",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_beqz: RvOpcodeData = RvOpcodeData {
    name: "beqz",
    codec: RvCodec::SB,
    format: RV_FMT_RS1_OFFSET,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_bnez: RvOpcodeData = RvOpcodeData {
    name: "bnez",
    codec: RvCodec::SB,
    format: RV_FMT_RS1_OFFSET,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_blez: RvOpcodeData = RvOpcodeData {
    name: "blez",
    codec: RvCodec::SB,
    format: RV_FMT_RS2_OFFSET,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_bgez: RvOpcodeData = RvOpcodeData {
    name: "bgez",
    codec: RvCodec::SB,
    format: RV_FMT_RS1_OFFSET,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_bltz: RvOpcodeData = RvOpcodeData {
    name: "bltz",
    codec: RvCodec::SB,
    format: RV_FMT_RS1_OFFSET,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
// static RV_OPCODE_DATA_bgtz: RvOpcodeData = RvOpcodeData {
//     name: "bgtz",
//     codec: RvCodec::SB,
//     format: RV_FMT_RS2_OFFSET,
//     pseudo: None,
//     decomp_rv32: None,
//     decomp_rv64: None,
//     decomp_rv128: None,
//     check_imm_n: false,
// };
static RV_OPCODE_DATA_ble: RvOpcodeData = RvOpcodeData {
    name: "ble",
    codec: RvCodec::SB,
    format: RV_FMT_RS2_RS1_OFFSET,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_bleu: RvOpcodeData = RvOpcodeData {
    name: "bleu",
    codec: RvCodec::SB,
    format: RV_FMT_RS2_RS1_OFFSET,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
// static RV_OPCODE_DATA_bgt: RvOpcodeData = RvOpcodeData {
//     name: "bgt",
//     codec: RvCodec::SB,
//     format: RV_FMT_RS2_RS1_OFFSET,
//     pseudo: None,
//     decomp_rv32: None,
//     decomp_rv64: None,
//     decomp_rv128: None,
//     check_imm_n: false,
// };
static RV_OPCODE_DATA_bgtu: RvOpcodeData = RvOpcodeData {
    name: "bgtu",
    codec: RvCodec::SB,
    format: RV_FMT_RS2_RS1_OFFSET,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_j: RvOpcodeData = RvOpcodeData {
    name: "j",
    codec: RvCodec::Uj,
    format: RV_FMT_OFFSET,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_ret: RvOpcodeData = RvOpcodeData {
    name: "ret",
    codec: RvCodec::I,
    format: RV_FMT_NONE,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_jr: RvOpcodeData = RvOpcodeData {
    name: "jr",
    codec: RvCodec::I,
    format: RV_FMT_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_rdcycle: RvOpcodeData = RvOpcodeData {
    name: "rdcycle",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_rdtime: RvOpcodeData = RvOpcodeData {
    name: "rdtime",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_rdinstret: RvOpcodeData = RvOpcodeData {
    name: "rdinstret",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_rdcycleh: RvOpcodeData = RvOpcodeData {
    name: "rdcycleh",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_rdtimeh: RvOpcodeData = RvOpcodeData {
    name: "rdtimeh",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_rdinstreth: RvOpcodeData = RvOpcodeData {
    name: "rdinstreth",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_frcsr: RvOpcodeData = RvOpcodeData {
    name: "frcsr",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_frrm: RvOpcodeData = RvOpcodeData {
    name: "frrm",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};

static RV_OPCODE_DATA_FRFLAGS: RvOpcodeData = RvOpcodeData {
    name: "frflags",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};

static RV_OPCODE_DATA_FSCSR: RvOpcodeData = RvOpcodeData {
    name: "fscsr",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};

static RV_OPCODE_DATA_FSRM: RvOpcodeData = RvOpcodeData {
    name: "fsrm",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};

static RV_OPCODE_DATA_FSFLAGS: RvOpcodeData = RvOpcodeData {
    name: "fsflags",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};

static RV_OPCODE_DATA_FSRMI: RvOpcodeData = RvOpcodeData {
    name: "fsrmi",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD_ZIMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};

static RV_OPCODE_DATA_FSFLAGSI: RvOpcodeData = RvOpcodeData {
    name: "fsflagsi",
    codec: RvCodec::ICsr,
    format: RV_FMT_RD_ZIMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};

static RV_OPCODE_DATA_LI: RvOpcodeData = RvOpcodeData {
    name: "li",
    codec: RvCodec::Li,
    format: RV_FMT_RD_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_andn: RvOpcodeData = RvOpcodeData {
    name: "andn",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_adduw: RvOpcodeData = RvOpcodeData {
    name: "add.uw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: Some(&RVCP_ADDUW),
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_bset: RvOpcodeData = RvOpcodeData {
    name: "bset",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_bseti: RvOpcodeData = RvOpcodeData {
    name: "bseti",
    codec: RvCodec::ISh5,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_bseti64: RvOpcodeData = RvOpcodeData {
    name: "bset",
    codec: RvCodec::ISh6,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_bclr: RvOpcodeData = RvOpcodeData {
    name: "bclr",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_bclri: RvOpcodeData = RvOpcodeData {
    name: "bclri",
    codec: RvCodec::ISh5,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_bclri64: RvOpcodeData = RvOpcodeData {
    name: "bclri",
    codec: RvCodec::ISh6,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_bext: RvOpcodeData = RvOpcodeData {
    name: "bext",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_bexti: RvOpcodeData = RvOpcodeData {
    name: "bexti",
    codec: RvCodec::ISh5,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_binv: RvOpcodeData = RvOpcodeData {
    name: "binv",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_binvi: RvOpcodeData = RvOpcodeData {
    name: "binvi",
    codec: RvCodec::ISh5,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_binvi64: RvOpcodeData = RvOpcodeData {
    name: "binvi",
    codec: RvCodec::ISh6,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_clmul: RvOpcodeData = RvOpcodeData {
    name: "clmul",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_clmulh: RvOpcodeData = RvOpcodeData {
    name: "clmulh",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_clmulr: RvOpcodeData = RvOpcodeData {
    name: "clmulr",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_clz: RvOpcodeData = RvOpcodeData {
    name: "clz",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_clzw: RvOpcodeData = RvOpcodeData {
    name: "clzw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cpop: RvOpcodeData = RvOpcodeData {
    name: "cpop",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_cpopw: RvOpcodeData = RvOpcodeData {
    name: "cpopw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_ctz: RvOpcodeData = RvOpcodeData {
    name: "ctz",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_ctzw: RvOpcodeData = RvOpcodeData {
    name: "ctzw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_max: RvOpcodeData = RvOpcodeData {
    name: "max",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_maxu: RvOpcodeData = RvOpcodeData {
    name: "maxu",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_min: RvOpcodeData = RvOpcodeData {
    name: "min",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_minu: RvOpcodeData = RvOpcodeData {
    name: "minu",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_orcb: RvOpcodeData = RvOpcodeData {
    name: "orc.b",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_orn: RvOpcodeData = RvOpcodeData {
    name: "orn",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_rev8: RvOpcodeData = RvOpcodeData {
    name: "rev8",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_rol: RvOpcodeData = RvOpcodeData {
    name: "rol",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_rolw: RvOpcodeData = RvOpcodeData {
    name: "rolw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_ror: RvOpcodeData = RvOpcodeData {
    name: "ror",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_rori: RvOpcodeData = RvOpcodeData {
    name: "rori",
    codec: RvCodec::ISh5,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_rori64: RvOpcodeData = RvOpcodeData {
    name: "rori",
    codec: RvCodec::ISh6,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_roriw: RvOpcodeData = RvOpcodeData {
    name: "roriw",
    codec: RvCodec::ISh5,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_rorw: RvOpcodeData = RvOpcodeData {
    name: "rorw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sext_b: RvOpcodeData = RvOpcodeData {
    name: "sext.b",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sext_h: RvOpcodeData = RvOpcodeData {
    name: "sext.h",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sh1add: RvOpcodeData = RvOpcodeData {
    name: "sh1add",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sh1adduw: RvOpcodeData = RvOpcodeData {
    name: "sh1add.uw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sh2add: RvOpcodeData = RvOpcodeData {
    name: "sh2add",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sh2adduw: RvOpcodeData = RvOpcodeData {
    name: "sh2add.uw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sh3add: RvOpcodeData = RvOpcodeData {
    name: "sh3add",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_sh3adduw: RvOpcodeData = RvOpcodeData {
    name: "sh3add.uw",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_slliuw: RvOpcodeData = RvOpcodeData {
    name: "slli.uw",
    codec: RvCodec::ISh6,
    format: RV_FMT_RD_RS1_IMM,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_xnor: RvOpcodeData = RvOpcodeData {
    name: "xnor",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1_RS2,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_zexth: RvOpcodeData = RvOpcodeData {
    name: "zext.h",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};
static RV_OPCODE_DATA_zextw: RvOpcodeData = RvOpcodeData {
    name: "zext.w",
    codec: RvCodec::R,
    format: RV_FMT_RD_RS1,
    pseudo: None,
    decomp_rv32: None,
    decomp_rv64: None,
    decomp_rv128: None,
    check_imm_nz: false,
};

pub(crate) fn csr_name(csrno: i32) -> &'static str {
    match csrno {
        0x0 => "ustatus",
        0x1 => "fflags",
        0x2 => "frm",
        0x3 => "fcsr",
        0x4 => "uie",
        0x5 => "utvec",
        0x7 => "utvt",
        0x8 => "vstart",
        0x9 => "vxsat",
        0xa => "vxrm",
        0xf => "vcsr",
        0x40 => "uscratch",
        0x41 => "uepc",
        0x42 => "ucause",
        0x43 => "utval",
        0x44 => "uip",
        0x45 => "unxti",
        0x46 => "uintstatus",
        0x48 => "uscratchcsw",
        0x49 => "uscratchcswl",
        0x100 => "sstatus",
        0x102 => "sedeleg",
        0x103 => "sideleg",
        0x104 => "sie",
        0x105 => "stvec",
        0x106 => "scounteren",
        0x107 => "stvt",
        0x10a => "senvcfg",
        0x10c => "sstateen0",
        0x10d => "sstateen1",
        0x10e => "sstateen2",
        0x10f => "sstateen3",
        0x120 => "scountinhibit",
        0x140 => "sscratch",
        0x141 => "sepc",
        0x142 => "scause",
        0x143 => "stval",
        0x144 => "sip",
        0x145 => "snxti",
        0x146 => "sintstatus",
        0x148 => "sscratchcsw",
        0x149 => "sscratchcswl",
        0x180 => "satp",
        0x200 => "vsstatus",
        0x204 => "vsie",
        0x205 => "vstvec",
        0x240 => "vsscratch",
        0x241 => "vsepc",
        0x242 => "vscause",
        0x243 => "vstval",
        0x244 => "vsip",
        0x280 => "vsatp",
        0x300 => "mstatus",
        0x301 => "misa",
        0x302 => "medeleg",
        0x303 => "mideleg",
        0x304 => "mie",
        0x305 => "mtvec",
        0x306 => "mcounteren",
        0x307 => "mtvt",
        0x30a => "menvcfg",
        0x30c => "mstateen0",
        0x30d => "mstateen1",
        0x30e => "mstateen2",
        0x30f => "mstateen3",
        0x310 => "mstatush",
        0x312 => "medelegh",
        0x31a => "menvcfgh",
        0x31c => "mstateen0h",
        0x31d => "mstateen1h",
        0x31e => "mstateen2h",
        0x31f => "mstateen3h",
        0x320 => "mcountinhibit",
        0x323 => "mhpmevent3",
        0x324 => "mhpmevent4",
        0x325 => "mhpmevent5",
        0x326 => "mhpmevent6",
        0x327 => "mhpmevent7",
        0x328 => "mhpmevent8",
        0x329 => "mhpmevent9",
        0x32a => "mhpmevent10",
        0x32b => "mhpmevent11",
        0x32c => "mhpmevent12",
        0x32d => "mhpmevent13",
        0x32e => "mhpmevent14",
        0x32f => "mhpmevent15",
        0x330 => "mhpmevent16",
        0x331 => "mhpmevent17",
        0x332 => "mhpmevent18",
        0x333 => "mhpmevent19",
        0x334 => "mhpmevent20",
        0x335 => "mhpmevent21",
        0x336 => "mhpmevent22",
        0x337 => "mhpmevent23",
        0x338 => "mhpmevent24",
        0x339 => "mhpmevent25",
        0x33a => "mhpmevent26",
        0x33b => "mhpmevent27",
        0x33c => "mhpmevent28",
        0x33d => "mhpmevent29",
        0x33e => "mhpmevent30",
        0x33f => "mhpmevent31",
        0x340 => "mscratch",
        0x341 => "mepc",
        0x342 => "mcause",
        0x343 => "mtval",
        0x344 => "mip",
        0x345 => "mnxti",
        0x346 => "mintstatus",
        0x348 => "mscratchcsw",
        0x349 => "mscratchcswl",
        0x34a => "mtinst",
        0x34b => "mtval2",
        0x3a0 => "pmpcfg0",
        0x3a1 => "pmpcfg1",
        0x3a2 => "pmpcfg2",
        0x3a3 => "pmpcfg3",
        0x3a4 => "pmpcfg4",
        0x3a5 => "pmpcfg5",
        0x3a6 => "pmpcfg6",
        0x3a7 => "pmpcfg7",
        0x3a8 => "pmpcfg8",
        0x3a9 => "pmpcfg9",
        0x3aa => "pmpcfg10",
        0x3ab => "pmpcfg11",
        0x3ac => "pmpcfg12",
        0x3ad => "pmpcfg13",
        0x3ae => "pmpcfg14",
        0x3af => "pmpcfg15",
        0x3b0 => "pmpaddr0",
        0x3b1 => "pmpaddr1",
        0x3b2 => "pmpaddr2",
        0x3b3 => "pmpaddr3",
        0x3b4 => "pmpaddr4",
        0x3b5 => "pmpaddr5",
        0x3b6 => "pmpaddr6",
        0x3b7 => "pmpaddr7",
        0x3b8 => "pmpaddr8",
        0x3b9 => "pmpaddr9",
        0x3ba => "pmpaddr10",
        0x3bb => "pmpaddr11",
        0x3bc => "pmpaddr12",
        0x3bd => "pmpaddr13",
        0x3be => "pmpaddr14",
        0x3bf => "pmpaddr15",
        0x3c0 => "pmpaddr16",
        0x3c1 => "pmpaddr17",
        0x3c2 => "pmpaddr18",
        0x3c3 => "pmpaddr19",
        0x3c4 => "pmpaddr20",
        0x3c5 => "pmpaddr21",
        0x3c6 => "pmpaddr22",
        0x3c7 => "pmpaddr23",
        0x3c8 => "pmpaddr24",
        0x3c9 => "pmpaddr25",
        0x3ca => "pmpaddr26",
        0x3cb => "pmpaddr27",
        0x3cc => "pmpaddr28",
        0x3cd => "pmpaddr29",
        0x3ce => "pmpaddr30",
        0x3cf => "pmpaddr31",
        0x3d0 => "pmpaddr32",
        0x3d1 => "pmpaddr33",
        0x3d2 => "pmpaddr34",
        0x3d3 => "pmpaddr35",
        0x3d4 => "pmpaddr36",
        0x3d5 => "pmpaddr37",
        0x3d6 => "pmpaddr38",
        0x3d7 => "pmpaddr39",
        0x3d8 => "pmpaddr40",
        0x3d9 => "pmpaddr41",
        0x3da => "pmpaddr42",
        0x3db => "pmpaddr43",
        0x3dc => "pmpaddr44",
        0x3dd => "pmpaddr45",
        0x3de => "pmpaddr46",
        0x3df => "pmpaddr47",
        0x3e0 => "pmpaddr48",
        0x3e1 => "pmpaddr49",
        0x3e2 => "pmpaddr50",
        0x3e3 => "pmpaddr51",
        0x3e4 => "pmpaddr52",
        0x3e5 => "pmpaddr53",
        0x3e6 => "pmpaddr54",
        0x3e7 => "pmpaddr55",
        0x3e8 => "pmpaddr56",
        0x3e9 => "pmpaddr57",
        0x3ea => "pmpaddr58",
        0x3eb => "pmpaddr59",
        0x3ec => "pmpaddr60",
        0x3ed => "pmpaddr61",
        0x3ee => "pmpaddr62",
        0x3ef => "pmpaddr63",
        0x5a8 => "scontext",
        0x600 => "hstatus",
        0x602 => "hedeleg",
        0x603 => "hideleg",
        0x604 => "hie",
        0x605 => "htimedelta",
        0x606 => "hcounteren",
        0x607 => "hgeie",
        0x60a => "henvcfg",
        0x60c => "hstateen0",
        0x60d => "hstateen1",
        0x60e => "hstateen2",
        0x60f => "hstateen3",
        0x612 => "hedelegh",
        0x615 => "htimedeltah",
        0x61a => "henvcfgh",
        0x61c => "hstateen0h",
        0x61d => "hstateen1h",
        0x61e => "hstateen2h",
        0x61f => "hstateen3h",
        0x643 => "htval",
        0x644 => "hip",
        0x645 => "hvip",
        0x64a => "htinst",
        0x680 => "hgatp",
        0x6a8 => "hcontext",
        0x723 => "mhpmevent3h",
        0x724 => "mhpmevent4h",
        0x725 => "mhpmevent5h",
        0x726 => "mhpmevent6h",
        0x727 => "mhpmevent7h",
        0x728 => "mhpmevent8h",
        0x729 => "mhpmevent9h",
        0x72a => "mhpmevent10h",
        0x72b => "mhpmevent11h",
        0x72c => "mhpmevent12h",
        0x72d => "mhpmevent13h",
        0x72e => "mhpmevent14h",
        0x72f => "mhpmevent15h",
        0x730 => "mhpmevent16h",
        0x731 => "mhpmevent17h",
        0x732 => "mhpmevent18h",
        0x733 => "mhpmevent19h",
        0x734 => "mhpmevent20h",
        0x735 => "mhpmevent21h",
        0x736 => "mhpmevent22h",
        0x737 => "mhpmevent23h",
        0x738 => "mhpmevent24h",
        0x739 => "mhpmevent25h",
        0x73a => "mhpmevent26h",
        0x73b => "mhpmevent27h",
        0x73c => "mhpmevent28h",
        0x73d => "mhpmevent29h",
        0x73e => "mhpmevent30h",
        0x73f => "mhpmevent31h",
        0x740 => "mnscratch",
        0x741 => "mnepc",
        0x742 => "mncause",
        0x744 => "mnstatus",
        0x747 => "mseccfg",
        0x757 => "mseccfgh",
        0x7a0 => "tselect",
        0x7a1 => "tdata1",
        0x7a2 => "tdata2",
        0x7a3 => "tdata3",
        0x7a4 => "tinfo",
        0x7a5 => "tcontrol",
        0x7a8 => "mcontext",
        0x7a9 => "mnoise",
        0x7b0 => "dcsr",
        0x7b1 => "dpc",
        0x7b2 => "dscratch0",
        0x7b3 => "dscratch1",
        0xb00 => "mcycle",
        0xb02 => "minstret",
        0xb03 => "mhpmcounter3",
        0xb04 => "mhpmcounter4",
        0xb05 => "mhpmcounter5",
        0xb06 => "mhpmcounter6",
        0xb07 => "mhpmcounter7",
        0xb08 => "mhpmcounter8",
        0xb09 => "mhpmcounter9",
        0xb0a => "mhpmcounter10",
        0xb0b => "mhpmcounter11",
        0xb0c => "mhpmcounter12",
        0xb0d => "mhpmcounter13",
        0xb0e => "mhpmcounter14",
        0xb0f => "mhpmcounter15",
        0xb10 => "mhpmcounter16",
        0xb11 => "mhpmcounter17",
        0xb12 => "mhpmcounter18",
        0xb13 => "mhpmcounter19",
        0xb14 => "mhpmcounter20",
        0xb15 => "mhpmcounter21",
        0xb16 => "mhpmcounter22",
        0xb17 => "mhpmcounter23",
        0xb18 => "mhpmcounter24",
        0xb19 => "mhpmcounter25",
        0xb1a => "mhpmcounter26",
        0xb1b => "mhpmcounter27",
        0xb1c => "mhpmcounter28",
        0xb1d => "mhpmcounter29",
        0xb1e => "mhpmcounter30",
        0xb1f => "mhpmcounter31",
        0xb80 => "mcycleh",
        0xb82 => "minstreth",
        0xb83 => "mhpmcounter3h",
        0xb84 => "mhpmcounter4h",
        0xb85 => "mhpmcounter5h",
        0xb86 => "mhpmcounter6h",
        0xb87 => "mhpmcounter7h",
        0xb88 => "mhpmcounter8h",
        0xb89 => "mhpmcounter9h",
        0xb8a => "mhpmcounter10h",
        0xb8b => "mhpmcounter11h",
        0xb8c => "mhpmcounter12h",
        0xb8d => "mhpmcounter13h",
        0xb8e => "mhpmcounter14h",
        0xb8f => "mhpmcounter15h",
        0xb90 => "mhpmcounter16h",
        0xb91 => "mhpmcounter17h",
        0xb92 => "mhpmcounter18h",
        0xb93 => "mhpmcounter19h",
        0xb94 => "mhpmcounter20h",
        0xb95 => "mhpmcounter21h",
        0xb96 => "mhpmcounter22h",
        0xb97 => "mhpmcounter23h",
        0xb98 => "mhpmcounter24h",
        0xb99 => "mhpmcounter25h",
        0xb9a => "mhpmcounter26h",
        0xb9b => "mhpmcounter27h",
        0xb9c => "mhpmcounter28h",
        0xb9d => "mhpmcounter29h",
        0xb9e => "mhpmcounter30h",
        0xb9f => "mhpmcounter31h",
        0xc00 => "cycle",
        0xc01 => "time",
        0xc02 => "instret",
        0xc03 => "hpmcounter3",
        0xc04 => "hpmcounter4",
        0xc05 => "hpmcounter5",
        0xc06 => "hpmcounter6",
        0xc07 => "hpmcounter7",
        0xc08 => "hpmcounter8",
        0xc09 => "hpmcounter9",
        0xc0a => "hpmcounter10",
        0xc0b => "hpmcounter11",
        0xc0c => "hpmcounter12",
        0xc0d => "hpmcounter13",
        0xc0e => "hpmcounter14",
        0xc0f => "hpmcounter15",
        0xc10 => "hpmcounter16",
        0xc11 => "hpmcounter17",
        0xc12 => "hpmcounter18",
        0xc13 => "hpmcounter19",
        0xc14 => "hpmcounter20",
        0xc15 => "hpmcounter21",
        0xc16 => "hpmcounter22",
        0xc17 => "hpmcounter23",
        0xc18 => "hpmcounter24",
        0xc19 => "hpmcounter25",
        0xc1a => "hpmcounter26",
        0xc1b => "hpmcounter27",
        0xc1c => "hpmcounter28",
        0xc1d => "hpmcounter29",
        0xc1e => "hpmcounter30",
        0xc1f => "hpmcounter31",
        0xc20 => "vl",
        0xc21 => "vtype",
        0xc22 => "vlenb",
        0xc80 => "cycleh",
        0xc81 => "timeh",
        0xc82 => "instreth",
        0xc83 => "hpmcounter3h",
        0xc84 => "hpmcounter4h",
        0xc85 => "hpmcounter5h",
        0xc86 => "hpmcounter6h",
        0xc87 => "hpmcounter7h",
        0xc88 => "hpmcounter8h",
        0xc89 => "hpmcounter9h",
        0xc8a => "hpmcounter10h",
        0xc8b => "hpmcounter11h",
        0xc8c => "hpmcounter12h",
        0xc8d => "hpmcounter13h",
        0xc8e => "hpmcounter14h",
        0xc8f => "hpmcounter15h",
        0xc90 => "hpmcounter16h",
        0xc91 => "hpmcounter17h",
        0xc92 => "hpmcounter18h",
        0xc93 => "hpmcounter19h",
        0xc94 => "hpmcounter20h",
        0xc95 => "hpmcounter21h",
        0xc96 => "hpmcounter22h",
        0xc97 => "hpmcounter23h",
        0xc98 => "hpmcounter24h",
        0xc99 => "hpmcounter25h",
        0xc9a => "hpmcounter26h",
        0xc9b => "hpmcounter27h",
        0xc9c => "hpmcounter28h",
        0xc9d => "hpmcounter29h",
        0xc9e => "hpmcounter30h",
        0xc9f => "hpmcounter31h",
        0xda0 => "scountovf",
        0xe12 => "hgeip",
        0xf11 => "mvendorid",
        0xf12 => "marchid",
        0xf13 => "mimpid",
        0xf14 => "mhartid",
        0xf15 => "mentropy",
        _ => "",
    }
}

fn decode_inst_opcode_compressed_0(isa: RvIsa, inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 13) & 7 {
        0 => Some(&RV_OPCODE_DATA_caddi4spn),
        1 => Some(if isa == RvIsa::Rv128 {
            &RV_OPCODE_DATA_clq
        } else {
            &RV_OPCODE_DATA_cfld
        }),
        2 => Some(&RV_OPCODE_DATA_clw),
        3 => Some(if isa == RvIsa::Rv32 {
            &RV_OPCODE_DATA_cflw
        } else {
            &RV_OPCODE_DATA_cld
        }),
        4 => None,
        5 => Some(if isa == RvIsa::Rv128 {
            &RV_OPCODE_DATA_csq
        } else {
            &RV_OPCODE_DATA_cfsd
        }),
        6 => Some(&RV_OPCODE_DATA_csw),
        7 => Some(if isa == RvIsa::Rv32 {
            &RV_OPCODE_DATA_cfsw
        } else {
            &RV_OPCODE_DATA_csd
        }),
        _ => unreachable!(),
    }
}

fn decode_inst_opcode_compressed_1(isa: RvIsa, inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 13) & 7 {
        0 => Some(match (inst >> 2) & 0x7ff {
            0 => &RV_OPCODE_DATA_cnop,
            _ => &RV_OPCODE_DATA_caddi,
        }),
        1 => Some(if isa == RvIsa::Rv32 {
            &RV_OPCODE_DATA_cjal
        } else {
            &RV_OPCODE_DATA_caddiw
        }),
        2 => Some(&RV_OPCODE_DATA_cli),
        3 => Some(match (inst >> 7) & 0x1f {
            2 => &RV_OPCODE_DATA_caddi16sp,
            _ => &RV_OPCODE_DATA_clui,
        }),
        4 => match (inst >> 10) & 3 {
            0 => Some(&RV_OPCODE_DATA_csrli),
            1 => Some(&RV_OPCODE_DATA_csrai),
            2 => Some(&RV_OPCODE_DATA_candi),
            3 => match (inst >> 10) & 4 | (inst >> 5) & 3 {
                0 => Some(&RV_OPCODE_DATA_csub),
                1 => Some(&RV_OPCODE_DATA_cxor),
                2 => Some(&RV_OPCODE_DATA_cor),
                3 => Some(&RV_OPCODE_DATA_cand),
                4 => Some(&RV_OPCODE_DATA_csubw),
                5 => Some(&RV_OPCODE_DATA_caddw),
                _ => None,
            },
            _ => unreachable!(),
        },
        5 => Some(&RV_OPCODE_DATA_cj),
        6 => Some(&RV_OPCODE_DATA_cbeqz),
        7 => Some(&RV_OPCODE_DATA_cbnez),
        _ => unreachable!(),
    }
}

fn decode_inst_opcode_compressed_2(isa: RvIsa, inst: u64) -> Option<&'static RvOpcodeData> {
    Some(match (inst >> 13) & 7 {
        0 => &RV_OPCODE_DATA_cslli,
        1 => {
            if isa == RvIsa::Rv128 {
                &RV_OPCODE_DATA_clqsp
            } else {
                &RV_OPCODE_DATA_cfldsp
            }
        }
        2 => &RV_OPCODE_DATA_clwsp,
        3 => {
            if isa == RvIsa::Rv32 {
                &RV_OPCODE_DATA_cflwsp
            } else {
                &RV_OPCODE_DATA_cldsp
            }
        }
        4 => match (inst >> 12) & 1 {
            0 => match (inst >> 2) & 0x1f {
                0 => &RV_OPCODE_DATA_cjr,
                _ => &RV_OPCODE_DATA_cmv,
            },
            1 => match (inst >> 2) & 0x1f {
                0 => match (inst >> 7) & 0x1f {
                    0 => &RV_OPCODE_DATA_cebreak,
                    _ => &RV_OPCODE_DATA_cjalr,
                },
                _ => &RV_OPCODE_DATA_cadd,
            },
            _ => unreachable!(),
        },
        5 => {
            if isa == RvIsa::Rv128 {
                &RV_OPCODE_DATA_csqsp
            } else {
                &RV_OPCODE_DATA_cfsdsp
            }
        }
        6 => &RV_OPCODE_DATA_cswsp,
        7 => {
            if isa == RvIsa::Rv32 {
                &RV_OPCODE_DATA_cfswsp
            } else {
                &RV_OPCODE_DATA_csdsp
            }
        }
        _ => unreachable!(),
    })
}

fn decode_inst_opcode_load(inst: u64) -> Option<&'static RvOpcodeData> {
    Some(match (inst >> 12) & 7 {
        0 => &RV_OPCODE_DATA_lb,
        1 => &RV_OPCODE_DATA_lh,
        2 => &RV_OPCODE_DATA_lw,
        3 => &RV_OPCODE_DATA_ld,
        4 => &RV_OPCODE_DATA_lbu,
        5 => &RV_OPCODE_DATA_lhu,
        6 => &RV_OPCODE_DATA_lwu,
        7 => &RV_OPCODE_DATA_ldu,
        _ => unreachable!(),
    })
}

fn decode_inst_opcode_load_fp(inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 12) & 7 {
        2 => Some(&RV_OPCODE_DATA_flw),
        3 => Some(&RV_OPCODE_DATA_FLD),
        4 => Some(&RV_OPCODE_DATA_flq),
        _ => None,
    }
}

fn decode_inst_opcode_misc_mem(inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 12) & 7 {
        0 => Some(&RV_OPCODE_DATA_fence),
        1 => Some(&RV_OPCODE_DATA_fencei),
        2 => Some(&RV_OPCODE_DATA_lq),
        _ => None,
    }
}

fn decode_inst_opcode_op_imm(isa: RvIsa, inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 12) & 7 {
        0 => Some(&RV_OPCODE_DATA_addi),
        1 => {
            if (inst >> 27) & 0x1f == 0 {
                Some(&RV_OPCODE_DATA_slli)
            } else if inst >> 20 == 0x600 {
                Some(&RV_OPCODE_DATA_clz)
            } else if inst >> 20 == 0x601 {
                Some(&RV_OPCODE_DATA_ctz)
            } else if inst >> 20 == 0x602 {
                Some(&RV_OPCODE_DATA_cpop)
            } else if inst >> 20 == 0x604 {
                Some(&RV_OPCODE_DATA_sext_b)
            } else if inst >> 20 == 0x605 {
                Some(&RV_OPCODE_DATA_sext_h)
            } else {
                match isa {
                    RvIsa::Rv32 => match (inst >> 25) & 0x7f {
                        0x14 => Some(&RV_OPCODE_DATA_bseti),
                        0x24 => Some(&RV_OPCODE_DATA_bclri),
                        0x34 => Some(&RV_OPCODE_DATA_binvi),
                        _ => None,
                    },
                    RvIsa::Rv64 => match (inst >> 26) & 0x3f {
                        0xa => Some(&RV_OPCODE_DATA_bseti64),
                        0x12 => Some(&RV_OPCODE_DATA_bclri64),
                        0x1a => Some(&RV_OPCODE_DATA_binvi64),
                        _ => None,
                    },
                    _ => None,
                }
            }
        }
        2 => Some(&RV_OPCODE_DATA_slti),
        3 => Some(&RV_OPCODE_DATA_sltiu),
        4 => Some(&RV_OPCODE_DATA_xori),
        5 => {
            if inst >> 20 == 0x287 {
                Some(&RV_OPCODE_DATA_orcb)
            } else if (isa == RvIsa::Rv32 && inst >> 20 == 0x698)
                || (isa == RvIsa::Rv64 && inst >> 20 == 0x6b8)
            {
                Some(&RV_OPCODE_DATA_rev8)
            } else if isa == RvIsa::Rv32 && inst >> 25 == 0x30 {
                Some(&RV_OPCODE_DATA_rori)
            } else if isa == RvIsa::Rv64 && inst >> 26 == 0x18 {
                Some(&RV_OPCODE_DATA_rori64)
            } else {
                match (inst >> 27) & 0x1f {
                    0 => Some(&RV_OPCODE_DATA_srli),
                    8 => Some(&RV_OPCODE_DATA_srai),
                    9 => Some(&RV_OPCODE_DATA_bexti),
                    _ => None,
                }
            }
        }
        6 => Some(&RV_OPCODE_DATA_ori),
        7 => Some(&RV_OPCODE_DATA_andi),
        _ => None,
    }
}

fn decode_inst_opcode_op_imm_32(inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 12) & 7 {
        0 => Some(&RV_OPCODE_DATA_addiw),
        1 => {
            if (inst >> 26) & 0x3f == 2 {
                Some(&RV_OPCODE_DATA_slliuw)
            } else if (inst >> 25) & 0x7f == 0 {
                Some(&RV_OPCODE_DATA_slliw)
            } else if inst >> 20 == 0x600 {
                Some(&RV_OPCODE_DATA_clzw)
            } else if inst >> 20 == 0x601 {
                Some(&RV_OPCODE_DATA_ctzw)
            } else if inst >> 20 == 0x602 {
                Some(&RV_OPCODE_DATA_cpopw)
            } else {
                None
            }
        }
        5 => match (inst >> 25) & 0x7f {
            0 => Some(&RV_OPCODE_DATA_srliw),
            32 => Some(&RV_OPCODE_DATA_sraiw),
            48 => Some(&RV_OPCODE_DATA_roriw),
            _ => None,
        },
        _ => None,
    }
}

fn decode_inst_opcode_store(inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 12) & 7 {
        0 => Some(&RV_OPCODE_DATA_sb),
        1 => Some(&RV_OPCODE_DATA_sh),
        2 => Some(&RV_OPCODE_DATA_sw),
        3 => Some(&RV_OPCODE_DATA_sd),
        4 => Some(&RV_OPCODE_DATA_sq),
        _ => None,
    }
}

fn decode_inst_opcode_store_fp(inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 12) & 7 {
        2 => Some(&RV_OPCODE_DATA_fsw),
        3 => Some(&RV_OPCODE_DATA_fsd),
        4 => Some(&RV_OPCODE_DATA_fsq),
        _ => None,
    }
}

fn decode_inst_opcode_amo(inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 24) & 0xf8 | (inst >> 12) & 7 {
        2 => Some(&RV_OPCODE_DATA_amoaddw),
        3 => Some(&RV_OPCODE_DATA_amoaddd),
        4 => Some(&RV_OPCODE_DATA_amoaddq),
        10 => Some(&RV_OPCODE_DATA_amoswapw),
        11 => Some(&RV_OPCODE_DATA_amoswapd),
        12 => Some(&RV_OPCODE_DATA_amoswapq),
        18 => {
            if (inst >> 20) & 0x1f == 0 {
                Some(&RV_OPCODE_DATA_lrw)
            } else {
                None
            }
        }
        19 => {
            if (inst >> 20) & 0x1f == 0 {
                Some(&RV_OPCODE_DATA_lrd)
            } else {
                None
            }
        }
        20 => {
            if (inst >> 20) & 0x1f == 0 {
                Some(&RV_OPCODE_DATA_lrq)
            } else {
                None
            }
        }
        26 => Some(&RV_OPCODE_DATA_scw),
        27 => Some(&RV_OPCODE_DATA_scd),
        28 => Some(&RV_OPCODE_DATA_scq),
        34 => Some(&RV_OPCODE_DATA_amoxorw),
        35 => Some(&RV_OPCODE_DATA_amoxord),
        36 => Some(&RV_OPCODE_DATA_amoxorq),
        66 => Some(&RV_OPCODE_DATA_amoorw),
        67 => Some(&RV_OPCODE_DATA_amoord),
        68 => Some(&RV_OPCODE_DATA_amoorq),
        98 => Some(&RV_OPCODE_DATA_amoandw),
        99 => Some(&RV_OPCODE_DATA_amoandd),
        100 => Some(&RV_OPCODE_DATA_amoandq),
        130 => Some(&RV_OPCODE_DATA_amominw),
        131 => Some(&RV_OPCODE_DATA_amomind),
        132 => Some(&RV_OPCODE_DATA_amominq),
        162 => Some(&RV_OPCODE_DATA_amomaxw),
        163 => Some(&RV_OPCODE_DATA_amomaxd),
        164 => Some(&RV_OPCODE_DATA_amomaxq),
        194 => Some(&RV_OPCODE_DATA_amominuw),
        195 => Some(&RV_OPCODE_DATA_amominud),
        196 => Some(&RV_OPCODE_DATA_amominuq),
        226 => Some(&RV_OPCODE_DATA_amomaxuw),
        227 => Some(&RV_OPCODE_DATA_amomaxud),
        228 => Some(&RV_OPCODE_DATA_amomaxuq),
        _ => None,
    }
}

fn decode_inst_opcode_op(isa: RvIsa, inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 22) & 0x3f8 | (inst >> 12) & 7 {
        0 => Some(&RV_OPCODE_DATA_add),
        1 => Some(&RV_OPCODE_DATA_sll),
        2 => Some(&RV_OPCODE_DATA_slt),
        3 => Some(&RV_OPCODE_DATA_sltu),
        4 => Some(&RV_OPCODE_DATA_xor),
        5 => Some(&RV_OPCODE_DATA_srl),
        6 => Some(&RV_OPCODE_DATA_or),
        7 => Some(&RV_OPCODE_DATA_and),
        8 => Some(&RV_OPCODE_DATA_mul),
        9 => Some(&RV_OPCODE_DATA_mulh),
        10 => Some(&RV_OPCODE_DATA_mulhsu),
        11 => Some(&RV_OPCODE_DATA_mulhu),
        12 => Some(&RV_OPCODE_DATA_div),
        13 => Some(&RV_OPCODE_DATA_divu),
        14 => Some(&RV_OPCODE_DATA_rem),
        15 => Some(&RV_OPCODE_DATA_remu),
        36 if isa == RvIsa::Rv32 && inst >> 20 == 0x080 => Some(&RV_OPCODE_DATA_zexth),
        41 => Some(&RV_OPCODE_DATA_clmul),
        42 => Some(&RV_OPCODE_DATA_clmulr),
        43 => Some(&RV_OPCODE_DATA_clmulh),
        44 => Some(&RV_OPCODE_DATA_min),
        45 => Some(&RV_OPCODE_DATA_minu),
        46 => Some(&RV_OPCODE_DATA_max),
        47 => Some(&RV_OPCODE_DATA_maxu),
        130 => Some(&RV_OPCODE_DATA_sh1add),
        132 => Some(&RV_OPCODE_DATA_sh2add),
        134 => Some(&RV_OPCODE_DATA_sh3add),
        161 => Some(&RV_OPCODE_DATA_bset),
        256 => Some(&RV_OPCODE_DATA_sub),
        260 => Some(&RV_OPCODE_DATA_xnor),
        261 => Some(&RV_OPCODE_DATA_sra),
        262 => Some(&RV_OPCODE_DATA_orn),
        263 => Some(&RV_OPCODE_DATA_andn),
        289 => Some(&RV_OPCODE_DATA_bclr),
        293 => Some(&RV_OPCODE_DATA_bext),
        385 => Some(&RV_OPCODE_DATA_rol),
        389 => Some(&RV_OPCODE_DATA_ror),
        417 => Some(&RV_OPCODE_DATA_binv),
        _ => None,
    }
}

fn decode_inst_opcode_op_32_14(inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 22) & 0x3f8 | (inst >> 12) & 7 {
        0 => Some(&RV_OPCODE_DATA_addw),
        1 => Some(&RV_OPCODE_DATA_sllw),
        5 => Some(&RV_OPCODE_DATA_srlw),
        8 => Some(&RV_OPCODE_DATA_mulw),
        12 => Some(&RV_OPCODE_DATA_divw),
        13 => Some(&RV_OPCODE_DATA_divuw),
        14 => Some(&RV_OPCODE_DATA_remw),
        15 => Some(&RV_OPCODE_DATA_remuw),
        32 => Some(&RV_OPCODE_DATA_adduw),
        36 => Some(&RV_OPCODE_DATA_zexth),
        130 => Some(&RV_OPCODE_DATA_sh1adduw),
        132 => Some(&RV_OPCODE_DATA_sh2adduw),
        134 => Some(&RV_OPCODE_DATA_sh3adduw),
        256 => Some(&RV_OPCODE_DATA_subw),
        261 => Some(&RV_OPCODE_DATA_sraw),
        385 => Some(&RV_OPCODE_DATA_rolw),
        389 => Some(&RV_OPCODE_DATA_rorw),
        _ => None,
    }
}

fn decode_inst_opcode_madd(inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 25) & 3 {
        0 => Some(&RV_OPCODE_DATA_fmadds),
        1 => Some(&RV_OPCODE_DATA_fmaddd),
        3 => Some(&RV_OPCODE_DATA_fmaddq),
        _ => None,
    }
}

fn decode_inst_opcode_msub(inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 25) & 3 {
        0 => Some(&RV_OPCODE_DATA_fmsubs),
        1 => Some(&RV_OPCODE_DATA_fmsubd),
        3 => Some(&RV_OPCODE_DATA_fmsubq),
        _ => None,
    }
}

fn decode_inst_opcode_nmsub(inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 25) & 3 {
        0 => Some(&RV_OPCODE_DATA_fnmsubs),
        1 => Some(&RV_OPCODE_DATA_fnmsubd),
        3 => Some(&RV_OPCODE_DATA_fnmsubq),
        _ => None,
    }
}

fn decode_inst_opcode_nmadd(inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 25) & 3 {
        0 => Some(&RV_OPCODE_DATA_fnmadds),
        1 => Some(&RV_OPCODE_DATA_fnmaddd),
        3 => Some(&RV_OPCODE_DATA_fnmaddq),
        _ => None,
    }
}

fn decode_inst_opcode_op_fp(inst: u64) -> Option<&'static RvOpcodeData> {
    match ((inst >> 25) & 0x7f, (inst >> 20) & 0x1f, (inst >> 12) & 7) {
        (0, _, _) => Some(&RV_OPCODE_DATA_fadds),
        (1, _, _) => Some(&RV_OPCODE_DATA_faddd),
        (3, _, _) => Some(&RV_OPCODE_DATA_faddq),
        (4, _, _) => Some(&RV_OPCODE_DATA_fsubs),
        (5, _, _) => Some(&RV_OPCODE_DATA_fsubd),
        (7, _, _) => Some(&RV_OPCODE_DATA_fsubq),
        (8, _, _) => Some(&RV_OPCODE_DATA_fmuls),
        (9, _, _) => Some(&RV_OPCODE_DATA_fmuld),
        (11, _, _) => Some(&RV_OPCODE_DATA_fmulq),
        (12, _, _) => Some(&RV_OPCODE_DATA_fdivs),
        (13, _, _) => Some(&RV_OPCODE_DATA_fdivd),
        (15, _, _) => Some(&RV_OPCODE_DATA_fdivq),
        (16, _, 0) => Some(&RV_OPCODE_DATA_fsgnjs),
        (16, _, 1) => Some(&RV_OPCODE_DATA_fsgnjns),
        (16, _, 2) => Some(&RV_OPCODE_DATA_fsgnjxs),
        (17, _, 0) => Some(&RV_OPCODE_DATA_fsgnjd),
        (17, _, 1) => Some(&RV_OPCODE_DATA_fsgnjnd),
        (17, _, 2) => Some(&RV_OPCODE_DATA_fsgnjxd),
        (19, _, 0) => Some(&RV_OPCODE_DATA_fsgnjq),
        (19, _, 1) => Some(&RV_OPCODE_DATA_fsgnjnq),
        (19, _, 2) => Some(&RV_OPCODE_DATA_fsgnjxq),
        (20, _, 0) => Some(&RV_OPCODE_DATA_fmins),
        (20, _, 1) => Some(&RV_OPCODE_DATA_fmaxs),
        (21, _, 0) => Some(&RV_OPCODE_DATA_fmind),
        (21, _, 1) => Some(&RV_OPCODE_DATA_fmaxd),
        (23, _, 0) => Some(&RV_OPCODE_DATA_fminq),
        (23, _, 1) => Some(&RV_OPCODE_DATA_fmaxq),
        (32, 1, _) => Some(&RV_OPCODE_DATA_fcvtsd),
        (32, 3, _) => Some(&RV_OPCODE_DATA_fcvtsq),
        (33, 0, _) => Some(&RV_OPCODE_DATA_fcvtds),
        (33, 3, _) => Some(&RV_OPCODE_DATA_fcvtdq),
        (35, 0, _) => Some(&RV_OPCODE_DATA_fcvtqs),
        (35, 1, _) => Some(&RV_OPCODE_DATA_fcvtqd),
        (44, 0, _) => Some(&RV_OPCODE_DATA_fsqrts),
        (45, 0, _) => Some(&RV_OPCODE_DATA_fsqrtd),
        (47, 0, _) => Some(&RV_OPCODE_DATA_fsqrtq),
        (80, _, 0) => Some(&RV_OPCODE_DATA_fles),
        (80, _, 1) => Some(&RV_OPCODE_DATA_flts),
        (80, _, 2) => Some(&RV_OPCODE_DATA_feqs),
        (81, _, 0) => Some(&RV_OPCODE_DATA_fled),
        (81, _, 1) => Some(&RV_OPCODE_DATA_fltd),
        (81, _, 2) => Some(&RV_OPCODE_DATA_feqd),
        (83, _, 0) => Some(&RV_OPCODE_DATA_fleq),
        (83, _, 1) => Some(&RV_OPCODE_DATA_fltq),
        (83, _, 2) => Some(&RV_OPCODE_DATA_feqq),
        (96, 0, _) => Some(&RV_OPCODE_DATA_fcvtws),
        (96, 1, _) => Some(&RV_OPCODE_DATA_fcvtwus),
        (96, 2, _) => Some(&RV_OPCODE_DATA_fcvtls),
        (96, 3, _) => Some(&RV_OPCODE_DATA_fcvtlus),
        (97, 0, _) => Some(&RV_OPCODE_DATA_fcvtwd),
        (97, 1, _) => Some(&RV_OPCODE_DATA_fcvtwud),
        (97, 2, _) => Some(&RV_OPCODE_DATA_fcvtld),
        (97, 3, _) => Some(&RV_OPCODE_DATA_fcvtlud),
        (99, 0, _) => Some(&RV_OPCODE_DATA_fcvtwq),
        (99, 1, _) => Some(&RV_OPCODE_DATA_fcvtwuq),
        (99, 2, _) => Some(&RV_OPCODE_DATA_fcvtlq),
        (99, 3, _) => Some(&RV_OPCODE_DATA_fcvtluq),
        (104, 0, _) => Some(&RV_OPCODE_DATA_fcvtsw),
        (104, 1, _) => Some(&RV_OPCODE_DATA_fcvtswu),
        (104, 2, _) => Some(&RV_OPCODE_DATA_fcvtsl),
        (104, 3, _) => Some(&RV_OPCODE_DATA_fcvtslu),
        (105, 0, _) => Some(&RV_OPCODE_DATA_fcvtdw),
        (105, 1, _) => Some(&RV_OPCODE_DATA_fcvtdwu),
        (105, 2, _) => Some(&RV_OPCODE_DATA_fcvtdl),
        (105, 3, _) => Some(&RV_OPCODE_DATA_fcvtdlu),
        (107, 0, _) => Some(&RV_OPCODE_DATA_fcvtqw),
        (107, 1, _) => Some(&RV_OPCODE_DATA_fcvtqwu),
        (107, 2, _) => Some(&RV_OPCODE_DATA_fcvtql),
        (107, 3, _) => Some(&RV_OPCODE_DATA_fcvtqlu),
        (112, _, _) => match (inst >> 17) & 0xf8 | (inst >> 12) & 7 {
            0 => Some(&RV_OPCODE_DATA_fmvxs),
            1 => Some(&RV_OPCODE_DATA_fclasss),
            _ => None,
        },
        (113, _, _) => match (inst >> 17) & 0xf8 | (inst >> 12) & 7 {
            0 => Some(&RV_OPCODE_DATA_fmvxd),
            1 => Some(&RV_OPCODE_DATA_fclassd),
            _ => None,
        },
        (115, _, _) => match (inst >> 17) & 0xf8 | (inst >> 12) & 7 {
            0 => Some(&RV_OPCODE_DATA_fmvxq),
            1 => Some(&RV_OPCODE_DATA_fclassq),
            _ => None,
        },
        (120, _, _) => {
            if (inst >> 17) & 0xf8 | (inst >> 12) & 7 == 0 {
                Some(&RV_OPCODE_DATA_fmvsx)
            } else {
                None
            }
        }
        (121, _, _) => {
            if (inst >> 17) & 0xf8 | (inst >> 12) & 7 == 0 {
                Some(&RV_OPCODE_DATA_fmvdx)
            } else {
                None
            }
        }
        (123, _, _) => {
            if (inst >> 17) & 0xf8 | (inst >> 12) & 7 == 0 {
                Some(&RV_OPCODE_DATA_fmvqx)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn decode_inst_opcode_custom2_rv128(inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 12) & 7 {
        0 => Some(&RV_OPCODE_DATA_addid),
        1 => {
            if (inst >> 26) & 0x3f == 0 {
                Some(&RV_OPCODE_DATA_sllid)
            } else {
                None
            }
        }
        5 => match (inst >> 26) & 0x3f {
            0 => Some(&RV_OPCODE_DATA_srlid),
            16 => Some(&RV_OPCODE_DATA_sraid),
            _ => None,
        },
        _ => None,
    }
}

fn decode_inst_opcode_branch(inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 12) & 7 {
        0 => Some(&RV_OPCODE_DATA_beq),
        1 => Some(&RV_OPCODE_DATA_bne),
        4 => Some(&RV_OPCODE_DATA_blt),
        5 => Some(&RV_OPCODE_DATA_bge),
        6 => Some(&RV_OPCODE_DATA_bltu),
        7 => Some(&RV_OPCODE_DATA_bgeu),
        _ => None,
    }
}

fn decode_inst_opcode_jalr(inst: u64) -> Option<&'static RvOpcodeData> {
    if (inst >> 12) & 7 == 0 {
        Some(&RV_OPCODE_DATA_jalr)
    } else {
        None
    }
}

fn decode_inst_opcode_system(inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 12) & 7 {
        0 => match (inst >> 20) & 0xfe0 | (inst >> 7) & 0x1f {
            0 => match (inst >> 15) & 0x3ff {
                0 => Some(&RV_OPCODE_DATA_ecall),
                32 => Some(&RV_OPCODE_DATA_ebreak),
                64 => Some(&RV_OPCODE_DATA_uret),
                _ => None,
            },
            256 => match (inst >> 20) & 0x1f {
                2 => {
                    if (inst >> 15) & 0x1f == 0 {
                        Some(&RV_OPCODE_DATA_sret)
                    } else {
                        None
                    }
                }
                4 => Some(&RV_OPCODE_DATA_sfencevm),
                5 => {
                    if (inst >> 15) & 0x1f == 0 {
                        Some(&RV_OPCODE_DATA_wfi)
                    } else {
                        None
                    }
                }
                _ => None,
            },
            288 => Some(&RV_OPCODE_DATA_sfencevma),
            512 => {
                if (inst >> 15) & 0x3ff == 64 {
                    Some(&RV_OPCODE_DATA_hret)
                } else {
                    None
                }
            }
            768 => {
                if (inst >> 15) & 0x3ff == 64 {
                    Some(&RV_OPCODE_DATA_mret)
                } else {
                    None
                }
            }
            1952 => {
                if (inst >> 15) & 0x3ff == 576 {
                    Some(&RV_OPCODE_DATA_dret)
                } else {
                    None
                }
            }
            _ => None,
        },
        1 => Some(&RV_OPCODE_DATA_csrrw),
        2 => Some(&RV_OPCODE_DATA_csrrs),
        3 => Some(&RV_OPCODE_DATA_csrrc),
        5 => Some(&RV_OPCODE_DATA_csrrwi),
        6 => Some(&RV_OPCODE_DATA_csrrsi),
        7 => Some(&RV_OPCODE_DATA_csrrci),
        _ => None,
    }
}

fn decode_inst_opcode_custom3_rv128(inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 22) & 0x3f8 | (inst >> 12) & 7 {
        0 => Some(&RV_OPCODE_DATA_addd),
        1 => Some(&RV_OPCODE_DATA_slld),
        5 => Some(&RV_OPCODE_DATA_srld),
        8 => Some(&RV_OPCODE_DATA_muld),
        12 => Some(&RV_OPCODE_DATA_divd),
        13 => Some(&RV_OPCODE_DATA_divud),
        14 => Some(&RV_OPCODE_DATA_remd),
        15 => Some(&RV_OPCODE_DATA_remud),
        256 => Some(&RV_OPCODE_DATA_subd),
        261 => Some(&RV_OPCODE_DATA_srad),
        _ => None,
    }
}

fn decode_inst_opcode_uncompressed(isa: RvIsa, inst: u64) -> Option<&'static RvOpcodeData> {
    match (inst >> 2) & 0x1f {
        0 => decode_inst_opcode_load(inst),
        1 => decode_inst_opcode_load_fp(inst),
        3 => decode_inst_opcode_misc_mem(inst),
        4 => decode_inst_opcode_op_imm(isa, inst),
        5 => Some(&RV_OPCODE_DATA_auipc),
        6 => {
            if isa == RvIsa::Rv64 {
                decode_inst_opcode_op_imm_32(inst)
            } else {
                None
            }
        }
        8 => decode_inst_opcode_store(inst),
        9 => decode_inst_opcode_store_fp(inst),
        11 => decode_inst_opcode_amo(inst),
        12 => decode_inst_opcode_op(isa, inst),
        13 => Some(&RV_OPCODE_DATA_lui),
        14 => {
            if isa == RvIsa::Rv64 {
                decode_inst_opcode_op_32_14(inst)
            } else {
                None
            }
        }
        16 => decode_inst_opcode_madd(inst),
        17 => decode_inst_opcode_msub(inst),
        18 => decode_inst_opcode_nmsub(inst),
        19 => decode_inst_opcode_nmadd(inst),
        20 => decode_inst_opcode_op_fp(inst),
        22 => decode_inst_opcode_custom2_rv128(inst),
        24 => decode_inst_opcode_branch(inst),
        25 => decode_inst_opcode_jalr(inst),
        27 => Some(&RV_OPCODE_DATA_jal),
        28 => decode_inst_opcode_system(inst),
        30 => decode_inst_opcode_custom3_rv128(inst),
        _ => None,
    }
}

fn decode_inst_opcode(dec: &mut RvDecode, isa: RvIsa) {
    let inst: RvInst = dec.inst;
    dec.op = match inst & 3 {
        0 => decode_inst_opcode_compressed_0(isa, inst),
        1 => decode_inst_opcode_compressed_1(isa, inst),
        2 => decode_inst_opcode_compressed_2(isa, inst),
        3 => decode_inst_opcode_uncompressed(isa, inst),
        _ => unreachable!(),
    }
}
fn operand_rd(inst: RvInst) -> u32 {
    (inst << 52 >> 59) as u32
}
fn operand_rs1(inst: RvInst) -> u32 {
    (inst << 44 >> 59) as u32
}
fn operand_rs2(inst: RvInst) -> u32 {
    (inst << 39 >> 59) as u32
}
fn operand_rs3(inst: RvInst) -> u32 {
    (inst << 32 >> 59) as u32
}
fn operand_aq(inst: RvInst) -> u32 {
    (inst << 37 >> 63) as u32
}
fn operand_rl(inst: RvInst) -> u32 {
    (inst << 38 >> 63) as u32
}
fn operand_pred(inst: RvInst) -> u32 {
    (inst << 36 >> 60) as u32
}
fn operand_succ(inst: RvInst) -> u32 {
    (inst << 40 >> 60) as u32
}
fn operand_rm(inst: RvInst) -> u32 {
    (inst << 49 >> 61) as u32
}
fn operand_shamt5(inst: RvInst) -> u32 {
    (inst << 39 >> 59) as u32
}
fn operand_shamt6(inst: RvInst) -> u32 {
    (inst << 38 >> 58) as u32
}
fn operand_shamt7(inst: RvInst) -> u32 {
    (inst << 37 >> 57) as u32
}
fn operand_crdq(inst: RvInst) -> u32 {
    (inst << 59 >> 61) as u32
}
fn operand_crs1q(inst: RvInst) -> u32 {
    (inst << 54 >> 61) as u32
}
fn operand_crs1rdq(inst: RvInst) -> u32 {
    (inst << 54 >> 61) as u32
}
fn operand_crs2q(inst: RvInst) -> u32 {
    (inst << 59 >> 61) as u32
}
fn operand_crd(inst: RvInst) -> u32 {
    (inst << 52 >> 59) as u32
}
fn operand_crs1(inst: RvInst) -> u32 {
    (inst << 52 >> 59) as u32
}
fn operand_crs1rd(inst: RvInst) -> u32 {
    (inst << 52 >> 59) as u32
}
fn operand_crs2(inst: RvInst) -> u32 {
    (inst << 57 >> 59) as u32
}
// fn operand_cimmsh5(inst: RvInst) -> u32 {
//     (inst << 57 >> 59) as u32
// }
fn operand_csr12(inst: RvInst) -> u32 {
    (inst << 32 >> 52) as u32
}
fn operand_imm12(inst: RvInst) -> i32 {
    ((inst as i64) << 32 >> 52) as i32
}
fn operand_imm20(inst: RvInst) -> i32 {
    (((inst as i64) << 32 >> 44) << 12) as i32
}
fn operand_jimm20(inst: RvInst) -> i32 {
    ((((inst as i64) << 32 >> 63) << 20) as u64
        | ((inst << 33 >> 54) << 1)
        | ((inst << 43 >> 63) << 11)
        | ((inst << 44 >> 56) << 12)) as i32
}
fn operand_simm12(inst: RvInst) -> i32 {
    ((((inst as i64) << 32 >> 57) << 5) as u64 | (inst << 52 >> 59)) as i32
}
fn operand_sbimm12(inst: RvInst) -> i32 {
    ((((inst as i64) << 32 >> 63) << 12) as u64
        | ((inst << 33 >> 58) << 5)
        | ((inst << 52 >> 60) << 1)
        | ((inst << 56 >> 63) << 11)) as i32
}
fn operand_cimmsh6(inst: RvInst) -> u32 {
    (((inst << 51 >> 63) << 5) | (inst << 57 >> 59)) as u32
}
fn operand_cimmi(inst: RvInst) -> i32 {
    ((((inst as i64) << 51 >> 63) << 5) as u64 | (inst << 57 >> 59)) as i32
}
fn operand_cimmui(inst: RvInst) -> i32 {
    ((((inst as i64) << 51 >> 63) << 17) as u64 | ((inst << 57 >> 59) << 12)) as i32
}
fn operand_cimmlwsp(inst: RvInst) -> u32 {
    (((inst << 51 >> 63) << 5) | ((inst << 57 >> 61) << 2) | ((inst << 60 >> 62) << 6)) as u32
}
fn operand_cimmldsp(inst: RvInst) -> u32 {
    (((inst << 51 >> 63) << 5) | ((inst << 57 >> 62) << 3) | ((inst << 59 >> 61) << 6)) as u32
}
fn operand_cimmlqsp(inst: RvInst) -> u32 {
    (((inst << 51 >> 63) << 5) | ((inst << 57 >> 63) << 4) | ((inst << 58 >> 60) << 6)) as u32
}
fn operand_cimm16sp(inst: RvInst) -> i32 {
    ((((inst as i64) << 51 >> 63) << 9) as u64
        | ((inst << 57 >> 63) << 4)
        | ((inst << 58 >> 63) << 6)
        | ((inst << 59 >> 62) << 7)
        | ((inst << 61 >> 63) << 5)) as i32
}
fn operand_cimmj(inst: RvInst) -> i32 {
    ((((inst as i64) << 51 >> 63) << 11) as u64
        | ((inst << 52 >> 63) << 4)
        | ((inst << 53 >> 62) << 8)
        | ((inst << 55 >> 63) << 10)
        | ((inst << 56 >> 63) << 6)
        | ((inst << 57 >> 63) << 7)
        | ((inst << 58 >> 61) << 1)
        | ((inst << 61 >> 63) << 5)) as i32
}
fn operand_cimmb(inst: RvInst) -> i32 {
    ((((inst as i64) << 51 >> 63) << 8) as u64
        | ((inst << 52 >> 62) << 3)
        | ((inst << 57 >> 62) << 6)
        | ((inst << 59 >> 62) << 1)
        | ((inst << 61 >> 63) << 5)) as i32
}
fn operand_cimmswsp(inst: RvInst) -> u32 {
    (((inst << 51 >> 60) << 2) | ((inst << 55 >> 62) << 6)) as u32
}
fn operand_cimmsdsp(inst: RvInst) -> u32 {
    (((inst << 51 >> 61) << 3) | ((inst << 54 >> 61) << 6)) as u32
}
fn operand_cimmsqsp(inst: RvInst) -> u32 {
    (((inst << 51 >> 62) << 4) | ((inst << 53 >> 60) << 6)) as u32
}
fn operand_cimm4spn(inst: RvInst) -> u32 {
    (((inst << 51 >> 62) << 4)
        | ((inst << 53 >> 60) << 6)
        | ((inst << 57 >> 63) << 2)
        | ((inst << 58 >> 63) << 3)) as u32
}
fn operand_cimmw(inst: RvInst) -> u32 {
    (((inst << 51 >> 61) << 3) | ((inst << 57 >> 63) << 2) | ((inst << 58 >> 63) << 6)) as u32
}
fn operand_cimmd(inst: RvInst) -> u32 {
    (((inst << 51 >> 61) << 3) | ((inst << 57 >> 62) << 6)) as u32
}
fn operand_cimmq(inst: RvInst) -> u32 {
    (((inst << 51 >> 62) << 4) | ((inst << 53 >> 63) << 8) | ((inst << 57 >> 62) << 6)) as u32
}

fn decode_inst_operands(dec: &mut RvDecode) {
    let inst: RvInst = dec.inst;
    dec.codec = dec.op.unwrap_or(&RV_OPCODE_DATA_ILLEGAL).codec;
    match dec.codec {
        RvCodec::None => {
            dec.rs2 = RvIreg::Zero as u8;
            dec.rs1 = RvIreg::Zero as u8;
            dec.rd = RvIreg::Zero as u8;
            dec.imm = 0;
        }
        RvCodec::U => {
            dec.rd = operand_rd(inst) as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.rs1 = RvIreg::Zero as u8;
            dec.imm = operand_imm20(inst);
        }
        RvCodec::Uj => {
            dec.rd = operand_rd(inst) as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.rs1 = RvIreg::Zero as u8;
            dec.imm = operand_jimm20(inst);
        }
        RvCodec::I => {
            dec.rd = operand_rd(inst) as u8;
            dec.rs1 = operand_rs1(inst) as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_imm12(inst);
        }
        RvCodec::ISh5 => {
            dec.rd = operand_rd(inst) as u8;
            dec.rs1 = operand_rs1(inst) as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_shamt5(inst) as i32;
        }
        RvCodec::ISh6 => {
            dec.rd = operand_rd(inst) as u8;
            dec.rs1 = operand_rs1(inst) as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_shamt6(inst) as i32;
        }
        RvCodec::ISh7 => {
            dec.rd = operand_rd(inst) as u8;
            dec.rs1 = operand_rs1(inst) as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_shamt7(inst) as i32;
        }
        RvCodec::ICsr => {
            dec.rd = operand_rd(inst) as u8;
            dec.rs1 = operand_rs1(inst) as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_csr12(inst) as i32;
        }
        RvCodec::S => {
            dec.rd = RvIreg::Zero as u8;
            dec.rs1 = operand_rs1(inst) as u8;
            dec.rs2 = operand_rs2(inst) as u8;
            dec.imm = operand_simm12(inst);
        }
        RvCodec::SB => {
            dec.rd = RvIreg::Zero as u8;
            dec.rs1 = operand_rs1(inst) as u8;
            dec.rs2 = operand_rs2(inst) as u8;
            dec.imm = operand_sbimm12(inst);
        }
        RvCodec::R => {
            dec.rd = operand_rd(inst) as u8;
            dec.rs1 = operand_rs1(inst) as u8;
            dec.rs2 = operand_rs2(inst) as u8;
            dec.imm = 0;
        }
        RvCodec::RM => {
            dec.rd = operand_rd(inst) as u8;
            dec.rs1 = operand_rs1(inst) as u8;
            dec.rs2 = operand_rs2(inst) as u8;
            dec.imm = 0;
            dec.rm = operand_rm(inst) as u8;
        }
        RvCodec::R4M => {
            dec.rd = operand_rd(inst) as u8;
            dec.rs1 = operand_rs1(inst) as u8;
            dec.rs2 = operand_rs2(inst) as u8;
            dec.rs3 = operand_rs3(inst) as u8;
            dec.imm = 0;
            dec.rm = operand_rm(inst) as u8;
        }
        RvCodec::RA => {
            dec.rd = operand_rd(inst) as u8;
            dec.rs1 = operand_rs1(inst) as u8;
            dec.rs2 = operand_rs2(inst) as u8;
            dec.imm = 0;
            dec.aq = operand_aq(inst) as u8;
            dec.rl = operand_rl(inst) as u8;
        }
        RvCodec::RL => {
            dec.rd = operand_rd(inst) as u8;
            dec.rs1 = operand_rs1(inst) as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = 0;
            dec.aq = operand_aq(inst) as u8;
            dec.rl = operand_rl(inst) as u8;
        }
        RvCodec::RF => {
            dec.rd = RvIreg::Zero as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.rs1 = RvIreg::Zero as u8;
            dec.pred = operand_pred(inst) as u8;
            dec.succ = operand_succ(inst) as u8;
            dec.imm = 0;
        }
        RvCodec::Cb => {
            dec.rd = RvIreg::Zero as u8;
            dec.rs1 = (operand_crs1q(inst)).wrapping_add(8) as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_cimmb(inst);
        }
        RvCodec::CbImm => {
            dec.rs1 = (operand_crs1rdq(inst)).wrapping_add(8) as u8;
            dec.rd = dec.rs1;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_cimmi(inst);
        }
        // RvCodec::CbSh5 => {
        //     dec.rs1 = (operand_crs1rdq(inst)).wrapping_add(8) as u8;
        //     dec.rd = dec.rs1;
        //     dec.rs2 = RvIreg::Zero as u8;
        //     dec.imm = operand_cimmsh5(inst) as i32;
        // }
        RvCodec::CbSh6 => {
            dec.rs1 = (operand_crs1rdq(inst)).wrapping_add(8) as u8;
            dec.rd = dec.rs1;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_cimmsh6(inst) as i32;
        }
        RvCodec::Ci => {
            dec.rs1 = operand_crs1rd(inst) as u8;
            dec.rd = dec.rs1;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_cimmi(inst);
        }
        // RvCodec::CiSh5 => {
        //     dec.rs1 = operand_crs1rd(inst) as u8;
        //     dec.rd = dec.rs1;
        //     dec.rs2 = RvIreg::Zero as u8;
        //     dec.imm = operand_cimmsh5(inst) as i32;
        // }
        RvCodec::CiSh6 => {
            dec.rs1 = operand_crs1rd(inst) as u8;
            dec.rd = dec.rs1;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_cimmsh6(inst) as i32;
        }
        RvCodec::Ci16sp => {
            dec.rd = RvIreg::Sp as u8;
            dec.rs1 = RvIreg::Sp as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_cimm16sp(inst);
        }
        RvCodec::CiLwsp => {
            dec.rd = operand_crd(inst) as u8;
            dec.rs1 = RvIreg::Sp as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_cimmlwsp(inst) as i32;
        }
        RvCodec::CiLdsp => {
            dec.rd = operand_crd(inst) as u8;
            dec.rs1 = RvIreg::Sp as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_cimmldsp(inst) as i32;
        }
        RvCodec::CiLqsp => {
            dec.rd = operand_crd(inst) as u8;
            dec.rs1 = RvIreg::Sp as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_cimmlqsp(inst) as i32;
        }
        RvCodec::CiLi => {
            dec.rd = operand_crd(inst) as u8;
            dec.rs1 = RvIreg::Zero as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_cimmi(inst);
        }
        RvCodec::CiLui => {
            dec.rd = operand_crd(inst) as u8;
            dec.rs1 = RvIreg::Zero as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_cimmui(inst);
        }
        RvCodec::CiNone => {
            dec.rs2 = RvIreg::Zero as u8;
            dec.rs1 = RvIreg::Zero as u8;
            dec.rd = RvIreg::Zero as u8;
            dec.imm = 0;
        }
        RvCodec::Ciw4spn => {
            dec.rd = (operand_crdq(inst)).wrapping_add(8) as u8;
            dec.rs1 = RvIreg::Sp as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_cimm4spn(inst) as i32;
        }
        RvCodec::Cj => {
            dec.rs2 = RvIreg::Zero as u8;
            dec.rs1 = RvIreg::Zero as u8;
            dec.rd = RvIreg::Zero as u8;
            dec.imm = operand_cimmj(inst);
        }
        RvCodec::CjJal => {
            dec.rd = RvIreg::Ra as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.rs1 = RvIreg::Zero as u8;
            dec.imm = operand_cimmj(inst);
        }
        RvCodec::ClLw => {
            dec.rd = (operand_crdq(inst)).wrapping_add(8) as u8;
            dec.rs1 = (operand_crs1q(inst)).wrapping_add(8) as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_cimmw(inst) as i32;
        }
        RvCodec::ClLd => {
            dec.rd = (operand_crdq(inst)).wrapping_add(8) as u8;
            dec.rs1 = (operand_crs1q(inst)).wrapping_add(8) as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_cimmd(inst) as i32;
        }
        RvCodec::ClLq => {
            dec.rd = (operand_crdq(inst)).wrapping_add(8) as u8;
            dec.rs1 = (operand_crs1q(inst)).wrapping_add(8) as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_cimmq(inst) as i32;
        }
        RvCodec::Cr => {
            dec.rs1 = operand_crs1rd(inst) as u8;
            dec.rd = dec.rs1;
            dec.rs2 = operand_crs2(inst) as u8;
            dec.imm = 0;
        }
        RvCodec::CrMv => {
            dec.rd = operand_crd(inst) as u8;
            dec.rs1 = operand_crs2(inst) as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = 0;
        }
        RvCodec::CrJalr => {
            dec.rd = RvIreg::Ra as u8;
            dec.rs1 = operand_crs1(inst) as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = 0;
        }
        RvCodec::CrJr => {
            dec.rd = RvIreg::Zero as u8;
            dec.rs1 = operand_crs1(inst) as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = 0;
        }
        RvCodec::Cs => {
            dec.rs1 = (operand_crs1rdq(inst)).wrapping_add(8) as u8;
            dec.rd = dec.rs1;
            dec.rs2 = (operand_crs2q(inst)).wrapping_add(8) as u8;
            dec.imm = 0;
        }
        RvCodec::CsSw => {
            dec.rd = RvIreg::Zero as u8;
            dec.rs1 = (operand_crs1q(inst)).wrapping_add(8) as u8;
            dec.rs2 = (operand_crs2q(inst)).wrapping_add(8) as u8;
            dec.imm = operand_cimmw(inst) as i32;
        }
        RvCodec::CsSd => {
            dec.rd = RvIreg::Zero as u8;
            dec.rs1 = (operand_crs1q(inst)).wrapping_add(8) as u8;
            dec.rs2 = (operand_crs2q(inst)).wrapping_add(8) as u8;
            dec.imm = operand_cimmd(inst) as i32;
        }
        RvCodec::CsSq => {
            dec.rd = RvIreg::Zero as u8;
            dec.rs1 = (operand_crs1q(inst)).wrapping_add(8) as u8;
            dec.rs2 = (operand_crs2q(inst)).wrapping_add(8) as u8;
            dec.imm = operand_cimmq(inst) as i32;
        }
        RvCodec::CssSwsp => {
            dec.rd = RvIreg::Zero as u8;
            dec.rs1 = RvIreg::Sp as u8;
            dec.rs2 = operand_crs2(inst) as u8;
            dec.imm = operand_cimmswsp(inst) as i32;
        }
        RvCodec::CssSdsp => {
            dec.rd = RvIreg::Zero as u8;
            dec.rs1 = RvIreg::Sp as u8;
            dec.rs2 = operand_crs2(inst) as u8;
            dec.imm = operand_cimmsdsp(inst) as i32;
        }
        RvCodec::CssSqsp => {
            dec.rd = RvIreg::Zero as u8;
            dec.rs1 = RvIreg::Sp as u8;
            dec.rs2 = operand_crs2(inst) as u8;
            dec.imm = operand_cimmsqsp(inst) as i32;
        }
        RvCodec::Li => {
            dec.rd = operand_crd(inst) as u8;
            dec.rs1 = RvIreg::Zero as u8;
            dec.rs2 = RvIreg::Zero as u8;
            dec.imm = operand_imm12(inst);
        }
        RvCodec::Illegal => {}
    };
}

fn decode_inst_decompress(dec: &mut RvDecode, isa: RvIsa) {
    if dec.op.is_none() {
        return;
    }
    let data = dec.op.unwrap();
    let decomp_op = match isa {
        RvIsa::Rv32 => data.decomp_rv32,
        RvIsa::Rv64 => data.decomp_rv64,
        RvIsa::Rv128 => data.decomp_rv128,
    };
    if let Some(decomp_op) = decomp_op {
        if data.check_imm_nz && dec.imm == 0 {
            dec.op = None;
        } else {
            dec.op = Some(decomp_op);
            dec.codec = decomp_op.codec;
        }
    }
}

fn check_constraints(dec: &mut RvDecode, c: &'static [RvcConstraint]) -> bool {
    let imm: i32 = dec.imm;
    let rd: u8 = dec.rd;
    let rs1: u8 = dec.rs1;
    let rs2: u8 = dec.rs2;
    for c in c.iter() {
        match *c {
            RdEqRa => {
                if rd != 1 {
                    return false;
                }
            }
            RdEqX0 => {
                if rd != 0 {
                    return false;
                }
            }
            Rs1EqX0 => {
                if rs1 != 0 {
                    return false;
                }
            }
            Rs2EqX0 => {
                if rs2 != 0 {
                    return false;
                }
            }
            Rs2EqRs1 => {
                if rs2 != rs1 {
                    return false;
                }
            }
            Rs1EqRa => {
                if rs1 != 1 {
                    return false;
                }
            }
            ImmEqZero => {
                if imm != 0 {
                    return false;
                }
            }
            ImmEqN1 => {
                if imm != -1 {
                    return false;
                }
            }
            ImmEqP1 => {
                if imm != 1 {
                    return false;
                }
            }
            CsrEq0x001 => {
                if imm != 1 {
                    return false;
                }
            }
            CsrEq0x002 => {
                if imm != 2 {
                    return false;
                }
            }
            CsrEq0x003 => {
                if imm != 3 {
                    return false;
                }
            }
            CsrEq0xc00 => {
                if imm != 0xc00 {
                    return false;
                }
            }
            CsrEq0xc01 => {
                if imm != 0xc01 {
                    return false;
                }
            }
            CsrEq0xc02 => {
                if imm != 0xc02 {
                    return false;
                }
            }
            CsrRq0xc80 => {
                if imm != 0xc80 {
                    return false;
                }
            }
            CsrEq0xc81 => {
                if imm != 0xc81 {
                    return false;
                }
            }
            CsrEq0xc82 => {
                if imm != 0xc82 {
                    return false;
                }
            }
        }
    }
    true
}

fn decode_inst_lift_pseudo(dec: &mut RvDecode) {
    if dec.op.is_none() {
        return;
    }
    let comp_data = dec.op.unwrap().pseudo;
    if comp_data.is_none() {
        return;
    }
    for comp_data in comp_data.unwrap().iter() {
        if check_constraints(dec, comp_data.constraints) {
            dec.op = Some(comp_data.op);
            dec.codec = dec.op.unwrap().codec;
            return;
        }
    }
}

fn decode_inst_format(dec: &mut RvDecode) -> String {
    let len: usize = inst_length(dec.inst);
    let mut buf = match len {
        2 => format!("{:04x}              ", dec.inst & 0xffff),
        4 => format!("{:08x}          ", dec.inst & 0xffff_ffff),
        6 => format!("{:012x}      ", dec.inst & 0xffff_ffff_ffff),
        _ => format!("{:016x}  ", dec.inst),
    };
    let (fmt, name) = match dec.op {
        Some(op) => (op.format, op.name),
        None => (RV_FMT_NONE, "illegal"),
    };
    for f in fmt.chars() {
        match f {
            'O' => buf += name,
            '(' => buf += "(",
            ',' => buf += ",",
            ')' => buf += ")",
            '0' => buf += rv_ireg_name_sym[dec.rd as usize],
            '1' => buf += rv_ireg_name_sym[dec.rs1 as usize],
            '2' => buf += rv_ireg_name_sym[dec.rs2 as usize],
            '3' => buf += rv_freg_name_sym[dec.rd as usize],
            '4' => buf += rv_freg_name_sym[dec.rs1 as usize],
            '5' => buf += rv_freg_name_sym[dec.rs2 as usize],
            '6' => buf += rv_freg_name_sym[dec.rs3 as usize],
            '7' => buf += dec.rs1.to_string().as_str(),
            'i' => buf += dec.imm.to_string().as_str(),
            'o' => {
                buf += dec.imm.to_string().as_str();
                buf += " ".repeat(TAB_SIZE * 2 - buf.len()).as_str();
                buf += format!("# 0x{:x}", (dec.pc as i64).wrapping_add(dec.imm as i64)).as_str();
            }
            'c' => {
                let name = csr_name(dec.imm & 0xfff);
                if !name.is_empty() {
                    buf += name;
                } else {
                    buf += format!("0x{:03x}", dec.imm & 0xfff).as_str();
                }
            }
            'r' => match dec.rm as i32 {
                0 => buf += "rne",
                1 => buf += "rtz",
                2 => buf += "rdn",
                3 => buf += "rup",
                4 => buf += "rmm",
                7 => buf += "dyn",
                _ => buf += "inv",
            },
            'p' => {
                if dec.pred as i32 & RvFence::I as i32 != 0 {
                    buf += "i"
                }
                if dec.pred as i32 & RvFence::O as i32 != 0 {
                    buf += "o"
                }
                if dec.pred as i32 & RvFence::R as i32 != 0 {
                    buf += "r"
                }
                if dec.pred as i32 & RvFence::W as i32 != 0 {
                    buf += "w"
                }
            }
            's' => {
                if dec.succ as i32 & RvFence::I as i32 != 0 {
                    buf += "i"
                }
                if dec.succ as i32 & RvFence::O as i32 != 0 {
                    buf += "o"
                }
                if dec.succ as i32 & RvFence::R as i32 != 0 {
                    buf += "r"
                }
                if dec.succ as i32 & RvFence::W as i32 != 0 {
                    buf += "w"
                }
            }
            '\t' => {
                buf += " ".repeat(TAB_SIZE.saturating_sub(buf.len())).as_str();
            }
            'A' => {
                if dec.aq != 0 {
                    buf += ".aq";
                }
            }
            'R' => {
                if dec.rl != 0 {
                    buf += ".rl";
                }
            }
            _ => {}
        }
    }
    buf
}

pub fn inst_length(inst: RvInst) -> usize {
    (if inst & 3 != 3 {
        2
    } else if inst & 0x1c != 0x1c {
        4
    } else if inst & 0x3f == 0x1f {
        6
    } else if inst & 0x7f == 0x3f {
        8
    } else {
        0
    }) as usize
}

pub fn disasm_inst(isa: RvIsa, pc: u64, inst: RvInst) -> String {
    let mut dec: RvDecode = {
        RvDecode {
            pc,
            inst,
            imm: 0,
            op: None,
            codec: RvCodec::Illegal,
            rd: 0,
            rs1: 0,
            rs2: 0,
            rs3: 0,
            rm: 0,
            pred: 0,
            succ: 0,
            aq: 0,
            rl: 0,
        }
    };
    decode_inst_opcode(&mut dec, isa);
    decode_inst_operands(&mut dec);
    decode_inst_decompress(&mut dec, isa);
    decode_inst_lift_pseudo(&mut dec);
    decode_inst_format(&mut dec)
}

#[cfg(test)]
mod csr_tests {
    use std::collections::HashSet;
    #[test]
    fn test_csrs_unique() {
        let mut names = HashSet::new();
        for i in 0..0x1000 {
            let name = super::csr_name(i);
            if !name.is_empty() {
                assert!(!names.contains(name), "duplicate CSR name: {}", name);
                names.insert(name);
            }
        }
    }
}

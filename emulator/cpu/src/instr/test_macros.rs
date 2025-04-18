/*++

Licensed under the Apache-2.0 license.

File Name:

    test_macros.rs

Abstract:

    File contains implementation of RISCV Instruction encoding

--*/
#[cfg(test)]
mod test {
    #[macro_export]
    macro_rules! test_ld_op {
        ($test:ident, $instr:ident, $result:expr, $offset:expr, $base:expr, $data:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::$instr(XReg::X14, $offset, XReg::X1);
                    ],
                    0x1000 => $data,
                    {
                        XReg::X1 = $base;
                    },
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_imm_op {
        ($test:ident, $instr:ident, $result:expr, $data:expr, $imm:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::$instr(XReg::X14, XReg::X1, $imm);
                    ],
                    0x1000 => vec![0],
                    {
                        XReg::X1 = $data;
                    },
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_imm_dest_bypass {
        ($test:ident, 0, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);                             // 0x0000
                        tests::li0(XReg::X1, $val1);                                    // 0x0004
                        tests::li1(XReg::X1, $val1);                                    // 0x0008
                        tests::$instr(XReg::X14, XReg::X1, tests::sign_extend($val2)); // 0x000C
                        tests::addi(XReg::X6, XReg::X14, 0);                            // 0x0010
                        tests::addi(XReg::X4, XReg::X4, 1);                             // 0x0014
                        tests::addi(XReg::X5, XReg::X0, 2);                             // 0x0018
                        tests::bne(XReg::X4, XReg::X5, 0xFFE8);                         // 0x001C
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X6 = $result;
                    }
                );
            }
        };
        ($test:ident, 1, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);                             // 0x0000
                        tests::li0(XReg::X1, $val1);                                    // 0x0004
                        tests::li1(XReg::X1, $val1);                                    // 0x0008
                        tests::$instr(XReg::X14, XReg::X1, tests::sign_extend($val2));  // 0x000C
                        tests::nop();                                                   // 0x0010
                        tests::addi(XReg::X6, XReg::X14, 0);                            // 0x0014
                        tests::addi(XReg::X4, XReg::X4, 1);                             // 0x0018
                        tests::addi(XReg::X5, XReg::X0, 2);                             // 0x001C
                        tests::bne(XReg::X4, XReg::X5, 0xFFE4);                         // 0x0020
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X6 = $result;
                    }
                );
            }
        };
        ($test:ident, 2, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);                             // 0x0000
                        tests::li0(XReg::X1, $val1);                                    // 0x0004
                        tests::li1(XReg::X1, $val1);                                    // 0x0008
                        tests::$instr(XReg::X14, XReg::X1, tests::sign_extend($val2));  // 0x000C
                        tests::nop();                                                   // 0x0010
                        tests::nop();                                                   // 0x0014
                        tests::addi(XReg::X6, XReg::X14, 0);                            // 0x0018
                        tests::addi(XReg::X4, XReg::X4, 1);                             // 0x001C
                        tests::addi(XReg::X5, XReg::X0, 2);                             // 0x0020
                        tests::bne(XReg::X4, XReg::X5, 0xFFE0);                         // 0x0024
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X6 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_imm_src1_bypass {
        ($test:ident, 0, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);                            // 0x0000
                        tests::li0(XReg::X1, $val1);                                   // 0x0004
                        tests::li1(XReg::X1, $val1);                                   // 0x0008
                        tests::$instr(XReg::X14, XReg::X1, tests::sign_extend($val2)); // 0x000C
                        tests::addi(XReg::X4, XReg::X4, 1);                            // 0x0010
                        tests::addi(XReg::X5, XReg::X0, 2);                            // 0x0014
                        tests::bne(XReg::X4, XReg::X5, 0xFFEC);                        // 0x0018
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
        ($test:ident, 1, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);                            // 0x0000
                        tests::li0(XReg::X1, $val1);                                   // 0x0004
                        tests::li1(XReg::X1, $val1);                                   // 0x0008
                        tests::nop();                                                  // 0x000C
                        tests::$instr(XReg::X14, XReg::X1, tests::sign_extend($val2)); // 0x0010
                        tests::addi(XReg::X4, XReg::X4, 1);                            // 0x0014
                        tests::addi(XReg::X5, XReg::X0, 2);                            // 0x0018
                        tests::bne(XReg::X4, XReg::X5, 0xFFE8);                        // 0x001C
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
        ($test:ident, 2, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);                            // 0x0000
                        tests::li0(XReg::X1, $val1);                                   // 0x0004
                        tests::li1(XReg::X1, $val1);                                   // 0x0008
                        tests::nop();                                                  // 0x000C
                        tests::nop();                                                  // 0x0010
                        tests::$instr(XReg::X14, XReg::X1, tests::sign_extend($val2)); // 0x0014
                        tests::addi(XReg::X4, XReg::X4, 1);                            // 0x0018
                        tests::addi(XReg::X5, XReg::X0, 2);                            // 0x001C
                        tests::bne(XReg::X4, XReg::X5, 0xFFE4);                        // 0x0020
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_imm_src1_eq_dest {
        ($test:ident, $instr:ident, $result:expr, $data:expr, $imm:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::$instr(XReg::X1, XReg::X1, $imm);
                    ],
                    0x1000 => vec![0],
                    {
                        XReg::X1 = $data;
                    },
                    {
                        XReg::X1 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_imm_zero_src1 {
        ($test:ident, $instr:ident, $result:expr, $imm:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::$instr(XReg::X1, XReg::X0, $imm);
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X1 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_imm_zero_dest {
        ($test:ident, $instr:ident, $data:expr, $imm:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::$instr(XReg::X0, XReg::X1, $imm);
                    ],
                    0x1000 => vec![0],
                    {
                        XReg::X1 = $data;
                    },
                    {
                        XReg::X0 = 0;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_st_op {
        ($test:ident, $ld_instr:ident, $st_instr:ident, $result:expr, $offset:expr, $base:expr, $data:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::$st_instr(XReg::X2, $offset, XReg::X1);
                        tests::$ld_instr(XReg::X14, $offset, XReg::X1);
                    ],
                    0x1000 => $data,
                    {
                        XReg::X1 = $base;
                        XReg::X2 = $result;
                    },
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_r_op {
        ($test:ident, $instr:ident, $result:expr, $val1:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::$instr(XReg::X14, XReg::X1);
                    ],
                    0x1000 => vec![0],
                    {
                        XReg::X1 = $val1;
                    },
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_rr_op {
        ($test:ident, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::$instr(XReg::X14, XReg::X1, XReg::X2);
                    ],
                    0x1000 => vec![0],
                    {
                        XReg::X1 = $val1;
                        XReg::X2 = $val2;
                    },
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_r_src1_eq_dest{
        ($test:ident, $instr:ident, $result:expr, $val1:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::$instr(XReg::X1, XReg::X1);
                    ],
                    0x1000 => vec![0],
                    {
                        XReg::X1 = $val1;
                    },
                    {
                        XReg::X1 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_rr_src1_eq_dest{
        ($test:ident, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::$instr(XReg::X1, XReg::X1, XReg::X2);
                    ],
                    0x1000 => vec![0],
                    {
                        XReg::X1 = $val1;
                        XReg::X2 = $val2;
                    },
                    {
                        XReg::X1 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_rr_src2_eq_dest{
        ($test:ident, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::$instr(XReg::X2, XReg::X1, XReg::X2);
                    ],
                    0x1000 => vec![0],
                    {
                        XReg::X1 = $val1;
                        XReg::X2 = $val2;
                    },
                    {
                        XReg::X2 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_rr_src12_eq_dest{
        ($test:ident, $instr:ident, $result:expr, $val:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::$instr(XReg::X1, XReg::X1, XReg::X1);
                    ],
                    0x1000 => vec![0],
                    {
                        XReg::X1 = $val;
                    },
                    {
                        XReg::X1 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_r_dest_bypass {
        ($test:ident, 0, $instr:ident, $result:expr, $val1:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);     // 0x0000
                        tests::li0(XReg::X1, $val1);            // 0x0004
                        tests::li1(XReg::X1, $val1);            // 0x0008
                        tests::$instr(XReg::X14, XReg::X1);     // 0x000C
                        tests::addi(XReg::X6, XReg::X14, 0);    // 0x0010
                        tests::addi(XReg::X4, XReg::X4, 1);     // 0x0014
                        tests::addi(XReg::X5, XReg::X0, 2);     // 0x0018
                        tests::bne(XReg::X4, XReg::X5, 0xFFE8); // 0x001C
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X6 = $result;
                    }
                );
            }
        };
        ($test:ident, 1, $instr:ident, $result:expr, $val1:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);     // 0x0000
                        tests::li0(XReg::X1, $val1);            // 0x0004
                        tests::li1(XReg::X1, $val1);            // 0x0008
                        tests::$instr(XReg::X14, XReg::X1);     // 0x000C
                        tests::nop();                           // 0x0010
                        tests::addi(XReg::X6, XReg::X14, 0);    // 0x0014
                        tests::addi(XReg::X4, XReg::X4, 1);     // 0x0018
                        tests::addi(XReg::X5, XReg::X0, 2);     // 0x001C
                        tests::bne(XReg::X4, XReg::X5, 0xFFE4); // 0x0020
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X6 = $result;
                    }
                );
            }
        };
        ($test:ident, 2, $instr:ident, $result:expr, $val1:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);     // 0x0000
                        tests::li0(XReg::X1, $val1);            // 0x0004
                        tests::li1(XReg::X1, $val1);            // 0x0008
                        tests::$instr(XReg::X14, XReg::X1);     // 0x000C
                        tests::nop();                           // 0x0010
                        tests::nop();                           // 0x0014
                        tests::addi(XReg::X6, XReg::X14, 0);    // 0x0018
                        tests::addi(XReg::X4, XReg::X4, 1);     // 0x001C
                        tests::addi(XReg::X5, XReg::X0, 2);     // 0x0020
                        tests::bne(XReg::X4, XReg::X5, 0xFFE0); // 0x0024
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X6 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_rr_dest_bypass {
        ($test:ident, 0, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);           // 0x0000
                        tests::li0(XReg::X1, $val1);                  // 0x0004
                        tests::li1(XReg::X1, $val1);                  // 0x0008
                        tests::li0(XReg::X2, $val2);                  // 0x000C
                        tests::li1(XReg::X2, $val2);                  // 0x0010
                        tests::$instr(XReg::X14, XReg::X1, XReg::X2); // 0x0014
                        tests::addi(XReg::X6, XReg::X14, 0);          // 0x0018
                        tests::addi(XReg::X4, XReg::X4, 1);           // 0x001C
                        tests::addi(XReg::X5, XReg::X0, 2);           // 0x0020
                        tests::bne(XReg::X4, XReg::X5, 0xFFE0);       // 0x0024
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X6 = $result;
                    }
                );
            }
        };
        ($test:ident, 1, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);           // 0x0000
                        tests::li0(XReg::X1, $val1);                  // 0x0004
                        tests::li1(XReg::X1, $val1);                  // 0x0008
                        tests::li0(XReg::X2, $val2);                  // 0x000C
                        tests::li1(XReg::X2, $val2);                  // 0x0010
                        tests::$instr(XReg::X14, XReg::X1, XReg::X2); // 0x0014
                        tests::nop();                                 // 0x0018
                        tests::addi(XReg::X6, XReg::X14, 0);          // 0x001C
                        tests::addi(XReg::X4, XReg::X4, 1);           // 0x0020
                        tests::addi(XReg::X5, XReg::X0, 2);           // 0x0024
                        tests::bne(XReg::X4, XReg::X5, 0xFFDC);       // 0x0028
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X6 = $result;
                    }
                );
            }
        };
        ($test:ident, 2, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);           // 0x0000
                        tests::li0(XReg::X1, $val1);                  // 0x0004
                        tests::li1(XReg::X1, $val1);                  // 0x0008
                        tests::li0(XReg::X2, $val2);                  // 0x000C
                        tests::li1(XReg::X2, $val2);                  // 0x0010
                        tests::$instr(XReg::X14, XReg::X1, XReg::X2); // 0x0014
                        tests::nop();                                 // 0x0018
                        tests::nop();                                 // 0x001C
                        tests::addi(XReg::X6, XReg::X14, 0);          // 0x0020
                        tests::addi(XReg::X4, XReg::X4, 1);           // 0x0024
                        tests::addi(XReg::X5, XReg::X0, 2);           // 0x0028
                        tests::bne(XReg::X4, XReg::X5, 0xFFD8);       // 0x002C
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X6 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_rr_src12_bypass {
        ($test:ident, 0, 0, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);           // 0x0000
                        tests::li0(XReg::X1, $val1);                  // 0x0004
                        tests::li1(XReg::X1, $val1);                  // 0x0008
                        tests::li0(XReg::X2, $val2);                  // 0x000C
                        tests::li1(XReg::X2, $val2);                  // 0x0010
                        tests::$instr(XReg::X14, XReg::X1, XReg::X2); // 0x0014
                        tests::addi(XReg::X4, XReg::X4, 1);           // 0x0018
                        tests::addi(XReg::X5, XReg::X0, 2);           // 0x001C
                        tests::bne(XReg::X4, XReg::X5, 0xFFE4);       // 0x0020
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
        ($test:ident, 0, 1, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);           // 0x0000
                        tests::li0(XReg::X1, $val1);                  // 0x0004
                        tests::li1(XReg::X1, $val1);                  // 0x0008
                        tests::li0(XReg::X2, $val2);                  // 0x000C
                        tests::li1(XReg::X2, $val2);                  // 0x0010
                        tests::nop();                                 // 0x0014
                        tests::$instr(XReg::X14, XReg::X1, XReg::X2); // 0x0018
                        tests::addi(XReg::X4, XReg::X4, 1);           // 0x001C
                        tests::addi(XReg::X5, XReg::X0, 2);           // 0x0020
                        tests::bne(XReg::X4, XReg::X5, 0xFFE0);       // 0x0024
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
        ($test:ident, 0, 2, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);           // 0x0000
                        tests::li0(XReg::X1, $val1);                  // 0x0004
                        tests::li1(XReg::X1, $val1);                  // 0x0008
                        tests::li0(XReg::X2, $val2);                  // 0x000C
                        tests::li1(XReg::X2, $val2);                  // 0x0010
                        tests::nop();                                 // 0x0014
                        tests::nop();                                 // 0x0018
                        tests::$instr(XReg::X14, XReg::X1, XReg::X2); // 0x001C
                        tests::addi(XReg::X4, XReg::X4, 1);           // 0x0020
                        tests::addi(XReg::X5, XReg::X0, 2);           // 0x0024
                        tests::bne(XReg::X4, XReg::X5, 0xFFDC);       // 0x0028
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
        ($test:ident, 1, 0, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);           // 0x0000
                        tests::li0(XReg::X1, $val1);                  // 0x0004
                        tests::li1(XReg::X1, $val1);                  // 0x0008
                        tests::nop();                                 // 0x000C
                        tests::li0(XReg::X2, $val2);                  // 0x0010
                        tests::li1(XReg::X2, $val2);                  // 0x0014
                        tests::$instr(XReg::X14, XReg::X1, XReg::X2); // 0x0018
                        tests::addi(XReg::X4, XReg::X4, 1);           // 0x001C
                        tests::addi(XReg::X5, XReg::X0, 2);           // 0x0020
                        tests::bne(XReg::X4, XReg::X5, 0xFFE0);       // 0x0024
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
        ($test:ident, 1, 1, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);           // 0x0000
                        tests::li0(XReg::X1, $val1);                  // 0x0004
                        tests::li1(XReg::X1, $val1);                  // 0x0008
                        tests::nop();                                 // 0x000C
                        tests::li0(XReg::X2, $val2);                  // 0x0010
                        tests::li1(XReg::X2, $val2);                  // 0x0014
                        tests::nop();                                 // 0x0018
                        tests::$instr(XReg::X14, XReg::X1, XReg::X2); // 0x001C
                        tests::addi(XReg::X4, XReg::X4, 1);           // 0x0020
                        tests::addi(XReg::X5, XReg::X0, 2);           // 0x0024
                        tests::bne(XReg::X4, XReg::X5, 0xFFDC);       // 0x0028
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
        ($test:ident, 2, 0, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);           // 0x0000
                        tests::li0(XReg::X1, $val1);                  // 0x0004
                        tests::li1(XReg::X1, $val1);                  // 0x0008
                        tests::nop();                                 // 0x000C
                        tests::nop();                                 // 0x0010
                        tests::li0(XReg::X2, $val2);                  // 0x0014
                        tests::li1(XReg::X2, $val2);                  // 0x0018
                        tests::$instr(XReg::X14, XReg::X1, XReg::X2); // 0x001C
                        tests::addi(XReg::X4, XReg::X4, 1);           // 0x0020
                        tests::addi(XReg::X5, XReg::X0, 2);           // 0x0024
                        tests::bne(XReg::X4, XReg::X5, 0xFFDC);       // 0x0028
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_rr_src21_bypass {
        ($test:ident, 0, 0, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);           // 0x0000
                        tests::li0(XReg::X2, $val2);                  // 0x0004
                        tests::li1(XReg::X2, $val2);                  // 0x0008
                        tests::li0(XReg::X1, $val1);                  // 0x000C
                        tests::li1(XReg::X1, $val1);                  // 0x0010
                        tests::$instr(XReg::X14, XReg::X1, XReg::X2); // 0x0014
                        tests::addi(XReg::X4, XReg::X4, 1);           // 0x0018
                        tests::addi(XReg::X5, XReg::X0, 2);           // 0x001C
                        tests::bne(XReg::X4, XReg::X5, 0xFFE4);       // 0x0020
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
        ($test:ident, 0, 1, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);           // 0x0000
                        tests::li0(XReg::X2, $val2);                  // 0x0004
                        tests::li1(XReg::X2, $val2);                  // 0x0008
                        tests::li0(XReg::X1, $val1);                  // 0x000C
                        tests::li1(XReg::X1, $val1);                  // 0x0010
                        tests::nop();                                 // 0x0014
                        tests::$instr(XReg::X14, XReg::X1, XReg::X2); // 0x0018
                        tests::addi(XReg::X4, XReg::X4, 1);           // 0x001C
                        tests::addi(XReg::X5, XReg::X0, 2);           // 0x0020
                        tests::bne(XReg::X4, XReg::X5, 0xFFE0);       // 0x0024
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
        ($test:ident, 0, 2, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);           // 0x0000
                        tests::li0(XReg::X2, $val2);                  // 0x0004
                        tests::li1(XReg::X2, $val2);                  // 0x0008
                        tests::li0(XReg::X1, $val1);                  // 0x000C
                        tests::li1(XReg::X1, $val1);                  // 0x0010
                        tests::nop();                                 // 0x0014
                        tests::nop();                                 // 0x0018
                        tests::$instr(XReg::X14, XReg::X1, XReg::X2); // 0x001C
                        tests::addi(XReg::X4, XReg::X4, 1);           // 0x0020
                        tests::addi(XReg::X5, XReg::X0, 2);           // 0x0024
                        tests::bne(XReg::X4, XReg::X5, 0xFFDC);       // 0x0028
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
        ($test:ident, 1, 0, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);            // 0x0000
                        tests::li0(XReg::X2, $val2);                   // 0x0004
                        tests::li1(XReg::X2, $val2);                   // 0x0008
                        tests::nop();                                  // 0x000C
                        tests::li0(XReg::X1, $val1);                   // 0x0010
                        tests::li1(XReg::X1, $val1);                   // 0x0014
                        tests::$instr(XReg::X14, XReg::X1, XReg::X2);  // 0x0018
                        tests::addi(XReg::X4, XReg::X4, 1);            // 0x001C
                        tests::addi(XReg::X5, XReg::X0, 2);            // 0x0020
                        tests::bne(XReg::X4, XReg::X5, 0xFFE0);        // 0x0024
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
        ($test:ident, 1, 1, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);            // 0x0000
                        tests::li0(XReg::X2, $val2);                   // 0x0004
                        tests::li1(XReg::X2, $val2);                   // 0x000C
                        tests::nop();                                  // 0x0008
                        tests::li0(XReg::X1, $val1);                   // 0x0010
                        tests::li1(XReg::X1, $val1);                   // 0x0014
                        tests::nop();                                  // 0x0018
                        tests::$instr(XReg::X14, XReg::X1, XReg::X2);  // 0x001C
                        tests::addi(XReg::X4, XReg::X4, 1);            // 0x0020
                        tests::addi(XReg::X5, XReg::X0, 2);            // 0x0024
                        tests::bne(XReg::X4, XReg::X5, 0xFFDC);        // 0x0028
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
        ($test:ident, 2, 0, $instr:ident, $result:expr, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::addi(XReg::X4, XReg::X0, 0);           // 0x0000
                        tests::li0(XReg::X2, $val2);                  // 0x0004
                        tests::li1(XReg::X2, $val2);                  // 0x0008
                        tests::nop();                                 // 0x000C
                        tests::nop();                                 // 0x0010
                        tests::li0(XReg::X1, $val1);                  // 0x0014
                        tests::li1(XReg::X1, $val1);                  // 0x0018
                        tests::$instr(XReg::X14, XReg::X1, XReg::X2); // 0x001C
                        tests::addi(XReg::X4, XReg::X4, 1);           // 0x0020
                        tests::addi(XReg::X5, XReg::X0, 2);           // 0x0024
                        tests::bne(XReg::X4, XReg::X5, 0xFFDC);       // 0x0028
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X14 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_rr_zerosrc1 {
        ($test:ident, $instr:ident, $result:expr, $val:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::$instr(XReg::X2, XReg::X0, XReg::X1);
                    ],
                    0x1000 => vec![0],
                    {
                        XReg::X1 = $val;
                    },
                    {
                        XReg::X2 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_rr_zerosrc2 {
        ($test:ident, $instr:ident, $result:expr, $val:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::$instr(XReg::X2, XReg::X1, XReg::X0);
                    ],
                    0x1000 => vec![0],
                    {
                        XReg::X1 = $val;
                    },
                    {
                        XReg::X2 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_rr_zerosrc12 {
        ($test:ident, $instr:ident, $result:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::$instr(XReg::X1, XReg::X0, XReg::X0);
                    ],
                    0x1000 => vec![0],
                    {
                    },
                    {
                        XReg::X1 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_rr_zerodest{
        ($test:ident, $instr:ident, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::$instr(XReg::X0, XReg::X1, XReg::X2);
                    ],
                    0x1000 => vec![0],
                    {
                        XReg::X1 = $val1;
                        XReg::X2 = $val2;
                    },
                    {
                        XReg::X0 = 0;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_lui {
        ($test:ident, $result:expr, $val:expr, $shamt:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests::{lui, srai};

                isa_test!(
                    0x0000 => text![
                        lui(XReg::X1, $val);
                        srai(XReg::X1, XReg::X1, $shamt);
                    ],
                    0x1000 => vec![0],
                    {},
                    {
                        XReg::X1 = $result;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_br2_op_taken {
        ($test:ident, $instr:ident, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::$instr(XReg::X1, XReg::X2, 0x0010);           // 0x0000
                        tests::beq(XReg::X3, XReg::X3, 0x0010);              // 0x0004
                        tests::addi(XReg::X4, XReg::X0, 1);                  // 0x0008
                        tests::beq(XReg::X3, XReg::X4, 0x0008);              // 0x000C
                        tests::$instr(XReg::X1, XReg::X2, -8i32 as u32);     // 0x0010
                        tests::nop();                                        // 0x0014
                    ],
                    0x1000 => vec![0],
                    {
                        XReg::X1 = $val1;
                        XReg::X2 = $val2;
                        XReg::X3 = 1;
                        XReg::X4 = 0;
                    },
                    {
                        XReg::X4 = 1;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! test_br2_op_not_taken {
        ($test:ident, $instr:ident, $val1:expr, $val2:expr) => {
            #[test]
            fn $test() {
                use $crate::xreg_file::XReg;
                use $crate::instr::test_encoder::tests;

                $crate::isa_test!(
                    0x0000 => $crate::text![
                        tests::$instr(XReg::X1, XReg::X2, 0x0014);           // 0x0000
                        tests::beq(XReg::X3, XReg::X3, 0x0008);              // 0x0004
                        tests::beq(XReg::X3, XReg::X4, 0x000C);              // 0x0008
                        tests::$instr(XReg::X1, XReg::X2, -4i32 as u32);     // 0x000C
                        tests::addi(XReg::X4, XReg::X0, 1);                  // 0x0010
                        tests::nop();                                        // 0x0014
                    ],
                    0x1000 => vec![0],
                    {
                        XReg::X1 = $val1;
                        XReg::X2 = $val2;
                        XReg::X3 = 1;
                        XReg::X4 = 0;
                    },
                    {
                        XReg::X4 = 1;
                    }
                );
            }
        };
    }

    #[macro_export]
    macro_rules! isa_test {
        (
            $text_addr:expr => $text:expr,
            $data_addr:expr => $data:expr,
            {$($init_reg:path = $init_val:expr;)*},
            {$($result_reg:path = $result_val:expr;)*}
        ) => {
            let mut cpu = $crate::isa_test_cpu!( $text_addr => $text, $data_addr => $data);
            $(assert_eq!(cpu.write_xreg($init_reg, $init_val).ok(), Some(()));)*

            while (cpu.read_pc() < $text_addr + $text.len() as u32) {
                assert_eq!(cpu.exec_instr(None).ok(), Some($crate::cpu::StepAction::Continue));
            }

            $(assert_eq!(cpu.read_xreg($result_reg).ok(), Some($result_val));)*
        };
    }

    #[macro_export]
    macro_rules! isa_test_cpu {
        (
            $text_addr:expr => $text:expr,
            $data_addr:expr => $data:expr
        ) => {{
            use emulator_bus::{Clock, DynamicBus, Ram, Rom};
            use std::rc::Rc;
            use $crate::cpu::Cpu;
            use $crate::pic::Pic;

            let text_range = $text_addr..=u32::try_from($text_addr + $text.len() - 1).unwrap();
            let data_range = $data_addr..=u32::try_from($data_addr + $data.len() - 1).unwrap();

            let clock = Rc::new(Clock::new());
            let pic = Rc::new(Pic::new());
            let mut cpu = Cpu::new(DynamicBus::new(), clock, pic);
            let rom = Rom::new($text.clone());
            cpu.bus
                .attach_dev("ROM", text_range, Box::new(rom))
                .unwrap();

            let ram = Ram::new($data.clone());
            cpu.bus
                .attach_dev("RAM", data_range, Box::new(ram))
                .unwrap();
            cpu
        }};
    }

    #[macro_export]
    macro_rules! db {
        ($byte:expr) => {{
            let val: u8 = $byte;
            val
        }};
    }

    #[macro_export]
    macro_rules! dh {
        ($half_word:expr) => {{
            let val: u16 = $half_word;
            val
        }};
    }

    #[macro_export]
    macro_rules! dw {
        ($word:expr) => {{
            let val: u32 = $word;
            val
        }};
    }

    #[macro_export]
    macro_rules! text {
        ($($item:expr;)*) => {{
            let mut v = vec![];
            $(v.extend($item.to_le_bytes());)*
            v
        }};
    }

    #[macro_export]
    macro_rules! data {
        ($($item:expr;)*) => {{
            let mut v = vec![];
            $(v.extend($item.to_le_bytes());)*
            v
        }};
    }
}

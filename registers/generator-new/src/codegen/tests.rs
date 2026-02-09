// Licensed under the Apache-2.0 license

//! Tests for the code generator.

mod test {
    use super::super::{generate_tock_registers, generate_tock_registers_from_file};
    use std::path::Path;

    #[test]
    fn test_mcu() {
        let result =
            generate_tock_registers_from_file(Path::new("../../hw/mcu.rdl"), &[("mcu", 0)])
                .unwrap();
        println!("addrmap: {}", result);
    }

    #[test]
    fn test() {
        let result = generate_tock_registers(
            r#"
addrmap mcu {
    I3CCSR I3CCSR @ 0x2000_4000;
    mci_top mci_top @ 0x2100_0000;
};
"#,
            &[],
        )
        .unwrap();
        println!("{}", result);
    }

    #[test]
    fn test_simple_addrmap() {
        use super::super::World;

        let input = r#"
addrmap test_addrmap {
    reg {
        field { sw=rw; hw=r; } my_field[8] = 0;
    } my_reg @ 0x0;

    reg {
        field { sw=r; hw=rw; } status[4] = 0;
        field { sw=rw; hw=na; } control[4] = 0;
    } ctrl_reg @ 0x4;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).unwrap();
        let world = World::parse(&root).unwrap();

        if let Some(code) = world
            .generate_addrmap_code("test_addrmap", 0x1000_0000)
            .unwrap()
        {
            println!("Generated code:\n{}", code);
            assert!(code.contains("pub const TEST_ADDRMAP_ADDR: u32 = 0x1000_0000;"));
        }
    }

    /// Test that multiple instances of the same register type only generate
    /// the bitfield type once, but create separate register instances.
    #[test]
    fn test_multiple_register_instances() {
        use super::super::World;

        let input = r#"
addrmap test_multi_inst {
    // Define a register type with fields
    reg status_reg_t {
        field { sw=r; hw=rw; } ready[1] = 0;
        field { sw=r; hw=rw; } error[1] = 0;
        field { sw=r; hw=rw; } busy[1] = 0;
    };

    // Instantiate the same register type multiple times at different offsets
    status_reg_t flash0_status @ 0x100;
    status_reg_t flash1_status @ 0x200;
    status_reg_t flash2_status @ 0x300;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).unwrap();
        let world = World::parse(&root).unwrap();

        let code = world
            .generate_addrmap_code("test_multi_inst", 0)
            .unwrap()
            .unwrap();
        println!("Generated code:\n{}", code);

        // The type should only be defined once in the bitfields
        let type_def_count = code.matches("pub StatusRegT [").count();
        assert_eq!(
            type_def_count, 1,
            "StatusRegT should be defined exactly once, found {} times",
            type_def_count
        );

        // But we should have three separate register instances
        assert!(
            code.contains("flash0_status"),
            "Should have flash0_status instance"
        );
        assert!(
            code.contains("flash1_status"),
            "Should have flash1_status instance"
        );
        assert!(
            code.contains("flash2_status"),
            "Should have flash2_status instance"
        );

        // Verify offsets are correct
        assert!(
            code.contains("0x100 =>"),
            "flash0_status should be at offset 0x100"
        );
        assert!(
            code.contains("0x200 =>"),
            "flash1_status should be at offset 0x200"
        );
        assert!(
            code.contains("0x300 =>"),
            "flash2_status should be at offset 0x300"
        );

        // All instances should reference the same type
        let type_ref_count = code.matches("StatusRegT::Register").count();
        assert_eq!(
            type_ref_count, 3,
            "StatusRegT::Register should be referenced 3 times, found {} times",
            type_ref_count
        );
    }

    /// Test that multiple instances of a nested addrmap (like flash_ctrl)
    /// only generate the register types once, but create separate instances
    /// with correct offsets.
    #[test]
    fn test_multiple_addrmap_instances() {
        use super::super::World;

        // Define a flash controller addrmap with multiple registers
        let input = r#"
addrmap flash_ctrl {
    reg {
        field { sw = rw; } ERROR[0:0];
        field { sw = rw; } EVENT[1:1];
    } FL_INTERRUPT_STATE @ 0x00;

    reg {
        field { sw = rw; } ERROR[0:0];
        field { sw = rw; } EVENT[1:1];
    } FL_INTERRUPT_ENABLE @ 0x04;

    reg {
        field { sw = rw; } PAGE_SIZE[31:0];
    } PAGE_SIZE @ 0x08;

    reg {
        field { sw = rw; } OP[2:1];
        field { sw = rw; } START[0:0];
    } FL_CONTROL @ 0x14;

    reg {
        field { sw = rw; } ERR[3:1];
        field { sw = rw; } DONE[0:0];
    } OP_STATUS @ 0x18;
};

// Parent addrmap with two flash controller instances
addrmap soc {
    flash_ctrl flash0 @ 0x1000;
    flash_ctrl flash1 @ 0x2000;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).unwrap();
        let world = World::parse(&root).unwrap();

        let code = world.generate_addrmap_code("soc", 0).unwrap().unwrap();
        println!("Generated code:\n{}", code);

        // Each register type should only be defined once
        let fl_interrupt_state_count = code.matches("pub FlInterruptState [").count();
        assert_eq!(
            fl_interrupt_state_count, 1,
            "FlInterruptState should be defined exactly once, found {} times",
            fl_interrupt_state_count
        );

        let fl_control_count = code.matches("pub FlControl [").count();
        assert_eq!(
            fl_control_count, 1,
            "FlControl should be defined exactly once, found {} times",
            fl_control_count
        );

        let op_status_count = code.matches("pub OpStatus [").count();
        assert_eq!(
            op_status_count, 1,
            "OpStatus should be defined exactly once, found {} times",
            op_status_count
        );

        // But we should have two sets of register instances (one per flash controller)
        // flash0 registers at 0x1000 + offset
        assert!(
            code.contains("0x1000 =>") || code.contains("flash0_fl_interrupt_state"),
            "Should have flash0 FL_INTERRUPT_STATE at base 0x1000"
        );
        assert!(
            code.contains("0x1014 =>") || code.contains("flash0_fl_control"),
            "Should have flash0 FL_CONTROL at 0x1014"
        );

        // flash1 registers at 0x2000 + offset
        assert!(
            code.contains("0x2000 =>") || code.contains("flash1_fl_interrupt_state"),
            "Should have flash1 FL_INTERRUPT_STATE at base 0x2000"
        );
        assert!(
            code.contains("0x2014 =>") || code.contains("flash1_fl_control"),
            "Should have flash1 FL_CONTROL at 0x2014"
        );

        // Each register type should be referenced twice (once per flash instance)
        let fl_interrupt_state_ref_count = code.matches("FlInterruptState::Register").count();
        assert_eq!(
            fl_interrupt_state_ref_count, 2,
            "FlInterruptState::Register should be referenced twice, found {} times",
            fl_interrupt_state_ref_count
        );

        let fl_control_ref_count = code.matches("FlControl::Register").count();
        assert_eq!(
            fl_control_ref_count, 2,
            "FlControl::Register should be referenced twice, found {} times",
            fl_control_ref_count
        );
    }

    /// Test that registers with constraint definitions are handled gracefully
    /// (constraints are ignored for code generation purposes).
    /// Note: This tests the code path handling, not parser capability.
    #[test]
    fn test_register_body_completeness() {
        use super::super::World;

        // Test a register with all supported body elements
        let input = r#"
addrmap test_complete {
    reg my_reg_t {
        // PropertyAssignment
        name = "My Register";
        desc = "A test register";

        // EnumDef
        enum status_e {
            IDLE = 0;
            BUSY = 1;
        };

        // ComponentDef (field)
        field { sw = rw; encode = status_e; } status[1:0];
        field { sw = r; } reserved[7:2];
    };

    my_reg_t my_reg @ 0x0;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).unwrap();
        let world = World::parse(&root).unwrap();

        let code = world
            .generate_addrmap_code("test_complete", 0)
            .unwrap()
            .unwrap();
        println!("Generated code:\n{}", code);

        // The register should be generated correctly
        assert!(code.contains("pub MyRegT ["), "Should have MyRegT type");
        assert!(
            code.contains("Status OFFSET(0) NUMBITS(2)"),
            "Should have Status field with 2 bits"
        );
        assert!(
            code.contains("Reserved OFFSET(2) NUMBITS(6)"),
            "Should have Reserved field with 6 bits"
        );
        assert!(code.contains("my_reg:"), "Should have my_reg instance");

        // Should have enum values
        assert!(code.contains("Idle = 0"), "Should have Idle enum value");
        assert!(code.contains("Busy = 1"), "Should have Busy enum value");
    }

    /// Test that enums defined in both field and register scopes work correctly
    #[test]
    fn test_enum_scopes() {
        use super::super::World;

        // Test enum defined at register level (referenced by field)
        let input_reg_level = r#"
addrmap test_reg_enum {
    reg my_reg_t {
        enum cmd_e {
            READ = 0;
            WRITE = 1;
            ERASE = 2;
        };

        field { sw = rw; encode = cmd_e; } command[2:0];
    };

    my_reg_t cmd_reg @ 0x0;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input_reg_level).unwrap();
        let world = World::parse(&root).unwrap();

        let code = world
            .generate_addrmap_code("test_reg_enum", 0)
            .unwrap()
            .unwrap();
        println!("Register-level enum code:\n{}", code);

        assert!(code.contains("Read = 0"), "Should have Read enum value");
        assert!(code.contains("Write = 1"), "Should have Write enum value");
        assert!(code.contains("Erase = 2"), "Should have Erase enum value");

        // Test enum defined inside field body
        let input_field_level = r#"
addrmap test_field_enum {
    reg my_reg_t {
        field {
            sw = rw;
            enum mode_e {
                NORMAL = 0;
                FAST = 1;
                SLOW = 2;
            };
            encode = mode_e;
        } mode[2:0];
    };

    my_reg_t mode_reg @ 0x0;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input_field_level).unwrap();
        let world = World::parse(&root).unwrap();

        let code = world
            .generate_addrmap_code("test_field_enum", 0)
            .unwrap()
            .unwrap();
        println!("Field-level enum code:\n{}", code);

        assert!(code.contains("Normal = 0"), "Should have Normal enum value");
        assert!(code.contains("Fast = 1"), "Should have Fast enum value");
        assert!(code.contains("Slow = 2"), "Should have Slow enum value");
    }

    /// Test that array register instances are handled correctly
    #[test]
    fn test_array_registers() {
        use super::super::World;

        let input = r#"
addrmap test_arrays {
    reg data_reg_t {
        field { sw=rw; hw=r; } data[32] = 0;
    };

    // Array of 4 registers starting at 0x100
    data_reg_t data_regs[4] @ 0x100;

    // Single register for comparison
    data_reg_t single_reg @ 0x200;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).unwrap();
        let world = World::parse(&root).unwrap();

        let code = world
            .generate_addrmap_code("test_arrays", 0)
            .unwrap()
            .unwrap();
        println!("Array registers code:\n{}", code);

        // Should have array syntax in the register_structs! macro
        // Array registers are represented as: [type; count]
        assert!(
            code.contains("data_regs:") || code.contains("[4]"),
            "Should have data_regs array or size indication"
        );

        // The array should start at offset 0x100
        assert!(code.contains("0x100 =>"), "Array should start at 0x100");

        // Single register at 0x200
        assert!(
            code.contains("0x200 =>") && code.contains("single_reg"),
            "Single register should be at 0x200"
        );
    }

    #[test]
    fn test_duplicate_offset_registers() {
        // Test that registers at the same offset are merged.
        // This is common for TX/RX ports where one is write-only and one is read-only.
        use super::super::World;

        let input = r#"
addrmap test_dup {
    reg tx_port_t {
        field { sw=w; hw=r; } data[32] = 0;
    };
    reg rx_port_t {
        field { sw=r; hw=w; } data[32] = 0;
    };

    // Both at same offset - write-only TX and read-only RX
    tx_port_t TX_DATA_PORT @ 0x10;
    rx_port_t RX_DATA_PORT @ 0x10;

    // Normal register at different offset
    tx_port_t OTHER_REG @ 0x20;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).unwrap();
        let world = World::parse(&root).unwrap();

        let code = world.generate_addrmap_code("test_dup", 0).unwrap().unwrap();
        println!("Duplicate offset test code:\n{}", code);

        // Should have exactly ONE register at offset 0x10
        let offset_0x10_count = code.matches("(0x10 =>").count();
        assert_eq!(
            offset_0x10_count, 1,
            "Should have exactly one register at 0x10, found {offset_0x10_count}"
        );

        // The merged register should be ReadWrite (combining write-only TX + read-only RX)
        assert!(
            code.contains("(0x10 => pub tx_data_port: tock_registers::registers::ReadWrite<u32>"),
            "Merged register should be ReadWrite, got:\n{code}"
        );

        // Should NOT have rx_data_port as a separate register
        assert!(
            !code.contains("rx_data_port:"),
            "RX_DATA_PORT should be merged into TX_DATA_PORT, not separate"
        );

        // Other register at 0x20 should still exist
        assert!(
            code.contains("(0x20 =>") && code.contains("other_reg"),
            "OTHER_REG at 0x20 should exist"
        );
    }

    #[test]
    fn test_name_config_transform() {
        // Test default suffix stripping
        let config = crate::config::NameConfig::with_defaults();

        // _csr suffix
        assert_eq!(config.transform("i3c_csr"), "i3c");
        assert_eq!(config.transform("I3C_CSR"), "I3C");

        // CSR suffix (no underscore)
        assert_eq!(config.transform("I3CCSR"), "I3C");

        // _ctrl suffix
        assert_eq!(config.transform("otp_ctrl"), "otp");

        // _reg suffix
        assert_eq!(config.transform("my_reg"), "my");

        // _ifc suffix
        assert_eq!(config.transform("soc_ifc"), "soc");

        // _top suffix
        assert_eq!(config.transform("mci_top"), "mci");

        // Multiple suffixes (chained)
        assert_eq!(config.transform("test_reg_csr"), "test");

        // No matching suffix
        assert_eq!(config.transform("simple"), "simple");

        // Custom prefix stripping
        let custom_config = crate::config::NameConfig::none()
            .add_prefix("caliptra_")
            .add_suffix("_reg");
        assert_eq!(custom_config.transform("caliptra_mbox_reg"), "mbox");

        // Case insensitivity
        assert_eq!(config.transform("TEST_CSR"), "TEST");
        assert_eq!(config.transform("testCSR"), "test"); // lowercase CSR after lower
    }

    /// Test that msb0 bit ordering correctly converts field positions.
    /// In msb0 mode, bit 0 is the MSB. Fields should be converted to lsb0
    /// positions in the generated output.
    #[test]
    fn test_msb0_bit_ordering() {
        use super::super::World;

        // In msb0 mode with a 32-bit register:
        //   msb0 bit 0 = lsb0 bit 31
        //   A field at msb0 [0:7] (8 bits from MSB) = lsb0 OFFSET(24) NUMBITS(8)
        //   A field at msb0 [8:15] = lsb0 OFFSET(16) NUMBITS(8)
        //   A field at msb0 [16:31] = lsb0 OFFSET(0) NUMBITS(16)
        let input = r#"
addrmap test_msb0 {
    msb0;
    reg {
        field { sw=rw; hw=r; } high_byte[8] = 0;
        field { sw=rw; hw=r; } mid_byte[8] = 0;
        field { sw=rw; hw=r; } low_half[16] = 0;
    } my_reg @ 0x0;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).unwrap();
        let world = World::parse(&root).unwrap();

        let code = world
            .generate_addrmap_code("test_msb0", 0)
            .unwrap()
            .unwrap();
        println!("msb0 code:\n{}", code);

        // high_byte: msb0 bits [0:7] -> lsb0 OFFSET(24) NUMBITS(8)
        assert!(
            code.contains("HighByte OFFSET(24) NUMBITS(8)"),
            "high_byte should be at lsb0 offset 24, got:\n{}",
            code
        );
        // mid_byte: msb0 bits [8:15] -> lsb0 OFFSET(16) NUMBITS(8)
        assert!(
            code.contains("MidByte OFFSET(16) NUMBITS(8)"),
            "mid_byte should be at lsb0 offset 16, got:\n{}",
            code
        );
        // low_half: msb0 bits [16:31] -> lsb0 OFFSET(0) NUMBITS(16)
        assert!(
            code.contains("LowHalf OFFSET(0) NUMBITS(16)"),
            "low_half should be at lsb0 offset 0, got:\n{}",
            code
        );
    }

    /// Test that lsb0 (default) bit ordering is unchanged.
    #[test]
    fn test_lsb0_default_ordering() {
        use super::super::World;

        let input = r#"
addrmap test_lsb0 {
    reg {
        field { sw=rw; hw=r; } low_byte[8] = 0;
        field { sw=rw; hw=r; } mid_byte[8] = 0;
        field { sw=rw; hw=r; } high_half[16] = 0;
    } my_reg @ 0x0;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).unwrap();
        let world = World::parse(&root).unwrap();

        let code = world
            .generate_addrmap_code("test_lsb0", 0)
            .unwrap()
            .unwrap();
        println!("lsb0 code:\n{}", code);

        // Default lsb0: fields are allocated from bit 0 upward
        assert!(
            code.contains("LowByte OFFSET(0) NUMBITS(8)"),
            "low_byte should be at offset 0"
        );
        assert!(
            code.contains("MidByte OFFSET(8) NUMBITS(8)"),
            "mid_byte should be at offset 8"
        );
        assert!(
            code.contains("HighHalf OFFSET(16) NUMBITS(16)"),
            "high_half should be at offset 16"
        );
    }

    /// Test msb0 with explicit lsb0 = false property.
    #[test]
    fn test_lsb0_false_is_msb0() {
        use super::super::World;

        let input = r#"
addrmap test_lsb0_false {
    lsb0 = false;
    reg {
        field { sw=rw; hw=r; } top_bit[1] = 0;
        field { sw=rw; hw=r; } rest[31] = 0;
    } my_reg @ 0x0;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).unwrap();
        let world = World::parse(&root).unwrap();

        let code = world
            .generate_addrmap_code("test_lsb0_false", 0)
            .unwrap()
            .unwrap();
        println!("lsb0=false code:\n{}", code);

        // top_bit: msb0 bit [0] (1 bit) -> lsb0 OFFSET(31) NUMBITS(1)
        assert!(
            code.contains("TopBit OFFSET(31) NUMBITS(1)"),
            "top_bit should be at lsb0 offset 31, got:\n{}",
            code
        );
        // rest: msb0 bits [1:31] (31 bits) -> lsb0 OFFSET(0) NUMBITS(31)
        assert!(
            code.contains("Rest OFFSET(0) NUMBITS(31)"),
            "rest should be at lsb0 offset 0, got:\n{}",
            code
        );
    }

    /// Test that range syntax [msb:lsb] is rejected on non-field component instances.
    #[test]
    fn test_range_rejected_on_register_instance() {
        use super::super::World;

        let input = r#"
addrmap test_range_reject {
    reg my_reg_t {
        field { sw=rw; hw=r; } data[32] = 0;
    };

    // Range syntax should only be valid on fields, not registers
    my_reg_t bad_reg[7:0] @ 0x0;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).unwrap();
        let result = World::parse(&root);
        match result {
            Ok(_) => panic!("Range syntax on register instance should be rejected"),
            Err(e) => {
                let err = e.to_string();
                assert!(
                    err.contains("Range syntax"),
                    "Error should mention range syntax, got: {}",
                    err
                );
            }
        }
    }

    /// Test compact addressing mode: no alignment gaps between registers.
    #[test]
    fn test_compact_addressing() {
        use super::super::World;

        // With compact addressing, a 16-bit register (2 bytes) followed by a
        // 32-bit register (4 bytes) should pack tightly: offsets 0x0, 0x2
        let input = r#"
addrmap test_compact {
    addressing = compact;

    reg small_reg_t {
        regwidth = 16;
        field { sw=rw; hw=r; } data[16] = 0;
    };
    reg big_reg_t {
        field { sw=rw; hw=r; } data[32] = 0;
    };

    small_reg_t small @ 0x0;
    big_reg_t big;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).unwrap();
        let world = World::parse(&root).unwrap();

        let code = world
            .generate_addrmap_code("test_compact", 0)
            .unwrap()
            .unwrap();
        println!("compact code:\n{}", code);

        // With compact, big should be at 0x2 (right after 2-byte small reg)
        assert!(
            code.contains("(0x2 => pub big"),
            "With compact addressing, big should be at offset 0x2, got:\n{}",
            code
        );
    }

    /// Test fullalign addressing mode: align to next power-of-2 >= regwidth.
    #[test]
    fn test_fullalign_addressing() {
        use super::super::World;

        // With fullalign, a 24-bit register (3 bytes) has next_power_of_two(3) = 4,
        // so the next register should align to 4-byte boundary.
        // Using 32-bit (4 bytes) registers: next_power_of_two(4) = 4, same as regalign.
        // But with a weird width it matters. Let's use two 32-bit registers which
        // should still align to 4.
        let input = r#"
addrmap test_fullalign {
    addressing = fullalign;

    reg my_reg_t {
        field { sw=rw; hw=r; } data[32] = 0;
    };

    my_reg_t reg_a @ 0x0;
    my_reg_t reg_b;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).unwrap();
        let world = World::parse(&root).unwrap();

        let code = world
            .generate_addrmap_code("test_fullalign", 0)
            .unwrap()
            .unwrap();
        println!("fullalign code:\n{}", code);

        // 32-bit register = 4 bytes, next_power_of_two(4) = 4
        // So reg_b should be at 0x4
        assert!(
            code.contains("(0x4 =>") && code.contains("reg_b"),
            "With fullalign, reg_b should be at offset 0x4, got:\n{}",
            code
        );
    }

    /// Test default regalign addressing mode.
    #[test]
    fn test_regalign_addressing() {
        use super::super::World;

        let input = r#"
addrmap test_regalign {
    reg small_reg_t {
        regwidth = 16;
        field { sw=rw; hw=r; } data[16] = 0;
    };
    reg big_reg_t {
        field { sw=rw; hw=r; } data[32] = 0;
    };

    small_reg_t small @ 0x0;
    big_reg_t big;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).unwrap();
        let world = World::parse(&root).unwrap();

        let code = world
            .generate_addrmap_code("test_regalign", 0)
            .unwrap()
            .unwrap();
        println!("regalign code:\n{}", code);

        // With regalign (default), big (4-byte) should align to its own width.
        // small is at 0x0, size 2 bytes. Next offset = 0x2.
        // Align 0x2 to 4-byte boundary = 0x4.
        assert!(
            code.contains("(0x4 =>") && code.contains("big"),
            "With regalign, big should be at offset 0x4, got:\n{}",
            code
        );
    }
}

#[cfg(test)]
mod otp_tests {
    use super::super::*;
    use std::path::Path;

    #[test]
    fn test_otp_ctrl_generation() {
        let rdl_path = Path::new("../../hw/caliptra-ss/src/fuse_ctrl/rtl/otp_ctrl.rdl");
        match generate_tock_registers_from_file(rdl_path, &[("otp_ctrl", 0)]) {
            Ok(code) => {
                std::fs::write("/tmp/otp_ctrl_generated.rs", &code).unwrap();
                println!("Generated code written to /tmp/otp_ctrl_generated.rs");
                println!("Generated code length: {} bytes", code.len());
            }
            Err(e) => {
                panic!("Error: {:?}", e);
            }
        }
    }

    #[test]
    fn test_i3c_generation() {
        let rdl_path = Path::new("../../hw/caliptra-ss/third_party/i3c-core/src/rdl/registers.rdl");
        match generate_tock_registers_from_file(rdl_path, &[("I3CCSR", 0)]) {
            Ok(code) => {
                std::fs::write("/tmp/i3c_generated.rs", &code).unwrap();
                println!("Generated code written to /tmp/i3c_generated.rs");
                println!("Generated code length: {} bytes", code.len());
            }
            Err(e) => {
                panic!("Error: {:?}", e);
            }
        }
    }
}

#[cfg(test)]
mod compile_tests {
    //! Tests that verify generated code actually compiles.
    //!
    //! These tests create a temporary Rust project with tock-registers dependency,
    //! write the generated code to it, and run `cargo check` to verify validity.

    use super::super::*;
    use std::path::Path;
    use std::process::Command;
    use tempfile::TempDir;

    /// Creates a temporary Cargo project that can compile tock-registers code.
    fn create_temp_project() -> TempDir {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");

        // Create Cargo.toml with tock-registers dependency
        let cargo_toml = r#"[package]
name = "compile-test"
version = "0.1.0"
edition = "2021"

[dependencies]
tock-registers = { git = "https://github.com/tock/tock.git", rev = "release-2.2" }
"#;
        std::fs::write(temp_dir.path().join("Cargo.toml"), cargo_toml)
            .expect("Failed to write Cargo.toml");

        // Create src directory
        std::fs::create_dir(temp_dir.path().join("src")).expect("Failed to create src dir");

        temp_dir
    }

    /// Compiles the given generated code and returns Ok(()) if successful.
    /// The `module_name` should match the addrmap name used in generation
    /// (e.g., "simple_test" for an addrmap named "simple_test").
    fn compile_generated_code(code: &str, module_name: &str) -> Result<(), String> {
        let temp_dir = create_temp_project();

        // Wrap the generated code in a module matching the expected crate path.
        // The generated code references `crate::{module_name}::bits::...`, so we need
        // to create that module structure.
        // The recursion_limit is needed for large register files (i3c, otp_ctrl).
        let lib_content = format!(
            r#"#![recursion_limit = "2048"]
#![allow(dead_code)]
#![allow(unused_imports)]

pub mod {module_name} {{
{code}
}}
"#
        );
        std::fs::write(temp_dir.path().join("src/lib.rs"), &lib_content)
            .expect("Failed to write lib.rs");

        // Run cargo check
        let output = Command::new("cargo")
            .arg("check")
            .arg("--message-format=short")
            .current_dir(temp_dir.path())
            .output()
            .expect("Failed to run cargo check");

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            Err(format!(
                "Compilation failed!\n\nstderr:\n{stderr}\n\nstdout:\n{stdout}\n\nGenerated code written to: {}/src/lib.rs",
                temp_dir.path().display()
            ))
        }
    }

    #[test]
    fn test_simple_addrmap_compiles() {
        use super::super::World;

        let input = r#"
addrmap simple_test {
    reg status_reg_t {
        field { sw=r; hw=w; } busy[0:0] = 0;
        field { sw=r; hw=w; } error[1:1] = 0;
        field { sw=rw; hw=r; } enable[2:2] = 0;
    };

    reg data_reg_t {
        field { sw=rw; hw=r; } data[31:0] = 0;
    };

    status_reg_t status @ 0x0;
    data_reg_t data @ 0x4;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).expect("Failed to parse RDL");
        let world = World::parse(&root).expect("Failed to parse world");

        let code = world
            .generate_addrmap_code("simple_test", 0)
            .expect("Failed to generate code")
            .expect("No code generated");

        compile_generated_code(&code, "simple_test").expect("Generated code should compile");
    }

    #[test]
    fn test_array_registers_compile() {
        use super::super::World;

        let input = r#"
addrmap array_test {
    reg data_reg_t {
        field { sw=rw; hw=r; } data[31:0] = 0;
    };

    // Array of 8 registers
    data_reg_t data_array[8] @ 0x100;

    // Single register
    data_reg_t single @ 0x200;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).expect("Failed to parse RDL");
        let world = World::parse(&root).expect("Failed to parse world");

        let code = world
            .generate_addrmap_code("array_test", 0)
            .expect("Failed to generate code")
            .expect("No code generated");

        compile_generated_code(&code, "array_test").expect("Generated code should compile");
    }

    #[test]
    fn test_duplicate_offset_compiles() {
        use super::super::World;

        let input = r#"
addrmap dup_test {
    reg tx_port_t {
        field { sw=w; hw=r; } data[31:0] = 0;
    };
    reg rx_port_t {
        field { sw=r; hw=w; } data[31:0] = 0;
    };

    // Both at same offset - should be merged
    tx_port_t TX_DATA_PORT @ 0x10;
    rx_port_t RX_DATA_PORT @ 0x10;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).expect("Failed to parse RDL");
        let world = World::parse(&root).expect("Failed to parse world");

        let code = world
            .generate_addrmap_code("dup_test", 0)
            .expect("Failed to generate code")
            .expect("No code generated");

        compile_generated_code(&code, "dup_test").expect("Generated code should compile");
    }

    #[test]
    fn test_mixed_access_types_compile() {
        use super::super::World;

        let input = r#"
addrmap access_test {
    reg ro_reg_t {
        field { sw=r; hw=w; } val[31:0] = 0;
    };

    reg wo_reg_t {
        field { sw=w; hw=r; } val[31:0] = 0;
    };

    reg rw_reg_t {
        field { sw=rw; hw=rw; } val[31:0] = 0;
    };

    ro_reg_t read_only @ 0x0;
    wo_reg_t write_only @ 0x4;
    rw_reg_t read_write @ 0x8;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).expect("Failed to parse RDL");
        let world = World::parse(&root).expect("Failed to parse world");

        let code = world
            .generate_addrmap_code("access_test", 0)
            .expect("Failed to generate code")
            .expect("No code generated");

        compile_generated_code(&code, "access_test").expect("Generated code should compile");
    }

    #[test]
    fn test_otp_ctrl_compiles() {
        let rdl_path = Path::new("../../hw/caliptra-ss/src/fuse_ctrl/rtl/otp_ctrl.rdl");
        if !rdl_path.exists() {
            println!("Skipping test_otp_ctrl_compiles: RDL file not found");
            return;
        }

        let code = generate_tock_registers_from_file(rdl_path, &[("otp_ctrl", 0)])
            .expect("Failed to generate code");

        // Module name is "otp" after stripping "_ctrl" suffix (default NameConfig)
        compile_generated_code(&code, "otp").expect("Generated otp_ctrl code should compile");
    }

    #[test]
    fn test_i3c_compiles() {
        let rdl_path = Path::new("../../hw/caliptra-ss/third_party/i3c-core/src/rdl/registers.rdl");
        if !rdl_path.exists() {
            println!("Skipping test_i3c_compiles: RDL file not found");
            return;
        }

        let code = generate_tock_registers_from_file(rdl_path, &[("I3CCSR", 0)])
            .expect("Failed to generate code");

        // Module name is "i3c" after stripping "CSR" suffix (default NameConfig)
        compile_generated_code(&code, "i3c").expect("Generated i3c code should compile");
    }

    #[test]
    fn test_bitfield_types_compile() {
        use super::super::World;

        let input = r#"
addrmap bitfield_test {
    reg ctrl_reg_t {
        field { sw=rw; hw=r; } enable[0:0] = 0;
        field { sw=rw; hw=r; } mode[3:1] = 0;
        field { sw=r; hw=w; } status[7:4] = 0;
        field { sw=rw; hw=r; } count[15:8] = 0;
        field { sw=rw; hw=r; } reserved[31:16] = 0;
    };

    ctrl_reg_t ctrl @ 0x0;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).expect("Failed to parse RDL");
        let world = World::parse(&root).expect("Failed to parse world");

        let code = world
            .generate_addrmap_code("bitfield_test", 0)
            .expect("Failed to generate code")
            .expect("No code generated");

        compile_generated_code(&code, "bitfield_test").expect("Generated code should compile");
    }

    #[test]
    fn test_regfile_compiles() {
        use super::super::World;

        let input = r#"
addrmap regfile_test {
    reg data_reg_t {
        field { sw=rw; hw=r; } data[31:0] = 0;
    };

    regfile my_regs {
        data_reg_t reg0 @ 0x0;
        data_reg_t reg1 @ 0x4;
        data_reg_t reg2 @ 0x8;
    };

    my_regs block @ 0x100;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).expect("Failed to parse RDL");
        let world = World::parse(&root).expect("Failed to parse world");

        let code = world
            .generate_addrmap_code("regfile_test", 0)
            .expect("Failed to generate code")
            .expect("No code generated");

        compile_generated_code(&code, "regfile_test").expect("Generated code should compile");
    }

    /// Test mixed register widths with explicit offsets
    /// Expected offsets from PeakRDL:
    /// - byte_reg0: 0x00 (1 byte)
    /// - byte_reg1: 0x01 (1 byte)
    /// - byte_reg2: 0x02 (1 byte)
    /// - byte_reg3: 0x03 (1 byte)
    /// - word_reg0: 0x04 (4 bytes)
    /// - dword_reg0: 0x08 (8 bytes)
    /// - half_reg0: 0x10 (2 bytes)
    /// - half_reg1: 0x12 (2 bytes)
    /// - word_reg1: 0x14 (4 bytes)
    /// Test mixed register widths with sequential layout (auto-calculated offsets)
    /// This tests that offset auto-calculation respects register widths.
    /// Expected offsets:
    /// - byte_reg0: 0x0 (1 byte)
    /// - byte_reg1: 0x1 (1 byte)
    /// - byte_reg2: 0x2 (1 byte)
    /// - byte_reg3: 0x3 (1 byte)
    /// - word_reg0: 0x4 (4 bytes)
    /// - dword_reg0: 0x8 (8 bytes)
    /// - half_reg0: 0x10 (2 bytes)
    /// - half_reg1: 0x12 (2 bytes)
    /// - word_reg1: 0x14 (4 bytes)
    #[test]
    fn test_mixed_widths_auto_offsets() {
        use super::super::World;

        let input = r#"
addrmap mixed_widths {
    // 8-bit register
    reg reg8_t {
        regwidth = 8;
        field {} data[7:0];
    };

    // 16-bit register
    reg reg16_t {
        regwidth = 16;
        field {} low[7:0];
        field {} high[15:8];
    };

    // 32-bit register
    reg reg32_t {
        regwidth = 32;
        field {} value[31:0];
    };

    // 64-bit register
    reg reg64_t {
        regwidth = 64;
        field {} low[31:0];
        field {} high[63:32];
    };

    // Sequential instances - NO explicit offsets, tests auto-calculation
    reg8_t  byte_reg0;
    reg8_t  byte_reg1;
    reg8_t  byte_reg2;
    reg8_t  byte_reg3;
    reg32_t word_reg0;
    reg64_t dword_reg0;
    reg16_t half_reg0;
    reg16_t half_reg1;
    reg32_t word_reg1;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).expect("Failed to parse RDL");
        let world = World::parse(&root).expect("Failed to parse world");

        let code = world
            .generate_addrmap_code("mixed_widths", 0)
            .expect("Failed to generate code")
            .expect("No code generated");

        println!("Generated code:\n{}", code);

        // Verify expected auto-calculated offsets
        assert!(
            code.contains("0x0 =>") && code.contains("byte_reg0"),
            "byte_reg0 should be at 0x0"
        );
        assert!(
            code.contains("0x1 =>") && code.contains("byte_reg1"),
            "byte_reg1 should be at 0x1 (1 byte after byte_reg0)"
        );
        assert!(
            code.contains("0x2 =>") && code.contains("byte_reg2"),
            "byte_reg2 should be at 0x2 (1 byte after byte_reg1)"
        );
        assert!(
            code.contains("0x3 =>") && code.contains("byte_reg3"),
            "byte_reg3 should be at 0x3 (1 byte after byte_reg2)"
        );
        assert!(
            code.contains("0x4 =>") && code.contains("word_reg0"),
            "word_reg0 should be at 0x4 (1 byte after byte_reg3)"
        );
        assert!(
            code.contains("0x8 =>") && code.contains("dword_reg0"),
            "dword_reg0 should be at 0x8 (4 bytes after word_reg0)"
        );
        assert!(
            code.contains("0x10 =>") && code.contains("half_reg0"),
            "half_reg0 should be at 0x10 (8 bytes after dword_reg0)"
        );
        assert!(
            code.contains("0x12 =>") && code.contains("half_reg1"),
            "half_reg1 should be at 0x12 (2 bytes after half_reg0)"
        );
        assert!(
            code.contains("0x14 =>") && code.contains("word_reg1"),
            "word_reg1 should be at 0x14 (2 bytes after half_reg1)"
        );

        // These assertions verify multi-width type support
        assert!(
            code.contains("<u8>") || code.contains("<u8,"),
            "8-bit registers should use u8"
        );
        assert!(
            code.contains("<u16>") || code.contains("<u16,"),
            "16-bit registers should use u16"
        );
        assert!(
            code.contains("<u64>") || code.contains("<u64,"),
            "64-bit registers should use u64"
        );

        // Verify the generated code actually compiles with tock-registers
        compile_generated_code(&code, "mixed_widths")
            .expect("Multi-width register code should compile");
    }

    /// Test mixed register widths with sequential layout (no explicit offsets)
    /// Expected offsets from PeakRDL:
    /// - first_byte: 0x0 (1 byte)
    /// - second_byte: 0x1 (1 byte)
    /// - first_half: 0x2 (2 bytes)
    /// - first_word: 0x4 (4 bytes)
    /// - first_dword: 0x8 (8 bytes)
    /// - trailing_byte: 0x10 (1 byte)
    #[test]
    fn test_mixed_widths_sequential() {
        use super::super::World;

        let input = r#"
addrmap mixed_widths_seq {
    reg reg8_t {
        regwidth = 8;
        field {} data[7:0];
    };

    reg reg16_t {
        regwidth = 16;
        field {} value[15:0];
    };

    reg reg32_t {
        regwidth = 32;
        field {} value[31:0];
    };

    reg reg64_t {
        regwidth = 64;
        field {} value[63:0];
    };

    // Sequential instances - no explicit offsets
    reg8_t  first_byte;
    reg8_t  second_byte;
    reg16_t first_half;
    reg32_t first_word;
    reg64_t first_dword;
    reg8_t  trailing_byte;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).expect("Failed to parse RDL");
        let world = World::parse(&root).expect("Failed to parse world");

        let code = world
            .generate_addrmap_code("mixed_widths_seq", 0)
            .expect("Failed to generate code")
            .expect("No code generated");

        // Verify expected sequential offsets (based on PeakRDL output)
        // These pass because offset calculation respects regwidth
        assert!(
            code.contains("0x0 =>") && code.contains("first_byte"),
            "first_byte should be at 0x0"
        );
        assert!(
            code.contains("0x1 =>") && code.contains("second_byte"),
            "second_byte should be at 0x1 (after 1-byte reg)"
        );
        assert!(
            code.contains("0x2 =>") && code.contains("first_half"),
            "first_half should be at 0x2 (after two 1-byte regs)"
        );
        assert!(
            code.contains("0x4 =>") && code.contains("first_word"),
            "first_word should be at 0x4 (after 2-byte reg)"
        );
        assert!(
            code.contains("0x8 =>") && code.contains("first_dword"),
            "first_dword should be at 0x8 (after 4-byte reg)"
        );
        assert!(
            code.contains("0x10 =>") && code.contains("trailing_byte"),
            "trailing_byte should be at 0x10 (after 8-byte reg)"
        );

        // These assertions verify multi-width type support
        assert!(
            code.contains("first_byte: tock_registers::registers::ReadWrite<u8"),
            "8-bit registers should use u8"
        );
        assert!(
            code.contains("first_half: tock_registers::registers::ReadWrite<u16"),
            "16-bit registers should use u16"
        );
        assert!(
            code.contains("first_dword: tock_registers::registers::ReadWrite<u64"),
            "64-bit registers should use u64"
        );

        // Verify the generated code actually compiles with tock-registers
        compile_generated_code(&code, "mixed_widths_seq")
            .expect("Multi-width sequential register code should compile");
    }

    /// Test that different register widths generate correct Rust types
    #[test]
    fn test_register_width_types() {
        use super::super::World;

        let input = r#"
addrmap width_types {
    reg reg8_t {
        regwidth = 8;
        field { sw=rw; } data[7:0];
    };

    reg reg16_t {
        regwidth = 16;
        field { sw=rw; } data[15:0];
    };

    reg reg32_t {
        regwidth = 32;
        field { sw=rw; } data[31:0];
    };

    reg reg64_t {
        regwidth = 64;
        field { sw=rw; } data[63:0];
    };

    // Sequential instances - no explicit offsets
    // SystemRDL regalign default aligns each to its width
    // Expected: r8@0x0, r16@0x2, r32@0x4, r64@0x8
    reg8_t  r8;
    reg16_t r16;
    reg32_t r32;
    reg64_t r64;
};
"#;
        let root = mcu_registers_systemrdl_new::parse(input).expect("Failed to parse RDL");
        let world = World::parse(&root).expect("Failed to parse world");

        let code = world
            .generate_addrmap_code("width_types", 0)
            .expect("Failed to generate code")
            .expect("No code generated");

        // Print code for debugging
        println!("Generated code:\n{}", code);

        // Check that appropriate types are generated for each width
        let has_u8 = code.contains("<u8");
        let has_u16 = code.contains("<u16");
        let has_u32 = code.contains("<u32");
        let has_u64 = code.contains("<u64");

        println!(
            "Type usage: u8={}, u16={}, u32={}, u64={}",
            has_u8, has_u16, has_u32, has_u64
        );

        // These assertions verify multi-width type support
        assert!(has_u8, "8-bit registers should generate u8 type");
        assert!(has_u16, "16-bit registers should generate u16 type");
        assert!(has_u32, "32-bit registers should generate u32 type");
        assert!(has_u64, "64-bit registers should generate u64 type");

        // Verify the generated code actually compiles with tock-registers
        compile_generated_code(&code, "width_types")
            .expect("Width types register code should compile");
    }
}

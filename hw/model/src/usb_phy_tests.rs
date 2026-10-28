// Licensed under the Apache-2.0 license

use super::ModelEmulated;
use crate::{InitParams, McuHwModel};
use caliptra_emu_bus::Bus;
use caliptra_emu_types::RvSize;
use caliptra_mcu_emulator_periph::LpcipUsbPhyError;
use caliptra_mcu_registers_generated::usb_dev0_mem::USB_DEV0_MEM_ADDR;

fn branch(rs1: u32, rs2: u32, offset: i32, not_equal: bool) -> u32 {
    assert!((-4096..4096).contains(&offset) && offset % 2 == 0);
    let imm = offset as u32;
    ((imm >> 12) & 1) << 31
        | ((imm >> 5) & 0x3f) << 25
        | rs2 << 20
        | rs1 << 15
        | u32::from(not_equal) << 12
        | ((imm >> 1) & 0xf) << 8
        | ((imm >> 11) & 1) << 7
        | 0x63
}

fn load_immediate(program: &mut Vec<u32>, register: u32, value: u32) {
    program.push((value.wrapping_add(0x800) & 0xffff_f000) | register << 7 | 0x37);
    program.push((value & 0xfff) << 20 | register << 15 | register << 7 | 0x13);
}

fn phy_init_rom(expected_vendor_low: u8) -> Vec<u8> {
    // Execute the ROM's ULPI protocol on the CPU: stage each command, start
    // ACCESS, bounded-poll completion, then inspect identity/scratch readback.
    // No model-side initialization or production recovery firmware is needed.
    let mut program = vec![
        0x2000_10b7, // lui x1, 0x20001
        0x03c0_8093, // addi x1, x1, 0x3c (ULPIDEBUG)
        0x0200_01b7, // lui x3, 0x02000 (ACCESS)
        0x3000_03b7, // lui x7, 0x30000 (result in Device 0 SRAM)
    ];
    let mut failures = Vec::new();
    for (address, write, data) in [
        (0u8, false, expected_vendor_low),
        (1, false, 4),
        (2, false, 7),
        (3, false, 0),
        (0x16, true, 0xa5),
        (0x16, false, 0xa5),
        (0x17, true, 0x0f),
        (0x16, false, 0xaf),
        (0x18, true, 0xf0),
        (0x16, false, 0x0f),
        (4, true, 0x40),
        (10, true, 0),
        (4, false, 0x40),
        (10, false, 0),
    ] {
        let command = (1 << 31)
            | u32::from(address)
            | if write {
                (1 << 24) | (u32::from(data) << 8)
            } else {
                0
            };
        load_immediate(&mut program, 2, command);
        program.push(0x0020_a023); // sw x2, 0(x1) (stage)
        load_immediate(&mut program, 2, command | (1 << 25));
        program.extend([
            0x0020_a023, // sw x2, 0(x1) (start)
            0x0100_0213, // li x4, 16 (bounded poll)
            0x0000_a283, // poll: lw x5, 0(x1)
            0x0032_f333, // and x6, x5, x3
            0xfff2_0213, // addi x4, x4, -1
            branch(6, 0, 12, false),
            branch(4, 0, -16, true),
        ]);
        failures.push((program.len(), 0, 0, false));
        program.push(0); // Timeout branches to failure.
        if !write {
            program.extend([
                0x0102_d293, // srli x5, x5, 16
                0x0ff2_f293, // andi x5, x5, 255
            ]);
            load_immediate(&mut program, 6, u32::from(data));
            failures.push((program.len(), 5, 6, true));
            program.push(0); // Identity/scratch mismatch branches to failure.
        }
    }
    load_immediate(&mut program, 1, 0x2000_0000);
    load_immediate(&mut program, 2, (1 << 16) | (1 << 7));
    program.push(0x0020_a023); // DCON | DEV_EN, only after successful PHY init
    program.extend([
        0x0010_0113, // li x2, 1 (success)
        0x0023_a023, // sw x2, 0(x7)
        0x0000_006f, // j .
    ]);
    let failure = program.len();
    for (index, rs1, rs2, not_equal) in failures {
        let offset = ((failure - index) * 4) as i32;
        program[index] = branch(rs1, rs2, offset, not_equal);
    }
    program.extend([
        0x0020_0113, // li x2, 2 (failure)
        0x0023_a023, // sw x2, 0(x7)
        0x0000_006f, // j .
    ]);
    program.into_iter().flat_map(u32::to_le_bytes).collect()
}

#[test]
fn test_lpcip_phy_rom_initializes_before_dcon() {
    let rom = phy_init_rom(0x24);
    let mut model = ModelEmulated::new_unbooted(InitParams {
        mcu_rom: &rom,
        ..Default::default()
    })
    .unwrap();
    let host = model.lpcip_usb_host_controller.clone();
    host.set_vbus(true);
    model.cpu_enabled.set(true);
    for _ in 0..2000 {
        model.step();
        if host.connected() {
            break;
        }
    }
    assert!(host.connected(), "ROM did not complete PHY initialization");
    // The first observed connection must already have the programmed controls.
    let snapshot = host.phy().snapshot();
    assert_eq!(snapshot.function_control, 0x40);
    assert_eq!(snapshot.otg_control, 0);
    assert_eq!(snapshot.scratch, 0x0f);
    assert_eq!(snapshot.completed_accesses, 14);
    assert_eq!(snapshot.last_error, None);
    for _ in 0..10 {
        model.step();
    }
    assert_eq!(
        model.cpu.bus.read(RvSize::Word, USB_DEV0_MEM_ADDR).unwrap(),
        1
    );
}

#[test]
fn test_lpcip_phy_rom_timeout_is_bounded_and_never_connects() {
    let rom = phy_init_rom(0x24);
    let mut model = ModelEmulated::new_unbooted(InitParams {
        mcu_rom: &rom,
        ..Default::default()
    })
    .unwrap();
    let host = model.lpcip_usb_host_controller.clone();
    host.set_vbus(true);
    host.phy().set_access_stalled(true);
    model.cpu_enabled.set(true);
    for _ in 0..1000 {
        model.step();
        assert!(!host.connected());
    }
    assert_eq!(
        model.cpu.bus.read(RvSize::Word, USB_DEV0_MEM_ADDR).unwrap(),
        2
    );
    let snapshot = host.phy().snapshot();
    assert!(snapshot.access_pending);
    assert_eq!(snapshot.completed_accesses, 0);
    assert_eq!(snapshot.last_error, Some(LpcipUsbPhyError::AccessStalled));
    assert_eq!(snapshot.function_control, 0x41);
    assert_eq!(snapshot.otg_control, 6);
}

#[test]
fn test_lpcip_phy_rom_rejects_identity_mismatch_before_connect() {
    let rom = phy_init_rom(0x25);
    let mut model = ModelEmulated::new_unbooted(InitParams {
        mcu_rom: &rom,
        ..Default::default()
    })
    .unwrap();
    let host = model.lpcip_usb_host_controller.clone();
    host.set_vbus(true);
    model.cpu_enabled.set(true);
    for _ in 0..1000 {
        model.step();
        assert!(!host.connected());
    }
    assert_eq!(
        model.cpu.bus.read(RvSize::Word, USB_DEV0_MEM_ADDR).unwrap(),
        2
    );
    let snapshot = host.phy().snapshot();
    assert_eq!(snapshot.completed_accesses, 1);
    assert_eq!(snapshot.last_error, None);
    assert_eq!(snapshot.function_control, 0x41);
    assert_eq!(snapshot.otg_control, 6);
}

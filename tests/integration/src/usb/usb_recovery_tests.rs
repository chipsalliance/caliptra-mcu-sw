// Licensed under the Apache-2.0 license

use caliptra_emu_bus::Bus;
use caliptra_emu_periph::dma::axi_root_bus::AxiRootBus;
use caliptra_emu_types::RvSize;
use caliptra_mcu_emulator_periph::LpcipUsbHostController;
use caliptra_mcu_hw_model::{InitParams, McuHwModel, ModelEmulated};

fn model() -> ModelEmulated {
    // Minimal MCU firmware configures the shared SETUP mirror and connection.
    // Recovery routing, data and responses still traverse the real peripherals.
    let rom: Vec<u8> = [
        0x2000_00b7u32, // lui x1, 0x20000
        0x3000_0137,    // lui x2, 0x30000
        0x0001_01b7,    // lui x3, 0x10
        0x4801_8193,    // addi x3, x3, 0x480 (DCON|DEV_EN|FORCE_VBUS)
        0x0030_a023,    // sw x3, 0(x1)
        0x0020_a423,    // sw x2, 8(x1)
        0x0020_a623,    // sw x2, 12(x1)
        0x0040_0193,    // li x3, 4
        0x0031_2223,    // sw x3, 4(x2) (SETUP buffer at SRAM+0x100)
        0x0000_006f,    // j .
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect();
    let mut model = ModelEmulated::new_unbooted(InitParams {
        mcu_rom: &rom,
        usb_recovery: true,
        check_booted_to_runtime: false,
        ..Default::default()
    })
    .unwrap();
    model.boot().unwrap();
    for _ in 0..100 {
        model.step();
    }
    assert!(
        !model.has_bmc_for_test(),
        "USB recovery must not auto-load BMC images"
    );
    assert!(model.lpcip_usb_host_controller.connected());
    model
}

fn put(host: &LpcipUsbHostController, command: u8, data: &[u8]) {
    let [low, high] = (data.len() as u16).to_le_bytes();
    host.host_setup(0, &[0x21, 0, command, 0, 0, 0, low, high])
        .unwrap();
    host.host_out(0, 0, data).unwrap();
    assert!(host.host_in(0, 0).unwrap().is_empty());
}

fn progress(model: &mut ModelEmulated) {
    // Deliver via the registered MCU/core CPU event channels, not a local mock.
    for _ in 0..1000 {
        model.mcu_bus_for_test().poll();
        model.step();
    }
}

fn start_dma_read(model: &mut ModelEmulated, address: u64, bytes: u32) {
    let dma = model.caliptra_dma_for_test();
    for (offset, value) in [
        (8, 2), // FLUSH
        (0x14, address as u32),
        (0x18, (address >> 32) as u32),
        (0x24, bytes),
        (8, (2 << 16) | 1), // AXI -> AHB read FIFO, GO
    ] {
        dma.write(RvSize::Word, offset, value).unwrap();
    }
}

fn dma_busy(model: &mut ModelEmulated) -> bool {
    model
        .caliptra_dma_for_test()
        .read(RvSize::Word, 0x0c)
        .unwrap()
        & 1
        != 0
}

fn finish_dma_read(model: &mut ModelEmulated, words: usize) -> Vec<u32> {
    progress(model);
    let dma = model.caliptra_dma_for_test();
    let status = dma.read(RvSize::Word, 0x0c).unwrap();
    assert_eq!(
        status & 3,
        0,
        "Caliptra recovery DMA is busy or failed: {status:#x}"
    );
    (0..words)
        .map(|_| dma.read(RvSize::Word, 0x30).unwrap())
        .collect()
}

#[test]
fn test_lpcip_recovery_caliptra_axi_streams_beyond_fifo_depth() {
    let mut model = model();
    let host = model.lpcip_usb_host_controller.clone();
    put(&host, 0x2d, &[0, 1, 151, 0, 0, 0]);
    let mut expected: Vec<u8> = (0..601).map(|index| (index % 251) as u8).collect();
    let address = AxiRootBus::RECOVERY_REGISTER_INTERFACE_OFFSET + 0x68;
    assert!(model.caliptra_dma_for_test().axi.must_schedule(address));
    start_dma_read(&mut model, address, 604);
    progress(&mut model);
    assert!(dma_busy(&mut model));
    for (index, packet) in expected.chunks(64).enumerate() {
        put(&host, 0x2f, packet);
        assert!(host.recovery_snapshot().unwrap().fifo_words <= 64);
        progress(&mut model);
        if index < 9 {
            assert!(dma_busy(&mut model));
        }
    }
    let received: Vec<u8> = finish_dma_read(&mut model, 151)
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    expected.resize(604, 0);
    assert_eq!(received.len(), 604);
    assert_eq!(received, expected);
    assert_eq!(host.recovery_snapshot().unwrap().accepted_words, 151);
    assert_eq!(host.recovery_snapshot().unwrap().fifo_words, 0);
    assert_eq!(
        model
            .mcu_bus_for_test()
            .read(RvSize::Word, 0x2000_0a04)
            .unwrap(),
        5
    );
    put(&host, 0x26, &[0, 1, 0x0f]);
    assert!(host.recovery_snapshot().unwrap().image_activated);
    start_dma_read(
        &mut model,
        AxiRootBus::RECOVERY_REGISTER_INTERFACE_OFFSET + 0x3c,
        4,
    );
    assert_eq!(finish_dma_read(&mut model, 1), [0x000f_0100]);
}

#[test]
fn test_lpcip_recovery_caliptra_register_events_use_the_usb_aperture() {
    let mut model = model();
    let address = AxiRootBus::RECOVERY_REGISTER_INTERFACE_OFFSET;
    start_dma_read(&mut model, address + 4, 16);
    assert_eq!(
        finish_dma_read(&mut model, 4),
        [0x2050_434f, 0x5643_4552, 0x1a9a_0101, 1]
    );
    // Caliptra firmware status is returned to the USB Recovery Agent verbatim.
    model
        .caliptra_dma_for_test()
        .axi
        .write(RvSize::Word, address + 0x40, 0x21)
        .unwrap();
    progress(&mut model);
    let host = &model.lpcip_usb_host_controller;
    host.host_setup(0, &[0xa1, 0, 0x27, 0, 0, 0, 64, 0])
        .unwrap();
    assert_eq!(host.host_in(0, 0).unwrap(), [0x21, 0]);
    host.host_out(0, 0, &[]).unwrap();
    assert_eq!(
        model
            .mcu_bus_for_test()
            .read(RvSize::Word, 0x2000_0840)
            .unwrap(),
        0x21
    );
}

#[test]
fn test_lpcip_recovery_rejects_competing_i3c_event_owners() {
    for (flash_boot, network_boot) in [(true, false), (false, true)] {
        let error = ModelEmulated::new_unbooted(InitParams {
            usb_recovery: true,
            flash_boot,
            network_boot,
            ..Default::default()
        })
        .err()
        .expect("competing recovery transports must be rejected");
        assert!(error.to_string().contains("USB recovery cannot share"));
    }
}

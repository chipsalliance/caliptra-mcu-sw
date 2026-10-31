// Licensed under the Apache-2.0 license

//! Nonprivileged ROM/model coverage; usbip_tests covers Linux/libusb recovery.

use crate::test::{build_test_binaries, TestBinaries, TestParams, TEST_LOCK};
use anyhow::{anyhow, bail, ensure, Result};
use caliptra_emu_bus::Bus;
use caliptra_emu_types::RvSize;
use caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP;
use caliptra_mcu_emulator_periph::{LpcipUsbError, LpcipUsbSpeed};
use caliptra_mcu_firmware_bundler::args::Common;
use caliptra_mcu_hw_model::{InitParams, McuHwModel, ModelEmulated};
use caliptra_mcu_ocp::protocol::RecoveryCommand;
use caliptra_mcu_romtime::handoff::{FirmwareBootType, HandoffData, McuRomCapabilities};
use caliptra_mcu_romtime::McuBootMilestones;
use caliptra_mcu_usb_recovery::{
    RecoveryAgent, RecoveryImages, RecoveryOptions, RecoveryOutcome, RecoveryTransport,
    CONTROL_MAX_BYTES,
};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use zerocopy::TryFromBytes;

const FEATURE: &str = "test-lpcip-usb-ocp-recovery";

pub(super) fn binaries() -> &'static TestBinaries {
    static BINARIES: OnceLock<TestBinaries> = OnceLock::new();
    BINARIES.get_or_init(|| {
        build_test_binaries(&TestParams {
            rom_feature: Some(FEATURE),
            ..Default::default()
        })
    })
}

struct Transport {
    model: ModelEmulated,
    activated: Vec<u8>,
    requested: u8,
    address: u8,
}

impl Transport {
    fn new() -> Result<Self> {
        let binaries = binaries();
        let mut model = ModelEmulated::new_unbooted(InitParams {
            caliptra_rom: &binaries.caliptra_rom,
            mcu_rom: &binaries.mcu_rom,
            vendor_pk_hash: Some(binaries.vendor_pk_hash_u8.as_slice().try_into()?),
            usb_recovery: true,
            check_booted_to_runtime: false,
            ..Default::default()
        })?;
        ensure!(
            !model.has_bmc_for_test(),
            "USB must not auto-load BMC images"
        );
        model.lpcip_usb_host_controller.set_vbus(true);
        model.boot()?;
        let mut transport = Self {
            model,
            activated: vec![],
            requested: 0,
            address: 0,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while !transport.model.lpcip_usb_host_controller.connected() {
            transport.step(1000)?;
            ensure!(Instant::now() < deadline, "USB ROM did not connect");
        }
        transport
            .model
            .lpcip_usb_host_controller
            .bus_reset(LpcipUsbSpeed::High)?;
        transport.step(1000)?;
        // Standard enumeration is deliberately driven through ROM's EP0 path.
        transport
            .model
            .lpcip_usb_host_controller
            .host_setup(0, &[0x80, 6, 0, 1, 0, 0, 18, 0])?;
        let descriptor = transport.input(deadline)?;
        ensure!(
            descriptor.len() == 18 && descriptor[0] == 18,
            "device descriptor"
        );
        transport.output(&[], deadline)?;
        transport.step(1000)?;
        transport
            .model
            .lpcip_usb_host_controller
            .host_setup(0, &[0, 5, 7, 0, 0, 0, 0, 0])?;
        ensure!(transport.input(deadline)?.is_empty(), "address status");
        transport.step(1000)?;
        transport.address = 7;
        transport
            .model
            .lpcip_usb_host_controller
            .host_setup(7, &[0, 9, 1, 0, 0, 0, 0, 0])?;
        ensure!(
            transport.input(deadline)?.is_empty(),
            "configuration status"
        );
        transport.step(1000)?;
        assert_eq!(
            transport.mci_read(0xb0)? & 1,
            1,
            "USB must leave MCU watchdog enabled"
        );
        assert_eq!(
            transport.mci_read(0xb8)?,
            caliptra_mcu_config_emulator::EMULATOR_MCU_STRAPS.mcu_wdt_cfg0_debug
        );
        Ok(transport)
    }

    fn mci_read(&mut self, offset: u32) -> Result<u32> {
        self.model
            .mcu_bus_for_test()
            .read(RvSize::Word, EMULATOR_MEMORY_MAP.mci_offset + offset)
            .map_err(|error| anyhow!("MCI read at {offset:#x} failed: {error:?}"))
    }

    fn mci_write(&mut self, offset: u32, value: u32) -> Result<()> {
        self.model
            .mcu_bus_for_test()
            .write(RvSize::Word, EMULATOR_MEMORY_MAP.mci_offset + offset, value)
            .map_err(|error| anyhow!("MCI write at {offset:#x} failed: {error:?}"))
    }

    fn step(&mut self, count: usize) -> Result<()> {
        for _ in 0..count {
            self.model.step();
            let error = self
                .model
                .mcu_bus_for_test()
                .read(RvSize::Word, EMULATOR_MEMORY_MAP.mci_offset + 0x60)
                .map_err(|error| anyhow!("MCI fatal-error read failed: {error:?}"))?;
            ensure!(
                error == 0,
                "MCU fatal error {error:#x}: {}",
                self.model.output().peek()
            );
        }
        Ok(())
    }

    fn input(&mut self, deadline: Instant) -> Result<Vec<u8>> {
        loop {
            match self
                .model
                .lpcip_usb_host_controller
                .host_in(self.address, 0)
            {
                Err(LpcipUsbError::Nak) => self.step(100)?,
                result => return Ok(result?),
            }
            ensure!(
                Instant::now() < deadline,
                "USB IN timeout: {}",
                self.model.output().peek()
            );
        }
    }

    fn output(&mut self, data: &[u8], deadline: Instant) -> Result<()> {
        loop {
            match self
                .model
                .lpcip_usb_host_controller
                .host_out(self.address, 0, data)
            {
                Err(LpcipUsbError::Nak) => self.step(100)?,
                result => return Ok(result?),
            }
            ensure!(
                Instant::now() < deadline,
                "USB OUT timeout: {}",
                self.model.output().peek()
            );
        }
    }
}

impl RecoveryTransport for Transport {
    fn read(
        &mut self,
        command: RecoveryCommand,
        response: &mut [u8; CONTROL_MAX_BYTES],
        timeout: Duration,
    ) -> Result<usize> {
        self.step(100)?;
        self.model
            .lpcip_usb_host_controller
            .host_setup(self.address, &[0xa1, 0, command as u8, 0, 0, 0, 64, 0])?;
        let deadline = Instant::now() + timeout;
        let data = self.input(deadline)?;
        ensure!(data.len() <= response.len(), "oversized OCP response");
        response[..data.len()].copy_from_slice(&data);
        self.output(&[], deadline)?;
        if command == RecoveryCommand::RecoveryStatus {
            self.requested = response[0] >> 4;
        }
        Ok(data.len())
    }

    fn write(&mut self, command: RecoveryCommand, data: &[u8], timeout: Duration) -> Result<()> {
        let length = u16::try_from(data.len())?.to_le_bytes();
        self.model.lpcip_usb_host_controller.host_setup(
            self.address,
            &[0x21, 0, command as u8, 0, 0, 0, length[0], length[1]],
        )?;
        let deadline = Instant::now() + timeout;
        self.output(data, deadline)?;
        ensure!(self.input(deadline)?.is_empty(), "OCP status stage");
        if command == RecoveryCommand::RecoveryCtrl && data.get(2) == Some(&0x0f) {
            self.activated.push(self.requested);
        }
        Ok(())
    }

    fn wait(&mut self, _: Duration) -> Result<()> {
        self.step(1000)
    }
}

fn agent() -> Result<RecoveryAgent<Transport>> {
    RecoveryAgent::new(
        Transport::new()?,
        RecoveryOptions {
            progress_timeout: Duration::from_secs(60),
            overall_timeout: Duration::from_secs(180),
            ..Default::default()
        },
    )
}

#[test]
fn test_lpcip_usb_common_rom_recovers_all_three_images() -> Result<()> {
    let _lock = TEST_LOCK.lock().unwrap();
    let binaries = binaries();
    let mut agent = agent()?;
    assert_eq!(
        agent.run(&RecoveryImages {
            caliptra_fmc_rt: &binaries.caliptra_fw,
            soc_manifest: &binaries.soc_manifest,
            mcu_runtime: &binaries.mcu_runtime,
        })?,
        RecoveryOutcome::Confirmed
    );
    let mut transport = agent.into_transport();
    assert_eq!(transport.activated, [0, 1, 2]);
    let output = transport.model.output().peek();
    let interface_log = output
        .find("[mcu-rom] Caliptra recovery interface: Usb")
        .expect("ROM must log the selected hardware USB recovery interface");
    let boot_go_log = output
        .find("[mcu-rom] Setting Caliptra boot go")
        .expect("ROM must log Caliptra boot-go");
    assert!(
        interface_log < boot_go_log,
        "interface must be logged before boot-go"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while !transport
        .model
        .mci_boot_milestones()
        .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
    {
        transport.step(1000)?;
        ensure!(
            Instant::now() < deadline,
            "USB firmware handoff timed out: {}",
            transport.model.output().peek()
        );
    }
    let selection = transport
        .model
        .mcu_bus_for_test()
        .read(RvSize::Word, EMULATOR_MEMORY_MAP.mci_offset)
        .map_err(|error| anyhow!("MCI recovery selection read failed: {error:?}"))?;
    assert_eq!(selection & 3, 0);
    let rom_manifest = Common {
        manifest: caliptra_mcu_builder::PROJECT_ROOT
            .join("firmware-bundler/reference/emulator/user-app-devel.toml"),
        ..Default::default()
    }
    .manifest()?;
    let handoff_offset = u32::try_from(rom_manifest.platform.handoff().offset)?;
    let mut handoff_bytes = [0; HandoffData::SIZE];
    for (offset, word) in handoff_bytes.chunks_exact_mut(4).enumerate() {
        let address = handoff_offset + u32::try_from(offset * 4)?;
        let value = transport
            .model
            .mcu_bus_for_test()
            .read(RvSize::Word, address)
            .map_err(|error| anyhow!("handoff read at {address:#x} failed: {error:?}"))?;
        word.copy_from_slice(&value.to_le_bytes());
    }
    let handoff = HandoffData::try_read_from_bytes(&handoff_bytes)
        .map_err(|error| anyhow!("invalid USB ROM handoff: {error:?}"))?;
    assert_eq!(
        handoff.firmware_boot_type(),
        Some(FirmwareBootType::HwOcpUsb)
    );
    let capabilities = handoff.mcu_rom_capabilities().expect("ROM capabilities");
    assert!(capabilities.contains(McuRomCapabilities::HW_OCP_USB_BOOT));
    assert!(!capabilities.contains(McuRomCapabilities::AXI_STREAMING_USB_BOOT));
    Ok(())
}

#[test]
fn test_lpcip_usb_common_rom_rejects_corrupt_soc_manifest() -> Result<()> {
    let _lock = TEST_LOCK.lock().unwrap();
    let binaries = binaries();
    let mut corrupt = binaries.soc_manifest.clone();
    corrupt.fill(0xff);
    let mut agent = agent()?;
    let result = agent.run(&RecoveryImages {
        caliptra_fmc_rt: &binaries.caliptra_fw,
        soc_manifest: &corrupt,
        mcu_runtime: &binaries.mcu_runtime,
    });
    ensure!(result.is_err(), "corrupt manifest was accepted");
    let mut transport = agent.into_transport();
    ensure!(
        !transport.activated.contains(&2),
        "MCU image activated after corrupt manifest"
    );
    ensure!(
        !transport
            .model
            .mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE),
        "corrupt manifest reached runtime"
    );
    Ok(())
}

#[test]
fn test_lpcip_usb_common_rom_reports_disconnect_before_images() -> Result<()> {
    let _lock = TEST_LOCK.lock().unwrap();
    let mut transport = Transport::new()?;
    transport.model.lpcip_usb_host_controller.set_vbus(false);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match transport.step(100) {
            Err(error) => {
                ensure!(
                    format!("{error:#}").contains("0x10048"),
                    "unexpected error: {error:#}"
                );
                return Ok(());
            }
            Ok(()) if Instant::now() >= deadline => bail!("USB disconnect did not fail explicitly"),
            Ok(()) => {}
        }
    }
}

#[test]
fn test_lpcip_usb_common_rom_missing_images_remain_watchdog_bounded() -> Result<()> {
    let _lock = TEST_LOCK.lock().unwrap();
    let mut transport = Transport::new()?;
    let mut status = [0; CONTROL_MAX_BYTES];
    transport.read(
        RecoveryCommand::RecoveryStatus,
        &mut status,
        Duration::from_secs(2),
    )?;
    assert_eq!(status[0], 1, "awaiting first recovery image");
    // Accelerate the already enabled watchdog only in this model test.
    transport.mci_write(0xb8, 1000)?;
    transport.mci_write(0xbc, 0)?;
    transport.mci_write(0xb4, 1)?;
    for _ in 0..2000 {
        transport.step(1)?;
        if transport.mci_read(0xd0)? & 3 == 3 {
            assert!(!transport
                .model
                .mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE));
            assert!(transport.activated.is_empty());
            return Ok(());
        }
    }
    bail!("missing images did not trigger the cascaded watchdog")
}

#[test]
fn test_lpcip_usb_common_rom_reports_interrupted_fifo_batch() -> Result<()> {
    let _lock = TEST_LOCK.lock().unwrap();
    let mut transport = Transport::new()?;
    transport.write(
        RecoveryCommand::IndirectFifoCtrl,
        &[0, 1, 1, 0, 0, 0],
        Duration::from_secs(2),
    )?;
    let host = transport.model.lpcip_usb_host_controller.clone();
    host.host_setup(transport.address, &[0x21, 0, 0x2f, 0, 0, 0, 4, 0])?;
    host.host_setup(transport.address, &[0x80, 6, 0, 1, 0, 0, 18, 0])?;
    transport.step(1000)?;
    let status = host.recovery_snapshot().unwrap();
    assert_eq!(status.protocol_error, 0xff);
    let mut response = [0; CONTROL_MAX_BYTES];
    transport.read(
        RecoveryCommand::DeviceStatus,
        &mut response,
        Duration::from_secs(2),
    )?;
    assert_eq!(response[1], 0xff, "host-visible interrupted-batch error");
    assert_eq!(
        transport.mci_read(0x60)?,
        0,
        "recoverable USB protocol failure"
    );
    Ok(())
}

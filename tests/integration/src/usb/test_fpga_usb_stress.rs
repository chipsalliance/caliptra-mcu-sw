// Licensed under the Apache-2.0 license

use super::test_fpga_usb_arch_b::recover_runtime;
use crate::test::TEST_LOCK;
use anyhow::{ensure, Context, Result};
use caliptra_mcu_hw_model::fpga_ulpi_usb::{enumerate_hub_port, FpgaUlpiUsbHost};
use caliptra_mcu_hw_model::{DefaultHwModel, McuHwModel};
use caliptra_mcu_registers_generated::mci;
use caliptra_mcu_romtime::StaticRef;
use std::time::{Duration, Instant};
use tock_registers::interfaces::{Readable, Writeable};

const ADDRESS: u8 = 7;
const START: u32 = 0x4353_5401;
const READY: u32 = 0x4353_5452;
const FAILED: u32 = 0x4353_5446;

struct Fixture {
    hw: DefaultHwModel,
    host: FpgaUlpiUsbHost,
    mci: StaticRef<mci::regs::Mci>,
}

fn validate_caps(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() == 16 && &bytes[..4] == b"CST1" && bytes[4] == 1,
        "not a CST1 peer"
    );
    ensure!(
        bytes[7] == 2 && u16::from_le_bytes([bytes[8], bytes[9]]) == 512,
        "CST1 peer is not HS/512"
    );
    ensure!(
        u16::from_le_bytes([bytes[10], bytes[11]]) == 1024,
        "unexpected control limit"
    );
    ensure!(
        u32::from_le_bytes(bytes[12..16].try_into()?) & 0xf == 0xf,
        "missing CST1 features"
    );
    Ok(())
}

impl Fixture {
    fn new() -> Result<Self> {
        let hw = recover_runtime(Some("test-usb-stress-dev0"))?;
        ensure!(
            hw.base.devs[0]
                .map_size(0)
                .map_err(|e| anyhow::anyhow!("{e:?}"))?
                >= 0x10000,
            "internal host requires the 64 KiB wrapper mapping"
        );
        let mut host = unsafe { FpgaUlpiUsbHost::from_wrapper_ptr(hw.base.wrapper.ptr) }?;
        host.soft_reset();
        let ptr = hw.base.mmio.mci().context("MCI mapping disabled")?.ptr;
        let mci = unsafe { StaticRef::new(ptr.cast::<mci::regs::Mci>()) };
        hw.base.wrapper.regs().mci_generic_input_wires[0].set(START);
        let mut fixture = Self { hw, host, mci };
        let deadline = Instant::now() + Duration::from_secs(10);
        while fixture.mci.mci_reg_generic_output_wires[1].get() != READY {
            ensure!(
                fixture.mci.mci_reg_generic_output_wires[1].get() != FAILED,
                "kernel stress peer failed; inspect MCU UART"
            );
            ensure!(
                Instant::now() < deadline,
                "kernel stress peer did not become ready"
            );
            fixture.hw.step();
        }
        fixture.enumerate()?;
        validate_caps(&fixture.read(0xc0, 0x5d, 0, 0, 16)?)?;
        Ok(fixture)
    }

    fn read(
        &mut self,
        kind: u8,
        request: u8,
        value: u16,
        index: u16,
        length: u16,
    ) -> Result<Vec<u8>> {
        let mut data = [0; 64];
        let hw = &mut self.hw;
        let n = self.host.control_read_raw(
            ADDRESS,
            kind,
            request,
            value,
            index,
            length,
            &mut data,
            || hw.step(),
            Duration::from_secs(2),
        )?;
        Ok(data[..n].to_vec())
    }

    fn write(&mut self, kind: u8, request: u8, value: u16, index: u16, data: &[u8]) -> Result<()> {
        let hw = &mut self.hw;
        self.host.control_write_raw(
            ADDRESS,
            kind,
            request,
            value,
            index,
            data,
            || hw.step(),
            Duration::from_secs(2),
        )
    }

    fn enumerate(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.host.status().dev_connected {
            ensure!(Instant::now() < deadline, "USB upstream did not connect");
            self.hw.step();
        }
        let hw = &mut self.hw;
        self.host.bus_reset_high_speed(|| hw.step())?;
        let host = &self.host;
        enumerate_hub_port(127, Duration::from_secs(10), |address, setup, timeout| {
            let value = u16::from_le_bytes([setup[2], setup[3]]);
            let index = u16::from_le_bytes([setup[4], setup[5]]);
            if setup[0] & 0x80 != 0 {
                let mut data = [0; 64];
                let length = host.control_read_raw(
                    address,
                    setup[0],
                    setup[1],
                    value,
                    index,
                    u16::from_le_bytes([setup[6], setup[7]]),
                    &mut data,
                    || hw.step(),
                    timeout,
                )?;
                Ok(data[..length].to_vec())
            } else {
                host.control_write_raw(
                    address,
                    setup[0],
                    setup[1],
                    value,
                    index,
                    &[],
                    || hw.step(),
                    timeout,
                )?;
                Ok(Vec::new())
            }
        })?;
        // USB reset recovery precedes any request to the downstream device.
        std::thread::sleep(Duration::from_millis(10));
        let mut descriptor = [0; 18];
        let length = self.host.control_read_raw(
            0,
            0x80,
            6,
            0x100,
            0,
            18,
            &mut descriptor,
            || self.hw.step(),
            Duration::from_secs(2),
        )?;
        ensure!(
            length == 18
                && descriptor[4] == 0
                && descriptor[7] == 64
                && descriptor[8..12] == [0x24, 4, 7, 0],
            "unexpected Device0 descriptor: {descriptor:02x?}"
        );
        self.host.control_write_raw(
            0,
            0,
            5,
            ADDRESS.into(),
            0,
            &[],
            || self.hw.step(),
            Duration::from_secs(2),
        )?;
        std::thread::sleep(Duration::from_millis(2));
        let configuration = self.read(0x80, 6, 0x200, 0, 41)?;
        ensure!(
            configuration.len() == 41
                && configuration[13] == 0
                && configuration[14] == 0xff
                && configuration[22] == 2
                && configuration[29] == 1
                && configuration[36] == 0x81
                && u16::from_le_bytes([configuration[31], configuration[32]]) == 512
                && u16::from_le_bytes([configuration[38], configuration[39]]) == 512,
            "invalid CST1 configuration: {configuration:02x?}"
        );
        self.write(0, 9, 1, 0, &[])
    }
}

#[test]
fn test_fpga_usb_stress_dev0_control() -> Result<()> {
    let _lock = TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new()?;
    for size in [1, 31, 64] {
        let data: Vec<u8> = (0..size).map(|n| n as u8 ^ 0xa5).collect();
        fixture.write(0x40, 0x5b, 0, 0, &data)?;
        ensure!(
            fixture.read(0xc0, 0x5c, 0, 0, size as u16)? == data,
            "control echo mismatch"
        );
    }
    Ok(())
}

#[test]
fn test_fpga_usb_stress_dev0_short_loopback() -> Result<()> {
    let _lock = TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new()?;
    fixture.write(0x40, 0x5e, 1, 0, &[])?;
    fixture.write(1, 11, 1, 0, &[])?;
    let caps = fixture.read(0xc0, 0x5d, 0, 0, 16)?;
    validate_caps(&caps)?;
    ensure!(
        caps[5] == 1 && caps[6] == 1,
        "loopback mode/alternate not committed"
    );
    let mut data1 = false;
    let start = Instant::now();
    let mut bytes = 0;
    for iteration in 0..16 {
        for size in [0, 1, 7, 31, 63, 64] {
            let data: Vec<u8> = (0..size)
                .map(|n| (n as u8).wrapping_add(iteration))
                .collect();
            let hw = &mut fixture.hw;
            fixture.host.bulk_write_packet(
                ADDRESS,
                1,
                &data,
                data1,
                || hw.step(),
                Duration::from_secs(2),
            )?;
            let mut output = [0; 64];
            let length = fixture.host.bulk_read_packet(
                ADDRESS,
                1,
                &mut output,
                data1,
                || hw.step(),
                Duration::from_secs(2),
            )?;
            ensure!(
                length == size && output[..length] == data,
                "bulk echo mismatch at {size} bytes"
            );
            data1 = !data1;
            bytes += size;
        }
    }
    println!("CST1 short-packet loopback: {} bytes each direction in {:?}; HS/512 endpoints, host packets <=64", bytes, start.elapsed());
    ensure!(
        fixture.mci.mci_reg_generic_output_wires[1].get() == READY,
        "kernel peer failed"
    );
    Ok(())
}

#[test]
fn cst1_caps_reject_ordinary_recovery_and_wrong_packet_sizes() {
    assert!(validate_caps(&[0; 16]).is_err());
    assert!(validate_caps(b"CST1").is_err());
    let mut caps = *b"CST1\x01\x00\x00\x02\x00\x02\x00\x04\x0f\x00\x00\x00";
    assert!(validate_caps(&caps).is_ok());
    caps[8] = 64;
    caps[9] = 0;
    assert!(validate_caps(&caps).is_err());
}

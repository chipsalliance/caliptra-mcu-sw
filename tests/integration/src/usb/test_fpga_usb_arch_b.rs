// Licensed under the Apache-2.0 license

//! VCK190 recovery through the internal ULPI host

use crate::test::TEST_LOCK;
use anyhow::{ensure, Context, Result};
use caliptra_api::{error::CaliptraError, SocManager};
use caliptra_image_types::{FwVerificationPqcKeyType, ImageManifest};
use caliptra_mcu_builder::FirmwareBinaries;
use caliptra_mcu_hw_model::fpga_ulpi_usb::FpgaUlpiUsbHost;
use caliptra_mcu_hw_model::{new_unbooted, DefaultHwModel, Fuses, InitParams, McuHwModel};
use caliptra_mcu_ocp::protocol::{
    device_id, hw_status, indirect_fifo_ctrl::IndirectFifoCtrl, indirect_fifo_status, prot_cap,
    RecoveryCommand,
};
use caliptra_mcu_romtime::McuBootMilestones;
use caliptra_mcu_usb_recovery::{
    RecoveryAgent, RecoveryImages, RecoveryOptions, RecoveryOutcome, RecoveryTransport,
    CONTROL_MAX_BYTES,
};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tock_registers::interfaces::Readable;
use zerocopy::FromBytes;

fn log_host_otp_lc_snapshot(hw: &DefaultHwModel, phase: &str) -> Result<()> {
    println!("[arch-b-recovery] Reading host OTP/LCC snapshot: {phase}");
    let lc_ptr = hw.base.mmio.lc_mmio().context("LCC MMIO is disabled")?;
    let otp_ptr = hw.base.mmio.otp_mmio().context("OTP MMIO is disabled")?;
    // Both mappings are owned by the live model; only read-only CSRs are used.
    let lc = unsafe { &*lc_ptr.cast::<caliptra_mcu_registers_generated::lc_ctrl::regs::LcCtrl>() };
    let otp =
        unsafe { &*otp_ptr.cast::<caliptra_mcu_registers_generated::otp_ctrl::regs::OtpCtrl>() };
    let lc_status = lc.status.get();
    let lc_state = lc.lc_state.get();
    let lc_count = lc.lc_transition_cnt.get();
    let otp_status = otp.otp_status.get();
    println!(
        "[arch-b-recovery] {phase}: LC_STATUS=0x{lc_status:08x} LC_STATE=0x{lc_state:08x} LC_TRANSITION_CNT=0x{lc_count:08x} OTP_STATUS=0x{otp_status:08x}"
    );
    Ok(())
}

struct FpgaUlpiRecoveryTransport<'a> {
    host: FpgaUlpiUsbHost,
    hw: &'a mut DefaultHwModel,
}

impl<'a> FpgaUlpiRecoveryTransport<'a> {
    fn enumerate(hw: &'a mut DefaultHwModel) -> Result<Self> {
        let wrapper_size = hw.base.devs[0]
            .map_size(0)
            .map_err(|error| anyhow::anyhow!("read wrapper UIO mapping size: {error:?}"))?;
        ensure!(
            wrapper_size >= 0x10000,
            "Architecture B requires a 64 KiB wrapper UIO mapping"
        );
        // The borrowed model keeps the UIO mapping alive, and TEST_LOCK excludes
        // other test users of the shared host engine.
        let host = unsafe { FpgaUlpiUsbHost::from_wrapper_ptr(hw.base.wrapper.ptr) }?;
        let mut transport = Self { host, hw };
        transport.host.soft_reset();
        transport.enumerate_device()?;
        Ok(transport)
    }

    fn enumerate_device(&mut self) -> Result<()> {
        let hw = &mut *self.hw;
        let enumeration = self
            .host
            .wait_and_enumerate(7, || hw.step(), Duration::from_secs(30))
            .context("enumerate Device 0 through the internal ULPI host");
        if let Err(error) = &enumeration {
            println!(
                "[arch-b-recovery] Enumeration failed: {error:#}; host={:?}; diag={:?}",
                self.host.status(),
                self.host.diag()
            );
            log_host_otp_lc_snapshot(hw, "After enumeration failure, before teardown")
                .with_context(|| {
                    format!("host snapshot failed; enumeration also failed: {error:#}")
                })?;
        }
        let device = enumeration?;
        println!(
            "[arch-b-recovery] Device address={} VID:PID={:04x}:{:04x} OCP interface={}",
            device.address, device.vendor_id, device.product_id, device.ocp_interface
        );
        ensure!(
            device.vendor_id == 0x0424 && device.product_id == 0x0007,
            "Expected FPGA Device 0 VID:PID 0424:0007, got {:04x}:{:04x}",
            device.vendor_id,
            device.product_id
        );
        ensure!(
            device.hub_address.is_some(),
            "FPGA recovery must enumerate Device 0 through the internal hub"
        );
        ensure!(self.host.status().hs_active, "USB did not enter HS mode");
        Ok(())
    }

    fn ensure_no_mcu_boot(&mut self) -> Result<()> {
        ensure!(
            self.hw.mci_fw_fatal_error().is_none(),
            "MCU fatal error during failed recovery: {:?}",
            self.hw.mci_fw_fatal_error()
        );
        ensure!(
            !self
                .hw
                .mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE),
            "failed recovery reached MCU firmware boot"
        );
        Ok(())
    }

    fn wait_for_status_only(&mut self) -> Result<()> {
        let mci = self.hw.base.mmio.mci().context("MCI MMIO is disabled")?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            self.hw.step();
            self.ensure_no_mcu_boot()?;
            if u32::from(mci.regs().wdt_timer1_en().read()) & 1 == 0 {
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "MCU did not disable its watchdog for status-only recovery"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn check_failed_diagnostics(&mut self) -> Result<()> {
        let core_error = self.hw.base.soc_ifc().cptra_fw_error_fatal().read();
        let mut response = [0; CONTROL_MAX_BYTES];
        for (command, minimum) in [
            (RecoveryCommand::ProtCap, prot_cap::RESPONSE_LEN),
            (RecoveryCommand::DeviceId, device_id::MIN_MESSAGE_LEN),
            (RecoveryCommand::DeviceStatus, 7),
            (RecoveryCommand::RecoveryStatus, 2),
            (RecoveryCommand::HwStatus, hw_status::MIN_MESSAGE_LEN),
            (
                RecoveryCommand::IndirectFifoStatus,
                indirect_fifo_status::MESSAGE_LEN,
            ),
        ] {
            let length = self.read(command, &mut response, Duration::from_secs(2))?;
            ensure!(
                length >= minimum,
                "{command:?} diagnostic response is too short: {length}"
            );
            match command {
                RecoveryCommand::ProtCap => {
                    ensure!(length == prot_cap::RESPONSE_LEN, "PROT_CAP length");
                    ensure!(&response[..8] == prot_cap::MAGIC, "PROT_CAP magic");
                }
                RecoveryCommand::DeviceStatus => {
                    ensure!(
                        length == 7 + usize::from(response[6]),
                        "DEVICE_STATUS length"
                    );
                    ensure!(
                        matches!(response[0] & 0xf, 2 | 15),
                        "device no longer reports failure: {:02x?}",
                        &response[..length]
                    );
                }
                RecoveryCommand::RecoveryStatus => {
                    ensure!(length == 2, "RECOVERY_STATUS length");
                    ensure!(
                        matches!(response[0] & 0xf, 0xc..=0xe) && response[0] >> 4 == 0,
                        "failed recovery/image index was not preserved: {:02x?}",
                        &response[..length]
                    );
                }
                RecoveryCommand::DeviceId => {
                    ensure!(
                        length == device_id::MIN_MESSAGE_LEN + usize::from(response[1]),
                        "DEVICE_ID length"
                    );
                }
                RecoveryCommand::HwStatus => {
                    ensure!(
                        length == hw_status::MIN_MESSAGE_LEN + usize::from(response[3]),
                        "HW_STATUS length"
                    );
                }
                RecoveryCommand::IndirectFifoStatus => {
                    ensure!(
                        length == indirect_fifo_status::MESSAGE_LEN,
                        "FIFO_STATUS length"
                    );
                }
                _ => unreachable!(),
            }
        }
        if core_error != 0 {
            ensure!(
                self.hw.base.soc_ifc().cptra_fw_error_fatal().read() == core_error,
                "reading USB diagnostics changed the Core fatal error"
            );
        }
        self.ensure_no_mcu_boot()
    }

    fn expect_write_stall(&mut self, command: RecoveryCommand, data: &[u8]) -> Result<()> {
        let error = self
            .write(command, data, Duration::from_secs(2))
            .err()
            .with_context(|| format!("status-only recovery accepted {command:?}"))?;
        let status = self.host.status();
        ensure!(
            !status.timeout_err && status.rx_pid == 0xe,
            "{command:?} failed without a USB STALL: {error:#}; {status:?}"
        );
        println!("[arch-b-recovery] Expected {command:?} STALL: {error:#}");
        self.ensure_no_mcu_boot()
    }
}

impl RecoveryTransport for FpgaUlpiRecoveryTransport<'_> {
    fn read(
        &mut self,
        command: RecoveryCommand,
        response: &mut [u8; CONTROL_MAX_BYTES],
        timeout: Duration,
    ) -> Result<usize> {
        let hw = &mut *self.hw;
        self.host.control_read_raw(
            self.host.device_address(),
            0xa1,
            0,
            command as u16,
            u16::from(self.host.ocp_interface()),
            CONTROL_MAX_BYTES as u16,
            response,
            || hw.step(),
            timeout,
        )
    }

    fn write(&mut self, command: RecoveryCommand, data: &[u8], timeout: Duration) -> Result<()> {
        ensure!(
            !data.is_empty() && data.len() <= CONTROL_MAX_BYTES,
            "invalid OCP control OUT length {}",
            data.len()
        );
        let hw = &mut *self.hw;
        self.host.control_write_raw(
            self.host.device_address(),
            0x21,
            0,
            command as u16,
            u16::from(self.host.ocp_interface()),
            data,
            || hw.step(),
            timeout,
        )
    }

    fn wait(&mut self, duration: Duration) -> Result<()> {
        let deadline = Instant::now() + duration;
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            self.hw.step();
            std::thread::sleep(remaining.min(Duration::from_millis(1)));
        }
        Ok(())
    }
}

fn boot_usb_recovery(binaries: &FirmwareBinaries) -> Result<DefaultHwModel> {
    let feature = "test-lpcip-usb-ocp-recovery";
    ensure!(
        binaries.has_test_feature_rom(feature),
        "firmware bundle is missing the latest FPGA {feature} ROM"
    );
    let mcu_rom = binaries.test_feature_rom(feature);
    let vpk = binaries
        .vendor_pk_hash()
        .context("missing vendor public-key hash")?;
    let mut vendor_pk_hash = [0; 12];
    for (word, bytes) in vendor_pk_hash.iter_mut().zip(vpk.chunks_exact(4)) {
        *word = u32::from_be_bytes(bytes.try_into()?);
    }
    // Empty firmware slices suppress the model's automatic I3C recovery.
    // The feature ROM selects USB and supplies no software image provider.
    let mut hw = new_unbooted(InitParams {
        fuses: Fuses {
            fuse_pqc_key_type: FwVerificationPqcKeyType::LMS as u32,
            vendor_pk_hash,
            ..Default::default()
        },
        caliptra_rom: &binaries.caliptra_rom,
        mcu_rom: &mcu_rom,
        vendor_pk_hash: Some(vpk),
        vendor_pqc_type: Some(FwVerificationPqcKeyType::LMS),
        active_mode: true,
        enable_mcu_uart_log: true,
        check_booted_to_runtime: false,
        ..Default::default()
    })?;
    log_host_otp_lc_snapshot(&hw, "After new_unbooted(), before boot()")?;
    hw.boot()?;
    Ok(hw)
}

fn recovery_agent(hw: &mut DefaultHwModel) -> Result<RecoveryAgent<FpgaUlpiRecoveryTransport<'_>>> {
    RecoveryAgent::new(
        FpgaUlpiRecoveryTransport::enumerate(hw)?,
        RecoveryOptions {
            transfer_timeout: Duration::from_secs(5),
            progress_timeout: Duration::from_secs(45),
            overall_timeout: Duration::from_secs(180),
            ..Default::default()
        },
    )
}

#[test]
fn test_fpga_usb_arch_b_ocp_recovery_boot() -> Result<()> {
    let lock = TEST_LOCK.lock().unwrap();
    let binaries = FirmwareBinaries::from_env().context("load CPTRA_FIRMWARE_BUNDLE")?;
    let images = RecoveryImages {
        caliptra_fmc_rt: &binaries.caliptra_fw,
        soc_manifest: &binaries.soc_manifest,
        mcu_runtime: &binaries.mcu_runtime,
    };
    ensure!(
        !images.caliptra_fmc_rt.is_empty()
            && !images.soc_manifest.is_empty()
            && !images.mcu_runtime.is_empty(),
        "recovery requires all three firmware images"
    );
    let mut hw = boot_usb_recovery(binaries)?;
    let mut agent = recovery_agent(&mut hw)?;
    println!("[arch-b-recovery] Discovery: {:?}", agent.probe()?);
    let outcome = agent
        .run(&images)
        .context("recover over internal FPGA USB")?;
    let transport = agent.into_transport();
    println!(
        "[arch-b-recovery] Outcome={outcome:?}, diagnostics={:?}",
        transport.host.diag()
    );
    ensure!(
        outcome == RecoveryOutcome::Confirmed,
        "recovery was not confirmed"
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        hw.step();
        ensure!(
            hw.mci_fw_fatal_error().is_none(),
            "MCU fatal error after recovery: {:?}",
            hw.mci_fw_fatal_error()
        );
        if hw
            .mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
        {
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "MCU did not finish booting after recovery; milestones=0x{:04x}",
            u16::from(hw.mci_boot_milestones())
        );
    }
    lock.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

#[test]
fn test_fpga_usb_arch_b_rejects_corrupt_core_image() -> Result<()> {
    let lock = TEST_LOCK.lock().unwrap();
    let binaries = FirmwareBinaries::from_env().context("load CPTRA_FIRMWARE_BUNDLE")?;
    let mut corrupt = binaries.caliptra_fw.clone();
    let (manifest, _) = ImageManifest::read_from_prefix(&corrupt)
        .map_err(|error| anyhow::anyhow!("parse Core image manifest: {error:?}"))?;
    ensure!(manifest.runtime.size > 0, "Core runtime image is empty");
    *corrupt
        .get_mut(usize::try_from(manifest.runtime.offset)?)
        .context("Core runtime offset is outside the image")? ^= 1;
    let mut hw = boot_usb_recovery(binaries)?;
    let mut agent = recovery_agent(&mut hw)?;
    let error = agent
        .run(&RecoveryImages {
            caliptra_fmc_rt: &corrupt,
            soc_manifest: &binaries.soc_manifest,
            mcu_runtime: &binaries.mcu_runtime,
        })
        .err()
        .context("corrupted Core image was accepted")?;
    println!("[arch-b-recovery] Expected image-verification failure: {error:#}");
    let mut transport = agent.into_transport();
    transport.wait_for_status_only()?;
    let expected_error = u32::from(CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH);
    ensure!(
        transport.hw.base.soc_ifc().cptra_fw_error_fatal().read() == expected_error,
        "Core image rejection did not report a runtime digest mismatch"
    );
    transport.check_failed_diagnostics()?;
    transport.host.set_vbus(false)?;
    transport.wait(Duration::from_millis(100))?;
    transport.host.set_vbus(true)?;
    transport.enumerate_device()?;
    transport.check_failed_diagnostics()?;
    transport.expect_write_stall(RecoveryCommand::RecoveryCtrl, &[0, 0, 0x0f])?;
    transport.check_failed_diagnostics()?;
    ensure!(
        transport.hw.base.soc_ifc().cptra_fw_error_fatal().read() == expected_error,
        "reconnecting USB or rejecting activation changed the Core fatal error"
    );
    lock.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

#[test]
fn test_fpga_usb_arch_b_reenumerates_after_interrupted_image() -> Result<()> {
    let lock = TEST_LOCK.lock().unwrap();
    let binaries = FirmwareBinaries::from_env().context("load CPTRA_FIRMWARE_BUNDLE")?;
    ensure!(
        binaries.caliptra_fw.len() > CONTROL_MAX_BYTES,
        "Core image is too short for a partial transfer"
    );
    let mut hw = boot_usb_recovery(binaries)?;
    let mut agent = recovery_agent(&mut hw)?;
    agent.probe()?;
    let mut transport = agent.into_transport();
    let mut response = [0; CONTROL_MAX_BYTES];
    let length = transport.read(
        RecoveryCommand::RecoveryStatus,
        &mut response,
        Duration::from_secs(2),
    )?;
    ensure!(length == 2 && response[0] == 1, "not awaiting Core image 0");
    transport.write(
        RecoveryCommand::RecoveryCtrl,
        &[0, 0, 0],
        Duration::from_secs(2),
    )?;
    let words = u32::try_from(binaries.caliptra_fw.len().div_ceil(4))?;
    let mut control = [0; 6];
    IndirectFifoCtrl::new(0, false, words.to_le())
        .to_message(&mut control)
        .map_err(|error| anyhow::anyhow!("encode partial image FIFO control: {error:?}"))?;
    transport.write(
        RecoveryCommand::IndirectFifoCtrl,
        &control,
        Duration::from_secs(2),
    )?;
    transport.write(
        RecoveryCommand::IndirectFifoData,
        &binaries.caliptra_fw[..CONTROL_MAX_BYTES],
        Duration::from_secs(2),
    )?;
    transport.host.set_vbus(false)?;
    transport.wait_for_status_only()?;

    for _ in 0..2 {
        transport.wait(Duration::from_millis(100))?;
        transport.ensure_no_mcu_boot()?;
        transport.host.set_vbus(true)?;
        transport.enumerate_device()?;
        transport.check_failed_diagnostics()?;
        for (command, data) in [
            (RecoveryCommand::RecoveryCtrl, &[0, 0, 0x0f][..]),
            (RecoveryCommand::IndirectFifoCtrl, &control[..]),
            (RecoveryCommand::IndirectFifoData, &[1, 2, 3, 4][..]),
            (RecoveryCommand::DeviceReset, &[0][..]),
        ] {
            transport.expect_write_stall(command, data)?;
            transport.check_failed_diagnostics()?;
        }
        transport.host.set_vbus(false)?;
        transport.ensure_no_mcu_boot()?;
    }
    lock.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

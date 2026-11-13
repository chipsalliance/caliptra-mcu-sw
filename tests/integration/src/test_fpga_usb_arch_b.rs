// Licensed under the Apache-2.0 license

//! VCK190 recovery through Carl's internal ULPI host, not Linux/libusb.

use crate::test::TEST_LOCK;
use anyhow::{ensure, Context, Result};
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_mcu_builder::FirmwareBinaries;
use caliptra_mcu_hw_model::fpga_ulpi_usb::FpgaUlpiUsbHost;
use caliptra_mcu_hw_model::{new_unbooted, DefaultHwModel, Fuses, InitParams, McuHwModel};
use caliptra_mcu_ocp::protocol::RecoveryCommand;
use caliptra_mcu_romtime::McuBootMilestones;
use caliptra_mcu_usb_recovery::{
    RecoveryAgent, RecoveryImages, RecoveryOptions, RecoveryOutcome, RecoveryTransport,
    CONTROL_MAX_BYTES,
};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tock_registers::interfaces::Readable;

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
        let hw = &mut *transport.hw;
        let enumeration = transport
            .host
            .wait_and_enumerate(7, || hw.step(), Duration::from_secs(30))
            .context("enumerate Device 0 through the internal ULPI host");
        if let Err(error) = &enumeration {
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
        ensure!(
            transport.host.status().hs_active,
            "USB did not enter HS mode"
        );
        Ok(transport)
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

#[test]
fn test_fpga_usb_arch_b_ocp_recovery_boot() -> Result<()> {
    let lock = TEST_LOCK.lock().unwrap();
    let binaries = FirmwareBinaries::from_env().context("load CPTRA_FIRMWARE_BUNDLE")?;
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
    let transport = FpgaUlpiRecoveryTransport::enumerate(&mut hw)?;
    let mut agent = RecoveryAgent::new(
        transport,
        RecoveryOptions {
            transfer_timeout: Duration::from_secs(5),
            progress_timeout: Duration::from_secs(45),
            overall_timeout: Duration::from_secs(180),
            ..Default::default()
        },
    )?;
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

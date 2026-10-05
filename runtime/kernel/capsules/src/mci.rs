// Licensed under the Apache-2.0 license

//! This provides the MCI capsule that calls the underlying MCI driver

use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::processbuffer::ReadableProcessBuffer;
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::{ErrorCode, ProcessId};

use caliptra_mcu_registers_generated::fuses::{
    OtpPartitionInfo, SECRET_MANUF_PARTITION, SECRET_PROD_PARTITION_0, SECRET_PROD_PARTITION_1,
    SECRET_PROD_PARTITION_2, SECRET_PROD_PARTITION_3,
};

const RMA_SECRET_PARTITIONS: [&OtpPartitionInfo; 5] = [
    SECRET_MANUF_PARTITION,
    SECRET_PROD_PARTITION_0,
    SECRET_PROD_PARTITION_1,
    SECRET_PROD_PARTITION_2,
    SECRET_PROD_PARTITION_3,
];

fn uds_and_field_entropy_are_zeroized(
    mut read_dword: impl FnMut(usize) -> Result<u64, ErrorCode>,
) -> Result<bool, ErrorCode> {
    for partition in RMA_SECRET_PARTITIONS {
        if !partition.zeroizable
            || !partition.byte_offset.is_multiple_of(8)
            || !partition.byte_size.is_multiple_of(8)
        {
            return Err(ErrorCode::FAIL);
        }

        let first_dword = partition.byte_offset / 8;
        let dword_count = partition.byte_size / 8;
        for dword in first_dword..first_dword + dword_count {
            if read_dword(dword)? != u64::MAX {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// The driver number for Caliptra MCI commands.
pub const DRIVER_NUM: usize = 0xB000_0000;

mod cmd {
    pub const MCI_READ: u32 = 1;
    pub const MCI_WRITE: u32 = 2;
    pub const MCI_SET_REGISTER: u32 = 3;
    pub const MCI_TRIGGER_WARM_RESET: u32 = 4;
    pub const MCI_SET_MAILBOX_READY: u32 = 5;
    pub const MCI_SET_SPDM_MCTP_RESPONDER_READY: u32 = 6;
    pub const MCI_SET_SPDM_DOE_RESPONDER_READY: u32 = 7;
    pub const MCI_ENTER_RMA: u32 = 8;
}

mod ro_allow {
    pub const RMA_TOKEN: usize = 0;
    pub const COUNT: u8 = 1;
    pub const MCI_SET_PLDM_READY: u32 = 8;
}

mod mci_reg {
    pub const RESET_REASON: u32 = 0x38;
    pub const SECURITY_STATE: u32 = 0x40;
    pub const WDT_TIMER1_EN: u32 = 0xb0;
    pub const NOTIF0_INTR_TRIG_R: u32 = 0x1034;
}

#[derive(Default)]
pub struct App {
    pub reg_offset: u32,
    pub reg_index: u32,
}

pub struct Mci {
    driver: &'static caliptra_mcu_romtime::Mci,
    lifecycle: &'static caliptra_mcu_romtime::Lifecycle,
    otp: &'static caliptra_mcu_romtime::Otp,
    // Per-app state.
    apps: Grant<App, UpcallCount<0>, AllowRoCount<{ ro_allow::COUNT }>, AllowRwCount<0>>,
}

impl Mci {
    pub fn new(
        driver: &'static caliptra_mcu_romtime::Mci,
        lifecycle: &'static caliptra_mcu_romtime::Lifecycle,
        otp: &'static caliptra_mcu_romtime::Otp,
        grant: Grant<App, UpcallCount<0>, AllowRoCount<{ ro_allow::COUNT }>, AllowRwCount<0>>,
    ) -> Mci {
        Mci {
            driver,
            lifecycle,
            otp,
            apps: grant,
        }
    }

    fn uds_and_field_entropy_are_zeroized(&self) -> Result<bool, ErrorCode> {
        uds_and_field_entropy_are_zeroized(|dword| {
            self.otp.read_dword(dword).map_err(|_| ErrorCode::FAIL)
        })
    }

    fn read_reg(&self, processid: ProcessId) -> CommandReturn {
        match self.apps.enter(processid, |app, _| match app.reg_offset {
            mci_reg::RESET_REASON => CommandReturn::success_u32(self.driver.reset_reason()),
            mci_reg::SECURITY_STATE => CommandReturn::success_u32(self.driver.security_state()),
            mci_reg::WDT_TIMER1_EN => CommandReturn::success_u32(self.driver.read_wdt_timer1_en()),
            mci_reg::NOTIF0_INTR_TRIG_R => {
                CommandReturn::success_u32(self.driver.read_notif0_intr_trig_r())
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }) {
            Ok(ret) => ret,
            Err(_) => CommandReturn::failure(ErrorCode::FAIL),
        }
    }

    fn write_reg(&self, value: u32, processid: ProcessId) -> CommandReturn {
        match self.apps.enter(processid, |app, _| match app.reg_offset {
            mci_reg::WDT_TIMER1_EN => {
                self.driver.write_wdt_timer1_en(value);
                CommandReturn::success()
            }
            mci_reg::NOTIF0_INTR_TRIG_R => {
                self.driver.write_notif0_intr_trig_r(value);
                CommandReturn::success()
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }) {
            Ok(ret) => ret,
            Err(_) => CommandReturn::failure(ErrorCode::FAIL),
        }
    }

    fn set_reg(&self, reg: u32, index: u32, processid: ProcessId) -> CommandReturn {
        if self
            .apps
            .enter(processid, |app, _| {
                app.reg_offset = reg;
                app.reg_index = index;
            })
            .is_err()
        {
            return CommandReturn::failure(ErrorCode::FAIL);
        }
        CommandReturn::success()
    }

    fn enter_rma(&self, processid: ProcessId) -> CommandReturn {
        let result = self.apps.enter(processid, |_, kernel_data| {
            let token_buffer = kernel_data
                .get_readonly_processbuffer(ro_allow::RMA_TOKEN)
                .map_err(|_| ErrorCode::INVAL)?;
            let mut token = [0u8; 16];
            token_buffer
                .enter(|buffer| {
                    if buffer.len() != token.len() {
                        return Err(ErrorCode::INVAL);
                    }
                    buffer.copy_to_slice(&mut token);
                    Ok(())
                })
                .map_err(|_| ErrorCode::FAIL)??;

            match self.uds_and_field_entropy_are_zeroized() {
                Ok(true) => {}
                Ok(false) | Err(_) => return Err(ErrorCode::INVAL),
            }

            self.lifecycle
                .transition(
                    caliptra_mcu_romtime::LifecycleControllerState::Rma,
                    &caliptra_mcu_romtime::LifecycleToken(token),
                )
                .map_err(|_| ErrorCode::FAIL)
        });

        match result {
            Ok(Ok(())) => CommandReturn::success(),
            Ok(Err(error)) => CommandReturn::failure(error),
            Err(error) => CommandReturn::failure(error.into()),
        }
    }
}

/// Provide an interface for userland.
impl SyscallDriver for Mci {
    fn command(
        &self,
        mci_cmd: usize,
        arg1: usize,
        arg2: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        match mci_cmd as u32 {
            cmd::MCI_READ => self.read_reg(processid),
            cmd::MCI_WRITE => self.write_reg(arg1 as u32, processid),
            cmd::MCI_SET_REGISTER => self.set_reg(arg1 as u32, arg2 as u32, processid),
            cmd::MCI_TRIGGER_WARM_RESET => {
                self.driver.trigger_warm_reset();
                CommandReturn::success()
            }
            cmd::MCI_SET_MAILBOX_READY => {
                self.driver.set_flow_milestone(
                    caliptra_mcu_romtime::McuBootMilestones::FIRMWARE_MAILBOX_READY.into(),
                );
                CommandReturn::success()
            }
            cmd::MCI_SET_SPDM_MCTP_RESPONDER_READY => {
                self.driver.set_flow_milestone(
                    caliptra_mcu_romtime::McuBootMilestones::FIRMWARE_SPDM_MCTP_READY.into(),
                );
                CommandReturn::success()
            }
            cmd::MCI_SET_SPDM_DOE_RESPONDER_READY => {
                self.driver.set_flow_milestone(
                    caliptra_mcu_romtime::McuBootMilestones::FIRMWARE_SPDM_DOE_READY.into(),
                );
                CommandReturn::success()
            }
            cmd::MCI_ENTER_RMA => self.enter_rma(processid),
            cmd::MCI_SET_PLDM_READY => {
                self.driver.set_flow_milestone(
                    caliptra_mcu_romtime::McuBootMilestones::FIRMWARE_PLDM_READY.into(),
                );
                CommandReturn::success()
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rma_requires_every_uds_and_field_entropy_partition_to_be_zeroized() {
        for nonzeroized_partition in RMA_SECRET_PARTITIONS {
            let nonzeroized_dword = nonzeroized_partition.byte_offset / 8;
            assert!(!uds_and_field_entropy_are_zeroized(|dword| {
                Ok(if dword == nonzeroized_dword {
                    0
                } else {
                    u64::MAX
                })
            })
            .unwrap());
        }
    }

    #[test]
    fn rma_accepts_fully_zeroized_uds_and_field_entropy_partitions() {
        assert!(uds_and_field_entropy_are_zeroized(|_| Ok(u64::MAX)).unwrap());
    }

    #[test]
    fn rma_fails_closed_when_otp_cannot_be_read() {
        assert!(uds_and_field_entropy_are_zeroized(|_| Err(ErrorCode::FAIL)).is_err());
    }
}

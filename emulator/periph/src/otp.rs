/*++

Licensed under the Apache-2.0 license.

File Name:

    otp.rs

Abstract:

    OpenTitan OTP Open Source Controller emulated device.
    We only support 32-bit granularity for now.

--*/
use crate::otp_digest;
use emulator_bus::{
    BusError, Clock, ReadOnlyRegister, ReadWriteRegister, Timer, WriteOnlyRegister,
};
use emulator_derive::Bus;
use emulator_types::{RvAddr, RvData, RvSize};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::Seek;
use std::path::PathBuf;
use tock_registers::interfaces::{Readable, Writeable};
use tock_registers::register_bitfields;

/// OTP Digest constant, randomly generated. Usually read from configuration file.
const DIGEST_CONST: u128 = 0xfc2f4d648d4a45b482924470b96f0cee;
/// OTP Digest IV, randomly generated. Usually read from configuration file.
const DIGEST_IV: u64 = 0x25b5e5a1627a3557;

#[allow(dead_code)]
enum Partitions {
    VendorTest = 0,
    CreatorSwCfg = 1,
    Secret0 = 2,
    Secret1 = 3,
    LifeCycle = 4,
}

const VENDOR_TEST_PARITION_ADDR: usize = 0;
const VENDOR_TEST_PARITION_SIZE: usize = 64;
const CREATOR_SW_CFG_PARTITION_ADDR: usize = VENDOR_TEST_PARITION_SIZE;
const CREATOR_SW_CFG_PARTITION_SIZE: usize = 244;
const SECRET0_PARTITION_ADDR: usize = CREATOR_SW_CFG_PARTITION_ADDR + CREATOR_SW_CFG_PARTITION_SIZE;
const SECRET0_PARTITION_SIZE: usize = 48;
const SECRET1_PARTITION_ADDR: usize = SECRET0_PARTITION_ADDR + SECRET0_PARTITION_SIZE;
const SECRET1_PARTITION_SIZE: usize = 32;
const LIFE_CYCLE_PARTITION_ADDR: usize = SECRET1_PARTITION_ADDR + SECRET1_PARTITION_SIZE;
const LIFE_CYCLE_PARTITION_SIZE: usize = 88;
const TOTAL_SIZE: usize = LIFE_CYCLE_PARTITION_ADDR + LIFE_CYCLE_PARTITION_SIZE;

register_bitfields! [
    u32,

    // TODO: confirm that we aren't shifting bits for the unused partitions with hardware folks
    /// Status Register Fields
    Status [
        VENDOR_TEST_ERROR OFFSET(0) NUMBITS(1) [],
        CREATOR_SW_CFG_ERROR OFFSET(1) NUMBITS(1) [],
        SECRET0_ERROR OFFSET(7) NUMBITS(1) [],
        SECRET1_ERROR OFFSET(8) NUMBITS(1) [],
        LIFE_CYCLE_ERROR OFFSET(10) NUMBITS(1) [],
        DAI_ERROR OFFSET(11) NUMBITS(1) [],
        LCI_ERROR OFFSET(12) NUMBITS(1) [],
        TIMEOUT_ERROR OFFSET(13) NUMBITS(1) [],
        LFSR_FSM_ERROR OFFSET(14) NUMBITS(1) [],
        SCRAMBLING_FSM_ERROR OFFSET(15) NUMBITS(1) [],
        KEY_DERIV_FSM_ERROR OFFSET(16) NUMBITS(1) [],
        BUS_INTEG_ERROR OFFSET(17) NUMBITS(1) [],
        DAI_IDLE OFFSET(18) NUMBITS(1) [],
        CHECK_PENDING OFFSET(19) NUMBITS(1) [],
    ],

    ErrCode [
        ERR_CODE OFFSET(0) NUMBITS(3) [
            NO_ERROR = 0,
            MACRO_ERROR = 1,
            MACRO_ECC_CORR_ERROR = 2,
            MACRO_ECC_UNCORR_ERROR = 3,
            MACRO_WRITE_BLANK_ERROR = 4,
            ACCESS_ERROR = 5,
            CHECK_FAIL_ERROR = 6,
            FSM_STATE_ERROR = 7,
        ],
    ],

    Regwen [
        ENABLED OFFSET(0) NUMBITS(1) [
            DISABLED = 0,
            ENABLED = 1,
        ],
    ],

    DacCmd [
        RD OFFSET(0) NUMBITS(1) [],
        WR OFFSET(1) NUMBITS(1) [],
        DIGEST OFFSET(2) NUMBITS(1) [],
    ],
];

/// Used to hold the state that is saved between emulator runs.
#[derive(Deserialize, Serialize)]
struct OtpState {
    partitions: Vec<u8>,
    calculate_digests_on_reset: HashSet<usize>,
    digests: Vec<u32>,
}

#[derive(Bus)]
#[poll_fn(poll)]
#[warm_reset_fn(warm_reset)]
#[allow(dead_code)]
pub struct Otp {
    /// File to store the OTP partitions.
    file: Option<File>,
    direct_access_buffer: u32,
    timer: Timer,
    partitions: Vec<u8>,
    /// Partitions to calculate digests for on reset.
    calculate_digests_on_reset: HashSet<usize>,
    /// Interrupt State Register
    #[register(offset = 0x0, write_fn = write_intr_state)]
    intr_state: ReadWriteRegister<u32>,
    /// Interrupt Enable Register
    #[register(offset = 0x4)]
    intr_enable: ReadWriteRegister<u32>,
    /// Interrupt Test Register
    #[register(offset = 0x8, write_fn = write_intr_test)]
    intr_test: WriteOnlyRegister<u32>,
    /// Alert Test Register
    #[register(offset = 0xc, write_fn = write_alert_test)]
    alert_test: WriteOnlyRegister<u32>,
    /// OTP status register.
    #[register(offset = 0x10)]
    status: ReadOnlyRegister<u32, Status::Register>,
    /// These registers hold information about error conditions that occurred in the agents
    #[register_array(offset = 0x14)]
    err_codes: [ReadOnlyRegister<u32, ErrCode::Register>; 13],
    /// Register write enable for all direct access interface registers.
    #[register(offset = 0x48)]
    direct_access_regwen: ReadWriteRegister<u32, Regwen::Register>,
    /// Command register for direct accesses.
    #[register(offset = 0x4c, write_fn = write_direct_access_cmd, read_fn = read_zero)]
    direct_access_cmd: ReadWriteRegister<u32, DacCmd::Register>,
    /// Address register for direct accesses.
    #[register(offset = 0x50, write_fn = write_direct_access_address, read_fn = read_direct_access_address)]
    direct_access_address: u32,
    /// Write data for direct accesses.
    #[register(offset = 0x54, write_fn = write_direct_access_wdata_0, read_fn = read_direct_access_wdata_0)]
    _direct_access_wdata_0: (),
    /// Write data for direct accesses.
    #[register(offset = 0x58, write_fn = write_error, read_fn = read_error)]
    _direct_access_wdata_1: (),
    /// Read data for direct accesses.
    #[register(offset = 0x5c, read_fn = read_direct_access_rdata_0, write_fn = write_error)]
    _direct_access_rdata_0: (),
    /// Read data for direct accesses.
    #[register(offset = 0x60, read_fn = read_direct_access_rdata_1, write_fn = write_error)]
    _direct_access_rdata_1: (),
    /// Register write enable for !!CHECK_TRIGGER.
    #[register(offset = 0x64)]
    check_trigger_regwen: ReadWriteRegister<u32, Regwen::Register>,
    /// Check trigger register.
    #[register(offset = 0x68, write_fn = write_check_trigger, read_fn = read_zero)]
    check_trigger: ReadWriteRegister<u32>,
    /// Register write enable for !!INTEGRITY_CHECK_PERIOD and !!CONSISTENCY_CHECK_PERIOD.
    #[register(offset = 0x6c, write_fn = write_check_regwen, read_fn = read_check_regwen)]
    check_regwen: ReadWriteRegister<u32>,
    /// Timeout value for the integrity and consistency checks.
    #[register(offset = 0x70, write_fn = write_check_timeout, read_fn = read_check_timeout)]
    check_timeout: ReadWriteRegister<u32>,
    /// This value specifies the maximum period that can be generated pseudo-randomly.
    #[register(offset = 0x74, write_fn = write_integrity_check_period, read_fn = read_integrity_check_period)]
    integrity_check_period: ReadWriteRegister<u32>,
    /// This value specifies the maximum period that can be generated pseudo-randomly.
    #[register(offset = 0x78, write_fn = write_consistency_check_period, read_fn = read_consistency_check_period)]
    consistency_check_period: ReadWriteRegister<u32>,
    /// Runtime read lock for the VENDOR_TEST partition.
    #[register(offset = 0x7c, write_fn = write_vendor_test_read_lock, read_fn = read_vendor_test_read_lock)]
    vendor_test_read_lock: ReadWriteRegister<u32>,
    /// Runtime read lock for the CREATOR_SW_CFG partition.
    #[register(offset = 0x80, write_fn = write_creator_sw_cfg_read_lock, read_fn = read_creator_sw_cfg_read_lock)]
    creator_sw_cfg_read_lock: ReadWriteRegister<u32>,
    /// Integrity digest for the partitions.
    #[register_array(offset = 0x84, write_fn = write_error_array)]
    digests: [u32; 10],
    /// Any read to this window directly maps to the corresponding offset in the creator and owner software
    #[register_array(offset = 0x800, item_size = 4, len = 2048, write_fn = write_sw_cfg_window, read_fn = read_sw_cfg_window)]
    _sw_cfg_window: (),
}

// Ensure that we save the state before we drop the OTP instance.
impl Drop for Otp {
    fn drop(&mut self) {
        self.save_to_file().unwrap();
        if let Some(file) = &mut self.file {
            file.sync_all().unwrap();
        }
    }
}

#[allow(dead_code)]
impl Otp {
    pub fn new(clock: &Clock, file_name: Option<PathBuf>) -> Result<Self, std::io::Error> {
        let file = if let Some(path) = file_name {
            Some(
                std::fs::File::options()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(path)?,
            )
        } else {
            None
        };

        let mut otp = Self {
            file,
            direct_access_buffer: 0,
            calculate_digests_on_reset: HashSet::new(),
            timer: Timer::new(clock),
            partitions: vec![0u8; TOTAL_SIZE],
            intr_state: ReadWriteRegister::new(0),
            intr_enable: ReadWriteRegister::new(0),
            intr_test: WriteOnlyRegister::new(0),
            alert_test: WriteOnlyRegister::new(0),
            status: ReadOnlyRegister::new(Status::DAI_IDLE::SET.value),
            err_codes: core::array::from_fn::<_, 13, _>(|_| ReadOnlyRegister::new(0)),
            direct_access_regwen: ReadWriteRegister::new(1),
            direct_access_cmd: ReadWriteRegister::new(0),
            direct_access_address: 0,
            _direct_access_wdata_0: (),
            _direct_access_wdata_1: (),
            _direct_access_rdata_0: (),
            _direct_access_rdata_1: (),
            check_trigger_regwen: ReadWriteRegister::new(1),
            check_trigger: ReadWriteRegister::new(0),
            check_regwen: ReadWriteRegister::new(1),
            check_timeout: ReadWriteRegister::new(0),
            integrity_check_period: ReadWriteRegister::new(0),
            consistency_check_period: ReadWriteRegister::new(0),
            vendor_test_read_lock: ReadWriteRegister::new(1),
            creator_sw_cfg_read_lock: ReadWriteRegister::new(1),
            digests: [0; 10],
            _sw_cfg_window: (),
        };
        otp.read_from_file()?;
        // if there were digests that were pending a reset, then calculate them now
        otp.calculate_digests()?;
        Ok(otp)
    }

    /// Memory map size.
    pub fn mmap_size(&self) -> RvAddr {
        4096
    }

    fn write_intr_state(&mut self, _size: RvSize, _val: RvData) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }
    fn write_intr_test(&mut self, _size: RvSize, _val: RvData) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }
    fn write_alert_test(&mut self, _size: RvSize, _val: RvData) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }
    fn write_direct_access_cmd(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        if val.count_ones() > 1 {
            Err(BusError::StoreAccessFault)?;
        };
        self.direct_access_cmd.reg.set(val);
        self.timer.schedule_poll_in(2);
        self.status.reg.set(Status::DAI_IDLE::CLEAR.value);
        Ok(())
    }
    fn read_zero(&mut self, _size: RvSize) -> Result<RvData, BusError> {
        Ok(0)
    }
    fn write_error_array(
        &mut self,
        _size: RvSize,
        _index: usize,
        _val: RvData,
    ) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }
    fn write_error(&mut self, _size: RvSize, _val: RvData) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }
    fn read_error(&mut self, _size: RvSize) -> Result<RvData, BusError> {
        Err(BusError::LoadAccessFault)
    }
    fn write_direct_access_address(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?;
        }
        if val as usize >= TOTAL_SIZE {
            Err(BusError::StoreAccessFault)
        } else {
            self.direct_access_address = val;
            Ok(())
        }
    }
    fn read_direct_access_address(&mut self, size: RvSize) -> Result<RvData, BusError> {
        if size != RvSize::Word {
            Err(BusError::LoadAccessFault)?;
        }
        Ok(self.direct_access_address)
    }
    fn write_direct_access_wdata_0(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        if size != RvSize::Word {
            return Err(BusError::StoreAccessFault);
        }
        self.direct_access_buffer = val;
        Ok(())
    }
    fn read_direct_access_wdata_0(&mut self, size: RvSize) -> Result<RvData, BusError> {
        if size != RvSize::Word {
            return Err(BusError::LoadAccessFault);
        }
        Ok(self.direct_access_buffer)
    }
    fn read_direct_access_rdata_0(&mut self, size: RvSize) -> Result<RvData, BusError> {
        if size != RvSize::Word {
            return Err(BusError::LoadAccessFault)?;
        }
        Ok(self.direct_access_buffer)
    }
    fn read_direct_access_rdata_1(&mut self, _size: RvSize) -> Result<RvData, BusError> {
        Err(BusError::LoadAccessFault)
    }
    fn write_check_trigger(&mut self, _size: RvSize, _val: RvData) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }
    fn read_check_trigger(&mut self, _size: RvSize) -> Result<RvData, BusError> {
        Err(BusError::LoadAccessFault)
    }
    fn write_check_regwen(&mut self, _size: RvSize, _val: RvData) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }
    fn read_check_regwen(&mut self, _size: RvSize) -> Result<RvData, BusError> {
        Err(BusError::LoadAccessFault)
    }
    fn write_check_timeout(&mut self, _size: RvSize, _val: RvData) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }
    fn read_check_timeout(&mut self, _size: RvSize) -> Result<RvData, BusError> {
        Err(BusError::LoadAccessFault)
    }
    fn write_integrity_check_period(
        &mut self,
        _size: RvSize,
        _val: RvData,
    ) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }
    fn read_integrity_check_period(&mut self, _size: RvSize) -> Result<RvData, BusError> {
        Err(BusError::LoadAccessFault)
    }
    fn write_consistency_check_period(
        &mut self,
        _size: RvSize,
        _val: RvData,
    ) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }
    fn read_consistency_check_period(&mut self, _size: RvSize) -> Result<RvData, BusError> {
        Err(BusError::LoadAccessFault)
    }
    fn write_vendor_test_read_lock(&mut self, _size: RvSize, _val: RvData) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }
    fn read_vendor_test_read_lock(&mut self, _size: RvSize) -> Result<RvData, BusError> {
        Err(BusError::LoadAccessFault)
    }
    fn write_creator_sw_cfg_read_lock(
        &mut self,
        _size: RvSize,
        _val: RvData,
    ) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }
    fn read_creator_sw_cfg_read_lock(&mut self, _size: RvSize) -> Result<RvData, BusError> {
        Err(BusError::LoadAccessFault)
    }
    fn write_owner_sw_cfg_read_lock(
        &mut self,
        _size: RvSize,
        _val: RvData,
    ) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }
    fn read_owner_sw_cfg_read_lock(&mut self, _size: RvSize) -> Result<RvData, BusError> {
        Err(BusError::LoadAccessFault)
    }
    fn write_rot_creator_auth_codesign_read_lock(
        &mut self,
        _size: RvSize,
        _val: RvData,
    ) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }
    fn read_rot_creator_auth_codesign_read_lock(
        &mut self,
        _size: RvSize,
    ) -> Result<RvData, BusError> {
        Err(BusError::LoadAccessFault)
    }
    fn write_rot_creator_auth_state_read_lock(
        &mut self,
        _size: RvSize,
        _val: RvData,
    ) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }
    fn read_rot_creator_auth_state_read_lock(&mut self, _size: RvSize) -> Result<RvData, BusError> {
        Err(BusError::LoadAccessFault)
    }
    fn write_digest(&mut self, _size: RvSize, _index: usize, _val: RvData) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }

    fn write_sw_cfg_window(
        &mut self,
        _size: RvSize,
        _index: usize,
        _val: RvData,
    ) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }
    fn read_sw_cfg_window(&mut self, _size: RvSize, _index: usize) -> Result<RvData, BusError> {
        Err(BusError::LoadAccessFault)
    }

    /// Called by Bus::poll() to indicate that time has passed
    fn poll(&mut self) {
        if self.direct_access_cmd.reg.read(DacCmd::WR) == 1 {
            // clear bottom two bits
            let addr = (self.direct_access_address & 0xffff_fffc) as usize;
            if addr + 4 <= TOTAL_SIZE {
                // refuse to write twice
                if self.partitions[addr..addr + 4].iter().all(|x| *x == 0) {
                    self.partitions[addr..addr + 4]
                        .copy_from_slice(&self.direct_access_buffer.to_le_bytes());
                }
            }
            // reset direct access
            self.direct_access_cmd.reg.set(0);
            self.direct_access_address = 0;
            self.direct_access_buffer = 0;
        } else if self.direct_access_cmd.reg.read(DacCmd::RD) == 1 {
            self.direct_access_cmd.reg.set(0);
            // clear bottom two bits
            let addr = (self.direct_access_address & 0xffff_fffc) as usize;
            if addr + 4 <= TOTAL_SIZE {
                let mut buf = [0; 4];
                buf.copy_from_slice(&self.partitions[addr..addr + 4]);
                self.direct_access_buffer = u32::from_le_bytes(buf);
            }
            // reset direct access
            self.direct_access_cmd.reg.set(0);
            self.direct_access_address = 0;
        } else if self.direct_access_cmd.reg.read(DacCmd::DIGEST) == 1 {
            // clear bottom two bits
            let addr = (self.direct_access_address & 0xffff_fffc) as usize;
            let partition = match addr {
                VENDOR_TEST_PARITION_ADDR => 0,
                CREATOR_SW_CFG_PARTITION_ADDR => 1,
                SECRET0_PARTITION_ADDR => 2,
                SECRET1_PARTITION_ADDR => 3,
                _ => 4,
            };
            // cowardly refuse to calculate digests for the lifecycle partition
            if partition != 4 {
                self.calculate_digests_on_reset.insert(partition);
            }
        }

        // set idle status so that users know operations have completed
        self.status.reg.set(Status::DAI_IDLE::SET.value);
    }

    /// Called by Bus::warm_reset() to reset the device.
    fn warm_reset(&mut self) {
        self.calculate_digests().unwrap();
    }

    fn calculate_digests(&mut self) -> Result<(), std::io::Error> {
        let partitions = self.calculate_digests_on_reset.clone();
        for partition in partitions {
            self.calculate_digest(partition);
        }
        self.calculate_digests_on_reset.clear();
        self.save_to_file()
    }

    fn calculate_digest(&mut self, partition: usize) {
        let (addr, size) = match partition {
            0 => (VENDOR_TEST_PARITION_ADDR, VENDOR_TEST_PARITION_SIZE),
            1 => (CREATOR_SW_CFG_PARTITION_ADDR, CREATOR_SW_CFG_PARTITION_SIZE),
            2 => (SECRET0_PARTITION_ADDR, SECRET0_PARTITION_SIZE),
            3 => (SECRET1_PARTITION_ADDR, SECRET1_PARTITION_SIZE),
            _ => unreachable!(),
        };
        let digest =
            otp_digest::otp_digest(&self.partitions[addr..addr + size], DIGEST_IV, DIGEST_CONST);
        self.digests[partition * 2] = (digest & 0xffff_ffff) as u32;
        self.digests[partition * 2 + 1] = (digest >> 32) as u32;
    }

    fn get_state(&self) -> OtpState {
        OtpState {
            partitions: self.partitions.clone(),
            calculate_digests_on_reset: self.calculate_digests_on_reset.clone(),
            digests: self.digests.to_vec(),
        }
    }

    fn load_state(&mut self, state: &OtpState) {
        self.partitions = state.partitions.clone();
        self.calculate_digests_on_reset = state.calculate_digests_on_reset.clone();
        self.digests.copy_from_slice(&state.digests);
    }

    fn read_from_file(&mut self) -> Result<(), std::io::Error> {
        if let Some(file) = &mut self.file {
            if file.metadata()?.len() > 0 {
                file.rewind()?;
                let state: OtpState = serde_json::from_reader(file)?;
                self.load_state(&state);
            }
        }
        Ok(())
    }

    fn save_to_file(&mut self) -> Result<(), std::io::Error> {
        let state = self.get_state();
        if let Some(file) = &mut self.file {
            file.rewind()?;
            serde_json::to_writer(file, &state)?;
        }
        Ok(())
    }

    fn digest_bytes(&self) -> Vec<u8> {
        self.digests
            .iter()
            .flat_map(|x| x.to_le_bytes().to_vec())
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tock_registers::interfaces::{Readable, Writeable};

    #[test]
    fn test_bootup() {
        let clock = Clock::new();
        let otp = Otp::new(&clock, None).unwrap();
        // simulate post-bootup flow
        assert_eq!(otp.status.reg.get(), Status::DAI_IDLE::SET.value);
        otp.integrity_check_period.reg.set(0x3_FFFF);
        otp.consistency_check_period.reg.set(0x3FF_FFFF);
        otp.check_timeout.reg.set(0b10_0000);
        otp.check_regwen.reg.set(0);
        // one-off integrity check
        otp.check_trigger.reg.set(0b11);

        // assert_eq!(
        //     Status::CHECK_PENDING::SET.value,
        //     otp.status.reg.read(Status::CHECK_PENDING)
        // );
        // disable integrity checks
        otp.check_trigger_regwen.reg.set(0);
        // block read access to the SW managed partitions
        otp.creator_sw_cfg_read_lock.reg.set(0);
    }

    #[test]
    fn test_write_and_read() {
        let clock = Clock::new();
        let mut otp = Otp::new(&clock, None).unwrap();
        // write the vendor partition
        assert_eq!(otp.status.reg.get(), Status::DAI_IDLE::SET.value);
        for i in 0..VENDOR_TEST_PARITION_SIZE / 4 {
            otp.write_direct_access_wdata_0(RvSize::Word, i as u32)
                .unwrap();
            otp.write_direct_access_address(RvSize::Word, (i * 4) as u32)
                .unwrap();
            otp.write_direct_access_cmd(RvSize::Word, 2).unwrap();
            // wait for idle
            assert_eq!(otp.status.reg.get(), Status::DAI_IDLE::CLEAR.value);
            for _ in 0..1000 {
                if otp.status.reg.read(Status::DAI_IDLE) != 0 {
                    break;
                }
                otp.poll();
            }
            // check that we are idle with no errors
            assert_eq!(otp.status.reg.get(), Status::DAI_IDLE::SET.value);
        }

        // read the vendor partition
        assert_eq!(otp.status.reg.get(), Status::DAI_IDLE::SET.value);
        for i in 0..VENDOR_TEST_PARITION_SIZE / 4 {
            otp.write_direct_access_address(RvSize::Word, (i * 4) as u32)
                .unwrap();
            otp.write_direct_access_cmd(RvSize::Word, 1).unwrap();
            // wait for idle
            assert_eq!(otp.status.reg.get(), Status::DAI_IDLE::CLEAR.value);
            for _ in 0..1000 {
                if otp.status.reg.read(Status::DAI_IDLE) != 0 {
                    break;
                }
                otp.poll();
            }
            // check that we are idle with no errors
            assert_eq!(otp.status.reg.get(), Status::DAI_IDLE::SET.value);
            // read the data
            let data = otp.read_direct_access_rdata_0(RvSize::Word).unwrap();
            assert_eq!(data, i as u32);
        }
    }

    #[test]
    fn test_digest() {
        let clock = Clock::new();
        let mut otp = Otp::new(&clock, None).unwrap();
        // write the vendor partition
        assert_eq!(otp.status.reg.get(), Status::DAI_IDLE::SET.value);
        for i in 0..VENDOR_TEST_PARITION_SIZE / 4 {
            otp.write_direct_access_wdata_0(RvSize::Word, i as u32)
                .unwrap();
            otp.write_direct_access_address(RvSize::Word, (i * 4) as u32)
                .unwrap();
            otp.write_direct_access_cmd(RvSize::Word, 2).unwrap();
            // wait for idle
            assert_eq!(otp.status.reg.get(), Status::DAI_IDLE::CLEAR.value);
            for _ in 0..1000 {
                if otp.status.reg.read(Status::DAI_IDLE) != 0 {
                    break;
                }
                otp.poll();
            }
            // check that we are idle with no errors
            assert_eq!(otp.status.reg.get(), Status::DAI_IDLE::SET.value);
        }

        // trigger a digest
        otp.write_direct_access_address(RvSize::Word, 0).unwrap();
        otp.write_direct_access_cmd(RvSize::Word, 4).unwrap();
        // wait for idle
        assert_eq!(otp.status.reg.get(), Status::DAI_IDLE::CLEAR.value);
        for _ in 0..1000 {
            if otp.status.reg.read(Status::DAI_IDLE) != 0 {
                break;
            }
            otp.poll();
        }
        // check that we are idle with no errors
        assert_eq!(otp.status.reg.get(), Status::DAI_IDLE::SET.value);
        // check that the digest is invalid
        assert_ne!(otp.digests[0], 0xd7e4a117);
        assert_ne!(otp.digests[1], 0x421763fd);
        // reset
        otp.warm_reset();
        // check that the digest is valid
        assert_eq!(otp.digests[0], 0xd7e4a117);
        assert_eq!(otp.digests[1], 0x421763fd);
    }
}

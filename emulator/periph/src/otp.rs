/*++

Licensed under the Apache-2.0 license.

File Name:

    otp.rs

Abstract:

    OpenTitan OTP Open Source Controller emulated device.
    We only support 32-bit granularity for now.

--*/
use crate::otp_digest;
use caliptra_emu_types::{RvAddr, RvData};
use emulator_bus::{Clock, ReadWriteRegister, Timer};
use registers_generated::fuses::{self, NON_SECRET_FUSES_WORD_OFFSET, SECRET3_WORD_OFFSET};
use registers_generated::otp_ctrl::bits::{DirectAccessCmd, Status};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::Seek;
use std::path::PathBuf;
#[allow(unused_imports)] // Rust compiler doesn't like these
use tock_registers::interfaces::{Readable, Writeable};

/// OTP Digest constant, randomly generated. Usually read from configuration file.
const DIGEST_CONST: u128 = 0xfc2f4d648d4a45b482924470b96f0cee;
/// OTP Digest IV, randomly generated. Usually read from configuration file.
const DIGEST_IV: u64 = 0x25b5e5a1627a3557;

#[allow(dead_code)]
enum Partitions {
    VendorTest = 0,
    NonSecret = 1,
    Secret0 = 2,
    Secret1 = 3,
    Secret2 = 4,
    Secret3 = 5,
    LifeCycle = 6,
}

const TOTAL_SIZE: usize = (fuses::LIFE_CYCLE_WORD_OFFSET + fuses::LIFE_CYCLE_WORD_SIZE) * 4;

/// Used to hold the state that is saved between emulator runs.
#[derive(Deserialize, Serialize)]
struct OtpState {
    partitions: Vec<u8>,
    calculate_digests_on_reset: HashSet<usize>,
    digests: Vec<u32>,
}

//#[derive(Bus)]
#[allow(dead_code)]
pub struct Otp {
    /// File to store the OTP partitions.
    file: Option<File>,
    direct_access_address: u32,
    direct_access_buffer: u32,
    direct_access_cmd: ReadWriteRegister<u32, DirectAccessCmd::Register>,
    status: ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Status::Register>,
    timer: Timer,
    partitions: Vec<u8>,
    digests: [u32; 12],
    /// Partitions to calculate digests for on reset.
    calculate_digests_on_reset: HashSet<usize>,
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
    pub fn new(
        clock: &Clock,
        file_name: Option<PathBuf>,
        owner_pk_hash: Option<[u8; 48]>,
        vendor_pk_hash: Option<[u8; 48]>,
    ) -> Result<Self, std::io::Error> {
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
            direct_access_address: 0,
            direct_access_buffer: 0,
            direct_access_cmd: 0u32.into(),
            status: 0b100_0000_0000_0000u32.into(), // DAI idle state
            calculate_digests_on_reset: HashSet::new(),
            timer: Timer::new(clock),
            partitions: vec![0u8; TOTAL_SIZE],
            digests: [0; 12],
        };
        otp.read_from_file()?;
        if let Some(mut owner_pk_hash) = owner_pk_hash {
            swap_endianness(&mut owner_pk_hash);
            otp.partitions
                [(NON_SECRET_FUSES_WORD_OFFSET + 8) * 4..(NON_SECRET_FUSES_WORD_OFFSET + 20) * 4]
                .copy_from_slice(&owner_pk_hash);
        }
        if let Some(mut vendor_pk_hash) = vendor_pk_hash {
            swap_endianness(&mut vendor_pk_hash);
            otp.partitions[SECRET3_WORD_OFFSET * 4..(SECRET3_WORD_OFFSET + 12) * 4]
                .copy_from_slice(&vendor_pk_hash);
        }
        // if there were digests that were pending a reset, then calculate them now
        otp.calculate_digests()?;
        Ok(otp)
    }

    /// Memory map size.
    pub fn mmap_size(&self) -> RvAddr {
        4096
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
        let (word_addr, word_size) = match partition {
            0 => (fuses::VENDOR_TEST_WORD_OFFSET, fuses::VENDOR_TEST_WORD_SIZE),
            1 => (
                fuses::NON_SECRET_FUSES_WORD_OFFSET,
                fuses::NON_SECRET_FUSES_WORD_SIZE,
            ),
            2 => (fuses::SECRET0_WORD_OFFSET, fuses::SECRET0_WORD_SIZE),
            3 => (fuses::SECRET1_WORD_OFFSET, fuses::SECRET1_WORD_SIZE),
            4 => (fuses::SECRET2_WORD_OFFSET, fuses::SECRET2_WORD_SIZE),
            5 => (fuses::SECRET3_WORD_OFFSET, fuses::SECRET3_WORD_SIZE),
            _ => unreachable!(),
        };
        let addr = word_addr * 4;
        let size = word_size * 4;
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

impl emulator_registers_generated::otp::OtpPeripheral for Otp {
    fn read_status(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Status::Register>
    {
        self.status.clone()
    }

    fn write_direct_access_address(
        &mut self,
        val: ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::DirectAccessAddress::Register,
        >,
    ) {
        let val = val.reg.get();
        if (val as usize) < TOTAL_SIZE {
            self.direct_access_address = val;
        }
    }

    fn read_direct_access_address(
        &mut self,
    ) -> ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::DirectAccessAddress::Register>
    {
        self.direct_access_address.into()
    }

    fn write_direct_access_cmd(
        &mut self,
        val: ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::DirectAccessCmd::Register>,
    ) {
        let val = val.reg.get();
        if val.count_ones() > 1 {
            return;
        };
        self.direct_access_cmd.reg.set(val);
        self.timer.schedule_poll_in(2);
        self.status.reg.set(Status::DailIdle::CLEAR.value);
    }

    fn read_dai_rdata_rf_direct_access_rdata_0(&mut self) -> RvData {
        self.direct_access_buffer
    }

    fn read_dai_wdata_rf_direct_access_wdata_0(&mut self) -> RvData {
        self.direct_access_buffer
    }

    fn write_dai_wdata_rf_direct_access_wdata_0(&mut self, val: RvData) {
        self.direct_access_buffer = val;
    }

    /// Called by Bus::poll() to indicate that time has passed
    fn poll(&mut self) {
        if self.direct_access_cmd.reg.read(DirectAccessCmd::Wr) == 1 {
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
        } else if self.direct_access_cmd.reg.read(DirectAccessCmd::Rd) == 1 {
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
        } else if self.direct_access_cmd.reg.read(DirectAccessCmd::Digest) == 1 {
            // clear bottom two bits
            let addr = (self.direct_access_address & 0xffff_fffc) as usize;
            let partition = match addr / 4 {
                fuses::VENDOR_TEST_WORD_OFFSET => 0,
                fuses::NON_SECRET_FUSES_WORD_OFFSET => 1,
                fuses::SECRET0_WORD_OFFSET => 2,
                fuses::SECRET1_WORD_OFFSET => 3,
                fuses::SECRET2_WORD_OFFSET => 4,
                fuses::SECRET3_WORD_OFFSET => 5,
                _ => 6,
            };
            // cowardly refuse to calculate digests for the lifecycle partition
            if partition != 6 {
                self.calculate_digests_on_reset.insert(partition);
            }
        }

        // set idle status so that users know operations have completed
        self.status.reg.set(Status::DailIdle::SET.value);
    }

    /// Called by Bus::warm_reset() to reset the device.
    fn warm_reset(&mut self) {
        self.calculate_digests().unwrap();
    }
}

/// Convert the slice to hardware format
fn swap_endianness(value: &mut [u8]) {
    for i in (0..value.len()).step_by(4) {
        value[i..i + 4].reverse();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use emulator_registers_generated::otp::OtpPeripheral;
    #[allow(unused_imports)]
    use tock_registers::interfaces::{Readable, Writeable};

    #[test]
    fn test_bootup() {
        let clock = Clock::new();
        let mut otp = Otp::new(&clock, None, None, None).unwrap();
        // simulate post-bootup flow
        assert_eq!(otp.status.reg.get(), Status::DailIdle::SET.value);
        otp.write_integrity_check_period(0x3_FFFFu32.into());
        otp.write_consistency_check_period(0x3FF_FFFFu32.into());
        otp.write_check_timeout(0b10_0000u32.into());
        otp.write_check_regwen(0u32.into());
        // one-off integrity check
        otp.write_check_trigger(0b11u32.into());

        // assert_eq!(
        //     Status::CHECK_PENDING::SET.value,
        //     otp.status.reg.read(Status::CHECK_PENDING)
        // );
        // disable integrity checks
        otp.write_check_trigger_regwen(0u32.into());
        // block read access to the SW managed partitions
        otp.write_vendor_test_read_lock(0u32.into());
    }

    #[test]
    fn test_write_and_read() {
        let clock = Clock::new();
        let mut otp = Otp::new(&clock, None, None, None).unwrap();
        // write the vendor partition
        assert_eq!(otp.status.reg.get(), Status::DailIdle::SET.value);
        for i in 0..fuses::VENDOR_TEST_WORD_SIZE {
            otp.write_dai_wdata_rf_direct_access_wdata_0(i as u32);
            otp.write_direct_access_address(((i * 4) as u32).into());
            otp.write_direct_access_cmd(2u32.into());
            // wait for idle
            assert_eq!(otp.status.reg.get(), Status::DailIdle::CLEAR.value);
            for _ in 0..1000 {
                if otp.status.reg.read(Status::DailIdle) != 0 {
                    break;
                }
                otp.poll();
            }
            // check that we are idle with no errors
            assert_eq!(otp.status.reg.get(), Status::DailIdle::SET.value);
        }

        // read the vendor partition
        assert_eq!(otp.status.reg.get(), Status::DailIdle::SET.value);
        for i in 0..fuses::VENDOR_TEST_WORD_SIZE {
            otp.write_direct_access_address(((i * 4) as u32).into());
            otp.write_direct_access_cmd(1u32.into());
            // wait for idle
            assert_eq!(otp.status.reg.get(), Status::DailIdle::CLEAR.value);
            for _ in 0..1000 {
                if otp.status.reg.read(Status::DailIdle) != 0 {
                    break;
                }
                otp.poll();
            }
            // check that we are idle with no errors
            assert_eq!(otp.status.reg.get(), Status::DailIdle::SET.value);
            // read the data
            let data = otp.read_dai_rdata_rf_direct_access_rdata_0();
            assert_eq!(data, i as u32);
        }
    }

    #[test]
    fn test_digest() {
        let clock = Clock::new();
        let mut otp = Otp::new(&clock, None, None, None).unwrap();
        // write the vendor partition
        assert_eq!(otp.status.reg.get(), Status::DailIdle::SET.value);
        for i in 0..fuses::VENDOR_TEST_WORD_SIZE {
            otp.write_dai_wdata_rf_direct_access_wdata_0(i as u32);
            otp.write_direct_access_address(((i * 4) as u32).into());
            otp.write_direct_access_cmd(2u32.into());
            // wait for idle
            assert_eq!(otp.status.reg.get(), Status::DailIdle::CLEAR.value);
            for _ in 0..1000 {
                if otp.status.reg.read(Status::DailIdle) != 0 {
                    break;
                }
                otp.poll();
            }
            // check that we are idle with no errors
            assert_eq!(otp.status.reg.get(), Status::DailIdle::SET.value);
        }

        // trigger a digest
        otp.write_direct_access_address(0u32.into());
        otp.write_direct_access_cmd(4u32.into());
        // wait for idle
        assert_eq!(otp.status.reg.get(), Status::DailIdle::CLEAR.value);
        for _ in 0..1000 {
            if otp.status.reg.read(Status::DailIdle) != 0 {
                break;
            }
            otp.poll();
        }
        // check that we are idle with no errors
        assert_eq!(otp.status.reg.get(), Status::DailIdle::SET.value);
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

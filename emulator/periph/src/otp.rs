/*++

Licensed under the Apache-2.0 license.

File Name:

    otp.rs

Abstract:

    OpenTitan OTP Open Source Controller emulated device.
    We only support 32-bit granularity for now.

--*/
use crate::otp_digest;
use caliptra_emu_bus::{Clock, ReadWriteRegister, Timer};
use caliptra_emu_types::{RvAddr, RvData};
use caliptra_image_types::FwVerificationPqcKeyType;
use emulator_registers_generated::otp::OtpGenerated;
use registers_generated::fuses::{self};
use registers_generated::otp_ctrl::bits::{DirectAccessCmd, OtpStatus};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashSet;
use std::fs::File;
use std::io::Seek;
use std::path::PathBuf;
use std::rc::Rc;
#[allow(unused_imports)] // Rust compiler doesn't like these
use tock_registers::interfaces::{Readable, Writeable};

/// OTP Digest constant default from caliptra-ss/src/fuse_ctrl/rtl/otp_ctrl_part_pkg.sv
const DIGEST_CONST: u128 = 0xF98C48B1F93772844A22D4B78FE0266F;
/// OTP Digest IV default from caliptra-ss/src/fuse_ctrl/rtl/otp_ctrl_part_pkg.sv
const DIGEST_IV: u64 = 0x90C7F21F6224F027;

const TOTAL_SIZE: usize = fuses::LIFE_CYCLE_BYTE_OFFSET + fuses::LIFE_CYCLE_BYTE_SIZE;

const PARTITIONS: [(usize, usize); 15] = [
    (
        fuses::SW_TEST_UNLOCK_PARTITION_BYTE_OFFSET,
        fuses::SW_TEST_UNLOCK_PARTITION_BYTE_SIZE,
    ),
    (
        fuses::SECRET_MANUF_PARTITION_BYTE_OFFSET,
        fuses::SECRET_MANUF_PARTITION_BYTE_SIZE,
    ),
    (
        fuses::SECRET_PROD_PARTITION_0_BYTE_OFFSET,
        fuses::SECRET_PROD_PARTITION_0_BYTE_SIZE,
    ),
    (
        fuses::SECRET_PROD_PARTITION_1_BYTE_OFFSET,
        fuses::SECRET_PROD_PARTITION_1_BYTE_SIZE,
    ),
    (
        fuses::SECRET_PROD_PARTITION_2_BYTE_OFFSET,
        fuses::SECRET_PROD_PARTITION_2_BYTE_SIZE,
    ),
    (
        fuses::SECRET_PROD_PARTITION_3_BYTE_OFFSET,
        fuses::SECRET_PROD_PARTITION_3_BYTE_SIZE,
    ),
    (
        fuses::SW_MANUF_PARTITION_BYTE_OFFSET,
        fuses::SW_MANUF_PARTITION_BYTE_SIZE,
    ),
    (
        fuses::SECRET_LC_TRANSITION_PARTITION_BYTE_OFFSET,
        fuses::SECRET_LC_TRANSITION_PARTITION_BYTE_SIZE,
    ),
    (
        fuses::SVN_PARTITION_BYTE_OFFSET,
        fuses::SVN_PARTITION_BYTE_SIZE,
    ),
    (
        fuses::VENDOR_TEST_PARTITION_BYTE_OFFSET,
        fuses::VENDOR_TEST_PARTITION_BYTE_SIZE,
    ),
    (
        fuses::VENDOR_HASHES_MANUF_PARTITION_BYTE_OFFSET,
        fuses::VENDOR_HASHES_MANUF_PARTITION_BYTE_SIZE,
    ),
    (
        fuses::VENDOR_HASHES_PROD_PARTITION_BYTE_OFFSET,
        fuses::VENDOR_HASHES_PROD_PARTITION_BYTE_SIZE,
    ),
    (
        fuses::VENDOR_REVOCATIONS_PROD_PARTITION_BYTE_OFFSET,
        fuses::VENDOR_REVOCATIONS_PROD_PARTITION_BYTE_SIZE,
    ),
    (
        fuses::VENDOR_SECRET_PROD_PARTITION_BYTE_OFFSET,
        fuses::VENDOR_SECRET_PROD_PARTITION_BYTE_SIZE,
    ),
    (
        fuses::VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET,
        fuses::VENDOR_NON_SECRET_PROD_PARTITION_BYTE_SIZE,
    ),
];

/// Used to hold the state that is saved between emulator runs.
#[derive(Deserialize, Serialize)]
struct OtpState {
    partitions: Vec<u8>,
    calculate_digests_on_reset: HashSet<usize>,
    digests: Vec<u32>,
}

#[derive(Default, Clone)]
pub struct OtpArgs {
    pub file_name: Option<PathBuf>,
    pub raw_memory: Option<Vec<u8>>,
    pub owner_pk_hash: Option<[u8; 48]>,
    pub vendor_pk_hash: Option<[u8; 48]>,
    pub vendor_pqc_type: FwVerificationPqcKeyType,
    pub soc_manifest_svn: Option<u8>,
    pub soc_manifest_max_svn: Option<u8>,
    pub vendor_hashes_prod_partition: Option<Vec<u8>>,
    pub vendor_test_partition: Option<Vec<u8>>,
}

//#[derive(Bus)]
#[allow(dead_code)]
pub struct Otp {
    /// File to store the OTP partitions.
    file: Option<File>,
    direct_access_address: u32,
    direct_access_buffer: u32,
    direct_access_cmd: ReadWriteRegister<u32, DirectAccessCmd::Register>,
    status: ReadWriteRegister<u32, OtpStatus::Register>,
    timer: Timer,
    partitions: Rc<RefCell<Vec<u8>>>,
    digests: [u32; PARTITIONS.len() * 2],
    /// Partitions to calculate digests for on reset.
    calculate_digests_on_reset: HashSet<usize>,
    generated: OtpGenerated,
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
    pub fn new(clock: &Clock, args: OtpArgs) -> Result<Self, std::io::Error> {
        let file = if let Some(path) = args.file_name {
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

        let mut partitions = vec![0u8; TOTAL_SIZE];

        if let Some(raw_memory) = args.raw_memory {
            if raw_memory.len() > TOTAL_SIZE {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Raw memory is too large",
                ))?;
            }
            partitions[..raw_memory.len()].copy_from_slice(&raw_memory);
        }

        let partitions = Rc::new(RefCell::new(partitions));

        let mut otp = Self {
            file,
            direct_access_address: 0,
            direct_access_buffer: 0,
            direct_access_cmd: 0u32.into(),
            status: OtpStatus::DaiIdle::SET.value.into(),
            calculate_digests_on_reset: HashSet::new(),
            timer: Timer::new(clock),
            partitions,
            digests: [0; PARTITIONS.len() * 2],
            generated: OtpGenerated::default(),
        };
        otp.read_from_file()?;
        if let Some(mut vendor_pk_hash) = args.vendor_pk_hash {
            swap_endianness(&mut vendor_pk_hash);
            otp.partitions.borrow_mut()[fuses::VENDOR_HASHES_MANUF_PARTITION_BYTE_OFFSET
                ..fuses::VENDOR_HASHES_MANUF_PARTITION_BYTE_OFFSET + 48]
                .copy_from_slice(&vendor_pk_hash);
        }
        // encode as a single bit, MLDSA as the default
        let val = match args.vendor_pqc_type {
            FwVerificationPqcKeyType::MLDSA => 0,
            FwVerificationPqcKeyType::LMS => 1,
        };
        {
            let mut partitions = otp.partitions.borrow_mut();
            partitions[fuses::VENDOR_HASHES_MANUF_PARTITION_BYTE_OFFSET + 48] = val;
            partitions[fuses::SVN_PARTITION_BYTE_OFFSET + 36] =
                args.soc_manifest_max_svn.unwrap_or(0);
            if let Some(soc_manifest_svn) = args.soc_manifest_svn {
                let svn_bitmap = Self::svn_to_bitmap(soc_manifest_svn as u32);
                partitions
                    [fuses::SVN_PARTITION_BYTE_OFFSET + 20..fuses::SVN_PARTITION_BYTE_OFFSET + 36]
                    .copy_from_slice(&svn_bitmap);
            }

            if let Some(vendor_hashes_prod_partition) = args.vendor_hashes_prod_partition {
                let dst_start = fuses::VENDOR_HASHES_PROD_PARTITION_BYTE_OFFSET;
                let max_len = fuses::VENDOR_HASHES_PROD_PARTITION_BYTE_SIZE;
                let copy_len = vendor_hashes_prod_partition.len().min(max_len);
                partitions[dst_start..dst_start + copy_len]
                    .copy_from_slice(&vendor_hashes_prod_partition[..copy_len]);
            }
            if let Some(vendor_test_partition) = args.vendor_test_partition {
                let dst_start = fuses::VENDOR_TEST_PARTITION_BYTE_OFFSET;
                let max_len = fuses::VENDOR_TEST_PARTITION_BYTE_SIZE;
                let copy_len = vendor_test_partition.len().min(max_len);
                partitions[dst_start..dst_start + copy_len]
                    .copy_from_slice(&vendor_test_partition[..copy_len]);
            }
        }

        // if there were digests that were pending a reset, then calculate them now
        otp.calculate_digests()?;
        Ok(otp)
    }

    /// Memory map size.
    pub fn mmap_size(&self) -> RvAddr {
        4096
    }

    /// Returns a clone of the shared partitions reference.
    /// This allows the model to hold a reference to the OTP memory.
    pub fn partitions_ref(&self) -> Rc<RefCell<Vec<u8>>> {
        self.partitions.clone()
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
        if partition >= PARTITIONS.len() - 1 {
            return;
        }
        let (addr, size) = PARTITIONS[partition];
        let partitions = self.partitions.borrow();
        let digest =
            otp_digest::otp_digest(&partitions[addr..addr + size], DIGEST_IV, DIGEST_CONST);
        self.digests[partition * 2] = (digest & 0xffff_ffff) as u32;
        self.digests[partition * 2 + 1] = (digest >> 32) as u32;
    }

    fn get_state(&self) -> OtpState {
        OtpState {
            partitions: self.partitions.borrow().clone(),
            calculate_digests_on_reset: self.calculate_digests_on_reset.clone(),
            digests: self.digests.to_vec(),
        }
    }

    fn load_state(&mut self, state: &OtpState) {
        *self.partitions.borrow_mut() = state.partitions.clone();
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

    pub fn svn_to_bitmap(svn: u32) -> [u8; 16] {
        let n = if svn > 128 { 128 } else { svn };

        // Build a 128-bit value with the lowest `n` bits set.
        // Shifting by 128 is invalid, so handle that case explicitly.
        let val: u128 = if n == 0 {
            0
        } else if n == 128 {
            u128::MAX
        } else {
            (1u128 << n) - 1
        };

        val.to_le_bytes()
    }
}

impl emulator_registers_generated::otp::OtpPeripheral for Otp {
    fn generated(&mut self) -> Option<&mut OtpGenerated> {
        Some(&mut self.generated)
    }

    fn read_otp_status(&mut self) -> caliptra_emu_bus::ReadWriteRegister<u32, OtpStatus::Register> {
        ReadWriteRegister::new(self.status.reg.get())
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
        self.status.reg.set(OtpStatus::DaiIdle::CLEAR.value);
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
                // OTP can only burn bits from 0 to 1, never clear bits.
                // We OR the new value with the existing value to emulate this behavior.
                let mut partitions = self.partitions.borrow_mut();
                let current = u32::from_le_bytes([
                    partitions[addr],
                    partitions[addr + 1],
                    partitions[addr + 2],
                    partitions[addr + 3],
                ]);
                let new_value = current | self.direct_access_buffer;
                partitions[addr..addr + 4].copy_from_slice(&new_value.to_le_bytes());
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
                let partitions = self.partitions.borrow();
                buf.copy_from_slice(&partitions[addr..addr + 4]);
                self.direct_access_buffer = u32::from_le_bytes(buf);
            }
            // reset direct access
            self.direct_access_cmd.reg.set(0);
            self.direct_access_address = 0;
        } else if self.direct_access_cmd.reg.read(DirectAccessCmd::Digest) == 1 {
            // clear bottom two bits
            let addr = (self.direct_access_address & 0xffff_fffc) as usize;
            let mut partition = PARTITIONS.len() - 1;
            for (i, p) in PARTITIONS.iter().enumerate() {
                if addr == p.0 {
                    partition = i;
                    break;
                }
            }
            // cowardly refuse to calculate digests for the lifecycle partition
            if partition != PARTITIONS.len() - 1 {
                self.calculate_digests_on_reset.insert(partition);
            }
        }

        // set idle status so that users know operations have completed
        self.status.reg.set(OtpStatus::DaiIdle::SET.value);
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
        let mut otp = Otp::new(
            &clock,
            OtpArgs {
                vendor_pqc_type: FwVerificationPqcKeyType::MLDSA,
                ..Default::default()
            },
        )
        .unwrap();
        // simulate post-bootup flow
        assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::SET.value);
        otp.write_integrity_check_period(0x3_FFFFu32);
        otp.write_consistency_check_period(0x3FF_FFFFu32);
        otp.write_check_timeout(0b10_0000u32);
        otp.write_check_regwen(0u32.into());
        // one-off integrity check
        otp.write_check_trigger(0b11u32.into());
        // simulate post-bootup flow
        assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::SET.value);
        otp.write_integrity_check_period(0x3_FFFFu32);
        otp.write_consistency_check_period(0x3FF_FFFFu32);
        otp.write_check_timeout(0b10_0000u32);
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
        otp.write_vendor_test_partition_read_lock(0u32.into());
    }

    #[test]
    fn test_write_and_read() {
        let clock = Clock::new();
        let mut otp = Otp::new(
            &clock,
            OtpArgs {
                vendor_pqc_type: FwVerificationPqcKeyType::MLDSA,
                ..Default::default()
            },
        )
        .unwrap();
        // write the vendor partition
        assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::SET.value);
        for i in 0..fuses::VENDOR_TEST_PARTITION_BYTE_SIZE {
            otp.write_dai_wdata_rf_direct_access_wdata_0(i as u32);
            otp.write_direct_access_address(
                ((fuses::VENDOR_TEST_PARTITION_BYTE_OFFSET + i * 4) as u32).into(),
            );
        }
        // write the vendor partition
        assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::SET.value);
        for i in 0..fuses::VENDOR_TEST_PARTITION_BYTE_SIZE {
            otp.write_dai_wdata_rf_direct_access_wdata_0(i as u32);
            otp.write_direct_access_address(
                ((fuses::VENDOR_TEST_PARTITION_BYTE_OFFSET + i * 4) as u32).into(),
            );
            otp.write_direct_access_cmd(2u32.into());
            // wait for idle
            assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::CLEAR.value);
            for _ in 0..1000 {
                if otp.status.reg.read(OtpStatus::DaiIdle) != 0 {
                    break;
                }
                otp.poll();
            }
            // check that we are idle with no errors
            assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::SET.value);
        }

        // read the vendor partition
        assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::SET.value);
        for i in 0..fuses::VENDOR_TEST_PARTITION_BYTE_SIZE {
            otp.write_direct_access_address(
                ((fuses::VENDOR_TEST_PARTITION_BYTE_OFFSET + i * 4) as u32).into(),
            );
            otp.write_direct_access_cmd(1u32.into());
            // wait for idle
            assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::CLEAR.value);
            for _ in 0..1000 {
                if otp.status.reg.read(OtpStatus::DaiIdle) != 0 {
                    break;
                }
                otp.poll();
            }
            // check that we are idle with no errors
            assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::SET.value);
            // read the data
            let data = otp.read_dai_rdata_rf_direct_access_rdata_0();
            assert_eq!(data, i as u32);
        }
    }

    #[test]
    fn test_digest() {
        let clock = Clock::new();
        let mut otp = Otp::new(
            &clock,
            OtpArgs {
                vendor_pqc_type: FwVerificationPqcKeyType::MLDSA,
                ..Default::default()
            },
        )
        .unwrap();
        // write the vendor partition
        assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::SET.value);
        for i in 0..fuses::VENDOR_TEST_PARTITION_BYTE_SIZE {
            otp.write_dai_wdata_rf_direct_access_wdata_0(i as u32);
            otp.write_direct_access_address(
                ((fuses::VENDOR_TEST_PARTITION_BYTE_OFFSET + i * 4) as u32).into(),
            );
            otp.write_direct_access_cmd(2u32.into());
            // wait for idle
            assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::CLEAR.value);
            for _ in 0..1000 {
                if otp.status.reg.read(OtpStatus::DaiIdle) != 0 {
                    break;
                }
                otp.poll();
            }
            // check that we are idle with no errors
            assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::SET.value);
        }

        // trigger a digest
        otp.write_direct_access_address((fuses::VENDOR_TEST_PARTITION_BYTE_OFFSET as u32).into());
        otp.write_direct_access_cmd(4u32.into());
        // wait for idle
        assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::CLEAR.value);
        for _ in 0..1000 {
            if otp.status.reg.read(OtpStatus::DaiIdle) != 0 {
                break;
            }
            otp.poll();
        }
        // check that we are idle with no errors
        assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::SET.value);
        // check that the digest is invalid
        assert_ne!(otp.digests[18], 0xb01d0fde);
        assert_ne!(otp.digests[19], 0x3fc74486);
        // reset
        otp.warm_reset();
        // check that the digest is valid
        assert_eq!(otp.digests[18], 0xb01d0fde);
        assert_eq!(otp.digests[19], 0x3fc74486);
    }
}

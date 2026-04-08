/*++

Licensed under the Apache-2.0 license.

File Name:

    otp.rs

Abstract:

    OpenTitan OTP Open Source Controller emulated device.
    Supports 32-bit and 64-bit DAI access granularity with blank-check
    enforcement matching hardware behavior.

--*/
use crate::ecc_ram::EccRam;
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
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::rc::Rc;
#[allow(unused_imports)] // Rust compiler doesn't like these
use tock_registers::interfaces::{Readable, Writeable};

/// OTP Digest constant default from caliptra-ss/src/fuse_ctrl/rtl/otp_ctrl_part_pkg.sv
const DIGEST_CONST: u128 = 0xF98C48B1F93772844A22D4B78FE0266F;
/// OTP Digest IV default from caliptra-ss/src/fuse_ctrl/rtl/otp_ctrl_part_pkg.sv
const DIGEST_IV: u64 = 0x90C7F21F6224F027;

const TOTAL_SIZE: usize = fuses::LIFE_CYCLE_BYTE_OFFSET + fuses::LIFE_CYCLE_BYTE_SIZE;

/// Used to hold the state that is saved between emulator runs.
#[derive(Deserialize, Serialize)]
struct OtpState {
    partitions: Vec<u8>,
    calculate_digests_on_reset: HashSet<usize>,
    digests: Vec<u32>,
    /// Per-partition ECC RAM instances (indexed by partition number).
    #[serde(default)]
    ecc_rams: Vec<Option<EccRam>>,
}

#[derive(Default, Clone)]
pub struct OtpArgs {
    pub file_name: Option<PathBuf>,
    pub raw_memory: Option<Vec<u8>>,
    pub owner_pk_hash: Option<[u8; 48]>,
    pub vendor_pk_hash: Option<[u8; 48]>,
    pub vendor_pqc_type: Option<FwVerificationPqcKeyType>,
    pub soc_manifest_svn: Option<u8>,
    pub soc_manifest_max_svn: Option<u8>,
    pub vendor_hashes_prod_partition: Option<Vec<u8>>,
    pub vendor_test_partition: Option<Vec<u8>>,
    /// Raw lifecycle partition data (LIFECYCLE_MEM_SIZE bytes) to provision.
    /// If set, written to the LIFE_CYCLE partition in OTP.
    pub lifecycle_state: Option<Vec<u8>>,
    /// Partition indices that should have ECC protection.
    /// Defaults to `{15}` (the lifecycle partition) when empty.
    pub ecc_partitions: HashSet<usize>,
    /// Which `err_code_rf_err_code_N` register index carries the DAI error code.
    /// Defaults to `OTP_PARTITIONS.len()` (16), matching DaiIdx in the RTL.
    pub dai_err_code_register: Option<usize>,
}

//#[derive(Bus)]
#[allow(dead_code)]
pub struct Otp {
    /// File to store the OTP partitions.
    file: Option<File>,
    direct_access_address: u32,
    direct_access_buffer: u32,
    direct_access_buffer_hi: u32,
    direct_access_cmd: ReadWriteRegister<u32, DirectAccessCmd::Register>,
    status: ReadWriteRegister<u32, OtpStatus::Register>,
    /// Per-register error codes (indexed 0–17).
    err_codes: Vec<u32>,
    /// Which `err_code_rf_err_code_N` register index carries the DAI error.
    dai_err_code_register: usize,
    timer: Timer,
    partitions: Rc<RefCell<Vec<u8>>>,
    digests: [u32; fuses::OTP_PARTITIONS.len() * 2],
    /// Partitions to calculate digests for on reset.
    calculate_digests_on_reset: HashSet<usize>,
    generated: OtpGenerated,
    /// Per-partition ECC RAM. `ecc_rams[i]` is `Some(…)` when partition `i`
    /// has ECC protection enabled.
    ecc_rams: Vec<Option<EccRam>>,
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

        let ecc_partitions = if args.ecc_partitions.is_empty() {
            // Default: lifecycle partition only.
            let mut s = HashSet::new();
            s.insert(fuses::OTP_PARTITIONS.len() - 1); // life_cycle is last
            s
        } else {
            args.ecc_partitions
        };

        let ecc_rams: Vec<Option<EccRam>> = fuses::OTP_PARTITIONS
            .iter()
            .enumerate()
            .map(|(i, p)| {
                if ecc_partitions.contains(&i) {
                    Some(EccRam::new(p.byte_size))
                } else {
                    None
                }
            })
            .collect();

        let mut otp = Self {
            file,
            direct_access_address: 0,
            direct_access_buffer: 0,
            direct_access_buffer_hi: 0,
            direct_access_cmd: 0u32.into(),
            status: 0b100_0000_0000_0000_0000_0000u32.into(), // DAI idle state
            err_codes: vec![0u32; NUM_ERR_CODE_REGISTERS],
            dai_err_code_register: args
                .dai_err_code_register
                .unwrap_or(fuses::OTP_PARTITIONS.len()),
            calculate_digests_on_reset: HashSet::new(),
            timer: Timer::new(clock),
            partitions,
            digests: [0; fuses::OTP_PARTITIONS.len() * 2],
            generated: OtpGenerated::default(),
            ecc_rams,
        };
        otp.read_from_file()?;
        if let Some(mut vendor_pk_hash) = args.vendor_pk_hash {
            swap_endianness(&mut vendor_pk_hash);
            otp.partitions.borrow_mut()[fuses::VENDOR_HASHES_MANUF_PARTITION_BYTE_OFFSET
                ..fuses::VENDOR_HASHES_MANUF_PARTITION_BYTE_OFFSET + 48]
                .copy_from_slice(&vendor_pk_hash);
        }
        // encode as a single bit
        if let Some(pqc_type) = args.vendor_pqc_type {
            let val = match pqc_type {
                FwVerificationPqcKeyType::MLDSA => 0,
                FwVerificationPqcKeyType::LMS => 1,
            };
            otp.partitions.borrow_mut()[fuses::VENDOR_HASHES_MANUF_PARTITION_BYTE_OFFSET + 48] =
                val;
        }
        {
            let mut partitions = otp.partitions.borrow_mut();
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

            // Provision lifecycle fuses if provided and current fuses are blank.
            if let Some(lc_data) = args.lifecycle_state {
                let lc_start = fuses::LIFE_CYCLE_BYTE_OFFSET;
                let lc_end = lc_start + fuses::LIFE_CYCLE_BYTE_SIZE;
                let current_lc = &partitions[lc_start..lc_end];
                if current_lc.iter().all(|&b| b == 0) {
                    let copy_len = lc_data.len().min(fuses::LIFE_CYCLE_BYTE_SIZE);
                    partitions[lc_start..lc_start + copy_len].copy_from_slice(&lc_data[..copy_len]);
                }
            }
        }

        // if there were digests that were pending a reset, then calculate them now
        otp.calculate_digests()?;
        otp.sync_ecc_from_partitions();
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

    /// Extract the raw lifecycle partition bytes from OTP partition data.
    /// Returns None if the lifecycle region is all zeros (unprovisioned).
    pub fn lifecycle_bytes_from_partitions(partitions: &[u8]) -> Option<Vec<u8>> {
        let lc_start = fuses::LIFE_CYCLE_BYTE_OFFSET;
        let lc_end = lc_start + fuses::LIFE_CYCLE_BYTE_SIZE;
        if partitions.len() < lc_end {
            return None;
        }
        let lc_data = &partitions[lc_start..lc_end];
        if lc_data.iter().all(|&b| b == 0) {
            None
        } else {
            Some(lc_data.to_vec())
        }
    }

    /// Read the lifecycle partition bytes from a saved OTP file.
    /// Returns None if file doesn't exist, is empty, or lifecycle is unprovisioned.
    pub fn read_lifecycle_from_file(path: &Path) -> Option<Vec<u8>> {
        let mut file = File::open(path).ok()?;
        let len = file.metadata().ok()?.len();
        if len == 0 {
            return None;
        }
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).ok()?;
        let state: OtpState = serde_json::from_slice(&contents).ok()?;
        Self::lifecycle_bytes_from_partitions(&state.partitions)
    }

    /// Returns `true` if a correctable ECC error has been detected on any
    /// ECC-protected partition.
    pub fn has_correctable_ecc_error(&self) -> bool {
        self.ecc_rams
            .iter()
            .any(|r| r.as_ref().is_some_and(|e| e.has_correctable_error()))
    }

    /// Returns `true` if an uncorrectable ECC error has been detected on any
    /// ECC-protected partition.
    pub fn has_uncorrectable_ecc_error(&self) -> bool {
        self.ecc_rams
            .iter()
            .any(|r| r.as_ref().is_some_and(|e| e.has_uncorrectable_error()))
    }

    /// Clear ECC error interrupt flags on all protected partitions.
    pub fn clear_ecc_errors(&mut self) {
        for ram in self.ecc_rams.iter_mut().flatten() {
            ram.clear_errors();
        }
    }

    /// Returns a mutable reference to the ECC RAM for the given partition
    /// index, if that partition has ECC protection enabled.
    pub fn partition_ecc_mut(&mut self, partition_idx: usize) -> Option<&mut EccRam> {
        self.ecc_rams.get_mut(partition_idx)?.as_mut()
    }

    /// Read the current DAI error code from the configured register.
    fn dai_err_code(&self) -> u32 {
        self.err_codes[self.dai_err_code_register]
    }

    /// Set the DAI error code in the configured register.
    fn set_dai_err_code(&mut self, code: u32) {
        self.err_codes[self.dai_err_code_register] = code;
    }

    /// Initialize all ECC RAMs from the current partition data.
    fn sync_ecc_from_partitions(&mut self) {
        let partitions = self.partitions.borrow();
        for (i, ram_opt) in self.ecc_rams.iter_mut().enumerate() {
            if let Some(ram) = ram_opt {
                let p = &fuses::OTP_PARTITIONS[i];
                let start = p.byte_offset;
                let end = start + p.byte_size;
                ram.init_from_bytes(&partitions[start..end]);
            }
        }
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
        let p = match fuses::OTP_PARTITIONS.get(partition) {
            Some(p) => p,
            None => return,
        };
        // Skip lifecycle partition — it has no software/hardware digest
        if !p.sw_digest && !p.hw_digest {
            return;
        }
        let addr = p.byte_offset;
        let size = p.byte_size;
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
            ecc_rams: self.ecc_rams.clone(),
        }
    }

    fn load_state(&mut self, state: &OtpState) {
        *self.partitions.borrow_mut() = state.partitions.clone();
        self.calculate_digests_on_reset = state.calculate_digests_on_reset.clone();
        self.digests.copy_from_slice(&state.digests);
        // Restore ECC RAMs for partitions that are both saved and enabled.
        for (i, saved) in state.ecc_rams.iter().enumerate() {
            if let (Some(Some(dst)), Some(src)) = (self.ecc_rams.get_mut(i), saved) {
                *dst = src.clone();
            }
        }
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

/// OTP error codes matching the hardware definition.
const OTP_ERR_MACRO_WRITE_BLANK: u32 = 4;

/// Number of OTP err_code registers (one per partition + DAI + LCI agents).
const NUM_ERR_CODE_REGISTERS: usize = 18;

/// Returns true if `byte_addr` falls within a 64-bit access granule region
/// (digest field or secret partition data). Non-secret partition data uses
/// 32-bit granularity.
fn is_64bit_granule(byte_addr: usize) -> bool {
    for p in fuses::OTP_PARTITIONS {
        if byte_addr < p.byte_offset || byte_addr >= p.byte_offset + p.byte_size {
            continue;
        }
        // Digest fields always use 64-bit granule
        if let Some(digest_off) = p.digest_offset {
            if byte_addr >= digest_off && byte_addr < digest_off + 8 {
                return true;
            }
        }
        // Secret (scrambled) partitions use 64-bit granule for all data
        if p.name.starts_with("secret_")
            || p.name == "sw_test_unlock_partition"
            || p.name == "vendor_secret_prod_partition"
        {
            return true;
        }
        return false;
    }
    false
}

/// Returns the PRESENT scrambling key for a secret partition, or None if
/// the address is in a non-secret partition.
fn scramble_key_for_addr(byte_addr: usize) -> Option<u128> {
    for (i, p) in fuses::OTP_PARTITIONS.iter().enumerate() {
        if byte_addr < p.byte_offset || byte_addr >= p.byte_offset + p.byte_size {
            continue;
        }
        return match i {
            1 => Some(otp_digest::OTP_SCRAMBLE_KEYS[0]),
            2 => Some(otp_digest::OTP_SCRAMBLE_KEYS[1]),
            3 => Some(otp_digest::OTP_SCRAMBLE_KEYS[2]),
            4 => Some(otp_digest::OTP_SCRAMBLE_KEYS[3]),
            5 => Some(otp_digest::OTP_SCRAMBLE_KEYS[4]),
            7 => Some(otp_digest::OTP_SCRAMBLE_KEYS[6]),
            13 => Some(otp_digest::OTP_SCRAMBLE_KEYS[5]),
            _ => None,
        };
    }
    None
}

/// If `byte_addr` falls within a partition that has an ECC RAM, return the
/// partition index and its byte offset.
fn ecc_partition_for_addr(byte_addr: usize, ecc_rams: &[Option<EccRam>]) -> Option<(usize, usize)> {
    for (i, p) in fuses::OTP_PARTITIONS.iter().enumerate() {
        if byte_addr >= p.byte_offset && byte_addr < p.byte_offset + p.byte_size {
            if ecc_rams.get(i).is_some_and(|r| r.is_some()) {
                return Some((i, p.byte_offset));
            }
            return None;
        }
    }
    None
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

    fn read_dai_rdata_rf_direct_access_rdata_1(&mut self) -> RvData {
        self.direct_access_buffer_hi
    }

    fn read_err_code_rf_err_code_0(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.err_codes[0])
    }
    fn read_err_code_rf_err_code_1(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.err_codes[1])
    }
    fn read_err_code_rf_err_code_2(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.err_codes[2])
    }
    fn read_err_code_rf_err_code_3(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.err_codes[3])
    }
    fn read_err_code_rf_err_code_4(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.err_codes[4])
    }
    fn read_err_code_rf_err_code_5(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.err_codes[5])
    }
    fn read_err_code_rf_err_code_6(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.err_codes[6])
    }
    fn read_err_code_rf_err_code_7(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.err_codes[7])
    }
    fn read_err_code_rf_err_code_8(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.err_codes[8])
    }
    fn read_err_code_rf_err_code_9(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.err_codes[9])
    }
    fn read_err_code_rf_err_code_10(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.err_codes[10])
    }
    fn read_err_code_rf_err_code_11(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.err_codes[11])
    }
    fn read_err_code_rf_err_code_12(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.err_codes[12])
    }
    fn read_err_code_rf_err_code_13(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.err_codes[13])
    }
    fn read_err_code_rf_err_code_14(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.err_codes[14])
    }
    fn read_err_code_rf_err_code_15(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.err_codes[15])
    }
    fn read_err_code_rf_err_code_16(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.err_codes[16])
    }
    fn read_err_code_rf_err_code_17(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.err_codes[17])
    }

    fn read_dai_wdata_rf_direct_access_wdata_0(&mut self) -> RvData {
        self.direct_access_buffer
    }

    fn write_dai_wdata_rf_direct_access_wdata_0(&mut self, val: RvData) {
        self.direct_access_buffer = val;
    }

    fn write_dai_wdata_rf_direct_access_wdata_1(&mut self, val: RvData) {
        self.direct_access_buffer_hi = val;
    }

    /// Called by Bus::poll() to indicate that time has passed
    fn poll(&mut self) {
        if self.direct_access_cmd.reg.read(DirectAccessCmd::Wr) == 1 {
            // Clear any previous DAI error before processing a new command.
            self.set_dai_err_code(0);
            let use_64 = is_64bit_granule(self.direct_access_address as usize);
            // Align address to the access granule (mask low 2 or 3 bits)
            let addr = if use_64 {
                (self.direct_access_address & 0xffff_fff8) as usize
            } else {
                (self.direct_access_address & 0xffff_fffc) as usize
            };

            let mut blank_error = false;
            if addr + 4 <= TOTAL_SIZE {
                let write_len = if use_64 { 8 } else { 4 };
                if let Some((part_idx, part_off)) = ecc_partition_for_addr(addr, &self.ecc_rams) {
                    // ECC RAM handles blank-check on all 22 bits (data + parity).
                    let ecc_off = addr - part_off;
                    let ram = self.ecc_rams[part_idx].as_mut().unwrap();
                    let mut buf = [0u8; 8];
                    buf[..4].copy_from_slice(&self.direct_access_buffer.to_le_bytes());
                    if use_64 {
                        buf[4..8].copy_from_slice(&self.direct_access_buffer_hi.to_le_bytes());
                    }
                    if ram.otp_write_bytes(ecc_off, &buf[..write_len]) {
                        // Commit succeeded — sync data back to partitions Vec.
                        let mut partitions = self.partitions.borrow_mut();
                        let mut readback = [0u8; 8];
                        ram.read_bytes(ecc_off, &mut readback[..write_len]);
                        partitions[addr..addr + write_len].copy_from_slice(&readback[..write_len]);
                    } else {
                        blank_error = true;
                    }
                } else {
                    let mut partitions = self.partitions.borrow_mut();
                    let current_lo = u32::from_le_bytes([
                        partitions[addr],
                        partitions[addr + 1],
                        partitions[addr + 2],
                        partitions[addr + 3],
                    ]);

                    // Blank check: writing must not attempt to clear already-set bits
                    if (current_lo & self.direct_access_buffer) != current_lo {
                        blank_error = true;
                    }

                    if use_64 && addr + 8 <= TOTAL_SIZE {
                        let current_hi = u32::from_le_bytes([
                            partitions[addr + 4],
                            partitions[addr + 5],
                            partitions[addr + 6],
                            partitions[addr + 7],
                        ]);
                        if (current_hi & self.direct_access_buffer_hi) != current_hi {
                            blank_error = true;
                        }

                        if !blank_error {
                            let mut new_lo = current_lo | self.direct_access_buffer;
                            let mut new_hi = current_hi | self.direct_access_buffer_hi;
                            if let Some(key) = scramble_key_for_addr(addr) {
                                let plaintext = ((new_hi as u64) << 32) | new_lo as u64;
                                let scrambled = otp_digest::otp_scramble(plaintext, key);
                                new_lo = scrambled as u32;
                                new_hi = (scrambled >> 32) as u32;
                            }
                            partitions[addr..addr + 4].copy_from_slice(&new_lo.to_le_bytes());
                            partitions[addr + 4..addr + 8].copy_from_slice(&new_hi.to_le_bytes());
                        }
                    } else if !blank_error {
                        let new_lo = current_lo | self.direct_access_buffer;
                        partitions[addr..addr + 4].copy_from_slice(&new_lo.to_le_bytes());
                    }
                }
            }

            if blank_error {
                self.set_dai_err_code(OTP_ERR_MACRO_WRITE_BLANK);
                self.status
                    .reg
                    .set(OtpStatus::DaiIdle::SET.value | OtpStatus::DaiError::SET.value);
            }

            // reset direct access
            self.direct_access_cmd.reg.set(0);
            self.direct_access_address = 0;
            self.direct_access_buffer = 0;
            self.direct_access_buffer_hi = 0;
        } else if self.direct_access_cmd.reg.read(DirectAccessCmd::Rd) == 1 {
            // Clear any previous DAI error before processing a new command.
            self.set_dai_err_code(0);
            self.direct_access_cmd.reg.set(0);
            // clear bottom two bits
            let addr = (self.direct_access_address & 0xffff_fffc) as usize;
            if addr + 4 <= TOTAL_SIZE {
                if let Some((part_idx, part_off)) = ecc_partition_for_addr(addr, &self.ecc_rams) {
                    // Read through ECC RAM.
                    let ecc_off = addr - part_off;
                    let ram = self.ecc_rams[part_idx].as_mut().unwrap();
                    let mut buf = [0u8; 4];
                    ram.read_bytes(ecc_off, &mut buf);
                    self.direct_access_buffer = u32::from_le_bytes(buf);
                    let p = &fuses::OTP_PARTITIONS[part_idx];
                    if addr + 8 <= p.byte_offset + p.byte_size {
                        let mut buf_hi = [0u8; 4];
                        ram.read_bytes(ecc_off + 4, &mut buf_hi);
                        self.direct_access_buffer_hi = u32::from_le_bytes(buf_hi);
                    } else {
                        self.direct_access_buffer_hi = 0;
                    }
                } else {
                    let mut buf = [0; 4];
                    let partitions = self.partitions.borrow();
                    buf.copy_from_slice(&partitions[addr..addr + 4]);
                    self.direct_access_buffer = u32::from_le_bytes(buf);
                    // Also read the high word for 64-bit granule reads
                    if addr + 8 <= TOTAL_SIZE {
                        buf.copy_from_slice(&partitions[addr + 4..addr + 8]);
                        self.direct_access_buffer_hi = u32::from_le_bytes(buf);
                    } else {
                        self.direct_access_buffer_hi = 0;
                    }
                    if let Some(key) = scramble_key_for_addr(addr) {
                        let scrambled = ((self.direct_access_buffer_hi as u64) << 32)
                            | self.direct_access_buffer as u64;
                        let plaintext = otp_digest::otp_unscramble(scrambled, key);
                        self.direct_access_buffer = plaintext as u32;
                        self.direct_access_buffer_hi = (plaintext >> 32) as u32;
                    }
                }
            }
            // reset direct access
            self.direct_access_cmd.reg.set(0);
            self.direct_access_address = 0;
        } else if self.direct_access_cmd.reg.read(DirectAccessCmd::Digest) == 1 {
            // Clear any previous DAI error before processing a new command.
            self.set_dai_err_code(0);
            // clear bottom two bits
            let addr = (self.direct_access_address & 0xffff_fffc) as usize;
            if let Some(partition) = fuses::OTP_PARTITIONS
                .iter()
                .position(|p| addr == p.byte_offset)
            {
                let p = &fuses::OTP_PARTITIONS[partition];
                // Only schedule digest calculation for partitions that have a digest
                if p.sw_digest || p.hw_digest {
                    self.calculate_digests_on_reset.insert(partition);
                }
            }
        }

        // Set idle status so that users know operations have completed.
        // Only set plain idle if no error was flagged earlier in this poll.
        if self.dai_err_code() == 0 {
            self.status.reg.set(OtpStatus::DaiIdle::SET.value);
        }
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
                vendor_pqc_type: Some(FwVerificationPqcKeyType::MLDSA),
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
                vendor_pqc_type: Some(FwVerificationPqcKeyType::MLDSA),
                ..Default::default()
            },
        )
        .unwrap();

        // Only write the data portion (32-bit granule). The last 8 bytes are
        // the digest field which uses 64-bit granule and different addressing.
        let data_words = (fuses::VENDOR_TEST_PARTITION_BYTE_SIZE - 8) / 4;

        // write the vendor partition data area
        assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::SET.value);
        for i in 0..data_words {
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

        // read the vendor partition data area
        assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::SET.value);
        for i in 0..data_words {
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
                vendor_pqc_type: Some(FwVerificationPqcKeyType::MLDSA),
                ..Default::default()
            },
        )
        .unwrap();

        // Only write the data portion (exclude the 8-byte digest field)
        let data_words = (fuses::VENDOR_TEST_PARTITION_BYTE_SIZE - 8) / 4;
        assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::SET.value);
        for i in 0..data_words {
            otp.write_dai_wdata_rf_direct_access_wdata_0(i as u32);
            otp.write_direct_access_address(
                ((fuses::VENDOR_TEST_PARTITION_BYTE_OFFSET + i * 4) as u32).into(),
            );
            otp.write_direct_access_cmd(2u32.into());
            assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::CLEAR.value);
            for _ in 0..1000 {
                if otp.status.reg.read(OtpStatus::DaiIdle) != 0 {
                    break;
                }
                otp.poll();
            }
            assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::SET.value);
        }

        // trigger a digest
        otp.write_direct_access_address((fuses::VENDOR_TEST_PARTITION_BYTE_OFFSET as u32).into());
        otp.write_direct_access_cmd(4u32.into());
        assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::CLEAR.value);
        for _ in 0..1000 {
            if otp.status.reg.read(OtpStatus::DaiIdle) != 0 {
                break;
            }
            otp.poll();
        }
        assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::SET.value);
        // Digest should not be updated until warm_reset
        let old_lo = otp.digests[18];
        let old_hi = otp.digests[19];
        otp.warm_reset();
        // After reset the digest should be computed and non-zero
        assert_ne!(otp.digests[18], 0, "digest lo should be non-zero");
        assert_ne!(otp.digests[19], 0, "digest hi should be non-zero");
        assert!(
            otp.digests[18] != old_lo || otp.digests[19] != old_hi,
            "digest should change after reset"
        );
    }

    /// Write-then-rewrite: writing the same value should succeed (no blank error),
    /// but writing a value that would clear bits should fail with MacroWriteBlankError.
    #[test]
    fn test_blank_check() {
        let clock = Clock::new();
        let mut otp = Otp::new(
            &clock,
            OtpArgs {
                vendor_pqc_type: Some(FwVerificationPqcKeyType::MLDSA),
                ..Default::default()
            },
        )
        .unwrap();
        let addr = fuses::VENDOR_TEST_PARTITION_BYTE_OFFSET as u32;

        // First write: 0xFF00_FF00 should succeed on blank OTP
        otp.write_dai_wdata_rf_direct_access_wdata_0(0xFF00_FF00);
        otp.write_direct_access_address(addr.into());
        otp.write_direct_access_cmd(2u32.into());
        otp.poll();
        assert_eq!(
            otp.status.reg.get(),
            OtpStatus::DaiIdle::SET.value,
            "first write should succeed"
        );
        assert_eq!(otp.dai_err_code(), 0);

        // Re-write same value: should succeed (OR produces same result)
        otp.write_dai_wdata_rf_direct_access_wdata_0(0xFF00_FF00);
        otp.write_direct_access_address(addr.into());
        otp.write_direct_access_cmd(2u32.into());
        otp.poll();
        assert_eq!(
            otp.status.reg.get(),
            OtpStatus::DaiIdle::SET.value,
            "rewrite of same value should succeed"
        );
        assert_eq!(otp.dai_err_code(), 0);

        // Write superset: should succeed (only setting more bits)
        otp.write_dai_wdata_rf_direct_access_wdata_0(0xFFFF_FFFF);
        otp.write_direct_access_address(addr.into());
        otp.write_direct_access_cmd(2u32.into());
        otp.poll();
        assert_eq!(
            otp.status.reg.get(),
            OtpStatus::DaiIdle::SET.value,
            "writing superset should succeed"
        );
        assert_eq!(otp.dai_err_code(), 0);

        // Write value that would clear bits: should fail
        otp.write_dai_wdata_rf_direct_access_wdata_0(0x0000_0001);
        otp.write_direct_access_address(addr.into());
        otp.write_direct_access_cmd(2u32.into());
        otp.poll();
        assert_ne!(
            otp.status.reg.get() & OtpStatus::DaiError::SET.value,
            0,
            "clearing bits should produce DaiError"
        );
        assert_eq!(otp.dai_err_code(), OTP_ERR_MACRO_WRITE_BLANK);
    }

    /// Helper: DAI write a 32-bit value at the given byte address.
    fn dai_write(otp: &mut Otp, addr: u32, val: u32) {
        otp.write_dai_wdata_rf_direct_access_wdata_0(val);
        otp.write_direct_access_address(addr.into());
        otp.write_direct_access_cmd(2u32.into());
        for _ in 0..100 {
            otp.poll();
            if otp.status.reg.read(OtpStatus::DaiIdle) != 0 {
                break;
            }
        }
    }

    /// Helper: DAI read a 32-bit value from the given byte address.
    fn dai_read(otp: &mut Otp, addr: u32) -> u32 {
        otp.write_direct_access_address(addr.into());
        otp.write_direct_access_cmd(1u32.into());
        for _ in 0..100 {
            otp.poll();
            if otp.status.reg.read(OtpStatus::DaiIdle) != 0 {
                break;
            }
        }
        otp.read_dai_rdata_rf_direct_access_rdata_0()
    }

    #[test]
    fn test_lifecycle_ecc_write_read() {
        let clock = Clock::new();
        let mut otp = Otp::new(
            &clock,
            OtpArgs {
                vendor_pqc_type: Some(FwVerificationPqcKeyType::MLDSA),
                ..Default::default()
            },
        )
        .unwrap();

        let addr = fuses::LIFE_CYCLE_BYTE_OFFSET as u32;
        dai_write(&mut otp, addr, 0xDEAD_BEEF);
        let readback = dai_read(&mut otp, addr);
        assert_eq!(readback, 0xDEAD_BEEF);
        assert!(!otp.has_correctable_ecc_error());
        assert!(!otp.has_uncorrectable_ecc_error());
    }

    #[test]
    fn test_lifecycle_ecc_correctable_error() {
        let clock = Clock::new();
        let mut otp = Otp::new(
            &clock,
            OtpArgs {
                vendor_pqc_type: Some(FwVerificationPqcKeyType::MLDSA),
                ..Default::default()
            },
        )
        .unwrap();

        let addr = fuses::LIFE_CYCLE_BYTE_OFFSET as u32;
        dai_write(&mut otp, addr, 0xCAFE_BABE);

        // Inject a single-bit error in the ECC RAM.
        otp.partition_ecc_mut(15).unwrap().flip_bit(0, 7);

        let readback = dai_read(&mut otp, addr);
        assert_eq!(
            readback, 0xCAFE_BABE,
            "single-bit error should be corrected"
        );
        assert!(otp.has_correctable_ecc_error());
        assert!(!otp.has_uncorrectable_ecc_error());

        otp.clear_ecc_errors();
        assert!(!otp.has_correctable_ecc_error());
    }

    #[test]
    fn test_lifecycle_ecc_uncorrectable_error() {
        let clock = Clock::new();
        let mut otp = Otp::new(
            &clock,
            OtpArgs {
                vendor_pqc_type: Some(FwVerificationPqcKeyType::MLDSA),
                ..Default::default()
            },
        )
        .unwrap();

        let addr = fuses::LIFE_CYCLE_BYTE_OFFSET as u32;
        dai_write(&mut otp, addr, 0x1234_5678);

        // Inject a double-bit error in the ECC RAM.
        otp.partition_ecc_mut(15).unwrap().flip_bit(0, 0);
        otp.partition_ecc_mut(15).unwrap().flip_bit(0, 1);

        let _readback = dai_read(&mut otp, addr);
        assert!(otp.has_uncorrectable_ecc_error());
    }

    #[test]
    fn test_lifecycle_ecc_or_only_write() {
        let clock = Clock::new();
        let mut otp = Otp::new(
            &clock,
            OtpArgs {
                vendor_pqc_type: Some(FwVerificationPqcKeyType::MLDSA),
                ..Default::default()
            },
        )
        .unwrap();

        let addr = fuses::LIFE_CYCLE_BYTE_OFFSET as u32;

        // First write to blank OTP should succeed.
        dai_write(&mut otp, addr, 0xFF00_FF00);
        assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::SET.value);
        assert_eq!(otp.dai_err_code(), 0);

        // Re-writing the same value should succeed (OR is a no-op).
        dai_write(&mut otp, addr, 0xFF00_FF00);
        assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::SET.value);
        assert_eq!(otp.dai_err_code(), 0);

        // Verify the data reads back correctly.
        assert_eq!(dai_read(&mut otp, addr), 0xFF00_FF00);

        // Writing a value that clears data bits should fail with blank error.
        dai_write(&mut otp, addr, 0x0000_0001);
        assert_ne!(
            otp.status.reg.get() & OtpStatus::DaiError::SET.value,
            0,
            "clearing lifecycle bits should produce DaiError"
        );
        assert_eq!(otp.dai_err_code(), OTP_ERR_MACRO_WRITE_BLANK);
    }

    /// Verify that a write which is a data-bit superset but causes an ECC
    /// parity conflict is rejected with a blank error.
    #[test]
    fn test_lifecycle_ecc_parity_blank_check() {
        use crate::ecc_ram::ecc_encode;

        let clock = Clock::new();
        let mut otp = Otp::new(
            &clock,
            OtpArgs {
                vendor_pqc_type: Some(FwVerificationPqcKeyType::MLDSA),
                ..Default::default()
            },
        )
        .unwrap();

        let addr = fuses::LIFE_CYCLE_BYTE_OFFSET as u32;

        // Find a pair (old, new) where new's data bits are a superset of
        // old's, but the 22-bit ECC word is NOT a superset (parity conflict).
        let old_val: u16 = 0x0001;
        let new_val: u16 = 0x0003;
        let old_ecc = ecc_encode(old_val);
        let new_ecc = ecc_encode(new_val);
        // Precondition: data bits are a superset.
        assert_eq!(old_val & new_val, old_val);
        // Precondition: parity bits are NOT a superset.
        assert_ne!(
            old_ecc & new_ecc,
            old_ecc,
            "test pair should have a parity conflict"
        );

        // Write old value.
        dai_write(&mut otp, addr, old_val as u32);
        assert_eq!(otp.dai_err_code(), 0);

        // Attempt to write new value — should fail due to parity conflict.
        dai_write(&mut otp, addr, new_val as u32);
        assert_ne!(
            otp.status.reg.get() & OtpStatus::DaiError::SET.value,
            0,
            "parity conflict should produce DaiError"
        );
        assert_eq!(otp.dai_err_code(), OTP_ERR_MACRO_WRITE_BLANK);

        // Original value should be preserved.
        assert_eq!(dai_read(&mut otp, addr), old_val as u32);
    }

    #[test]
    fn test_secret_partition_scrambling() {
        let clock = Clock::new();
        let mut otp = Otp::new(&clock, OtpArgs::default()).unwrap();

        // Write a known 64-bit value to the secret_manuf_partition via DAI
        let addr = fuses::SECRET_MANUF_PARTITION_BYTE_OFFSET;
        let plaintext_lo: u32 = 0xDEADBEEF;
        let plaintext_hi: u32 = 0xCAFEBABE;

        // DAI 64-bit write
        otp.write_dai_wdata_rf_direct_access_wdata_0(plaintext_lo);
        otp.write_dai_wdata_rf_direct_access_wdata_1(plaintext_hi);
        otp.write_direct_access_address((addr as u32).into());
        otp.write_direct_access_cmd(2u32.into()); // write command
        for _ in 0..1000 {
            if otp.status.reg.read(OtpStatus::DaiIdle) != 0 {
                break;
            }
            otp.poll();
        }
        assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::SET.value);

        // Read raw memory (bypassing DAI) to verify scrambled storage
        let (raw_lo, raw_hi) = {
            let raw = otp.partitions.borrow();
            let lo = u32::from_le_bytes(raw[addr..addr + 4].try_into().unwrap());
            let hi = u32::from_le_bytes(raw[addr + 4..addr + 8].try_into().unwrap());
            (lo, hi)
        };

        // The raw data should NOT equal the plaintext (it should be scrambled)
        let plaintext_u64 = ((plaintext_hi as u64) << 32) | plaintext_lo as u64;
        let raw_u64 = ((raw_hi as u64) << 32) | raw_lo as u64;
        assert_ne!(
            raw_u64, plaintext_u64,
            "Raw OTP data should be scrambled, not plaintext"
        );

        // Verify that otp_scramble produces the same result
        let expected_scrambled =
            otp_digest::otp_scramble(plaintext_u64, otp_digest::OTP_SCRAMBLE_KEYS[0]);
        assert_eq!(
            raw_u64, expected_scrambled,
            "Raw OTP data should match otp_scramble output"
        );

        // Read back through DAI and verify we get plaintext
        otp.write_direct_access_address((addr as u32).into());
        otp.write_direct_access_cmd(1u32.into()); // read command
        for _ in 0..1000 {
            if otp.status.reg.read(OtpStatus::DaiIdle) != 0 {
                break;
            }
            otp.poll();
        }
        assert_eq!(otp.status.reg.get(), OtpStatus::DaiIdle::SET.value);

        let read_lo = otp.read_dai_rdata_rf_direct_access_rdata_0();
        let read_hi = otp.read_dai_rdata_rf_direct_access_rdata_1();
        assert_eq!(read_lo, plaintext_lo, "DAI read lo should return plaintext");
        assert_eq!(read_hi, plaintext_hi, "DAI read hi should return plaintext");
    }
}

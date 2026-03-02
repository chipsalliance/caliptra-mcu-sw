// Licensed under the Apache-2.0 license

#![no_std]

use core::mem::offset_of;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub use mcu_config::boot::{PartitionId, PartitionStatus, RollbackEnable};

/// On-flash partition table layout (two redundant copies expected).
#[repr(C, packed)]
#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq, Default)]
pub struct PartitionTable {
    pub active_partition: u32,
    pub partition_a_boot_count: u16,
    pub partition_a_status: u16,
    pub partition_b_boot_count: u16,
    pub partition_b_status: u16,
    pub rollback_enable: u32,
    pub generation: u32,
    pub reserved: u32,
    pub checksum: u32,
}

/// Trait for computing / verifying the partition-table checksum.
///
/// The default implementation uses a simple additive checksum over the
/// u32 words preceding the `checksum` field.
pub trait ChecksumCalculator {
    fn calculate(&self, data: &[u8]) -> u32 {
        let words = data.len() / 4;
        let mut sum: u32 = 0;
        for i in 0..words {
            let offset = i * 4;
            let word = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            sum = sum.wrapping_add(word);
        }
        sum
    }
}

/// A stand-alone (no-dependency) checksum calculator that uses the default
/// additive implementation.
#[derive(Default)]
pub struct StandAloneChecksumCalculator;

impl StandAloneChecksumCalculator {
    pub fn new() -> Self {
        Self
    }
}

impl ChecksumCalculator for StandAloneChecksumCalculator {}

impl PartitionTable {
    /// Create a new `PartitionTable` with the given parameters.
    ///
    /// The checksum is **not** populated by this constructor — call
    /// [`populate_checksum`](Self::populate_checksum) afterwards.
    pub fn new(
        active_partition: PartitionId,
        partition_a_boot_count: u16,
        partition_a_status: PartitionStatus,
        partition_b_boot_count: u16,
        partition_b_status: PartitionStatus,
        rollback_enable: RollbackEnable,
    ) -> Self {
        Self {
            active_partition: active_partition as u32,
            partition_a_boot_count,
            partition_a_status: partition_a_status as u16,
            partition_b_boot_count,
            partition_b_status: partition_b_status as u16,
            rollback_enable: rollback_enable as u32,
            generation: 0,
            reserved: 0,
            checksum: 0,
        }
    }

    /// Return the active partition identifier.
    pub fn get_active_partition_id(&self) -> PartitionId {
        let val = self.active_partition;
        PartitionId::try_from(val).unwrap_or(PartitionId::None)
    }

    /// Set the active partition.
    pub fn set_active_partition(&mut self, partition: PartitionId) {
        self.active_partition = partition as u32;
    }

    /// Retrieve the status of the given partition.
    pub fn get_partition_status(&self, partition: PartitionId) -> PartitionStatus {
        let raw = match partition {
            PartitionId::A => self.partition_a_status,
            PartitionId::B => self.partition_b_status,
            _ => return PartitionStatus::Invalid,
        };
        PartitionStatus::try_from(raw).unwrap_or(PartitionStatus::Invalid)
    }

    /// Set the status of the given partition.
    pub fn set_partition_status(&mut self, partition: PartitionId, status: PartitionStatus) {
        match partition {
            PartitionId::A => self.partition_a_status = status as u16,
            PartitionId::B => self.partition_b_status = status as u16,
            _ => {}
        }
    }

    /// Returns `true` when rollback is enabled.
    pub fn is_rollback_enabled(&self) -> bool {
        self.rollback_enable == RollbackEnable::Enabled as u32
    }

    /// Compute and store the checksum using the supplied calculator.
    pub fn populate_checksum<C: ChecksumCalculator>(&mut self, calculator: &C) {
        self.checksum = 0;
        let bytes = self.as_bytes();
        let payload = &bytes[..offset_of!(PartitionTable, checksum)];
        self.checksum = calculator.calculate(payload);
    }

    /// Verify the stored checksum using the supplied calculator.
    pub fn verify_checksum<C: ChecksumCalculator>(&self, calculator: &C) -> bool {
        let bytes = self.as_bytes();
        let payload = &bytes[..offset_of!(PartitionTable, checksum)];
        let expected = calculator.calculate(payload);
        self.checksum == expected
    }
}

/// Parse a byte slice into a `PartitionTable`, returning `None` if the
/// slice is too small or the checksum does not verify.
pub fn parse_partition_table(data: &[u8]) -> Option<PartitionTable> {
    let pt = PartitionTable::read_from_bytes(data).ok()?;
    let calc = StandAloneChecksumCalculator;
    if pt.verify_checksum(&calc) {
        Some(pt)
    } else {
        None
    }
}

/// Given two (possibly invalid) copies of the partition table, select the
/// best one.  Higher generation wins; on a tie, `copy_0` is preferred.
pub fn select_partition_table(
    copy_0: Option<PartitionTable>,
    copy_1: Option<PartitionTable>,
) -> Option<PartitionTable> {
    match (copy_0, copy_1) {
        (Some(c0), Some(c1)) => {
            let g0 = c0.generation;
            let g1 = c1.generation;
            if g1 > g0 {
                Some(c1)
            } else {
                Some(c0)
            }
        }
        (Some(c0), None) => Some(c0),
        (None, Some(c1)) => Some(c1),
        (None, None) => None,
    }
}

/// Prepare a dual-write of the partition table.
///
/// * Bumps the generation (wrapping at `u32::MAX`).
/// * Recomputes the checksum.
/// * Returns `(first_write_offset, second_write_offset)` so that the
///   *older* copy is written first (minimising the window where both
///   copies are stale).
///
/// If both copies have the same generation (or are both invalid), copy 0
/// is written first.
pub fn prepare_dual_write(
    pt: &mut PartitionTable,
    gen_0: Option<u32>,
    gen_1: Option<u32>,
    offset_0: u32,
    offset_1: u32,
) -> (u32, u32) {
    // Determine next generation: max of the two valid generations + 1, wrapping.
    let max_gen = match (gen_0, gen_1) {
        (Some(g0), Some(g1)) => {
            if g0 >= g1 {
                g0
            } else {
                g1
            }
        }
        (Some(g), None) | (None, Some(g)) => g,
        (None, None) => 0,
    };
    pt.generation = max_gen.wrapping_add(1);

    let calc = StandAloneChecksumCalculator;
    pt.populate_checksum(&calc);

    // Write the older copy first.
    match (gen_0, gen_1) {
        (Some(g0), Some(g1)) => {
            if g1 > g0 {
                // copy_0 is older
                (offset_0, offset_1)
            } else if g0 > g1 {
                // copy_1 is older
                (offset_1, offset_0)
            } else {
                // tie — copy_0 first
                (offset_0, offset_1)
            }
        }
        (None, Some(_)) => {
            // copy_0 is invalid → write it first
            (offset_0, offset_1)
        }
        (Some(_), None) => {
            // copy_1 is invalid → write it first
            (offset_1, offset_0)
        }
        (None, None) => {
            // both invalid → copy_0 first
            (offset_0, offset_1)
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use zerocopy::IntoBytes;

    fn make_valid_pt() -> PartitionTable {
        let mut pt = PartitionTable::new(
            PartitionId::A,
            0,
            PartitionStatus::Valid,
            0,
            PartitionStatus::Invalid,
            RollbackEnable::Disabled,
        );
        let calc = StandAloneChecksumCalculator;
        pt.populate_checksum(&calc);
        pt
    }

    #[test]
    fn test_new_partition_table() {
        let pt = PartitionTable::new(
            PartitionId::A,
            1,
            PartitionStatus::Valid,
            2,
            PartitionStatus::BootFailed,
            RollbackEnable::Enabled,
        );
        let active = pt.active_partition;
        assert_eq!(active, PartitionId::A as u32);
        let a_count = pt.partition_a_boot_count;
        assert_eq!(a_count, 1);
        let a_status = pt.partition_a_status;
        assert_eq!(a_status, PartitionStatus::Valid as u16);
        let b_count = pt.partition_b_boot_count;
        assert_eq!(b_count, 2);
        let b_status = pt.partition_b_status;
        assert_eq!(b_status, PartitionStatus::BootFailed as u16);
        let rb = pt.rollback_enable;
        assert_eq!(rb, RollbackEnable::Enabled as u32);
        let gen = pt.generation;
        assert_eq!(gen, 0);
    }

    #[test]
    fn test_checksum_detects_corruption() {
        let mut pt = make_valid_pt();
        let calc = StandAloneChecksumCalculator;
        assert!(pt.verify_checksum(&calc));
        pt.active_partition = PartitionId::B as u32;
        assert!(!pt.verify_checksum(&calc));
    }

    #[test]
    fn test_select_both_valid_higher_gen_wins() {
        let mut pt0 = make_valid_pt();
        pt0.generation = 5;
        let calc = StandAloneChecksumCalculator;
        pt0.populate_checksum(&calc);

        let mut pt1 = make_valid_pt();
        pt1.generation = 10;
        pt1.populate_checksum(&calc);

        let selected = select_partition_table(Some(pt0), Some(pt1.clone())).unwrap();
        assert_eq!(selected, pt1);
    }

    #[test]
    fn test_select_one_valid() {
        let pt = make_valid_pt();
        let selected = select_partition_table(None, Some(pt.clone())).unwrap();
        assert_eq!(selected, pt);

        let selected = select_partition_table(Some(pt.clone()), None).unwrap();
        assert_eq!(selected, pt);
    }

    #[test]
    fn test_select_both_invalid() {
        let result = select_partition_table(None, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_select_both_same_generation_prefers_copy_0() {
        let mut pt0 = make_valid_pt();
        pt0.generation = 7;
        let calc = StandAloneChecksumCalculator;
        pt0.populate_checksum(&calc);

        let mut pt1 = make_valid_pt();
        pt1.generation = 7;
        // Make pt1 slightly different so we can distinguish
        pt1.partition_b_boot_count = 99;
        pt1.populate_checksum(&calc);

        let selected = select_partition_table(Some(pt0.clone()), Some(pt1)).unwrap();
        assert_eq!(selected, pt0);
    }

    #[test]
    fn test_prepare_dual_write_older_first() {
        let mut pt = make_valid_pt();
        let (first, second) = prepare_dual_write(&mut pt, Some(3), Some(5), 0x1000, 0x2000);
        // copy_0 (gen 3) is older → written first
        assert_eq!(first, 0x1000);
        assert_eq!(second, 0x2000);
        let gen = pt.generation;
        assert_eq!(gen, 6);
    }

    #[test]
    fn test_prepare_dual_write_one_copy_invalid() {
        let mut pt = make_valid_pt();
        // copy_1 is invalid → write it first
        let (first, second) = prepare_dual_write(&mut pt, Some(4), None, 0x1000, 0x2000);
        assert_eq!(first, 0x2000);
        assert_eq!(second, 0x1000);
        let gen = pt.generation;
        assert_eq!(gen, 5);
    }

    #[test]
    fn test_prepare_dual_write_both_invalid() {
        let mut pt = make_valid_pt();
        let (first, second) = prepare_dual_write(&mut pt, None, None, 0x1000, 0x2000);
        assert_eq!(first, 0x1000);
        assert_eq!(second, 0x2000);
        let gen = pt.generation;
        assert_eq!(gen, 1);
    }

    #[test]
    fn test_prepare_dual_write_generation_wraps() {
        let mut pt = make_valid_pt();
        let (_, _) = prepare_dual_write(&mut pt, Some(u32::MAX), Some(u32::MAX - 1), 0x1000, 0x2000);
        let gen = pt.generation;
        assert_eq!(gen, 0); // u32::MAX wraps to 0
    }

    #[test]
    fn test_parse_valid() {
        let pt = make_valid_pt();
        let bytes = pt.as_bytes();
        let parsed = parse_partition_table(bytes).unwrap();
        assert_eq!(parsed, pt);
    }

    #[test]
    fn test_parse_corrupt() {
        let mut pt = make_valid_pt();
        let calc = StandAloneChecksumCalculator;
        pt.populate_checksum(&calc);
        let mut bytes = alloc::vec::Vec::from(pt.as_bytes());
        // Corrupt one byte
        bytes[0] ^= 0xFF;
        let result = parse_partition_table(&bytes);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_too_small() {
        let result = parse_partition_table(&[0u8; 4]);
        assert!(result.is_none());
    }

    #[test]
    fn test_partition_status_round_trip() {
        let mut pt = make_valid_pt();
        pt.set_partition_status(PartitionId::A, PartitionStatus::BootSuccessful);
        assert_eq!(
            pt.get_partition_status(PartitionId::A),
            PartitionStatus::BootSuccessful
        );
        pt.set_partition_status(PartitionId::B, PartitionStatus::BootFailed);
        assert_eq!(
            pt.get_partition_status(PartitionId::B),
            PartitionStatus::BootFailed
        );
    }

    #[test]
    fn test_rollback_enable() {
        let pt_disabled = PartitionTable::new(
            PartitionId::A,
            0,
            PartitionStatus::Valid,
            0,
            PartitionStatus::Invalid,
            RollbackEnable::Disabled,
        );
        assert!(!pt_disabled.is_rollback_enabled());

        let pt_enabled = PartitionTable::new(
            PartitionId::A,
            0,
            PartitionStatus::Valid,
            0,
            PartitionStatus::Invalid,
            RollbackEnable::Enabled,
        );
        assert!(pt_enabled.is_rollback_enabled());
    }

    #[test]
    fn test_set_active_partition_round_trip() {
        let mut pt = make_valid_pt();
        pt.set_active_partition(PartitionId::B);
        assert_eq!(pt.get_active_partition_id(), PartitionId::B);
        pt.set_active_partition(PartitionId::A);
        assert_eq!(pt.get_active_partition_id(), PartitionId::A);
    }
}

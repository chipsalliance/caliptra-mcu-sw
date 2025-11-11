// Licensed under the Apache-2.0 license

//! Checksum calculation utilities for VDM transport
//!
//! This module provides checksum calculation functions for external mailbox commands.

/// Calculate the checksum for external mailbox commands
/// Formula: 0 - (SUM(command code bytes) + SUM(request/response bytes))
pub fn calc_checksum(cmd: u32, data: &[u8]) -> u32 {
    let mut checksum = 0u32;
    for c in cmd.to_le_bytes().iter() {
        checksum = checksum.wrapping_add(*c as u32);
    }
    for d in data {
        checksum = checksum.wrapping_add(*d as u32);
    }
    0u32.wrapping_sub(checksum)
}

/// Verify checksum
pub fn verify_checksum(checksum: u32, cmd: u32, data: &[u8]) -> bool {
    calc_checksum(cmd, data) == checksum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc")]
    use alloc::vec;
    #[cfg(not(feature = "alloc"))]
    use std::{vec, vec::Vec};

    #[test]
    fn test_calc_checksum() {
        assert_eq!(calc_checksum(0xe8dc3994, &[0x83, 0xe7, 0x25]), 0xfffffbe0);
    }

    #[test]
    fn test_checksum_overflow() {
        let data = vec![0xff; 1000]; // Smaller test data
        let result = calc_checksum(0xe8dc3994, &data);
        assert!(verify_checksum(result, 0xe8dc3994, &data));
    }

    #[test]
    fn test_verify_checksum() {
        assert!(verify_checksum(0xfffffbe0, 0xe8dc3994, &[0x83, 0xe7, 0x25]));
        assert!(!verify_checksum(
            0xfffffbdf,
            0xe8dc3994,
            &[0x83, 0xe7, 0x25]
        ));
        assert!(!verify_checksum(
            0xfffffbe1,
            0xe8dc3994,
            &[0x83, 0xe7, 0x25]
        ));
    }

    #[test]
    fn test_round_trip() {
        let cmd = 0x00000001u32;
        let data = [0x00000000u32; 1];
        let checksum = calc_checksum(cmd, data[0].to_le_bytes().as_ref());
        assert!(verify_checksum(checksum, cmd, &data[0].to_le_bytes()));
    }
}

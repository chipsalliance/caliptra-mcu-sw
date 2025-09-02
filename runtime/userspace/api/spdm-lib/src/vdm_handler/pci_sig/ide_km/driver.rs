// Licensed under the Apache-2.0 license

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, Unaligned};

pub const IDE_STREAM_KEY_SIZE_DW: usize = 8;
pub const IDE_STREAM_IV_SIZE_DW: usize = 2;

#[derive(Debug, IntoBytes, FromBytes, Immutable, Unaligned, Default)]
#[repr(C, packed)]
pub struct PortConfig {
    port_index: u8,
    function_num: u8,
    bus_num: u8,
    segment: u8,
    max_port_index: u8,
    ide_cap_reg: u32,
    ide_ctrl_reg: u32,
}

/// Link IDE Register Block
#[derive(Default, Debug, Clone, Copy, IntoBytes, FromBytes, Immutable)]
#[repr(C, packed)]
pub struct LinkIdeStreamRegBlock {
    ctrl_reg: u32,
    status_reg: u32,
}

#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, Default)]
#[repr(C, packed)]
pub struct SelectiveIdeStreamRegBlock {
    capability_reg: u32,
    ctrl_reg: u32,
    status_reg: u32,
    rid_association_reg_1: u32,
    rid_association_reg_2: u32,
}

#[derive(Default, Debug, Clone, Copy, IntoBytes, FromBytes, Unaligned)]
#[repr(C, packed)]
pub struct AddrAssociationRegBlock {
    reg1: u32,
    reg2: u32,
    reg3: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdeDriverError {
    InvalidPortIndex,
    UnsupportedPortIndex,
    InvalidStreamId,
    InvalidArgument,
    GetPortConfigFail,
    KeyProgFail,
    KeySetGoFail,
    KeySetStopFail,
    NoMemory,
}

pub type IdeDriverResult<T> = Result<T, IdeDriverError>;

bitfield! {
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct KeyInfo(u8);
    impl Debug;
    pub key_set_bit, set_key_set_bit: 0;
    pub key_direction, set_key_direction: 1;
    reserved, _: 3, 2;
    pub key_sub_stream, set_key_sub_stream: 7, 4;
}

impl KeyInfo {
    /// Create a new KeyInfo with specified parameters
    pub fn new(key_set_bit: bool, key_direction: bool, key_sub_stream: u8) -> Self {
        let mut info = KeyInfo(0);
        info.set_key_set_bit(key_set_bit);
        info.set_key_direction(key_direction);
        info.set_key_sub_stream(key_sub_stream & 0xF); // Ensure only 4 bits
        info
    }

    /// Get the raw value
    pub fn raw(&self) -> u8 {
        self.0
    }
}

/// IDE Driver Trait
///
/// Provides an interface for Integrity and Data Encryption (IDE) key management operations.
/// This trait abstracts hardware-specific implementations for different platforms.
#[async_trait]
pub trait IdeDriver {
    /// Get the count of link IDE stream register blocks.
    ///
    /// # Returns
    /// The number of link IDE stream register blocks.
    fn link_ide_stream_reg_block_count(&self) -> usize;

    /// Get the count of selective IDE stream register blocks.
    ///
    /// # Returns
    /// The number of selective IDE stream register blocks.
    fn selective_ide_stream_reg_block_count(&self) -> usize;

    /// Get the count of selective address association register blocks.
    ///
    /// # Returns
    /// The number of selective address association register blocks.
    fn selective_addr_association_reg_block_count(&self) -> usize;

    /// Get the port configuration for a given port index.
    ///
    /// # Arguments
    /// * `port_index` - The index of the port to retrieve the configuration for.
    ///
    /// # Returns
    /// A result containing the `PortConfig` for the specified port index, or an error
    /// if the port index is invalid or unsupported.
    async fn port_config(&self, port_index: u8) -> IdeDriverResult<PortConfig>;

    /// Key programming for a specific port and stream.
    ///
    /// # Arguments
    /// * `stream_id` - Stream ID
    /// * `key_info` - Key information containing key set bit, direction, and sub-stream.
    /// * `port_index` - Port to which the key is to be programmed.
    /// * `key` - The key data to be programmed (8 DWORDs).
    /// * `iv` - The initialization vector (2 DWORDs).
    ///
    /// # Returns
    /// A result containing the status of the key programming operation:
    /// - `00h`: Successful
    /// - `01h`: Incorrect Length
    /// - `02h`: Unsupported Port Index value
    /// - `03h`: Unsupported value in other fields
    /// - `04h`: Unspecified Failure
    async fn key_prog(
        &self,
        stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
        key: &[u32; IDE_STREAM_KEY_SIZE_DW],
        iv: &[u32; IDE_STREAM_IV_SIZE_DW],
    ) -> IdeDriverResult<u8>;

    /// Start using the key set for a specific port and stream.
    ///
    /// # Arguments
    /// * `stream_id` - Stream ID
    /// * `key_info` - Key information containing key set bit, direction, and sub-stream.
    /// * `port_index` - Port to which the key set is to be started.
    ///
    /// # Returns
    /// A result containing the updated `KeyInfo` after starting the key set, or an
    /// error if the operation fails.
    async fn key_set_go(
        &self,
        stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
    ) -> IdeDriverResult<KeyInfo>;

    /// Stop the key set for a specific port and stream.
    ///
    /// # Arguments
    /// * `stream_id` - Stream ID
    /// * `key_info` - Key information containing key set bit, direction, and sub-stream.
    /// * `port_index` - Port to which the key set is to be stopped
    ///
    /// # Returns
    /// A result containing the updated `KeyInfo` after stopping the key set, or an error
    /// if the operation fails.
    async fn key_set_stop(
        &self,
        stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
    ) -> IdeDriverResult<KeyInfo>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Example implementations for testing - these are only compiled during tests
    struct ExampleIdeDriver;

    #[async_trait]
    impl IdeDriver for ExampleIdeDriver {
        fn link_ide_stream_reg_block_count(&self) -> usize {
            8 // Example constant
        }

        fn selective_ide_stream_reg_block_count(&self) -> usize {
            16 // Example constant
        }

        fn selective_addr_association_reg_block_count(&self) -> usize {
            2 // Example constant
        }

        async fn port_config(&self, _port_index: u8) -> IdeDriverResult<PortConfig> {
            // Test implementation - return a default config
            Ok(PortConfig::default())
        }

        async fn key_prog(
            &self,
            _stream_id: u8,
            _key_info: KeyInfo,
            _port_index: u8,
            _key: &[u32; IDE_STREAM_KEY_SIZE_DW],
            _iv: &[u32; IDE_STREAM_IV_SIZE_DW],
        ) -> IdeDriverResult<u8> {
            // Test implementation - return success
            Ok(0x00) // Successful
        }

        async fn key_set_go(
            &self,
            _stream_id: u8,
            key_info: KeyInfo,
            _port_index: u8,
        ) -> IdeDriverResult<KeyInfo> {
            // Test implementation - return the same key_info
            Ok(key_info)
        }

        async fn key_set_stop(
            &self,
            _stream_id: u8,
            key_info: KeyInfo,
            _port_index: u8,
        ) -> IdeDriverResult<KeyInfo> {
            // Test implementation - return the same key_info
            Ok(key_info)
        }
    }

    #[test]
    fn test_key_info() {
        let key_info = KeyInfo::new(true, false, 5);
        assert!(key_info.key_set_bit());
        assert!(!key_info.key_direction());
        assert_eq!(key_info.key_sub_stream(), 5);
    }

    #[test]
    fn test_key_info_raw() {
        let key_info = KeyInfo::new(true, true, 0xA);
        // bit 0 = 1 (key_set_bit), bit 1 = 1 (key_direction), bits 4-7 = 0xA (key_sub_stream)
        // Expected: 0b10100011 = 0xA3
        assert_eq!(key_info.raw(), 0xA3);
    }

    #[test]
    fn test_port_config_encode_decode() {
        use zerocopy::{FromBytes, IntoBytes};

        // Test that PortConfig supports zerocopy operations
        let config = PortConfig {
            port_index: 1,
            function_num: 2,
            bus_num: 3,
            segment: 4,
            max_port_index: 5,
            ..Default::default()
        };

        // Convert to bytes
        let bytes = config.as_bytes();
        assert!(!bytes.is_empty());

        // Convert back from bytes
        let parsed_config = PortConfig::read_from_bytes(bytes).unwrap();

        // Basic verification that the round-trip worked
        assert_eq!(parsed_config.port_index, config.port_index);
        assert_eq!(parsed_config.function_num, config.function_num);
    }
}

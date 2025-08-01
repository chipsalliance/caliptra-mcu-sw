// Licensed under the Apache-2.0 license

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, Unaligned};

pub const IDE_STREAM_KEY_SIZE_DW: usize = 4;
pub const IDE_STREAM_IV_SIZE_DW: usize = 2;

#[derive(Debug, IntoBytes, FromBytes, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct PortConfig<
    const LINK_IDE_REG_BLOCK_COUNT: usize,
    const SELECTIVE_IDE_REG_BLOCK_COUNT: usize,
> {
    port_index: u8,
    function_num: u8,
    bus_num: u8,
    segment: u8,
    max_port_index: u8,
    ide_cap_reg: u32,
    ide_ctrl_reg: u32,
    link_ide_stream_reg_block: [LinkIdeStreamRegBlock; LINK_IDE_REG_BLOCK_COUNT],
    selective_ide_stream_reg_block: [SelectiveIdeStreamRegBlock<1>; SELECTIVE_IDE_REG_BLOCK_COUNT],
}

impl<const LINK_IDE_REG_BLOCK_COUNT: usize, const SELECTIVE_IDE_REG_BLOCK_COUNT: usize> Default
    for PortConfig<LINK_IDE_REG_BLOCK_COUNT, SELECTIVE_IDE_REG_BLOCK_COUNT>
{
    fn default() -> Self {
        Self {
            port_index: 0,
            function_num: 0,
            bus_num: 0,
            segment: 0,
            max_port_index: 0,
            ide_cap_reg: 0,
            ide_ctrl_reg: 0,
            link_ide_stream_reg_block: [LinkIdeStreamRegBlock::default(); LINK_IDE_REG_BLOCK_COUNT],
            selective_ide_stream_reg_block: [SelectiveIdeStreamRegBlock::default();
                SELECTIVE_IDE_REG_BLOCK_COUNT],
        }
    }
}

/// Link IDE Register Block
#[derive(Default, Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct LinkIdeStreamRegBlock {
    ctrl_reg: u32,
    status_reg: u32,
}

#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct SelectiveIdeStreamRegBlock<const ADDR_ASSOC_COUNT: usize> {
    capability_reg: u32,
    ctrl_reg: u32,
    status_reg: u32,
    rid_association_reg_1: u32,
    rid_association_reg_2: u32,
    addr_assoc_reg_blk: [AddrAssociationRegBlock; ADDR_ASSOC_COUNT],
}

impl<const ADDR_ASSOC_COUNT: usize> Default for SelectiveIdeStreamRegBlock<ADDR_ASSOC_COUNT> {
    fn default() -> Self {
        Self {
            capability_reg: 0,
            ctrl_reg: 0,
            status_reg: 0,
            rid_association_reg_1: 0,
            rid_association_reg_2: 0,
            addr_assoc_reg_blk: [AddrAssociationRegBlock::default(); ADDR_ASSOC_COUNT],
        }
    }
}

#[derive(Default, Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, Unaligned)]
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
///
/// # Implementation Notes
///
/// When implementing this trait, you should define your `PortConfig` associated type
/// using the generic `PortConfig` struct with your implementation's constants:
///
/// ```ignore
/// type PortConfig = PortConfig<
///     { Self::LINK_IDE_REG_BLOCK_COUNT },
///     { Self::SELECTIVE_IDE_REG_BLOCK_COUNT }
/// >;
/// ```
#[async_trait]
pub trait IdeDriver {
    /// Number of Link IDE register blocks supported by this implementation
    const LINK_IDE_REG_BLOCK_COUNT: usize;

    /// Number of Selective IDE register blocks supported by this implementation  
    const SELECTIVE_IDE_REG_BLOCK_COUNT: usize;

    /// Number of Address Association register blocks per Selective IDE block
    const SELECTIVE_ADDR_ASSOCIATION_REG_BLOCK_COUNT: usize;

    /// Associated type for PortConfig with implementation-specific array sizes.
    ///
    /// This should typically be defined as:
    /// ```ignore
    /// type PortConfig = PortConfig<
    ///     { Self::LINK_IDE_REG_BLOCK_COUNT },
    ///     { Self::SELECTIVE_IDE_REG_BLOCK_COUNT }
    /// >;
    /// ```
    type PortConfig;

    /// Get the port configuration for a given port index.
    ///
    /// # Arguments
    /// * `port_index` - The index of the port to retrieve the configuration for.
    ///
    /// # Returns
    /// A result containing the `PortConfig` for the specified port index, or an error
    /// if the port index is invalid or unsupported.
    async fn port_config(&self, port_index: u8) -> IdeDriverResult<Self::PortConfig>;

    /// Key programming for a specific port and stream.
    ///
    /// # Arguments
    /// * `stream_id` - Stream ID
    /// * `key_info` - Key information containing key set bit, direction, and sub-stream.
    /// * `port_index` - Port to which the key is to be programmed.
    /// * `key` - The key data to be programmed (4 DWORDs).
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
        const LINK_IDE_REG_BLOCK_COUNT: usize = 8;
        const SELECTIVE_IDE_REG_BLOCK_COUNT: usize = 16; // Some test value
        const SELECTIVE_ADDR_ASSOCIATION_REG_BLOCK_COUNT: usize = 2;

        // Define the specific PortConfig type for this implementation
        type PortConfig =
            PortConfig<{ Self::LINK_IDE_REG_BLOCK_COUNT }, { Self::SELECTIVE_IDE_REG_BLOCK_COUNT }>;

        async fn port_config(&self, _port_index: u8) -> IdeDriverResult<Self::PortConfig> {
            // Test implementation - return a default config
            Ok(Self::PortConfig::default())
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
        assert_eq!(key_info.key_set_bit(), true);
        assert_eq!(key_info.key_direction(), false);
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
    fn test_driver_constants() {
        // Test that the implementation has the expected constants
        assert_eq!(ExampleIdeDriver::LINK_IDE_REG_BLOCK_COUNT, 8);
        assert_eq!(ExampleIdeDriver::SELECTIVE_IDE_REG_BLOCK_COUNT, 16);
    }

    #[test]
    fn test_port_config_encode_decode() {
        use zerocopy::{FromBytes, IntoBytes};

        // Test that PortConfig supports zerocopy operations
        type TestPortConfig = PortConfig<1, 1>;
        let mut config = TestPortConfig::default();
        config.port_index = 1;
        config.function_num = 2;
        config.bus_num = 3;
        config.segment = 4;
        config.max_port_index = 5;

        // Convert to bytes
        let bytes = config.as_bytes();
        assert!(!bytes.is_empty());

        // Convert back from bytes
        let parsed_config = TestPortConfig::read_from_bytes(bytes).unwrap();

        // Basic verification that the round-trip worked
        assert_eq!(parsed_config.port_index, config.port_index);
        assert_eq!(parsed_config.function_num, config.function_num);
    }
}

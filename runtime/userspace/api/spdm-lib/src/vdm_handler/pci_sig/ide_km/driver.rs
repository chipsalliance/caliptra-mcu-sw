// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::codec::{Codec, CodecError, CodecResult, CommonCodec, MessageBuf};
use alloc::boxed::Box;
use async_trait::async_trait;
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const IDE_STREAM_KEY_SIZE_DW: usize = 8;
pub const IDE_STREAM_IV_SIZE_DW: usize = 2;
pub const MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT: usize = 15;

// IDE Capability Register
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Clone, Copy)]
#[repr(C)]
    pub struct IdeCapabilityReg(u32);
    impl Debug;
    u8;
    pub link_ide_stream_supported, set_link_ide_stream_supported: 0,0;
    pub selective_ide_stream_supported, set_selective_ide_stream_supported: 1,1;
    pub flow_through_ide_stream_supported, set_flow_through_ide_stream_supported: 3,2;
    pub aggregation_supported, set_aggregation_supported: 4,4;
    pub pcrc_supported, set_pcrc_supported: 5,5;
    pub ide_km_protocol_supported, set_ide_km_protocol_supported: 6,6;
    pub selective_ide_for_config_req_supported, set_selective_ide_for_config_req_supported: 7,7;
    pub supported_algorithms, set_supported_algorithms: 12,8;
    pub num_tcs_supported_for_link_ide, set_num_tcs_supported_for_link_ide: 15,13;
    pub num_selective_ide_streams_supported, set_num_selective_ide_streams_supported: 23,16;
    reserved, _: 31,24;
}

// IDE Control Register
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Clone, Copy)]
#[repr(C)]
    pub struct IdeControlReg(u32);
    impl Debug;
    u8;
    reserved1, _: 1,0;
    pub flow_through_ide_stream_enabled, set_flow_through_ide_stream_enabled: 2,2;
    reserved2, _: 31,3;
}

// Link IDE Register Block

// Link IDE Stream Control Register
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Clone, Copy)]
#[repr(C)]
    pub struct LinkIdeStreamControlReg(u32);
    impl Debug;
    u8;
    pub link_ide_stream_enable, set_link_ide_stream_enable: 0,0;
    reserved1, _: 1,1;
    pub tx_aggregation_mode_npr, set_tx_aggregation_mode_npr: 3,2;
    pub tx_aggregation_mode_pr, set_tx_aggregation_mode_pr: 5,4;
    pub tx_aggregation_mode_cpl, set_tx_aggregation_mode_cpl: 7,6;
    pub pcrc_enable, set_pcrc_enable: 8,8;
    reserved2, _: 13,9;
    pub selected_algorithm, set_selected_algorithm: 18,14;
    pub tc, set_tc: 21,19;
    reserved3, _: 23,22;
    pub stream_id, set_stream_id: 31,24;
}

// Link IDE Stream Status Register
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Clone, Copy)]
#[repr(C)]
    pub struct LinkIdeStreamStatusReg(u32);
    impl Debug;
    u8;
    pub link_ide_stream_state, set_link_ide_stream_state: 3,0;
    reserved, _: 31,4;
}

// Selective IDE Stream Register Block

// Selective IDE Stream Capability Register
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Clone, Copy)]
#[repr(C)]
    pub struct SelectiveIdeStreamCapabilityReg(u32);
    impl Debug;
    u8;
    pub num_addr_association_reg_blocks, set_num_addr_association_reg_blocks: 3,0;
    reserved, _: 31,4;
}
impl CommonCodec for SelectiveIdeStreamCapabilityReg {}

// Selective IDE Stream Control Register
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Clone, Copy)]
#[repr(C)]
    pub struct SelectiveIdeStreamControlReg(u32);
    impl Debug;
    u8;
    pub selective_ide_stream_enable, set_selective_ide_stream_enable: 0,0;
    reserved1, _: 1,1;
    pub tx_aggregation_mode_npr, set_tx_aggregation_mode_npr: 3,2;
    pub tx_aggregation_mode_pr, set_tx_aggregation_mode_pr: 5,4;
    pub tx_aggregation_mode_cpl, set_tx_aggregation_mode_cpl: 7,6;
    pub pcrc_enable, set_pcrc_enable: 8,8;
    pub selective_ide_for_config_req_enable, set_selective_ide_for_config_req_enable: 9,9;
    reserved2, _: 13,10;
    pub selected_algorithm, set_selected_algorithm: 18,14;
    pub tc, set_tc: 21,19;
    pub default_stream, set_default_stream: 22,22;
    reserved3, _: 23,23;
    pub stream_id, set_stream_id: 31,24;
}

impl CommonCodec for SelectiveIdeStreamControlReg {}

// Selective IDE Stream Status Register
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Clone, Copy)]
#[repr(C)]
    pub struct SelectiveIdeStreamStatusReg(u32);
    impl Debug;
    u8;
    pub selective_ide_stream_state, set_selective_ide_stream_state: 3,0;
    pub received_integrity_check_fail_msg, set_received_integrity_check_fail_msg: 31,4;
}

impl CommonCodec for SelectiveIdeStreamStatusReg {}

// Selective IDE RID Association Register Block

// Selective IDE RID Association Register 1
bitfield! {
#[derive(Default, FromBytes, IntoBytes, Immutable, Clone, Copy)]
#[repr(C)]
    pub struct SelectiveIdeRidAssociationReg1(u32);
    impl Debug;
    u8;
    reserved1, _: 7,0;
    u16;
    pub rid_limit, set_rid_limit: 23,8;
    reserved2, _: 31,24;
}

impl CommonCodec for SelectiveIdeRidAssociationReg1 {}

// Selective IDE RID Association Register 2
bitfield! {
#[derive(Default, FromBytes, IntoBytes, Immutable, Clone, Copy)]
#[repr(C)]
    pub struct SelectiveIdeRidAssociationReg2(u32);
    impl Debug;
    u8;
    pub valid, set_valid: 0,0;
    reserved1, _: 7,1;
    u16;
    pub rid_base, set_rid_base: 23,8;
    reserved2, _: 31,24;
}

impl CommonCodec for SelectiveIdeRidAssociationReg2 {}

// Selective IDE Address Association Register Block

// IDE Address Association Register 1
bitfield! {
#[derive(Default, FromBytes, IntoBytes, Immutable, Clone, Copy)]
#[repr(C)]
    pub struct IdeAddrAssociationReg1(u32);
    impl Debug;
    u8;
    pub valid, set_valid: 0,0;
    reserved1, _: 7,1;
    u16;
    pub memory_base_lower, set_memory_base_lower: 19,8;
    pub memory_limit_lower, set_memory_limit_lower: 31,20;
}

// IDE Address Association Register 2
#[derive(Debug, Default, FromBytes, IntoBytes, Immutable, Clone, Copy)]
pub struct IdeAddrAssociationReg2 {
    pub memory_limit_upper: u32,
}

// IDE Address Association Register 3
#[derive(Debug, Default, FromBytes, IntoBytes, Immutable, Clone, Copy)]
#[repr(C)]
pub struct IdeAddrAssociationReg3 {
    pub memory_base_upper: u32,
}

/// IDE Port configuration
#[derive(Debug, Default, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct PortConfig {
    port_index: u8,
    function_num: u8,
    bus_num: u8,
    segment: u8,
    max_port_index: u8,
}

impl CommonCodec for PortConfig {}

#[derive(Debug, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct IdeRegBlock {
    pub ide_cap_reg: IdeCapabilityReg,
    pub ide_ctrl_reg: IdeControlReg,
}

impl CommonCodec for IdeRegBlock {}

/// Link IDE Register Block
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct LinkIdeStreamRegBlock {
    ctrl_reg: LinkIdeStreamControlReg,
    status_reg: LinkIdeStreamStatusReg,
}
impl CommonCodec for LinkIdeStreamRegBlock {}

#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct SelectiveIdeStreamRegBlock {
    capability_reg: SelectiveIdeStreamCapabilityReg,
    ctrl_reg: SelectiveIdeStreamControlReg,
    status_reg: SelectiveIdeStreamStatusReg,
    rid_association_reg_1: SelectiveIdeRidAssociationReg1,
    rid_association_reg_2: SelectiveIdeRidAssociationReg2,
    addr_association_reg_block: [AddrAssociationRegBlock; MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT],
}

impl Default for SelectiveIdeStreamRegBlock {
    fn default() -> Self {
        SelectiveIdeStreamRegBlock {
            capability_reg: SelectiveIdeStreamCapabilityReg(0),
            ctrl_reg: SelectiveIdeStreamControlReg(0),
            status_reg: SelectiveIdeStreamStatusReg(0),
            rid_association_reg_1: SelectiveIdeRidAssociationReg1(0),
            rid_association_reg_2: SelectiveIdeRidAssociationReg2(0),
            addr_association_reg_block: [AddrAssociationRegBlock::default();
                MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT],
        }
    }
}

impl Codec for SelectiveIdeStreamRegBlock {
    fn encode(&self, buffer: &mut MessageBuf) -> CodecResult<usize> {
        let cap_reg = self.capability_reg;
        let num_addr_association_reg_blks = cap_reg.num_addr_association_reg_blocks() as usize;
        if num_addr_association_reg_blks > MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT {
            Err(CodecError::BufferOverflow)?;
        }
        let mut len = self.capability_reg.encode(buffer)?;
        len += self.ctrl_reg.encode(buffer)?;
        len += self.status_reg.encode(buffer)?;
        len += self.rid_association_reg_1.encode(buffer)?;
        len += self.rid_association_reg_2.encode(buffer)?;
        for i in 0..num_addr_association_reg_blks {
            len += self.addr_association_reg_block[i].encode(buffer)?;
        }
        Ok(len)
    }

    fn decode(buffer: &mut MessageBuf) -> CodecResult<Self> {
        let capability_reg = SelectiveIdeStreamCapabilityReg::decode(buffer)?;
        let num_addr_association_reg_blks =
            capability_reg.num_addr_association_reg_blocks() as usize;
        let ctrl_reg = SelectiveIdeStreamControlReg::decode(buffer)?;
        let status_reg = SelectiveIdeStreamStatusReg::decode(buffer)?;
        let rid_association_reg_1 = SelectiveIdeRidAssociationReg1::decode(buffer)?;
        let rid_association_reg_2 = SelectiveIdeRidAssociationReg2::decode(buffer)?;

        if num_addr_association_reg_blks > MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT {
            Err(CodecError::BufferOverflow)?;
        }

        let mut addr_association_reg_block =
            [AddrAssociationRegBlock::default(); MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT];
        for reg in addr_association_reg_block
            .iter_mut()
            .take(num_addr_association_reg_blks)
        {
            *reg = AddrAssociationRegBlock::decode(buffer)?;
        }

        Ok(Self {
            capability_reg,
            ctrl_reg,
            status_reg,
            rid_association_reg_1,
            rid_association_reg_2,
            addr_association_reg_block,
        })
    }
}

#[derive(Debug, Default, Clone, Copy, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct AddrAssociationRegBlock {
    reg1: IdeAddrAssociationReg1,
    reg2: IdeAddrAssociationReg2,
    reg3: IdeAddrAssociationReg3,
}

impl CommonCodec for AddrAssociationRegBlock {}

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
pub trait IdeDriver: Send + Sync {
    /// Get the port configuration for a given port index.
    ///
    /// # Arguments
    /// * `port_index` - The index of the port to retrieve the configuration for.
    ///
    /// # Returns
    /// A result containing the `PortConfig` for the specified port index, or an error
    /// if the port index is invalid or unsupported.
    fn port_config(&self, port_index: u8) -> IdeDriverResult<PortConfig>;

    /// Get the IDE register block.
    ///
    /// # Arguments
    /// * `port_index` - The index of the port.
    ///
    /// # Returns
    /// A result containing the `IdeRegBlock` for the specified port, or an error
    fn ide_reg_block(&self, port_index: u8) -> IdeDriverResult<IdeRegBlock>;

    /// Get the link IDE register block for a specific port and block index.
    ///
    /// # Arguments
    /// * `port_index` - The index of the port.
    /// * `block_index` - The index of the register block.
    ///
    /// # Returns
    /// A result containing the `LinkIdeStreamRegBlock` for the specified port and block
    fn link_ide_reg_block(
        &self,
        port_index: u8,
        block_index: u8,
    ) -> IdeDriverResult<LinkIdeStreamRegBlock>;

    /// Get the selective IDE register block for a specific port and block index.
    ///
    /// # Arguments
    /// * `port_index` - The index of the port.
    /// * `block_index` - The index of the register block.
    ///
    /// # Returns
    /// A result containing the `SelectiveIdeStreamRegBlock` for the specified port and block
    fn selective_ide_reg_block(
        &self,
        port_index: u8,
        block_index: u8,
    ) -> IdeDriverResult<SelectiveIdeStreamRegBlock>;

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
    struct ExampleIdeDriver {
        port_index: u8,
        func_num: u8,
        bus_num: u8,
        segment_num: u8,
        num_link_ide_streams: u8,
        num_selective_ide_streams: u8,
        num_addr_association_reg_blocks: u8,
    }

    #[async_trait]
    impl IdeDriver for ExampleIdeDriver {
        fn port_config(&self, port_index: u8) -> IdeDriverResult<PortConfig> {
            // Test implementation - return a default config
            if port_index != self.port_index {
                Err(IdeDriverError::InvalidPortIndex)?;
            }
            Ok(PortConfig {
                port_index: self.port_index,
                function_num: self.func_num,
                bus_num: self.bus_num,
                segment: self.segment_num,
                max_port_index: 1,
            })
        }

        fn ide_reg_block(&self, port_index: u8) -> IdeDriverResult<IdeRegBlock> {
            if port_index != self.port_index {
                Err(IdeDriverError::InvalidPortIndex)?;
            }
            let mut ide_cap_reg = IdeCapabilityReg(0);
            ide_cap_reg.set_link_ide_stream_supported(1);
            ide_cap_reg.set_selective_ide_stream_supported(1);
            ide_cap_reg.set_ide_km_protocol_supported(1);
            ide_cap_reg.set_num_tcs_supported_for_link_ide(self.num_link_ide_streams);
            ide_cap_reg.set_num_selective_ide_streams_supported(self.num_selective_ide_streams);

            let ide_ctrl_reg = IdeControlReg(1);
            Ok(IdeRegBlock {
                ide_cap_reg,
                ide_ctrl_reg,
            })
        }

        fn link_ide_reg_block(
            &self,
            _port_index: u8,
            _block_index: u8,
        ) -> IdeDriverResult<LinkIdeStreamRegBlock> {
            // Test implementation - initialize all fields using set methods
            let mut ctrl_reg = LinkIdeStreamControlReg(0);
            ctrl_reg.set_link_ide_stream_enable(1);
            ctrl_reg.set_tx_aggregation_mode_npr(2);
            ctrl_reg.set_tx_aggregation_mode_pr(1);
            ctrl_reg.set_tx_aggregation_mode_cpl(3);
            ctrl_reg.set_pcrc_enable(1);
            ctrl_reg.set_selected_algorithm(5);
            ctrl_reg.set_tc(4);
            ctrl_reg.set_stream_id(0xAB);

            let mut status_reg = LinkIdeStreamStatusReg(0);
            status_reg.set_link_ide_stream_state(7);

            let ide_reg_block = LinkIdeStreamRegBlock {
                ctrl_reg,
                status_reg,
            };
            Ok(ide_reg_block)
        }

        fn selective_ide_reg_block(
            &self,
            _port_index: u8,
            _block_index: u8,
        ) -> IdeDriverResult<SelectiveIdeStreamRegBlock> {
            // Test implementation - return a default block
            // Test implementation - initialize all fields using set methods
            let mut capability_reg = SelectiveIdeStreamCapabilityReg(0);
            capability_reg.set_num_addr_association_reg_blocks(3);

            let mut ctrl_reg = SelectiveIdeStreamControlReg(0);
            ctrl_reg.set_selective_ide_stream_enable(1);
            ctrl_reg.set_tx_aggregation_mode_npr(1);
            ctrl_reg.set_tx_aggregation_mode_pr(2);
            ctrl_reg.set_tx_aggregation_mode_cpl(3);
            ctrl_reg.set_pcrc_enable(1);
            ctrl_reg.set_selective_ide_for_config_req_enable(1);
            ctrl_reg.set_selected_algorithm(4);
            ctrl_reg.set_tc(5);
            ctrl_reg.set_default_stream(1);
            ctrl_reg.set_stream_id(0xCD);

            let mut status_reg = SelectiveIdeStreamStatusReg(0);
            status_reg.set_selective_ide_stream_state(5);
            status_reg.set_received_integrity_check_fail_msg(1);

            let mut rid_association_reg_1 = SelectiveIdeRidAssociationReg1(0);
            rid_association_reg_1.set_rid_limit(0x1234);

            let mut rid_association_reg_2 = SelectiveIdeRidAssociationReg2(0);
            rid_association_reg_2.set_valid(1);
            rid_association_reg_2.set_rid_base(0x5678);

            let mut addr_association_reg_block = [AddrAssociationRegBlock {
                reg1: IdeAddrAssociationReg1(0),
                reg2: IdeAddrAssociationReg2 {
                    memory_limit_upper: 0,
                },
                reg3: IdeAddrAssociationReg3 {
                    memory_base_upper: 0,
                },
            };
                MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT];
            for (i, reg) in addr_association_reg_block.iter_mut().enumerate() {
                if i < self.num_addr_association_reg_blocks as usize {
                    let mut reg1 = reg.reg1;
                    reg1.set_valid(1);
                    reg1.set_memory_base_lower(0x12);
                    reg1.set_memory_limit_lower(0x34);
                    reg.reg1 = reg1;
                    reg.reg2.memory_limit_upper = 0x56;
                    reg.reg3.memory_base_upper = 0x78;
                } else {
                    // Leave as default (zeroed)
                }
            }

            let selective_reg_block = SelectiveIdeStreamRegBlock {
                capability_reg,
                ctrl_reg,
                status_reg,
                rid_association_reg_1,
                rid_association_reg_2,
                addr_association_reg_block,
            };
            Ok(selective_reg_block)
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

    #[test]
    fn test_example_ide_driver() {
        let driver = ExampleIdeDriver {
            port_index: 1,
            func_num: 1,
            bus_num: 0,
            segment_num: 1,
            num_link_ide_streams: 1,
            num_selective_ide_streams: 2,
            num_addr_association_reg_blocks: 3,
        };

        // Test link_ide_reg_block
        let link_block = driver.link_ide_reg_block(0, 0).unwrap();
        assert_eq!(link_block.ctrl_reg.link_ide_stream_enable(), 1);
        assert_eq!(link_block.ctrl_reg.tx_aggregation_mode_npr(), 2);
        assert_eq!(link_block.ctrl_reg.stream_id(), 0xAB);
        assert_eq!(link_block.status_reg.link_ide_stream_state(), 7);

        // Test selective_ide_reg_block
        let selective_block = driver.selective_ide_reg_block(0, 0).unwrap();
        assert_eq!(
            selective_block
                .capability_reg
                .num_addr_association_reg_blocks(),
            3
        );
        let num_addr_assoc_reg_blocks = selective_block
            .capability_reg
            .num_addr_association_reg_blocks() as usize;
        assert_eq!(selective_block.ctrl_reg.selective_ide_stream_enable(), 1);
        assert_eq!(selective_block.ctrl_reg.stream_id(), 0xCD);
        assert_eq!(selective_block.status_reg.selective_ide_stream_state(), 5);
        assert_eq!(selective_block.rid_association_reg_1.rid_limit(), 0x1234);
        assert_eq!(selective_block.rid_association_reg_2.valid(), 1);
        assert_eq!(selective_block.rid_association_reg_2.rid_base(), 0x5678);
        for (i, reg) in selective_block
            .addr_association_reg_block
            .iter()
            .enumerate()
        {
            if i < num_addr_assoc_reg_blocks {
                assert_eq!(reg.reg1.valid(), 1);
                assert_eq!(reg.reg1.memory_base_lower(), 0x12);
                assert_eq!(reg.reg1.memory_limit_lower(), 0x34);
                assert_eq!(reg.reg2.memory_limit_upper, 0x56);
                assert_eq!(reg.reg3.memory_base_upper, 0x78);
            } else {
                assert_eq!(reg.reg1.valid(), 0);
                assert_eq!(reg.reg1.memory_base_lower(), 0);
                assert_eq!(reg.reg1.memory_limit_lower(), 0);
                assert_eq!(reg.reg2.memory_limit_upper, 0);
                assert_eq!(reg.reg3.memory_base_upper, 0);
            }
        }
    }
}

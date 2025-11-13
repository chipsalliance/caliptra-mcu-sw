// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::vdm_handler::pci_sig::ide_km::protocol::*;
use alloc::boxed::Box;
use async_trait::async_trait;

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
        &mut self,
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
        &mut self,
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
        &mut self,
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
            &mut self,
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
            &mut self,
            _stream_id: u8,
            key_info: KeyInfo,
            _port_index: u8,
        ) -> IdeDriverResult<KeyInfo> {
            // Test implementation - return the same key_info
            Ok(key_info)
        }

        async fn key_set_stop(
            &mut self,
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

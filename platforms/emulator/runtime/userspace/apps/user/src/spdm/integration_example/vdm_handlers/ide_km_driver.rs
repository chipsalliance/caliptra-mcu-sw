// Licensed under the Apache-2.0 license

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use spdm_lib::vdm_handler::pci_sig::ide_km::driver::{IdeDriver, IdeDriverError, IdeDriverResult};
use spdm_lib::vdm_handler::pci_sig::ide_km::protocol::*;

pub struct TestIdeDriver {
    port_index: u8,
    func_num: u8,
    bus_num: u8,
    segment_num: u8,
    num_link_ide_streams: u8,
    num_selective_ide_streams: u8,
    num_addr_association_reg_blocks: u8,
    max_port_index: u8,
}

impl Default for TestIdeDriver {
    fn default() -> Self {
        TestIdeDriver {
            port_index: 0,
            func_num: 0,
            bus_num: 0x6a,
            segment_num: 1,
            num_link_ide_streams: 1,
            num_selective_ide_streams: 1,
            num_addr_association_reg_blocks: 2,
            max_port_index: 1,
        }
    }
}

#[async_trait]
impl IdeDriver for TestIdeDriver {
    fn port_config(&self, port_index: u8) -> IdeDriverResult<PortConfig> {
        // Test implementation - return a default config
        if port_index != self.port_index {
            Err(IdeDriverError::InvalidPortIndex)?;
        }
        Ok(PortConfig {
            function_num: self.func_num,
            bus_num: self.bus_num,
            segment: self.segment_num,
            max_port_index: self.max_port_index,
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

        const NUM_ADDR_ASSOCIATION_BLOCKS: usize = 1;
        let mut capability_reg = SelectiveIdeStreamCapabilityReg(0);
        capability_reg.set_num_addr_association_reg_blocks(NUM_ADDR_ASSOCIATION_BLOCKS as u8);

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
        }; MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT];
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

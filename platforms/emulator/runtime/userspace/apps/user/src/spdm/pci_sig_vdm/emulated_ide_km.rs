// Licensed under the Apache-2.0 license

//! Emulator IDE-KM driver used by the DOE/SPDM TDISP+IDE validator test.

use mcu_spdm_lite_codec::{
    AddrAssociationRegBlock, IdeCapabilityReg, IdeControlReg, KeyInfo, LinkIdeStreamControlReg,
    LinkIdeStreamRegBlock, LinkIdeStreamStatusReg, PortConfig, SelectiveIdeRidAssociationReg1,
    SelectiveIdeRidAssociationReg2, SelectiveIdeStreamCapabilityReg, SelectiveIdeStreamControlReg,
    SelectiveIdeStreamRegBlock, SelectiveIdeStreamStatusReg, IDE_STREAM_IV_SIZE_DW,
    IDE_STREAM_KEY_SIZE_DW, MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT,
};
use mcu_spdm_lite_traits::SpdmPalAlloc;
use mcu_spdm_lite_vdm_handler::pci_sig::ide_km::{IdeDriver, IdeDriverError, IdeDriverResult};
use zerocopy::little_endian::U32;

/// Minimal emulator implementation for DOE/SPDM IDE-KM validation.
#[derive(Debug, Clone, Copy)]
pub struct EmulatedIdeDriver {
    pub port_index: u8,
    pub function_num: u8,
    pub bus_num: u8,
    pub segment: u8,
    pub num_link_ide_streams: u8,
    pub num_selective_ide_streams: u8,
    pub num_addr_association_reg_blocks: u8,
}

impl Default for EmulatedIdeDriver {
    fn default() -> Self {
        Self {
            port_index: 0,
            function_num: 0,
            bus_num: 0,
            segment: 0,
            num_link_ide_streams: 1,
            num_selective_ide_streams: 1,
            num_addr_association_reg_blocks: 1,
        }
    }
}

impl IdeDriver for EmulatedIdeDriver {
    fn port_config<Alloc>(&self, port_index: u8, _scratch: &Alloc) -> IdeDriverResult<PortConfig>
    where
        Alloc: SpdmPalAlloc,
    {
        self.check_port(port_index)?;
        Ok(PortConfig {
            function_num: self.function_num,
            bus_num: self.bus_num,
            segment: self.segment,
            max_port_index: self.port_index,
        })
    }

    fn ide_reg_block<Alloc>(
        &self,
        port_index: u8,
        _scratch: &Alloc,
    ) -> IdeDriverResult<mcu_spdm_lite_codec::IdeRegBlock>
    where
        Alloc: SpdmPalAlloc,
    {
        self.check_port(port_index)?;
        let mut ide_cap_reg = IdeCapabilityReg::default();
        ide_cap_reg.set_link_ide_stream_supported(1);
        ide_cap_reg.set_selective_ide_stream_supported(1);
        ide_cap_reg.set_ide_km_protocol_supported(1);
        ide_cap_reg.set_num_tcs_supported_for_link_ide(self.num_link_ide_streams);
        ide_cap_reg.set_num_selective_ide_streams_supported(self.num_selective_ide_streams);

        let mut ide_ctrl_reg = IdeControlReg::default();
        ide_ctrl_reg.set_flow_through_ide_stream_enabled(1);
        Ok(mcu_spdm_lite_codec::IdeRegBlock {
            ide_cap_reg,
            ide_ctrl_reg,
        })
    }

    fn link_ide_reg_block<Alloc>(
        &self,
        port_index: u8,
        block_index: u8,
        _scratch: &Alloc,
    ) -> IdeDriverResult<LinkIdeStreamRegBlock>
    where
        Alloc: SpdmPalAlloc,
    {
        self.check_port(port_index)?;
        if block_index >= self.num_link_ide_streams {
            return Err(IdeDriverError::InvalidStreamId);
        }
        let mut ctrl_reg = LinkIdeStreamControlReg::default();
        ctrl_reg.set_link_ide_stream_enable(1);
        ctrl_reg.set_pcrc_enable(1);
        ctrl_reg.set_selected_algorithm(5);
        ctrl_reg.set_tc(block_index & 0x7);
        ctrl_reg.set_stream_id(block_index);

        let mut status_reg = LinkIdeStreamStatusReg::default();
        status_reg.set_link_ide_stream_state(7);
        Ok(LinkIdeStreamRegBlock {
            ctrl_reg,
            status_reg,
        })
    }

    fn selective_ide_reg_block<Alloc>(
        &self,
        port_index: u8,
        block_index: u8,
        _scratch: &Alloc,
    ) -> IdeDriverResult<SelectiveIdeStreamRegBlock>
    where
        Alloc: SpdmPalAlloc,
    {
        self.check_port(port_index)?;
        if block_index >= self.num_selective_ide_streams {
            return Err(IdeDriverError::InvalidStreamId);
        }

        let mut capability_reg = SelectiveIdeStreamCapabilityReg::default();
        capability_reg.set_num_addr_association_reg_blocks(
            self.num_addr_association_reg_blocks
                .min(MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT as u8),
        );

        let mut ctrl_reg = SelectiveIdeStreamControlReg::default();
        ctrl_reg.set_selective_ide_stream_enable(1);
        ctrl_reg.set_pcrc_enable(1);
        ctrl_reg.set_selective_ide_for_config_req_enable(1);
        ctrl_reg.set_selected_algorithm(4);
        ctrl_reg.set_tc(block_index & 0x7);
        ctrl_reg.set_default_stream(1);
        ctrl_reg.set_stream_id(block_index);

        let mut status_reg = SelectiveIdeStreamStatusReg::default();
        status_reg.set_selective_ide_stream_state(5);

        let mut rid_association_reg_1 = SelectiveIdeRidAssociationReg1::default();
        rid_association_reg_1.set_rid_limit(0x1234);
        let mut rid_association_reg_2 = SelectiveIdeRidAssociationReg2::default();
        rid_association_reg_2.set_valid(1);
        rid_association_reg_2.set_rid_base(0x5678);

        let mut addr_association_reg_block =
            [AddrAssociationRegBlock::default(); MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT];
        for reg in addr_association_reg_block
            .iter_mut()
            .take(capability_reg.num_addr_association_reg_blocks() as usize)
        {
            reg.reg1.set_valid(1);
            reg.reg1.set_memory_base_lower(0x12);
            reg.reg1.set_memory_limit_lower(0x34);
            reg.reg2.memory_limit_upper = U32::new(0x1234_5678);
            reg.reg3.memory_base_upper = U32::new(0x8765_4321);
        }

        Ok(SelectiveIdeStreamRegBlock {
            capability_reg,
            ctrl_reg,
            status_reg,
            rid_association_reg_1,
            rid_association_reg_2,
            addr_association_reg_block,
        })
    }

    async fn key_prog<Alloc>(
        &self,
        _stream_id: u8,
        _key_info: KeyInfo,
        port_index: u8,
        _key: &[U32; IDE_STREAM_KEY_SIZE_DW],
        _iv: &[U32; IDE_STREAM_IV_SIZE_DW],
        _scratch: &Alloc,
    ) -> IdeDriverResult<u8>
    where
        Alloc: SpdmPalAlloc,
    {
        self.check_port(port_index)?;
        Ok(0)
    }

    async fn key_set_go<Alloc>(
        &self,
        _stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
        _scratch: &Alloc,
    ) -> IdeDriverResult<()>
    where
        Alloc: SpdmPalAlloc,
    {
        self.check_port(port_index)?;
        let _ = key_info;
        Ok(())
    }

    async fn key_set_stop<Alloc>(
        &self,
        _stream_id: u8,
        key_info: KeyInfo,
        port_index: u8,
        _scratch: &Alloc,
    ) -> IdeDriverResult<()>
    where
        Alloc: SpdmPalAlloc,
    {
        self.check_port(port_index)?;
        let _ = key_info;
        Ok(())
    }
}

impl EmulatedIdeDriver {
    fn check_port(&self, port_index: u8) -> IdeDriverResult<()> {
        if port_index == self.port_index {
            Ok(())
        } else {
            Err(IdeDriverError::InvalidPortIndex)
        }
    }
}

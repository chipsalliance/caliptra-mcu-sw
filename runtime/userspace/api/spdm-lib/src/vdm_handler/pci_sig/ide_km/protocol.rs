// Licensed under the Apache-2.0 license

use crate::codec::{Codec, CodecError, CodecResult, CommonCodec, MessageBuf};
use crate::vdm_handler::pci_sig::ide_km::commands::key_prog_ack::{KeyData, KeyProg};
use crate::vdm_handler::pci_sig::ide_km::commands::key_set_go_stop_ack::KeySetGoStop;
use crate::vdm_handler::pci_sig::ide_km::commands::query_resp::Query;
use crate::vdm_handler::{VdmError, VdmResult};
use bitfield::bitfield;
use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const IDE_STREAM_KEY_SIZE_DW: usize = 8;
pub const IDE_STREAM_IV_SIZE_DW: usize = 2;
pub const MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT: usize = 15;

#[derive(Debug)]
pub enum IdeKmCommand {
    Query = 0x00,
    QueryResp = 0x01,
    KeyProg = 0x02,
    KeyProgAck = 0x03,
    KeySetGo = 0x04,
    KeySetStop = 0x05,
    KeyGoStopAck = 0x06,
}

impl IdeKmCommand {
    pub fn response(&self) -> VdmResult<Self> {
        match self {
            IdeKmCommand::Query => Ok(IdeKmCommand::QueryResp),
            IdeKmCommand::KeyProg => Ok(IdeKmCommand::KeyProgAck),
            IdeKmCommand::KeySetGo | IdeKmCommand::KeySetStop => Ok(IdeKmCommand::KeyGoStopAck),
            _ => Err(VdmError::InvalidVdmCommand),
        }
    }

    pub fn payload_len(&self) -> usize {
        match self {
            IdeKmCommand::Query => size_of::<Query>(),
            IdeKmCommand::KeyProg => size_of::<KeyProg>() + size_of::<KeyData>(),
            IdeKmCommand::KeySetGo | IdeKmCommand::KeySetStop => size_of::<KeySetGoStop>(),
            _ => 0,
        }
    }
}

impl TryFrom<u8> for IdeKmCommand {
    type Error = VdmError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(IdeKmCommand::Query),
            0x01 => Ok(IdeKmCommand::QueryResp),
            0x02 => Ok(IdeKmCommand::KeyProg),
            0x03 => Ok(IdeKmCommand::KeyProgAck),
            0x04 => Ok(IdeKmCommand::KeySetGo),
            0x05 => Ok(IdeKmCommand::KeySetStop),
            0x06 => Ok(IdeKmCommand::KeyGoStopAck),
            _ => Err(VdmError::InvalidVdmCommand),
        }
    }
}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct IdeKmHdr {
    pub(crate) object_id: u8,
}

impl CommonCodec for IdeKmHdr {}

// Key Information Field
// (Key Sub-stream | Reserved | RxTxB | Key Set)
bitfield! {
    #[derive(Clone, Copy, FromBytes, IntoBytes, Immutable)]
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
    pub function_num: u8,
    pub bus_num: u8,
    pub segment: u8,
    pub max_port_index: u8,
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
    pub ctrl_reg: LinkIdeStreamControlReg,
    pub status_reg: LinkIdeStreamStatusReg,
}
impl CommonCodec for LinkIdeStreamRegBlock {}

#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct SelectiveIdeStreamRegBlock {
    pub capability_reg: SelectiveIdeStreamCapabilityReg,
    pub ctrl_reg: SelectiveIdeStreamControlReg,
    pub status_reg: SelectiveIdeStreamStatusReg,
    pub rid_association_reg_1: SelectiveIdeRidAssociationReg1,
    pub rid_association_reg_2: SelectiveIdeRidAssociationReg2,
    pub addr_association_reg_block:
        [AddrAssociationRegBlock; MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT],
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
    pub reg1: IdeAddrAssociationReg1,
    pub reg2: IdeAddrAssociationReg2,
    pub reg3: IdeAddrAssociationReg3,
}

impl CommonCodec for AddrAssociationRegBlock {}

// Licensed under the Apache-2.0 license

//! PCI-SIG IDE-KM protocol wire types.

use core::mem::size_of;

use zerocopy::{
    little_endian::U16, little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
};

use crate::{WireError, WireWriter};

/// IDE stream key size in DWORDs.
pub const IDE_STREAM_KEY_SIZE_DW: usize = 8;
/// IDE stream IV size in DWORDs.
pub const IDE_STREAM_IV_SIZE_DW: usize = 2;
/// Maximum selective IDE address-association register blocks.
pub const MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT: usize = 15;

/// PCI-SIG IDE-KM protocol ID within PCI-SIG VDMs.
pub const IDE_KM_PROTOCOL_ID: u8 = 0x00;

/// IDE-KM object IDs used as command and response codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
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
    /// Returns the IDE-KM response object ID for a request object ID.
    pub const fn response(self) -> Option<Self> {
        match self {
            Self::Query => Some(Self::QueryResp),
            Self::KeyProg => Some(Self::KeyProgAck),
            Self::KeySetGo | Self::KeySetStop => Some(Self::KeyGoStopAck),
            _ => None,
        }
    }

    /// Returns the expected request payload size after [`IdeKmHdr`].
    pub const fn payload_len(self) -> usize {
        match self {
            Self::Query => Query::SIZE,
            Self::KeyProg => KeyProg::SIZE + KeyData::SIZE,
            Self::KeySetGo | Self::KeySetStop => KeySetGoStop::SIZE,
            _ => 0,
        }
    }

    /// Decodes an IDE-KM object ID.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Query),
            0x01 => Some(Self::QueryResp),
            0x02 => Some(Self::KeyProg),
            0x03 => Some(Self::KeyProgAck),
            0x04 => Some(Self::KeySetGo),
            0x05 => Some(Self::KeySetStop),
            0x06 => Some(Self::KeyGoStopAck),
            _ => None,
        }
    }
}

/// IDE-KM command header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct IdeKmHdr {
    /// IDE-KM object ID.
    pub object_id: u8,
}

impl IdeKmHdr {
    /// Size of the IDE-KM header on the wire.
    pub const SIZE: usize = 1;
}

const _: () = assert!(size_of::<IdeKmHdr>() == IdeKmHdr::SIZE);

/// Key Information field: Key Sub-stream | Reserved | RxTxB | Key Set.
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[repr(transparent)]
pub struct KeyInfo(pub u8);

impl KeyInfo {
    /// Creates a KeyInfo field from key-set, direction, and sub-stream values.
    pub fn new(key_set_bit: bool, key_direction: bool, key_sub_stream: u8) -> Self {
        let mut info = Self(0);
        info.set_key_set_bit(key_set_bit as u8);
        info.set_key_direction(key_direction as u8);
        info.set_key_sub_stream(key_sub_stream);
        info
    }

    /// Returns the Key Set bit.
    pub const fn key_set_bit(self) -> u8 {
        self.0 & 0x1
    }

    /// Sets the Key Set bit.
    pub fn set_key_set_bit(&mut self, value: u8) {
        self.0 = set_field_u8(self.0, 0, 1, value);
    }

    /// Returns the RxTxB key direction bit.
    pub const fn key_direction(self) -> u8 {
        (self.0 >> 1) & 0x1
    }

    /// Sets the RxTxB key direction bit.
    pub fn set_key_direction(&mut self, value: u8) {
        self.0 = set_field_u8(self.0, 1, 1, value);
    }

    /// Returns the key sub-stream nibble.
    pub const fn key_sub_stream(self) -> u8 {
        (self.0 >> 4) & 0x0f
    }

    /// Sets the key sub-stream nibble.
    pub fn set_key_sub_stream(&mut self, value: u8) {
        self.0 = set_field_u8(self.0, 4, 4, value);
    }

    /// Returns the raw wire byte.
    pub const fn raw(self) -> u8 {
        self.0
    }
}

/// IDE Capability Register.
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[repr(transparent)]
pub struct IdeCapabilityReg(pub U32);

impl IdeCapabilityReg {
    /// Creates a register from raw bits.
    pub const fn new(bits: u32) -> Self {
        Self(U32::new(bits))
    }

    /// Returns raw register bits.
    pub fn raw(self) -> u32 {
        self.0.get()
    }

    pub fn link_ide_stream_supported(self) -> u8 {
        get_bit(self.raw(), 0)
    }
    pub fn set_link_ide_stream_supported(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 0, 1, value as u32));
    }
    pub fn selective_ide_stream_supported(self) -> u8 {
        get_bit(self.raw(), 1)
    }
    pub fn set_selective_ide_stream_supported(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 1, 1, value as u32));
    }
    pub fn flow_through_ide_stream_supported(self) -> u8 {
        get_field(self.raw(), 2, 2) as u8
    }
    pub fn set_flow_through_ide_stream_supported(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 2, 2, value as u32));
    }
    pub fn aggregation_supported(self) -> u8 {
        get_bit(self.raw(), 4)
    }
    pub fn set_aggregation_supported(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 4, 1, value as u32));
    }
    pub fn pcrc_supported(self) -> u8 {
        get_bit(self.raw(), 5)
    }
    pub fn set_pcrc_supported(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 5, 1, value as u32));
    }
    pub fn ide_km_protocol_supported(self) -> u8 {
        get_bit(self.raw(), 6)
    }
    pub fn set_ide_km_protocol_supported(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 6, 1, value as u32));
    }
    pub fn selective_ide_for_config_req_supported(self) -> u8 {
        get_bit(self.raw(), 7)
    }
    pub fn set_selective_ide_for_config_req_supported(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 7, 1, value as u32));
    }
    pub fn supported_algorithms(self) -> u8 {
        get_field(self.raw(), 8, 5) as u8
    }
    pub fn set_supported_algorithms(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 8, 5, value as u32));
    }
    pub fn num_tcs_supported_for_link_ide(self) -> u8 {
        get_field(self.raw(), 13, 3) as u8
    }
    pub fn set_num_tcs_supported_for_link_ide(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 13, 3, value as u32));
    }
    pub fn num_selective_ide_streams_supported(self) -> u8 {
        get_field(self.raw(), 16, 8) as u8
    }
    pub fn set_num_selective_ide_streams_supported(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 16, 8, value as u32));
    }

    fn set_bits(&mut self, bits: u32) {
        self.0 = U32::new(bits);
    }
}

/// IDE Control Register.
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[repr(transparent)]
pub struct IdeControlReg(pub U32);

impl IdeControlReg {
    pub const fn new(bits: u32) -> Self {
        Self(U32::new(bits))
    }
    pub fn raw(self) -> u32 {
        self.0.get()
    }
    pub fn flow_through_ide_stream_enabled(self) -> u8 {
        get_bit(self.raw(), 2)
    }
    pub fn set_flow_through_ide_stream_enabled(&mut self, value: u8) {
        self.0 = U32::new(set_field(self.raw(), 2, 1, value as u32));
    }
}

/// Link IDE Stream Control Register.
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[repr(transparent)]
pub struct LinkIdeStreamControlReg(pub U32);

impl LinkIdeStreamControlReg {
    pub const fn new(bits: u32) -> Self {
        Self(U32::new(bits))
    }
    pub fn raw(self) -> u32 {
        self.0.get()
    }
    pub fn link_ide_stream_enable(self) -> u8 {
        get_bit(self.raw(), 0)
    }
    pub fn set_link_ide_stream_enable(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 0, 1, value as u32));
    }
    pub fn tx_aggregation_mode_npr(self) -> u8 {
        get_field(self.raw(), 2, 2) as u8
    }
    pub fn set_tx_aggregation_mode_npr(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 2, 2, value as u32));
    }
    pub fn tx_aggregation_mode_pr(self) -> u8 {
        get_field(self.raw(), 4, 2) as u8
    }
    pub fn set_tx_aggregation_mode_pr(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 4, 2, value as u32));
    }
    pub fn tx_aggregation_mode_cpl(self) -> u8 {
        get_field(self.raw(), 6, 2) as u8
    }
    pub fn set_tx_aggregation_mode_cpl(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 6, 2, value as u32));
    }
    pub fn pcrc_enable(self) -> u8 {
        get_bit(self.raw(), 8)
    }
    pub fn set_pcrc_enable(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 8, 1, value as u32));
    }
    pub fn selected_algorithm(self) -> u8 {
        get_field(self.raw(), 14, 5) as u8
    }
    pub fn set_selected_algorithm(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 14, 5, value as u32));
    }
    pub fn tc(self) -> u8 {
        get_field(self.raw(), 19, 3) as u8
    }
    pub fn set_tc(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 19, 3, value as u32));
    }
    pub fn stream_id(self) -> u8 {
        get_field(self.raw(), 24, 8) as u8
    }
    pub fn set_stream_id(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 24, 8, value as u32));
    }
    fn set_bits(&mut self, bits: u32) {
        self.0 = U32::new(bits);
    }
}

/// Link IDE Stream Status Register.
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[repr(transparent)]
pub struct LinkIdeStreamStatusReg(pub U32);

impl LinkIdeStreamStatusReg {
    pub const fn new(bits: u32) -> Self {
        Self(U32::new(bits))
    }
    pub fn raw(self) -> u32 {
        self.0.get()
    }
    pub fn link_ide_stream_state(self) -> u8 {
        get_field(self.raw(), 0, 4) as u8
    }
    pub fn set_link_ide_stream_state(&mut self, value: u8) {
        self.0 = U32::new(set_field(self.raw(), 0, 4, value as u32));
    }
}

/// Selective IDE Stream Capability Register.
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[repr(transparent)]
pub struct SelectiveIdeStreamCapabilityReg(pub U32);

impl SelectiveIdeStreamCapabilityReg {
    pub const fn new(bits: u32) -> Self {
        Self(U32::new(bits))
    }
    pub fn raw(self) -> u32 {
        self.0.get()
    }
    pub fn num_addr_association_reg_blocks(self) -> u8 {
        get_field(self.raw(), 0, 4) as u8
    }
    pub fn set_num_addr_association_reg_blocks(&mut self, value: u8) {
        self.0 = U32::new(set_field(self.raw(), 0, 4, value as u32));
    }
}

/// Selective IDE Stream Control Register.
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[repr(transparent)]
pub struct SelectiveIdeStreamControlReg(pub U32);

impl SelectiveIdeStreamControlReg {
    pub const fn new(bits: u32) -> Self {
        Self(U32::new(bits))
    }
    pub fn raw(self) -> u32 {
        self.0.get()
    }
    pub fn selective_ide_stream_enable(self) -> u8 {
        get_bit(self.raw(), 0)
    }
    pub fn set_selective_ide_stream_enable(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 0, 1, value as u32));
    }
    pub fn tx_aggregation_mode_npr(self) -> u8 {
        get_field(self.raw(), 2, 2) as u8
    }
    pub fn set_tx_aggregation_mode_npr(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 2, 2, value as u32));
    }
    pub fn tx_aggregation_mode_pr(self) -> u8 {
        get_field(self.raw(), 4, 2) as u8
    }
    pub fn set_tx_aggregation_mode_pr(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 4, 2, value as u32));
    }
    pub fn tx_aggregation_mode_cpl(self) -> u8 {
        get_field(self.raw(), 6, 2) as u8
    }
    pub fn set_tx_aggregation_mode_cpl(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 6, 2, value as u32));
    }
    pub fn pcrc_enable(self) -> u8 {
        get_bit(self.raw(), 8)
    }
    pub fn set_pcrc_enable(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 8, 1, value as u32));
    }
    pub fn selective_ide_for_config_req_enable(self) -> u8 {
        get_bit(self.raw(), 9)
    }
    pub fn set_selective_ide_for_config_req_enable(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 9, 1, value as u32));
    }
    pub fn selected_algorithm(self) -> u8 {
        get_field(self.raw(), 14, 5) as u8
    }
    pub fn set_selected_algorithm(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 14, 5, value as u32));
    }
    pub fn tc(self) -> u8 {
        get_field(self.raw(), 19, 3) as u8
    }
    pub fn set_tc(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 19, 3, value as u32));
    }
    pub fn default_stream(self) -> u8 {
        get_bit(self.raw(), 22)
    }
    pub fn set_default_stream(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 22, 1, value as u32));
    }
    pub fn stream_id(self) -> u8 {
        get_field(self.raw(), 24, 8) as u8
    }
    pub fn set_stream_id(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 24, 8, value as u32));
    }
    fn set_bits(&mut self, bits: u32) {
        self.0 = U32::new(bits);
    }
}

/// Selective IDE Stream Status Register.
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[repr(transparent)]
pub struct SelectiveIdeStreamStatusReg(pub U32);

impl SelectiveIdeStreamStatusReg {
    pub const fn new(bits: u32) -> Self {
        Self(U32::new(bits))
    }
    pub fn raw(self) -> u32 {
        self.0.get()
    }
    pub fn selective_ide_stream_state(self) -> u8 {
        get_field(self.raw(), 0, 4) as u8
    }
    pub fn set_selective_ide_stream_state(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 0, 4, value as u32));
    }
    pub fn received_integrity_check_fail_msg(self) -> u32 {
        get_field(self.raw(), 4, 28)
    }
    pub fn set_received_integrity_check_fail_msg(&mut self, value: u32) {
        self.set_bits(set_field(self.raw(), 4, 28, value));
    }
    fn set_bits(&mut self, bits: u32) {
        self.0 = U32::new(bits);
    }
}

/// Selective IDE RID Association Register 1.
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[repr(transparent)]
pub struct SelectiveIdeRidAssociationReg1(pub U32);

impl SelectiveIdeRidAssociationReg1 {
    pub const fn new(bits: u32) -> Self {
        Self(U32::new(bits))
    }
    pub fn raw(self) -> u32 {
        self.0.get()
    }
    pub fn rid_limit(self) -> u16 {
        get_field(self.raw(), 8, 16) as u16
    }
    pub fn set_rid_limit(&mut self, value: u16) {
        self.0 = U32::new(set_field(self.raw(), 8, 16, value as u32));
    }
}

/// Selective IDE RID Association Register 2.
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[repr(transparent)]
pub struct SelectiveIdeRidAssociationReg2(pub U32);

impl SelectiveIdeRidAssociationReg2 {
    pub const fn new(bits: u32) -> Self {
        Self(U32::new(bits))
    }
    pub fn raw(self) -> u32 {
        self.0.get()
    }
    pub fn valid(self) -> u8 {
        get_bit(self.raw(), 0)
    }
    pub fn set_valid(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 0, 1, value as u32));
    }
    pub fn rid_base(self) -> u16 {
        get_field(self.raw(), 8, 16) as u16
    }
    pub fn set_rid_base(&mut self, value: u16) {
        self.set_bits(set_field(self.raw(), 8, 16, value as u32));
    }
    fn set_bits(&mut self, bits: u32) {
        self.0 = U32::new(bits);
    }
}

/// Selective IDE Address Association Register 1.
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[repr(transparent)]
pub struct IdeAddrAssociationReg1(pub U32);

impl IdeAddrAssociationReg1 {
    pub const fn new(bits: u32) -> Self {
        Self(U32::new(bits))
    }
    pub fn raw(self) -> u32 {
        self.0.get()
    }
    pub fn valid(self) -> u8 {
        get_bit(self.raw(), 0)
    }
    pub fn set_valid(&mut self, value: u8) {
        self.set_bits(set_field(self.raw(), 0, 1, value as u32));
    }
    pub fn memory_base_lower(self) -> u16 {
        get_field(self.raw(), 8, 12) as u16
    }
    pub fn set_memory_base_lower(&mut self, value: u16) {
        self.set_bits(set_field(self.raw(), 8, 12, value as u32));
    }
    pub fn memory_limit_lower(self) -> u16 {
        get_field(self.raw(), 20, 12) as u16
    }
    pub fn set_memory_limit_lower(&mut self, value: u16) {
        self.set_bits(set_field(self.raw(), 20, 12, value as u32));
    }
    fn set_bits(&mut self, bits: u32) {
        self.0 = U32::new(bits);
    }
}

/// Selective IDE Address Association Register 2.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct IdeAddrAssociationReg2 {
    pub memory_limit_upper: U32,
}

/// Selective IDE Address Association Register 3.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct IdeAddrAssociationReg3 {
    pub memory_base_upper: U32,
}

/// IDE Port configuration.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct PortConfig {
    pub function_num: u8,
    pub bus_num: u8,
    pub segment: u8,
    pub max_port_index: u8,
}

impl PortConfig {
    pub const SIZE: usize = 4;
}

/// IDE Capability and Control register block.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct IdeRegBlock {
    pub ide_cap_reg: IdeCapabilityReg,
    pub ide_ctrl_reg: IdeControlReg,
}

impl IdeRegBlock {
    pub const SIZE: usize = 8;
}

/// Link IDE Stream register block.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct LinkIdeStreamRegBlock {
    pub ctrl_reg: LinkIdeStreamControlReg,
    pub status_reg: LinkIdeStreamStatusReg,
}

impl LinkIdeStreamRegBlock {
    pub const SIZE: usize = 8;
}

/// Selective IDE Stream register block.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
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

impl SelectiveIdeStreamRegBlock {
    /// Size of the fixed fields before variable address-association blocks.
    pub const FIXED_SIZE: usize = 20;

    /// Encodes this block with the variable address-association count from capability_reg.
    pub fn encode(&self, writer: &mut WireWriter<'_>) -> Result<(), WireError> {
        let count = self.capability_reg.num_addr_association_reg_blocks() as usize;
        if count > MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT {
            return Err(WireError);
        }
        writer.write(&self.capability_reg)?;
        writer.write(&self.ctrl_reg)?;
        writer.write(&self.status_reg)?;
        writer.write(&self.rid_association_reg_1)?;
        writer.write(&self.rid_association_reg_2)?;
        for reg in self.addr_association_reg_block.iter().take(count) {
            writer.write(reg)?;
        }
        Ok(())
    }
}

impl Default for SelectiveIdeStreamRegBlock {
    fn default() -> Self {
        Self {
            capability_reg: SelectiveIdeStreamCapabilityReg::default(),
            ctrl_reg: SelectiveIdeStreamControlReg::default(),
            status_reg: SelectiveIdeStreamStatusReg::default(),
            rid_association_reg_1: SelectiveIdeRidAssociationReg1::default(),
            rid_association_reg_2: SelectiveIdeRidAssociationReg2::default(),
            addr_association_reg_block: [AddrAssociationRegBlock::default();
                MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT],
        }
    }
}

/// Selective IDE Address Association register block.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct AddrAssociationRegBlock {
    pub reg1: IdeAddrAssociationReg1,
    pub reg2: IdeAddrAssociationReg2,
    pub reg3: IdeAddrAssociationReg3,
}

impl AddrAssociationRegBlock {
    pub const SIZE: usize = 12;
}

/// IDE-KM QUERY request payload.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct Query {
    pub reserved: u8,
    pub port_index: u8,
}

impl Query {
    pub const SIZE: usize = 2;
}

/// IDE-KM KEY_PROG request/ack payload before key material.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct KeyProg {
    pub reserved: U16,
    pub stream_id: u8,
    pub status: u8,
    pub key_info: KeyInfo,
    pub port_index: u8,
}

impl KeyProg {
    pub const SIZE: usize = 6;
}

/// IDE-KM key material payload.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone)]
#[repr(C)]
pub struct KeyData {
    pub key: [U32; IDE_STREAM_KEY_SIZE_DW],
    pub iv: [U32; IDE_STREAM_IV_SIZE_DW],
}

impl KeyData {
    pub const SIZE: usize = 40;
}

/// IDE-KM KEY_SET_GO / KEY_SET_STOP request and ACK payload.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct KeySetGoStop {
    pub reserved1: U16,
    pub stream_id: u8,
    pub reserved2: u8,
    pub key_info: KeyInfo,
    pub port_index: u8,
}

impl KeySetGoStop {
    pub const SIZE: usize = 6;
}

const _: () = assert!(size_of::<PortConfig>() == PortConfig::SIZE);
const _: () = assert!(size_of::<IdeRegBlock>() == IdeRegBlock::SIZE);
const _: () = assert!(size_of::<LinkIdeStreamRegBlock>() == LinkIdeStreamRegBlock::SIZE);
const _: () = assert!(size_of::<AddrAssociationRegBlock>() == AddrAssociationRegBlock::SIZE);
const _: () = assert!(size_of::<Query>() == Query::SIZE);
const _: () = assert!(size_of::<KeyProg>() == KeyProg::SIZE);
const _: () = assert!(size_of::<KeyData>() == KeyData::SIZE);
const _: () = assert!(size_of::<KeySetGoStop>() == KeySetGoStop::SIZE);

const fn set_field_u8(bits: u8, shift: u8, width: u8, value: u8) -> u8 {
    let mask = ((1u16 << width) - 1) as u8;
    (bits & !(mask << shift)) | ((value & mask) << shift)
}

fn get_bit(bits: u32, shift: u8) -> u8 {
    ((bits >> shift) & 1) as u8
}

fn get_field(bits: u32, shift: u8, width: u8) -> u32 {
    (bits >> shift) & ((1u32 << width) - 1)
}

fn set_field(bits: u32, shift: u8, width: u8, value: u32) -> u32 {
    let mask = (1u32 << width) - 1;
    (bits & !(mask << shift)) | ((value & mask) << shift)
}

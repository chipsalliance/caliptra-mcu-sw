// Licensed under the Apache-2.0 license

use bitfield::bitfield;
use zerocopy::{FromBytes, IntoBytes};

#[derive(Debug)]
pub enum I3cError {
    NoMoreAddresses,
    DeviceAttachedWithoutAddress,
    InvalidAddress,
    TargetNotFound,
    TargetNoResponseReady,
    InvalidTcriCommand,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DynamicI3cAddress {
    address: u8,
}

impl DynamicI3cAddress {
    pub fn new(value: u8) -> Result<Self, I3cError> {
        // Assume I2C might be there
        match value {
            0x08..=0x3d | 0x3f..=0x6d | 0x6f..=0x75 => Ok(Self { address: value }),
            _ => Err(I3cError::InvalidAddress),
        }
    }
}

impl From<DynamicI3cAddress> for u32 {
    fn from(value: DynamicI3cAddress) -> Self {
        value.address as u32
    }
}

impl From<DynamicI3cAddress> for u8 {
    fn from(value: DynamicI3cAddress) -> Self {
        value.address
    }
}

impl TryFrom<u32> for DynamicI3cAddress {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value <= 256 {
            Ok(Self {
                address: value as u8,
            })
        } else {
            Err(format!("Address must be less than 256: {}", value))
        }
    }
}

impl From<u8> for DynamicI3cAddress {
    fn from(value: u8) -> Self {
        DynamicI3cAddress { address: value }
    }
}

impl Iterator for DynamicI3cAddress {
    type Item = DynamicI3cAddress;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.address;
        let next = match current {
            0x3d => Some(0x3f),
            0x6d => Some(0x6f),
            0x75 => None,
            _ => Some(current + 1),
        };
        next.map(|address| Self { address })
    }
}

bitfield! {
    #[derive(Clone, FromBytes, IntoBytes)]
    pub struct IbiDescriptor(u32);
    impl Debug;
    pub u8, received_status, set_received_status: 31, 31;
    pub u8, error, set_error: 30, 30;
    // Regular = 0
    // CreditAck = 1
    // ScheduledCmd = 2
    // AutocmdRead = 4
    // StbyCrBcastCcc = 7
    pub u8, status_type, set_status_type: 29, 27;
    pub u8, timestamp_preset, set_timestamp_preset: 25, 25;
    pub u8, last_status, set_last_status: 24, 24;
    pub u8, chunks, set_chunks: 23, 16;
    pub u8, id, set_id: 15, 8;
    pub u8, data_length, set_data_length: 7, 0;
}

bitfield! {
    #[derive(Clone, FromBytes, IntoBytes)]
    pub struct ImmediateDataTransferCommand(u64);
    impl Debug;
    u8, cmd_attr, set_cmd_attr: 2, 0;
    u8, tid, set_tid: 6, 3;
    u8, cmd, set_cmd: 14, 7;
    u8, cp, set_cp: 15, 15;
    u8, dev_index, set_dev_index: 20, 16;
    u8, ddt, set_ddt: 25, 23;
    u8, mode, set_mode: 28, 26;
    u8, rnw, set_rnw: 29, 29;
    u8, wroc, set_wroc: 30, 30;
    u8, toc, set_toc: 31, 31;
    pub u8, data_byte_1, set_data_byte_1: 39, 32;
    pub u8, data_byte_2, set_data_byte_2: 47, 40;
    pub u8, data_byte_3, set_data_byte_3: 55, 48;
    pub u8, data_byte_4, set_data_byte_4: 63, 56;
}

bitfield! {
    #[derive(Clone, FromBytes, IntoBytes)]
    pub struct ReguDataTransferCommand(u64);
    impl Debug;
    u8, cmd_attr, set_cmd_attr: 2, 0;
    u8, tid, set_tid: 6, 3;
    u8, cmd, set_cmd: 14, 7;
    u8, cp, set_cp: 15, 15;
    u8, dev_index, set_dev_index: 20, 16;
    u8, short_read_err, set_short_read_err: 24, 24;
    u8, dbp, set_dbp: 25, 25;
    u8, mode, set_mode: 28, 26;
    pub u8, rnw, set_rnw: 29, 29;
    u8, wroc, set_wroc: 30, 30;
    u8, toc, set_toc: 31, 31;
    u8, def_byte, set_def_byte: 39, 32;
    pub u16, data_length, set_data_length: 63, 48;
}

bitfield! {
    #[derive(Clone, FromBytes, IntoBytes)]
    pub struct ComboTransferCommand(u64);
    impl Debug;
    u8, cmd_attr, set_cmd_attr: 2, 0;
    u8, tid, set_tid: 6, 3;
    u8, cmd, set_cmd: 14, 7;
    u8, cp, set_cp: 15, 15;
    u8, dev_index, set_dev_index: 20, 16;
    u8, data_length_position, set_data_length_position: 23, 22;
    u8, first_phase_mode, set_first_phase_mode: 24, 24;
    u8, suboffset_16bit, set_suboffset_16bit: 25, 25;
    u8, mode, set_mode: 28, 26;
    u8, rnw, set_rnw: 29, 29;
    u8, wroc, set_wroc: 30, 30;
    u8, toc, set_toc: 31, 31;
    u8, offset, set_offset: 47, 32;
    u16, data_length, set_data_length: 63, 48;
}

bitfield! {
    #[derive(Clone, Copy, Default, FromBytes, IntoBytes)]
    pub struct ResponseDescriptor(u32);
    impl Debug;

    pub u16, data_length, set_data_length: 15, 0;
    u8, tid, set_tid: 27, 24;
    u8, err_status, set_err_status: 31, 28;
}

#[derive(Clone, Debug)]
pub enum I3cTcriCommand {
    Immediate(ImmediateDataTransferCommand),
    Regular(ReguDataTransferCommand),
    Combo(ComboTransferCommand),
}

impl TryFrom<[u32; 2]> for I3cTcriCommand {
    type Error = I3cError;

    fn try_from(data: [u32; 2]) -> Result<Self, Self::Error> {
        let combined_data = data[0] as u64 | ((data[1] as u64) << 32);

        match combined_data & 7 {
            1 => Ok(Self::Immediate(
                ImmediateDataTransferCommand::read_from_bytes(&combined_data.to_ne_bytes()[..])
                    .map_err(|_| I3cError::InvalidTcriCommand)?,
            )),
            0 => Ok(Self::Regular(
                ReguDataTransferCommand::read_from_bytes(&combined_data.to_ne_bytes()[..])
                    .map_err(|_| I3cError::InvalidTcriCommand)?,
            )),
            3 => Ok(Self::Combo(
                ComboTransferCommand::read_from_bytes(&combined_data.to_ne_bytes()[..])
                    .map_err(|_| I3cError::InvalidTcriCommand)?,
            )),
            _ => Err(I3cError::InvalidTcriCommand),
        }
    }
}

impl From<I3cTcriCommand> for u64 {
    fn from(item: I3cTcriCommand) -> u64 {
        match item {
            I3cTcriCommand::Regular(reg) => reg.0,
            I3cTcriCommand::Combo(combo) => combo.0,
            I3cTcriCommand::Immediate(imm) => imm.0,
        }
    }
}

impl I3cTcriCommand {
    pub fn raw_data_len(&self) -> usize {
        match self {
            Self::Immediate(_) => 4,
            Self::Regular(regular) => regular.data_length().into(),
            Self::Combo(combo) => combo.data_length().into(),
        }
    }
    pub fn data_len(&self) -> usize {
        match self {
            Self::Immediate(_) => 0,
            Self::Regular(regular) => regular.data_length().into(),
            Self::Combo(combo) => combo.data_length().into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct I3cBusCommand {
    pub addr: DynamicI3cAddress,
    pub cmd: I3cTcriCommandXfer,
}

#[derive(Clone, Debug)]
pub struct I3cBusResponse {
    pub ibi: Option<u8>,
    pub addr: DynamicI3cAddress,
    pub resp: I3cTcriResponseXfer,
}

#[derive(Clone, Debug)]
pub struct I3cTcriCommandXfer {
    pub cmd: I3cTcriCommand,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct I3cTcriResponseXfer {
    pub resp: ResponseDescriptor,
    pub data: Vec<u8>,
}

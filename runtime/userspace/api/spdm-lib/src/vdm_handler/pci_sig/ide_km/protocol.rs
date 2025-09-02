// Licensed under the Apache-2.0 license

use crate::vdm_handler::VdmError;

pub enum IdeKmCommand {
    Query = 0x00,
    QueryResp = 0x01,
    KeyProg = 0x02,
    KeyProgAck = 0x03,
    KeySetGo = 0x04,
    KeySetStop = 0x05,
    KeyGoStopAck = 0x06,
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

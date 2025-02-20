// Licensed under the Apache-2.0 license

use crate::error_rsp::CommandError;

// pub type CommandStatus = Result<(), CommandError>;
// pub type CommandResult = Result<(Option<usize>, CommandError), CommandError>;

// pub enum CommandResult {
//     Success(usize),
//     ErrorResponse(usize, CommandError),
//     ErrorNoResponse(CommandError),
// }
pub enum CommandResult {
    Success,
    ErrorResponse(CommandError),
    ErrorNoResponse(CommandError),
}

#[derive(Debug, Clone, Copy)]
pub enum ReqRespCode {
    GetVersion = 0x84,
    Version = 0x04,
    Error = 0x7F,
    Unsupported = 0,
}

impl From<u8> for ReqRespCode {
    fn from(value: u8) -> Self {
        match value {
            0x84 => ReqRespCode::GetVersion,
            0x04 => ReqRespCode::Version,
            0x7F => ReqRespCode::Error,
            _ => ReqRespCode::Unsupported,
        }
    }
}

impl From<ReqRespCode> for u8 {
    fn from(code: ReqRespCode) -> Self {
        code as u8
    }
}

impl ReqRespCode {
    pub fn response_code(&self) -> Option<ReqRespCode> {
        match self {
            ReqRespCode::GetVersion => Some(ReqRespCode::Version),
            ReqRespCode::Error => Some(ReqRespCode::Error),
            _ => None,
        }
    }
}

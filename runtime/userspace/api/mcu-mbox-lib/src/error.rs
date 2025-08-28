// Licensed under the Apache-2.0 license

/// Handle non-protocol specific error conditions.
#[derive(Debug)]
pub enum MsgHandlerError {
    Transport,
    Codec,
    McuMboxCommon,
    NotReady,
    InvalidParams,
    UnsupportedCommand,
}

// Licensed under the Apache-2.0 license

use crate::transport::TransportError;
use pldm_common::codec::PldmCodecError;

/// Handle non-protocol specific error conditions.
#[derive(Debug)]
pub enum MsgHandlerError {
    Codec(PldmCodecError),
    Transport(TransportError),
    NotReady,
}

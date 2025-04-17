// Licensed under the Apache-2.0 license

use crate::firmware_device::fd_ops::FdOpsError;
use crate::transport::TransportError;
use pldm_common::codec::PldmCodecError;
use pldm_common::error::{PldmError, UtilError};

/// Handle non-protocol specific error conditions.
#[derive(Debug)]
pub enum MsgHandlerError {
    Codec(PldmCodecError),
    Transport(TransportError),
    PldmCommon(PldmError),
    Util(UtilError),
    FdOps(FdOpsError),
    FdInitiatorModeError,
    NotReady,
}

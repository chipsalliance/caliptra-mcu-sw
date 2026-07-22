// Licensed under the Apache-2.0 license

//! Device Ownership Transfer commands for mailbox transport.

use super::checksum::calc_checksum;
use super::command_traits::*;
use caliptra_mcu_core_util_host_command_types::dot::{
    GetDotBackupBlobRequest, GetDotBackupBlobResponse, DOT_BLOB_SIZE,
};
use caliptra_mcu_core_util_host_command_types::CommonResponse;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// External command: Get DOT backup blob request (MC_GET_DOT_BACKUP_BLOB).
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetDotBackupBlobRequest {
    /// Checksum over input data.
    pub chksum: u32,
}

/// External command: Get DOT backup blob response (MC_GET_DOT_BACKUP_BLOB).
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetDotBackupBlobResponse {
    /// Checksum field.
    pub chksum: u32,
    /// FIPS approved or an error.
    pub fips_status: u32,
    /// Current DOT_BLOB bytes.
    pub blob: [u8; DOT_BLOB_SIZE],
}

impl FromInternalRequest<GetDotBackupBlobRequest> for ExtCmdGetDotBackupBlobRequest {
    fn from_internal(_internal: &GetDotBackupBlobRequest, command_code: u32) -> Self {
        Self {
            chksum: calc_checksum(command_code, &[]),
        }
    }
}

impl ToInternalResponse<GetDotBackupBlobResponse> for ExtCmdGetDotBackupBlobResponse {
    fn to_internal(&self) -> GetDotBackupBlobResponse {
        GetDotBackupBlobResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            blob: self.blob,
        }
    }
}

impl VariableSizeBytes for ExtCmdGetDotBackupBlobRequest {}
impl VariableSizeBytes for ExtCmdGetDotBackupBlobResponse {}

use crate::define_command;

define_command!(
    GetDotBackupBlobCmd,
    0x4D44_4F54, // MC_GET_DOT_BACKUP_BLOB - "MDOT"
    GetDotBackupBlobRequest,
    GetDotBackupBlobResponse,
    ExtCmdGetDotBackupBlobRequest,
    ExtCmdGetDotBackupBlobResponse
);

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::IntoBytes;

    #[test]
    fn get_dot_backup_blob_external_response_to_internal() {
        let external = ExtCmdGetDotBackupBlobResponse {
            chksum: 0,
            fips_status: 0x1234,
            blob: [0x5A; DOT_BLOB_SIZE],
        };

        let internal = external.to_internal();
        assert_eq!(internal.common.fips_status, 0x1234);
        assert_eq!(internal.blob, [0x5A; DOT_BLOB_SIZE]);
        assert_eq!(external.as_bytes().len(), 4 + 4 + DOT_BLOB_SIZE);
    }
}

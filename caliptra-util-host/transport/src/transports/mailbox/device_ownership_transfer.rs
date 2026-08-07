// Licensed under the Apache-2.0 license

//! Device Ownership Transfer commands for mailbox transport.

use super::checksum::calc_checksum;
use super::command_traits::*;
use caliptra_mcu_core_util_host_command_types::device_ownership_transfer::{
    GetDotBackupBlobRequest, GetDotBackupBlobResponse, DOT_BLOB_SIZE,
};
use caliptra_mcu_core_util_host_command_types::CommonResponse;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetDotBackupBlobRequest {
    pub chksum: u32,
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetDotBackupBlobResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub blob: [u8; DOT_BLOB_SIZE],
}

impl FromInternalRequest<GetDotBackupBlobRequest> for ExtCmdGetDotBackupBlobRequest {
    fn from_internal(_internal: &GetDotBackupBlobRequest, command_code: u32) -> Self {
        // MDOT has no request body, so the checksum covers only the command code.
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
    0x4D44_4F54,
    GetDotBackupBlobRequest,
    GetDotBackupBlobResponse,
    ExtCmdGetDotBackupBlobRequest,
    ExtCmdGetDotBackupBlobResponse
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mdot_mailbox_conversion_preserves_blob() {
        let request =
            ExtCmdGetDotBackupBlobRequest::from_internal(&GetDotBackupBlobRequest, 0x4D44_4F54);
        assert_eq!(request.chksum, calc_checksum(0x4D44_4F54, &[]));

        let external = ExtCmdGetDotBackupBlobResponse {
            chksum: 0,
            fips_status: 0,
            blob: [0x5A; DOT_BLOB_SIZE],
        };
        let internal = external.to_internal();
        assert_eq!(internal.common.fips_status, 0);
        assert_eq!(internal.blob, [0x5A; DOT_BLOB_SIZE]);
    }
}

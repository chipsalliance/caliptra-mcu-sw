// Licensed under the Apache-2.0 license

//! Command dispatch for SPDM VDM transport
//!
//! Maps internal `CaliptraCommandId` values to the VDM command
//! handler functions defined in the `commands` module.

use super::commands;

/// Type alias for VDM command handler functions.
pub type VdmCommandHandlerFn = fn(
    &[u8],
    &mut dyn super::transport::SpdmVdmDriver,
    &mut [u8],
) -> Result<usize, crate::TransportError>;

/// Look up the VDM command handler for a given internal command ID.
///
/// Returns `Some(handler)` for supported commands, `None` otherwise.
pub fn get_command_handler(command_id: u32) -> Option<VdmCommandHandlerFn> {
    use caliptra_mcu_core_util_host_command_types::CaliptraCommandId;
    match command_id {
        x if x == CaliptraCommandId::GetAttestation as u32 => {
            Some(commands::handle_get_attestation)
        }
        x if x == CaliptraCommandId::ExportAttestedCsr as u32 => {
            Some(commands::handle_export_attested_csr)
        }
        x if x == CaliptraCommandId::ProdDebugUnlockReq as u32 => {
            Some(commands::handle_prod_debug_unlock_req)
        }
        x if x == CaliptraCommandId::ProdDebugUnlockToken as u32 => {
            Some(commands::handle_prod_debug_unlock_token)
        }
        x if x == CaliptraCommandId::FeProg as u32 => Some(commands::handle_fe_prog),
        x if x == CaliptraCommandId::ProvisionVendorPkHash as u32 => {
            Some(commands::handle_provision_vendor_pk_hash)
        }
        x if x == CaliptraCommandId::FuseIncreaseCaliptraMinSvn as u32 => {
            Some(commands::handle_fuse_increase_caliptra_min_svn)
        }
        x if x == CaliptraCommandId::FuseRevokeVendorPubKey as u32 => {
            Some(commands::handle_fuse_revoke_vendor_pub_key)
        }
        x if x == CaliptraCommandId::FuseRevokeVendorPkHash as u32 => {
            Some(commands::handle_fuse_revoke_vendor_pk_hash)
        }
        x if x == CaliptraCommandId::FuseLockPartition as u32 => {
            Some(commands::handle_fuse_lock_partition)
        }
        x if x == CaliptraCommandId::ProvisionOwnerPkHash as u32 => {
            Some(commands::handle_provision_owner_pk_hash)
        }
        x if x == CaliptraCommandId::GetAuthCmdChallenge as u32 => {
            Some(commands::handle_get_auth_challenge)
        }
        x if x == CaliptraCommandId::DotLock as u32 => Some(commands::handle_dot_lock),
        x if x == CaliptraCommandId::DotDisable as u32 => Some(commands::handle_dot_disable),
        x if x == CaliptraCommandId::DotRotate as u32 => Some(commands::handle_dot_rotate),
        x if x == CaliptraCommandId::DotUnlockChallenge as u32 => {
            Some(commands::handle_dot_unlock_challenge)
        }
        x if x == CaliptraCommandId::DotUnlock as u32 => Some(commands::handle_dot_unlock),
        x if x == CaliptraCommandId::GetDotBackupBlob as u32 => {
            Some(commands::handle_get_dot_backup_blob)
        }
        x if x == CaliptraCommandId::DotStatus as u32 => Some(commands::handle_dot_status),
        x if x == CaliptraCommandId::DotRecovery as u32 => Some(commands::handle_dot_recovery),
        x if x == CaliptraCommandId::DotOverrideChallenge as u32 => {
            Some(commands::handle_dot_override_challenge)
        }
        x if x == CaliptraCommandId::DotOverride as u32 => Some(commands::handle_dot_override),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transports::spdm_vdm::protocol::command_id_to_vdm;
    use caliptra_mcu_core_util_host_command_types::CaliptraCommandId;

    #[test]
    fn dispatch_and_protocol_mappings_stay_aligned() {
        let ids = [
            CaliptraCommandId::GetAttestation,
            CaliptraCommandId::ExportAttestedCsr,
            CaliptraCommandId::ProdDebugUnlockReq,
            CaliptraCommandId::ProdDebugUnlockToken,
            CaliptraCommandId::FeProg,
            CaliptraCommandId::ProvisionVendorPkHash,
            CaliptraCommandId::FuseIncreaseCaliptraMinSvn,
            CaliptraCommandId::FuseRevokeVendorPubKey,
            CaliptraCommandId::FuseRevokeVendorPkHash,
            CaliptraCommandId::FuseLockPartition,
            CaliptraCommandId::ProvisionOwnerPkHash,
            CaliptraCommandId::GetAuthCmdChallenge,
            CaliptraCommandId::DotLock,
            CaliptraCommandId::DotDisable,
            CaliptraCommandId::DotRotate,
            CaliptraCommandId::DotUnlockChallenge,
            CaliptraCommandId::DotUnlock,
            CaliptraCommandId::GetDotBackupBlob,
            CaliptraCommandId::DotStatus,
            CaliptraCommandId::DotRecovery,
            CaliptraCommandId::DotOverrideChallenge,
            CaliptraCommandId::DotOverride,
        ];

        for id in ids {
            assert!(
                get_command_handler(id as u32).is_some(),
                "missing dispatch for {id:?}"
            );
            assert!(
                command_id_to_vdm(id as u32).is_some(),
                "missing VDM code for {id:?}"
            );
        }

        assert!(get_command_handler(CaliptraCommandId::HashInit as u32).is_none());
        assert!(command_id_to_vdm(CaliptraCommandId::HashInit as u32).is_none());
    }
}

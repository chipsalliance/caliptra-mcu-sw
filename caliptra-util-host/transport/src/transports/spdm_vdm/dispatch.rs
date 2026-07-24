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
        x if x == CaliptraCommandId::GetAuthCmdChallenge as u32 => {
            Some(commands::handle_get_auth_challenge)
        }
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
            CaliptraCommandId::ExportAttestedCsr,
            CaliptraCommandId::ProdDebugUnlockReq,
            CaliptraCommandId::ProdDebugUnlockToken,
            CaliptraCommandId::FeProg,
            CaliptraCommandId::GetAuthCmdChallenge,
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

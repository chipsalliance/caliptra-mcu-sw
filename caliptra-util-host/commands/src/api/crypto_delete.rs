// Licensed under the Apache-2.0 license

//! Cryptographic Delete API function
//!
//! High-level function for deleting encrypted CMK handles from storage.
//!
//! Delete operations:
//! - `caliptra_cmd_delete` - Delete an encrypted CMK from storage

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_util_host_command_types::crypto_delete::{DeleteRequest, DeleteResponse};
use caliptra_util_host_command_types::crypto_hmac::Cmk;
use caliptra_util_host_command_types::CaliptraCommandId;
use caliptra_util_host_session::CaliptraSession;

/// Delete an encrypted CMK from storage
///
/// This deletes a CMK (Cryptographic Mailbox Key) that was previously
/// created via import or key derivation operations. Deleting keys when
/// they are no longer needed is important for:
/// - Freeing storage slots (limited to 256 slots)
/// - Security hygiene (minimizing key exposure)
/// - Test isolation (each test starts with clean state)
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `cmk`: The CMK to delete
///
/// # Returns
///
/// - `Ok(DeleteResponse)` on successful deletion
/// - `Err(CaliptraApiError)` on failure
///
/// # Example
///
/// ```ignore
/// // Import a key
/// let resp = caliptra_cmd_import(&mut session, CmKeyUsage::Hmac, &key_data)?;
/// let cmk = resp.cmk;
///
/// // Use the key for operations...
///
/// // Delete the key when done
/// caliptra_cmd_delete(&mut session, &cmk)?;
/// ```
pub fn caliptra_cmd_delete(
    session: &mut CaliptraSession,
    cmk: &Cmk,
) -> CaliptraResult<DeleteResponse> {
    let request = DeleteRequest::new(cmk);
    session
        .execute_command_with_id(CaliptraCommandId::Delete, &request)
        .map_err(|_| CaliptraApiError::SessionError("Delete command execution failed"))
}

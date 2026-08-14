// Licensed under the Apache-2.0 license

pub(crate) mod debug_log;
pub(crate) mod device_ops;

use caliptra_mcu_common_commands::{
    CaliptraCmdHandler, CaliptraCmdResult, CaliptraCompletionCode, DebugUnlockChallenge,
    DeviceCapabilities, FirmwareVersion, GetLogResult,
};
use caliptra_mcu_config::capabilities::{
    encode_capabilities, AuthorizedSubcommandCapabilities, ExternalCommandCapabilities,
    McuRuntimeCapabilities,
};
use caliptra_mcu_config::version::get_mcu_runtime_version;
use mcu_caliptra_api_lite::{core_capabilities, core_firmware_version, ApiAlloc};

pub struct CaliptraCmdBackend;

fn mcu_runtime_capabilities() -> McuRuntimeCapabilities {
    let mut capabilities = McuRuntimeCapabilities::empty();
    if cfg!(feature = "flash-boot") {
        capabilities |= McuRuntimeCapabilities::FLASH_BOOT;
    }
    if cfg!(feature = "streaming-boot") {
        capabilities |= McuRuntimeCapabilities::STREAMING_BOOT;
    }
    if cfg!(feature = "firmware-update") {
        capabilities |= McuRuntimeCapabilities::FIRMWARE_UPDATE;
    }
    if cfg!(feature = "spdm") {
        capabilities |= McuRuntimeCapabilities::SPDM_RESPONDER;
    }
    if cfg!(feature = "mctp-vdm-service") {
        capabilities |= McuRuntimeCapabilities::MCTP_VDM_RESPONDER;
    }
    if cfg!(feature = "userspace-log") {
        capabilities |= McuRuntimeCapabilities::USERSPACE_DEBUG_LOG;
    }
    if cfg!(feature = "mcu-mbox-service") {
        capabilities |= McuRuntimeCapabilities::MCI_MAILBOX_SERVICE;
    }
    if cfg!(feature = "doe") {
        capabilities |= McuRuntimeCapabilities::DOE;
    }
    capabilities
}

fn external_command_capabilities() -> ExternalCommandCapabilities {
    let mut capabilities = ExternalCommandCapabilities::empty();
    if cfg!(feature = "mctp-vdm-service") {
        capabilities |= ExternalCommandCapabilities::FIRMWARE_VERSION
            | ExternalCommandCapabilities::DEVICE_CAPABILITIES
            | ExternalCommandCapabilities::GET_DEBUG_LOG
            | ExternalCommandCapabilities::CLEAR_DEBUG_LOG;
    }
    if cfg!(feature = "spdm") {
        capabilities |= ExternalCommandCapabilities::REQUEST_DEBUG_UNLOCK
            | ExternalCommandCapabilities::AUTHORIZE_DEBUG_UNLOCK_TOKEN
            | ExternalCommandCapabilities::EXPORT_ATTESTED_CSR
            | ExternalCommandCapabilities::AUTHORIZED_COMMAND;
    }
    capabilities
}

fn authorized_subcommand_capabilities() -> AuthorizedSubcommandCapabilities {
    if cfg!(feature = "spdm") {
        AuthorizedSubcommandCapabilities::GET_AUTH_CHALLENGE
            | AuthorizedSubcommandCapabilities::PROVISION_VENDOR_PK_HASH
            | AuthorizedSubcommandCapabilities::FUSE_INCREASE_CALIPTRA_MIN_SVN
            | AuthorizedSubcommandCapabilities::PROGRAM_FIELD_ENTROPY
            | AuthorizedSubcommandCapabilities::FUSE_REVOKE_VENDOR_PUBLIC_KEY
            | AuthorizedSubcommandCapabilities::FUSE_REVOKE_VENDOR_PK_HASH
            | AuthorizedSubcommandCapabilities::FUSE_LOCK_PARTITION
            | AuthorizedSubcommandCapabilities::PROVISION_OWNER_PK_HASH
    } else {
        AuthorizedSubcommandCapabilities::empty()
    }
}

fn write_firmware_version(
    version: &mut FirmwareVersion,
    packed_version: u32,
) -> CaliptraCmdResult<()> {
    let major = (packed_version >> 24) & 0xff;
    let minor = (packed_version >> 16) & 0xff;
    let patch = packed_version & 0xffff;

    version.ver_str.fill(0);
    let mut len = 0;
    push_decimal(&mut version.ver_str, &mut len, major)?;
    push_byte(&mut version.ver_str, &mut len, b'.')?;
    push_decimal(&mut version.ver_str, &mut len, minor)?;
    push_byte(&mut version.ver_str, &mut len, b'.')?;
    push_decimal(&mut version.ver_str, &mut len, patch)?;
    version.len = len;
    Ok(())
}

fn push_byte(buf: &mut [u8], len: &mut usize, byte: u8) -> CaliptraCmdResult<()> {
    let slot = buf
        .get_mut(*len)
        .ok_or(CaliptraCompletionCode::InvalidPayloadSize)?;
    *slot = byte;
    *len += 1;
    Ok(())
}

fn push_decimal(buf: &mut [u8], len: &mut usize, value: u32) -> CaliptraCmdResult<()> {
    // u32 has at most 10 decimal digits.
    let mut digits = [0u8; 10];
    let mut remaining = value;
    let mut count = 0;
    loop {
        digits[count] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        count += 1;
        if remaining == 0 {
            break;
        }
    }
    while count > 0 {
        count -= 1;
        push_byte(buf, len, digits[count])?;
    }
    Ok(())
}

impl CaliptraCmdHandler for CaliptraCmdBackend {
    async fn get_firmware_version(
        &self,
        index: u32,
        version: &mut FirmwareVersion,
    ) -> CaliptraCmdResult<()> {
        let packed_version = match index {
            0 => {
                core_firmware_version()
                    .await
                    .map_err(device_ops::map_mcu_err)?
                    .runtime
            }
            1 => get_mcu_runtime_version(),
            2 => return Err(CaliptraCompletionCode::UnsupportedOperation),
            _ => return Err(CaliptraCompletionCode::InvalidParameter),
        };

        write_firmware_version(version, packed_version)
    }

    async fn get_device_capabilities(
        &self,
        capabilities: &mut DeviceCapabilities,
    ) -> CaliptraCmdResult<()> {
        let core = core_capabilities().await.map_err(device_ops::map_mcu_err)?;
        capabilities.caliptra_rt.copy_from_slice(&core[..8]);
        capabilities.caliptra_fmc.copy_from_slice(&core[8..12]);
        capabilities.caliptra_rom.copy_from_slice(&core[12..16]);
        capabilities.mcu_rom.fill(0);
        capabilities.mcu_rt = encode_capabilities(mcu_runtime_capabilities().bits());
        capabilities.external_commands =
            encode_capabilities(external_command_capabilities().bits());
        capabilities.authorized_subcommands =
            encode_capabilities(authorized_subcommand_capabilities().bits());
        capabilities.reserved.fill(0);
        Ok(())
    }

    async fn export_attested_csr<Alloc: ApiAlloc>(
        &self,
        _alloc: &Alloc,
        device_key_id: u32,
        algorithm: u32,
        nonce: &[u8; 32],
        csr_buf: &mut [u8],
    ) -> CaliptraCmdResult<usize> {
        device_ops::export_attested_csr(device_key_id, algorithm, nonce, csr_buf).await
    }

    async fn export_idevid_csr<Alloc: ApiAlloc>(
        &self,
        _alloc: &Alloc,
        algorithm: u32,
        csr_buf: &mut [u8],
    ) -> CaliptraCmdResult<usize> {
        device_ops::export_idevid_csr(algorithm, csr_buf).await
    }

    /// Drain entries of `log_type` from the backing store.
    ///
    /// The debug log is backed by the Tock logging-flash capsule via
    /// [`LoggingSyscall`](caliptra_mcu_libsyscall_caliptra::logging::LoggingSyscall);
    /// the kernel cursor is advanced as entries are consumed and any entry
    /// that does not fit is held over for the next call.
    async fn get_log(&self, log_type: u32, data: &mut [u8]) -> CaliptraCmdResult<GetLogResult> {
        device_ops::get_debug_log(log_type, data).await
    }

    /// Erase the log of `log_type` and reset the read cursor.
    async fn clear_log(&self, log_type: u32) -> CaliptraCmdResult<()> {
        device_ops::clear_debug_log(log_type).await
    }

    async fn provision_vendor_pk_hash(&self, slot: u32, hash: &[u8; 48]) -> CaliptraCmdResult<()> {
        device_ops::provision_vendor_pk_hash(slot, hash)
    }

    async fn provision_owner_pk_hash(&self, hash: &[u8; 48]) -> CaliptraCmdResult<()> {
        device_ops::provision_owner_pk_hash(hash)
    }

    async fn fuse_lock_partition(&self, partition: u32) -> CaliptraCmdResult<()> {
        device_ops::fuse_lock_partition(partition)
    }

    async fn increase_caliptra_min_svn<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        svn: u32,
    ) -> CaliptraCmdResult<()> {
        device_ops::increase_caliptra_min_svn(alloc, svn).await
    }

    async fn revoke_vendor_pub_key<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        vendor_pk_hash_slot: u32,
        key_type: u32,
        key_index: u32,
    ) -> CaliptraCmdResult<()> {
        device_ops::revoke_vendor_pub_key(alloc, vendor_pk_hash_slot, key_type, key_index).await
    }

    async fn revoke_vendor_pk_hash(&self, vendor_pk_hash_slot: u32) -> CaliptraCmdResult<()> {
        device_ops::revoke_vendor_pk_hash(vendor_pk_hash_slot)
    }

    async fn program_field_entropy<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        partition: u32,
    ) -> CaliptraCmdResult<()> {
        device_ops::program_field_entropy(alloc, partition).await
    }

    async fn request_debug_unlock<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        unlock_level: u8,
        challenge: &mut DebugUnlockChallenge,
    ) -> CaliptraCmdResult<()> {
        let mut out = [0u8; caliptra_mcu_common_commands::DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE
            + caliptra_mcu_common_commands::DEBUG_UNLOCK_CHALLENGE_SIZE];
        let len = device_ops::request_debug_unlock(alloc, unlock_level, &mut out).await?;
        if len != out.len() {
            return Err(CaliptraCompletionCode::OperationFailed);
        }
        challenge.unique_device_identifier.copy_from_slice(
            &out[..caliptra_mcu_common_commands::DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE],
        );
        challenge.challenge.copy_from_slice(
            &out[caliptra_mcu_common_commands::DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE..],
        );
        Ok(())
    }

    async fn authorize_debug_unlock_token<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        token_request: &[u8],
    ) -> CaliptraCmdResult<()> {
        // Pass-through: the requester sends a complete Caliptra request
        // (including the mailbox checksum header), identical to the VDM path.
        device_ops::authorize_debug_unlock_token(alloc, token_request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_masks_follow_compiled_services() {
        let runtime = mcu_runtime_capabilities();
        let commands = external_command_capabilities();
        let authorized = authorized_subcommand_capabilities();
        let mctp_commands = ExternalCommandCapabilities::FIRMWARE_VERSION
            | ExternalCommandCapabilities::DEVICE_CAPABILITIES
            | ExternalCommandCapabilities::GET_DEBUG_LOG
            | ExternalCommandCapabilities::CLEAR_DEBUG_LOG;
        let spdm_commands = ExternalCommandCapabilities::REQUEST_DEBUG_UNLOCK
            | ExternalCommandCapabilities::AUTHORIZE_DEBUG_UNLOCK_TOKEN
            | ExternalCommandCapabilities::EXPORT_ATTESTED_CSR
            | ExternalCommandCapabilities::AUTHORIZED_COMMAND;

        assert_eq!(
            runtime.contains(McuRuntimeCapabilities::MCTP_VDM_RESPONDER),
            cfg!(feature = "mctp-vdm-service")
        );
        assert_eq!(
            commands.contains(mctp_commands),
            cfg!(feature = "mctp-vdm-service")
        );
        assert_eq!(
            runtime.contains(McuRuntimeCapabilities::SPDM_RESPONDER),
            cfg!(feature = "spdm")
        );
        assert_eq!(commands.contains(spdm_commands), cfg!(feature = "spdm"));
        assert_eq!(
            authorized.contains(
                AuthorizedSubcommandCapabilities::GET_AUTH_CHALLENGE
                    | AuthorizedSubcommandCapabilities::PROVISION_VENDOR_PK_HASH
                    | AuthorizedSubcommandCapabilities::FUSE_INCREASE_CALIPTRA_MIN_SVN
                    | AuthorizedSubcommandCapabilities::PROGRAM_FIELD_ENTROPY
                    | AuthorizedSubcommandCapabilities::FUSE_REVOKE_VENDOR_PUBLIC_KEY
                    | AuthorizedSubcommandCapabilities::FUSE_REVOKE_VENDOR_PK_HASH
            ),
            cfg!(feature = "spdm")
        );
        assert_eq!(
            runtime.contains(McuRuntimeCapabilities::DOE),
            cfg!(feature = "doe")
        );
        assert_eq!(commands.bits() & command_capability_for_test(0x05), 0);
    }

    const fn command_capability_for_test(command_code: u8) -> u32 {
        1u32 << (command_code as u32 - 1)
    }
}

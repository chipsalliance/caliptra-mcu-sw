// Licensed under the Apache-2.0 license

pub(crate) mod debug_log;
pub(crate) mod device_ops;

use caliptra_mcu_attestation_evidence::SIGNED_OCP_EAT_MAX_SIZE;
use caliptra_mcu_common_commands::{
    AsymAlgo, CaliptraCmdHandler, CaliptraCmdResult, CaliptraCompletionCode, DebugUnlockChallenge,
    DeviceCapabilities, EvidenceFormat, FirmwareVersion, GetLogResult, PkiEntitySlot,
    ATTESTATION_NONCE_LEN,
};
use caliptra_mcu_config::capabilities::{
    encode_capabilities, AuthorizedSubcommandCapabilities, ExternalCommandCapabilities,
    McuRuntimeCapabilities,
};
use caliptra_mcu_config::version::get_mcu_runtime_version;
#[cfg(feature = "ocp-lock")]
use caliptra_mcu_libapi_caliptra::error::CaliptraApiError;
#[cfg(feature = "ocp-lock")]
use caliptra_mcu_libapi_caliptra::ocp_lock::{
    HpkeHandle, OcpLock, OcpLockEnumerateHpkeHandlesResp,
};
#[cfg(feature = "ocp-lock")]
use caliptra_mcu_libapi_caliptra::signer::CaliptraDpeSigner;
#[cfg(feature = "ocp-lock")]
use caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox;
use caliptra_mcu_mbox_common::messages::{
    DotDisablePayload, DotLockPayload, DotOverrideChallengePayload, DotOverridePayload,
    DotRotatePayload, DotStatus, DotUnlockPayload, AUTH_CMD_NONCE_LEN, DOT_BLOB_SIZE,
};
use mcu_caliptra_api::{core_capabilities, core_firmware_version, ApiAlloc};
#[cfg(feature = "pcr-quote")]
use mcu_caliptra_api::{PCR_QUOTE_ECC384_BUF_LEN, PCR_QUOTE_MLDSA87_BUF_LEN};

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
    // GET_ATTESTATION is transport-agnostic: it is reachable over the SPDM VDM
    // transport and the MCU mailbox, so advertise it whenever either responder
    // is built and this build can produce at least one evidence format.
    if (cfg!(feature = "spdm") || cfg!(feature = "mcu-mbox-service"))
        && SUPPORTED_EVIDENCE_FORMATS != 0
    {
        capabilities |= ExternalCommandCapabilities::GET_ATTESTATION;
    }
    if cfg!(feature = "dot-spdm-vdm") {
        capabilities |= ExternalCommandCapabilities::DEVICE_OWNERSHIP_TRANSFER;
    }
    capabilities
}

/// Upper bound, in bytes, on evidence for one `(format, algorithm)` pair; `0`
/// when this build cannot produce it.
///
/// Every bound comes from the generator that would actually run, so the
/// transports' buffer reservations follow automatically when a generator is
/// enabled, disabled, or resized. Nothing here is an independently declared
/// number.
const fn evidence_len(format: EvidenceFormat, algorithm: AsymAlgo) -> usize {
    match (format, algorithm) {
        // The EAT signer emits only ES384 today, so there is no ML-DSA EAT
        // length to report yet.
        (EvidenceFormat::OcpEat, AsymAlgo::EccP384) => SIGNED_OCP_EAT_MAX_SIZE,
        #[cfg(feature = "pcr-quote")]
        (EvidenceFormat::PcrQuote, AsymAlgo::EccP384) => PCR_QUOTE_ECC384_BUF_LEN,
        #[cfg(feature = "pcr-quote")]
        (EvidenceFormat::PcrQuote, AsymAlgo::Mldsa87) => PCR_QUOTE_MLDSA87_BUF_LEN,
        _ => 0,
    }
}

/// Every `(format, algorithm)` pair `GET_ATTESTATION` can name, in bitmap and
/// worst-case-size order. Keeping one list means the bitmap, the worst-case
/// bound, and the per-pair lookup cannot drift apart.
const EVIDENCE_PAIRS: [(EvidenceFormat, AsymAlgo); 4] = [
    (EvidenceFormat::OcpEat, AsymAlgo::EccP384),
    (EvidenceFormat::OcpEat, AsymAlgo::Mldsa87),
    (EvidenceFormat::PcrQuote, AsymAlgo::EccP384),
    (EvidenceFormat::PcrQuote, AsymAlgo::Mldsa87),
];

/// Bitmap of formats this build can produce, returned for a format-discovery
/// query. A format is advertised when at least one algorithm works for it.
const SUPPORTED_EVIDENCE_FORMATS: u32 = {
    let mut bits = 0u32;
    let mut i = 0;
    while i < EVIDENCE_PAIRS.len() {
        let (format, algorithm) = EVIDENCE_PAIRS[i];
        if evidence_len(format, algorithm) != 0 {
            bits |= format.bit();
        }
        i += 1;
    }
    bits
};

/// Worst case across every enabled generator. Transports use this to size
/// static contracts (the VDM large-response capacity and the mailbox response
/// allocation); the per-request path still uses the per-pair value so a small
/// format never reserves the large one's buffer.
const MAX_ATTESTATION_EVIDENCE_LEN: usize = {
    let mut max = 0;
    let mut i = 0;
    while i < EVIDENCE_PAIRS.len() {
        let (format, algorithm) = EVIDENCE_PAIRS[i];
        let len = evidence_len(format, algorithm);
        if len > max {
            max = len;
        }
        i += 1;
    }
    max
};

fn authorized_subcommand_capabilities() -> AuthorizedSubcommandCapabilities {
    let mut capabilities = AuthorizedSubcommandCapabilities::empty();
    if cfg!(feature = "spdm") {
        capabilities |= AuthorizedSubcommandCapabilities::GET_AUTH_CHALLENGE
            | AuthorizedSubcommandCapabilities::PROVISION_VENDOR_PK_HASH
            | AuthorizedSubcommandCapabilities::FUSE_INCREASE_CALIPTRA_MIN_SVN
            | AuthorizedSubcommandCapabilities::PROGRAM_FIELD_ENTROPY
            | AuthorizedSubcommandCapabilities::FUSE_REVOKE_VENDOR_PUBLIC_KEY
            | AuthorizedSubcommandCapabilities::FUSE_REVOKE_VENDOR_PK_HASH
            | AuthorizedSubcommandCapabilities::FUSE_LOCK_PARTITION
            | AuthorizedSubcommandCapabilities::PROVISION_OWNER_PK_HASH;
    }
    if cfg!(feature = "dot-spdm-vdm") {
        capabilities |= AuthorizedSubcommandCapabilities::DOT_LOCK
            | AuthorizedSubcommandCapabilities::DOT_DISABLE
            | AuthorizedSubcommandCapabilities::DOT_ROTATE
            | AuthorizedSubcommandCapabilities::GET_DOT_BACKUP_BLOB;
    }
    capabilities
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
        capabilities.mcu_rom = encode_capabilities(
            caliptra_mcu_libsyscall_caliptra::system::System::mcu_rom_capabilities()
                .unwrap_or_default(),
        );
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

    const SUPPORTED_EVIDENCE_FORMATS: u32 = SUPPORTED_EVIDENCE_FORMATS;
    const MAX_ATTESTATION_EVIDENCE_LEN: usize = MAX_ATTESTATION_EVIDENCE_LEN;

    fn attestation_evidence_len(format: EvidenceFormat, algorithm: AsymAlgo) -> usize {
        evidence_len(format, algorithm)
    }

    async fn get_attestation<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        format: EvidenceFormat,
        algorithm: AsymAlgo,
        entity: PkiEntitySlot,
        nonce: &[u8; ATTESTATION_NONCE_LEN],
        out: &mut [u8],
    ) -> CaliptraCmdResult<usize> {
        device_ops::get_attestation(alloc, format, algorithm, entity, nonce, out).await
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

    async fn dot_lock<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        request: &DotLockPayload,
    ) -> CaliptraCmdResult<()> {
        device_ops::dot_lock(alloc, request).await
    }

    async fn dot_disable<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        request: &DotDisablePayload,
    ) -> CaliptraCmdResult<()> {
        device_ops::dot_disable(alloc, request).await
    }

    async fn dot_rotate<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        request: &DotRotatePayload,
    ) -> CaliptraCmdResult<()> {
        device_ops::dot_rotate(alloc, request).await
    }

    async fn dot_status(&self, status: &mut DotStatus) -> CaliptraCmdResult<()> {
        *status = device_ops::dot_status()?;
        Ok(())
    }

    async fn dot_recovery<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        blob: &[u8; DOT_BLOB_SIZE],
    ) -> CaliptraCmdResult<()> {
        device_ops::dot_recovery(alloc, blob).await
    }

    async fn dot_override_challenge<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        request: &DotOverrideChallengePayload,
    ) -> CaliptraCmdResult<[u8; AUTH_CMD_NONCE_LEN]> {
        device_ops::dot_override_challenge(alloc, request).await
    }

    async fn dot_override<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        request: &DotOverridePayload,
    ) -> CaliptraCmdResult<()> {
        device_ops::dot_override(alloc, request).await
    }

    async fn dot_unlock_challenge<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
    ) -> CaliptraCmdResult<[u8; caliptra_mcu_mbox_common::messages::AUTH_CMD_NONCE_LEN]> {
        device_ops::dot_unlock_challenge(alloc).await
    }

    async fn dot_unlock<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        request: &DotUnlockPayload,
    ) -> CaliptraCmdResult<()> {
        device_ops::dot_unlock(alloc, request).await
    }

    async fn dot_get_backup_blob<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        blob: &mut [u8; DOT_BLOB_SIZE],
    ) -> CaliptraCmdResult<()> {
        device_ops::dot_get_backup_blob(alloc, blob).await
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

    #[cfg(feature = "ocp-lock")]
    async fn get_ocp_lock_endorsement_cert(
        &self,
        hpke_handle: &HpkeHandle,
        cert_buf: &mut [u8],
    ) -> CaliptraCmdResult<usize> {
        let mailbox = Mailbox::new();
        let ocp_lock = OcpLock::new(&mailbox, &crate::ocp_lock_config::APP_RUNTIME_CONFIG);
        let signer = CaliptraDpeSigner::new(&mailbox);

        ocp_lock
            .get_hpke_public_key_x509(hpke_handle, cert_buf, &signer)
            .await
            .map_err(|e| match e {
                CaliptraApiError::MailboxBusy => CaliptraCompletionCode::CaliptraMailboxBusy,
                CaliptraApiError::BufferTooSmall => CaliptraCompletionCode::CaliptraBufferTooSmall,
                _ => CaliptraCompletionCode::OperationFailed,
            })
    }

    #[cfg(feature = "ocp-lock")]
    async fn ocp_lock_enumerate_hpke_handles(
        &self,
        resp: &mut OcpLockEnumerateHpkeHandlesResp,
    ) -> CaliptraCmdResult<()> {
        let mailbox = Mailbox::new();
        let ocp_lock = OcpLock::new(&mailbox, &crate::ocp_lock_config::APP_RUNTIME_CONFIG);

        ocp_lock
            .enumerate_hpke_handles(resp)
            .await
            .map_err(|e| match e {
                CaliptraApiError::MailboxBusy => CaliptraCompletionCode::CaliptraMailboxBusy,
                _ => CaliptraCompletionCode::OperationFailed,
            })
    }

    #[cfg(feature = "ocp-lock")]
    async fn get_ocp_lock_epoch_key_report(
        &self,
        nonce: &[u8; 32],
        sek_state: caliptra_mcu_mbox_common::messages::SekState,
        report_buf: &mut [u8],
    ) -> CaliptraCmdResult<usize> {
        let mailbox = Mailbox::new();
        let ocp_lock = OcpLock::new(&mailbox, &crate::ocp_lock_config::APP_RUNTIME_CONFIG);
        let signer = CaliptraDpeSigner::new(&mailbox);

        let len = ocp_lock
            .get_ocp_lock_epoch_key_report(nonce, sek_state, &signer, report_buf)
            .await
            .map_err(|e| match e {
                CaliptraApiError::MailboxBusy => CaliptraCompletionCode::CaliptraMailboxBusy,
                CaliptraApiError::BufferTooSmall | CaliptraApiError::InvalidArgBufferTooSmall => {
                    CaliptraCompletionCode::CaliptraBufferTooSmall
                }
                _ => CaliptraCompletionCode::OperationFailed,
            })?;

        Ok(len)
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
            commands.contains(ExternalCommandCapabilities::DEVICE_OWNERSHIP_TRANSFER),
            cfg!(feature = "dot-spdm-vdm")
        );
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
            authorized.contains(
                AuthorizedSubcommandCapabilities::DOT_LOCK
                    | AuthorizedSubcommandCapabilities::DOT_DISABLE
                    | AuthorizedSubcommandCapabilities::DOT_ROTATE
                    | AuthorizedSubcommandCapabilities::GET_DOT_BACKUP_BLOB
            ),
            cfg!(feature = "dot-spdm-vdm")
        );
        assert_eq!(
            runtime.contains(McuRuntimeCapabilities::DOE),
            cfg!(feature = "doe")
        );
        assert_eq!(
            commands.contains(ExternalCommandCapabilities::GET_ATTESTATION),
            (cfg!(feature = "spdm") || cfg!(feature = "mcu-mbox-service"))
                && SUPPORTED_EVIDENCE_FORMATS != 0
        );
    }
}

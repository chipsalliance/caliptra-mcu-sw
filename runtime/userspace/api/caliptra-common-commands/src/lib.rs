// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![allow(async_fn_in_trait)]

use caliptra_mcu_mbox_common::messages::{
    CommandId, DotLockPayload, HybridSignature, AUTH_CMD_NONCE_LEN,
};
use mcu_caliptra_api::ApiAlloc;
use zerocopy::{Immutable, IntoBytes};

pub const MAX_ATTESTED_CSR_DATA_LEN: usize = 12_800;
pub const MAX_FW_VERSION_LEN: usize = 32;

/// Size of the unique device identifier in bytes.
pub const DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE: usize = 32;
/// Size of the debug unlock challenge in bytes.
pub const DEBUG_UNLOCK_CHALLENGE_SIZE: usize = 48;

/// Caliptra command completion codes.
/// Standard codes (0x00-0x0F) follow the OCP command registry:
/// https://github.com/opencomputeproject/ocp-registry/blob/main/command-registry.md
/// Codes 0xC0-0xFF: Reserved for Caliptra project-specific error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CaliptraCompletionCode {
    // OCP standard codes (0x00-0x0F)
    Success = 0x00,
    GeneralError = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    InvalidIdentifier = 0x04,
    OperationFailed = 0x05,
    InsufficientResources = 0x06,
    UnsupportedOperation = 0x07,
    DeviceNotReady = 0x08,
    InvalidCommandVersion = 0x09,
    InvalidPayloadSize = 0x0A,
    Timeout = 0x0B,
    AccessDenied = 0x0C,
    ResourceUnavailable = 0x0D,
    PolicyViolation = 0x0E,
    InvalidState = 0x0F,

    // Caliptra project-specific codes (0xC0-0xFF)
    CaliptraMailboxBusy = 0xC0,
    CaliptraBufferTooSmall = 0xC1,
}

/// Result type for Caliptra command handlers.
pub type CaliptraCmdResult<T> = Result<T, CaliptraCompletionCode>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedCsrData {
    pub len: usize,
    pub data: [u8; MAX_ATTESTED_CSR_DATA_LEN],
}

impl Default for AttestedCsrData {
    fn default() -> Self {
        Self {
            len: 0,
            data: [0u8; MAX_ATTESTED_CSR_DATA_LEN],
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FirmwareVersion {
    pub len: usize,
    pub ver_str: [u8; MAX_FW_VERSION_LEN],
}

/// Attestation evidence formats carried by `GET_ATTESTATION`.
///
/// Wire-stable: these values appear verbatim in the `evidence_format` field of
/// both the SPDM VDM and MCU mailbox requests.
///
/// `0` is reserved on the wire as the format-discovery query and therefore has
/// no enum variant; the dispatch layer handles it before decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EvidenceFormat {
    /// Signed OCP Entity Attestation Token carrying OCP EAT profile claims.
    OcpEat = 1,
    /// Caliptra PCR quote.
    PcrQuote = 2,
}

/// Wire value reserved for the format-discovery query.
///
/// A request carrying this `evidence_format` returns the responder's
/// [`EvidenceFormat`] bitmap instead of evidence.
pub const EVIDENCE_FORMAT_QUERY: u32 = 0;

/// Nonce length for `GET_ATTESTATION`, matching `EXPORT_ATTESTED_CSR`.
pub const ATTESTATION_NONCE_LEN: usize = 32;

impl EvidenceFormat {
    /// Bit position of this format in a supported-formats bitmap.
    ///
    /// Bit `n` is set when the responder supports the format whose wire value
    /// is `n`, so bit 0 is never set (it is the query sentinel).
    pub const fn bit(self) -> u32 {
        1u32 << (self as u32)
    }
}

impl TryFrom<u32> for EvidenceFormat {
    type Error = CaliptraCompletionCode;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(EvidenceFormat::OcpEat),
            2 => Ok(EvidenceFormat::PcrQuote),
            _ => Err(CaliptraCompletionCode::InvalidParameter),
        }
    }
}

/// Signing algorithms selectable by `GET_ATTESTATION`.
///
/// Values match the `algorithm` field already used by `EXPORT_ATTESTED_CSR`
/// (`0x0001` = ECC384, `0x0002` = MLDSA87).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AsymAlgo {
    EccP384 = 1,
    Mldsa87 = 2,
}

impl TryFrom<u32> for AsymAlgo {
    type Error = CaliptraCompletionCode;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(AsymAlgo::EccP384),
            2 => Ok(AsymAlgo::Mldsa87),
            _ => Err(CaliptraCompletionCode::InvalidParameter),
        }
    }
}

/// PKI entity whose hierarchy endorses the evidence's signing key.
///
/// This selects an endorsement hierarchy, not a signing key: every slot signs
/// with the same DPE leaf key today.
///
/// Because signing is not slot-aware yet, only [`PkiEntitySlot::Vendor`] is
/// served; responders reject [`PkiEntitySlot::Owner`] with
/// `UNSUPPORTED_OPERATION` rather than return evidence claiming an endorsement
/// that was never selected. Once signing is slot-aware, whether an entity can
/// be served follows the provisioning state of its endorsement slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum PkiEntitySlot {
    /// Vendor (device manufacturer) hierarchy.
    #[default]
    Vendor = 0,
    /// Owner hierarchy. Reserved.
    Owner = 1,
}

impl TryFrom<u32> for PkiEntitySlot {
    type Error = CaliptraCompletionCode;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PkiEntitySlot::Vendor),
            1 => Ok(PkiEntitySlot::Owner),
            _ => Err(CaliptraCompletionCode::InvalidParameter),
        }
    }
}

/// Log type identifiers used by `get_log` / `clear_log`.
///
/// These values are wire-stable (carried in the MCU mailbox `log_type` field
/// and implied by Caliptra/MCTP VDM command codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LogType {
    /// MCU debug log (Tock logging-flash capsule).
    Debug = 0,
}

impl TryFrom<u32> for LogType {
    type Error = CaliptraCompletionCode;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LogType::Debug),
            _ => Err(CaliptraCompletionCode::InvalidParameter),
        }
    }
}

/// Result of a single `get_log` invocation.
///
/// Read-side cursor is owned by the implementor. Callers drain the log by
/// repeating `get_log` until `more_data == false`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GetLogResult {
    /// Number of valid bytes written into the caller-supplied buffer.
    pub bytes_written: usize,
    /// `true` if at least one further entry remains that did not fit in the
    /// caller's buffer; `false` if the log was fully drained by this call.
    pub more_data: bool,
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, Immutable, PartialEq, Eq)]
pub struct DeviceCapabilities {
    pub caliptra_rt: [u8; 8],            // Bytes [0:7], big-endian
    pub caliptra_fmc: [u8; 4],           // Bytes [8:11], big-endian
    pub caliptra_rom: [u8; 4],           // Bytes [12:15], big-endian
    pub mcu_rom: [u8; 4],                // Bytes [16:19], big-endian
    pub mcu_rt: [u8; 4],                 // Bytes [20:23], big-endian
    pub external_commands: [u8; 4],      // Bytes [24:27], big-endian
    pub authorized_subcommands: [u8; 4], // Bytes [28:31], big-endian
    pub reserved: [u8; 4],               // Bytes [32:35], zero
}

/// Debug unlock challenge response returned by `request_debug_unlock`.
#[derive(Debug, Clone)]
pub struct DebugUnlockChallenge {
    pub unique_device_identifier: [u8; DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE],
    pub challenge: [u8; DEBUG_UNLOCK_CHALLENGE_SIZE],
}

impl Default for DebugUnlockChallenge {
    fn default() -> Self {
        Self {
            unique_device_identifier: [0u8; DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE],
            challenge: [0u8; DEBUG_UNLOCK_CHALLENGE_SIZE],
        }
    }
}

/// Asynchronous trait for handling Caliptra common commands across all transport protocols.
///
/// Each function represents a transport-agnostic command handler. Implementors should provide
/// the specific logic for each command as required by their application.
pub trait CaliptraCmdHandler {
    /// Retrieves the firmware version for the given index.
    ///
    /// # Arguments
    /// * `index` - The firmware index to query.
    /// * `version` - Mutable reference to store the firmware version.
    ///
    /// # Returns
    /// * `CaliptraCmdResult<()>` - Ok on success, or an error.
    async fn get_firmware_version(
        &self,
        index: u32,
        version: &mut FirmwareVersion,
    ) -> CaliptraCmdResult<()>;

    /// Retrieves the device capabilities.
    ///
    /// # Arguments
    /// * `capabilities` - Mutable reference to store the device capabilities.
    ///
    /// # Returns
    /// * `CaliptraCmdResult<()>` - Ok on success, or an error.
    async fn get_device_capabilities(
        &self,
        capabilities: &mut DeviceCapabilities,
    ) -> CaliptraCmdResult<()>;

    /// Exports an attested CSR for the specified device key.
    ///
    /// # Arguments
    /// * `device_key_id` - The device key identifier (0x0001=LDevID, 0x0002=FMC Alias, 0x0003=RT Alias).
    /// * `algorithm` - The asymmetric algorithm (0x0001=ECC384, 0x0002=MLDSA87).
    /// * `nonce` - A 32-byte nonce provided by the requester for freshness.
    /// * `csr_buf` - Mutable buffer to write the CSR DER data into directly.
    ///
    /// # Returns
    /// * `CaliptraCmdResult<usize>` - Number of bytes written on success, or an error.
    async fn export_attested_csr<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        device_key_id: u32,
        algorithm: u32,
        nonce: &[u8; 32],
        csr_buf: &mut [u8],
    ) -> CaliptraCmdResult<usize>;

    /// Exports an IDevID CSR (manufacturing mode only).
    async fn export_idevid_csr<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        algorithm: u32,
        csr_buf: &mut [u8],
    ) -> CaliptraCmdResult<usize> {
        let _ = (alloc, algorithm, csr_buf);
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    /// Bitmap of [`EvidenceFormat`]s this build can produce.
    ///
    /// Bit `n` is set when the format whose wire value is `n` is supported; see
    /// [`EvidenceFormat::bit`]. Returned verbatim to a requester that issues a
    /// [`EVIDENCE_FORMAT_QUERY`] request.
    ///
    /// Implementors must keep this consistent with
    /// [`attestation_evidence_len`](Self::attestation_evidence_len): a format
    /// advertised here must report a non-zero length for at least one
    /// algorithm.
    const SUPPORTED_EVIDENCE_FORMATS: u32 = 0;

    /// Largest evidence this build can emit for any supported format and
    /// algorithm.
    ///
    /// This is the worst case across every enabled evidence generator and is
    /// what transports use to size static contracts (VDM large-response
    /// capacity, mailbox response buffers). Per-request buffers should use the
    /// narrower [`attestation_evidence_len`](Self::attestation_evidence_len)
    /// instead, so that an ECC quote does not reserve an ML-DSA-sized buffer.
    const MAX_ATTESTATION_EVIDENCE_LEN: usize = 0;

    /// Upper bound, in bytes, on evidence for one specific format and
    /// algorithm; `0` when the pair is not supported by this build.
    ///
    /// Transports call this before generating evidence so they can reserve
    /// exactly what the requested pair needs and reject unsupported pairs
    /// without allocating.
    fn attestation_evidence_len(format: EvidenceFormat, algorithm: AsymAlgo) -> usize {
        let _ = (format, algorithm);
        0
    }

    /// Generates signed attestation evidence in the requested format.
    ///
    /// # Arguments
    /// * `format` - Evidence encoding; see [`EvidenceFormat`].
    /// * `algorithm` - Signing algorithm; see [`AsymAlgo`].
    /// * `entity` - PKI entity whose hierarchy signs; see [`PkiEntitySlot`].
    /// * `nonce` - Requester-supplied freshness nonce, bound into the evidence.
    /// * `out` - Destination buffer. Callers must size it to at least
    ///   [`attestation_evidence_len`](Self::attestation_evidence_len) for the
    ///   requested pair.
    ///
    /// # Returns
    /// * `Ok(usize)` - Number of evidence bytes written into `out`.
    /// * `Err(CaliptraCompletionCode::UnsupportedOperation)` - The
    ///   format/algorithm pair, or the requested entity, is not enabled in this
    ///   build.
    /// * `Err(CaliptraCompletionCode::InsufficientResources)` - `out` is too
    ///   small for the generated evidence.
    async fn get_attestation<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        format: EvidenceFormat,
        algorithm: AsymAlgo,
        entity: PkiEntitySlot,
        nonce: &[u8; ATTESTATION_NONCE_LEN],
        out: &mut [u8],
    ) -> CaliptraCmdResult<usize> {
        let _ = (alloc, format, algorithm, entity, nonce, out);
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    /// Requests a production debug unlock challenge.
    ///
    /// # Arguments
    /// * `unlock_level` - The debug unlock level requested (1-8).
    /// * `challenge` - Mutable reference to store the challenge response.
    ///
    /// # Returns
    /// * `CaliptraCmdResult<()>` - Ok on success, or an error.
    async fn request_debug_unlock<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        unlock_level: u8,
        challenge: &mut DebugUnlockChallenge,
    ) -> CaliptraCmdResult<()>;

    /// Submits a signed debug unlock token.
    ///
    /// The request includes the requester-computed Caliptra mailbox checksum.
    /// This permits transports such as SPDM VDM to relay the request in chunks
    /// without buffering the complete token to compute its checksum.
    ///
    /// # Arguments
    /// * `token_request` - The complete Caliptra request, including its checksum header.
    ///
    /// # Returns
    /// * `CaliptraCmdResult<()>` - Ok on success, or an error.
    async fn authorize_debug_unlock_token<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        token_request: &[u8],
    ) -> CaliptraCmdResult<()>;

    /// Drain log entries of `log_type` into `data`.
    ///
    /// Reads as many complete log entries as fit into `data`. Entries are not
    /// split: if the next entry does not fit in the remaining buffer, it is
    /// left in place for the caller's next invocation and the returned
    /// `more_data` flag is set to `true`.
    ///
    /// Implementors own the read-side cursor; `clear_log` resets it.
    ///
    /// # Arguments
    /// * `log_type` - Log identifier; see [`LogType`].
    /// * `data` - Destination buffer for serialized log entries.
    ///
    /// # Returns
    /// * `Ok(GetLogResult)` on success.
    /// * `Err(CaliptraCompletionCode::InvalidParameter)` for unknown `log_type`.
    /// * `Err(CaliptraCompletionCode::UnsupportedOperation)` if the implementor
    ///   does not provide this log on the current platform.
    async fn get_log(&self, log_type: u32, data: &mut [u8]) -> CaliptraCmdResult<GetLogResult> {
        let _ = (log_type, data);
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    /// Clear (erase) the log of `log_type` and reset the read cursor.
    ///
    /// # Arguments
    /// * `log_type` - Log identifier; see [`LogType`].
    ///
    /// # Returns
    /// * `Ok(())` on success.
    /// * `Err(CaliptraCompletionCode::InvalidParameter)` for unknown `log_type`.
    /// * `Err(CaliptraCompletionCode::UnsupportedOperation)` if the implementor
    ///   does not provide this log on the current platform.
    async fn clear_log(&self, log_type: u32) -> CaliptraCmdResult<()> {
        let _ = log_type;
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    /// Provision a vendor public-key hash in an OTP slot.
    async fn provision_vendor_pk_hash(&self, slot: u32, hash: &[u8; 48]) -> CaliptraCmdResult<()> {
        let _ = (slot, hash);
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    /// Provision the owner public-key hash in OTP.
    async fn provision_owner_pk_hash(&self, hash: &[u8; 48]) -> CaliptraCmdResult<()> {
        let _ = hash;
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    /// Increase the minimum allowed Caliptra firmware SVN.
    async fn increase_caliptra_min_svn<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        svn: u32,
    ) -> CaliptraCmdResult<()> {
        let _ = (alloc, svn);
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    /// Revoke one vendor public key in a provisioned public-key-hash slot.
    async fn revoke_vendor_pub_key<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        vendor_pk_hash_slot: u32,
        key_type: u32,
        key_index: u32,
    ) -> CaliptraCmdResult<()> {
        let _ = (alloc, vendor_pk_hash_slot, key_type, key_index);
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    /// Revoke a provisioned vendor public-key-hash slot.
    async fn revoke_vendor_pk_hash(&self, vendor_pk_hash_slot: u32) -> CaliptraCmdResult<()> {
        let _ = vendor_pk_hash_slot;
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    /// Program field entropy for a given partition.
    ///
    /// Over both the MCU mailbox and VDM paths, the dispatch layer verifies
    /// authorization via `CommandAuthorizer::verify_signatures` before invoking
    /// this transport-agnostic handler.
    ///
    /// # Arguments
    /// * `partition` - The partition index to program.
    ///
    /// # Returns
    /// * `CaliptraCmdResult<()>` - Ok on success, or an error.
    async fn program_field_entropy<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        partition: u32,
    ) -> CaliptraCmdResult<()> {
        let _ = (alloc, partition);
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    /// Lock an OTP partition against further writes.
    async fn fuse_lock_partition(&self, partition: u32) -> CaliptraCmdResult<()> {
        let _ = partition;
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    /// Verify and commit a persistent DOT lock transition.
    async fn dot_lock<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        request: &DotLockPayload,
    ) -> CaliptraCmdResult<()> {
        let _ = (alloc, request);
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }
}

pub struct AuthorizationError;

pub type AuthorizationResult<T> = Result<T, AuthorizationError>;

pub trait CommandAuthorizer {
    /// Validates if a message is authorized.
    ///
    /// The request can contain authorization data (e.g. a verification).
    /// This method is responsible for unpacking the contained
    /// request message and returning it as a slice.
    ///
    /// # Arguments
    /// * `cmd_id` - Command identifier
    /// * `req` - Message to be authorized
    ///
    /// # Returns
    /// * `Result<&[u8], CommandError>` - Unpacked command or Error
    async fn is_authorized<'a, Alloc: ApiAlloc>(
        &mut self,
        alloc: &Alloc,
        cmd_id: CommandId,
        req: &'a [u8],
    ) -> Result<&'a [u8], AuthorizationError>;

    /// Verify signatures over a command using the stored challenge.
    ///
    /// This is transport-agnostic and is the SINGLE step-1 gate shared by the
    /// mailbox (`is_authorized`) and SPDM VDM paths: the implementation consumes
    /// the stored one-time challenge via `take()`, redundantly/constant-time
    /// compares it against the wire `nonce`, then verifies the hybrid signature
    /// with the wire-carried public keys (the device-side anchor check lives in
    /// `device_ops`).
    ///
    /// Consumes the stored challenge (one-time use) on any attempt.
    ///
    /// # Arguments
    /// * `cmd_id` - Raw command identifier (u32, serialized big-endian in verification)
    /// * `payload` - Command-specific payload bytes
    /// * `nonce` - 48-byte freshness nonce carried on the wire (compared to the
    ///   stored one-time challenge)
    /// * `ecc_pub_x`/`ecc_pub_y`/`mldsa_pub` - verifier public keys carried on the
    ///   wire (hash-anchored device-side before use)
    /// * `sig` - The hybrid signature received from the host
    #[allow(clippy::too_many_arguments)]
    async fn verify_signatures<Alloc: ApiAlloc>(
        &mut self,
        alloc: &Alloc,
        cmd_id: u32,
        payload: &[u8],
        nonce: &[u8; AUTH_CMD_NONCE_LEN],
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        mldsa_pub: &[u8; 2592],
        sig: &HybridSignature,
    ) -> Result<(), AuthorizationError>;

    /// Get the challenge from the last call to `MC_GET_AUTH_CMD_CHALLENGE`.
    ///
    /// This consumes the challenge so it can only be used once.
    fn take_challenge(&mut self) -> Option<[u8; AUTH_CMD_NONCE_LEN]>;

    /// Set the challenge nonce to be used on the next authorized command.
    fn set_challenge(&mut self, challenge: [u8; AUTH_CMD_NONCE_LEN]);
}

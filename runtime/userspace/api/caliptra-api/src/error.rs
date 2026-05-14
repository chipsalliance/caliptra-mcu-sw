// Licensed under the Apache-2.0 license

use caliptra_mcu_libsyscall_caliptra::mailbox::MailboxError;
use caliptra_mcu_libtock_platform::ErrorCode;
use caliptra_ocp_eat::EatError;

#[cfg(feature = "ocp-lock")]
use caliptra_mcu_romtime::ocp_lock::Error as OcpLockError;

pub type CaliptraApiResult<T> = Result<T, CaliptraApiError>;

/// Errors returned by the Caliptra mailbox API (the MCU userspace interface
/// to Caliptra mailbox commands).
///
/// `Mailbox(_)`, `Syscall(_)`, and `Eat(_)` wrap inner errors from the
/// libsyscall, tock, and EAT crates respectively; all other variants are
/// field-less. `error_code()` returns a stable u8 per variant (table below)
/// used by consumers for compact numeric logging.
///
/// ```text
///   Caliptra mailbox / firmware state
///   0x01 MailboxBusy
///   0x02 InvalidResponse
///   0x03 UnprovisionedCsr
///   0x04 AsymAlgoUnsupported
///
///   Generic
///   0x05 BufferTooSmall
///
///   AES-GCM
///   0x06 AesGcmInvalidDataLength
///   0x07 AesGcmInvalidAadLength
///   0x08 AesGcmInvalidOperation
///   0x09 AesGcmInvalidContext
///   0x0A AesGcmTagVerifyFailed
///
///   Caller bad argument (flattened from InvalidArgument)
///   0x0B InvalidArgBufferTooSmall
///   0x0C InvalidArgChunkSizeTooLarge
///   0x0D InvalidArgDataSizeExceedsLimit
///   0x0E InvalidArgDataSizeExceedsMax
///   0x0F InvalidArgHashBufferTooSmall
///   0x10 InvalidArgInfoSizeExceedsMax
///   0x11 InvalidArgSaltSizeExceedsMax
///   0x12 InvalidArgCertSize
///   0x13 InvalidArgDigestSize
///   0x14 InvalidArgPubkeySize
///   0x15 InvalidArgSignatureSize
///   0x16 InvalidArgSize
///
///   Caller in wrong state (flattened from InvalidOperation)
///   0x17 InvalidOpContextNotInitialized
///   0x18 InvalidOpHashAlgoNotInitialized
///
///   External-error wrappers
///   0x19 Mailbox(MailboxError)
///   0x1A Syscall(ErrorCode)
///   0x1B Eat(EatError)
/// ```
#[derive(Debug, PartialEq)]
pub enum CaliptraApiError {
    // Caliptra mailbox / firmware state
    MailboxBusy,
    InvalidResponse,
    UnprovisionedCsr,
    AsymAlgoUnsupported,
    // Generic
    BufferTooSmall,
    // AES-GCM
    AesGcmInvalidDataLength,
    AesGcmInvalidAadLength,
    AesGcmInvalidOperation,
    AesGcmInvalidContext,
    AesGcmTagVerifyFailed,
    // Caller bad argument (flattened from InvalidArgument)
    InvalidArgBufferTooSmall,
    InvalidArgChunkSizeTooLarge,
    InvalidArgDataSizeExceedsLimit,
    InvalidArgDataSizeExceedsMax,
    InvalidArgHashBufferTooSmall,
    InvalidArgInfoSizeExceedsMax,
    InvalidArgSaltSizeExceedsMax,
    InvalidArgCertSize,
    InvalidArgDigestSize,
    InvalidArgPubkeySize,
    InvalidArgSignatureSize,
    InvalidArgSize,
    // Caller in wrong state (flattened from InvalidOperation)
    InvalidOpContextNotInitialized,
    InvalidOpHashAlgoNotInitialized,
    // External-error wrappers
    Mailbox(MailboxError),
    Syscall(ErrorCode),
    Eat(EatError),
    #[cfg(feature = "ocp-lock")]
    OcpLock(OcpLockError),
}

#[cfg(feature = "ocp-lock")]
impl From<der::Error> for CaliptraApiError {
    fn from(_: der::Error) -> Self {
        // TODO(clundin): Inspect error kind and create more fine-grained errors.
        CaliptraApiError::OcpLock(OcpLockError::RUNTIME_HPKE_INVALID_CERT_FORMAT)
    }
}

impl CaliptraApiError {
    /// Returns a stable numeric ID for this variant.
    pub fn error_code(&self) -> u8 {
        match self {
            CaliptraApiError::MailboxBusy => 0x01,
            CaliptraApiError::InvalidResponse => 0x02,
            CaliptraApiError::UnprovisionedCsr => 0x03,
            CaliptraApiError::AsymAlgoUnsupported => 0x04,
            CaliptraApiError::BufferTooSmall => 0x05,
            CaliptraApiError::AesGcmInvalidDataLength => 0x06,
            CaliptraApiError::AesGcmInvalidAadLength => 0x07,
            CaliptraApiError::AesGcmInvalidOperation => 0x08,
            CaliptraApiError::AesGcmInvalidContext => 0x09,
            CaliptraApiError::AesGcmTagVerifyFailed => 0x0A,
            CaliptraApiError::InvalidArgBufferTooSmall => 0x0B,
            CaliptraApiError::InvalidArgChunkSizeTooLarge => 0x0C,
            CaliptraApiError::InvalidArgDataSizeExceedsLimit => 0x0D,
            CaliptraApiError::InvalidArgDataSizeExceedsMax => 0x0E,
            CaliptraApiError::InvalidArgHashBufferTooSmall => 0x0F,
            CaliptraApiError::InvalidArgInfoSizeExceedsMax => 0x10,
            CaliptraApiError::InvalidArgSaltSizeExceedsMax => 0x11,
            CaliptraApiError::InvalidArgCertSize => 0x12,
            CaliptraApiError::InvalidArgDigestSize => 0x13,
            CaliptraApiError::InvalidArgPubkeySize => 0x14,
            CaliptraApiError::InvalidArgSignatureSize => 0x15,
            CaliptraApiError::InvalidArgSize => 0x16,
            CaliptraApiError::InvalidOpContextNotInitialized => 0x17,
            CaliptraApiError::InvalidOpHashAlgoNotInitialized => 0x18,
            CaliptraApiError::Mailbox(_) => 0x19,
            CaliptraApiError::Syscall(_) => 0x1A,
            CaliptraApiError::Eat(_) => 0x1B,
        }
    }

    /// If this is the `Eat(_)` variant, returns the inner `EatError` mapped to
    /// a stable u8 ID; otherwise `None`. Lets callers (e.g. SPDM error
    /// logging) treat EAT failures as their own external error kind without
    /// taking a direct dependency on `caliptra-ocp-eat`.
    pub fn eat_id(&self) -> Option<u8> {
        match self {
            CaliptraApiError::Eat(e) => Some(match e {
                EatError::BufferTooSmall => 0x01,
                EatError::InvalidData => 0x02,
                EatError::MissingMandatoryClaim => 0x03,
                EatError::InvalidClaimSize => 0x04,
                EatError::EncodingError => 0x05,
                EatError::InvalidUtf8 => 0x06,
            }),
            _ => None,
        }
    }
}

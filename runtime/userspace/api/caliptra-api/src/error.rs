// Licensed under the Apache-2.0 license

use libsyscall_caliptra::mailbox::MailboxError;
use libtock_platform::ErrorCode;
use ocp_eat::EatError;

#[cfg(feature = "ocp-lock")]
use romtime::ocp_lock::Error as OcpLockError;

pub type CaliptraApiResult<T> = Result<T, CaliptraApiError>;

#[derive(Debug, PartialEq)]
pub enum CaliptraApiError {
    MailboxBusy,
    Mailbox(MailboxError),
    Syscall(ErrorCode),
    InvalidArgument(&'static str),
    InvalidOperation(&'static str),
    AesGcmInvalidDataLength,
    AesGcmInvalidAadLength,
    AesGcmInvalidOperation,
    AesGcmInvalidContext,
    AesGcmTagVerifyFailed,
    AsymAlgoUnsupported,
    InvalidResponse,
    UnprovisionedCsr,
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
